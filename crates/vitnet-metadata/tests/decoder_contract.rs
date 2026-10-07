use proptest::prelude::*;
use vitnet_metadata::{
    HEADER, StreamingDecoder, decode_metadata_prefix, encode_header, encode_record,
};

#[test]
fn csv_header_is_exactly_the_producer_header() {
    assert_eq!(encode_header(), b"Handle, Kind, Name, Children");
    assert_eq!(HEADER, b"Handle, Kind, Name, Children");

    for wrong in [
        b"Handle,Kind,Name,Children\n".as_slice(),
        b"handle, Kind, Name, Children\n".as_slice(),
        b"Handle, Kind, Name, Children \n".as_slice(),
    ] {
        let error = StreamingDecoder::new(wrong, 2, true)
            .next()
            .expect("header result")
            .unwrap_err();
        assert_eq!(error.diagnostic.code, "metadata.csv.header");
        assert_eq!(
            error.diagnostic.expected.as_deref(),
            Some("Handle, Kind, Name, Children")
        );
    }
}

#[test]
fn canonical_encoder_backslash_escapes_names_and_space_separates_children() {
    assert_eq!(
        encode_record(17, "ConstantStringValue", br#"a\"b"#, &[3, 5, 8]),
        br#"00000011, ConstantStringValue, "a\\\"b", "3 5 8""#
    );
}

#[test]
fn tiny_buffer_streaming_decodes_commas_multiline_backslash_and_doubled_quotes() {
    let input = b"Handle, Kind, Name, Children\r\n\
00000001, ConstantStringValue, \"first, line\nsecond\", \"2 3\"\r\n\
00000002, Type, \"slash\\\\ quote\\\" and doubled \"\"quote\"\"\", \"\"\n";
    let records = StreamingDecoder::new(input.as_slice(), 1, true)
        .collect::<Result<Vec<_>, _>>()
        .unwrap();

    assert_eq!(records.len(), 2);
    assert_eq!(records[0].name, b"first, line\nsecond");
    assert_eq!(records[0].children, vec![2, 3]);
    assert_eq!(records[0].logical_record, 1);
    assert_eq!(records[0].physical_line_start, 2);
    assert_eq!(records[0].physical_line_end, 4);
    assert_eq!(records[1].name, b"slash\\ quote\" and doubled \"quote\"");
    assert_eq!(records[1].children, Vec::<u32>::new());
    assert_eq!(records[1].physical_line_start, 4);
}

#[test]
fn invalid_utf8_name_is_preserved_as_raw_bytes() {
    let input = b"Handle, Kind, Name, Children\n00000001, String, \"a\xffb\", \"\"\n";
    let record = StreamingDecoder::new(input.as_slice(), 3, true)
        .next()
        .unwrap()
        .unwrap();
    assert_eq!(record.name, b"a\xffb");
    assert_eq!(record.name.len(), 3);
}

#[test]
fn producer_hex_handles_and_quoted_hex_children_accept_alpha_digits() {
    let input = b"Handle, Kind, Name, Children\nabcdef12, Type, \"T\", \"a ff 10\"\n";
    let record = StreamingDecoder::new(input.as_slice(), 5, true)
        .next()
        .unwrap()
        .unwrap();
    assert_eq!(record.handle, 0xabcd_ef12);
    assert_eq!(record.children, vec![0x0a, 0xff, 0x10]);
}

#[test]
fn strict_decoder_rejects_a_quote_sequence_that_breaks_field_boundaries() {
    let input = b"Handle, Kind, Name, Children\n00000001, String, \"closed\"x, \"\"\n";
    let error = StreamingDecoder::new(input.as_slice(), 8, true)
        .next()
        .unwrap()
        .unwrap_err();
    assert_eq!(error.diagnostic.code, "metadata.csv.name");
    assert!(error.diagnostic.message.contains("no closing quote"));
}

#[test]
fn producer_display_quotes_without_backslashes_are_preserved() {
    let input = b"Handle, Kind, Name, Children\n00000001, NamedArgument, \"FrameworkDisplayName\" = \".NET 8.0\", \"\"\n";
    let record = StreamingDecoder::new(input.as_slice(), 8, true)
        .next()
        .unwrap()
        .unwrap();
    assert_eq!(record.name, b"FrameworkDisplayName\" = \".NET 8.0");
}

#[test]
fn logical_record_limit_stops_adversarial_multiline_growth() {
    let input = b"Handle, Kind, Name, Children\n00000000, String, \"0123456789\", \"\"\n";
    let error = StreamingDecoder::new(input.as_slice(), 2, true)
        .with_record_limit(8)
        .next()
        .unwrap()
        .unwrap_err();
    assert_eq!(error.diagnostic.code, "resource.record_limit");
}

#[test]
fn unterminated_quote_has_typed_record_and_line_diagnostic() {
    let input = b"Handle, Kind, Name, Children\n00000001, String, \"line one\nline two";
    let error = StreamingDecoder::new(input.as_slice(), 4, true)
        .next()
        .unwrap()
        .unwrap_err();
    assert_eq!(error.diagnostic.code, "metadata.csv.quote");
    assert_eq!(error.diagnostic.logical_record, Some(0));
    assert_eq!(error.diagnostic.physical_line, Some(3));
    assert!(error.diagnostic.byte_offset.unwrap() >= input.len() as u64);
}

proptest! {
    #[test]
    fn fuzz_ready_decoder_never_panics_for_arbitrary_bytes(bytes in prop::collection::vec(any::<u8>(), 0..4096), strict in any::<bool>()) {
        let outcome = std::panic::catch_unwind(|| decode_metadata_prefix(&bytes, strict));
        prop_assert!(outcome.is_ok());
    }

    #[test]
    fn every_accepted_record_range_lies_inside_the_input(
        names in prop::collection::vec(prop::collection::vec(any::<u8>(), 0..40), 0..30)
    ) {
        let mut input = HEADER.to_vec();
        input.push(b'\n');
        for (index, name) in names.iter().enumerate() {
            let handle = u32::try_from(index).expect("property limits indexes to fewer than 30");
            input.extend_from_slice(&encode_record(handle, "String", name, &[]));
            input.push(b'\n');
        }
        let records = StreamingDecoder::new(input.as_slice(), 7, true)
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        for record in records {
            prop_assert!(record.byte_range.start <= record.byte_range.end);
            prop_assert!(record.byte_range.end <= input.len());
        }
    }

    #[test]
    fn canonical_records_round_trip_arbitrary_names_and_children(
        handle in any::<u32>(),
        name in prop::collection::vec(any::<u8>(), 0..256),
        children in prop::collection::vec(any::<u32>(), 0..30),
    ) {
        let mut input = HEADER.to_vec();
        input.push(b'\n');
        input.extend_from_slice(&encode_record(handle, "String", &name, &children));
        input.push(b'\n');
        let records = StreamingDecoder::new(input.as_slice(), 3, true)
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        prop_assert_eq!(records.len(), 1);
        prop_assert_eq!(records[0].handle, handle);
        prop_assert_eq!(&records[0].name, &name);
        prop_assert_eq!(&records[0].children, &children);
    }
}

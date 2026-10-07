use proptest::prelude::*;
use vitnet_mstat::{diff, summarize};

const FILE_ALIGNMENT: usize = 0x200;
const TEXT_RVA: u32 = 0x2000;
const METADATA_OFFSET: usize = 0x80;

struct Fixture {
    bytes: Vec<u8>,
    methods_code_offset: usize,
    names_offset: usize,
}

#[test]
fn summarizes_independently_constructed_v22_fixture() {
    let fixture = fixture();
    let summary = summarize(&fixture.bytes, 1024 * 1024).unwrap();

    assert_eq!(summary.schema, "vitnet.mstat-summary.v1");
    assert_eq!(summary.format_version.major, 2);
    assert_eq!(summary.format_version.minor, 2);
    assert_eq!(summary.assembly, "tiny.mstat");
    assert_eq!(summary.accounted_size_bytes, 66);
    assert_eq!(summary.mangled_names_bytes, 4);
    assert_eq!(summary.categories.len(), 7);
    assert_eq!(summary.categories[0].name, "Methods");
    assert_eq!(summary.categories[0].records, 1);
    assert_eq!(summary.categories[0].aggregate_size_bytes, 13);
    assert_eq!(summary.categories[1].aggregate_size_bytes, 20);
    assert_eq!(summary.categories[2].aggregate_size_bytes, 33);
    assert_eq!(summary.categories[4].records, 2);
    assert_eq!(summary.categories[4].aggregate_size_bytes, 11);
    assert_eq!(summary.categories[5].aggregate_size_bytes, 7);
    assert_eq!(summary.categories[6].items, 1);
    assert_eq!(summary.methods.body_bytes, 10);
    assert_eq!(summary.methods.gc_info_bytes, 2);
    assert_eq!(summary.methods.exception_info_bytes, 1);
    assert_eq!(summary.frozen_objects.owned_records, 1);
    assert_eq!(summary.frozen_objects.owned_bytes, 5);
    assert_eq!(summary.frozen_objects.unowned_records, 1);
    assert_eq!(summary.frozen_objects.unowned_bytes, 6);
    assert_eq!(summary.deduplicated_methods.groups, 1);
    assert_eq!(summary.deduplicated_methods.folded_methods, 1);
    assert_eq!(summary.deduplicated_methods.estimated_savings_bytes, None);
}

#[test]
fn every_truncated_file_boundary_is_rejected() {
    let fixture = fixture();
    for length in 0..fixture.bytes.len() {
        let error = summarize(&fixture.bytes[..length], 1024 * 1024).unwrap_err();
        assert!(
            error.diagnostic.code.starts_with("mstat."),
            "prefix {length} returned {}",
            error.diagnostic.code
        );
    }
}

#[test]
fn corrupt_record_opcode_has_a_typed_offset_diagnostic() {
    let mut fixture = fixture();
    fixture.bytes[fixture.methods_code_offset] = 0xff;

    let error = summarize(&fixture.bytes, 1024 * 1024).unwrap_err();
    assert_eq!(error.diagnostic.code, "mstat.il.opcode");
    assert_eq!(
        error.diagnostic.byte_offset,
        Some(fixture.methods_code_offset as u64 + 1)
    );
}

#[test]
fn rejects_invalid_metadata_tokens_and_serialized_names() {
    let mut token_fixture = fixture();
    token_fixture.bytes
        [token_fixture.methods_code_offset + 1..token_fixture.methods_code_offset + 5]
        .copy_from_slice(&0_u32.to_le_bytes());
    let token_error = summarize(&token_fixture.bytes, 1024 * 1024).unwrap_err();
    assert_eq!(token_error.diagnostic.code, "mstat.token.kind");

    let mut name_fixture = fixture();
    name_fixture.bytes[name_fixture.names_offset] = 0xff;
    let name_error = summarize(&name_fixture.bytes, 1024 * 1024).unwrap_err();
    assert_eq!(name_error.diagnostic.code, "mstat.names.compressed_length");
}

#[test]
fn resource_budget_is_enforced_before_mapping_state_is_parsed() {
    let fixture = fixture();
    let error = summarize(&fixture.bytes, 32 * 1024).unwrap_err();
    assert_eq!(error.diagnostic.code, "resource.memory_limit");
}

#[test]
fn json_representation_is_deterministic_and_versioned() {
    let fixture = fixture();
    let first = summarize(&fixture.bytes, 1024 * 1024).unwrap();
    let second = summarize(&fixture.bytes, 1024 * 1024).unwrap();
    assert_eq!(
        serde_json::to_string(&first).unwrap(),
        serde_json::to_string(&second).unwrap()
    );
    assert_eq!(first.schema, "vitnet.mstat-summary.v1");
}

#[test]
fn structural_diff_reconciles_changed_method_size() {
    let before = fixture();
    let mut after = fixture();
    after.bytes[after.methods_code_offset + 6] = 15;

    let report = diff(&before.bytes, &after.bytes, 16 * 1024 * 1024, 10).unwrap();
    assert_eq!(report.schema, "vitnet.mstat-diff.v1");
    assert_eq!(report.total_delta_bytes, 5);
    assert!(report.reconciliation.balanced);
    assert_eq!(report.reconciliation.section_delta_sum, 5);
    let methods = report
        .sections
        .iter()
        .find(|section| section.name == "Methods")
        .unwrap();
    assert_eq!(methods.changed, 1);
    assert_eq!(methods.delta_bytes, 5);
    assert_eq!(methods.entries.len(), 1);
    assert_eq!(methods.entries[0].before_bytes, 13);
    assert_eq!(methods.entries[0].after_bytes, 18);
}

#[test]
fn identical_structural_diff_is_empty_and_deterministic() {
    let fixture = fixture();
    let first = diff(&fixture.bytes, &fixture.bytes, 16 * 1024 * 1024, 10).unwrap();
    let second = diff(&fixture.bytes, &fixture.bytes, 16 * 1024 * 1024, 10).unwrap();
    assert_eq!(first, second);
    assert_eq!(first.total_delta_bytes, 0);
    assert!(first.reconciliation.balanced);
    assert!(
        first
            .sections
            .iter()
            .all(|section| section.entries.is_empty())
    );
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    #[test]
    fn arbitrary_input_never_panics(data in proptest::collection::vec(any::<u8>(), 0..8192)) {
        let _ = summarize(&data, 1024 * 1024);
    }
}

fn fixture() -> Fixture {
    let names = [
        "Methods",
        "Types",
        "Blobs",
        "RvaFields",
        "FrozenObjects",
        "ManifestResources",
        "DeduplicatedMethods",
    ];
    let mut strings = vec![0];
    let name_offsets = names
        .iter()
        .map(|name| push_string(&mut strings, name))
        .collect::<Vec<_>>();
    let assembly_name = push_string(&mut strings, "tiny.mstat");

    let bodies = [
        methods_body(),
        types_body(),
        blobs_body(),
        rva_fields_body(),
        frozen_objects_body(),
        resources_body(),
        deduplicated_body(),
    ];
    let placeholder_rvas = [0_u32; 7];
    let placeholder_metadata = metadata(&strings, &name_offsets, assembly_name, &placeholder_rvas);
    let bodies_offset = align4(METADATA_OFFSET + placeholder_metadata.len());
    let mut relative = bodies_offset;
    let mut method_rvas = [0_u32; 7];
    for (index, body) in bodies.iter().enumerate() {
        relative = align4(relative);
        method_rvas[index] = TEXT_RVA + u32::try_from(relative).unwrap();
        relative += 1 + body.len();
    }
    let metadata = metadata(&strings, &name_offsets, assembly_name, &method_rvas);
    assert_eq!(metadata.len(), placeholder_metadata.len());
    assert_eq!(metadata.len(), 393);

    let text_size = align(relative, FILE_ALIGNMENT);
    let names_raw_offset = FILE_ALIGNMENT + text_size;
    assert_eq!(bodies_offset, 0x20c);
    assert_eq!(names_raw_offset, 0x600);
    let mut bytes = vec![0_u8; names_raw_offset + FILE_ALIGNMENT];
    assert_eq!(bytes.len(), 0x800);
    write_pe_headers(&mut bytes, text_size, names_raw_offset);
    write_cli_header(&mut bytes, metadata.len());
    bytes[FILE_ALIGNMENT + METADATA_OFFSET..FILE_ALIGNMENT + METADATA_OFFSET + metadata.len()]
        .copy_from_slice(&metadata);

    let mut body_offset = bodies_offset;
    let mut methods_code_offset = 0;
    for (index, body) in bodies.iter().enumerate() {
        body_offset = align4(body_offset);
        let file_offset = FILE_ALIGNMENT + body_offset;
        bytes[file_offset] = u8::try_from(body.len() << 2).unwrap() | 2;
        bytes[file_offset + 1..file_offset + 1 + body.len()].copy_from_slice(body);
        if index == 0 {
            methods_code_offset = file_offset + 1;
        }
        body_offset += 1 + body.len();
    }
    bytes[names_raw_offset..names_raw_offset + 4].copy_from_slice(&[1, b'a', 1, b'b']);

    Fixture {
        bytes,
        methods_code_offset,
        names_offset: names_raw_offset,
    }
}

fn metadata(strings: &[u8], names: &[u32], assembly_name: u32, method_rvas: &[u32; 7]) -> Vec<u8> {
    let tables = tables(names, assembly_name, method_rvas);
    let user_strings = [0_u8, 1, 0, 1, 0];
    let root_size = 76;
    let strings_offset = root_size + tables.len();
    let user_strings_offset = strings_offset + strings.len();
    let mut bytes = Vec::with_capacity(user_strings_offset + user_strings.len());
    push_u32(&mut bytes, 0x424a_5342);
    push_u16(&mut bytes, 1);
    push_u16(&mut bytes, 1);
    push_u32(&mut bytes, 0);
    push_u32(&mut bytes, 12);
    bytes.extend_from_slice(b"v4.0.30319\0\0");
    push_u16(&mut bytes, 0);
    push_u16(&mut bytes, 3);
    push_u32(&mut bytes, as_u32(root_size));
    push_u32(&mut bytes, as_u32(tables.len()));
    bytes.extend_from_slice(b"#~\0\0");
    push_u32(&mut bytes, as_u32(strings_offset));
    push_u32(&mut bytes, as_u32(strings.len()));
    bytes.extend_from_slice(b"#Strings\0\0\0\0");
    push_u32(&mut bytes, as_u32(user_strings_offset));
    push_u32(&mut bytes, as_u32(user_strings.len()));
    bytes.extend_from_slice(b"#US\0");
    assert_eq!(bytes.len(), root_size);
    bytes.extend_from_slice(&tables);
    bytes.extend_from_slice(strings);
    bytes.extend_from_slice(&user_strings);
    bytes
}

fn tables(names: &[u32], assembly_name: u32, method_rvas: &[u32; 7]) -> Vec<u8> {
    let mut bytes = Vec::new();
    push_u32(&mut bytes, 0);
    bytes.extend_from_slice(&[2, 0, 0, 1]);
    let valid =
        (1_u64 << 0) | (1_u64 << 2) | (1_u64 << 4) | (1_u64 << 6) | (1_u64 << 32) | (1_u64 << 35);
    push_u64(&mut bytes, valid);
    push_u64(&mut bytes, 0);
    for count in [1_u32, 1, 1, 7, 1, 1] {
        push_u32(&mut bytes, count);
    }

    push_u16(&mut bytes, 0);
    push_u16(&mut bytes, 0);
    push_u16(&mut bytes, 0);
    push_u16(&mut bytes, 0);
    push_u16(&mut bytes, 0);

    push_u32(&mut bytes, 0);
    push_u16(&mut bytes, 0);
    push_u16(&mut bytes, 0);
    push_u16(&mut bytes, 0);
    push_u16(&mut bytes, 1);
    push_u16(&mut bytes, 1);

    push_u16(&mut bytes, 0);
    push_u16(&mut bytes, 0);
    push_u16(&mut bytes, 0);

    for (rva, name) in method_rvas.iter().zip(names) {
        push_u32(&mut bytes, *rva);
        push_u16(&mut bytes, 0);
        push_u16(&mut bytes, 0);
        push_u16(&mut bytes, u16::try_from(*name).unwrap());
        push_u16(&mut bytes, 0);
        push_u16(&mut bytes, 1);
    }

    push_u32(&mut bytes, 0);
    push_u16(&mut bytes, 2);
    push_u16(&mut bytes, 2);
    push_u16(&mut bytes, u16::MAX);
    push_u16(&mut bytes, u16::MAX);
    push_u32(&mut bytes, 0);
    push_u16(&mut bytes, 0);
    push_u16(&mut bytes, u16::try_from(assembly_name).unwrap());
    push_u16(&mut bytes, 0);

    bytes.extend_from_slice(&[0; 20]);
    bytes
}

fn write_pe_headers(bytes: &mut [u8], text_size: usize, names_raw_offset: usize) {
    bytes[0..2].copy_from_slice(b"MZ");
    write_u32(bytes, 0x3c, 0x80);
    bytes[0x80..0x84].copy_from_slice(b"PE\0\0");
    write_u16(bytes, 0x84, 0x14c);
    write_u16(bytes, 0x86, 2);
    write_u16(bytes, 0x94, 0xe0);
    let optional = 0x98;
    write_u16(bytes, optional, 0x10b);
    write_u32(bytes, optional + 92, 16);
    write_u32(bytes, optional + 96 + 14 * 8, TEXT_RVA);
    write_u32(bytes, optional + 96 + 14 * 8 + 4, 72);
    let sections = optional + 0xe0;
    bytes[sections..sections + 5].copy_from_slice(b".text");
    write_u32(bytes, sections + 8, as_u32(text_size));
    write_u32(bytes, sections + 12, TEXT_RVA);
    write_u32(bytes, sections + 16, as_u32(text_size));
    write_u32(bytes, sections + 20, as_u32(FILE_ALIGNMENT));
    let names = sections + 40;
    bytes[names..names + 6].copy_from_slice(b".names");
    write_u32(bytes, names + 8, 4);
    write_u32(bytes, names + 12, 0x4000);
    write_u32(bytes, names + 16, as_u32(FILE_ALIGNMENT));
    write_u32(bytes, names + 20, as_u32(names_raw_offset));
}

fn write_cli_header(bytes: &mut [u8], metadata_size: usize) {
    let cli = FILE_ALIGNMENT;
    write_u32(bytes, cli, 72);
    write_u16(bytes, cli + 4, 2);
    write_u16(bytes, cli + 6, 5);
    write_u32(
        bytes,
        cli + 8,
        TEXT_RVA + u32::try_from(METADATA_OFFSET).unwrap(),
    );
    write_u32(bytes, cli + 12, as_u32(metadata_size));
}

fn methods_body() -> Vec<u8> {
    let mut bytes = Vec::new();
    token(&mut bytes, 0x0600_0001);
    i4(&mut bytes, 10);
    i4(&mut bytes, 2);
    i4(&mut bytes, 1);
    i4(&mut bytes, 0);
    bytes
}

fn types_body() -> Vec<u8> {
    let mut bytes = Vec::new();
    token(&mut bytes, 0x0200_0001);
    i4(&mut bytes, 20);
    i4(&mut bytes, 0);
    bytes
}

fn blobs_body() -> Vec<u8> {
    let mut bytes = vec![0x72];
    push_u32(&mut bytes, 0x7000_0001);
    i4(&mut bytes, 33);
    bytes
}

fn rva_fields_body() -> Vec<u8> {
    let mut bytes = Vec::new();
    token(&mut bytes, 0x0400_0001);
    i4(&mut bytes, 4);
    i4(&mut bytes, 0);
    bytes
}

fn frozen_objects_body() -> Vec<u8> {
    let mut bytes = Vec::new();
    token(&mut bytes, 0x0200_0001);
    i4(&mut bytes, 5);
    i4(&mut bytes, 0);
    token(&mut bytes, 0x0200_0001);
    token(&mut bytes, 0x0200_0001);
    i4(&mut bytes, 6);
    i4(&mut bytes, 0);
    i4(&mut bytes, 0);
    bytes
}

fn resources_body() -> Vec<u8> {
    let mut bytes = Vec::new();
    i4(&mut bytes, 0x2300_0001);
    bytes.push(0x72);
    push_u32(&mut bytes, 0x7000_0003);
    i4(&mut bytes, 7);
    bytes
}

fn deduplicated_body() -> Vec<u8> {
    let mut bytes = Vec::new();
    token(&mut bytes, 0x0600_0003);
    i4(&mut bytes, 1);
    token(&mut bytes, 0x0600_0004);
    i4(&mut bytes, 0);
    bytes
}

fn token(bytes: &mut Vec<u8>, value: u32) {
    bytes.push(0xd0);
    push_u32(bytes, value);
}

fn i4(bytes: &mut Vec<u8>, value: i32) {
    match value {
        -1 => bytes.push(0x15),
        0..=8 => bytes.push(0x16 + u8::try_from(value).unwrap()),
        -128..=127 => {
            bytes.push(0x1f);
            bytes.push(i8::try_from(value).unwrap().to_le_bytes()[0]);
        }
        _ => {
            bytes.push(0x20);
            bytes.extend_from_slice(&value.to_le_bytes());
        }
    }
}

fn push_string(bytes: &mut Vec<u8>, value: &str) -> u32 {
    let offset = as_u32(bytes.len());
    bytes.extend_from_slice(value.as_bytes());
    bytes.push(0);
    offset
}

fn push_u16(bytes: &mut Vec<u8>, value: u16) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

fn push_u32(bytes: &mut Vec<u8>, value: u32) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

fn push_u64(bytes: &mut Vec<u8>, value: u64) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

fn write_u16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn write_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

const fn align4(value: usize) -> usize {
    (value + 3) & !3
}

const fn align(value: usize, alignment: usize) -> usize {
    (value + alignment - 1) & !(alignment - 1)
}

fn as_u32(value: usize) -> u32 {
    u32::try_from(value).unwrap()
}

use vitnet_mstat::summarize;

const FILE_ALIGNMENT: usize = 0x200;
const TEXT_RVA: u32 = 0x2000;
const METADATA_OFFSET: usize = 0x80;

struct Fixture {
    bytes: Vec<u8>,
    methods_code_offset: usize,
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
    assert_eq!(summary.mangled_names_bytes, 3);
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

    let text_size = align(relative, FILE_ALIGNMENT);
    let names_raw_offset = FILE_ALIGNMENT + text_size;
    let mut bytes = vec![0_u8; names_raw_offset + FILE_ALIGNMENT];
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
    bytes[names_raw_offset..names_raw_offset + 3].copy_from_slice(b"a\0b");

    Fixture {
        bytes,
        methods_code_offset,
    }
}

fn metadata(strings: &[u8], names: &[u32], assembly_name: u32, method_rvas: &[u32; 7]) -> Vec<u8> {
    let tables = tables(names, assembly_name, method_rvas);
    let root_size = 64;
    let strings_offset = root_size + tables.len();
    let mut bytes = Vec::with_capacity(strings_offset + strings.len());
    push_u32(&mut bytes, 0x424a_5342);
    push_u16(&mut bytes, 1);
    push_u16(&mut bytes, 1);
    push_u32(&mut bytes, 0);
    push_u32(&mut bytes, 12);
    bytes.extend_from_slice(b"v4.0.30319\0\0");
    push_u16(&mut bytes, 0);
    push_u16(&mut bytes, 2);
    push_u32(&mut bytes, as_u32(root_size));
    push_u32(&mut bytes, as_u32(tables.len()));
    bytes.extend_from_slice(b"#~\0\0");
    push_u32(&mut bytes, as_u32(strings_offset));
    push_u32(&mut bytes, as_u32(strings.len()));
    bytes.extend_from_slice(b"#Strings\0\0\0\0");
    assert_eq!(bytes.len(), root_size);
    bytes.extend_from_slice(&tables);
    bytes.extend_from_slice(strings);
    bytes
}

fn tables(names: &[u32], assembly_name: u32, method_rvas: &[u32; 7]) -> Vec<u8> {
    let mut bytes = Vec::new();
    push_u32(&mut bytes, 0);
    bytes.extend_from_slice(&[2, 0, 0, 1]);
    let valid = (1_u64 << 0) | (1_u64 << 2) | (1_u64 << 6) | (1_u64 << 32);
    push_u64(&mut bytes, valid);
    push_u64(&mut bytes, 0);
    for count in [1_u32, 1, 7, 1] {
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
    write_u32(bytes, names + 8, 3);
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
    token(&mut bytes, 0x0a00_0001);
    i4(&mut bytes, 10);
    i4(&mut bytes, 2);
    i4(&mut bytes, 1);
    i4(&mut bytes, 0);
    bytes
}

fn types_body() -> Vec<u8> {
    let mut bytes = Vec::new();
    token(&mut bytes, 0x0100_0001);
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
    token(&mut bytes, 0x0a00_0002);
    i4(&mut bytes, 4);
    i4(&mut bytes, 0);
    bytes
}

fn frozen_objects_body() -> Vec<u8> {
    let mut bytes = Vec::new();
    token(&mut bytes, 0x0100_0002);
    i4(&mut bytes, 5);
    i4(&mut bytes, 0);
    token(&mut bytes, 0x0100_0003);
    token(&mut bytes, 0x0100_0004);
    i4(&mut bytes, 6);
    i4(&mut bytes, 0);
    i4(&mut bytes, 0);
    bytes
}

fn resources_body() -> Vec<u8> {
    let mut bytes = Vec::new();
    i4(&mut bytes, 0x2300_0001);
    bytes.push(0x72);
    push_u32(&mut bytes, 0x7000_0002);
    i4(&mut bytes, 7);
    bytes
}

fn deduplicated_body() -> Vec<u8> {
    let mut bytes = Vec::new();
    token(&mut bytes, 0x0a00_0003);
    i4(&mut bytes, 1);
    token(&mut bytes, 0x0a00_0004);
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

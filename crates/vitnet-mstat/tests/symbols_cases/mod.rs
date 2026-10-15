use super::*;
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use vitnet_mstat::{
    MstatError, MstatSymbol, MstatSymbolsSummary, SymbolKind, SymbolResolution,
    SymbolResolutionBasis, visit_coalesced_path, visit_symbols_path,
};

const LIMIT: u64 = 1024 * 1024;

struct SymbolFixture {
    strings: Vec<u8>,
    blobs: Vec<u8>,
    rows: BTreeMap<usize, Vec<Vec<u8>>>,
    bodies: [Vec<u8>; 7],
    names: Vec<u8>,
}

impl SymbolFixture {
    fn new() -> Self {
        let mut fixture = Self {
            strings: vec![0],
            blobs: vec![0],
            rows: BTreeMap::new(),
            bodies: std::array::from_fn(|_| Vec::new()),
            names: Vec::new(),
        };
        fixture.add(0, vec![0; 10]);
        let module = fixture.string("<Module>");
        fixture.add(2, type_def(module, 0, 1, 1));
        let assembly_name = fixture.string("typed.mstat");
        let mut assembly = vec![0; 22];
        write_u16(&mut assembly, 4, 2);
        write_u16(&mut assembly, 6, 2);
        write_u16(&mut assembly, 18, assembly_name);
        fixture.add(32, assembly);
        let signature = fixture.blob(&[0, 0, 1]);
        for name in [
            "Methods",
            "Types",
            "Blobs",
            "RvaFields",
            "FrozenObjects",
            "ManifestResources",
            "DeduplicatedMethods",
        ] {
            let name = fixture.string(name);
            let mut row = vec![0; 14];
            write_u16(&mut row, 8, name);
            write_u16(&mut row, 10, signature);
            write_u16(&mut row, 12, 1);
            fixture.add(6, row);
        }
        fixture
    }

    fn add(&mut self, table: usize, row: Vec<u8>) -> u32 {
        let rows = self.rows.entry(table).or_default();
        rows.push(row);
        (u32::try_from(table).unwrap() << 24) | as_u32(rows.len())
    }

    fn string(&mut self, text: &str) -> u16 {
        u16::try_from(push_string(&mut self.strings, text)).unwrap()
    }

    fn blob(&mut self, bytes: &[u8]) -> u16 {
        let offset = u16::try_from(self.blobs.len()).unwrap();
        let length = bytes.len();
        if length < 128 {
            self.blobs.push(u8::try_from(length).unwrap());
        } else {
            self.blobs.push(u8::try_from((length >> 8) | 0x80).unwrap());
            self.blobs.push(u8::try_from(length & 255).unwrap());
        }
        self.blobs.extend_from_slice(bytes);
        offset
    }

    fn assembly_ref(&mut self, name: &str) -> u32 {
        let name = self.string(name);
        let mut row = vec![0; 20];
        write_u16(&mut row, 0, 9);
        write_u16(&mut row, 14, name);
        self.add(35, row)
    }

    fn type_ref(&mut self, scope: u32, namespace: &str, name: &str) -> u32 {
        let scope = match scope >> 24 {
            35 => ((scope & 0x00ff_ffff) << 2) | 2,
            1 => ((scope & 0x00ff_ffff) << 2) | 3,
            _ => scope,
        };
        let namespace = self.string(namespace);
        let name = self.string(name);
        self.add(1, words(&[u16::try_from(scope).unwrap(), name, namespace]))
    }

    fn type_spec(&mut self, bytes: &[u8]) -> u32 {
        let index = self.blob(bytes);
        self.add(27, words(&[index]))
    }

    fn member(&mut self, owner: u32, name: &str, bytes: &[u8]) -> u32 {
        let tag = match owner >> 24 {
            2 => 0,
            1 => 1,
            26 => 2,
            27 => 4,
            _ => panic!("owner kind"),
        };
        let owner = u16::try_from(((owner & 0x00ff_ffff) << 3) | tag).unwrap();
        let name = self.string(name);
        let signature = self.blob(bytes);
        self.add(10, words(&[owner, name, signature]))
    }

    fn method_spec(&mut self, parent: u32, bytes: &[u8]) -> u32 {
        let parent =
            u16::try_from(((parent & 0x00ff_ffff) << 1) | u32::from(parent >> 24 == 10)).unwrap();
        let signature = self.blob(bytes);
        self.add(43, words(&[parent, signature]))
    }

    fn record(&mut self, stream: usize, entity: u32, name: &[u8]) {
        let offset = i32::try_from(self.names.len()).unwrap();
        assert!(name.len() < 128);
        self.names.push(u8::try_from(name.len()).unwrap());
        self.names.extend_from_slice(name);
        let body = &mut self.bodies[stream];
        token(body, entity);
        i4(body, 10);
        if stream == 0 {
            i4(body, 2);
            i4(body, 1);
        }
        i4(body, offset);
    }

    fn tables(&self) -> Vec<u8> {
        let mut bytes = vec![0, 0, 0, 0, 2, 0, 0, 1];
        push_u64(
            &mut bytes,
            self.rows
                .keys()
                .fold(0, |valid, table| valid | (1 << table)),
        );
        push_u64(&mut bytes, 0);
        for rows in self.rows.values() {
            push_u32(&mut bytes, as_u32(rows.len()));
        }
        for rows in self.rows.values() {
            for row in rows {
                bytes.extend_from_slice(row);
            }
        }
        bytes
    }

    fn metadata(&self) -> Vec<u8> {
        let tables = self.tables();
        let user_strings = [0];
        let streams: [(&[u8], &[u8]); 4] = [
            (b"#~\0\0", &tables),
            (b"#Strings\0\0\0\0", &self.strings),
            (b"#US\0", &user_strings),
            (b"#Blob\0\0\0", &self.blobs),
        ];
        let root_size = 92;
        let mut bytes = Vec::new();
        push_u32(&mut bytes, 0x424a_5342);
        push_u16(&mut bytes, 1);
        push_u16(&mut bytes, 1);
        push_u32(&mut bytes, 0);
        push_u32(&mut bytes, 12);
        bytes.extend_from_slice(b"v4.0.30319\0\0");
        push_u16(&mut bytes, 0);
        push_u16(&mut bytes, 4);
        let mut offset = root_size;
        for (name, content) in streams {
            push_u32(&mut bytes, as_u32(offset));
            push_u32(&mut bytes, as_u32(content.len()));
            bytes.extend_from_slice(name);
            offset += content.len();
        }
        assert_eq!(bytes.len(), root_size);
        for (_, content) in streams {
            bytes.extend_from_slice(content);
        }
        bytes
    }

    fn bytes(mut self) -> Vec<u8> {
        let mut relative = align4(METADATA_OFFSET + self.metadata().len());
        let rows = self.rows.get_mut(&6).unwrap();
        for (row, body) in rows.iter_mut().take(7).zip(&self.bodies) {
            relative = align4(relative);
            write_u32(row, 0, TEXT_RVA + as_u32(relative));
            relative += body_header_size(body) + body.len();
        }
        let metadata = self.metadata();
        let text_size = align(relative, FILE_ALIGNMENT);
        let names_offset = FILE_ALIGNMENT + text_size;
        let names_size = align(self.names.len().max(1), FILE_ALIGNMENT);
        let mut bytes = vec![0; names_offset + names_size];
        write_pe_headers(&mut bytes, text_size, names_offset);
        write_cli_header(&mut bytes, metadata.len());
        let names_section = 0x98 + 0xe0 + 40;
        write_u32(&mut bytes, names_section + 8, as_u32(self.names.len()));
        write_u32(&mut bytes, names_section + 16, as_u32(names_size));
        bytes[FILE_ALIGNMENT + METADATA_OFFSET..FILE_ALIGNMENT + METADATA_OFFSET + metadata.len()]
            .copy_from_slice(&metadata);
        relative = align4(METADATA_OFFSET + metadata.len());
        for body in self.bodies {
            relative = align4(relative);
            let offset = FILE_ALIGNMENT + relative;
            let header = body_header_size(&body);
            if header == 1 {
                bytes[offset] = u8::try_from(body.len() << 2).unwrap() | 2;
            } else {
                write_u16(&mut bytes, offset, 0x3003);
                write_u32(&mut bytes, offset + 4, as_u32(body.len()));
            }
            bytes[offset + header..offset + header + body.len()].copy_from_slice(&body);
            relative += header + body.len();
        }
        bytes[names_offset..names_offset + self.names.len()].copy_from_slice(&self.names);
        bytes
    }
}

fn words(values: &[u16]) -> Vec<u8> {
    values
        .iter()
        .flat_map(|value| value.to_le_bytes())
        .collect()
}

fn type_def(name: u16, namespace: u16, field: u16, method: u16) -> Vec<u8> {
    let mut row = vec![0; 4];
    row.extend(words(&[name, namespace, 0, field, method]));
    row
}

struct FileFixture(PathBuf);

impl FileFixture {
    fn new(bytes: &[u8]) -> Self {
        static COUNTER: AtomicUsize = AtomicUsize::new(0);
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(format!(
            "symbol-fixture-{}-{}.mstat",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::write(&path, bytes).unwrap();
        Self(path)
    }

    fn visit(&self, budget: u64) -> Result<(MstatSymbolsSummary, Vec<MstatSymbol>), MstatError> {
        let mut records = Vec::new();
        let summary = visit_symbols_path(&self.0, budget, |record| {
            records.push(record);
            Ok(())
        })?;
        Ok((summary, records))
    }
}

impl Drop for FileFixture {
    fn drop(&mut self) {
        std::fs::remove_file(&self.0).unwrap();
    }
}

fn resolved(record: &MstatSymbol) -> (&Option<String>, &str, Option<&str>, &str) {
    match &record.resolution {
        SymbolResolution::Resolved {
            assembly,
            declaring_type,
            member_name,
            signature,
        } => (assembly, declaring_type, member_name.as_deref(), signature),
        SymbolResolution::Unresolved { reason } => panic!("unexpected unresolved: {reason}"),
    }
}

#[test]
fn symbols_resolve_simple_types_methods_fields_and_match_coalesced_raw_hashes() {
    let mut fixture = SymbolFixture::new();
    let assembly = fixture.assembly_ref("App");
    let ty = fixture.type_ref(assembly, "Example", "Widget");
    let method = fixture.member(ty, "Run", &[0x20, 1, 1, 8]);
    let field = fixture.member(ty, "Payload", &[6, 0x1d, 5]);
    fixture.record(0, method, b"producer_exact_name");
    fixture.record(1, ty, b"same_spelling");
    fixture.record(3, field, b"same_spelling");
    let bytes = fixture.bytes();
    let file = FileFixture::new(&bytes);
    let (summary, records) = file.visit(LIMIT).unwrap();
    assert_eq!(
        (summary.records, summary.resolved, summary.unresolved),
        (3, 3, 0)
    );
    assert!(summary.peak_tracked_memory_bytes <= LIMIT);
    assert_eq!(records[0].token, method);
    assert_eq!(records[0].kind, SymbolKind::Method);
    assert_eq!(
        records[0].resolution_basis,
        SymbolResolutionBasis::ArtifactLocalEcma335
    );
    let (assembly, ty, member, signature) = resolved(&records[0]);
    assert_eq!(
        assembly.as_deref(),
        Some("App, Version=9.0.0.0, Culture=neutral, PublicKeyToken=null, Flags=0x00000000")
    );
    assert_eq!(
        (ty, member, signature),
        (
            "Example.Widget",
            Some("Run"),
            "cc=0x20;generic=0;void(int32)"
        )
    );
    assert_eq!(resolved(&records[1]).1, "Example.Widget");
    assert_eq!(resolved(&records[2]).2, Some("Payload"));
    assert_eq!(resolved(&records[2]).3, "field uint8[]");
    let mut coalesced = Vec::new();
    let accounting = visit_coalesced_path(&file.0, LIMIT, |row| {
        coalesced.push(row);
        Ok(())
    })
    .unwrap();
    assert_eq!(accounting.accounted_size_bytes, 23);
    for symbol in &records {
        let row = coalesced
            .iter()
            .find(|row| {
                row.stream == symbol.stream && row.raw_identity_blake3 == symbol.raw_identity_blake3
            })
            .unwrap();
        assert_eq!(row.identity, symbol.identity);
        assert_eq!(row.identity_lossy, symbol.identity_lossy);
    }
    assert_ne!(records[1].stream, records[2].stream);
    assert_eq!(
        records[1].raw_identity_blake3,
        records[2].raw_identity_blake3
    );
}

#[test]
fn symbols_preserve_nested_generic_types_and_method_instantiations() {
    let mut fixture = SymbolFixture::new();
    let assembly = fixture.assembly_ref("App");
    let outer = fixture.type_ref(assembly, "Example", "Outer`1");
    let inner = fixture.type_ref(outer, "", "Inner`1");
    // GENERICINST CLASS TypeRef(2), two arguments: int32 and string.
    let instantiated = fixture.type_spec(&[0x15, 0x12, 9, 2, 8, 14]);
    let method = fixture.member(instantiated, "Transform", &[0x30, 1, 1, 0x1e, 0, 0x13, 0]);
    let method = fixture.method_spec(method, &[0x0a, 1, 14]);
    fixture.record(0, method, b"not_a_demangling");
    fixture.record(1, inner, b"inner");
    fixture.record(1, instantiated, b"constructed");
    let file = FileFixture::new(&fixture.bytes());
    let (_, records) = file.visit(LIMIT).unwrap();
    assert_eq!(
        resolved(&records[0]).1,
        "Example.Outer`1+Inner`1<int32,string>"
    );
    assert_eq!(resolved(&records[0]).2, Some("Transform"));
    assert_eq!(
        resolved(&records[0]).3,
        "cc=0x30;generic=1;!!0(!0) inst<string>"
    );
    assert_eq!(resolved(&records[1]).1, "Example.Outer`1+Inner`1");
    assert!(
        resolved(&records[2])
            .3
            .ends_with("Example.Outer`1+Inner`1<int32,string>")
    );
}

#[test]
fn symbols_distinguish_overloads_and_do_not_coalesce_conflicting_tokens() {
    let mut fixture = SymbolFixture::new();
    let assembly = fixture.assembly_ref("App");
    let ty = fixture.type_ref(assembly, "", "Widget");
    for signature in [&[0, 1, 1, 8][..], &[0, 1, 1, 14][..]] {
        let method = fixture.member(ty, "Run", signature);
        fixture.record(0, method, b"collision");
    }
    let file = FileFixture::new(&fixture.bytes());
    let (_, records) = file.visit(LIMIT).unwrap();
    assert_eq!(records.len(), 2);
    assert_ne!(records[0].token, records[1].token);
    assert_eq!(
        records[0].raw_identity_blake3,
        records[1].raw_identity_blake3
    );
    assert_eq!(resolved(&records[0]).2, resolved(&records[1]).2);
    assert_eq!(resolved(&records[0]).3, "cc=0x00;generic=0;void(int32)");
    assert_eq!(resolved(&records[1]).3, "cc=0x00;generic=0;void(string)");
}

#[test]
fn symbols_resolve_definition_ownership_and_nested_definitions() {
    let mut fixture = SymbolFixture::new();
    let outer_name = fixture.string("Outer");
    let inner_name = fixture.string("Inner");
    let namespace = fixture.string("Example");
    let outer = fixture.add(2, type_def(outer_name, namespace, 1, 8));
    let inner = fixture.add(2, type_def(inner_name, 0, 1, 8));
    fixture.add(
        41,
        words(&[
            u16::try_from(inner & 0x00ff_ffff).unwrap(),
            u16::try_from(outer & 0x00ff_ffff).unwrap(),
        ]),
    );
    let field_name = fixture.string("Payload");
    let field_sig = fixture.blob(&[6, 8]);
    let field = fixture.add(4, words(&[0, field_name, field_sig]));
    let method_name = fixture.string("Run");
    let method_sig = fixture.blob(&[0, 0, 1]);
    let mut row = vec![0; 8];
    row.extend(words(&[method_name, method_sig, 1]));
    let method = fixture.add(6, row);
    fixture.record(0, method, b"defmethod");
    fixture.record(1, inner, b"deftype");
    fixture.record(3, field, b"deffield");
    let file = FileFixture::new(&fixture.bytes());
    let (_, records) = file.visit(LIMIT).unwrap();
    for record in &records {
        assert_eq!(resolved(record).1, "Example.Outer+Inner");
        assert!(
            resolved(record)
                .0
                .as_ref()
                .unwrap()
                .starts_with("typed.mstat, Version=2.2.")
        );
    }
    assert_eq!(resolved(&records[0]).2, Some("Run"));
    assert_eq!(resolved(&records[2]).2, Some("Payload"));
}

#[test]
fn symbols_report_unsupported_scope_without_success_shaped_defaults_and_keep_lossy_names() {
    let mut fixture = SymbolFixture::new();
    let ty = fixture.type_ref(0, "Example", "Unsupported");
    fixture.record(1, ty, &[0xff]);
    let file = FileFixture::new(&fixture.bytes());
    let (summary, records) = file.visit(LIMIT).unwrap();
    assert_eq!((summary.resolved, summary.unresolved), (0, 1));
    assert_eq!(records[0].identity, "\u{fffd}");
    assert!(records[0].identity_lossy);
    assert_eq!(
        records[0].raw_identity_blake3,
        blake3::hash(&[0xff]).to_hex().to_string()
    );
    assert!(
        matches!(&records[0].resolution, SymbolResolution::Unresolved { reason }
        if reason.contains("scope"))
    );
    let json = serde_json::to_value(&records[0]).unwrap();
    assert_eq!(json["resolution"]["status"], "unresolved");
    assert!(json["resolution"].get("declaring_type").is_none());
}

#[test]
fn symbols_reject_corrupt_tokens_and_truncated_or_invalid_signatures() {
    for (bytes, expected) in [
        (&[0, 1, 1][..], "mstat.symbol.signature"),
        (&[0, 1, 1, 0x12, 0xff][..], "mstat.symbol.signature"),
        (&[0, 1, 1, 0x12, 0x7d][..], "mstat.token.rid"),
        (&[0, 1, 1, 0x12, 7][..], "mstat.token.kind"),
        (&[6, 8][..], "mstat.symbol.signature"),
        (&[0, 0, 1, 0][..], "mstat.symbol.signature"),
        (&[0, 1, 1, 0xff][..], "mstat.symbol.signature"),
        (&[0x10, 1, 1, 1, 0x1e, 1][..], "mstat.symbol.signature"),
        (&[0x10, 0, 0, 1][..], "mstat.symbol.signature"),
        (&[0, 0x80, 0, 1][..], "mstat.symbol.signature"),
        (&[0, 1, 1, 0x21][..], "mstat.symbol.signature"),
    ] {
        let mut fixture = SymbolFixture::new();
        let assembly = fixture.assembly_ref("App");
        let ty = fixture.type_ref(assembly, "", "Widget");
        let method = fixture.member(ty, "Run", bytes);
        fixture.record(0, method, b"invalid");
        let file = FileFixture::new(&fixture.bytes());
        assert_eq!(
            file.visit(LIMIT).unwrap_err().diagnostic.code,
            expected,
            "{bytes:?}"
        );
    }
    let mut fixture = SymbolFixture::new();
    fixture.record(0, 0x0a00_0042, b"invalid");
    let file = FileFixture::new(&fixture.bytes());
    assert_eq!(
        file.visit(LIMIT).unwrap_err().diagnostic.code,
        "mstat.token.rid"
    );
}

#[test]
fn symbols_validate_methodspec_arity_and_missing_blob_payloads() {
    let mut fixture = SymbolFixture::new();
    let assembly = fixture.assembly_ref("App");
    let ty = fixture.type_ref(assembly, "", "Widget");
    let method = fixture.member(ty, "Run", &[0x10, 1, 0, 1]);
    let spec = fixture.method_spec(method, &[0x0a, 2, 8, 14]);
    fixture.record(0, spec, b"arity");
    let file = FileFixture::new(&fixture.bytes());
    assert_eq!(
        file.visit(LIMIT).unwrap_err().diagnostic.code,
        "mstat.symbol.signature"
    );

    let mut fixture = SymbolFixture::new();
    let assembly = fixture.assembly_ref("App");
    let ty = fixture.type_ref(assembly, "", "Widget");
    let method = fixture.member(ty, "Run", &[0, 0, 1]);
    let row = fixture.rows.get_mut(&10).unwrap().last_mut().unwrap();
    write_u16(row, 4, 0);
    fixture.record(0, method, b"missing");
    let file = FileFixture::new(&fixture.bytes());
    assert_eq!(
        file.visit(LIMIT).unwrap_err().diagnostic.code,
        "mstat.symbol.signature"
    );

    let mut fixture = SymbolFixture::new();
    let assembly = fixture.assembly_ref("App");
    let ty = fixture.type_ref(assembly, "", "Widget");
    let method = fixture.member(ty, "Run", &[0, 0, 1]);
    fixture.blobs.pop();
    fixture.record(0, method, b"truncated");
    let file = FileFixture::new(&fixture.bytes());
    assert_eq!(
        file.visit(LIMIT).unwrap_err().diagnostic.code,
        "mstat.symbol.signature"
    );
}

#[test]
fn symbols_decode_array_bounds_modifiers_and_function_pointer_signatures() {
    let mut fixture = SymbolFixture::new();
    let assembly = fixture.assembly_ref("App");
    fixture.type_ref(assembly, "", "Modifier");
    let array = fixture.type_spec(&[0x14, 8, 2, 1, 5, 2, 0x7f, 0]);
    let modified = fixture.type_spec(&[0x1f, 5, 0x0f, 1]);
    let function = fixture.type_spec(&[0x1b, 1, 1, 8, 0x0f, 1]);
    fixture.record(1, array, b"array");
    fixture.record(1, modified, b"modified");
    fixture.record(1, function, b"function");
    let file = FileFixture::new(&fixture.bytes());
    let (_, records) = file.visit(LIMIT).unwrap();
    assert_eq!(
        resolved(&records[0]).3,
        "int32[rank=2;sizes=5,;bounds=-1,0,]"
    );
    assert!(
        resolved(&records[1])
            .3
            .starts_with("modreq([App, Version=9.0.0.0")
    );
    assert!(resolved(&records[1]).3.ends_with("]Modifier) void*"));
    assert_eq!(
        resolved(&records[2]).3,
        "fnptr cc=0x01;generic=0;int32(void*)"
    );
    assert_eq!(resolved(&records[2]).0, &None);
}

#[test]
fn symbols_module_member_parents_are_explicitly_unresolved() {
    let mut fixture = SymbolFixture::new();
    let module_name = fixture.string("external.netmodule");
    let module = fixture.add(26, words(&[module_name]));
    let method = fixture.member(module, "GlobalMethod", &[0, 0, 1]);
    fixture.record(0, method, b"module");
    let file = FileFixture::new(&fixture.bytes());
    let (summary, records) = file.visit(LIMIT).unwrap();
    assert_eq!((summary.resolved, summary.unresolved), (0, 1));
    assert!(
        matches!(&records[0].resolution, SymbolResolution::Unresolved { reason }
        if reason.contains("ModuleRef"))
    );
}

#[test]
fn symbols_truncated_il_operands_are_typed_failures_before_callbacks() {
    let mut fixture = SymbolFixture::new();
    fixture.bodies[0] = vec![0xd0, 1, 0];
    let file = FileFixture::new(&fixture.bytes());
    let mut visits = 0;
    let error = visit_symbols_path(&file.0, LIMIT, |_| {
        visits += 1;
        Ok(())
    })
    .unwrap_err();
    assert_eq!(error.diagnostic.code, "mstat.il.truncated");
    assert_eq!(visits, 0);
}

#[test]
fn symbols_reject_cycles_and_enforce_string_signature_and_memory_budgets() {
    let mut fixture = SymbolFixture::new();
    let ty = fixture.type_ref(0x0100_0001, "", "Cycle");
    fixture.record(1, ty, b"cycle");
    let file = FileFixture::new(&fixture.bytes());
    assert_eq!(
        file.visit(LIMIT).unwrap_err().diagnostic.code,
        "resource.memory_limit"
    );
    assert_eq!(
        file.visit(65536).unwrap_err().diagnostic.code,
        "resource.memory_limit"
    );
    let mut fixture = SymbolFixture::new();
    let assembly = fixture.assembly_ref("App");
    let ty = fixture.type_ref(assembly, "", &"x".repeat(16 * 1024 + 1));
    fixture.record(1, ty, b"long");
    let file = FileFixture::new(&fixture.bytes());
    assert_eq!(
        file.visit(LIMIT).unwrap_err().diagnostic.code,
        "resource.memory_limit"
    );
    let mut fixture = SymbolFixture::new();
    let ty = fixture.type_spec(&vec![0x1d; 16 * 1024 + 1]);
    fixture.record(1, ty, b"long-signature");
    let file = FileFixture::new(&fixture.bytes());
    assert_eq!(
        file.visit(LIMIT).unwrap_err().diagnostic.code,
        "resource.memory_limit"
    );
    let mut fixture = SymbolFixture::new();
    let assembly = fixture.assembly_ref("App");
    let ty = fixture.type_ref(assembly, "", &"x".repeat(2000));
    fixture.record(1, ty, b"record-budget");
    let file = FileFixture::new(&fixture.bytes());
    assert_eq!(
        file.visit(65536 + 4096).unwrap_err().diagnostic.code,
        "resource.memory_limit"
    );
}

#[test]
fn symbols_validate_empty_artifacts_and_propagate_visitor_failure() {
    let fixture = SymbolFixture::new();
    let file = FileFixture::new(&fixture.bytes());
    let (summary, records) = file.visit(LIMIT).unwrap();
    assert_eq!(
        (summary.records, summary.resolved, summary.unresolved),
        (0, 0, 0)
    );
    assert_eq!(records, []);
    let mut fixture = SymbolFixture::new();
    let assembly = fixture.assembly_ref("App");
    let ty = fixture.type_ref(assembly, "", "Widget");
    fixture.record(1, ty, b"visitor");
    let file = FileFixture::new(&fixture.bytes());
    let error = visit_symbols_path(&file.0, LIMIT, |_| {
        Err(MstatError {
            diagnostic: Box::new(vitnet_core::Diagnostic::malformed(
                "visitor.failure",
                "stop",
            )),
        })
    })
    .unwrap_err();
    assert_eq!(error.diagnostic.code, "visitor.failure");
    assert_eq!(error.diagnostic.input_path, Some(file.0.clone()));
}

#[test]
fn symbols_stream_record_memory_does_not_grow_with_inventory() {
    let mut fixture = SymbolFixture::new();
    let assembly = fixture.assembly_ref("App");
    let ty = fixture.type_ref(assembly, "Example", "Widget");
    for _ in 0..5000 {
        fixture.record(1, ty, b"a");
    }
    let file = FileFixture::new(&fixture.bytes());
    let mut visits = 0;
    let budget = 65536 + 8192;
    let summary = visit_symbols_path(&file.0, budget, |record| {
        visits += 1;
        assert_eq!(record.token, ty);
        assert_eq!(resolved(&record).1, "Example.Widget");
        Ok(())
    })
    .unwrap();
    assert_eq!(visits, 5000);
    assert_eq!(
        (summary.records, summary.resolved, summary.unresolved),
        (5000, 5000, 0)
    );
    assert!(summary.peak_tracked_memory_bytes <= budget);
    assert_eq!(
        visit_coalesced_path(&file.0, budget, |_| Ok(()))
            .unwrap_err()
            .diagnostic
            .code,
        "resource.memory_limit"
    );
}

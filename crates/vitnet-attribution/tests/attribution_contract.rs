use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use vitnet_attribution::model::{
    Artifact, Assembly, Binary, BinarySection, EVIDENCE_SCHEMA, Evidence, Generator, ManagedType,
    Mapping, Package, Resource, Source,
};
use vitnet_attribution::{
    Matcher, asset_duplicates, compare, compare_retention, evidence_changes, explain, import,
    locate_source, open_index, package_routes, parse_shape, physical_delta, read_pe_binary, report,
    validate_evidence, verify_artifacts, visit_identities,
};
use vitnet_dgml::{IndexControl, IndexOptions, WhyOptions, build_index};
use vitnet_mstat::CoalescedIdentity;

const MEMORY: u64 = 64 << 20;

mod common;

fn artifact(kind: &str, path: PathBuf) -> Artifact {
    Artifact {
        kind: kind.into(),
        path,
        revision: None,
        blake3: None,
    }
}

fn mstat_file(directory: &Path, name: &str, size: i32) -> PathBuf {
    let mut image = common::Image::new();
    image.method(b"Sample_Project_Widget__Run", size);
    image.blob(&[u16::from(b'x')], 7);
    let path = directory.join(name);
    fs::write(&path, image.bytes()).unwrap();
    path
}

fn native_file(
    directory: &Path,
    name: &str,
    raw: u32,
    virtual_size: u32,
    overlay: usize,
) -> PathBuf {
    let mut bytes = vec![0; 512 + raw as usize + overlay];
    bytes[..2].copy_from_slice(b"MZ");
    common::u32_at(&mut bytes, 0x3c, 0x80);
    bytes[0x80..0x84].copy_from_slice(b"PE\0\0");
    bytes[0x84..0x86].copy_from_slice(&0x14c_u16.to_le_bytes());
    bytes[0x86..0x88].copy_from_slice(&1_u16.to_le_bytes());
    bytes[0x94..0x96].copy_from_slice(&0xe0_u16.to_le_bytes());
    bytes[0x98..0x9a].copy_from_slice(&0x10b_u16.to_le_bytes());
    for (at, value) in [
        (0x98 + 32, 4096),
        (0x98 + 36, 512),
        (0x98 + 56, 8192),
        (0x98 + 60, 512),
        (0x98 + 92, 16),
    ] {
        common::u32_at(&mut bytes, at, value);
    }
    bytes[0x178..0x17d].copy_from_slice(b".text");
    for (at, value) in [
        (0x180, virtual_size),
        (0x184, 4096),
        (0x188, raw),
        (0x18c, 512),
    ] {
        common::u32_at(&mut bytes, at, value);
    }
    let path = directory.join(name);
    fs::write(&path, bytes).unwrap();
    path
}

#[test]
fn raw_mstat_unicode_rejects_invalid_encodings_and_coalesces_valid_raw_identities() {
    let directory = tempfile::tempdir().unwrap();
    let mut image = common::Image::new();
    // Mangled names are strictly UTF-8; malformed names never become a lossy
    // display identity. The current reader also rejects unpaired surrogates.
    for raw in [b"\xff", b"\xfe"] {
        let mut invalid = common::Image::new();
        invalid.method(raw, 2);
        assert_eq!(
            vitnet_mstat::summarize(&invalid.bytes(), MEMORY)
                .unwrap_err()
                .diagnostic
                .code,
            "mstat.names.utf8"
        );
    }
    image.method("\u{fffd}".as_bytes(), 11);
    for raw in [&[0xd800_u16][..], &[0xd801][..]] {
        let mut invalid = common::Image::new();
        invalid.blob(raw, 13);
        assert_eq!(
            vitnet_mstat::summarize(&invalid.bytes(), MEMORY)
                .unwrap_err()
                .diagnostic
                .code,
            "mstat.user_string.utf16"
        );
    }
    image.method("\u{fffd}".as_bytes(), 5);
    image.blob(&[0xfffd], 13);
    image.blob(&[0xfffd], 17);
    let mstat = directory.path().join("unicode.mstat");
    fs::write(&mstat, image.bytes()).unwrap();
    let mut manifest = evidence();
    manifest.artifacts.push(artifact("mstat", mstat));
    manifest
        .sources
        .push(source(directory.path().join("Widget.cs"), None));
    for stream in ["Methods", "Blobs"] {
        manifest.mappings.push(Mapping {
            stream: stream.into(),
            identity: "\u{fffd}".into(),
            assembly: "Sample.Project".into(),
            source_paths: vec![directory.path().join("Widget.cs")],
            basis: "display spelling only".into(),
        });
    }
    let input = write_manifest(directory.path(), &manifest, "unicode.json");
    let output = directory.path().join("index");
    let imported = import(&input, &output, MEMORY, false).unwrap();
    assert_eq!(imported.identities, 2);
    assert_eq!(imported.mstat.as_ref().unwrap().accounted_size_bytes, 46);
    let mut rows = Vec::new();
    visit_identities(&output, &imported, MEMORY, |row| {
        rows.push(row.clone());
        Ok(())
    })
    .unwrap();
    for (stream, expected) in [
        ("Methods", vec![(16, 2, false)]),
        ("Blobs", vec![(30, 2, false)]),
    ] {
        let mut actual: Vec<_> = rows
            .iter()
            .filter(|row| row.stream == stream)
            .map(|row| (row.bytes, row.records, row.identity_lossy))
            .collect();
        actual.sort_unstable();
        assert_eq!(actual, expected);
        assert!(
            rows.iter()
                .filter(|row| row.stream == stream)
                .all(|row| row.identity == "\u{fffd}")
        );
    }
    assert_eq!(
        rows.iter()
            .map(|row| &row.raw_identity_blake3)
            .collect::<std::collections::BTreeSet<_>>()
            .len(),
        2
    );
    let method = rows.iter().find(|row| row.stream == "Methods").unwrap();
    assert_eq!(
        method.raw_identity_blake3,
        blake3::hash("\u{fffd}".as_bytes()).to_hex().to_string()
    );
    let blob = rows
        .iter()
        .find(|row| row.stream == "Blobs" && row.bytes == 30)
        .unwrap();
    assert_eq!(
        blob.raw_identity_blake3,
        blake3::hash(&[0xfd, 0xff]).to_hex().to_string()
    );
    let result = report(&output, MEMORY, 10, None).unwrap();
    assert_eq!(result.accounted_mapping_bytes["asserted"], 46);
}

#[test]
fn cached_lossy_identities_preserve_raw_distinctions_and_never_assert_source_ownership() {
    let directory = tempfile::tempdir().unwrap();
    let mut manifest = evidence();
    manifest
        .sources
        .push(source(directory.path().join("Widget.cs"), None));
    manifest.mappings.push(Mapping {
        stream: "Blobs".into(),
        identity: "\u{fffd}".into(),
        assembly: "Sample.Project".into(),
        source_paths: vec![directory.path().join("Widget.cs")],
        basis: "display spelling only".into(),
    });
    let input = write_manifest(directory.path(), &manifest, "lossy.json");
    let output = directory.path().join("index");
    import(&input, &output, MEMORY, false).unwrap();
    let entries = [
        (vec![0, 0xd8], 30, true),
        (vec![1, 0xd8], 19, true),
        (vec![0xfd, 0xff], 23, false),
    ]
    .map(|(raw, bytes, identity_lossy)| CoalescedIdentity {
        stream: "Blobs".into(),
        accounted: true,
        identity: "\u{fffd}".into(),
        raw_identity_blake3: blake3::hash(&raw).to_hex().to_string(),
        identity_lossy,
        bytes,
        records: 1,
    });
    write_cached_identities(&output, &entries);
    let result = report(&output, MEMORY, 10, None).unwrap();
    assert_eq!(
        result.accounted_mapping_bytes["unmapped_lossy_identity"],
        49
    );
    assert_eq!(result.accounted_mapping_bytes["asserted"], 23);
    let located = locate_source(&output, "\u{fffd}", MEMORY).unwrap();
    assert_eq!(located.matches.len(), 3);
    assert_eq!(
        located
            .contributors
            .iter()
            .map(|row| &row.raw_identity_blake3)
            .collect::<std::collections::BTreeSet<_>>()
            .len(),
        3
    );
    assert_eq!(
        located
            .matches
            .iter()
            .filter(|item| item.status == "asserted")
            .count(),
        1
    );
    assert!(
        located
            .matches
            .iter()
            .filter(|item| item.status == "unmapped_lossy_identity")
            .all(|item| item.sources.is_empty() && item.assemblies.is_empty())
    );
}

#[test]
#[allow(clippy::too_many_lines)] // Independent compare dimensions require separate assertions.
fn compare_reads_metadata_source_mstat_and_native_evidence_with_independent_deltas() {
    let directory = tempfile::tempdir().unwrap();
    let source_path = directory.path().join("Widget.cs");
    fs::write(&source_path, "class Widget {}").unwrap();
    let mut left = evidence();
    left.provenance.insert("compiler".into(), "1".into());
    left.sources.push(source(source_path.clone(), None));
    left.packages.push(Package {
        target: "net10.0".into(),
        id: "Package.One".into(),
        version: "1.0.0".into(),
        direct: true,
        dependencies: vec![],
    });
    let metadata = directory.path().join("before.csv");
    fs::write(&metadata, b"Handle, Kind, Name, Children\n00000000, ScopeDefinition, \"Sample.Project\", \"a 1e\"\n0000000a, TypeDefinition, \"Widget\", \"14\"\n00000014, Method, \"Run\", \"\"\n0000001e, TypeDefinition, \"Unmapped\", \"\"\n00000028, End, \"\", \"\"\n").unwrap();
    left.artifacts.extend([
        artifact("mstat", mstat_file(directory.path(), "before.mstat", 13)),
        artifact("metadata", metadata),
        artifact(
            "binary",
            native_file(directory.path(), "before.exe", 512, 600, 0),
        ),
    ]);
    let before = directory.path().join("before");
    import(
        &write_manifest(directory.path(), &left, "before.json"),
        &before,
        MEMORY,
        false,
    )
    .unwrap();
    fs::write(&source_path, "class Widget { int Value; }").unwrap();
    let mut right = left.clone();
    right.provenance.insert("compiler".into(), "2".into());
    right.packages[0].version = "2.0.0".into();
    let metadata = directory.path().join("after.csv");
    fs::write(&metadata, b"Handle, Kind, Name, Children\n00000000, ScopeDefinition, \"Sample.Project\", \"a 28\"\n0000000a, TypeDefinition, \"Widget\", \"14\"\n00000014, Method, \"Run\", \"\"\n00000028, TypeDefinition, \"Unmapped\", \"\"\n0000003c, End, \"\", \"\"\n").unwrap();
    right.artifacts = vec![
        artifact("mstat", mstat_file(directory.path(), "after.mstat", 18)),
        artifact("metadata", metadata),
        artifact(
            "binary",
            native_file(directory.path(), "after.exe", 512, 900, 128),
        ),
    ];
    let after = directory.path().join("after");
    import(
        &write_manifest(directory.path(), &right, "after.json"),
        &after,
        MEMORY,
        false,
    )
    .unwrap();
    let result = compare(&before, &after, MEMORY, 10).unwrap();
    assert_eq!(result.schema, "vitnet.attribution-compare.v1");
    let mstat = result.mstat.as_ref().unwrap();
    assert_eq!(mstat.total_delta_bytes, 5);
    assert_eq!(mstat.reconciliation.section_delta_sum, 5);
    assert!(mstat.reconciliation.balanced);
    let metadata = result.metadata.as_ref().unwrap();
    assert_eq!(
        (
            metadata.before_lower_bound_bytes,
            metadata.after_lower_bound_bytes,
            metadata.lower_bound_delta_bytes
        ),
        (40, 60, 20)
    );
    assert!(metadata.complete_dimensions);
    let widget = metadata
        .by_type
        .entries
        .iter()
        .find(|e| e.name == "Sample.Project!Widget")
        .unwrap();
    assert_eq!(
        (widget.before_bytes, widget.after_bytes, widget.delta_bytes),
        (20, 30, 10)
    );
    assert_eq!(metadata.by_type.total_delta, 20);
    let assembly = metadata
        .by_assembly
        .entries
        .iter()
        .find(|e| e.name == "Sample.Project")
        .unwrap();
    assert_eq!(
        (
            assembly.before_bytes,
            assembly.after_bytes,
            assembly.delta_bytes
        ),
        (40, 60, 20)
    );
    let kind = metadata
        .by_kind
        .entries
        .iter()
        .find(|e| e.name == "TypeDefinition")
        .unwrap();
    assert_eq!(
        (kind.before_bytes, kind.after_bytes, kind.delta_bytes),
        (20, 30, 10)
    );
    assert_eq!(result.physical.before_bytes, Some(1024));
    assert_eq!(result.physical.after_bytes, Some(1152));
    assert_eq!(result.physical.delta_bytes, Some(128));
    assert_eq!(result.physical.sections[0].file_delta_bytes, 0);
    assert_eq!(result.physical.sections[0].virtual_delta_bytes, 300);
    assert_eq!(result.physical.compatible_architecture, Some(true));
    assert_eq!(result.provenance_changes[0].key, "compiler");
    assert_eq!(result.provenance_changes[0].before.as_deref(), Some("1"));
    assert_eq!(result.provenance_changes[0].after.as_deref(), Some("2"));
    assert_eq!(result.package_changes[0].key, "net10.0:Package.One");
    assert_eq!(result.package_changes[0].after.as_deref(), Some("2.0.0"));
    assert_eq!(result.source_changes.len(), 1);
    assert_eq!(result.source_changes[0].key, source_path.to_string_lossy());
    assert_eq!(
        result.source_changes[0].before.as_deref(),
        Some(blake3::hash(b"class Widget {}").to_hex().as_str())
    );
    assert_eq!(
        result.source_changes[0].after.as_deref(),
        Some(
            blake3::hash(b"class Widget { int Value; }")
                .to_hex()
                .as_str()
        )
    );
    assert_eq!(
        result
            .diagnostics
            .iter()
            .filter(|d| d.code == "evidence.artifact.stale")
            .count(),
        1
    );
    assert!(result.retention.is_none());
    let reverse = compare(&after, &before, MEMORY, 10).unwrap();
    assert_eq!(reverse.mstat.as_ref().unwrap().total_delta_bytes, -5);
    assert_eq!(
        reverse.metadata.as_ref().unwrap().lower_bound_delta_bytes,
        -20
    );
    assert_eq!(reverse.physical.delta_bytes, Some(-128));
    assert_eq!(reverse.physical.sections[0].virtual_delta_bytes, -300);
    // Source drift is diagnostic snapshot evidence, but critical binary drift
    // must block physical/MSTAT controlled comparison.
    let mstat_bytes = fs::read(&right.artifacts[0].path).unwrap();
    fs::write(&right.artifacts[0].path, b"changed accounting input").unwrap();
    assert_eq!(
        compare(&before, &after, MEMORY, 10)
            .unwrap_err()
            .diagnostic
            .code,
        "attribution.compare.stale"
    );
    fs::write(&right.artifacts[0].path, mstat_bytes).unwrap();
    fs::write(&right.artifacts[2].path, b"changed native input").unwrap();
    assert_eq!(
        compare(&before, &after, MEMORY, 10)
            .unwrap_err()
            .diagnostic
            .code,
        "attribution.compare.stale"
    );
}

fn source(path: PathBuf, generated_by: Option<&str>) -> Source {
    Source {
        assembly: "Sample.Project".into(),
        type_name: "Widget".into(),
        member: Some("Run".into()),
        path,
        line: 10,
        end_line: 12,
        kind: "method".into(),
        attributes: vec!["RegisterService".into()],
        generated_by: generated_by.map(str::to_owned),
        sha256: None,
    }
}

fn evidence() -> Evidence {
    Evidence {
        schema: EVIDENCE_SCHEMA.into(),
        label: "synthetic build".into(),
        ..Evidence::default()
    }
}

fn write_manifest(directory: &Path, evidence: &Evidence, name: &str) -> PathBuf {
    let path = directory.join(name);
    fs::write(&path, serde_json::to_vec_pretty(evidence).unwrap()).unwrap();
    path
}

fn write_cached_identities(
    directory: &Path,
    entries: &[CoalescedIdentity],
) -> vitnet_attribution::AttributionIndex {
    let index_path = directory.join("index.json");
    let mut index = open_index(directory, MEMORY).unwrap();
    let mut bytes = Vec::new();
    for entry in entries {
        bytes.extend(serde_json::to_vec(entry).unwrap());
        bytes.push(b'\n');
    }
    fs::write(directory.join("identities.ndjson"), &bytes).unwrap();
    index.identities = entries.len() as u64;
    index.identities_blake3 = blake3::hash(&bytes).to_hex().to_string();
    fs::write(index_path, serde_json::to_vec(&index).unwrap()).unwrap();
    index
}

#[test]
fn import_is_versioned_immutable_and_detects_source_drift() {
    let directory = tempfile::tempdir().unwrap();
    let source_path = directory.path().join("Widget.cs");
    fs::write(&source_path, "class Widget {}").unwrap();
    let mut manifest = evidence();
    manifest.sources.push(source(source_path.clone(), None));
    let manifest_path = write_manifest(directory.path(), &manifest, "evidence.json");
    let output = directory.path().join("index");

    let imported = import(&manifest_path, &output, MEMORY, false).unwrap();
    assert_eq!(imported.schema, "vitnet.attribution-index.v1");
    assert!(
        imported
            .diagnostics
            .iter()
            .any(|item| item.code == "evidence.mstat.missing")
    );
    assert!(verify_artifacts(&imported).unwrap().is_empty());
    assert_eq!(
        import(&manifest_path, &output, MEMORY, false)
            .unwrap_err()
            .diagnostic
            .code,
        "attribution.output.exists"
    );

    fs::write(&source_path, "class Widget { int Value; }").unwrap();
    let drift = verify_artifacts(&imported).unwrap();
    assert_eq!(drift.len(), 1);
    assert_eq!(drift[0].code, "evidence.artifact.stale");
    assert_eq!(drift[0].path.as_deref(), Some(source_path.as_path()));
}

#[test]
fn evidence_validation_and_cache_integrity_fail_with_typed_diagnostics() {
    let mut invalid = evidence();
    invalid.schema = "vitnet.evidence.v2".into();
    assert_eq!(
        validate_evidence(&invalid).unwrap_err().diagnostic.code,
        "attribution.schema"
    );

    let mut invalid = evidence();
    invalid.sources.push(Source {
        line: 0,
        end_line: 0,
        ..source("invalid.cs".into(), None)
    });
    assert_eq!(
        validate_evidence(&invalid).unwrap_err().diagnostic.code,
        "attribution.source"
    );

    let duplicate = Package {
        target: "net10.0".into(),
        id: "Package.One".into(),
        version: "1.0.0".into(),
        direct: true,
        dependencies: vec![],
    };
    let mut invalid = evidence();
    invalid.packages = vec![duplicate.clone(), duplicate];
    assert_eq!(
        validate_evidence(&invalid).unwrap_err().diagnostic.code,
        "attribution.package"
    );

    let directory = tempfile::tempdir().unwrap();
    let manifest_path = write_manifest(directory.path(), &evidence(), "evidence.json");
    let output = directory.path().join("index");
    let imported = import(&manifest_path, &output, MEMORY, false).unwrap();
    fs::write(
        output.join("identities.ndjson"),
        br#"{"stream":"Methods","accounted":true,"identity":"injected","bytes":1,"records":1}
"#,
    )
    .unwrap();
    assert_eq!(
        visit_identities(&output, &imported, MEMORY, |_| Ok(()))
            .unwrap_err()
            .diagnostic
            .code,
        "attribution.cache.integrity"
    );
}

#[test]
fn resolved_package_routes_preserve_transitive_missing_and_cycle_evidence() {
    let mut manifest = evidence();
    manifest.packages = vec![
        Package {
            target: "net10.0/win-x64".into(),
            id: "Direct".into(),
            version: "1.0.0".into(),
            direct: true,
            dependencies: vec!["Transitive/2.0.0".into()],
        },
        Package {
            target: "net10.0/win-x64".into(),
            id: "Transitive".into(),
            version: "2.0.0".into(),
            direct: false,
            dependencies: vec!["Missing/1.0.0".into()],
        },
        Package {
            target: "net10.0".into(),
            id: "Cycle.A".into(),
            version: "1.0.0".into(),
            direct: true,
            dependencies: vec!["Cycle.B/1.0.0".into()],
        },
        Package {
            target: "net10.0".into(),
            id: "Cycle.B".into(),
            version: "1.0.0".into(),
            direct: false,
            dependencies: vec!["Cycle.A/1.0.0".into()],
        },
    ];

    let routes = package_routes(&manifest, MEMORY).unwrap();
    let transitive = routes
        .iter()
        .find(|route| route.package == "Transitive/2.0.0")
        .unwrap();
    assert_eq!(
        transitive.shortest_route.as_deref(),
        Some(&["Direct/1.0.0".into(), "Transitive/2.0.0".into()][..])
    );
    assert_eq!(
        transitive.missing_dependencies,
        ["Missing/1.0.0".to_owned()]
    );
    assert!(
        routes
            .iter()
            .filter(|route| route.target == "net10.0")
            .all(|route| route.cyclic_target)
    );
}

#[test]
#[allow(clippy::too_many_lines)] // Cross-surface fixture and observable contract.
fn report_correlates_asserted_source_generator_package_and_resource_evidence() {
    let directory = tempfile::tempdir().unwrap();
    let generated = directory.path().join("Generated.g.cs");
    fs::write(&generated, "class Widget {}").unwrap();
    let generator = directory.path().join("Sample.Generator.dll");
    fs::write(&generator, b"generator evidence").unwrap();
    let hash = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    let identity = "Sample_Project_Widget__Run";
    let mut manifest = evidence();
    manifest.packages.push(Package {
        target: "net10.0".into(),
        id: "Package.One".into(),
        version: "1.0.0".into(),
        direct: true,
        dependencies: vec![],
    });
    manifest.assemblies.push(Assembly {
        name: "Sample.Project".into(),
        path: directory.path().join("Sample.Project.dll"),
        package: Some("Package.One/1.0.0".into()),
        types: vec![ManagedType {
            name: "Widget".into(),
            kind: "reference".into(),
            members: 1,
        }],
    });
    manifest
        .sources
        .push(source(generated.clone(), Some("Sample.Generator")));
    manifest.generators.push(Generator {
        name: "Sample.Generator".into(),
        version: "1.2.3".into(),
        assembly_path: generator,
        generated_files: vec![generated.clone()],
        input_symbols: vec!["Sample.Input".into()],
    });
    manifest.mappings.push(Mapping {
        stream: "Methods".into(),
        identity: identity.into(),
        assembly: "Sample.Project".into(),
        source_paths: vec![generated],
        basis: "synthetic exact mapping".into(),
    });
    for name in ["first.bin", "copy.bin"] {
        manifest.resources.push(Resource {
            assembly: "Sample.Project".into(),
            container: "assets".into(),
            name: name.into(),
            bytes: 3,
            sha256: Some(hash.into()),
            source_path: None,
            storage: "managed".into(),
        });
    }
    let manifest_path = write_manifest(directory.path(), &manifest, "evidence.json");
    let output = directory.path().join("index");
    import(&manifest_path, &output, MEMORY, false).unwrap();
    write_cached_identities(
        &output,
        &[CoalescedIdentity {
            stream: "Methods".into(),
            accounted: true,
            identity: identity.into(),
            raw_identity_blake3: "fixed".into(),
            identity_lossy: false,
            bytes: 123,
            records: 7,
        }],
    );

    let result = report(&output, MEMORY, 10, None).unwrap();
    assert_eq!(result.schema, "vitnet.attribution-report.v1");
    assert_eq!(result.accounted_mapping_bytes["asserted"], 123);
    assert_eq!(result.assembly_groups[0].name, "Sample.Project");
    assert_eq!(result.package_groups[0].name, "Package.One/1.0.0");
    assert_eq!(result.contributors[0].sources.status, "asserted");
    assert_eq!(result.contributors[0].sources.sources[0].line, 10);
    assert_eq!(result.generators[0].generated_declarations, 1);
    assert_eq!(result.generators[0].version, "1.2.3");
    assert_eq!(result.generators[0].generated_files, 1);
    assert_eq!(result.generators[0].declared_inputs, 1);
    assert_eq!(result.generators[0].candidate_accounted_bytes, 0);
    assert_eq!(result.generators[0].asserted_accounted_bytes, 123);
    assert_eq!(result.full_resource_asset_bytes, 6);
    assert_eq!(result.duplicate_assets[0].instances.len(), 2);

    let located = locate_source(&output, identity, MEMORY).unwrap();
    assert_eq!(located.schema, "vitnet.attribution-source.v1");
    assert_eq!(located.matches[0].status, "asserted");
    assert_eq!(located.related_files.len(), 1);
    assert_eq!(
        locate_source(&output, "missing", MEMORY)
            .unwrap_err()
            .diagnostic
            .code,
        "attribution.identity.missing"
    );
    assert_eq!(
        report(&output, MEMORY, 0, None)
            .unwrap_err()
            .diagnostic
            .code,
        "resource.memory_limit"
    );
}

#[test]
fn source_matching_keeps_asserted_ambiguous_candidate_and_unmapped_states_distinct() {
    let path = PathBuf::from("Widget.cs");
    let mut manifest = evidence();
    manifest.assemblies.push(Assembly {
        name: "Sample.Project".into(),
        path: "Sample.Project.dll".into(),
        package: None,
        types: vec![],
    });
    manifest.sources.push(source(path.clone(), None));
    manifest.mappings.extend([
        Mapping {
            stream: "Methods".into(),
            identity: "exact".into(),
            assembly: "Sample.Project".into(),
            source_paths: vec![path.clone()],
            basis: "PDB sequence point".into(),
        },
        Mapping {
            stream: "Methods".into(),
            identity: "ambiguous".into(),
            assembly: "Sample.Project".into(),
            source_paths: vec![path],
            basis: "first candidate".into(),
        },
        Mapping {
            stream: "Methods".into(),
            identity: "ambiguous".into(),
            assembly: "Other.Project".into(),
            source_paths: vec![],
            basis: "second candidate".into(),
        },
    ]);
    let matcher = Matcher::new(&manifest);

    assert_eq!(matcher.locate("Methods", "exact").status, "asserted");
    assert_eq!(matcher.locate("Methods", "ambiguous").status, "ambiguous");
    assert_eq!(
        matcher
            .locate("Methods", "Sample_Project_Widget__Run")
            .status,
        "producer_prefix_candidate"
    );
    assert_eq!(matcher.locate("Methods", "Unknown").status, "unmapped");
}

#[test]
fn retention_explanation_reuses_generation_and_preserves_original_witnesses() {
    let directory = tempfile::tempdir().unwrap();
    let graph = directory.path().join("graph.xml");
    fs::write(
        &graph,
        br#"<DirectedGraph><Nodes><Node Id="0" Label="root"/><Node Id="1" Label="Sample_Project_Widget__Run"/></Nodes><Links><Link Source="0" Target="1" Reason="call"/></Links></DirectedGraph>"#,
    )
    .unwrap();
    let graph_index = build_index(
        &graph,
        &IndexOptions {
            cache_root: directory.path().join("cache"),
            memory_limit: 16 << 20,
            selected_entry: None,
            strict_hash: false,
            control: IndexControl::default(),
        },
    )
    .unwrap()
    .index_directory;
    let source_path = directory.path().join("Widget.cs");
    fs::write(&source_path, "class Widget {}").unwrap();
    let mut manifest = evidence();
    manifest.artifacts.push(Artifact {
        kind: "scan_index".into(),
        path: graph_index,
        revision: None,
        blake3: None,
    });
    manifest.sources.push(source(source_path.clone(), None));
    manifest.mappings.push(Mapping {
        stream: "Methods".into(),
        identity: "Sample_Project_Widget__Run".into(),
        assembly: "Sample.Project".into(),
        source_paths: vec![source_path],
        basis: "synthetic exact mapping".into(),
    });
    let manifest_path = write_manifest(directory.path(), &manifest, "evidence.json");
    let output = directory.path().join("index");
    let imported = import(&manifest_path, &output, MEMORY, false).unwrap();
    let generation = imported
        .artifacts
        .iter()
        .find_map(|artifact| artifact.graph_generation.clone())
        .unwrap();

    let result = explain(
        &output,
        1,
        "scan_index",
        MEMORY,
        &WhyOptions {
            generation: Some(generation.clone()),
            ..WhyOptions::default()
        },
        10,
    )
    .unwrap();
    assert_eq!(result.witness.generation, generation);
    assert_eq!(result.witness.paths[0].nodes[0].node_id, 0);
    assert_eq!(result.witness.paths[0].nodes[1].node_id, 1);
    assert_eq!(result.witness.paths[0].reasons, ["call"]);
    assert_eq!(
        result.annotated_paths[0].anchors[0].sources.status,
        "asserted"
    );
    assert_eq!(result.alternative_incoming.total_edges, 1);
    assert_eq!(
        explain(
            &output,
            1,
            "unknown_index",
            MEMORY,
            &WhyOptions::default(),
            10,
        )
        .unwrap_err()
        .diagnostic
        .code,
        "attribution.graph.kind"
    );
    assert_eq!(
        explain(
            &output,
            1,
            "scan_index",
            MEMORY,
            &WhyOptions {
                generation: Some("stale-generation".into()),
                ..WhyOptions::default()
            },
            10,
        )
        .unwrap_err()
        .diagnostic
        .code,
        "attribution.graph.stale"
    );
}

#[test]
fn generic_shapes_preserve_nested_arguments_groups_and_invalid_syntax() {
    let shape = parse_shape("Map<String,List<Int32>>__Method<T,__Canon>")
        .unwrap()
        .unwrap();
    assert_eq!(shape.family, "Map<>__Method<>");
    assert_eq!(shape.arguments, ["String", "List<Int32>", "T", "__Canon"]);
    assert_eq!(shape.group_boundaries, [2, 4]);
    assert!(shape.canonical_shared);
    assert!(parse_shape("PlainType").unwrap().is_none());
    assert_eq!(
        parse_shape("Broken<").unwrap_err().diagnostic.code,
        "attribution.generic.syntax"
    );
}

#[test]
fn resource_duplicates_require_hash_and_consistent_lengths() {
    let hash = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    let resources = vec![
        Resource {
            assembly: "A".into(),
            container: "one".into(),
            name: "first".into(),
            bytes: 3,
            sha256: Some(hash.into()),
            source_path: None,
            storage: "managed".into(),
        },
        Resource {
            assembly: "B".into(),
            container: "two".into(),
            name: "second".into(),
            bytes: 3,
            sha256: Some(hash.into()),
            source_path: None,
            storage: "avalonia".into(),
        },
        Resource {
            assembly: "C".into(),
            container: "three".into(),
            name: "same length, unknown content".into(),
            bytes: 3,
            sha256: None,
            source_path: None,
            storage: "managed".into(),
        },
    ];
    let duplicates = asset_duplicates(&resources).unwrap();
    assert_eq!(duplicates.len(), 1);
    assert_eq!(duplicates[0].bytes_each, 3);
    assert_eq!(duplicates[0].instances.len(), 2);

    let mut inconsistent = resources;
    inconsistent[1].bytes = 4;
    assert_eq!(
        asset_duplicates(&inconsistent).unwrap_err().diagnostic.code,
        "attribution.resource.hash"
    );
}

#[test]
fn native_and_build_comparison_keep_signed_physical_virtual_and_unknown_states() {
    let before = Binary {
        path: "before.exe".into(),
        format: "PE".into(),
        architecture: "x64".into(),
        file_bytes: 1024,
        sections: vec![BinarySection {
            name: ".text".into(),
            file_bytes: 512,
            virtual_bytes: 600,
        }],
    };
    let after = Binary {
        path: "after.exe".into(),
        format: "PE".into(),
        architecture: "x64".into(),
        file_bytes: 1280,
        sections: vec![
            BinarySection {
                name: ".text".into(),
                file_bytes: 768,
                virtual_bytes: 900,
            },
            BinarySection {
                name: ".data".into(),
                file_bytes: 128,
                virtual_bytes: 64,
            },
        ],
    };
    let delta = physical_delta(Some(&before), Some(&after)).unwrap();
    assert_eq!(delta.delta_bytes, Some(256));
    assert_eq!(delta.sections[0].name, ".data");
    assert_eq!(delta.sections[0].file_delta_bytes, 128);
    assert_eq!(delta.sections[1].file_delta_bytes, 256);
    assert_eq!(delta.sections[1].virtual_delta_bytes, 300);
    assert_eq!(delta.compatible_architecture, Some(true));
    assert_eq!(
        physical_delta(Some(&before), None).unwrap().delta_bytes,
        None
    );

    let changes = evidence_changes(
        &BTreeMap::from([("configuration".into(), "Debug".into())]),
        &BTreeMap::from([
            ("configuration".into(), "Release".into()),
            ("rid".into(), "win-x64".into()),
        ]),
    );
    assert_eq!(changes.len(), 2);
    assert_eq!(changes[0].key, "configuration");
    assert_eq!(changes[0].before.as_deref(), Some("Debug"));
    assert_eq!(changes[0].after.as_deref(), Some("Release"));
    assert_eq!(changes[1].before, None);

    let directory = tempfile::tempdir().unwrap();
    let unsupported = directory.path().join("native.bin");
    fs::write(&unsupported, b"not a PE image").unwrap();
    assert_eq!(
        read_pe_binary(&unsupported).unwrap_err().diagnostic.code,
        "attribution.io"
    );

    let overflowing = Binary {
        sections: vec![
            BinarySection {
                name: ".text".into(),
                file_bytes: u64::MAX,
                virtual_bytes: 1,
            },
            BinarySection {
                name: ".text".into(),
                file_bytes: 1,
                virtual_bytes: 1,
            },
        ],
        ..before
    };
    assert_eq!(
        physical_delta(Some(&overflowing), Some(&after))
            .unwrap_err()
            .diagnostic
            .code,
        "attribution.size"
    );
}

#[test]
fn strict_import_rejects_mismatch_and_post_staging_failures_without_publishing_partial_indexes() {
    let directory = tempfile::tempdir().unwrap();
    let mstat = mstat_file(directory.path(), "valid.mstat", 13);
    let mut manifest = evidence();
    let mut input = artifact("mstat", mstat.clone());
    input.blake3 = Some(vitnet_attribution::hash_file(&mstat).unwrap().1);
    manifest.artifacts.push(input);
    let committed = directory.path().join("committed");
    let path = write_manifest(directory.path(), &manifest, "strict.json");
    let index = import(&path, &committed, MEMORY, true).unwrap();
    assert!(index.diagnostics.is_empty());
    assert_eq!(index.artifacts[0].matches_expected, Some(true));
    assert_eq!(index.mstat.as_ref().unwrap().accounted_size_bytes, 20);
    let committed_bytes = fs::read(committed.join("index.json")).unwrap();
    manifest.artifacts[0].blake3 = Some("0".repeat(64));
    let path = write_manifest(directory.path(), &manifest, "mismatch.json");
    let permissive = import(&path, &directory.path().join("permissive"), MEMORY, false).unwrap();
    assert_eq!(permissive.artifacts[0].matches_expected, Some(false));
    assert_eq!(
        permissive.diagnostics[0].code,
        "evidence.fingerprint.mismatch"
    );
    assert_eq!(
        permissive.diagnostics[0].path.as_deref(),
        Some(mstat.as_path())
    );
    let rejected = directory.path().join("strict-rejected");
    assert_eq!(
        import(&path, &rejected, MEMORY, true)
            .unwrap_err()
            .diagnostic
            .code,
        "attribution.evidence.incomplete"
    );
    assert!(!rejected.exists());
    manifest.artifacts[0].blake3 = None;
    manifest
        .provenance
        .insert("source_revision".into(), "new".into());
    manifest.artifacts[0].revision = Some("old".into());
    let path = write_manifest(directory.path(), &manifest, "revision.json");
    assert_eq!(
        import(&path, &rejected, MEMORY, true)
            .unwrap_err()
            .diagnostic
            .code,
        "attribution.evidence.incomplete"
    );
    let absent = write_manifest(directory.path(), &evidence(), "absent.json");
    assert_eq!(
        import(&absent, &rejected, MEMORY, true)
            .unwrap_err()
            .diagnostic
            .code,
        "attribution.evidence.incomplete"
    );
    // Metadata/MSTAT decoding occurs after creating temporary identities.ndjson.
    // A malformed input must remove that staging directory, not just prevalidate.
    let bad = directory.path().join("invalid.mstat");
    fs::write(&bad, b"invalid").unwrap();
    manifest.artifacts = vec![artifact("mstat", bad)];
    manifest.provenance.clear();
    let path = write_manifest(directory.path(), &manifest, "invalid.json");
    assert!(
        import(&path, &rejected, MEMORY, false)
            .unwrap_err()
            .diagnostic
            .code
            .starts_with("mstat.")
    );
    assert!(!rejected.exists());
    assert!(fs::read_dir(directory.path()).unwrap().all(|entry| {
        !entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(".vitnet-attribution-")
    }));
    assert_eq!(
        fs::read(committed.join("index.json")).unwrap(),
        committed_bytes
    );
    assert_eq!(open_index(&committed, MEMORY).unwrap().identities, 2);
}

#[test]
fn manifest_and_cache_row_budgets_honor_exact_caps_and_cleanup_failed_publication() {
    let directory = tempfile::tempdir().unwrap();
    let json = write_manifest(directory.path(), &evidence(), "small.json");
    let length = fs::metadata(&json).unwrap().len();
    let value: Evidence = vitnet_attribution::read_json(&json, length * 8).unwrap();
    assert_eq!(value.label, "synthetic build");
    assert_eq!(
        vitnet_attribution::read_json::<Evidence>(&json, length * 8 - 1)
            .unwrap_err()
            .diagnostic
            .code,
        "resource.memory_limit"
    );
    let output = directory.path().join("index");
    import(&json, &output, MEMORY, false).unwrap();
    let index = write_cached_identities(
        &output,
        &[CoalescedIdentity {
            stream: "Methods".into(),
            accounted: true,
            identity: "boundary".into(),
            raw_identity_blake3: "raw".into(),
            identity_lossy: false,
            bytes: 13,
            records: 2,
        }],
    );
    let row_bytes = fs::metadata(output.join("identities.ndjson"))
        .unwrap()
        .len();
    let mut actual = Vec::new();
    visit_identities(&output, &index, row_bytes * 64, |row| {
        actual.push((row.identity.clone(), row.bytes, row.records));
        Ok(())
    })
    .unwrap();
    assert_eq!(actual, [("boundary".into(), 13, 2)]);
    let mut visited = 0;
    assert_eq!(
        visit_identities(&output, &index, row_bytes * 64 - 1, |_| {
            visited += 1;
            Ok(())
        })
        .unwrap_err()
        .diagnostic
        .code,
        "resource.memory_limit"
    );
    assert_eq!(visited, 0);
    let minimum = 16 << 20;
    assert_eq!(
        import(
            &json,
            &directory.path().join("under-minimum"),
            minimum - 1,
            false
        )
        .unwrap_err()
        .diagnostic
        .code,
        "resource.memory_limit"
    );
    let mut large = evidence();
    let base = serde_json::to_vec(&large).unwrap().len();
    large
        .label
        .push_str(&"x".repeat((minimum / 8) as usize - base));
    let large_path = directory.path().join("large.json");
    fs::write(&large_path, serde_json::to_vec(&large).unwrap()).unwrap();
    assert_eq!(fs::metadata(&large_path).unwrap().len(), minimum / 8);
    let failed = directory.path().join("failed");
    let error = import(&large_path, &failed, minimum, false).unwrap_err();
    assert_eq!(error.diagnostic.code, "resource.memory_limit");
    assert!(error.diagnostic.message.contains("persisted evidence"));
    assert!(!failed.exists());
    // Control-character name fits the raw visitor cap but six-byte JSON escapes
    // exceed the persisted row cap.
    let mut image = common::Image::new();
    image.method(&vec![1; 50_000], 1);
    let mstat = directory.path().join("escaped.mstat");
    fs::write(&mstat, image.bytes()).unwrap();
    let mut escaped = evidence();
    escaped.artifacts.push(artifact("mstat", mstat));
    let path = write_manifest(directory.path(), &escaped, "escaped.json");
    let error = import(&path, &failed, minimum, false).unwrap_err();
    assert_eq!(error.diagnostic.code, "resource.memory_limit");
    assert!(
        error.diagnostic.message.contains("serialized identity"),
        "{error}"
    );
    assert!(!failed.exists());
    assert!(fs::read_dir(directory.path()).unwrap().all(|entry| {
        !entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(".vitnet-attribution-")
    }));
}

fn package(target: &str, id: &str, direct: bool, dependencies: &[&str]) -> Package {
    Package {
        target: target.into(),
        id: id.into(),
        version: "1".into(),
        direct,
        dependencies: dependencies.iter().map(|item| (*item).into()).collect(),
    }
}

#[test]
fn bounded_package_routes_preserve_target_diamonds_unreachable_and_long_chain_limits() {
    assert!(package_routes(&evidence(), 0).unwrap().is_empty());
    let mut manifest = evidence();
    manifest
        .packages
        .push(package("net10.0", "Root", true, &[]));
    // One materialized string "Root/1" plus 32 bytes bookkeeping.
    let exact = (6 + 32) * 8;
    let route = package_routes(&manifest, exact).unwrap();
    assert_eq!(route[0].shortest_route.as_ref().unwrap(), &["Root/1"]);
    assert!(route[0].direct);
    assert_eq!(
        package_routes(&manifest, exact - 1)
            .unwrap_err()
            .diagnostic
            .code,
        "resource.memory_limit"
    );
    manifest.packages = vec![
        package("net10.0", "Root", true, &["Left/1", "Right/1"]),
        package("net10.0", "Left", false, &["Leaf/1"]),
        package("net10.0", "Right", false, &["Leaf/1"]),
        package("net10.0", "Leaf", false, &[]),
        package("net10.0", "Orphan", false, &[]),
        package("net10.0/win-x64", "Leaf", true, &[]),
    ];
    let routes = package_routes(&manifest, MEMORY).unwrap();
    let leaf = routes
        .iter()
        .find(|r| r.target == "net10.0" && r.package == "Leaf/1")
        .unwrap();
    assert_eq!(
        leaf.shortest_route.as_ref().unwrap(),
        &["Root/1", "Left/1", "Leaf/1"]
    );
    assert_eq!(leaf.retained_by_packages, ["Left/1", "Right/1"]);
    assert!(!leaf.cyclic_target);
    let orphan = routes.iter().find(|r| r.package == "Orphan/1").unwrap();
    assert!(orphan.shortest_route.is_none());
    assert_eq!(orphan.retained_by_packages, Vec::<String>::new());
    let rid_leaf = routes
        .iter()
        .find(|r| r.target == "net10.0/win-x64")
        .unwrap();
    assert_eq!(rid_leaf.shortest_route.as_ref().unwrap(), &["Leaf/1"]);
    assert_eq!(rid_leaf.retained_by_packages, Vec::<String>::new());
    let expected = serde_json::to_value(&routes).unwrap();
    manifest.packages.reverse();
    assert_eq!(
        serde_json::to_value(package_routes(&manifest, MEMORY).unwrap()).unwrap(),
        expected
    );
    manifest.packages = (0..2000)
        .map(|i| Package {
            target: "net10.0".into(),
            id: format!("P{i:04}"),
            version: "1".into(),
            direct: i == 0,
            dependencies: if i == 1999 {
                vec![]
            } else {
                vec![format!("P{:04}/1", i + 1)]
            },
        })
        .collect();
    let error = package_routes(&manifest, 4096).unwrap_err();
    assert_eq!(error.diagnostic.code, "resource.memory_limit");
    assert!(error.diagnostic.message.contains("package route"));
}

#[test]
fn metadata_type_source_joins_keep_partials_assembly_and_member_boundaries() {
    let directory = tempfile::tempdir().unwrap();
    let csv = directory.path().join("metadata.csv");
    fs::write(&csv, b"Handle, Kind, Name, Children\n00000000, ScopeDefinition, \"Sample.Project\", \"a 1e\"\n0000000a, TypeDefinition, \"Widget\", \"14\"\n00000014, Method, \"Run\", \"\"\n0000001e, TypeDefinition, \"Absent\", \"\"\n00000028, End, \"\", \"\"\n").unwrap();
    let mut manifest = evidence();
    manifest.artifacts.push(artifact("metadata", csv));
    for (name, assembly, member) in [
        ("first.cs", "Sample.Project", None),
        ("second.cs", "Sample.Project", None),
        ("method.cs", "Sample.Project", Some("Run()")),
        ("other.cs", "Other.Project", None),
    ] {
        let path = directory.path().join(name);
        fs::write(&path, "class Widget {}").unwrap();
        manifest.sources.push(Source {
            assembly: assembly.into(),
            member: member.map(str::to_owned),
            kind: if member.is_none() { "class" } else { "method" }.into(),
            ..source(path, None)
        });
    }

    let output = directory.path().join("index");
    import(
        &write_manifest(directory.path(), &manifest, "metadata.json"),
        &output,
        MEMORY,
        false,
    )
    .unwrap();
    let result = report(&output, MEMORY, 10, None).unwrap();
    assert_eq!(result.metadata_lower_bound_bytes, Some(40));
    let widget = result
        .metadata_type_sources
        .iter()
        .find(|r| r.qualified_type == "Sample.Project!Widget")
        .unwrap();
    assert_eq!(widget.lower_bound_bytes, 20);
    assert_eq!(widget.status, "managed_type_name_match");
    assert_eq!(
        widget
            .sources
            .iter()
            .map(|s| s.path.file_name().unwrap().to_str().unwrap())
            .collect::<Vec<_>>(),
        ["first.cs", "second.cs"]
    );
    let absent = result
        .metadata_type_sources
        .iter()
        .find(|r| r.qualified_type == "Sample.Project!Absent")
        .unwrap();
    assert_eq!(absent.lower_bound_bytes, 10);
    assert_eq!(absent.status, "unmapped");
    assert!(absent.sources.is_empty());
    let matcher = Matcher::new(&manifest);
    let candidate = matcher.locate("Methods", "Sample_Project_Widget__Run");
    assert_eq!(candidate.status, "producer_prefix_candidate");
    assert_eq!(candidate.sources.len(), 1);
    assert_eq!(candidate.sources[0].member.as_deref(), Some("Run()"));
    write_cached_identities(
        &output,
        &[CoalescedIdentity {
            stream: "Methods".into(),
            accounted: true,
            identity: "Sample_Project_Widget__Run".into(),
            raw_identity_blake3: "raw".into(),
            identity_lossy: false,
            bytes: 5,
            records: 1,
        }],
    );
    // Only related source drift is surfaced by source query, not unrelated files.
    fs::write(
        directory.path().join("method.cs"),
        "class Widget { void Run(){} }",
    )
    .unwrap();
    fs::write(
        directory.path().join("other.cs"),
        "unrelated changed source",
    )
    .unwrap();
    let located = locate_source(&output, "Sample_Project_Widget__Run", MEMORY).unwrap();
    assert_eq!(located.matches[0].status, "producer_prefix_candidate");
    assert_eq!(located.diagnostics.len(), 1);
    assert_eq!(located.diagnostics[0].code, "evidence.artifact.stale");
    assert_eq!(
        located.diagnostics[0].path,
        Some(directory.path().join("method.cs"))
    );
}

#[test]
#[allow(clippy::too_many_lines)] // Fixed shape partitions plus exact boundary checks.
fn generic_reports_keep_group_boundaries_type_collisions_and_usage_distinct() {
    let directory = tempfile::tempdir().unwrap();
    let mut manifest = evidence();
    manifest.assemblies.push(Assembly {
        name: "A".into(),
        path: directory.path().join("A.dll"),
        package: None,
        types: [
            ("V", "value"),
            ("R", "reference"),
            ("E", "enum"),
            ("N.T", "value"),
            ("N_T", "reference"),
        ]
        .map(|(name, kind)| ManagedType {
            name: name.into(),
            kind: kind.into(),
            members: 0,
        })
        .to_vec(),
    });
    let output = directory.path().join("index");
    import(
        &write_manifest(directory.path(), &manifest, "shapes.json"),
        &output,
        MEMORY,
        false,
    )
    .unwrap();
    let rows = [
        ("Methods", "F<A_V,A_R>__M<A_E>", 10, 5),
        ("Methods", "F<A_V__A_R>__M<A_E>", 20, 7),
        ("Methods", "F<A_V>__M<A_R,A_E>", 30, 1),
        ("Methods", "F<__Canon,A_N_T>__M<A_Unknown>", 40, 1),
        ("Types", "F<A_V,A_R>__M<A_E>", 50, 1),
        ("Methods", "Broken<", 3, 1),
    ]
    .map(|(stream, identity, bytes, records)| CoalescedIdentity {
        stream: stream.into(),
        accounted: true,
        identity: identity.into(),
        raw_identity_blake3: blake3::hash(identity.as_bytes()).to_hex().to_string(),
        identity_lossy: false,
        bytes,
        records,
    });
    write_cached_identities(&output, &rows);
    let result = report(&output, MEMORY, 10, None).unwrap();
    let methods = result
        .generic_families
        .iter()
        .find(|g| g.stream == "Methods")
        .unwrap();
    assert_eq!(methods.family, "F<>__M<>");
    assert_eq!(methods.bytes, 100);
    assert_eq!(methods.producer_identities, 4);
    assert_eq!(methods.distinct_shapes, 3);
    assert_eq!(methods.canonical_shared_shapes, 1);
    assert_eq!(
        methods.argument_kinds,
        BTreeMap::from([
            ("value".into(), 2),
            ("reference".into(), 2),
            ("enum".into(), 2),
            ("canonical_shared".into(), 1),
            ("ambiguous".into(), 1),
            ("unknown".into(), 1),
        ])
    );
    let types = result
        .generic_families
        .iter()
        .find(|g| g.stream == "Types")
        .unwrap();
    assert_eq!(
        (
            types.bytes,
            types.distinct_shapes,
            types.producer_identities
        ),
        (50, 1, 1)
    );
    assert_eq!(result.malformed_generic_identities, 1);
    let shape64 = format!("{}V{}", "F<".repeat(64), ">".repeat(64));
    assert_eq!(
        parse_shape(&shape64).unwrap().unwrap().group_boundaries,
        [1]
    );
    let shape65 = format!("{}V{}", "F<".repeat(65), ">".repeat(65));
    assert_eq!(
        parse_shape(&shape65).unwrap_err().diagnostic.code,
        "attribution.generic.depth"
    );
    assert!(parse_shape(&"x".repeat(1 << 20)).unwrap().is_none());
    assert_eq!(
        parse_shape(&"x".repeat((1 << 20) + 1))
            .unwrap_err()
            .diagnostic
            .code,
        "resource.memory_limit"
    );
    for malformed in ["F<>", "F<V,>", "F<,V>", "F<V>>", "F<V>__M<"] {
        assert_eq!(
            parse_shape(malformed).unwrap_err().diagnostic.code,
            "attribution.generic.syntax",
            "{malformed}"
        );
    }
}

#[test]
fn report_top_bounds_keep_complete_counts_and_separate_resource_containers() {
    let directory = tempfile::tempdir().unwrap();
    let mut manifest = evidence();
    manifest.packages = vec![
        package("net10.0", "First", true, &[]),
        package("net10.0", "Second", true, &[]),
    ];
    for name in ["First", "Second"] {
        manifest.generators.push(Generator {
            name: name.into(),
            version: "1".into(),
            assembly_path: directory.path().join(format!("{name}.dll")),
            generated_files: vec![],
            input_symbols: vec![],
        });
    }
    for (name, bytes, hash, storage) in [
        ("container", 100, None, "manifest_container"),
        ("a", 3, Some("a".repeat(64)), "avalonia_asset"),
        ("b", 3, Some("a".repeat(64)), "avalonia_asset"),
        ("c", 4, Some("b".repeat(64)), "resources_serialized"),
        ("d", 4, Some("b".repeat(64)), "resources_serialized"),
    ] {
        manifest.resources.push(Resource {
            name: name.into(),
            bytes,
            sha256: hash,
            assembly: "A".into(),
            container: "container".into(),
            storage: storage.into(),
            source_path: None,
        });
    }
    let output = directory.path().join("index");
    import(
        &write_manifest(directory.path(), &manifest, "top.json"),
        &output,
        MEMORY,
        false,
    )
    .unwrap();
    write_cached_identities(
        &output,
        &[
            CoalescedIdentity {
                stream: "Methods".into(),
                accounted: true,
                identity: "unknown".into(),
                raw_identity_blake3: "method".into(),
                identity_lossy: false,
                bytes: 30,
                records: 1,
            },
            CoalescedIdentity {
                stream: "Blobs".into(),
                accounted: true,
                identity: "blob".into(),
                raw_identity_blake3: "blob".into(),
                identity_lossy: false,
                bytes: 40,
                records: 1,
            },
        ],
    );
    let result = report(&output, MEMORY, 1, Some("nothing")).unwrap();
    assert_eq!(result.accounted_mapping_bytes["unmapped"], 70);
    assert_eq!(result.assembly_groups[0].bytes, 70);
    assert_eq!(result.assembly_groups[0].identities, 2);
    assert_eq!(result.full_resource_asset_bytes, 14);
    assert_eq!(result.full_resource_container_bytes, 100);
    assert_eq!(result.displayed_resource_bytes, 100);
    assert_eq!(result.resources.len(), 1);
    assert_eq!(result.package_route_count, 2);
    assert_eq!(result.package_routes.len(), 1);
    assert_eq!(result.generator_count, 2);
    assert_eq!(result.generators.len(), 1);
    assert_eq!(result.generators[0].asserted_accounted_bytes, 0);
    assert_eq!(result.generators[0].candidate_accounted_bytes, 0);
    assert_eq!(result.duplicate_asset_group_count, 2);
    assert_eq!(result.duplicate_assets.len(), 1);
    assert_eq!(result.duplicate_assets[0].instance_count, 2);
    assert_eq!(result.duplicate_assets[0].instances.len(), 1);
    assert!(result.contributors.is_empty());
    assert_eq!(result.accounted_bytes, None);
}

fn graph_bundle(directory: &Path, name: &str, xml: &str) -> (PathBuf, String) {
    let path = directory.join(format!("{name}.dgml"));
    fs::write(&path, xml).unwrap();
    let graph = build_index(
        &path,
        &IndexOptions {
            cache_root: directory.join(format!("{name}-cache")),
            memory_limit: 16 << 20,
            selected_entry: None,
            strict_hash: false,
            control: IndexControl::default(),
        },
    )
    .unwrap();
    let mut manifest = evidence();
    manifest
        .artifacts
        .push(artifact("scan_index", graph.index_directory));
    let source_path = directory.join(format!("{name}.cs"));
    fs::write(&source_path, "class Widget {}").unwrap();
    manifest.sources.push(source(source_path.clone(), None));
    manifest.mappings.push(Mapping {
        stream: "Methods".into(),
        identity: "target".into(),
        assembly: "Sample.Project".into(),
        source_paths: vec![source_path],
        basis: "synthetic selected identity".into(),
    });
    let output = directory.join(name);
    import(
        &write_manifest(directory, &manifest, &format!("{name}.json")),
        &output,
        MEMORY,
        false,
    )
    .unwrap();
    (output, graph.generation)
}

#[test]
#[allow(clippy::too_many_lines)] // Separate selected graph fixtures and preserved witnesses.
fn selected_retention_compare_preserves_before_after_generations_reasons_and_incoming_deltas() {
    let directory = tempfile::tempdir().unwrap();
    let (before, before_generation) = graph_bundle(
        directory.path(),
        "before-graph",
        r#"<DirectedGraph><Nodes><Node Id="0" Label="root"/><Node Id="1" Label="target"/></Nodes><Links><Link Source="0" Target="1" Reason="before call"/></Links></DirectedGraph>"#,
    );
    let (after, after_generation) = graph_bundle(
        directory.path(),
        "after-graph",
        r#"<DirectedGraph><Nodes><Node Id="10" Label="root"/><Node Id="11" Label="alternate"/><Node Id="9" Label="target"/></Nodes><Links><Link Source="10" Target="9" Reason="after call"/><Link Source="11" Target="9" Reason="alternate reason"/></Links></DirectedGraph>"#,
    );
    let before_bytes = fs::read(before.join("index.json")).unwrap();
    let after_bytes = fs::read(after.join("index.json")).unwrap();
    let base = compare(&before, &after, MEMORY, 10).unwrap();
    assert!(base.retention.is_none());
    assert_eq!(base.graph_generation_changes.len(), 1);
    assert_eq!(base.graph_generation_changes[0].key, "scan_index");
    assert_eq!(
        base.graph_generation_changes[0].before.as_ref(),
        Some(&before_generation)
    );
    assert_eq!(
        base.graph_generation_changes[0].after.as_ref(),
        Some(&after_generation)
    );
    for _ in 0..2 {
        let result = compare_retention(
            &before,
            &after,
            1,
            9,
            "scan_index",
            MEMORY,
            &WhyOptions::default(),
        )
        .unwrap();
        assert_eq!(result.before.witness.generation, before_generation);
        assert_eq!(result.after.witness.generation, after_generation);
        assert_eq!(result.before_incoming_edges, 1);
        assert_eq!(result.after_incoming_edges, 2);
        assert_eq!(result.incoming_edge_delta, 1);
        assert_eq!(
            result.before.witness.paths[0]
                .nodes
                .iter()
                .map(|n| n.node_id)
                .collect::<Vec<_>>(),
            [0, 1]
        );
        assert_eq!(result.before.witness.paths[0].reasons, ["before call"]);
        let mut reasons: Vec<_> = result
            .after
            .witness
            .paths
            .iter()
            .flat_map(|p| &p.reasons)
            .cloned()
            .collect();
        reasons.sort();
        assert_eq!(reasons, ["after call", "alternate reason"]);
        assert!(
            result
                .after
                .witness
                .paths
                .iter()
                .all(|p| p.nodes.last().unwrap().node_id == 9)
        );
        assert_eq!(
            result.before.annotated_paths[0].anchors[0].sources.status,
            "asserted"
        );
        assert_eq!(
            result.before.annotated_paths[0].anchors[0].sources.sources[0].path,
            directory.path().join("before-graph.cs")
        );
        assert!(
            result
                .caveat
                .contains("user-supplied cross-build correspondences")
        );
    }
    assert_eq!(fs::read(before.join("index.json")).unwrap(), before_bytes);
    assert_eq!(fs::read(after.join("index.json")).unwrap(), after_bytes);
    let reverse = compare_retention(
        &after,
        &before,
        9,
        1,
        "scan_index",
        MEMORY,
        &WhyOptions::default(),
    )
    .unwrap();
    assert_eq!(reverse.incoming_edge_delta, -1);
    assert_eq!(
        compare_retention(
            &before,
            &after,
            1,
            9,
            "scan_index",
            MEMORY,
            &WhyOptions {
                generation: Some("wrong".into()),
                ..WhyOptions::default()
            }
        )
        .unwrap_err()
        .diagnostic
        .code,
        "attribution.graph.stale"
    );
    assert_eq!(
        compare_retention(
            &before,
            &after,
            999,
            9,
            "scan_index",
            MEMORY,
            &WhyOptions::default()
        )
        .unwrap_err()
        .diagnostic
        .code,
        "dgml.query.node"
    );
}

#[test]
fn current_source_and_recorded_binlog_revision_mismatches_preserve_both_facts() {
    let directory = tempfile::tempdir().unwrap();
    let mut manifest = evidence();
    manifest.artifacts.push(artifact(
        "mstat",
        mstat_file(directory.path(), "revision.mstat", 1),
    ));
    manifest.provenance.insert(
        "source.current_revision:synthetic-root".into(),
        "new".into(),
    );
    manifest.provenance.insert(
        "binlog.property:synthetic-project:SourceRevisionId".into(),
        "old".into(),
    );
    let path = write_manifest(directory.path(), &manifest, "revision-facts.json");
    let result = import(&path, &directory.path().join("permissive"), MEMORY, false).unwrap();
    assert_eq!(
        result.evidence.provenance["source.current_revision:synthetic-root"],
        "new"
    );
    assert_eq!(
        result.evidence.provenance["binlog.property:synthetic-project:SourceRevisionId"],
        "old"
    );
    assert_eq!(
        result
            .diagnostics
            .iter()
            .filter(|d| d.code == "evidence.revision.mismatch")
            .count(),
        1
    );
    assert_eq!(
        import(&path, &directory.path().join("strict"), MEMORY, true)
            .unwrap_err()
            .diagnostic
            .code,
        "attribution.evidence.incomplete"
    );
    manifest.provenance.insert(
        "binlog.property:synthetic-project:SourceRevisionId".into(),
        "new".into(),
    );
    let path = write_manifest(directory.path(), &manifest, "matching-revisions.json");
    assert!(
        import(&path, &directory.path().join("matching"), MEMORY, true)
            .unwrap()
            .diagnostics
            .is_empty()
    );
}

#[test]
fn multi_manifest_target_namespaces_survive_import_without_merging_project_routes() {
    let directory = tempfile::tempdir().unwrap();
    let first = format!(
        "{}::net10.0/win-x64",
        directory.path().join("first.assets.json").display()
    );
    let second = format!(
        "{}::net10.0/win-x64",
        directory.path().join("second.assets.json").display()
    );
    let mut manifest = evidence();
    manifest.packages = vec![
        package(&first, "Direct", true, &["Leaf/1"]),
        package(&first, "Leaf", false, &[]),
        package(
            &second,
            "Direct",
            true,
            &["Leaf/1", "unresolved:Missing/[3.0.0]"],
        ),
        package(&second, "Leaf", false, &[]),
    ];
    let output = directory.path().join("index");
    let imported = import(
        &write_manifest(directory.path(), &manifest, "assets.json"),
        &output,
        MEMORY,
        false,
    )
    .unwrap();
    assert_eq!(imported.evidence.packages.len(), 4);
    let result = report(&output, MEMORY, 10, None).unwrap();
    assert_eq!(result.package_route_count, 4);
    let directs: Vec<_> = result
        .package_routes
        .iter()
        .filter(|r| r.package == "Direct/1")
        .collect();
    assert_eq!(directs.len(), 2);
    assert_eq!(directs[0].target, first);
    assert_eq!(directs[0].missing_dependencies, Vec::<String>::new());
    assert_eq!(directs[1].target, second);
    assert_eq!(
        directs[1].missing_dependencies,
        ["unresolved:Missing/[3.0.0]"]
    );
    assert!(result.package_routes.iter().all(|r| !r.cyclic_target));
    for leaf in result
        .package_routes
        .iter()
        .filter(|r| r.package == "Leaf/1")
    {
        assert_eq!(
            leaf.shortest_route.as_ref().unwrap(),
            &["Direct/1", "Leaf/1"]
        );
        assert_eq!(leaf.retained_by_packages, ["Direct/1"]);
    }
}

#[test]
fn source_prefix_collisions_and_overloads_remain_candidates_not_verified_joins() {
    let mut manifest = evidence();
    for (name, member) in [
        ("first.cs", "Run()"),
        ("second.cs", "Run(int)"),
        ("different.cs", "Other()"),
    ] {
        manifest.sources.push(Source {
            member: Some(member.into()),
            ..source(name.into(), None)
        });
    }
    let candidate = Matcher::new(&manifest).locate("Methods", "Sample_Project_Widget__Run");
    assert_eq!(candidate.status, "producer_prefix_candidate");
    assert_eq!(candidate.assemblies, ["Sample.Project"]);
    assert_eq!(
        candidate
            .sources
            .iter()
            .map(|s| s.member.as_deref().unwrap())
            .collect::<Vec<_>>(),
        ["Run()", "Run(int)"]
    );
    manifest.sources.push(Source {
        type_name: "Wid.get".into(),
        member: None,
        ..source("dotted.cs".into(), None)
    });
    manifest.sources.push(Source {
        type_name: "Wid_get".into(),
        member: None,
        ..source("underscored.cs".into(), None)
    });
    let ambiguous = Matcher::new(&manifest).locate("Types", "Sample_Project_Wid_get");
    assert_eq!(ambiguous.status, "ambiguous");
    assert_eq!(
        ambiguous
            .sources
            .iter()
            .map(|s| s.type_name.as_str())
            .collect::<Vec<_>>(),
        ["Wid.get", "Wid_get"]
    );
}

#[test]
fn compare_missing_and_multiple_native_inputs_never_invent_zero_physical_savings() {
    let directory = tempfile::tempdir().unwrap();
    let empty = write_manifest(directory.path(), &evidence(), "empty.json");
    let before = directory.path().join("before");
    import(&empty, &before, MEMORY, false).unwrap();
    let result = compare(&before, &before, MEMORY, 1).unwrap();
    assert!(result.mstat.is_none());
    assert!(result.metadata.is_none());
    assert_eq!(result.physical.delta_bytes, None);
    assert_eq!(result.physical.before_bytes, None);
    assert!(result.physical.sections.is_empty());
    assert_eq!(
        result
            .diagnostics
            .iter()
            .filter(|d| d.code == "evidence.compare.mstat.missing")
            .count(),
        1
    );
    let mut manifest = evidence();
    manifest.artifacts = vec![
        artifact(
            "binary",
            native_file(directory.path(), "one.exe", 512, 600, 0),
        ),
        artifact(
            "binary",
            native_file(directory.path(), "two.exe", 512, 900, 0),
        ),
    ];
    let after = directory.path().join("after");
    import(
        &write_manifest(directory.path(), &manifest, "two-native.json"),
        &after,
        MEMORY,
        false,
    )
    .unwrap();
    assert_eq!(
        compare(&before, &after, MEMORY, 1)
            .unwrap_err()
            .diagnostic
            .code,
        "attribution.compare.binary"
    );
}

#[test]
fn compare_projected_metadata_never_claims_complete_dimensions() {
    let directory = tempfile::tempdir().unwrap();
    let metadata = directory.path().join("metadata.csv");
    fs::write(&metadata, b"Handle, Kind, Name, Children\n00000000, ScopeDefinition, \"Sample.Project\", \"a 1e\"\n0000000a, TypeDefinition, \"Widget\", \"14\"\n00000014, Method, \"Run\", \"\"\n0000001e, TypeDefinition, \"Other\", \"\"\n00000028, End, \"\", \"\"\n").unwrap();
    let mut manifest = evidence();
    manifest.artifacts.push(artifact("metadata", metadata));
    let output = directory.path().join("index");
    let mut index = import(
        &write_manifest(directory.path(), &manifest, "projection.json"),
        &output,
        MEMORY,
        false,
    )
    .unwrap();
    let analysis = index.metadata.as_mut().unwrap();
    assert_eq!(analysis.by_type.len(), 2);
    analysis.by_type.truncate(1);
    analysis
        .concentration
        .get_mut("by_type")
        .unwrap()
        .reported_groups = 1;
    fs::write(
        output.join("index.json"),
        serde_json::to_vec(&index).unwrap(),
    )
    .unwrap();
    let result = compare(&output, &output, MEMORY, 10).unwrap();
    let metadata = result.metadata.unwrap();
    assert!(!metadata.complete_dimensions);
    assert_eq!(metadata.before_lower_bound_bytes, 40);
    assert_eq!(metadata.after_lower_bound_bytes, 40);
    assert_eq!(metadata.lower_bound_delta_bytes, 0);
    assert_eq!(metadata.by_type.entries.len(), 1);
    assert_eq!(metadata.by_type.entries[0].name, "Sample.Project!Widget");
    assert_eq!(metadata.by_type.entries[0].before_bytes, 20);
    assert_eq!(metadata.by_type.entries[0].after_bytes, 20);
    assert_eq!(metadata.by_type.entries[0].delta_bytes, 0);
}

#[test]
fn native_reader_honors_pe32_pe32plus_headers_and_adjacent_section_bounds() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("header.exe");
    for (magic, optional, machine, architecture) in [
        (0x10b_u16, 96_u16, 0x14c_u16, "x86"),
        (0x20b, 112, 0x8664, "x64"),
    ] {
        // Exact minimal header/table file: no section payload or application.
        let mut bytes = vec![0; 64 + 24 + optional as usize];
        bytes[..2].copy_from_slice(b"MZ");
        common::u32_at(&mut bytes, 60, 64);
        bytes[64..68].copy_from_slice(b"PE\0\0");
        bytes[68..70].copy_from_slice(&machine.to_le_bytes());
        bytes[84..86].copy_from_slice(&optional.to_le_bytes());
        bytes[88..90].copy_from_slice(&magic.to_le_bytes());
        fs::write(&path, &bytes).unwrap();
        let binary = read_pe_binary(&path).unwrap();
        assert_eq!(binary.architecture, architecture);
        assert_eq!(binary.file_bytes, 88 + u64::from(optional));
        assert!(binary.sections.is_empty());
        // The required optional header boundary is magic-specific.
        bytes[84..86].copy_from_slice(&(optional - 1).to_le_bytes());
        fs::write(&path, &bytes).unwrap();
        assert_eq!(
            read_pe_binary(&path).unwrap_err().diagnostic.code,
            "attribution.binary.format"
        );
        bytes[84..86].copy_from_slice(&optional.to_le_bytes());
        bytes[70..72].copy_from_slice(&1_u16.to_le_bytes());
        fs::write(&path, &bytes).unwrap();
        assert_eq!(
            read_pe_binary(&path).unwrap_err().diagnostic.code,
            "attribution.binary.section"
        );
        bytes[70..72].copy_from_slice(&4097_u16.to_le_bytes());
        fs::write(&path, &bytes).unwrap();
        assert_eq!(
            read_pe_binary(&path).unwrap_err().diagnostic.code,
            "resource.memory_limit"
        );
        common::u32_at(&mut bytes, 60, 63);
        fs::write(&path, &bytes).unwrap();
        assert_eq!(
            read_pe_binary(&path).unwrap_err().diagnostic.code,
            "attribution.binary.format"
        );
    }

    let path = native_file(directory.path(), "section.exe", 512, 600, 0);
    let binary = read_pe_binary(&path).unwrap();
    assert_eq!(binary.sections[0].file_bytes, 512);
    assert_eq!(binary.sections[0].virtual_bytes, 600);
    let mut bytes = fs::read(&path).unwrap();
    common::u32_at(&mut bytes, 0x18c, 513);
    fs::write(&path, &bytes).unwrap();
    assert_eq!(
        read_pe_binary(&path).unwrap_err().diagnostic.code,
        "attribution.binary.section"
    );
    bytes[0x98..0x9a].copy_from_slice(&0x107_u16.to_le_bytes());
    fs::write(&path, &bytes).unwrap();
    assert_eq!(
        read_pe_binary(&path).unwrap_err().diagnostic.code,
        "attribution.binary.format"
    );
    fs::write(&path, vec![0; 64]).unwrap();
    assert_eq!(
        read_pe_binary(&path).unwrap_err().diagnostic.code,
        "attribution.binary.format"
    );
}

#[test]
fn annotated_graph_limits_preserve_stops_and_never_assert_truncated_source_labels() {
    let directory = tempfile::tempdir().unwrap();
    let (index, generation) = graph_bundle(
        directory.path(),
        "bounded",
        r#"<DirectedGraph><Nodes><Node Id="0" Label="root"/><Node Id="1" Label="intermediate"/><Node Id="2" Label="target"/></Nodes><Links><Link Source="0" Target="1" Reason="root call"/><Link Source="1" Target="2" Reason="target call"/></Links></DirectedGraph>"#,
    );
    for (options, stop) in [
        (
            WhyOptions {
                max_depth: 0,
                ..WhyOptions::default()
            },
            "max_depth",
        ),
        (
            WhyOptions {
                max_visited: 1,
                ..WhyOptions::default()
            },
            "max_visited",
        ),
        (
            WhyOptions {
                max_edges: 1,
                ..WhyOptions::default()
            },
            "max_edges",
        ),
    ] {
        let result = explain(&index, 2, "scan_index", MEMORY, &options, 1).unwrap();
        assert_eq!(result.witness.stop_reason, stop);
        assert_eq!(result.witness.generation, generation);
        assert_eq!(result.alternative_incoming.total_edges, 1);
        assert_eq!(result.alternative_incoming.edges[0].source_id, 1);
    }
    let full = explain(&index, 2, "scan_index", MEMORY, &WhyOptions::default(), 1).unwrap();
    assert_eq!(full.witness.stop_reason, "complete");
    assert_eq!(full.witness.paths[0].reasons, ["root call", "target call"]);
    assert_eq!(
        full.annotated_paths[0].anchors[0].sources.status,
        "asserted"
    );
    let preview = explain(
        &index,
        2,
        "scan_index",
        MEMORY,
        &WhyOptions {
            preview_bytes: 3,
            ..WhyOptions::default()
        },
        1,
    )
    .unwrap();
    assert_eq!(preview.witness.node.label, "tar");
    assert!(preview.witness.node.truncated);
    assert!(preview.annotated_paths[0].anchors.is_empty());
    assert_eq!(preview.annotated_paths[0].collapsed_unmapped_nodes, 3);
    assert_eq!(
        preview.incoming_anchors[0].sources.status,
        "unmapped_truncated_label"
    );
    assert_eq!(preview.witness.paths[0].reason_bytes, [9, 11]);
    assert_eq!(preview.witness.paths[0].reasons_truncated, [true, true]);
}

#[test]
fn synthesized_nested_types_use_nearest_declared_parent_without_rewriting_identity_or_member() {
    let directory = tempfile::tempdir().unwrap();
    let metadata = directory.path().join("nested.csv");
    fs::write(&metadata, b"Handle, Kind, Name, Children\n00000000, ScopeDefinition, \"Sample.Project\", \"a 14 1e 28\"\n0000000a, TypeDefinition, \"N.Parent\", \"\"\n00000014, TypeDefinition, \"N.Parent+Declared\", \"\"\n0000001e, TypeDefinition, \"N.Parent+Declared+<Lambda>\", \"\"\n00000028, TypeDefinition, \"N.Absent+<Lambda>\", \"\"\n00000032, End, \"\", \"\"\n").unwrap();
    let mut manifest = evidence();
    manifest.artifacts.push(artifact("metadata", metadata));
    for (file, type_name, member) in [
        ("parent.cs", "N.Parent", None),
        ("declared.cs", "N.Parent+Declared", None),
        ("run.cs", "N.Parent+Declared", Some("Run()")),
        ("other-assembly.cs", "N.Parent+Declared+<Lambda>", None),
    ] {
        let path = directory.path().join(file);
        fs::write(&path, "namespace N; class Parent {}").unwrap();
        let assembly = if file == "other-assembly.cs" {
            "Other.Project"
        } else {
            "Sample.Project"
        };
        manifest.sources.push(Source {
            assembly: assembly.into(),
            type_name: type_name.into(),
            member: member.map(str::to_owned),
            kind: "class".into(),
            ..source(path, None)
        });
    }
    let output = directory.path().join("index");
    import(
        &write_manifest(directory.path(), &manifest, "nested.json"),
        &output,
        MEMORY,
        false,
    )
    .unwrap();
    let identity = "Sample_Project_N_Parent_Declared_CompilerNested__LambdaBody";
    write_cached_identities(
        &output,
        &[CoalescedIdentity {
            stream: "Methods".into(),
            accounted: true,
            identity: identity.into(),
            raw_identity_blake3: "synthetic".into(),
            identity_lossy: false,
            bytes: 13,
            records: 1,
        }],
    );
    let result = report(&output, MEMORY, 10, None).unwrap();
    let exact = result
        .metadata_type_sources
        .iter()
        .find(|s| s.qualified_type == "Sample.Project!N.Parent+Declared")
        .unwrap();
    assert_eq!(exact.status, "managed_type_name_match");
    let enclosing = result
        .metadata_type_sources
        .iter()
        .find(|s| s.qualified_type == "Sample.Project!N.Parent+Declared+<Lambda>")
        .unwrap();
    assert_eq!(enclosing.status, "managed_enclosing_type_name_match");
    assert_eq!(enclosing.lower_bound_bytes, 10);
    assert_eq!(enclosing.sources.len(), 1);
    assert_eq!(enclosing.sources[0].type_name, "N.Parent+Declared");
    assert_eq!(
        enclosing.sources[0].path,
        directory.path().join("declared.cs")
    );
    assert!(enclosing.sources[0].member.is_none());
    let missing = result
        .metadata_type_sources
        .iter()
        .find(|s| s.qualified_type == "Sample.Project!N.Absent+<Lambda>")
        .unwrap();
    assert_eq!(missing.status, "unmapped");
    assert!(missing.sources.is_empty());
    assert_eq!(result.contributors[0].identity, identity);
    let candidate = &result.contributors[0].sources;
    assert_eq!(candidate.status, "producer_prefix_candidate");
    assert_eq!(
        candidate.basis,
        "Nearest enclosing producer-name spelling candidate; not a verified nested/member join"
    );
    assert_eq!(candidate.sources.len(), 1);
    assert_eq!(candidate.sources[0].type_name, "N.Parent+Declared");
    assert!(candidate.sources[0].member.is_none());
    let located = locate_source(&output, identity, MEMORY).unwrap();
    assert_eq!(located.identity, identity);
    assert_eq!(located.contributors[0].identity, identity);
    assert_eq!(located.matches[0].basis, candidate.basis);
}

#[test]
fn current_source_revision_disagrees_with_recorded_source_root_without_losing_either_fact() {
    let directory = tempfile::tempdir().unwrap();
    let mut manifest = evidence();
    manifest.artifacts.push(artifact(
        "mstat",
        mstat_file(directory.path(), "source-root.mstat", 1),
    ));
    manifest.provenance.insert(
        "source.current_revision:synthetic-root".into(),
        "current".into(),
    );
    manifest.provenance.insert(
        "binlog.source_revision:synthetic.binlog:synthetic-root".into(),
        "recorded".into(),
    );
    let path = write_manifest(directory.path(), &manifest, "source-root.json");
    let output = directory.path().join("index");
    let result = import(&path, &output, MEMORY, false).unwrap();
    assert_eq!(
        result
            .diagnostics
            .iter()
            .filter(|d| d.code == "evidence.revision.mismatch")
            .count(),
        1
    );
    assert_eq!(
        result.evidence.provenance["source.current_revision:synthetic-root"],
        "current"
    );
    assert_eq!(
        result.evidence.provenance["binlog.source_revision:synthetic.binlog:synthetic-root"],
        "recorded"
    );
    assert_eq!(
        import(&path, &directory.path().join("strict"), MEMORY, true)
            .unwrap_err()
            .diagnostic
            .code,
        "attribution.evidence.incomplete"
    );
    manifest.provenance.insert(
        "source.current_revision:synthetic-root".into(),
        "recorded".into(),
    );
    let path = write_manifest(directory.path(), &manifest, "matching-source-root.json");
    let matched = import(&path, &directory.path().join("matched"), MEMORY, true).unwrap();
    assert!(matched.diagnostics.is_empty());
}

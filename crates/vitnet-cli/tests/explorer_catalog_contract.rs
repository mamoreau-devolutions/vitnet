//! Complete explorer catalog persistence contracts; synthetic bounded local fixtures only.
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use vitnet_attribution::model::{
    Artifact, Assembly, Binary, BinarySection, EVIDENCE_SCHEMA, Evidence, EvidenceDiagnostic,
    Generator, ManagedType, Mapping, Package, Resource, Source,
};
use vitnet_cli::explorer::data;
use vitnet_dgml::{
    GraphSession, IncomingOptions, IndexControl, IndexOptions, SearchMode, SearchOptions,
    build_index,
};
use vitnet_mstat::CoalescedIdentity;

const MEMORY: u64 = 128 << 20;

#[path = "../../vitnet-attribution/tests/common/mod.rs"]
mod common;

fn write_json(path: &Path, value: &impl serde::Serialize) {
    fs::write(path, serde_json::to_vec(value).unwrap()).unwrap();
}

fn read_json(path: &Path) -> Value {
    serde_json::from_slice(&fs::read(path).unwrap()).unwrap()
}

fn row(identity: &str, bytes: u64) -> CoalescedIdentity {
    CoalescedIdentity {
        stream: "Methods".into(),
        identity: identity.into(),
        bytes,
        records: 1,
        accounted: true,
        identity_lossy: false,
        raw_identity_blake3: blake3::hash(identity.as_bytes()).to_hex().to_string(),
    }
}

fn evidence() -> Evidence {
    Evidence {
        schema: EVIDENCE_SCHEMA.into(),
        label: "synthetic complete explorer catalog".into(),
        ..Evidence::default()
    }
}

fn rich_evidence() -> Evidence {
    let mut value = evidence();
    for id in 0..101 {
        value
            .provenance
            .insert(format!("property-{id:03}"), format!("value-{id:03}"));
        value.generators.push(Generator {
            name: format!("generator-{id:03}"),
            version: "1.0".into(),
            assembly_path: PathBuf::from(format!("generator-{id:03}.dll")),
            generated_files: (0..61)
                .map(|i| PathBuf::from(format!("generated-{id:03}-{i:03}.cs")))
                .collect(),
            input_symbols: (0..121).map(|i| format!("symbol-{id:03}-{i:03}")).collect(),
        });
    }
    for id in 0..201 {
        value.resources.push(Resource {
            assembly: "App".into(),
            container: "synthetic".into(),
            name: format!("resource-{id:03}"),
            bytes: 7,
            sha256: Some("a".repeat(64)),
            storage: "asset".into(),
            ..Resource::default()
        });
        value.packages.push(Package {
            target: "net10.0".into(),
            id: format!("package-{id:03}"),
            version: "1.0".into(),
            direct: true,
            dependencies: Vec::new(),
        });
    }
    value.assemblies.push(Assembly {
        name: "App".into(),
        path: "synthetic-missing.dll".into(),
        types: vec![ManagedType {
            name: "Widget".into(),
            kind: "class".into(),
            members: 9_007_199_254_740_993,
        }],
        package: None,
    });
    value.sources.push(Source {
        assembly: "App".into(),
        type_name: "Widget".into(),
        member: Some("Run".into()),
        path: "synthetic-missing.cs".into(),
        line: 1,
        end_line: 3,
        kind: "method".into(),
        generated_by: Some("generator-100".into()),
        attributes: (0..61).map(|i| format!("attribute-{i:03}")).collect(),
        ..Source::default()
    });
    value.mappings.push(Mapping {
        stream: "Methods".into(),
        identity: "Widget000<System_Int32>__Run".into(),
        assembly: "App".into(),
        source_paths: vec!["synthetic-missing.cs".into()],
        basis: "synthetic asserted association".into(),
    });
    value.binaries.push(Binary {
        path: "synthetic.bin".into(),
        format: "synthetic".into(),
        architecture: "unknown".into(),
        file_bytes: 9_007_199_254_740_993,
        sections: vec![BinarySection {
            name: "section".into(),
            file_bytes: 11,
            virtual_bytes: 29,
        }],
    });
    value.artifacts.push(Artifact {
        kind: "synthetic-unknown".into(),
        path: "synthetic-artifact.dat".into(),
        revision: None,
        blake3: None,
    });
    value.diagnostics.push(EvidenceDiagnostic {
        code: "synthetic.catalog".into(),
        message: "explicit unknown state, not a zero measurement".into(),
        path: None,
    });
    value
}

fn import(root: &Path, name: &str, value: &Evidence, rows: &[CoalescedIdentity]) -> PathBuf {
    let input = root.join(format!("{name}.json"));
    write_json(&input, value);
    let index = root.join(name);
    let mut manifest = vitnet_attribution::import(&input, &index, MEMORY, false).unwrap();
    let mut bytes = Vec::new();
    for row in rows {
        bytes.extend(serde_json::to_vec(row).unwrap());
        bytes.push(b'\n');
    }
    fs::write(index.join("identities.ndjson"), &bytes).unwrap();
    manifest.identities = u64::try_from(rows.len()).unwrap();
    manifest.identities_blake3 = blake3::hash(&bytes).to_hex().to_string();
    write_json(&index.join("index.json"), &manifest);
    index
}

fn prepare(index: &Path, bundle: &Path) -> Value {
    data::prepare(
        index,
        bundle,
        &[],
        None,
        &[],
        "scan_index",
        MEMORY,
        &IndexControl::default(),
    )
    .unwrap();
    read_json(&bundle.join("bundle.json"))
}

fn names(path: &Path) -> BTreeSet<String> {
    fs::read_dir(path)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect()
}

fn contents(path: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    let mut result = BTreeMap::new();
    for entry in fs::read_dir(path).unwrap() {
        let entry = entry.unwrap();
        if entry.file_type().unwrap().is_dir() {
            for (relative, bytes) in contents(&entry.path()) {
                result.insert(PathBuf::from(entry.file_name()).join(relative), bytes);
            }
        } else {
            result.insert(
                PathBuf::from(entry.file_name()),
                fs::read(entry.path()).unwrap(),
            );
        }
    }
    result
}

fn records(bundle: &Path, name: &str) -> Vec<Value> {
    fs::read(bundle.join(format!("catalog_{name}.ndjson")))
        .unwrap()
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .map(|line| serde_json::from_slice(line).unwrap())
        .collect()
}

fn sync_catalog_manifest(bundle: &Path, manifest: &mut Value) {
    let mut snapshot = read_json(&bundle.join("snapshot.json"));
    snapshot["datasets"] = manifest["datasets"].clone();
    sync_generation(bundle, manifest, &mut snapshot);
}

fn sync_generation(bundle: &Path, manifest: &mut Value, snapshot: &mut Value) {
    snapshot["generation"] = Value::Null;
    let mut fingerprint = blake3::Hasher::new();
    fingerprint.update(b"vitnet.explorer-generation.v1\0");
    fingerprint.update(manifest["index_blake3"].as_str().unwrap().as_bytes());
    fingerprint.update(manifest["identities_blake3"].as_str().unwrap().as_bytes());
    fingerprint.update(&serde_json::to_vec(snapshot).unwrap());
    let generation = fingerprint.finalize().to_hex().to_string();
    snapshot["generation"] = json!(generation);
    manifest["generation"] = json!(generation);
    write_json(&bundle.join("snapshot.json"), &snapshot);
    manifest["snapshot_blake3"] = json!(
        blake3::hash(&fs::read(bundle.join("snapshot.json")).unwrap())
            .to_hex()
            .to_string()
    );
    write_json(&bundle.join("bundle.json"), manifest);
}

#[test]
#[allow(clippy::too_many_lines)] // One fixture reconciles all persisted dataset projections.
fn complete_catalog_persists_uncapped_inventory_and_exact_offsets() {
    let root = tempfile::tempdir().unwrap();
    let rows: Vec<_> = (0..101)
        .map(|id| row(&format!("Widget{id:03}<System_Int32>__Run"), 101 - id))
        .collect();
    let value = rich_evidence();
    let index = import(root.path(), "index", &value, &rows);
    let bundle = root.path().join("bundle");
    let manifest = prepare(&index, &bundle);
    let datasets = manifest["datasets"].as_object().unwrap();
    for (name, count) in [
        ("generic_families", 101),
        ("generators", 101),
        ("provenance", 101),
        ("resources", 201),
        ("package_routes", 201),
        ("packages", 201),
        ("duplicate_assets", 1),
        ("assemblies", 1),
        ("sources", 1),
        ("mappings", 1),
        ("binaries", 1),
        ("evidence_header", 1),
        ("mstat_summary", 0),
        ("comparison", 0),
    ] {
        assert_eq!(datasets[name]["records"], count, "{name}");
    }
    assert!(datasets["groups"]["records"].as_u64().unwrap() >= 101);
    for name in ["artifacts", "diagnostics"] {
        assert!(datasets[name]["records"].as_u64().unwrap() >= 1, "{name}");
    }
    for (name, descriptor) in datasets {
        let data = fs::read(bundle.join(format!("catalog_{name}.ndjson"))).unwrap();
        let offsets = fs::read(bundle.join(format!("catalog_{name}.offsets"))).unwrap();
        let count = descriptor["records"].as_u64().unwrap();
        assert_eq!(
            descriptor["data_bytes"],
            u64::try_from(data.len()).unwrap(),
            "{name}"
        );
        assert_eq!(
            descriptor["blake3"],
            blake3::hash(&data).to_hex().to_string(),
            "{name}"
        );
        assert_eq!(
            descriptor["offsets_blake3"],
            blake3::hash(&offsets).to_hex().to_string(),
            "{name}"
        );
        assert_eq!(
            u64::try_from(offsets.len()).unwrap(),
            (count + 1) * 8,
            "{name}"
        );
        let actual: Vec<_> = offsets
            .chunks_exact(8)
            .map(|chunk| u64::from_le_bytes(chunk.try_into().unwrap()))
            .collect();
        let mut expected = vec![0_u64];
        for line in data.split_inclusive(|byte| *byte == b'\n') {
            assert_eq!(line.last(), Some(&b'\n'), "{name}");
            let _: Value = serde_json::from_slice(line).unwrap();
            expected.push(expected.last().unwrap() + u64::try_from(line.len()).unwrap());
        }
        assert_eq!(
            actual, expected,
            "every {name} record has exactly one addressable interval"
        );
    }
    let resources = records(&bundle, "resources");
    assert_eq!(resources.first().unwrap()["name"], "resource-000");
    assert_eq!(resources.last().unwrap()["name"], "resource-200");
    assert_eq!(
        resources
            .iter()
            .map(|entry| entry["bytes"].as_u64().unwrap())
            .sum::<u64>(),
        1407
    );
    assert_eq!(
        records(&bundle, "packages").last().unwrap()["id"],
        "package-200"
    );
    let duplicate = records(&bundle, "duplicate_assets");
    assert_eq!(duplicate[0]["instances"].as_array().unwrap().len(), 201);
    assert_eq!(duplicate[0]["bytes_each"], 7);
    let generators = records(&bundle, "generators");
    let generator = &generators[100];
    assert_eq!(generator["name"], "generator-100");
    assert_eq!(generator["generated_declarations"], 1);
    assert_eq!(generator["asserted_accounted_bytes"], 101);
    assert_eq!(generator["candidate_accounted_bytes"], 0);
    assert_eq!(
        generator["evidence"]["generated_files"]
            .as_array()
            .unwrap()
            .len(),
        61
    );
    assert_eq!(
        generator["evidence"]["input_symbols"][120],
        "symbol-100-120"
    );
    assert_eq!(
        records(&bundle, "sources")[0]["attributes"][60],
        "attribute-060"
    );
    assert_eq!(
        records(&bundle, "binaries")[0]["file_bytes"],
        9_007_199_254_740_993_u64
    );
    let snapshot = data::Bundle::open(&bundle, MEMORY).unwrap().snapshot;
    for (name, cap) in [
        ("generic_families", 100),
        ("generators", 100),
        ("resources", 200),
        ("package_routes", 200),
    ] {
        assert_eq!(
            snapshot[name].as_array().unwrap().len(),
            cap,
            "{name} remains a bounded projection"
        );
    }
    assert_eq!(
        snapshot["duplicate_assets"][0]["instances"]
            .as_array()
            .unwrap()
            .len(),
        20
    );
    assert_eq!(snapshot["coverage"]["resource_count"], 201);
    assert_eq!(snapshot["coverage"]["generic_family_count"], 101);
    assert_eq!(snapshot["datasets"], manifest["datasets"]);
    data::verify(&bundle, MEMORY).unwrap();
}

#[test]
#[allow(clippy::too_many_lines)] // Captured metadata, comparison and independent supplemental evidence.
fn metadata_comparison_and_supplemental_are_independent_complete_datasets() {
    let root = tempfile::tempdir().unwrap();
    let before = import(root.path(), "before", &evidence(), &[]);
    let metadata = root.path().join("metadata.csv");
    fs::write(&metadata, b"Handle, Kind, Name, Children\n00000000, ScopeDefinition, \"App\", \"a\"\n0000000a, TypeDefinition, \"Widget\", \"14\"\n00000014, Method, \"Run\", \"\"\n00000028, End, \"\", \"\"\n").unwrap();
    let mstat = root.path().join("empty.mstat");
    fs::write(&mstat, common::Image::new().bytes()).unwrap();
    let mut value = evidence();
    value.artifacts = vec![
        Artifact {
            kind: "metadata".into(),
            path: metadata,
            revision: None,
            blake3: None,
        },
        Artifact {
            kind: "mstat".into(),
            path: mstat,
            revision: None,
            blake3: None,
        },
    ];
    value.provenance.insert("change".into(), "after".into());
    let after = import(root.path(), "after", &value, &[]);
    let inventory = root.path().join("supplemental.json");
    let mut supplemental = evidence();
    supplemental.label = "independent supplemental".into();
    supplemental
        .provenance
        .insert("private-to-supplement".into(), "do not merge".into());
    supplemental.resources.push(Resource {
        assembly: "Supplement".into(),
        container: "container".into(),
        name: "extra".into(),
        bytes: 19,
        storage: "asset".into(),
        ..Resource::default()
    });
    supplemental.sources.push(Source {
        assembly: "Supplement".into(),
        type_name: "Unmerged".into(),
        path: "unmerged.cs".into(),
        line: 1,
        end_line: 1,
        kind: "type".into(),
        ..Source::default()
    });
    write_json(&inventory, &supplemental);
    let bundle = root.path().join("bundle");
    data::prepare(
        &after,
        &bundle,
        &[inventory],
        Some(&before),
        &[],
        "scan_index",
        MEMORY,
        &IndexControl::default(),
    )
    .unwrap();
    let manifest = read_json(&bundle.join("bundle.json"));
    for name in [
        "metadata_summary",
        "metadata_by_kind",
        "metadata_by_assembly",
        "metadata_by_namespace",
        "metadata_by_type",
        "metadata_largest_strings",
        "metadata_unowned",
    ] {
        assert!(manifest["datasets"].get(name).is_some(), "missing {name}");
        assert_eq!(
            records(&bundle, name).len() as u64,
            manifest["datasets"][name]["records"].as_u64().unwrap()
        );
    }
    assert_eq!(records(&bundle, "mstat_summary").len(), 1);
    let kinds = records(&bundle, "metadata_by_kind");
    let analysis = vitnet_attribution::open_index(&after, MEMORY)
        .unwrap()
        .metadata
        .unwrap();
    let summary = records(&bundle, "metadata_summary");
    assert!(analysis.observed_record_count > 0);
    assert_eq!(
        summary[0]["observed_record_count"],
        analysis.observed_record_count
    );
    assert_eq!(
        summary[0]["observed_lower_bound"],
        analysis.observed_lower_bound
    );
    assert_eq!(summary[0]["total_lower_bound"], analysis.total_lower_bound);
    for (name, expected) in [
        ("metadata_by_kind", json!(analysis.by_kind)),
        ("metadata_by_assembly", json!(analysis.by_assembly)),
        ("metadata_by_namespace", json!(analysis.by_namespace)),
        ("metadata_by_type", json!(analysis.by_type)),
        ("metadata_largest_strings", json!(analysis.largest_strings)),
        ("metadata_unowned", json!(analysis.unowned)),
    ] {
        assert_eq!(
            json!(records(&bundle, name)),
            expected,
            "complete analysis mapping for {name}"
        );
    }
    assert!(
        kinds
            .iter()
            .any(|entry| entry.to_string().contains("TypeDefinition")),
        "{kinds:?}"
    );
    assert!(
        records(&bundle, "metadata_by_type")
            .iter()
            .any(|entry| entry.to_string().contains("Widget"))
    );
    let comparison = records(&bundle, "comparison");
    assert_eq!(comparison.len(), 1);
    assert_eq!(
        comparison[0]["provenance_changes"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        records(&bundle, "supplemental_0_evidence_header")[0]["label"],
        "independent supplemental"
    );
    assert_eq!(
        records(&bundle, "supplemental_0_provenance"),
        vec![json!({"key":"private-to-supplement","value":"do not merge"})]
    );
    assert_eq!(
        records(&bundle, "supplemental_0_sources")[0]["type_name"],
        "Unmerged"
    );
    assert_eq!(records(&bundle, "sources"), Vec::<Value>::new());
    assert_eq!(
        records(&bundle, "provenance"),
        vec![json!({"key":"change","value":"after"})]
    );
    assert_eq!(records(&bundle, "resources")[0]["bytes"], 19);
    assert_eq!(
        records(&bundle, "supplemental_0_resource_evidence")[0]["name"],
        "extra"
    );
    assert_eq!(
        data::Bundle::open(&bundle, MEMORY).unwrap().snapshot["accounting"]["total_bytes"],
        0
    );
    data::verify(&bundle, MEMORY).unwrap();
}

#[test]
fn catalog_schema_hash_count_offset_and_same_length_corruption_fail_explicitly() {
    for mutation in [
        "schema",
        "count",
        "data-bytes",
        "data-hash",
        "offset-hash",
        "same-length",
        "first-offset",
        "equal-offset",
        "past-end",
        "terminal-offset",
        "json",
        "name",
    ] {
        let root = tempfile::tempdir().unwrap();
        let index = import(root.path(), "index", &evidence(), &[]);
        let bundle = root.path().join("bundle");
        let mut manifest = prepare(&index, &bundle);
        let data_path = bundle.join("catalog_evidence_header.ndjson");
        let offset_path = bundle.join("catalog_evidence_header.offsets");
        let expected = match mutation {
            "schema" => {
                manifest["schema"] = json!("vitnet.explorer-bundle.v999");
                "explorer.schema"
            }
            "count" => {
                manifest["datasets"]["evidence_header"]["records"] = json!(2);
                "explorer.dataset.integrity"
            }
            "data-bytes" => {
                manifest["datasets"]["evidence_header"]["data_bytes"] = json!(1);
                "explorer.dataset.integrity"
            }
            "data-hash" => {
                manifest["datasets"]["evidence_header"]["blake3"] = json!("0".repeat(64));
                "explorer.dataset.integrity"
            }
            "offset-hash" => {
                manifest["datasets"]["evidence_header"]["offsets_blake3"] = json!("0".repeat(64));
                "explorer.dataset.integrity"
            }
            "same-length" => {
                let mut bytes = fs::read(&data_path).unwrap();
                let at = bytes
                    .windows(9)
                    .position(|part| part == b"synthetic")
                    .unwrap();
                bytes[at] = b'X';
                fs::write(&data_path, bytes).unwrap();
                "explorer.dataset.integrity"
            }
            "first-offset" | "equal-offset" | "past-end" | "terminal-offset" => {
                let mut bytes = fs::read(&offset_path).unwrap();
                if mutation == "first-offset" {
                    bytes[..8].copy_from_slice(&1_u64.to_le_bytes());
                } else {
                    let end = match mutation {
                        "equal-offset" => 0,
                        "past-end" => u64::MAX,
                        _ => {
                            manifest["datasets"]["evidence_header"]["data_bytes"]
                                .as_u64()
                                .unwrap()
                                - 1
                        }
                    };
                    bytes[8..16].copy_from_slice(&end.to_le_bytes());
                }
                fs::write(&offset_path, &bytes).unwrap();
                manifest["datasets"]["evidence_header"]["offsets_blake3"] =
                    json!(blake3::hash(&bytes).to_hex().to_string());
                "explorer.dataset.integrity"
            }
            "json" => {
                let mut bytes = fs::read(&data_path).unwrap();
                bytes[0] = b'!';
                fs::write(&data_path, &bytes).unwrap();
                manifest["datasets"]["evidence_header"]["blake3"] =
                    json!(blake3::hash(&bytes).to_hex().to_string());
                "explorer.dataset.json"
            }
            "name" => {
                let descriptor = manifest["datasets"]
                    .as_object_mut()
                    .unwrap()
                    .remove("evidence_header")
                    .unwrap();
                manifest["datasets"]["../index"] = descriptor;
                "explorer.dataset"
            }
            _ => unreachable!(),
        };
        sync_catalog_manifest(&bundle, &mut manifest);
        let error = data::verify(&bundle, MEMORY).unwrap_err();
        assert!(error.to_string().contains(expected), "{mutation}: {error}");
    }
}

#[test]
fn legacy_bundle_without_catalog_descriptors_is_openable() {
    let root = tempfile::tempdir().unwrap();
    let index = import(root.path(), "index", &evidence(), &[row("Widget__Run", 7)]);
    let bundle = root.path().join("bundle");
    let mut manifest = prepare(&index, &bundle);
    manifest.as_object_mut().unwrap().remove("datasets");
    let mut snapshot = read_json(&bundle.join("snapshot.json"));
    snapshot.as_object_mut().unwrap().remove("datasets");
    sync_generation(&bundle, &mut manifest, &mut snapshot);
    let opened = data::Bundle::open(&bundle, MEMORY).unwrap();
    assert!(opened.manifest.datasets.is_empty());
    assert_eq!(opened.manifest.identities, 1);
    assert_eq!(
        opened.snapshot["contributors"][0]["identity"],
        "Widget__Run"
    );
    data::verify(&bundle, MEMORY).unwrap();
}

fn graph_index(root: &Path, xml: &str) -> PathBuf {
    let path = root.join("synthetic.dgml");
    fs::write(&path, xml).unwrap();
    build_index(
        &path,
        &IndexOptions {
            cache_root: root.join("graph-cache"),
            memory_limit: MEMORY,
            selected_entry: None,
            strict_hash: false,
            control: IndexControl::default(),
        },
    )
    .unwrap()
    .index_directory
}

fn graph_text() -> String {
    format!("{}GRAPH-FULL-SUFFIX", "🦀é".repeat(1500))
}

fn graph_xml() -> String {
    let mut xml = String::from("<DirectedGraph><Nodes>");
    for (id, label) in [
        (0, String::new()),
        (2, graph_text()),
        (4, "target-four".into()),
        (6, "target-six".into()),
        (8, "isolated".into()),
    ] {
        write!(xml, "<Node Id=\"{id}\" Label=\"{label}\"/>").unwrap();
    }
    xml.push_str("</Nodes><Links><Link Source=\"0\" Target=\"4\" Reason=\"\"/>");
    write!(
        xml,
        "<Link Source=\"2\" Target=\"4\" Reason=\"{}\"/>",
        graph_text()
    )
    .unwrap();
    xml.push_str("<Link Source=\"0\" Target=\"6\" Reason=\"first-six\"/><Link Source=\"4\" Target=\"6\" Reason=\"second-six\"/></Links></DirectedGraph>");
    xml
}

#[test]
fn direct_graph_browse_and_full_records_keep_empty_labels_sparse_ids_and_csr_edges() {
    let root = tempfile::tempdir().unwrap();
    let index = graph_index(root.path(), &graph_xml());
    let mut graph = GraphSession::open(&index, MEMORY).unwrap();
    let mut options = SearchOptions {
        mode: SearchMode::Contains,
        limit: 2,
        preview_bytes: 512,
        generation: Some(graph.generation.clone()),
        ..SearchOptions::default()
    };
    let mut ids = Vec::new();
    for expected in [vec![0, 2], vec![4, 6], vec![8]] {
        let page = graph.browse_nodes(&options).unwrap();
        let actual: Vec<_> = page.entries.iter().map(|node| node.node_id).collect();
        assert_eq!(actual, expected);
        assert_eq!(page.generation, graph.generation);
        for node in &page.entries {
            match node.node_id {
                2 => {
                    assert_eq!(node.label, "🦀é".repeat(85));
                    assert_eq!(node.label_bytes, graph_text().len() as u64);
                    assert!(node.truncated);
                }
                4 => assert_eq!(node.label, "target-four"),
                6 => {
                    assert_eq!(node.label, "target-six");
                    assert_eq!(node.incoming_edges, 2);
                }
                8 => assert_eq!(node.incoming_edges, 0),
                _ => {}
            }
        }
        ids.extend(actual);
        options.after_id = page.next_after_id;
    }
    assert_eq!(ids, [0, 2, 4, 6, 8]);
    assert_eq!(options.after_id, None);
    let empty_label = graph.node_record(0).unwrap();
    assert_eq!(empty_label.node_id, 0);
    assert_eq!(empty_label.label, "");
    assert_eq!(empty_label.label_bytes, 0);
    assert!(!empty_label.truncated);
    let long = graph.node_record(2).unwrap();
    assert_eq!(long.label, graph_text());
    assert_eq!(long.label_bytes, graph_text().len() as u64);
    assert!(!long.truncated);
    let mut options = IncomingOptions {
        limit: 2,
        generation: Some(graph.generation.clone()),
        ..IncomingOptions::default()
    };
    let first = graph.browse_edges(&options).unwrap();
    assert_eq!(first.total, 4);
    assert_eq!(first.scanned, 2);
    assert_eq!(first.stop_reason, "limit");
    assert_eq!(first.next_after_edge, Some(1));
    assert_eq!(
        first
            .entries
            .iter()
            .map(|e| (e.ordinal, e.source_id, e.target_id))
            .collect::<Vec<_>>(),
        [(0, 0, 4), (1, 2, 4)]
    );
    assert_eq!(first.entries[0].reason, "");
    assert!(first.entries[1].reason_truncated);
    options.after_edge = first.next_after_edge;
    let last = graph.browse_edges(&options).unwrap();
    assert_eq!(
        last.entries
            .iter()
            .map(|e| (e.ordinal, e.source_id, e.target_id, e.reason.as_str()))
            .collect::<Vec<_>>(),
        [(2, 0, 6, "first-six"), (3, 4, 6, "second-six")]
    );
    assert_eq!(last.scanned, 2);
    assert_eq!(last.total, 4);
    assert_eq!(last.next_after_edge, None);
    assert_eq!(last.stop_reason, "complete");
    let edge = graph.edge_record(1).unwrap();
    assert_eq!((edge.ordinal, edge.source_id, edge.target_id), (1, 2, 4));
    assert_eq!(edge.reason, graph_text());
    assert_eq!(edge.reason_bytes, graph_text().len() as u64);
    assert!(!edge.reason_truncated);
    let local = graph.incoming_edge_record(6, 0).unwrap();
    assert_eq!((local.ordinal, local.source_id, local.target_id), (2, 0, 6));
    assert_eq!(local.reason, "first-six");
    assert_eq!(
        graph.incoming_edge_record(6, 1).unwrap().reason,
        "second-six"
    );
    assert_eq!(graph.node_record(6).unwrap().incoming_edges, 2);
    assert_eq!(graph.node_record(8).unwrap().incoming_edges, 0);
}

#[test]
#[allow(clippy::too_many_lines)] // Table of distinct public graph guard partitions.
fn direct_graph_invalid_paths_cursors_budgets_and_generations_fail_explicitly() {
    let root = tempfile::tempdir().unwrap();
    let index = graph_index(root.path(), &graph_xml());
    let mut graph = GraphSession::open(&index, MEMORY).unwrap();
    for id in [1, 9, u64::MAX] {
        assert_eq!(
            graph.node_record(id).unwrap_err().diagnostic.code,
            "dgml.query.node"
        );
    }
    for ordinal in [4, u64::MAX] {
        assert_eq!(
            graph.edge_record(ordinal).unwrap_err().diagnostic.code,
            "dgml.query.cursor"
        );
    }
    assert_eq!(
        graph
            .incoming_edge_record(1, 0)
            .unwrap_err()
            .diagnostic
            .code,
        "dgml.query.node"
    );
    for (node, ordinal) in [(8, 0), (6, 2), (6, u64::MAX)] {
        assert_eq!(
            graph
                .incoming_edge_record(node, ordinal)
                .unwrap_err()
                .diagnostic
                .code,
            "dgml.query.cursor"
        );
    }
    for after in [9, u64::MAX] {
        let options = SearchOptions {
            after_id: Some(after),
            ..SearchOptions::default()
        };
        assert_eq!(
            graph.browse_nodes(&options).unwrap_err().diagnostic.code,
            "dgml.query.cursor"
        );
    }
    for after in [4, u64::MAX] {
        let options = IncomingOptions {
            after_edge: Some(after),
            ..IncomingOptions::default()
        };
        assert_eq!(
            graph.browse_edges(&options).unwrap_err().diagnostic.code,
            "dgml.query.cursor"
        );
    }
    for options in [
        SearchOptions {
            mode: SearchMode::Exact,
            ..SearchOptions::default()
        },
        SearchOptions {
            count_all: true,
            ..SearchOptions::default()
        },
        SearchOptions {
            max_scanned: 0,
            ..SearchOptions::default()
        },
        SearchOptions {
            timeout_ms: 0,
            ..SearchOptions::default()
        },
    ] {
        assert_eq!(
            graph.browse_nodes(&options).unwrap_err().diagnostic.code,
            "dgml.query.options"
        );
    }
    for options in [
        SearchOptions {
            limit: 0,
            ..SearchOptions::default()
        },
        SearchOptions {
            preview_bytes: 0,
            ..SearchOptions::default()
        },
    ] {
        assert_eq!(
            graph.browse_nodes(&options).unwrap_err().diagnostic.code,
            "resource.memory_limit"
        );
    }
    assert_eq!(
        graph
            .browse_nodes(&SearchOptions {
                generation: Some("stale".into()),
                ..SearchOptions::default()
            })
            .unwrap_err()
            .diagnostic
            .code,
        "dgml.query.generation"
    );
    assert_eq!(
        graph
            .browse_edges(&IncomingOptions {
                generation: Some("stale".into()),
                ..IncomingOptions::default()
            })
            .unwrap_err()
            .diagnostic
            .code,
        "dgml.query.generation"
    );
    assert_eq!(
        graph
            .browse_edges(&IncomingOptions {
                limit: 0,
                ..IncomingOptions::default()
            })
            .unwrap_err()
            .diagnostic
            .code,
        "resource.memory_limit"
    );
    assert_eq!(
        graph
            .browse_edges(&IncomingOptions {
                timeout_ms: 0,
                ..IncomingOptions::default()
            })
            .unwrap_err()
            .diagnostic
            .code,
        "dgml.query.cursor"
    );
    let terminal = graph
        .browse_nodes(&SearchOptions {
            after_id: Some(8),
            ..SearchOptions::default()
        })
        .unwrap();
    assert_eq!(terminal.entries.len(), 0);
    assert_eq!(terminal.scanned_nodes, 0);
    assert_eq!(terminal.stop_reason, "complete");
    assert_eq!(terminal.next_after_id, None);
    let terminal = graph
        .browse_edges(&IncomingOptions {
            after_edge: Some(3),
            ..IncomingOptions::default()
        })
        .unwrap();
    assert!(terminal.entries.is_empty());
    assert_eq!(terminal.scanned, 0);
    assert_eq!(terminal.total, 4);
    assert_eq!(terminal.next_after_edge, None);
    assert_eq!(terminal.stop_reason, "complete");
}

#[test]
fn direct_graph_cancellation_reaches_each_new_operation_and_control_can_be_replaced() {
    let root = tempfile::tempdir().unwrap();
    let index = graph_index(root.path(), &graph_xml());
    let mut graph = GraphSession::open(&index, MEMORY).unwrap();
    let cancelled = IndexControl::default();
    cancelled.cancel();
    graph.set_control(cancelled);
    assert_eq!(
        graph.node_record(2).unwrap_err().diagnostic.code,
        "resource.cancelled"
    );
    assert_eq!(
        graph.edge_record(1).unwrap_err().diagnostic.code,
        "resource.cancelled"
    );
    assert_eq!(
        graph
            .incoming_edge_record(6, 0)
            .unwrap_err()
            .diagnostic
            .code,
        "resource.cancelled"
    );
    let nodes = graph.browse_nodes(&SearchOptions::default()).unwrap();
    assert_eq!(nodes.stop_reason, "cancelled");
    assert_eq!(nodes.entries.len(), 0);
    assert_eq!(nodes.scanned_nodes, 0);
    let edges = graph.browse_edges(&IncomingOptions::default()).unwrap();
    assert_eq!(edges.stop_reason, "cancelled");
    assert!(edges.entries.is_empty());
    assert_eq!(edges.scanned, 0);
    assert_eq!(edges.total, 4);
    graph.set_control(IndexControl::default());
    assert_eq!(graph.node_record(2).unwrap().label, graph_text());
    assert_eq!(graph.edge_record(1).unwrap().reason, graph_text());
    assert_eq!(
        graph
            .browse_nodes(&SearchOptions::default())
            .unwrap()
            .entries
            .len(),
        5
    );
    assert_eq!(
        graph
            .browse_edges(&IncomingOptions::default())
            .unwrap()
            .entries
            .len(),
        4
    );
}

#[test]
fn direct_graph_empty_and_singleton_pages_reconcile_without_false_continuations() {
    for present in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let xml = if present {
            "<DirectedGraph><Nodes><Node Id=\"0\" Label=\"\"/></Nodes><Links><Link Source=\"0\" Target=\"0\" Reason=\"\"/></Links></DirectedGraph>"
        } else {
            "<DirectedGraph><Nodes></Nodes><Links></Links></DirectedGraph>"
        };
        let index = graph_index(root.path(), xml);
        let mut graph = GraphSession::open(&index, MEMORY).unwrap();
        let nodes = graph
            .browse_nodes(&SearchOptions {
                limit: 1,
                ..SearchOptions::default()
            })
            .unwrap();
        assert_eq!(nodes.entries.len(), usize::from(present));
        assert_eq!(nodes.next_after_id, None);
        assert_eq!(nodes.stop_reason, "complete");
        let edges = graph
            .browse_edges(&IncomingOptions {
                limit: 1,
                ..IncomingOptions::default()
            })
            .unwrap();
        assert_eq!(edges.entries.len(), usize::from(present));
        assert_eq!(edges.total, u64::from(present));
        assert_eq!(edges.scanned, u64::from(present));
        assert_eq!(edges.next_after_edge, None);
        assert_eq!(edges.stop_reason, "complete");
        if present {
            assert_eq!(graph.node_record(0).unwrap().label, "");
            let edge = graph.edge_record(0).unwrap();
            assert_eq!((edge.source_id, edge.target_id), (0, 0));
            assert_eq!(edge.reason, "");
        }
    }
}

#[test]
fn complete_mstat_summary_distinguishes_measured_zero_and_populated_streams() {
    let root = tempfile::tempdir().unwrap();
    let mut image = common::Image::new();
    image.method(b"Owner__Run", 11);
    image.blob(&[65], 29);
    let path = root.path().join("sample.mstat");
    fs::write(&path, image.bytes()).unwrap();
    let mut value = evidence();
    value.artifacts.push(Artifact {
        kind: "mstat".into(),
        path,
        revision: None,
        blake3: None,
    });
    let input = root.path().join("evidence.json");
    write_json(&input, &value);
    let index = root.path().join("index");
    vitnet_attribution::import(&input, &index, MEMORY, false).unwrap();
    let bundle = root.path().join("bundle");
    prepare(&index, &bundle);
    let summary = records(&bundle, "mstat_summary");
    assert_eq!(summary.len(), 1);
    assert_eq!(summary[0]["accounted_size_bytes"], 40);
    assert_eq!(read_json(&bundle.join("bundle.json"))["identities"], 2);
    assert_eq!(
        data::Bundle::open(&bundle, MEMORY).unwrap().snapshot["accounting"]["total_bytes"],
        40
    );
    data::verify(&bundle, MEMORY).unwrap();
}

#[test]
fn original_inputs_and_existing_output_survive_success_failure_and_cancel() {
    let root = tempfile::tempdir().unwrap();
    let index = import(
        root.path(),
        "index",
        &rich_evidence(),
        &[row("Widget<System_Int32>__Run", 17)],
    );
    let originals = contents(&index);
    let input = fs::read(root.path().join("index.json")).unwrap();
    let bundle = root.path().join("bundle");
    prepare(&index, &bundle);
    assert_eq!(contents(&index), originals);
    assert_eq!(fs::read(root.path().join("index.json")).unwrap(), input);
    let output = contents(&bundle);
    let before = names(root.path());
    let error = data::prepare(
        &index,
        &bundle,
        &[],
        None,
        &[],
        "scan_index",
        MEMORY,
        &IndexControl::default(),
    )
    .unwrap_err();
    assert!(
        error.to_string().contains("explorer.output.exists"),
        "{error}"
    );
    assert_eq!(contents(&bundle), output);
    assert_eq!(names(root.path()), before);
    let inventory = root.path().join("conflicting.json");
    let mut conflicting = evidence();
    let mut resource = rich_evidence().resources.remove(0);
    resource.bytes = 8;
    conflicting.resources.push(resource);
    write_json(&inventory, &conflicting);
    let before = names(root.path());
    let failed = root.path().join("failed-after-staging");
    let error = data::prepare(
        &index,
        &failed,
        std::slice::from_ref(&inventory),
        None,
        &[],
        "scan_index",
        MEMORY,
        &IndexControl::default(),
    )
    .unwrap_err();
    assert!(
        error.to_string().contains("explorer.inventory.conflict"),
        "{error}"
    );
    assert!(!failed.exists());
    assert_eq!(names(root.path()), before);
    assert_eq!(contents(&index), originals);
    assert_eq!(contents(&bundle), output);
    assert_eq!(read_json(&inventory)["resources"][0]["bytes"], 8);
    let control = IndexControl::default();
    control.cancel();
    let cancelled = root.path().join("cancelled");
    let error = data::prepare(
        &index,
        &cancelled,
        &[],
        None,
        &[],
        "scan_index",
        MEMORY,
        &control,
    )
    .unwrap_err();
    assert!(error.to_string().contains("resource.cancelled"), "{error}");
    assert!(!cancelled.exists());
    assert_eq!(
        names(root.path()),
        before,
        "no leaked atomic staging directory"
    );
    assert_eq!(contents(&index), originals);
    assert_eq!(contents(&bundle), output);
}

#[test]
fn generation_covers_changes_beyond_snapshot_and_is_repeatable() {
    let root = tempfile::tempdir().unwrap();
    let index = import(root.path(), "index", &evidence(), &[]);
    let originals = contents(&index);
    let inventory = root.path().join("inventory.json");
    let mut supplemental = evidence();
    supplemental.generators = rich_evidence().generators;
    write_json(&inventory, &supplemental);
    let first = root.path().join("first");
    let repeated = root.path().join("repeated");
    let make = |output: &Path| {
        data::prepare(
            &index,
            output,
            std::slice::from_ref(&inventory),
            None,
            &[],
            "scan_index",
            MEMORY,
            &IndexControl::default(),
        )
        .unwrap()
    };
    let a = make(&first);
    let b = make(&repeated);
    assert_eq!(a.generation, b.generation);
    assert_eq!(
        fs::read(first.join("snapshot.json")).unwrap(),
        fs::read(repeated.join("snapshot.json")).unwrap()
    );
    // Generator 100 is outside the former 100-entry projection. Its metrics
    // remain unchanged; only an undisplayed raw input symbol changes.
    supplemental.generators[100].input_symbols[120] = "changed-outside-old-preview".into();
    write_json(&inventory, &supplemental);
    let changed = root.path().join("changed");
    let c = make(&changed);
    assert_ne!(a.generation, c.generation);
    let mut old = read_json(&first.join("snapshot.json"));
    let mut new = read_json(&changed.join("snapshot.json"));
    old["generation"] = Value::Null;
    new["generation"] = Value::Null;
    assert_eq!(
        old["generators"], new["generators"],
        "old bounded generator projection is identical"
    );
    assert_eq!(
        old["coverage"], new["coverage"],
        "counts cannot detect the change"
    );
    assert_eq!(contents(&index), originals);
}

#[test]
#[allow(clippy::too_many_lines)] // Full-search predicates and deterministic scan continuation share a graph.
fn direct_graph_full_search_and_sparse_scan_boundaries_preserve_progress() {
    let root = tempfile::tempdir().unwrap();
    let index = graph_index(root.path(), &graph_xml());
    let mut graph = GraphSession::open(&index, MEMORY).unwrap();
    let limited = graph
        .search_nodes(
            "",
            &SearchOptions {
                max_scanned: 2,
                limit: 50,
                ..SearchOptions::default()
            },
        )
        .unwrap();
    assert_eq!(
        limited
            .entries
            .iter()
            .map(|node| node.node_id)
            .collect::<Vec<_>>(),
        [0]
    );
    assert_eq!(limited.scanned_nodes, 2);
    assert_eq!(
        limited.next_after_id,
        Some(1),
        "empty sparse slot still advances work cursor"
    );
    assert_eq!(limited.stop_reason, "max_scanned");
    let rest = graph
        .search_nodes(
            "",
            &SearchOptions {
                after_id: limited.next_after_id,
                ..SearchOptions::default()
            },
        )
        .unwrap();
    assert_eq!(
        rest.entries
            .iter()
            .map(|node| node.node_id)
            .collect::<Vec<_>>(),
        [2, 4, 6, 8]
    );
    assert_eq!(rest.scanned_nodes, 7);
    assert_eq!(rest.next_after_id, None);
    for (query, expected) in [
        ("GRAPH-FULL-SUFFIX", vec![2]),
        ("target", vec![4, 6]),
        ("TARGET", vec![]),
        ("not-present", vec![]),
    ] {
        let page = graph
            .search_nodes(query, &SearchOptions::default())
            .unwrap();
        assert_eq!(
            page.entries
                .iter()
                .map(|node| node.node_id)
                .collect::<Vec<_>>(),
            expected
        );
        assert_eq!(page.scanned_nodes, 9);
        assert_eq!(page.stop_reason, "complete");
        assert_eq!(page.next_after_id, None);
    }
    for (query, expected) in [
        ("GRAPH-FULL-SUFFIX", vec![1]),
        ("six", vec![2, 3]),
        ("4", vec![0, 1, 3]), // target 4, plus source 4
        ("1", vec![1]),       // global ordinal, not reason or source/target
        ("2", vec![1, 2]),    // source 2 and global ordinal 2
        ("not-present", vec![]),
        ("", vec![0, 1, 2, 3]),
    ] {
        let page = graph
            .search_edges(query, &IncomingOptions::default(), 10)
            .unwrap();
        assert_eq!(
            page.entries
                .iter()
                .map(|edge| edge.ordinal)
                .collect::<Vec<_>>(),
            expected,
            "{query}"
        );
        assert_eq!(page.total, 4);
        assert_eq!(page.scanned, 4);
        assert_eq!(page.stop_reason, "complete");
        assert_eq!(page.next_after_edge, None);
    }
    let miss = graph
        .search_edges("absent", &IncomingOptions::default(), 2)
        .unwrap();
    assert!(miss.entries.is_empty());
    assert_eq!(miss.total, 4);
    assert_eq!(miss.scanned, 2);
    assert_eq!(miss.next_after_edge, Some(1));
    assert_eq!(miss.stop_reason, "max_scanned");
    let rest = graph
        .search_edges(
            "absent",
            &IncomingOptions {
                after_edge: miss.next_after_edge,
                ..IncomingOptions::default()
            },
            2,
        )
        .unwrap();
    assert!(rest.entries.is_empty());
    assert_eq!(rest.scanned, 2);
    assert_eq!(rest.stop_reason, "complete");
    assert_eq!(rest.next_after_edge, None);
    assert_eq!(
        graph
            .search_edges("", &IncomingOptions::default(), 0)
            .unwrap_err()
            .diagnostic
            .code,
        "dgml.query.cursor"
    );
    assert_eq!(
        graph
            .search_edges(&"x".repeat(1025), &IncomingOptions::default(), 10)
            .unwrap_err()
            .diagnostic
            .code,
        "dgml.query.cursor"
    );
    assert!(
        graph
            .search_edges(&"x".repeat(1024), &IncomingOptions::default(), 10)
            .unwrap()
            .entries
            .is_empty()
    );
    assert_eq!(
        graph
            .search_nodes(
                "",
                &SearchOptions {
                    after_id: Some(9),
                    ..SearchOptions::default()
                }
            )
            .unwrap_err()
            .diagnostic
            .code,
        "dgml.query.cursor"
    );
    let cancelled = IndexControl::default();
    cancelled.cancel();
    graph.set_control(cancelled);
    assert_eq!(
        graph
            .search_nodes("target", &SearchOptions::default())
            .unwrap()
            .stop_reason,
        "cancelled"
    );
    let cancelled = graph
        .search_edges("six", &IncomingOptions::default(), 10)
        .unwrap();
    assert_eq!(cancelled.stop_reason, "cancelled");
    assert_eq!(cancelled.scanned, 0);
    assert!(cancelled.entries.is_empty());
}

#[test]
fn comparison_is_captured_before_explorer_projection_caps() {
    let root = tempfile::tempdir().unwrap();
    let before = import(root.path(), "before", &evidence(), &[]);
    let mut value = evidence();
    for id in 0..201 {
        value
            .provenance
            .insert(format!("change-{id:03}"), format!("new-value-{id:03}"));
    }
    let after = import(root.path(), "after", &value, &[]);
    let bundle = root.path().join("comparison");
    data::prepare(
        &after,
        &bundle,
        &[],
        Some(&before),
        &[],
        "scan_index",
        MEMORY,
        &IndexControl::default(),
    )
    .unwrap();
    let full = records(&bundle, "comparison");
    assert_eq!(full.len(), 1);
    let changes = full[0]["provenance_changes"].as_array().unwrap();
    assert_eq!(changes.len(), 201);
    assert!(changes[200].to_string().contains("change-200"));
    assert!(changes[200].to_string().contains("new-value-200"));
    let snapshot = data::Bundle::open(&bundle, MEMORY).unwrap().snapshot;
    assert_eq!(
        snapshot["comparison"]["provenance_changes"]
            .as_array()
            .unwrap()
            .len(),
        100
    );
    assert_eq!(
        snapshot["comparison"]["projection_counts"]["provenance_changes"],
        201
    );
    data::verify(&bundle, MEMORY).unwrap();
}

#[test]
fn supplemental_catalog_preserves_every_independent_model_category_without_merging_sources() {
    let root = tempfile::tempdir().unwrap();
    let index = import(root.path(), "index", &evidence(), &[]);
    let inventory = root.path().join("all-categories.json");
    let mut supplemental = rich_evidence();
    supplemental.resources.truncate(1);
    supplemental.packages.truncate(1);
    supplemental.generators.truncate(1);
    supplemental.provenance.clear();
    supplemental
        .provenance
        .insert("supplement-only".into(), long_supplemental_text());
    write_json(&inventory, &supplemental);
    let original = fs::read(&inventory).unwrap();
    let bundle = root.path().join("bundle");
    data::prepare(
        &index,
        &bundle,
        std::slice::from_ref(&inventory),
        None,
        &[],
        "scan_index",
        MEMORY,
        &IndexControl::default(),
    )
    .unwrap();
    for category in [
        "evidence_header",
        "evidence_artifacts",
        "provenance",
        "packages",
        "assemblies",
        "sources",
        "generator_evidence",
        "resource_evidence",
        "binaries",
        "mappings",
        "evidence_diagnostics",
    ] {
        assert_eq!(
            records(&bundle, &format!("supplemental_0_{category}")).len(),
            1,
            "{category}"
        );
    }
    assert_eq!(
        records(&bundle, "supplemental_0_provenance")[0]["value"],
        long_supplemental_text()
    );
    assert_eq!(
        records(&bundle, "supplemental_0_sources")[0]["attributes"][60],
        "attribute-060"
    );
    assert_eq!(
        records(&bundle, "supplemental_0_generator_evidence")[0]["input_symbols"][120],
        "symbol-000-120"
    );
    assert_eq!(
        records(&bundle, "supplemental_0_binaries")[0]["file_bytes"],
        9_007_199_254_740_993_u64
    );
    assert_eq!(
        records(&bundle, "supplemental_0_assemblies")[0]["types"][0]["members"],
        9_007_199_254_740_993_u64
    );
    assert_eq!(
        records(&bundle, "supplemental_0_evidence_artifacts")[0]["kind"],
        "synthetic-unknown"
    );
    assert_eq!(records(&bundle, "sources"), Vec::<Value>::new());
    assert_eq!(records(&bundle, "provenance"), Vec::<Value>::new());
    assert_eq!(records(&bundle, "packages")[0]["id"], "package-000");
    assert_eq!(records(&bundle, "resources")[0]["name"], "resource-000");
    assert_eq!(fs::read(&inventory).unwrap(), original);
    data::verify(&bundle, MEMORY).unwrap();
}

fn long_supplemental_text() -> String {
    format!("{}SUPPLEMENT-FULL-TAIL", "é".repeat(3000))
}

#[test]
fn forged_matching_generation_fields_do_not_bypass_content_fingerprint_validation() {
    let root = tempfile::tempdir().unwrap();
    let index = import(root.path(), "index", &evidence(), &[]);
    let bundle = root.path().join("bundle");
    let mut manifest = prepare(&index, &bundle);
    let mut snapshot = read_json(&bundle.join("snapshot.json"));
    manifest["generation"] = json!("0".repeat(64));
    snapshot["generation"] = manifest["generation"].clone();
    write_json(&bundle.join("snapshot.json"), &snapshot);
    manifest["snapshot_blake3"] = json!(
        blake3::hash(&fs::read(bundle.join("snapshot.json")).unwrap())
            .to_hex()
            .to_string()
    );
    write_json(&bundle.join("bundle.json"), &manifest);
    let error = data::Bundle::open(&bundle, MEMORY)
        .err()
        .expect("forged generation must fail");
    assert!(error.to_string().contains("explorer.generation"), "{error}");
}

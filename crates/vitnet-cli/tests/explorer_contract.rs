//! Synthetic, bounded explorer data/command contracts. No corpus or network.
use clap::Parser;
use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use vitnet_attribution::model::{
    Artifact, EVIDENCE_SCHEMA, Evidence, EvidenceDiagnostic, Generator, Mapping, Package, Resource,
    Source,
};
use vitnet_cli::explorer::{ExploreCommand, data};
use vitnet_cli::{AppError, Cli};
use vitnet_dgml::{IndexControl, IndexOptions, build_index};
use vitnet_mstat::CoalescedIdentity;

#[path = "../../vitnet-attribution/tests/common/mod.rs"]
mod common;

const MEMORY: u64 = 128 << 20;

fn evidence() -> Evidence {
    Evidence {
        schema: EVIDENCE_SCHEMA.into(),
        label: "Synthetic explorer".into(),
        ..Evidence::default()
    }
}

fn artifact(kind: &str, path: PathBuf) -> Artifact {
    Artifact {
        kind: kind.into(),
        path,
        revision: None,
        blake3: None,
    }
}

fn write_json(path: &Path, value: &impl serde::Serialize) {
    fs::write(path, serde_json::to_vec(value).unwrap()).unwrap();
}

fn read_json(path: &Path) -> Value {
    serde_json::from_slice(&fs::read(path).unwrap()).unwrap()
}

fn import(root: &Path, name: &str, value: &Evidence) -> PathBuf {
    let manifest = root.join(format!("{name}.json"));
    write_json(&manifest, value);
    let index = root.join(name);
    vitnet_attribution::import(&manifest, &index, MEMORY, false).unwrap();
    index
}

fn mstat(root: &Path, image: common::Image) -> Artifact {
    let path = root.join("synthetic.mstat");
    fs::write(&path, image.bytes()).unwrap();
    artifact("mstat", path)
}

fn prepare(index: &Path, bundle: &Path) -> data::BundleManifest {
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
    .unwrap()
}

fn snapshot(bundle: &Path) -> Value {
    data::Bundle::open(bundle, MEMORY).unwrap().snapshot
}

fn code(error: &AppError) -> &str {
    match error {
        AppError::Unsupported(value)
        | AppError::Resource(value)
        | AppError::IoDiagnostic(value) => &value.code,
        AppError::Dgml(value) => &value.diagnostic.code,
        _ => panic!("unexpected error: {error}"),
    }
}

fn cached(index: &Path, rows: &[CoalescedIdentity]) {
    let mut bytes = Vec::new();
    for row in rows {
        bytes.extend(serde_json::to_vec(row).unwrap());
        bytes.push(b'\n');
    }
    fs::write(index.join("identities.ndjson"), &bytes).unwrap();
    let mut manifest = read_json(&index.join("index.json"));
    manifest["identities"] = json!(rows.len());
    manifest["identities_blake3"] = json!(blake3::hash(&bytes).to_hex().to_string());
    write_json(&index.join("index.json"), &manifest);
}

fn row(stream: &str, identity: &str, bytes: u64, accounted: bool) -> CoalescedIdentity {
    CoalescedIdentity {
        stream: stream.into(),
        identity: identity.into(),
        bytes,
        records: 1,
        accounted,
        identity_lossy: false,
        raw_identity_blake3: blake3::hash(identity.as_bytes()).to_hex().to_string(),
    }
}

fn simple(root: &Path) -> (PathBuf, PathBuf) {
    let mut image = common::Image::new();
    image.method(b"Owner__First", 11);
    image.method(b"Owner__Last", 29);
    let mut value = evidence();
    value.artifacts.push(mstat(root, image));
    let index = import(root, "index", &value);
    let bundle = root.join("bundle");
    prepare(&index, &bundle);
    (index, bundle)
}

fn directory_names(root: &Path) -> BTreeSet<String> {
    fs::read_dir(root)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect()
}

#[test]
fn complete_accounting_top_hundred_per_stream_is_disjoint_and_reconciles_remaining() {
    let root = tempfile::tempdir().unwrap();
    let mut image = common::Image::new();
    for size in 1..=105 {
        image.method(format!("Owner__Method{size:03}").as_bytes(), size);
        image.blob(&[u16::try_from(size).unwrap()], size * 2);
    }
    image.method(b"Owner__Method105", 5); // coalesced record, not another identity
    let mut value = evidence();
    value.artifacts.push(mstat(root.path(), image));
    let index = import(root.path(), "index", &value);
    let bundle = root.path().join("bundle");
    let manifest = prepare(&index, &bundle);
    let report = snapshot(&bundle);
    assert_eq!(manifest.identities, 210);
    assert_eq!(report["coverage"]["identities"], 210);
    assert_eq!(report["accounting"]["total_bytes"], 16_700);
    let contributors = report["contributors"].as_array().unwrap();
    assert_eq!(contributors.len(), 200);
    let ordinals: BTreeSet<_> = contributors
        .iter()
        .map(|entry| entry["ordinal"].as_u64().unwrap())
        .collect();
    assert_eq!(ordinals.len(), 200);
    for (stream, total, shown) in [("Methods", 5570, 5555), ("Blobs", 11130, 11100)] {
        let rows: Vec<_> = contributors
            .iter()
            .filter(|row| row["stream"] == stream)
            .collect();
        assert_eq!(rows.len(), 100);
        assert!(rows.iter().all(|row| row["accounted"] == true));
        assert_eq!(
            rows.iter()
                .map(|row| row["bytes"].as_u64().unwrap())
                .sum::<u64>(),
            shown
        );
        assert!(rows.windows(2).all(|pair| {
            pair[0]["bytes"].as_u64().unwrap() >= pair[1]["bytes"].as_u64().unwrap()
        }));
        let aggregate = report["accounting"]["streams"]
            .as_array()
            .unwrap()
            .iter()
            .find(|row| row["name"] == stream)
            .unwrap();
        assert_eq!(aggregate["bytes"], total);
        assert_eq!(aggregate["identities"], 105);
        assert_eq!(
            rows.iter().map(|row| row["bytes"].as_u64().unwrap()).min(),
            Some(if stream == "Methods" { 6 } else { 12 })
        );
    }
    let duplicate = contributors
        .iter()
        .find(|row| row["identity"] == "Owner__Method105")
        .unwrap();
    assert_eq!(duplicate["bytes"], 110);
    assert_eq!(duplicate["records"], 2);
    assert_eq!(report["coverage"]["displayed_accounted_bytes"], 16_655);
    assert_eq!(report["coverage"]["remaining_accounted_bytes"], 45);
    let offsets = fs::read(bundle.join("offsets.bin")).unwrap();
    let actual: Vec<_> = offsets
        .chunks_exact(8)
        .map(|bytes| u64::from_le_bytes(bytes.try_into().unwrap()))
        .collect();
    let payload = fs::read(index.join("identities.ndjson")).unwrap();
    let mut expected = vec![0_u64];
    for line in payload.split_inclusive(|byte| *byte == b'\n') {
        expected.push(expected.last().unwrap() + u64::try_from(line.len()).unwrap());
    }
    assert_eq!(actual, expected);
    data::verify(&bundle, MEMORY).unwrap();
}

#[test]
fn empty_and_absent_mstat_are_distinct_zero_and_unknown_states() {
    for present in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let mut value = evidence();
        if present {
            value
                .artifacts
                .push(mstat(root.path(), common::Image::new()));
        }
        let index = import(root.path(), "index", &value);
        let bundle = root.path().join("bundle");
        let manifest = prepare(&index, &bundle);
        assert_eq!(manifest.identities, 0);
        assert_eq!(manifest.identity_file_bytes, 0);
        assert_eq!(
            fs::read(bundle.join("offsets.bin")).unwrap(),
            0_u64.to_le_bytes()
        );
        let report = snapshot(&bundle);
        assert_eq!(report["coverage"]["identities"], 0);
        assert_eq!(report["coverage"]["remaining_accounted_bytes"], 0);
        assert_eq!(report["contributors"], json!([]));
        assert_eq!(report["details"], json!({}));
        assert_eq!(report["accounting"]["streams"], json!([]));
        assert_eq!(
            report["accounting"]["total_bytes"],
            if present { json!(0) } else { Value::Null }
        );
        data::verify(&bundle, MEMORY).unwrap();
    }
}

#[test]
fn sparse_unaccounted_rows_do_not_enter_additive_contributors() {
    let root = tempfile::tempdir().unwrap();
    let index = import(root.path(), "index", &evidence());
    cached(
        &index,
        &[
            row("Methods", "Only__Method", 7, true),
            row("DeduplicatedMethods", "Only__Method", 999, false),
        ],
    );
    let bundle = root.path().join("bundle");
    prepare(&index, &bundle);
    let report = snapshot(&bundle);
    assert_eq!(report["coverage"]["identities"], 2);
    assert_eq!(report["coverage"]["displayed_accounted_bytes"], 7);
    assert_eq!(report["coverage"]["remaining_accounted_bytes"], 0);
    assert_eq!(report["contributors"].as_array().unwrap().len(), 1);
    assert_eq!(report["contributors"][0]["stream"], "Methods");
    assert_eq!(
        report["accounting"]["streams"],
        json!([{"name":"Methods","bytes":7,"identities":1}])
    );
}

#[test]
fn unicode_preview_preserves_full_raw_hash_and_lossy_identities_never_claim_sources() {
    let root = tempfile::tempdir().unwrap();
    let long = format!("{}é尾", "x".repeat(511));
    let entry = row("Methods", &long, 41, true);
    let displayed = data::Row::new(&entry, 19);
    assert_eq!(displayed.identity, "x".repeat(511));
    assert_eq!(displayed.identity_bytes, 516);
    assert!(displayed.truncated);
    assert_eq!(displayed.ordinal, 19);
    assert_eq!(displayed.bytes, 41);
    assert_eq!(
        displayed.raw_identity_blake3,
        blake3::hash(long.as_bytes()).to_hex().to_string()
    );
    assert!(!displayed.identity_lossy);
    for length in [511, 512, 513] {
        let exact = row("Methods", &"a".repeat(length), 1, true);
        let projection = data::Row::new(&exact, 0);
        assert_eq!(projection.identity.len(), length.min(512));
        assert_eq!(projection.truncated, length > 512);
    }
    let mut value = evidence();
    value.mappings.push(Mapping {
        stream: "Blobs".into(),
        identity: "\u{fffd}".into(),
        assembly: "App".into(),
        source_paths: vec![],
        basis: "display spelling only".into(),
    });
    let index = import(root.path(), "index", &value);
    let mut rows = vec![
        row("Blobs", "\u{fffd}", 30, true),
        row("Blobs", "\u{fffd}", 19, true),
    ];
    for (entry, raw) in rows.iter_mut().zip([[0_u8, 0xd8], [1, 0xd8]]) {
        entry.identity_lossy = true;
        entry.raw_identity_blake3 = blake3::hash(&raw).to_hex().to_string();
    }
    rows.push(entry);
    cached(&index, &rows);
    let bundle = root.path().join("bundle");
    prepare(&index, &bundle);
    let report = snapshot(&bundle);
    for ordinal in ["0", "1"] {
        let detail = &report["details"][ordinal];
        assert_eq!(detail["sources"]["status"], "unmapped_lossy_identity");
        assert_eq!(detail["sources"]["assemblies"], json!([]));
        assert_eq!(detail["sources"]["sources"], json!([]));
        assert_eq!(detail["row"]["identity_lossy"], true);
    }
    assert_ne!(
        report["details"]["0"]["row"]["raw_identity_blake3"],
        report["details"]["1"]["row"]["raw_identity_blake3"]
    );
    assert_eq!(
        report["details"]["2"]["row"]["raw_identity_blake3"],
        displayed.raw_identity_blake3
    );
}

#[test]
fn source_details_cap_associations_attributes_and_text_without_hiding_omissions() {
    let root = tempfile::tempdir().unwrap();
    let identity = "App_Widget__Run";
    let mut value = evidence();
    for index in 0..55 {
        value.sources.push(Source {
            assembly: "App".into(),
            type_name: "Widget".into(),
            member: Some("Run".into()),
            path: root.path().join(format!("missing-{index}.cs")),
            line: 3,
            end_line: 9,
            kind: "é".repeat(3000),
            attributes: vec!["é".repeat(700); 45],
            ..Source::default()
        });
    }
    value.mappings.push(Mapping {
        stream: "Methods".into(),
        identity: identity.into(),
        assembly: "App".into(),
        source_paths: value
            .sources
            .iter()
            .map(|source| source.path.clone())
            .collect(),
        basis: "é".repeat(3000),
    });
    let index = import(root.path(), "index", &value);
    cached(
        &index,
        &[
            row("Methods", identity, 7, true),
            row("Methods", "Absent__Member", 3, true),
        ],
    );
    let bundle = root.path().join("bundle");
    prepare(&index, &bundle);
    let report = snapshot(&bundle);
    let detail = &report["details"]["0"];
    assert_eq!(detail["sources"]["status"], "asserted");
    assert_eq!(detail["total_sources"], 55);
    assert_eq!(detail["omitted_sources"], 5);
    assert_eq!(detail["sources"]["basis"], "é".repeat(2048));
    let sources = detail["sources"]["sources"].as_array().unwrap();
    assert_eq!(sources.len(), 50);
    for source in sources {
        assert_eq!(source["line"], 3);
        assert_eq!(source["end_line"], 9);
        assert_eq!(source["kind"], "é".repeat(2048));
        assert_eq!(source["attributes"].as_array().unwrap().len(), 40);
        assert!(
            source["attributes"]
                .as_array()
                .unwrap()
                .iter()
                .all(|attr| *attr == "é".repeat(512))
        );
    }
    assert!(
        detail["caveat"]
            .as_str()
            .unwrap()
            .contains("complete cached identity")
    );
    assert_eq!(report["details"]["1"]["sources"]["status"], "unmapped");
    assert_eq!(report["details"]["1"]["total_sources"], 0);
    assert_eq!(report["details"]["1"]["sources"]["sources"], json!([]));
}

#[test]
fn immutable_output_options_and_precancel_leave_no_temporary_or_partial_bundle() {
    let root = tempfile::tempdir().unwrap();
    let (index, bundle) = simple(root.path());
    fs::write(bundle.join("user-marker"), b"preserve exactly").unwrap();
    let before: Vec<_> = ["bundle.json", "offsets.bin", "snapshot.json", "user-marker"]
        .iter()
        .map(|name| fs::read(bundle.join(name)).unwrap())
        .collect();
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
    assert_eq!(code(&error), "explorer.output.exists");
    for (name, expected) in ["bundle.json", "offsets.bin", "snapshot.json", "user-marker"]
        .iter()
        .zip(before)
    {
        assert_eq!(fs::read(bundle.join(name)).unwrap(), expected);
    }
    let names = directory_names(root.path());
    for (memory, nodes, inventories) in [
        ((32 << 20) - 1, vec![], vec![]),
        (MEMORY, vec![0, 1, 2, 3], vec![]),
        (MEMORY, vec![], vec![root.path().join("unused"); 17]),
    ] {
        let output = root.path().join("invalid");
        let error = data::prepare(
            &index,
            &output,
            &inventories,
            None,
            &nodes,
            "scan_index",
            memory,
            &IndexControl::default(),
        )
        .unwrap_err();
        assert_eq!(code(&error), "resource.explorer.options");
        assert!(!output.exists());
        assert_eq!(directory_names(root.path()), names);
    }
    let cancelled = IndexControl::default();
    cancelled.cancel();
    let output = root.path().join("cancelled");
    let error = data::prepare(
        &index,
        &output,
        &[],
        None,
        &[],
        "scan_index",
        MEMORY,
        &cancelled,
    )
    .unwrap_err();
    assert!(error.to_string().contains("resource.cancelled"), "{error}");
    assert!(!output.exists());
    assert_eq!(directory_names(root.path()), names);
    let minimal = root.path().join("minimal");
    data::prepare(
        &index,
        &minimal,
        &[],
        None,
        &[],
        "scan_index",
        32 << 20,
        &IndexControl::default(),
    )
    .unwrap();
    assert_eq!(snapshot(&minimal)["accounting"]["total_bytes"], 40);
}

#[test]
fn bundle_schema_generation_snapshot_offsets_and_index_corruption_are_explicit() {
    for mutation in [
        "schema",
        "snapshot-schema",
        "generation",
        "snapshot-hash",
        "offset-length",
        "offset-hash",
        "index",
    ] {
        let root = tempfile::tempdir().unwrap();
        let (index, bundle) = simple(root.path());
        let expected = match mutation {
            "schema" => {
                let mut value = read_json(&bundle.join("bundle.json"));
                value["schema"] = json!("vitnet.explorer-bundle.v2");
                write_json(&bundle.join("bundle.json"), &value);
                "explorer.schema"
            }
            "snapshot-schema" | "generation" | "snapshot-hash" => {
                let mut value = read_json(&bundle.join("snapshot.json"));
                let key = match mutation {
                    "snapshot-schema" => "schema",
                    "generation" => "generation",
                    _ => "title",
                };
                value[key] = json!("changed");
                write_json(&bundle.join("snapshot.json"), &value);
                if mutation == "snapshot-hash" {
                    "explorer.snapshot.integrity"
                } else {
                    "explorer.generation"
                }
            }
            "offset-length" => {
                fs::write(bundle.join("offsets.bin"), [0; 8]).unwrap();
                "explorer.offsets"
            }
            "offset-hash" => {
                let mut bytes = fs::read(bundle.join("offsets.bin")).unwrap();
                bytes[0] ^= 1;
                fs::write(bundle.join("offsets.bin"), bytes).unwrap();
                "explorer.integrity"
            }
            "index" => {
                let mut bytes = fs::read(index.join("index.json")).unwrap();
                bytes.push(b' ');
                fs::write(index.join("index.json"), bytes).unwrap();
                "explorer.source.stale"
            }
            _ => unreachable!(),
        };
        let error = data::verify(&bundle, MEMORY).unwrap_err();
        assert_eq!(code(&error), expected, "{mutation}: {error}");
    }
}

#[test]
fn verify_rejects_original_identity_length_and_same_length_hash_drift() {
    for same_length in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let (index, bundle) = simple(root.path());
        let path = index.join("identities.ndjson");
        let mut bytes = fs::read(&path).unwrap();
        if same_length {
            let position = bytes
                .windows(5)
                .position(|value| value == b"First")
                .unwrap();
            bytes[position] = b'X';
        } else {
            bytes.push(b'\n');
        }
        fs::write(&path, bytes).unwrap();
        let error = data::verify(&bundle, MEMORY).unwrap_err();
        assert_eq!(
            code(&error),
            if same_length {
                "explorer.integrity"
            } else {
                "explorer.source.stale"
            }
        );
    }
}

#[test]
fn preparation_verifies_offset_visitor_count_hash_json_and_complete_accounting() {
    for mutation in ["count", "hash", "json", "accounting"] {
        let root = tempfile::tempdir().unwrap();
        let (index, _) = simple(root.path());
        let mut manifest = read_json(&index.join("index.json"));
        match mutation {
            "count" => manifest["identities"] = json!(3),
            "hash" => manifest["identities_blake3"] = json!("0".repeat(64)),
            "json" => {
                fs::write(index.join("identities.ndjson"), b"not json\n").unwrap();
                manifest["identities"] = json!(1);
                manifest["identities_blake3"] =
                    json!(blake3::hash(b"not json\n").to_hex().to_string());
            }
            "accounting" => manifest["mstat"]["accounted_size_bytes"] = json!(41),
            _ => unreachable!(),
        }
        write_json(&index.join("index.json"), &manifest);
        let before = directory_names(root.path());
        let output = root.path().join("failed");
        let error = data::prepare(
            &index,
            &output,
            &[],
            None,
            &[],
            "scan_index",
            MEMORY,
            &IndexControl::default(),
        )
        .unwrap_err();
        assert_eq!(
            code(&error),
            match mutation {
                "json" => "attribution.cache.identity",
                "accounting" => "explorer.accounting",
                _ => "attribution.cache.integrity",
            }
        );
        assert!(!output.exists());
        assert_eq!(directory_names(root.path()), before);
    }
}

fn resource(name: &str, bytes: u64, storage: &str) -> Resource {
    Resource {
        assembly: "App".into(),
        container: "bundle".into(),
        name: name.into(),
        bytes,
        storage: storage.into(),
        sha256: Some("a".repeat(64)),
        ..Resource::default()
    }
}

#[test]
fn inventories_deduplicate_report_nonadditive_bytes_and_reject_missing_invalid_conflicts() {
    let root = tempfile::tempdir().unwrap();
    let (index, _) = simple(root.path());
    let mut inventory = evidence();
    inventory.resources = vec![
        resource("one", 30, "asset"),
        resource("two", 30, "asset"),
        resource("container", 100, "avalonia_container"),
    ];
    // Containers are deliberately not grouped as duplicate payload instances.
    inventory.resources[2].sha256 = None;
    let input = root.path().join("inventory.json");
    write_json(&input, &inventory);
    let output = root.path().join("supplemented");
    data::prepare(
        &index,
        &output,
        &[input.clone(), input.clone()],
        None,
        &[],
        "scan_index",
        MEMORY,
        &IndexControl::default(),
    )
    .unwrap();
    let report = snapshot(&output);
    assert_eq!(report["accounting"]["total_bytes"], 40);
    assert_eq!(report["coverage"]["resource_count"], 3);
    assert_eq!(report["coverage"]["resource_asset_bytes"], 60);
    assert_eq!(report["coverage"]["resource_container_bytes"], 100);
    assert_eq!(
        report["coverage"]["supplemental_inventories"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    assert_eq!(report["duplicate_assets"].as_array().unwrap().len(), 1);
    assert_eq!(report["duplicate_assets"][0]["bytes_each"], 30);
    assert_eq!(
        report["duplicate_assets"][0]["instances"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    assert!(
        report["caveats"]
            .as_array()
            .unwrap()
            .iter()
            .any(|value| value.as_str().unwrap().contains("never extra totals"))
    );
    for (kind, expected) in [
        ("missing", "attribution.io"),
        ("schema", "attribution.schema"),
        ("json", "attribution.json"),
        ("conflict", "explorer.inventory.conflict"),
    ] {
        let additional = root.path().join(format!("{kind}.json"));
        match kind {
            "schema" => write_json(&additional, &json!({"schema":"invalid"})),
            "json" => fs::write(&additional, b"{").unwrap(),
            "conflict" => {
                let mut conflicting = inventory.clone();
                conflicting.resources[0].bytes = 31;
                write_json(&additional, &conflicting);
            }
            _ => {}
        }
        let output = root.path().join(format!("failed-{kind}"));
        let error = data::prepare(
            &index,
            &output,
            &[input.clone(), additional],
            None,
            &[],
            "scan_index",
            MEMORY,
            &IndexControl::default(),
        )
        .unwrap_err();
        assert_eq!(code(&error), expected);
        assert!(!output.exists());
        assert!(
            !directory_names(root.path())
                .iter()
                .any(|name| name.starts_with(".vitnet-explorer-"))
        );
    }
}

#[test]
fn metadata_and_unknown_native_comparison_never_become_additive_or_zero_claims() {
    let root = tempfile::tempdir().unwrap();
    let (before, _) = simple(root.path());
    let metadata = root.path().join("metadata.csv");
    fs::write(&metadata, b"Handle, Kind, Name, Children\n00000000, ScopeDefinition, \"App\", \"a\"\n0000000a, TypeDefinition, \"Widget\", \"14\"\n00000014, Method, \"Run\", \"\"\n00000028, End, \"\", \"\"\n").unwrap();
    let mut value = evidence();
    value.artifacts.push(artifact("metadata", metadata));
    let after = import(root.path(), "after", &value);
    let bundle = root.path().join("compared");
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
    let report = snapshot(&bundle);
    assert_eq!(report["accounting"]["total_bytes"], Value::Null);
    assert!(
        report["accounting"]["metadata_lower_bound_bytes"]
            .as_u64()
            .unwrap()
            > 0
    );
    assert_eq!(report["coverage"]["displayed_accounted_bytes"], 0);
    assert_eq!(report["comparison"]["physical"]["delta_bytes"], Value::Null);
    assert_eq!(
        report["comparison"]["physical"]["before_bytes"],
        Value::Null
    );
    assert_eq!(report["comparison"]["physical"]["after_bytes"], Value::Null);
    assert_eq!(report["comparison"]["physical"]["sections"], json!([]));
}

fn command(arguments: &[&str]) -> String {
    let mut args = vec!["vitnet", "--format", "json", "explore"];
    args.extend_from_slice(arguments);
    vitnet_cli::execute(&Cli::try_parse_from(args).unwrap()).unwrap()
}

#[test]
fn cli_prepare_verify_and_offline_export_escape_redact_and_refuse_overwrite() {
    let root = tempfile::tempdir().unwrap();
    let untrusted = "</script><>&\u{2028}\u{2029}";
    let mut value = evidence();
    value.label = untrusted.into();
    value
        .provenance
        .insert("private".into(), "SECRET-PROVENANCE".into());
    value.diagnostics.push(EvidenceDiagnostic {
        code: "evidence.test".into(),
        message: "SECRET-DIAGNOSTIC".into(),
        path: Some(root.path().join("SECRET-PATH")),
    });
    let index = import(root.path(), "index", &value);
    let bundle = root.path().join("bundle");
    let result: Value = serde_json::from_str(&command(&[
        "prepare",
        index.to_str().unwrap(),
        "--bundle",
        bundle.to_str().unwrap(),
    ]))
    .unwrap();
    assert_eq!(result["schema"], "vitnet.explorer-bundle.v1");
    assert_eq!(result["identities"], 0);
    assert!(command(&["verify", bundle.to_str().unwrap()]).contains("verified"));
    let html = root.path().join("offline.html");
    command(&[
        "export",
        bundle.to_str().unwrap(),
        "--html",
        html.to_str().unwrap(),
    ]);
    let content = fs::read_to_string(&html).unwrap();
    assert!(!content.contains(untrusted));
    assert!(content.contains("\\u003c/script\\u003e\\u003c\\u003e\\u0026\\u2028\\u2029"));
    assert!(content.contains("SECRET-PROVENANCE"));
    assert!(content.contains("SECRET-DIAGNOSTIC"));
    assert!(content.contains("SECRET-PATH"));
    assert!(!content.contains("<!--VITNET_STYLE-->"));
    assert!(!content.contains("/*VITNET_APP*/"));
    assert!(!content.contains("/*VITNET_WORKER*/null"));
    assert!(!content.contains("<script src="));
    assert!(!content.contains("<link rel=\"stylesheet\""));
    assert!(content.contains("const OFFLINE = true;"));
    assert!(content.contains("<meta http-equiv=\"Content-Security-Policy\""));
    assert!(content.contains("connect-src 'none'"));
    let redacted = root.path().join("redacted.html");
    command(&[
        "export",
        bundle.to_str().unwrap(),
        "--html",
        redacted.to_str().unwrap(),
        "--redact-paths",
    ]);
    let safe = fs::read_to_string(&redacted).unwrap();
    for secret in ["SECRET-PROVENANCE", "SECRET-DIAGNOSTIC", "SECRET-PATH"] {
        assert!(!safe.contains(secret), "redaction leaked {secret}");
    }
    assert!(safe.contains("Exported provenance values omitted"));
    assert!(safe.contains("\\u003credacted\\u003e"));
    let cli = Cli::try_parse_from([
        "vitnet",
        "explore",
        "export",
        bundle.to_str().unwrap(),
        "--html",
        html.to_str().unwrap(),
    ])
    .unwrap();
    assert_eq!(code(&vitnet_cli::execute(&cli).unwrap_err()), "io.explorer");
    assert_eq!(fs::read_to_string(&html).unwrap(), content);
}

#[test]
fn offline_witnesses_use_bounded_depth_and_generation_checked_graph() {
    let root = tempfile::tempdir().unwrap();
    let graph = root.path().join("graph.xml");
    let mut xml = String::from("<DirectedGraph><Nodes>");
    for id in 0..15 {
        write!(xml, "<Node Id=\"{id}\" Label=\"node{id}\"/>").unwrap();
    }
    xml.push_str("</Nodes><Links>");
    for id in 0..14 {
        write!(
            xml,
            "<Link Source=\"{id}\" Target=\"{}\" Reason=\"because{id}\"/>",
            id + 1
        )
        .unwrap();
    }
    xml.push_str("</Links></DirectedGraph>");
    fs::write(&graph, xml).unwrap();
    let graph_index = build_index(
        &graph,
        &IndexOptions {
            cache_root: root.path().join("cache"),
            memory_limit: MEMORY,
            selected_entry: None,
            strict_hash: false,
            control: IndexControl::default(),
        },
    )
    .unwrap()
    .index_directory;
    let mut value = evidence();
    value.artifacts.push(artifact("scan_index", graph_index));
    let index = import(root.path(), "index", &value);
    let bundle = root.path().join("bundle");
    data::prepare(
        &index,
        &bundle,
        &[],
        None,
        &[14, 0, 1],
        "scan_index",
        MEMORY,
        &IndexControl::default(),
    )
    .unwrap();
    let report = snapshot(&bundle);
    assert_eq!(report["witnesses"].as_array().unwrap().len(), 3);
    assert_eq!(report["witnesses"][0]["stop_reason"], "max_depth");
    assert_eq!(report["witnesses"][0]["paths"], json!([]));
    assert_eq!(report["witnesses"][1]["paths"][0]["nodes"][0]["node_id"], 0);
    assert_eq!(report["witnesses"][2]["paths"][0]["reasons"][0], "because0");
    assert_eq!(report["limits"]["query_timeout_ms"], 1500);
    assert_eq!(report["limits"]["max_scanned"], 100_000);
    assert_eq!(report["limits"]["graph_nodes"], 200);
    assert_eq!(report["limits"]["graph_edges"], 500);
    assert!(
        report["witnesses"][2]["caveat"]
            .as_str()
            .unwrap()
            .contains("conjunctions, not independent sufficient causes")
    );
    let mut manifest = read_json(&index.join("index.json"));
    manifest["artifacts"][0]["graph_generation"] = json!("stale");
    write_json(&index.join("index.json"), &manifest);
    let error = data::prepare(
        &index,
        &root.path().join("stale"),
        &[],
        None,
        &[1],
        "scan_index",
        MEMORY,
        &IndexControl::default(),
    )
    .unwrap_err();
    assert_eq!(code(&error), "explorer.graph.stale");
    let no_graph = import(root.path(), "no-graph", &evidence());
    let error = data::prepare(
        &no_graph,
        &root.path().join("missing"),
        &[],
        None,
        &[1],
        "scan_index",
        MEMORY,
        &IndexControl::default(),
    )
    .unwrap_err();
    assert_eq!(code(&error), "explorer.graph.missing");
}

#[test]
fn browse_with_output_is_rejected_without_starting_a_server() {
    let cli = Cli::try_parse_from([
        "vitnet",
        "--output",
        "do-not-write",
        "explore",
        "browse",
        "absent",
    ])
    .unwrap();
    let error = vitnet_cli::explorer::execute(
        &cli,
        &ExploreCommand::Browse {
            bundle: "absent".into(),
            port: 0,
            open: false,
        },
        &IndexControl::default(),
    )
    .unwrap_err();
    assert_eq!(code(&error), "explorer.output");
}

#[test]
fn snapshot_size_and_offset_count_overflow_fail_before_reading_unbounded_data() {
    for mutation in ["snapshot-size", "offset-overflow"] {
        let root = tempfile::tempdir().unwrap();
        let (_, bundle) = simple(root.path());
        if mutation == "snapshot-size" {
            std::fs::File::options()
                .write(true)
                .open(bundle.join("snapshot.json"))
                .unwrap()
                .set_len(8 * 1024 * 1024 + 1)
                .unwrap();
        } else {
            let mut manifest = read_json(&bundle.join("bundle.json"));
            manifest["identities"] = json!(u64::MAX);
            write_json(&bundle.join("bundle.json"), &manifest);
        }
        let Err(error) = data::Bundle::open(&bundle, MEMORY) else {
            panic!("invalid {mutation} bundle accepted");
        };
        assert_eq!(
            code(&error),
            if mutation == "snapshot-size" {
                "resource.explorer.snapshot"
            } else {
                "explorer.offsets"
            }
        );
    }
}

#[test]
fn supplemental_package_and_resource_identity_conflicts_are_not_silently_overwritten() {
    let root = tempfile::tempdir().unwrap();
    let (index, _) = simple(root.path());
    let mut value = evidence();
    value.resources.push(resource("same", 10, "asset"));
    value.packages.push(Package {
        target: "net10.0".into(),
        id: "Package".into(),
        version: "1.0".into(),
        direct: true,
        dependencies: vec![],
    });
    let original = root.path().join("original.json");
    write_json(&original, &value);
    let accepted = root.path().join("sixteen");
    data::prepare(
        &index,
        &accepted,
        &vec![original.clone(); 16],
        None,
        &[],
        "scan_index",
        MEMORY,
        &IndexControl::default(),
    )
    .unwrap();
    let report = snapshot(&accepted);
    assert_eq!(
        report["coverage"]["supplemental_inventories"]
            .as_array()
            .unwrap()
            .len(),
        16
    );
    assert_eq!(report["coverage"]["resource_count"], 1);
    assert_eq!(report["coverage"]["resource_asset_bytes"], 10);
    for partition in ["hash", "storage", "package-dependencies", "package-direct"] {
        let mut conflict = value.clone();
        match partition {
            "hash" => conflict.resources[0].sha256 = Some("b".repeat(64)),
            "storage" => conflict.resources[0].storage = "different-storage".into(),
            "package-dependencies" => conflict.packages[0].dependencies.push("Other".into()),
            "package-direct" => conflict.packages[0].direct = false,
            _ => unreachable!(),
        }
        let path = root.path().join(format!("{partition}.json"));
        write_json(&path, &conflict);
        let output = root.path().join(format!("{partition}-output"));
        let error = data::prepare(
            &index,
            &output,
            &[original.clone(), path],
            None,
            &[],
            "scan_index",
            MEMORY,
            &IndexControl::default(),
        )
        .unwrap_err();
        assert_eq!(code(&error), "explorer.inventory.conflict");
        assert!(!output.exists());
        assert!(
            !directory_names(root.path())
                .iter()
                .any(|name| name.starts_with(".vitnet-explorer-"))
        );
    }
}

#[test]
#[allow(clippy::too_many_lines)] // Pin independent nonadditive public snapshot projections together.
fn generic_generator_and_package_projections_keep_independent_accounting_and_evidence() {
    let root = tempfile::tempdir().unwrap();
    let mut value = evidence();
    let source_path = root.path().join("missing-generated.cs");
    value.sources.push(Source {
        assembly: "App".into(),
        type_name: "Widget".into(),
        path: source_path.clone(),
        line: 1,
        end_line: 2,
        kind: "class".into(),
        generated_by: Some("Emitter".into()),
        ..Source::default()
    });
    value.generators.push(Generator {
        name: "Emitter".into(),
        version: "2.3".into(),
        assembly_path: "tool.dll".into(),
        generated_files: vec![source_path.clone()],
        input_symbols: vec!["input".into()],
    });
    for identity in ["App_Widget<int>__Run", "App_Widget<__Canon>__Run"] {
        value.mappings.push(Mapping {
            stream: "Methods".into(),
            identity: identity.into(),
            assembly: "App".into(),
            source_paths: vec![source_path.clone()],
            basis: "asserted fixture".into(),
        });
    }
    value.packages = vec![
        Package {
            target: "net10".into(),
            id: "Root".into(),
            version: "1".into(),
            direct: true,
            dependencies: vec!["Leaf/1".into(), "Missing/1".into()],
        },
        Package {
            target: "net10".into(),
            id: "Leaf".into(),
            version: "1".into(),
            direct: false,
            dependencies: vec![],
        },
    ];
    let index = import(root.path(), "index", &value);
    cached(
        &index,
        &[
            row("Methods", "App_Widget<int>__Run", 10, true),
            row("Methods", "App_Widget<__Canon>__Run", 20, true),
            row("Methods", "Broken<__Run", 3, true),
            row("Types", "App_Widget<int>__Run", 5, true),
            row("Blobs", "App_Widget<int>__Run", 7, true),
        ],
    );
    let bundle = root.path().join("bundle");
    prepare(&index, &bundle);
    let report = snapshot(&bundle);
    assert_eq!(report["coverage"]["displayed_accounted_bytes"], 45);
    assert_eq!(report["coverage"]["remaining_accounted_bytes"], 0);
    assert_eq!(report["coverage"]["generic_family_count"], 2);
    assert_eq!(report["coverage"]["malformed_generic_identities"], 1);
    assert_eq!(
        report["generic_families"],
        json!([
            {"stream":"Methods","family":"App_Widget<>__Run","bytes":30,"identities":2,"canonical_shared_identities":1},
            {"stream":"Types","family":"App_Widget<>__Run","bytes":5,"identities":1,"canonical_shared_identities":0}
        ])
    );
    let emitter = &report["generators"][0];
    assert_eq!(emitter["name"], "Emitter");
    assert_eq!(emitter["version"], "2.3");
    assert_eq!(emitter["generated_files"], 1);
    assert_eq!(emitter["declared_inputs"], 1);
    assert_eq!(emitter["generated_declarations"], 1);
    assert_eq!(emitter["asserted_accounted_bytes"], 30);
    assert_eq!(emitter["candidate_accounted_bytes"], 12);
    assert!(emitter["caveat"].as_str().unwrap().contains("may overlap"));
    assert_eq!(report["coverage"]["package_route_count"], 2);
    let routes = report["package_routes"].as_array().unwrap();
    let leaf = routes
        .iter()
        .find(|route| route["package"] == "Leaf/1")
        .unwrap();
    assert_eq!(leaf["shortest_route"], json!(["Root/1", "Leaf/1"]));
    assert_eq!(leaf["retained_by_packages"], json!(["Root/1"]));
    assert_eq!(leaf["direct"], false);
    let route = routes
        .iter()
        .find(|route| route["package"] == "Root/1")
        .unwrap();
    assert_eq!(route["missing_dependencies"], json!(["Missing/1"]));
    assert_eq!(route["shortest_route"], json!(["Root/1"]));
    assert_eq!(route["cyclic_target"], false);
    let owner = report["groups"]
        .as_array()
        .unwrap()
        .iter()
        .find(|group| {
            group["dimension"] == "owner"
                && group["stream"] == "Methods"
                && group["name"] == "App_Widget"
        })
        .unwrap();
    assert_eq!(owner["bytes"], 30);
    assert_eq!(owner["identities"], 2);
    assert_eq!(owner["status"], "opaque_producer_family_prefix");
}

#[test]
fn offline_export_keeps_template_markers_and_script_evidence_inert() {
    let root = tempfile::tempdir().unwrap();
    let literal = "/*VITNET_APP*/ | /*VITNET_WORKER*/null | /*VITNET_DATA*/null | /*VITNET_OFFLINE*/false | <!--VITNET_STYLE--> | <script>globalThis.EVIDENCE_ONLY = 'not executable';</script>";
    let mut value = evidence();
    value.label = literal.into();
    let index = import(root.path(), "index", &value);
    let bundle = root.path().join("bundle");
    let prepared = prepare(&index, &bundle);
    let output = root.path().join("markers.html");
    command(&[
        "export",
        bundle.to_str().unwrap(),
        "--html",
        output.to_str().unwrap(),
    ]);
    let content = fs::read_to_string(output).unwrap();
    let serialized = content
        .split_once("const SNAPSHOT = ")
        .unwrap()
        .1
        .lines()
        .next()
        .unwrap()
        .strip_suffix(';')
        .unwrap();
    let exported: Value = serde_json::from_str(serialized).unwrap();
    // Exact decoded evidence catches substitutions inside the JSON string,
    // even when the corrupted export would still be valid JavaScript/JSON.
    assert_eq!(exported["title"], literal);
    assert_eq!(exported["schema"], "vitnet.explorer-snapshot.v1");
    assert_eq!(exported["generation"], prepared.generation);
    assert!(serialized.contains("/*VITNET_APP*/"));
    assert!(serialized.contains("/*VITNET_WORKER*/null"));
    assert!(serialized.contains("\\u003cscript\\u003e"));
    assert!(serialized.contains("\\u003c/script\\u003e"));
    assert!(!serialized.contains('<'));
    assert!(!serialized.contains('>'));
    assert_eq!(content.matches("<script>").count(), 1);
    assert_eq!(content.matches("</script>").count(), 1);
    assert!(!content.contains("<script>globalThis.EVIDENCE_ONLY"));
    assert!(content.contains("const OFFLINE = true;"));
    assert!(content.contains("connect-src 'none'"));
}

#[test]
#[allow(clippy::too_many_lines)] // Pin the generation recipe and independent projection dimensions together.
fn generation_fingerprints_original_inputs_and_each_bounded_projection() {
    let root = tempfile::tempdir().unwrap();
    let graph = root.path().join("graph.xml");
    fs::write(
        &graph,
        "<DirectedGraph><Nodes><Node Id=\"0\" Label=\"root\"/><Node Id=\"1\" Label=\"child\"/></Nodes><Links><Link Source=\"0\" Target=\"1\" Reason=\"because-root\"/></Links></DirectedGraph>",
    )
    .unwrap();
    let graph_index = build_index(
        &graph,
        &IndexOptions {
            cache_root: root.path().join("cache"),
            memory_limit: MEMORY,
            selected_entry: None,
            strict_hash: false,
            control: IndexControl::default(),
        },
    )
    .unwrap()
    .index_directory;
    let mut value = evidence();
    value.label = "λ".repeat(3000);
    value.provenance.insert("build".into(), "é".repeat(1000));
    value.artifacts.push(artifact("scan_index", graph_index));
    let index = import(root.path(), "index", &value);
    cached(
        &index,
        &[row(
            "Methods",
            &format!("Owner__{}TAIL", "x".repeat(600)),
            23,
            true,
        )],
    );
    let original_index = fs::read(index.join("index.json")).unwrap();
    let original_identities = fs::read(index.join("identities.ndjson")).unwrap();
    let index_hash = blake3::hash(&original_index).to_hex().to_string();
    let identities_hash = blake3::hash(&original_identities).to_hex().to_string();

    let mut inventory = evidence();
    inventory.resources = vec![resource("projection-one", 31, "asset")];
    let first_inventory = root.path().join("first-inventory.json");
    write_json(&first_inventory, &inventory);
    inventory.resources[0].bytes = 37;
    let second_inventory = root.path().join("second-inventory.json");
    write_json(&second_inventory, &inventory);
    let mut old = evidence();
    old.provenance.insert("build".into(), "old-one".into());
    let first_before = import(root.path(), "before-one", &old);
    old.provenance.insert("build".into(), "old-two".into());
    let second_before = import(root.path(), "before-two", &old);

    let make = |name: &str, inventories: &[PathBuf], before: Option<&Path>, nodes: &[u64]| {
        let bundle = root.path().join(name);
        let manifest = data::prepare(
            &index,
            &bundle,
            inventories,
            before,
            nodes,
            "scan_index",
            MEMORY,
            &IndexControl::default(),
        )
        .unwrap();
        (manifest, snapshot(&bundle))
    };
    let baseline = make("baseline", &[], None, &[]);
    let repeated = make("repeated", &[], None, &[]);
    assert_eq!(baseline.0.generation, repeated.0.generation);
    assert_eq!(baseline.1, repeated.1);
    assert_eq!(baseline.1["title"], "λ".repeat(2048));
    assert_eq!(baseline.1["provenance"]["build"], "é".repeat(512));
    assert_eq!(baseline.1["contributors"][0]["identity_bytes"], 611);
    assert_eq!(baseline.1["contributors"][0]["truncated"], true);
    assert_eq!(baseline.1["comparison"], Value::Null);
    assert_eq!(baseline.1["witnesses"], json!([]));

    let resource_one = make("resource-one", &[first_inventory], None, &[]);
    let resource_two = make("resource-two", &[second_inventory], None, &[]);
    assert_eq!(resource_one.1["resources"][0]["bytes"], 31);
    assert_eq!(resource_two.1["resources"][0]["bytes"], 37);
    let comparison_one = make("comparison-one", &[], Some(&first_before), &[]);
    let comparison_two = make("comparison-two", &[], Some(&second_before), &[]);
    assert_eq!(
        comparison_one.1["comparison"]["schema"],
        "vitnet.attribution-compare.v1"
    );
    assert_eq!(
        comparison_one.1["comparison"]["provenance_changes"][0]["before"],
        "old-one"
    );
    assert_eq!(
        comparison_two.1["comparison"]["provenance_changes"][0]["before"],
        "old-two"
    );
    let witness_root = make("witness-root", &[], None, &[0]);
    let witness_child = make("witness-child", &[], None, &[1]);
    assert_eq!(witness_root.1["witnesses"].as_array().unwrap().len(), 1);
    assert_eq!(witness_root.1["witnesses"][0]["node"]["node_id"], 0);
    assert_eq!(witness_child.1["witnesses"].as_array().unwrap().len(), 1);
    assert_eq!(witness_child.1["witnesses"][0]["node"]["node_id"], 1);
    assert_eq!(
        witness_child.1["witnesses"][0]["paths"][0]["reasons"],
        json!(["because-root"])
    );
    let variants = [
        baseline,
        resource_one,
        resource_two,
        comparison_one,
        comparison_two,
        witness_root,
        witness_child,
    ];
    let mut generations = BTreeSet::new();
    for (manifest, mut report) in variants {
        assert_eq!(manifest.index_blake3, index_hash);
        assert_eq!(manifest.identities_blake3, identities_hash);
        assert_eq!(report["generation"], manifest.generation);
        // Independent reconstruction of the specified wire-level hash recipe.
        // The bounded projection, not unbounded evidence or generation itself,
        // is hashed after both original source fingerprints and the domain.
        report["generation"] = Value::Null;
        let mut fingerprint = blake3::Hasher::new();
        fingerprint.update(b"vitnet.explorer-generation.v1\0");
        fingerprint.update(index_hash.as_bytes());
        fingerprint.update(identities_hash.as_bytes());
        fingerprint.update(&serde_json::to_vec(&report).unwrap());
        assert_eq!(
            manifest.generation,
            fingerprint.finalize().to_hex().to_string()
        );
        assert!(
            generations.insert(manifest.generation),
            "different supplemental/comparison/witness projections collided"
        );
    }
    assert_eq!(generations.len(), 7);
    assert_eq!(fs::read(index.join("index.json")).unwrap(), original_index);
    assert_eq!(
        fs::read(index.join("identities.ndjson")).unwrap(),
        original_identities
    );
}

#[test]
#[allow(clippy::too_many_lines)] // Reconcile full comparison counts with bounded export projections.
fn comparison_lists_cap_at_one_hundred_without_losing_full_projection_counts() {
    let root = tempfile::tempdir().unwrap();
    let mut before_evidence = evidence();
    for id in 0..104 {
        before_evidence.provenance.insert(
            format!("setting-{id:03}"),
            format!("SECRET-BEFORE-PROVENANCE-{id:03}"),
        );
        let path = root.path().join(format!("source-{id:03}.cs"));
        fs::write(&path, format!("before source {id:03}")).unwrap();
        before_evidence.sources.push(Source {
            assembly: "App".into(),
            type_name: format!("Type{id:03}"),
            path,
            line: 1,
            end_line: 1,
            kind: "class".into(),
            ..Default::default()
        });
    }
    let before = import(root.path(), "before", &before_evidence);
    let mut after_evidence = before_evidence.clone();
    for id in 0..104 {
        after_evidence.provenance.insert(
            format!("setting-{id:03}"),
            format!("SECRET-AFTER-PROVENANCE-{id:03}"),
        );
        fs::write(
            root.path().join(format!("source-{id:03}.cs")),
            format!("after source {id:03}"),
        )
        .unwrap();
    }
    let after = import(root.path(), "after", &after_evidence);
    let complete = vitnet_attribution::compare(&before, &after, MEMORY, 100).unwrap();
    assert_eq!(complete.provenance_changes.len(), 104);
    assert_eq!(complete.source_changes.len(), 104);
    assert_eq!(complete.diagnostics.len(), 105); //104 stale sources plus missing MSTAT.
    let full = serde_json::to_value(&complete).unwrap();
    let bundle = root.path().join("bundle");
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
    let report = snapshot(&bundle);
    let comparison = &report["comparison"];
    assert_eq!(comparison["schema"], "vitnet.attribution-compare.v1");
    assert_eq!(
        comparison["projection_counts"].as_object().unwrap().len(),
        6
    );
    for key in [
        "provenance_changes",
        "package_changes",
        "graph_generation_changes",
        "source_changes",
        "attribution_visible_changes",
        "diagnostics",
    ] {
        let entries = full[key].as_array().unwrap();
        assert_eq!(comparison["projection_counts"][key], entries.len());
        assert_eq!(comparison[key], json!(&entries[..entries.len().min(100)]));
    }
    let provenance = comparison["provenance_changes"].as_array().unwrap();
    let sources = comparison["source_changes"].as_array().unwrap();
    assert_eq!(provenance.len(), 100);
    assert_eq!(sources.len(), 100);
    for id in [0, 99] {
        assert_eq!(provenance[id]["key"], format!("setting-{id:03}"));
        assert_eq!(
            provenance[id]["before"],
            format!("SECRET-BEFORE-PROVENANCE-{id:03}")
        );
        assert_eq!(
            provenance[id]["after"],
            format!("SECRET-AFTER-PROVENANCE-{id:03}")
        );
        assert_eq!(
            sources[id]["key"],
            root.path()
                .join(format!("source-{id:03}.cs"))
                .to_string_lossy()
                .as_ref()
        );
        assert_eq!(
            sources[id]["before"],
            blake3::hash(format!("before source {id:03}").as_bytes())
                .to_hex()
                .to_string()
        );
        assert_eq!(
            sources[id]["after"],
            blake3::hash(format!("after source {id:03}").as_bytes())
                .to_hex()
                .to_string()
        );
    }
    assert_eq!(comparison["physical"]["delta_bytes"], Value::Null);
    assert!(fs::metadata(bundle.join("snapshot.json")).unwrap().len() <= 8 << 20);
    let html = root.path().join("redacted.html");
    command(&[
        "export",
        bundle.to_str().unwrap(),
        "--html",
        html.to_str().unwrap(),
        "--redact-paths",
    ]);
    let exported = fs::read_to_string(html).unwrap();
    assert!(!exported.contains("SECRET-BEFORE-PROVENANCE"));
    assert!(!exported.contains("SECRET-AFTER-PROVENANCE"));
    assert!(exported.contains("Exported provenance values omitted"));
}

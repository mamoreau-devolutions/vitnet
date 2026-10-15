//! Investigation regressions: independent local fixtures, no corpus/network.
use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use vitnet_attribution::Matcher;
use vitnet_attribution::model::{
    Artifact, Assembly, Binary, BinarySection, EVIDENCE_SCHEMA, Evidence, Mapping, Package,
    Resource, Source,
};
use vitnet_cli::AppError;
use vitnet_cli::explorer::data;
use vitnet_dgml::IndexControl;
use vitnet_mstat::CoalescedIdentity;

#[allow(dead_code)] // Shared fixture also exposes helpers not needed by this target.
#[path = "../../vitnet-attribution/tests/common/mod.rs"]
mod common;

const MEMORY: u64 = 128 << 20;
const LINK_CAVEAT: &str =
    "Recorded package origin, not compiler retention, exclusive byte ownership or removable size.";
const ACCOUNTING_BASIS: &str =
    "Reported NativeAOT object sizes; not a physical executable sum or savings estimate.";
const RESOURCE_BASIS: &str = "Inventory containers may contain child assets; neither inventory sum is additive to Blobs or proven equal to ResourceData.";
const DUPLICATE_CAVEAT: &str = "Collector content hashes establish equal asset content, not independently reclaimable native bytes.";
const RANKED_PAIRS: [(u64, u64); 7] = [
    (1000, 5),
    (120, 3),
    (90, 1),
    (90, 2),
    (45, 6),
    (10, 0),
    (0, 4),
];

fn evidence() -> Evidence {
    Evidence {
        schema: EVIDENCE_SCHEMA.into(),
        label: "Synthetic investigation".into(),
        ..Evidence::default()
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

fn cache(index: &Path, rows: &[CoalescedIdentity]) {
    let mut payload = Vec::new();
    for row in rows {
        payload.extend(serde_json::to_vec(row).unwrap());
        payload.push(b'\n');
    }
    fs::write(index.join("identities.ndjson"), &payload).unwrap();
    let mut manifest = read_json(&index.join("index.json"));
    manifest["identities"] = json!(rows.len());
    manifest["identities_blake3"] = json!(blake3::hash(&payload).to_hex().to_string());
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

fn seed() -> Vec<CoalescedIdentity> {
    let mut rows: Vec<_> = [10, 90, 90, 120, 0, 1000, 45]
        .into_iter()
        .enumerate()
        .map(|(ordinal, bytes)| {
            let stream = match ordinal {
                5 => "Blobs",
                6 => "Types",
                _ => "Methods",
            };
            row(
                stream,
                &format!("Opaque__Row{ordinal}"),
                bytes,
                ordinal != 5,
            )
        })
        .collect();
    rows[1].records = 2;
    rows
}

fn prepare(index: &Path, output: &Path, supplemental: &[PathBuf]) -> data::BundleManifest {
    data::prepare(
        index,
        output,
        supplemental,
        None,
        &[],
        "scan_index",
        MEMORY,
        &IndexControl::default(),
    )
    .unwrap()
}

fn cached_bundle(root: &Path, value: &Evidence, rows: &[CoalescedIdentity]) -> PathBuf {
    let index = import(root, "index", value);
    cache(&index, rows);
    let output = root.join("bundle");
    prepare(&index, &output, &[]);
    output
}

fn catalog(bundle: &Path, dataset: &str) -> Vec<Value> {
    fs::read(bundle.join(format!("catalog_{dataset}.ndjson")))
        .unwrap()
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .map(|line| serde_json::from_slice(line).unwrap())
        .collect()
}

fn diagnostic(error: &AppError) -> (&str, &str) {
    match error {
        AppError::Unsupported(value)
        | AppError::Resource(value)
        | AppError::IoDiagnostic(value) => (&value.code, &value.message),
        AppError::Dgml(value) => (&value.diagnostic.code, &value.diagnostic.message),
        _ => panic!("unexpected error variant: {error}"),
    }
}

fn expect_error<T>(result: Result<T, AppError>, code: &str, message: Option<&str>) {
    let Err(error) = result else {
        panic!("expected {code}, got success");
    };
    let actual = diagnostic(&error);
    assert_eq!(actual.0, code, "{error}");
    if let Some(message) = message {
        assert_eq!(actual.1, message, "{error}");
    }
}

fn encode_pairs(pairs: &[(u64, u64)]) -> Vec<u8> {
    let mut bytes = Vec::new();
    for (size, ordinal) in pairs {
        bytes.extend(size.to_le_bytes());
        bytes.extend(ordinal.to_le_bytes());
    }
    bytes
}

// Independently re-fingerprint only disposable fixtures. This allows mutations
// to reach semantic validators instead of failing on an unrelated generation.
fn refingerprint(bundle: &Path, manifest: &mut Value, snapshot: &mut Value) {
    snapshot["generation"] = Value::Null;
    let mut fingerprint = blake3::Hasher::new();
    fingerprint.update(b"vitnet.explorer-generation.v1\0");
    fingerprint.update(manifest["index_blake3"].as_str().unwrap().as_bytes());
    fingerprint.update(manifest["identities_blake3"].as_str().unwrap().as_bytes());
    fingerprint.update(&serde_json::to_vec(snapshot).unwrap());
    let generation = fingerprint.finalize().to_hex().to_string();
    snapshot["generation"] = json!(generation);
    manifest["generation"] = json!(generation);
    let bytes = serde_json::to_vec(snapshot).unwrap();
    manifest["snapshot_blake3"] = json!(blake3::hash(&bytes).to_hex().to_string());
    fs::write(bundle.join("snapshot.json"), bytes).unwrap();
    write_json(&bundle.join("bundle.json"), manifest);
}

fn rewrite_ranking(bundle: &Path, bytes: &[u8], records: u64) {
    fs::write(bundle.join("ranking.bin"), bytes).unwrap();
    let descriptor = json!({
        "records": records,
        "blake3": blake3::hash(bytes).to_hex().to_string(),
    });
    let mut manifest = read_json(&bundle.join("bundle.json"));
    let mut snapshot = read_json(&bundle.join("snapshot.json"));
    manifest["ranking"] = descriptor.clone();
    snapshot["ranking"] = descriptor;
    refingerprint(bundle, &mut manifest, &mut snapshot);
}

fn mapping(stream: &str, identity: &str, assembly: &str) -> Mapping {
    Mapping {
        stream: stream.into(),
        identity: identity.into(),
        assembly: assembly.into(),
        basis: "fixed_explicit_evidence".into(),
        ..Mapping::default()
    }
}

fn scope(
    dimension: &str,
    stream: &str,
    name: &str,
    bytes: u64,
    identities: u64,
    statuses: &[&str],
) -> Value {
    json!({
        "dimension":dimension, "stream":stream, "name":name,
        "bytes":bytes, "identities":identities, "statuses":statuses,
    })
}

fn assert_scope(records: &[Value], expected: &Value) {
    let matches: Vec<_> = records
        .iter()
        .filter(|record| {
            record["dimension"] == expected["dimension"]
                && record["stream"] == expected["stream"]
                && record["name"] == expected["name"]
        })
        .collect();
    assert_eq!(matches.len(), 1, "{expected}");
    assert_eq!(matches[0], expected);
}

fn artifact(kind: &str, path: PathBuf) -> Artifact {
    Artifact {
        kind: kind.into(),
        path,
        revision: None,
        blake3: None,
    }
}

fn mstat(root: &Path, image: common::Image) -> Artifact {
    let path = root.join("reported.mstat");
    fs::write(&path, image.bytes()).unwrap();
    artifact("mstat", path)
}

fn resources() -> Vec<Resource> {
    let h1 = "ab".repeat(32);
    let h2 = "cd".repeat(32);
    [
        ("A", 30, Some(h1.clone()), "asset"),
        ("B", 30, Some(h1.to_ascii_uppercase()), "asset"),
        ("C", 30, Some(h2), "asset"),
        ("D", 30, None, "asset"),
        ("Manifest", 800, Some(h1.clone()), "manifest_container"),
        ("Avalonia", 900, Some(h1), "avalonia_container"),
    ]
    .into_iter()
    .map(|(name, bytes, sha256, storage)| Resource {
        assembly: "App".into(),
        container: "App.resources".into(),
        name: name.into(),
        bytes,
        sha256,
        storage: storage.into(),
        ..Resource::default()
    })
    .collect()
}

fn directory_names(root: &Path) -> BTreeSet<String> {
    fs::read_dir(root)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_str().unwrap().to_owned())
        .collect()
}

#[test]
fn ranking_binary_descriptor_le_order_ties_and_permutation() {
    let mut singleton = row("Methods", "Single__Zero", 0, true);
    singleton.records = 2;
    for (rows, pairs) in [
        (Vec::new(), Vec::new()),
        (vec![singleton], vec![(0, 0)]),
        (seed(), RANKED_PAIRS.to_vec()),
    ] {
        let root = tempfile::tempdir().unwrap();
        let bundle = cached_bundle(root.path(), &evidence(), &rows);
        let expected = encode_pairs(&pairs);
        let actual = fs::read(bundle.join("ranking.bin")).unwrap();
        assert_eq!(actual, expected);
        assert_eq!(actual.len(), rows.len() * 16);
        let manifest = read_json(&bundle.join("bundle.json"));
        let opened = data::Bundle::open(&bundle, MEMORY).unwrap();
        let descriptor = json!({
            "records": rows.len(),
            "blake3": blake3::hash(&expected).to_hex().to_string(),
        });
        assert_eq!(manifest["ranking"], descriptor);
        assert_eq!(opened.snapshot["ranking"], descriptor);
        assert_eq!(
            opened.manifest.identities,
            u64::try_from(rows.len()).unwrap()
        );
        assert!(opened.manifest.ranking.is_some());
        let ordinals: Vec<_> = actual
            .chunks_exact(16)
            .map(|chunk| u64::from_le_bytes(chunk[8..].try_into().unwrap()))
            .collect();
        assert_eq!(
            ordinals,
            pairs.iter().map(|pair| pair.1).collect::<Vec<_>>()
        );
        assert_eq!(
            ordinals.into_iter().collect::<BTreeSet<_>>(),
            (0..u64::try_from(rows.len()).unwrap()).collect::<BTreeSet<_>>()
        );
        data::verify(&bundle, MEMORY).unwrap();
    }
}

fn complete_scope_bundle(root: &Path) -> PathBuf {
    let mut value = evidence();
    let mut rows = Vec::new();
    for index in 0..105 {
        let identity = format!("App_Box<int>__Run<V{index:03}>");
        value.mappings.push(mapping("Methods", &identity, "App"));
        rows.push(row("Methods", &identity, index + 1, true));
    }
    for index in 0..101 {
        let identity = format!("Second_F{index:03}<X>__Run");
        value.mappings.push(mapping("Methods", &identity, "Second"));
        rows.push(row("Methods", &identity, 1, true));
    }
    value.mappings.push(mapping("Types", "App_Box<int>", "App"));
    rows.push(row("Types", "App_Box<int>", 7, true));
    cached_bundle(root, &value, &rows)
}

#[test]
fn captured_scopes_are_complete_separated_and_nonadditive() {
    let root = tempfile::tempdir().unwrap();
    let bundle = complete_scope_bundle(root.path());
    let report = data::Bundle::open(&bundle, MEMORY).unwrap().snapshot;
    let records = catalog(&bundle, "scopes");
    assert_eq!(report["coverage"]["identities"], 207);
    assert_eq!(
        report["accounting"]["streams"],
        json!([
            {"name":"Methods","bytes":5666,"identities":206},
            {"name":"Types","bytes":7,"identities":1},
        ])
    );
    for (dimension, name, status) in [
        ("assembly", "App", "asserted"),
        ("owner", "App_Box", "opaque_producer_family_prefix"),
        ("family", "App_Box<>__Run<>", "parsed_producer_family"),
    ] {
        assert_scope(
            &records,
            &scope(dimension, "Methods", name, 5565, 105, &[status]),
        );
    }
    assert_scope(
        &records,
        &scope("assembly", "Methods", "Second", 101, 101, &["asserted"]),
    );
    assert_scope(
        &records,
        &scope("assembly", "Types", "App", 7, 1, &["asserted"]),
    );
    assert_scope(
        &records,
        &scope(
            "owner",
            "Types",
            "App_Box",
            7,
            1,
            &["opaque_producer_family_prefix"],
        ),
    );
    assert_scope(
        &records,
        &scope(
            "family",
            "Types",
            "App_Box<>",
            7,
            1,
            &["parsed_producer_family"],
        ),
    );
    for index in 0..101 {
        assert_scope(
            &records,
            &scope(
                "family",
                "Methods",
                &format!("Second_F{index:03}<>__Run"),
                1,
                1,
                &["parsed_producer_family"],
            ),
        );
    }
    assert_eq!(records.len(), 209);
    assert_eq!(report["coverage"]["generic_family_count"], 103);
    assert_eq!(report["generic_families"].as_array().unwrap().len(), 100);
    let selected: Vec<_> = report["contributors"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|entry| entry["stream"] == "Methods")
        .collect();
    assert_eq!(selected.len(), 100);
    assert_eq!(
        selected
            .iter()
            .map(|entry| entry["ordinal"].as_u64().unwrap())
            .collect::<Vec<_>>(),
        (5..105).rev().collect::<Vec<u64>>()
    );
    assert_eq!(
        selected
            .iter()
            .map(|entry| entry["bytes"].as_u64().unwrap())
            .sum::<u64>(),
        5550
    );
    assert_eq!(report["coverage"]["displayed_accounted_bytes"], 5557);
    assert_eq!(report["coverage"]["remaining_accounted_bytes"], 116);
    assert_eq!(report["ledger"]["accounted_bytes"], Value::Null);
    assert_eq!(report["accounting"]["total_bytes"], Value::Null);
    assert!(report["caveats"].as_array().unwrap().contains(&json!(
        "Methods, Types and Blobs are additive; resources, metadata, generic families and generator associations are overlapping projections, never extra totals."
    )));
    data::verify(&bundle, MEMORY).unwrap();
}

#[test]
fn conservative_scope_buckets_keep_lossy_raw_identities_separate() {
    // Independent conservative buckets: unaccounted generic families are not
    // accounted assembly/owner bytes; lossy rows retain separate raw identities.
    let small_root = tempfile::tempdir().unwrap();
    let mut small = evidence();
    small.mappings = vec![
        mapping("Methods", "App_Box<int>__Run<long>", "App"),
        mapping("Methods", "App_Box<string>__Run<short>", "App"),
        mapping("Methods", "App_Box<\u{fffd}>__Run<long>", "App"),
        mapping("Methods", "OpaqueAmbiguous", "App"),
        mapping("Methods", "OpaqueAmbiguous", "Second"),
        mapping("Types", "App_Box<int>", "App"),
    ];
    let mut rows = vec![
        row("Methods", "App_Box<int>__Run<long>", 10, true),
        row("Methods", "App_Box<string>__Run<short>", 1000, false),
        row("Methods", "Broken<__Run", 11, true),
        row("Methods", "App_Box<\u{fffd}>__Run<long>", 13, true),
        row("Methods", "App_Box<\u{fffd}>__Run<long>", 17, true),
        row("Methods", "OpaqueAmbiguous", 19, true),
        row("Methods", "NoMatch__Run", 23, true),
        row("Types", "App_Box<int>", 7, true),
    ];
    for (ordinal, raw) in [
        (3, b"App_Box<\xfe>__Run<long>".as_slice()),
        (4, b"App_Box<\xff>__Run<long>".as_slice()),
    ] {
        rows[ordinal].identity_lossy = true;
        rows[ordinal].raw_identity_blake3 = blake3::hash(raw).to_hex().to_string();
    }
    let bundle = cached_bundle(small_root.path(), &small, &rows);
    let report = data::Bundle::open(&bundle, MEMORY).unwrap().snapshot;
    assert_eq!(catalog(&bundle, "scopes"), conservative_scopes());
    assert_eq!(
        report["accounting"]["streams"],
        json!([
            {"name":"Methods","bytes":93,"identities":6},
            {"name":"Types","bytes":7,"identities":1},
        ])
    );
    assert_eq!(report["coverage"]["identities"], 8);
    assert_eq!(report["coverage"]["malformed_generic_identities"], 1);
    assert_eq!(
        report["details"]["2"]["shape_diagnostic"]["code"],
        "attribution.generic.syntax"
    );
    for ordinal in ["3", "4"] {
        let detail = &report["details"][ordinal];
        assert_eq!(detail["sources"]["status"], "unmapped_lossy_identity");
        assert_eq!(detail["sources"]["assemblies"], json!([]));
        assert!(detail.get("shape").is_none());
        assert!(detail.get("argument_sources").is_none());
    }
    assert_eq!(
        report["details"]["3"]["row"]["raw_identity_blake3"],
        blake3::hash(b"App_Box<\xfe>__Run<long>")
            .to_hex()
            .to_string()
    );
    assert_eq!(
        report["details"]["4"]["row"]["raw_identity_blake3"],
        blake3::hash(b"App_Box<\xff>__Run<long>")
            .to_hex()
            .to_string()
    );
    data::verify(&bundle, MEMORY).unwrap();
}

fn conservative_scopes() -> Vec<Value> {
    vec![
        scope("assembly", "Methods", "App", 10, 1, &["asserted"]),
        scope("assembly", "Methods", "_ambiguous", 19, 1, &["ambiguous"]),
        scope(
            "assembly",
            "Methods",
            "_unmapped",
            64,
            4,
            &["unmapped", "unmapped_lossy_identity"],
        ),
        scope("assembly", "Types", "App", 7, 1, &["asserted"]),
        scope(
            "family",
            "Methods",
            "App_Box<>__Run<>",
            1010,
            2,
            &["parsed_producer_family"],
        ),
        scope(
            "family",
            "Types",
            "App_Box<>",
            7,
            1,
            &["parsed_producer_family"],
        ),
        scope(
            "owner",
            "Methods",
            "App_Box",
            40,
            3,
            &["opaque_producer_family_prefix"],
        ),
        scope(
            "owner",
            "Methods",
            "Broken",
            11,
            1,
            &["opaque_producer_family_prefix"],
        ),
        scope(
            "owner",
            "Methods",
            "NoMatch",
            23,
            1,
            &["opaque_producer_family_prefix"],
        ),
        scope(
            "owner",
            "Methods",
            "OpaqueAmbiguous",
            19,
            1,
            &["opaque_producer_family_prefix"],
        ),
        scope(
            "owner",
            "Types",
            "App_Box",
            7,
            1,
            &["opaque_producer_family_prefix"],
        ),
    ]
}

#[test]
fn resource_classification_duplicates_and_unknown_ledger_are_conservative() {
    for (storage, expected) in [
        ("manifest_container", true),
        ("avalonia_container", true),
        ("asset", false),
        ("", false),
        ("manifest", false),
        ("Manifest_container", false),
        ("avalonia_container ", false),
        ("manifest_container_child", false),
    ] {
        assert_eq!(
            Resource {
                storage: storage.into(),
                ..Resource::default()
            }
            .is_container(),
            expected,
            "{storage:?}"
        );
    }
    let inventory = resources();
    let groups = vitnet_attribution::asset_duplicates(&inventory).unwrap();
    assert_eq!(groups.len(), 1);
    assert_eq!(groups[0].sha256, "ab".repeat(32));
    assert_eq!(groups[0].bytes_each, 30);
    assert_eq!(groups[0].instance_count, 2);
    assert_eq!(
        groups[0]
            .instances
            .iter()
            .map(|asset| asset.name.as_str())
            .collect::<Vec<_>>(),
        ["A", "B"]
    );
    assert_eq!(groups[0].caveat, DUPLICATE_CAVEAT);
    for storage in ["manifest_container", "avalonia_container"] {
        let mut with_invalid_container = inventory.clone();
        with_invalid_container.push(Resource {
            assembly: "App".into(),
            container: "App.resources".into(),
            name: "BadContainerHash".into(),
            bytes: 777,
            sha256: Some("not a SHA-256".into()),
            storage: storage.into(),
            ..Resource::default()
        });
        let groups = vitnet_attribution::asset_duplicates(&with_invalid_container).unwrap();
        assert_eq!(groups.len(), 1, "{storage}");
        assert_eq!(groups[0].instance_count, 2, "{storage}");
        assert_eq!(groups[0].bytes_each, 30, "{storage}");
        assert_eq!(groups[0].sha256, "ab".repeat(32), "{storage}");
        assert_eq!(
            groups[0]
                .instances
                .iter()
                .map(|asset| asset.name.as_str())
                .collect::<Vec<_>>(),
            ["A", "B"],
            "{storage}"
        );
    }
    for (invalid_hash, message) in [
        (
            false,
            "identical content hashes declare different asset lengths",
        ),
        (true, "asset SHA-256 must contain 64 hex digits"),
    ] {
        let mut invalid = inventory.clone();
        if invalid_hash {
            invalid[2].sha256 = Some("g".repeat(64));
        } else {
            invalid[1].bytes = 31;
        }
        let error = vitnet_attribution::asset_duplicates(&invalid).unwrap_err();
        assert_eq!(error.diagnostic.code, "attribution.resource.hash");
        assert_eq!(error.diagnostic.message, message);
    }
}

#[test]
fn resource_inventory_dedup_and_unknown_ledger_preserve_separate_totals() {
    let inventory = resources();
    let root = tempfile::tempdir().unwrap();
    let mut value = evidence();
    value.resources = inventory.clone();
    let index = import(root.path(), "index", &value);
    cache(&index, &seed());
    let mut supplemental = evidence();
    supplemental.resources.push(inventory[0].clone());
    let supplement = root.path().join("supplement.json");
    write_json(&supplement, &supplemental);
    let bundle = root.path().join("bundle");
    prepare(&index, &bundle, &[supplement]);
    let report = data::Bundle::open(&bundle, MEMORY).unwrap().snapshot;
    assert_eq!(report["coverage"]["resource_count"], 6);
    assert_eq!(report["coverage"]["duplicate_asset_group_count"], 1);
    assert_eq!(catalog(&bundle, "resources").len(), 6);
    let duplicates = catalog(&bundle, "duplicate_assets");
    let expected_duplicates = json!([{
        "sha256":"ab".repeat(32), "bytes_each":30, "instance_count":2,
        "instances":[inventory[0],inventory[1]], "caveat":DUPLICATE_CAVEAT,
    }]);
    assert_eq!(json!(duplicates), expected_duplicates);
    assert_eq!(report["duplicate_assets"], expected_duplicates);
    assert_eq!(
        report["ledger"],
        json!({
            "accounted_bytes":null, "accounting_basis":ACCOUNTING_BASIS,
            "physical_binaries":[], "physical_total_bytes":null,
            "resource_asset_bytes":120, "resource_container_bytes":1700,
            "metadata_lower_bound_bytes":null, "resource_basis":RESOURCE_BASIS,
        })
    );
    assert_eq!(report["accounting"]["total_bytes"], Value::Null);
    data::verify(&bundle, MEMORY).unwrap();
}

#[test]
fn ledger_absent_accounting_is_distinct_from_reported_zero() {
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
        prepare(&index, &bundle, &[]);
        let report = data::Bundle::open(&bundle, MEMORY).unwrap().snapshot;
        let expected_total = if present { json!(0) } else { Value::Null };
        assert_eq!(report["accounting"]["total_bytes"], expected_total);
        assert_eq!(report["ledger"]["accounted_bytes"], expected_total);
        assert_eq!(report["ledger"]["physical_total_bytes"], Value::Null);
        assert_eq!(report["ledger"]["metadata_lower_bound_bytes"], Value::Null);
        assert_eq!(report["ledger"]["resource_asset_bytes"], 0);
        assert_eq!(report["ledger"]["resource_container_bytes"], 0);
        assert_eq!(report["ledger"]["accounting_basis"], ACCOUNTING_BASIS);
        assert_eq!(report["ledger"]["resource_basis"], RESOURCE_BASIS);
        data::verify(&bundle, MEMORY).unwrap();
    }
}

#[test]
fn ledger_known_inventory_is_overlapping_not_additive() {
    let root = tempfile::tempdir().unwrap();
    let mut image = common::Image::new();
    image.method(b"Owner__First", 11);
    image.method(b"Owner__Last", 29);
    let metadata = root.path().join("metadata.csv");
    // Hex offset 0x46 is 70. The final record has unknown size: no
    // fabricated end-record length is included in this lower bound.
    fs::write(&metadata, b"Handle, Kind, Name, Children\n00000000, ScopeDefinition, \"App\", \"a\"\n0000000a, TypeDefinition, \"Widget\", \"14\"\n00000014, Method, \"Run\", \"\"\n00000046, End, \"\", \"\"\n").unwrap();
    let mut value = evidence();
    value.artifacts = vec![mstat(root.path(), image), artifact("metadata", metadata)];
    value.resources = resources();
    value.binaries = vec![
        Binary {
            path: root.path().join("reported-app.exe"),
            format: "PE".into(),
            architecture: "x64".into(),
            file_bytes: 1000,
            ..Binary::default()
        },
        Binary {
            path: root.path().join("reported-helper.so"),
            format: "ELF".into(),
            architecture: "aarch64".into(),
            file_bytes: 2000,
            ..Binary::default()
        },
    ];
    let index = import(root.path(), "index", &value);
    let bundle = root.path().join("bundle");
    prepare(&index, &bundle, &[]);
    let report = data::Bundle::open(&bundle, MEMORY).unwrap().snapshot;
    assert_eq!(
        report["ledger"],
        json!({
            "accounted_bytes":40, "accounting_basis":ACCOUNTING_BASIS,
            "physical_binaries":[
                {"path":root.path().join("reported-app.exe"),"format":"PE","architecture":"x64","file_bytes":1000},
                {"path":root.path().join("reported-helper.so"),"format":"ELF","architecture":"aarch64","file_bytes":2000},
            ],
            "physical_total_bytes":3000, "resource_asset_bytes":120,
            "resource_container_bytes":1700, "metadata_lower_bound_bytes":70,
            "resource_basis":RESOURCE_BASIS,
        })
    );
    assert_eq!(report["accounting"]["total_bytes"], 40);
    assert_eq!(report["accounting"]["metadata_lower_bound_bytes"], 70);
    assert_eq!(report["coverage"]["displayed_accounted_bytes"], 40);
    assert_eq!(report["coverage"]["remaining_accounted_bytes"], 0);
    assert_eq!(
        catalog(&bundle, "binaries"),
        value
            .binaries
            .iter()
            .map(|binary| serde_json::to_value(binary).unwrap())
            .collect::<Vec<_>>()
    );
    let summary = catalog(&bundle, "metadata_summary");
    assert_eq!(summary.len(), 1);
    assert_eq!(summary[0]["total_lower_bound"], 70);
    assert_eq!(summary[0]["observed_lower_bound"], 70);
    assert_eq!(summary[0]["total_is_lower_bound"], true);
    assert_eq!(summary[0]["final_record_size_known"], false);
    assert_eq!(report["duplicate_assets"][0]["caveat"], DUPLICATE_CAVEAT);
    assert!(report["caveats"].as_array().unwrap().contains(&json!(
        "Methods, Types and Blobs are additive; resources, metadata, generic families and generator associations are overlapping projections, never extra totals."
    )));
    data::verify(&bundle, MEMORY).unwrap();
}

fn source(root: &Path, assembly: &str, member: Option<&str>, file: &str) -> Source {
    Source {
        assembly: assembly.into(),
        type_name: "Box".into(),
        member: member.map(str::to_owned),
        path: root.join(file),
        line: 3,
        end_line: 8,
        kind: "method".into(),
        ..Source::default()
    }
}

fn package_mapping(assembly: &str, package: &str, basis: &str) -> Mapping {
    Mapping {
        basis: basis.into(),
        ..mapping("package", package, assembly)
    }
}

fn assert_match(
    matcher: &Matcher<'_>,
    stream: &str,
    identity: &str,
    status: &str,
    assemblies: &[&str],
    paths: &[PathBuf],
) {
    let located = matcher.locate(stream, identity);
    assert_eq!(located.status, status, "{identity}");
    assert_eq!(located.assemblies.as_slice(), assemblies, "{identity}");
    assert_eq!(
        located
            .sources
            .iter()
            .map(|source| source.path.clone())
            .collect::<Vec<_>>()
            .as_slice(),
        paths,
        "{identity}"
    );
}

fn link_base(root: &Path) -> Evidence {
    let mut base = evidence();
    base.assemblies = vec![
        Assembly {
            name: "App".into(),
            package: Some("RecordedPkg/1".into()),
            ..Assembly::default()
        },
        Assembly {
            name: "Second".into(),
            ..Assembly::default()
        },
    ];
    base.sources = vec![
        source(root, "App", Some("Member"), "base-member.cs"),
        source(root, "Second", Some("Run"), "second.cs"),
        source(root, "ArgApp", None, "argument.cs"),
    ];
    let app_path = base.sources[0].path.clone();
    let second_path = base.sources[1].path.clone();
    let argument_path = base.sources[2].path.clone();
    let app_looking = "App_Box<int>__Run<ArgToken>";
    let lossy_name = "OpaqueLossy<\u{fffd}>__Run";
    let mut opaque = mapping("Methods", "OpaqueMember", "App");
    opaque.source_paths.push(app_path.clone());
    let mut override_mapping = mapping("Methods", app_looking, "Second");
    override_mapping.source_paths.push(second_path.clone());
    let mut argument = mapping("Types", "ArgToken", "ArgApp");
    argument.source_paths.push(argument_path.clone());
    base.mappings = vec![
        opaque,
        override_mapping,
        argument,
        mapping("Methods", "AmbiguousMember", "App"),
        mapping("Methods", "AmbiguousMember", "Second"),
        mapping("Methods", lossy_name, "App"),
        package_mapping("App", "Pkg/1", "assets_resolved_runtime:net10/win-x64"),
        package_mapping("App", "Pkg/1", "assets_resolved_runtime:net10/linux-x64"),
        package_mapping(
            "Other",
            "OtherPkg/3",
            "assets_resolved_runtime:net10/win-x64",
        ),
        mapping("Methods", "NotAPackage/9", "App"),
        mapping("Package", "WrongCase/9", "App"),
    ];
    base
}

#[test]
fn real_matcher_uses_explicit_and_producer_evidence_not_assembly_spelling() {
    let root = tempfile::tempdir().unwrap();
    let base = link_base(root.path());
    let app_path = root.path().join("base-member.cs");
    let second_path = root.path().join("second.cs");
    let argument_path = root.path().join("argument.cs");
    let app_looking = "App_Box<int>__Run<ArgToken>";
    let producer = "App_Box<string>__Member<ArgToken>";
    let lossy_name = "OpaqueLossy<\u{fffd}>__Run";
    let matcher = Matcher::new(&base);
    assert_match(
        &matcher,
        "Methods",
        "OpaqueMember",
        "asserted",
        &["App"],
        std::slice::from_ref(&app_path),
    );
    assert_match(
        &matcher,
        "Methods",
        app_looking,
        "asserted",
        &["Second"],
        std::slice::from_ref(&second_path),
    );
    assert_match(
        &matcher,
        "Methods",
        "AmbiguousMember",
        "ambiguous",
        &["App", "Second"],
        &[],
    );
    assert_match(
        &matcher,
        "Methods",
        "NeverMatched__Run",
        "unmapped",
        &[],
        &[],
    );
    assert_match(
        &matcher,
        "Methods",
        producer,
        "producer_prefix_candidate",
        &["App"],
        std::slice::from_ref(&app_path),
    );
    assert_match(
        &matcher,
        "Types",
        "ArgToken",
        "asserted",
        &["ArgApp"],
        std::slice::from_ref(&argument_path),
    );
    // A plain string matcher can match this spelling; the explorer must not
    // attribute its lossy cache row, even though an explicit mapping exists.
    assert_match(&matcher, "Methods", lossy_name, "asserted", &["App"], &[]);
}

fn link_supplement(root: &Path) -> Evidence {
    let mut supplemental = evidence();
    supplemental.assemblies.push(Assembly {
        name: "Supplemental".into(),
        package: Some("SupplementalPkg/2".into()),
        ..Assembly::default()
    });
    // Same producer source key and an overlapping explicit source path would
    // contaminate both member inference and Types candidates if merged.
    supplemental.sources = vec![
        source(root, "App", Some("Member"), "supp-member.cs"),
        source(root, "Supplemental", None, "argument.cs"),
    ];
    let mut conflicting_member = mapping("Methods", "OpaqueMember", "Supplemental");
    conflicting_member
        .source_paths
        .push(supplemental.sources[0].path.clone());
    let mut conflicting_argument = mapping("Types", "ArgToken", "Supplemental");
    conflicting_argument
        .source_paths
        .push(supplemental.sources[1].path.clone());
    supplemental.mappings = vec![
        conflicting_member,
        conflicting_argument,
        mapping("Methods", "App_Box<int>__Run<ArgToken>", "Supplemental"),
        package_mapping("App", "Pkg/1", "assets_resolved_runtime:net10/win-x64"),
        package_mapping("App", "Pkg/1", "assets_resolved_compile:net10/win-x64"),
        package_mapping(
            "Supplemental",
            "SuppPkg/2",
            "assets_resolved_runtime:net10/win-x64",
        ),
        mapping("Package", "NotALink/9", "Supplemental"),
    ];
    supplemental
}

fn link_rows() -> Vec<CoalescedIdentity> {
    let app_looking = "App_Box<int>__Run<ArgToken>";
    let producer = "App_Box<string>__Member<ArgToken>";
    let lossy_name = "OpaqueLossy<\u{fffd}>__Run";
    let mut rows = vec![
        row("Methods", "OpaqueMember", 10, true),
        row("Methods", app_looking, 20, true),
        row("Methods", "AmbiguousMember", 30, true),
        row("Methods", "NeverMatched__Run", 40, true),
        row("Methods", lossy_name, 50, true),
        row("Methods", producer, 60, true),
        row("Types", "ArgToken", 7, true),
    ];
    rows[4].identity_lossy = true;
    rows[4].raw_identity_blake3 = blake3::hash(b"OpaqueLossy<\xff>__Run").to_hex().to_string();
    rows
}

#[test]
fn assembly_links_merge_targets_without_changing_real_matcher() {
    let root = tempfile::tempdir().unwrap();
    let base = link_base(root.path());
    let supplemental = link_supplement(root.path());
    let app_path = root.path().join("base-member.cs");
    let second_path = root.path().join("second.cs");
    let argument_path = root.path().join("argument.cs");
    let supplement = root.path().join("supplement.json");
    write_json(&supplement, &supplemental);
    let rows = link_rows();
    let index = import(root.path(), "index", &base);
    cache(&index, &rows);
    let plain = root.path().join("base-only");
    let extended = root.path().join("supplemented");
    prepare(&index, &plain, &[]);
    prepare(&index, &extended, &[supplement]);
    assert_eq!(catalog(&extended, "assembly_links"), fixed_link_records());
    let manifest = read_json(&extended.join("bundle.json"));
    assert_eq!(manifest["datasets"]["assembly_links"]["records"], 7);
    assert_eq!(catalog(&plain, "assembly_links").len(), 4);
    assert_eq!(catalog(&plain, "scopes"), catalog(&extended, "scopes"));
    for bundle in [&plain, &extended] {
        assert_base_associations(bundle, &app_path, &second_path, &argument_path);
        data::verify(bundle, MEMORY).unwrap();
    }
}

fn fixed_link_records() -> Vec<Value> {
    let expected_tuples = BTreeSet::from([
        ("App", "RecordedPkg/1", "", "recorded_assembly_package"),
        (
            "App",
            "Pkg/1",
            "net10/win-x64",
            "assets_resolved_runtime:net10/win-x64",
        ),
        (
            "App",
            "Pkg/1",
            "net10/linux-x64",
            "assets_resolved_runtime:net10/linux-x64",
        ),
        (
            "App",
            "Pkg/1",
            "net10/win-x64",
            "assets_resolved_compile:net10/win-x64",
        ),
        (
            "Supplemental",
            "SupplementalPkg/2",
            "",
            "recorded_assembly_package",
        ),
        (
            "Supplemental",
            "SuppPkg/2",
            "net10/win-x64",
            "assets_resolved_runtime:net10/win-x64",
        ),
        (
            "Other",
            "OtherPkg/3",
            "net10/win-x64",
            "assets_resolved_runtime:net10/win-x64",
        ),
    ]);
    expected_tuples
        .into_iter()
        .map(|(assembly, package, target, basis)| {
            json!({
                "assembly":assembly, "package":package, "target":target,
                "basis":basis, "caveat":LINK_CAVEAT,
            })
        })
        .collect()
}

fn assert_base_associations(
    bundle: &Path,
    app_path: &Path,
    second_path: &Path,
    argument_path: &Path,
) {
    let report = data::Bundle::open(bundle, MEMORY).unwrap().snapshot;
    for (ordinal, status, assemblies, paths) in [
        ("0", "asserted", vec!["App"], vec![app_path]),
        ("1", "asserted", vec!["Second"], vec![second_path]),
        ("2", "ambiguous", vec!["App", "Second"], vec![]),
        ("3", "unmapped", vec![], vec![]),
        ("4", "unmapped_lossy_identity", vec![], vec![]),
        (
            "5",
            "producer_prefix_candidate",
            vec!["App"],
            vec![app_path],
        ),
        ("6", "asserted", vec!["ArgApp"], vec![argument_path]),
    ] {
        let association = &report["details"][ordinal]["sources"];
        assert_eq!(association["status"], status, "{ordinal}");
        assert_eq!(association["assemblies"], json!(assemblies), "{ordinal}");
        assert_eq!(
            association["sources"]
                .as_array()
                .unwrap()
                .iter()
                .map(|source| source["path"].clone())
                .collect::<Vec<_>>(),
            paths.iter().map(|path| json!(path)).collect::<Vec<_>>(),
            "{ordinal}"
        );
    }
    for ordinal in ["1", "5"] {
        let candidates = report["details"][ordinal]["argument_sources"]
            .as_array()
            .unwrap()
            .iter()
            .find(|candidate| candidate["argument"] == "ArgToken")
            .unwrap();
        assert_eq!(candidates["candidates"]["status"], "asserted");
        assert_eq!(candidates["candidates"]["assemblies"], json!(["ArgApp"]));
        assert_eq!(candidates["total_sources"], 1);
        assert_eq!(
            candidates["candidates"]["sources"][0]["path"],
            json!(argument_path)
        );
    }
    assert!(report["details"]["4"].get("shape").is_none());
}

#[test]
fn ranking_integrity_rejects_fingerprint_and_semantic_corruption() {
    for mutation in [
        "same_length_hash",
        "missing",
        "truncated",
        "count",
        "record_length",
        "oversized_descriptor",
        "descriptor_disagreement",
        "out_of_order",
        "reversed_tie",
        "duplicate_key",
        "ordinal_n",
        "wrong_identity_bytes",
        "duplicate_ordinal_distinct_bytes",
    ] {
        let root = tempfile::tempdir().unwrap();
        let bundle = cached_bundle(root.path(), &evidence(), &seed());
        let original = encode_pairs(&RANKED_PAIRS);
        // Each mutation starts with an independently validated, fresh fixture.
        assert_eq!(fs::read(bundle.join("ranking.bin")).unwrap(), original);
        data::verify(&bundle, MEMORY).unwrap();
        let mut pairs = RANKED_PAIRS.to_vec();
        match mutation {
            "same_length_hash" => {
                let mut bytes = original.clone();
                bytes[0] ^= 1;
                fs::write(bundle.join("ranking.bin"), bytes).unwrap();
            }
            "missing" => fs::remove_file(bundle.join("ranking.bin")).unwrap(),
            "truncated" => {
                fs::write(bundle.join("ranking.bin"), &original[..original.len() - 1]).unwrap();
            }
            "count" => rewrite_ranking(&bundle, &original, 6),
            "record_length" => {
                rewrite_ranking(&bundle, &original[..original.len() - 16], 7);
            }
            // This exercises rejection of an oversized descriptor, not the
            // checked_mul branch: public offsets validation prevents a bounded
            // fixture with a correspondingly enormous identity count.
            "oversized_descriptor" => rewrite_ranking(&bundle, &original, u64::MAX / 16 + 1),
            "descriptor_disagreement" => {
                let mut manifest = read_json(&bundle.join("bundle.json"));
                let mut snapshot = read_json(&bundle.join("snapshot.json"));
                snapshot["ranking"]["blake3"] = json!("0".repeat(64));
                refingerprint(&bundle, &mut manifest, &mut snapshot);
            }
            "out_of_order" => {
                pairs.swap(0, 1);
                rewrite_ranking(&bundle, &encode_pairs(&pairs), 7);
            }
            "reversed_tie" => {
                pairs.swap(2, 3);
                rewrite_ranking(&bundle, &encode_pairs(&pairs), 7);
            }
            "duplicate_key" => {
                pairs[3] = pairs[2];
                rewrite_ranking(&bundle, &encode_pairs(&pairs), 7);
            }
            "ordinal_n" => {
                pairs[0].1 = 7;
                rewrite_ranking(&bundle, &encode_pairs(&pairs), 7);
            }
            "wrong_identity_bytes" => {
                // Preserve the ordinal permutation and monotone byte keys:
                // only the association between a size and identity is wrong.
                pairs[0].1 = 3;
                pairs[1].1 = 5;
                rewrite_ranking(&bundle, &encode_pairs(&pairs), 7);
            }
            "duplicate_ordinal_distinct_bytes" => {
                pairs[5].1 = 1; // [5,3,1,2,6,1,4], monotone keys
                rewrite_ranking(&bundle, &encode_pairs(&pairs), 7);
            }
            _ => unreachable!("fixture mutation not enumerated"),
        }
        let (code, message, cross_identity) = match mutation {
            "missing" => ("io.explorer", None, false),
            "descriptor_disagreement" => (
                "explorer.ranking.integrity",
                Some("ranking differs from snapshot generation"),
                false,
            ),
            "out_of_order" | "reversed_tie" | "duplicate_key" | "ordinal_n" => (
                "explorer.ranking.integrity",
                Some("ranking is not strictly byte/ordinal ordered"),
                false,
            ),
            "wrong_identity_bytes" | "duplicate_ordinal_distinct_bytes" => (
                "explorer.ranking.integrity",
                Some("ranked bytes differ from identity"),
                true,
            ),
            _ => (
                "explorer.ranking.integrity",
                Some("ranking fingerprint or count differs"),
                false,
            ),
        };
        if cross_identity {
            // open's structural contract is distinct from full verification.
            data::Bundle::open(&bundle, MEMORY).unwrap();
            expect_error(data::verify(&bundle, MEMORY), code, message);
        } else {
            expect_error(data::Bundle::open(&bundle, MEMORY), code, message);
            expect_error(data::verify(&bundle, MEMORY), code, message);
        }
    }
}

#[test]
fn legacy_v1_bundle_remains_usable_without_ranking() {
    for removed_datasets in [
        Vec::<&str>::new(),
        vec!["scopes"],
        vec!["assembly_links"],
        vec!["scopes", "assembly_links"],
    ] {
        let root = tempfile::tempdir().unwrap();
        let mut value = evidence();
        value.packages.push(Package {
            target: "net10/win-x64".into(),
            id: "LegacyPkg".into(),
            version: "1".into(),
            direct: true,
            dependencies: vec![],
        });
        let bundle = cached_bundle(root.path(), &value, &seed());
        let mut manifest = read_json(&bundle.join("bundle.json"));
        let mut snapshot = read_json(&bundle.join("snapshot.json"));
        manifest.as_object_mut().unwrap().remove("ranking");
        snapshot.as_object_mut().unwrap().remove("ranking");
        fs::remove_file(bundle.join("ranking.bin")).unwrap();
        for dataset in &removed_datasets {
            manifest["datasets"]
                .as_object_mut()
                .unwrap()
                .remove(*dataset);
            snapshot["datasets"]
                .as_object_mut()
                .unwrap()
                .remove(*dataset);
            fs::remove_file(bundle.join(format!("catalog_{dataset}.ndjson"))).unwrap();
            fs::remove_file(bundle.join(format!("catalog_{dataset}.offsets"))).unwrap();
        }
        refingerprint(&bundle, &mut manifest, &mut snapshot);
        let legacy = data::Bundle::open(&bundle, MEMORY).unwrap();
        assert_eq!(legacy.manifest.schema, "vitnet.explorer-bundle.v1");
        assert!(legacy.manifest.ranking.is_none());
        assert!(legacy.snapshot.get("ranking").is_none());
        assert_eq!(legacy.snapshot["coverage"]["identities"], 7);
        assert_eq!(
            legacy.snapshot["contributors"]
                .as_array()
                .unwrap()
                .iter()
                .map(|entry| entry["ordinal"].as_u64().unwrap())
                .collect::<Vec<_>>(),
            [3, 1, 2, 6, 0, 4]
        );
        assert_eq!(
            catalog(&bundle, "packages"),
            vec![json!({
                "target":"net10/win-x64","id":"LegacyPkg","version":"1",
                "direct":true,"dependencies":[],
            })]
        );
        assert_eq!(legacy.snapshot["datasets"]["packages"]["records"], 1);
        for dataset in &removed_datasets {
            assert!(!legacy.manifest.datasets.contains_key(*dataset));
            assert!(legacy.snapshot["datasets"].get(*dataset).is_none());
        }
        data::verify(&bundle, MEMORY).unwrap();
    }
    // Snapshot-present/manifest-missing is invalid, unlike genuine legacy
    // absence. Re-fingerprint so this reaches the ranking consistency check.
    let root = tempfile::tempdir().unwrap();
    let bundle = cached_bundle(root.path(), &evidence(), &seed());
    let mut manifest = read_json(&bundle.join("bundle.json"));
    let mut snapshot = read_json(&bundle.join("snapshot.json"));
    manifest.as_object_mut().unwrap().remove("ranking");
    refingerprint(&bundle, &mut manifest, &mut snapshot);
    expect_error(
        data::Bundle::open(&bundle, MEMORY),
        "explorer.ranking.integrity",
        Some("ranking manifest is missing"),
    );
}

#[test]
fn prepare_precancelled_investigation_leaves_no_output_or_residue() {
    let root = tempfile::tempdir().unwrap();
    let index = import(root.path(), "index", &evidence());
    cache(&index, &seed());
    let before = directory_names(root.path());
    let cancelled = IndexControl::default();
    cancelled.cancel();
    let output = root.path().join("cancelled-bundle");
    let result = data::prepare(
        &index,
        &output,
        &[],
        None,
        &[],
        "scan_index",
        MEMORY,
        &cancelled,
    );
    let Err(error) = result else {
        panic!("precancelled preparation succeeded");
    };
    assert!(matches!(&error, AppError::Resource(_)), "{error}");
    assert_eq!(diagnostic(&error).0, "resource.cancelled", "{error}");
    assert!(!output.exists());
    assert_eq!(directory_names(root.path()), before);
    let valid = root.path().join("uncancelled-bundle");
    let manifest = prepare(&index, &valid, &[]);
    assert_eq!(manifest.identities, 7);
    assert_eq!(
        fs::read(valid.join("ranking.bin")).unwrap(),
        encode_pairs(&RANKED_PAIRS)
    );
    data::verify(&valid, MEMORY).unwrap();
    let mut expected = before;
    expected.insert("uncancelled-bundle".into());
    assert_eq!(directory_names(root.path()), expected);
}

fn binary(root: &Path, name: &str, bytes: u64) -> Binary {
    Binary {
        path: root.join(name),
        format: "PE".into(),
        architecture: "x64".into(),
        file_bytes: bytes,
        sections: vec![BinarySection {
            name: ".text".into(),
            file_bytes: 70,
            virtual_bytes: 80,
        }],
    }
}

#[test]
fn shared_binary_inventory_deduplicates_by_path_without_changing_matcher() {
    let root = tempfile::tempdir().unwrap();
    let mut base = link_base(root.path());
    let shared = binary(root.path(), "app.exe", 100);
    let helper = binary(root.path(), "helper.exe", 200);
    base.binaries = vec![shared.clone(), shared.clone()];
    let index = import(root.path(), "index", &base);
    cache(&index, &link_rows());
    let original_index = fs::read(index.join("index.json")).unwrap();
    let mut extra = link_supplement(root.path());
    extra.binaries = vec![shared.clone(), helper.clone(), shared.clone()];
    let supplement = root.path().join("supplement.json");
    write_json(&supplement, &extra);
    let plain = root.path().join("plain");
    let extended = root.path().join("extended");
    prepare(&index, &plain, &[]);
    prepare(&index, &extended, &[supplement.clone(), supplement]);
    assert_eq!(catalog(&plain, "binaries"), vec![json!(shared)]);
    assert_eq!(
        catalog(&extended, "binaries"),
        vec![json!(shared), json!(helper)]
    );
    let report = data::Bundle::open(&extended, MEMORY).unwrap().snapshot;
    assert_eq!(report["ledger"]["physical_total_bytes"], 300);
    assert_eq!(
        report["ledger"]["physical_binaries"],
        json!([
            {"path":shared.path,"format":"PE","architecture":"x64","file_bytes":100},
            {"path":helper.path,"format":"PE","architecture":"x64","file_bytes":200},
        ])
    );
    for bundle in [&plain, &extended] {
        let snapshot = data::Bundle::open(bundle, MEMORY).unwrap().snapshot;
        assert_eq!(snapshot["details"]["0"]["sources"]["status"], "asserted");
        assert_eq!(
            snapshot["details"]["0"]["sources"]["assemblies"],
            json!(["App"])
        );
        assert_eq!(
            snapshot["details"]["0"]["sources"]["sources"][0]["path"],
            json!(root.path().join("base-member.cs"))
        );
        let argument = snapshot["details"]["1"]["argument_sources"]
            .as_array()
            .unwrap()
            .iter()
            .find(|candidate| candidate["argument"] == "ArgToken")
            .unwrap();
        assert_eq!(argument["candidates"]["status"], "asserted");
        assert_eq!(argument["candidates"]["assemblies"], json!(["ArgApp"]));
        assert_eq!(argument["total_sources"], 1);
        assert_eq!(
            argument["candidates"]["sources"][0]["path"],
            json!(root.path().join("argument.cs"))
        );
        data::verify(bundle, MEMORY).unwrap();
    }
    assert_eq!(fs::read(index.join("index.json")).unwrap(), original_index);
}

#[test]
fn shared_binary_conflicting_fields_are_explicit_and_leave_no_bundle() {
    for field in ["file_bytes", "format", "architecture", "sections"] {
        let root = tempfile::tempdir().unwrap();
        let mut base = evidence();
        let shared = binary(root.path(), "app.exe", 100);
        base.binaries.push(shared.clone());
        let index = import(root.path(), "index", &base);
        let mut extra = evidence();
        let mut conflicting = shared;
        match field {
            "file_bytes" => conflicting.file_bytes = 101,
            "format" => conflicting.format = "ELF".into(),
            "architecture" => conflicting.architecture = "aarch64".into(),
            "sections" => conflicting.sections[0].virtual_bytes = 81,
            _ => unreachable!(),
        }
        extra.binaries.push(conflicting);
        let supplement = root.path().join("supplement.json");
        write_json(&supplement, &extra);
        let before = directory_names(root.path());
        let output = root.path().join("conflicting");
        expect_error(
            data::prepare(
                &index,
                &output,
                &[supplement],
                None,
                &[],
                "scan_index",
                MEMORY,
                &IndexControl::default(),
            ),
            "explorer.inventory.conflict",
            Some("conflicting physical binary evidence for one path"),
        );
        assert!(!output.exists(), "{field}");
        assert_eq!(directory_names(root.path()), before, "{field}");
    }
}

fn reservation_evidence(tail_length: usize) -> Evidence {
    let mut value = evidence();
    // Each of 480 keys: App(3) + identity(4096) + target(0) + fixture(7)
    // + fixed per-key overhead(256) = 4362 bytes, independently specified.
    for n in 0..480 {
        value.mappings.push(Mapping {
            stream: "package".into(),
            assembly: "App".into(),
            identity: format!("p{n:03}{}", "x".repeat(4092)),
            basis: "fixture".into(),
            source_paths: vec![],
        });
    }
    value.mappings.push(Mapping {
        stream: "package".into(),
        assembly: "App".into(),
        identity: "z".repeat(tail_length),
        basis: "fixture".into(),
        source_paths: vec![],
    });
    value
}

#[test]
fn relation_key_reservation_before_at_after_boundary_counts_only_unique_keys() {
    const SMALL_MEMORY: u64 = 32 << 20;
    // 32 MiB / 16 = 2097152; 480 * 4362 + 266 + 3126 = 2097152.
    for (tail_length, supplemental_tail) in [
        (3125, false),
        (3126, false),
        (3127, false),
        (3125, true),
        (3126, true),
        (3127, true),
    ] {
        let root = tempfile::tempdir().unwrap();
        let value = reservation_evidence(tail_length);
        let mut base = value.clone();
        if supplemental_tail {
            // Charge the final distinct key across inventory boundaries, while
            // the other 480 keys in the supplement remain exact duplicates.
            base.mappings.pop().unwrap();
        }
        let index = import(root.path(), "index", &base);
        let supplement = root.path().join("duplicate-keys.json");
        write_json(&supplement, &value);
        let before = directory_names(root.path());
        let output = root.path().join("reserved");
        let result = data::prepare(
            &index,
            &output,
            &[supplement],
            None,
            &[],
            "scan_index",
            SMALL_MEMORY,
            &IndexControl::default(),
        );
        if tail_length == 3127 {
            expect_error(
                result,
                "resource.explorer.relations",
                Some(
                    "package-origin keys exceed their memory reservation; increase --memory-limit",
                ),
            );
            assert!(!output.exists());
            assert_eq!(directory_names(root.path()), before);
        } else {
            let manifest = result.unwrap();
            assert_eq!(manifest.datasets["assembly_links"].records, 481);
            let links = catalog(&output, "assembly_links");
            assert_eq!(links.len(), 481);
            assert_eq!(
                links[0],
                json!({"assembly":"App","package":format!("p000{}", "x".repeat(4092)),
                "target":"","basis":"fixture","caveat":LINK_CAVEAT})
            );
            assert_eq!(
                links[480],
                json!({"assembly":"App","package":"z".repeat(tail_length),
                "target":"","basis":"fixture","caveat":LINK_CAVEAT})
            );
            data::verify(&output, SMALL_MEMORY).unwrap();
        }
    }
}

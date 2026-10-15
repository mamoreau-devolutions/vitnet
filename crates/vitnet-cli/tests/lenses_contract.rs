//! Captured lens contracts through the public CLI; no network or source execution.
use clap::Parser;
use serde_json::{Value, json};
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use vitnet_attribution::model::{
    Artifact, EVIDENCE_SCHEMA, Evidence, GeneratorOutput, GeneratorRun, Mapping, Source,
    SourceAnnotation, XamlDocument,
};
use vitnet_cli::explorer::{ExploreCommand, data};
use vitnet_cli::{AppError, Cli, Command, execute, execute_with_index_control};
use vitnet_dgml::{
    GraphSession, IncomingOptions, IndexControl, IndexOptions, SearchMode, SearchOptions,
    WhyOptions,
};
use vitnet_mstat::CoalescedIdentity;

const MEMORY: u64 = 128 << 20;
const LEDGER: [&str; 8] = [
    "additive_bytes",
    "overlapping_bytes",
    "methods_bytes",
    "types_bytes",
    "blobs_bytes",
    "metadata_lower_bound_bytes",
    "identities",
    "canonical_shared_identities",
];
const VIEWS: [(&str, &str); 9] = [
    ("feature-owners", "lens_feature_owners"),
    ("xaml", "lens_xaml"),
    ("serializers", "lens_serializers"),
    ("repetitions", "lens_repetitions"),
    ("arguments", "lens_arguments"),
    ("costs", "lens_costs"),
    ("reflection", "lens_reflection"),
    ("strings", "lens_metadata_strings"),
    ("coverage", "lens_coverage"),
];

fn scratch_root() -> tempfile::TempDir {
    tempfile::Builder::new()
        .prefix("cli-lenses-")
        .tempdir()
        .unwrap()
}
fn evidence() -> Evidence {
    Evidence {
        schema: EVIDENCE_SCHEMA.into(),
        ..Evidence::default()
    }
}
fn source(owner: &str, path: &str) -> Source {
    Source {
        assembly: "App".into(),
        type_name: owner.into(),
        path: path.into(),
        line: 1,
        end_line: 4,
        kind: "class".into(),
        ..Source::default()
    }
}
fn row(stream: &str, identity: &str, bytes: u64, accounted: bool) -> CoalescedIdentity {
    CoalescedIdentity {
        stream: stream.into(),
        identity: identity.into(),
        bytes,
        accounted,
        records: 99,
        identity_lossy: false,
        raw_identity_blake3: blake3::hash(identity.as_bytes()).to_hex().to_string(),
    }
}
fn write_json(path: &Path, value: &impl serde::Serialize) {
    fs::write(path, serde_json::to_vec(value).unwrap()).unwrap();
}
fn read_json(path: &Path) -> Value {
    serde_json::from_slice(&fs::read(path).unwrap()).unwrap()
}
fn seed(index: &Path, rows: &[CoalescedIdentity]) {
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
fn import(root: &Path, e: &Evidence, rows: &[CoalescedIdentity]) -> PathBuf {
    write_json(&root.join("evidence.json"), e);
    let index = root.join("index");
    vitnet_attribution::import(&root.join("evidence.json"), &index, MEMORY, false).unwrap();
    seed(&index, rows);
    index
}
fn prepare(index: &Path, output: &Path, memory: u64) -> Result<data::BundleManifest, AppError> {
    data::prepare(
        index,
        output,
        &[],
        None,
        &[],
        "scan_index",
        memory,
        &IndexControl::default(),
    )
}
fn bundle(root: &Path, e: &Evidence, rows: &[CoalescedIdentity]) -> PathBuf {
    let index = import(root, e, rows);
    let output = root.join("bundle");
    prepare(&index, &output, MEMORY).unwrap();
    output
}
fn cli(format: &str, command: &str, path: &Path, extra: &[&str]) -> Cli {
    let mut args = vec![
        "vitnet",
        "--format",
        format,
        "--memory-limit",
        "128MiB",
        "--progress",
        "never",
        "--color",
        "never",
        "explore",
        command,
        path.to_str().unwrap(),
    ];
    args.extend_from_slice(extra);
    Cli::try_parse_from(args).unwrap()
}
fn query(command: &str, path: &Path, extra: &[&str]) -> Value {
    let v: Value =
        serde_json::from_str(&execute(&cli("json", command, path, extra)).unwrap()).unwrap();
    assert_eq!(v["schema"], "vitnet.explorer-cli.v1");
    assert_eq!(v["operation"], command);
    assert_eq!(
        v["generation"],
        read_json(&path.join("bundle.json"))["generation"]
    );
    v
}
fn code(error: &AppError) -> &str {
    match error {
        AppError::Unsupported(e) | AppError::Resource(e) | AppError::IoDiagnostic(e) => &e.code,
        AppError::Dgml(e) => &e.diagnostic.code,
        other => panic!("unexpected diagnostic: {other}"),
    }
}
fn expect_error(command: &str, path: &Path, extra: &[&str], expected: &str) {
    let e = execute(&cli("json", command, path, extra)).unwrap_err();
    assert_eq!(code(&e), expected, "{e}");
}
fn entries(v: &Value) -> &[Value] {
    v["data"]["entries"].as_array().unwrap()
}
fn ordinals(v: &Value) -> Vec<String> {
    entries(v)
        .iter()
        .map(|e| e["ordinal"].as_str().unwrap().into())
        .collect()
}
fn catalog(path: &Path, name: &str) -> Vec<Value> {
    let bytes = fs::read(path.join(format!("catalog_{name}.ndjson"))).unwrap();
    bytes
        .split(|b| *b == b'\n')
        .filter(|line| !line.is_empty())
        .map(|line| serde_json::from_slice(line).unwrap())
        .collect()
}
fn find<'a>(rows: &'a [Value], key: &str, expected: &str) -> &'a Value {
    rows.iter().find(|r| r[key] == expected).unwrap()
}
fn metadata_csv(path: &Path, text: &str) {
    fs::write(
        path,
        format!(
            "Handle, Kind, Name, Children\n\
         00000000, ScopeDefinition, \"App\", \"a\"\n\
         0000000a, NamespaceDefinition, \"Demo\", \"14\"\n\
         00000014, TypeDefinition, \"Demo.Page\", \"1e\"\n\
         0000001e, ConstantStringValue, \"{text}\", \"\"\n\
         00000028, End, \"\", \"\"\n"
        ),
    )
    .unwrap();
}
fn rich(root: &Path) -> (Evidence, Vec<CoalescedIdentity>) {
    let mut e = evidence();
    let mut page = source("Demo.Page", "Page.cs");
    page.annotations = Some(vec![SourceAnnotation {
        target: "return".into(),
        attributes: vec!["DynamicDependency(typeof(Demo.Target))".into()],
    }]);
    let mut a = source("Demo.ContextA", "ContextA.cs");
    a.attributes = vec![
        "JsonSerializable(typeof(Demo.Item))".into(),
        "JsonSourceGenerationOptions(WriteIndented = true)".into(),
    ];
    let mut b = source("Demo.ContextB", "ContextB.cs");
    b.attributes = vec!["JsonSerializable(typeof(Demo.Item))".into()];
    b.annotations = Some(vec![]);
    e.sources = vec![
        page,
        a,
        b,
        source("Demo.Child.Widget", "Child.cs"),
        source("Demonstration.Widget", "Other.cs"),
    ];
    e.xaml_documents.push(XamlDocument {
        path: "Page.axaml".into(),
        assembly: "App".into(),
        declared_class: Some("global::Demo.Page".into()),
        root_element: "UserControl".into(),
        sha256: "a".repeat(64),
        includes: vec!["Styles.axaml".into()],
        keys: vec!["Accent".into()],
    });
    e.generator_runs.push(GeneratorRun {
        name: "JsonGenerator".into(),
        status: "captured".into(),
        basis: "synthetic log".into(),
        execution_status: "observed".into(),
        outputs: vec![GeneratorOutput {
            path: "ContextA.g.cs".into(),
            build_match: "unknown".into(),
            ..GeneratorOutput::default()
        }],
        ..GeneratorRun::default()
    });
    e.provenance.insert(
        "source.project_assembly_hint:App.csproj".into(),
        "App".into(),
    );
    let rows = vec![
        row("Methods", "XamlIl_Page", 10, true),
        row("Types", "PageType", 20, true),
        row("Blobs", "PageBlob", 10, true),
        row("TemplateMethods", "XamlIl_Template", 9, false),
        row("Methods", "JsonContext<Demo.Item,Demo.Item>", 40, true),
        row("Methods", "JsonContextB", 7, true),
        row("Methods", "ChildMethod", 3, true),
        row("Methods", "OtherMethod", 4, true),
        row("Blobs", "OpaquePayload", 6, true),
    ];
    for (ordinal, source_index) in [
        (0, 0),
        (1, 0),
        (2, 0),
        (3, 0),
        (4, 1),
        (5, 2),
        (6, 3),
        (7, 4),
    ] {
        e.mappings.push(Mapping {
            stream: rows[ordinal].stream.clone(),
            identity: rows[ordinal].identity.clone(),
            assembly: "App".into(),
            source_paths: vec![e.sources[source_index].path.clone()],
            basis: "independent captured mapping".into(),
        });
    }
    let csv = root.join("metadata.csv");
    metadata_csv(&csv, "avares://App/Page.axaml");
    e.artifacts.push(Artifact {
        kind: "metadata".into(),
        path: csv,
        revision: None,
        blake3: None,
    });
    (e, rows)
}
fn fingerprints(paths: &[PathBuf]) -> Vec<Vec<u8>> {
    paths.iter().map(|p| fs::read(p).unwrap()).collect()
}

#[test]
fn prepare_publishes_lens_catalogs_without_extra_native_totals() {
    let root = scratch_root();
    let (e, rows) = rich(root.path());
    let index = import(root.path(), &e, &rows);
    let inputs = vec![
        root.path().join("evidence.json"),
        index.join("index.json"),
        index.join("identities.ndjson"),
        root.path().join("metadata.csv"),
    ];
    let before = fingerprints(&inputs);
    let path = root.path().join("bundle");
    let manifest = prepare(&index, &path, MEMORY).unwrap();
    for (_, name) in VIEWS {
        let bytes = fs::read(path.join(format!("catalog_{name}.ndjson"))).unwrap();
        let offsets = fs::read(path.join(format!("catalog_{name}.offsets"))).unwrap();
        let desc = &manifest.datasets[name];
        assert_eq!(
            usize::try_from(desc.records).unwrap(),
            catalog(&path, name).len()
        );
        assert_eq!(usize::try_from(desc.data_bytes).unwrap(), bytes.len());
        assert_eq!(desc.blake3, blake3::hash(&bytes).to_hex().to_string());
        assert_eq!(
            desc.offsets_blake3,
            blake3::hash(&offsets).to_hex().to_string()
        );
        assert_eq!(offsets.len() as u64, (desc.records + 1) * 8);
        assert_eq!(&offsets[..8], &0_u64.to_le_bytes());
        assert_eq!(
            &offsets[offsets.len() - 8..],
            &desc.data_bytes.to_le_bytes()
        );
    }
    let owners = catalog(&path, "lens_feature_owners");
    assert_eq!(owners, catalog(&path, "lens_costs"));
    assert_eq!(
        owners
            .iter()
            .map(|r| r["additive_bytes"].as_u64().unwrap())
            .sum::<u64>(),
        100
    );
    assert_eq!(
        owners
            .iter()
            .map(|r| r["overlapping_bytes"].as_u64().unwrap())
            .sum::<u64>(),
        9
    );
    let page = find(&owners, "owner", "Demo.Page");
    assert_eq!(
        [
            &page["methods_bytes"],
            &page["types_bytes"],
            &page["blobs_bytes"]
        ],
        [&json!(10), &json!(20), &json!(10)]
    );
    assert_eq!(page["xaml_bytes"], 10);
    let xaml = catalog(&path, "lens_xaml");
    assert_eq!(xaml.len(), 1);
    let doc = &xaml[0]["documents"][0];
    assert!(Path::new(doc["path"].as_str().unwrap()).is_absolute());
    assert_eq!(doc["includes"], json!(["Styles.axaml"]));
    assert_eq!(doc["keys"], json!(["Accent"]));
    assert_eq!(doc["sha256"], "a".repeat(64));
    let serializers = catalog(&path, "lens_serializers");
    let context = find(&serializers, "context", "Demo.ContextA");
    assert_eq!(context["declared_roots"], json!(["Demo.Item"]));
    assert_eq!(context["additive_bytes"], 40);
    assert_eq!(
        context["observed_owner_groups"][0]["owner"],
        "Demo.ContextA"
    );
    assert_eq!(context["generated_outputs_captured"], 1);
    assert_eq!(
        context["options"],
        json!(["JsonSourceGenerationOptions(WriteIndented = true)"])
    );
    let repetitions = catalog(&path, "lens_repetitions");
    assert_eq!(repetitions[0]["context_count"], 2);
    assert_eq!(repetitions[0]["distinct_native_artifacts_proven"], false);
    let arguments = catalog(&path, "lens_arguments");
    assert_eq!(
        find(&arguments, "argument", "Demo.Item")["cost"]["additive_bytes"],
        40
    );
    let reflection = catalog(&path, "lens_reflection");
    assert_eq!(reflection[0]["target"], "return");
    assert_eq!(reflection[0]["source_ordinal"], 0);
    let snapshot = read_json(&path.join("snapshot.json"));
    assert_eq!(snapshot["accounting"]["total_bytes"], Value::Null);
    assert_eq!(snapshot["ledger"]["metadata_lower_bound_bytes"], 40);
    assert_eq!(snapshot["coverage"]["displayed_accounted_bytes"], 100);
    for (view, _) in VIEWS {
        query("lenses", &path, &[view]);
    }
    query("footprint", &path, &["--namespace", "Demo"]);
    assert_eq!(fingerprints(&inputs), before);
    assert_eq!(read_json(&inputs[0])["sources"][0]["path"], "Page.cs");
}

#[test]
fn fresh_metadata_csv_preserves_selected_string_ownership_and_legacy_none() {
    let root = scratch_root();
    let csv = root.path().join("independent.csv");
    metadata_csv(&csv, "Demo.éSuffix");
    let parsed = Cli::try_parse_from([
        "vitnet",
        "--format",
        "json",
        "--memory-limit",
        "128MiB",
        "metadata",
        csv.to_str().unwrap(),
        "--strings",
        "--preview-bytes",
        "7",
        "--assembly",
        "App",
        "--type",
        "App!Demo.Page",
    ])
    .unwrap();
    let report: Value = serde_json::from_str(&execute(&parsed).unwrap()).unwrap();
    let string = &report["sections"]["largest_strings"][0];
    let entry: vitnet_metadata::StringEntry = serde_json::from_value(string.clone()).unwrap();
    assert_eq!(entry.assembly.as_deref(), Some("App"));
    assert_eq!(entry.namespace.as_deref(), Some("Demo"));
    assert_eq!(entry.type_name.as_deref(), Some("App!Demo.Page"));
    assert_eq!(entry.bytes, 10);
    assert_eq!(entry.logical_offset, 30);
    assert_eq!(entry.preview.text, "Demo.é");
    assert_eq!(entry.preview.original_bytes, 13);
    assert!(entry.preview.truncated);
    let lens = vitnet_attribution::lenses::metadata_string(string);
    assert_eq!(lens["ownership"], "metadata_log_selected_owner");
    assert_eq!(lens["owner"], "App!Demo.Page");
    assert_eq!(lens["role"], "qualified_identifier_candidate");
    assert_eq!(lens["bytes"], 10);
    assert_eq!(lens["preview"]["text"], "Demo.é");
    let mut old = string.clone();
    for key in ["assembly", "namespace", "type_name"] {
        old.as_object_mut().unwrap().remove(key);
    }
    let legacy: vitnet_metadata::StringEntry = serde_json::from_value(old.clone()).unwrap();
    assert_eq!(
        (legacy.assembly, legacy.namespace, legacy.type_name),
        (None, None, None)
    );
    assert_eq!(
        vitnet_attribution::lenses::metadata_string(&old)["ownership"],
        "not_captured_or_unowned"
    );
}

#[test]
fn captured_empty_and_legacy_missing_catalogs_remain_distinct() {
    let root = scratch_root();
    let path = bundle(root.path(), &evidence(), &[]);
    let manifest = read_json(&path.join("bundle.json"));
    for (view, name) in VIEWS.into_iter().filter(|(v, _)| *v != "strings") {
        assert_eq!(
            manifest["datasets"][name]["records"],
            u64::from(view == "coverage")
        );
        let v = query("lenses", &path, &[view]);
        assert_eq!(entries(&v).len(), usize::from(view == "coverage"));
        if view != "coverage" {
            assert_eq!(
                fs::read(path.join(format!("catalog_{name}.offsets"))).unwrap(),
                vec![0; 8]
            );
            assert_eq!(v["data"]["next_after"], Value::Null);
        }
    }
    assert!(manifest["datasets"].get("lens_metadata_strings").is_none());
    expect_error("lenses", &path, &["strings"], "explorer.dataset");
    let empty_root = scratch_root();
    let csv = empty_root.path().join("empty.csv");
    fs::write(&csv, "Handle, Kind, Name, Children\n").unwrap();
    let mut e = evidence();
    e.artifacts.push(Artifact {
        kind: "metadata".into(),
        path: csv,
        revision: None,
        blake3: None,
    });
    e.sources = vec![
        source("Demo.None", "None.cs"),
        source("Demo.Empty", "Empty.cs"),
    ];
    e.sources[1].annotations = Some(vec![]);
    let empty = bundle(empty_root.path(), &e, &[]);
    assert_eq!(
        read_json(&empty.join("bundle.json"))["datasets"]["lens_metadata_strings"]["records"],
        0
    );
    assert_eq!(
        entries(&query("lenses", &empty, &["strings"])),
        &Vec::<Value>::new()
    );
    assert_eq!(
        entries(&query("records", &empty, &["lens_metadata_strings"])),
        &Vec::<Value>::new()
    );
    let sources = catalog(&empty, "sources");
    assert!(sources[0].get("annotations").is_none());
    assert_eq!(sources[1]["annotations"], json!([]));
    remove_datasets(&empty, &["lens_metadata_strings", "lens_feature_owners"]);
    expect_error("lenses", &empty, &["strings"], "explorer.dataset");
    expect_error(
        "records",
        &empty,
        &["lens_metadata_strings"],
        "explorer.dataset",
    );
    expect_error(
        "inspect",
        &empty,
        &["0", "--dataset", "lens_metadata_strings"],
        "explorer.dataset",
    );
    expect_error("footprint", &empty, &[], "explorer.lenses.unavailable");
}

// Reseal only disposable reader fixtures using the public manifest generation algorithm.
fn reseal(path: &Path, manifest: &mut Value) {
    let mut snapshot = read_json(&path.join("snapshot.json"));
    snapshot["datasets"] = manifest["datasets"].clone();
    snapshot["generation"] = Value::Null;
    let mut hash = blake3::Hasher::new();
    hash.update(b"vitnet.explorer-generation.v1\0");
    hash.update(manifest["index_blake3"].as_str().unwrap().as_bytes());
    hash.update(manifest["identities_blake3"].as_str().unwrap().as_bytes());
    hash.update(&serde_json::to_vec(&snapshot).unwrap());
    let generation = hash.finalize().to_hex().to_string();
    snapshot["generation"] = json!(generation);
    write_json(&path.join("snapshot.json"), &snapshot);
    manifest["generation"] = json!(generation);
    manifest["snapshot_blake3"] = json!(
        vitnet_attribution::hash_file(&path.join("snapshot.json"))
            .unwrap()
            .1
    );
    write_json(&path.join("bundle.json"), manifest);
}
fn remove_datasets(path: &Path, names: &[&str]) {
    let mut manifest = read_json(&path.join("bundle.json"));
    for name in names {
        manifest["datasets"].as_object_mut().unwrap().remove(*name);
    }
    reseal(path, &mut manifest);
}

fn seal_catalog(path: &Path, name: &str, rows: &[Value]) {
    let mut bytes = Vec::new();
    let mut offsets = Vec::new();
    for row in rows {
        offsets.extend((bytes.len() as u64).to_le_bytes());
        bytes.extend(serde_json::to_vec(row).unwrap());
        bytes.push(b'\n');
    }
    offsets.extend((bytes.len() as u64).to_le_bytes());
    fs::write(path.join(format!("catalog_{name}.ndjson")), &bytes).unwrap();
    fs::write(path.join(format!("catalog_{name}.offsets")), &offsets).unwrap();
    let mut manifest = read_json(&path.join("bundle.json"));
    manifest["datasets"][name] = json!({
        "records":rows.len(), "data_bytes":bytes.len(),
        "blake3":blake3::hash(&bytes).to_hex().to_string(),
        "offsets_blake3":blake3::hash(&offsets).to_hex().to_string(),
    });
    reseal(path, &mut manifest);
}
fn inspect(path: &Path, dataset: &str, ordinal: usize, indices: &[u64], start: u64) -> Value {
    let ordinal = ordinal.to_string();
    let indices = indices
        .iter()
        .map(u64::to_string)
        .collect::<Vec<_>>()
        .join(",");
    let start = start.to_string();
    let mut args = vec![
        ordinal.as_str(),
        "--dataset",
        dataset,
        "--start",
        start.as_str(),
    ];
    if !indices.is_empty() {
        args.extend(["--path", indices.as_str()]);
    }
    query("inspect", path, &args)["data"].clone()
}
fn child_path(path: &Path, dataset: &str, ordinal: usize, keys: &[&str]) -> Vec<u64> {
    let mut result = Vec::new();
    for key in keys {
        let page = inspect(path, dataset, ordinal, &result, 0);
        let child = page["entries"]
            .as_array()
            .unwrap()
            .iter()
            .find(|e| e["key"] == *key)
            .unwrap();
        result.push(child["index"].as_u64().unwrap());
    }
    result
}
fn inspected_text(path: &Path, dataset: &str, ordinal: usize, keys: &[&str]) -> String {
    let indices = child_path(path, dataset, ordinal, keys);
    inspect(path, dataset, ordinal, &indices, 0)["text"]
        .as_str()
        .unwrap()
        .into()
}

#[test]
fn lens_views_and_records_share_exact_filters_and_captured_projections() {
    let root = scratch_root();
    let (e, rows) = rich(root.path());
    let path = bundle(root.path(), &e, &rows);
    assert_lens_record_projections(&path);
    assert_lens_filters_and_transport(&path);
}

fn assert_lens_record_projections(path: &Path) {
    for (view, dataset) in VIEWS {
        let lens = query("lenses", path, &[view]);
        let records = query("records", path, &[dataset]);
        assert_eq!(entries(&lens), entries(&records), "{view}");
        assert_eq!(
            ordinals(&lens),
            (0..catalog(path, dataset).len())
                .map(|n| n.to_string())
                .collect::<Vec<_>>()
        );
        for entry in entries(&lens) {
            let fields = entry["fields"].as_object().unwrap();
            assert!(fields.len() <= 32);
            assert!(fields.values().all(|v| !v.is_object() && !v.is_array()));
            assert!(
                fields
                    .values()
                    .filter_map(Value::as_str)
                    .all(|s| s.len() <= 512)
            );
        }
    }
    for (view, dataset, needle) in [
        ("xaml", "lens_xaml", "Accent"),
        ("serializers", "lens_serializers", "WriteIndented"),
        ("arguments", "lens_arguments", "40"),
        ("reflection", "lens_reflection", "Demo.Target"),
    ] {
        let lens = query("lenses", path, &[view, "--contains", needle]);
        assert_eq!(
            entries(&lens),
            entries(&query("records", path, &[dataset, "--contains", needle]))
        );
        assert_eq!(entries(&lens).len(), 1);
        assert!(
            entries(&query(
                "lenses",
                path,
                &[view, "--contains", &needle.to_lowercase()]
            ))
            .is_empty()
                || needle == "40"
        );
    }
}

fn assert_lens_filters_and_transport(path: &Path) {
    let owner = query(
        "lenses",
        path,
        &[
            "feature-owners",
            "--assembly",
            "App",
            "--namespace",
            "Demo",
            "--owner",
            "Demo.Page",
        ],
    );
    assert_eq!(entries(&owner).len(), 2); // native and separately tiered metadata
    assert_eq!(
        entries(&owner),
        entries(&query(
            "records",
            path,
            &[
                "lens_feature_owners",
                "--filter",
                "assembly=App",
                "--filter",
                "namespace=Demo",
                "--filter",
                "owner=Demo.Page"
            ]
        ))
    );
    assert_eq!(
        entries(&query(
            "lenses",
            path,
            &["feature-owners", "--assembly", "app"]
        )),
        &Vec::<Value>::new()
    );
    assert!(
        !entries(&query(
            "lenses",
            path,
            &["feature-owners", "--namespace", "Demo"]
        ))
        .iter()
        .any(|r| r["fields"]["owner"] == "Demo.Child.Widget")
    );
    for view in ["serializers", "arguments", "repetitions", "coverage"] {
        assert_eq!(
            entries(&query("lenses", path, &[view, "--owner", "Demo.ContextA"])),
            &Vec::<Value>::new()
        );
    }
    let serializer = query(
        "lenses",
        path,
        &["serializers", "--contains", "WriteIndented"],
    );
    assert_eq!(
        entries(&serializer)[0]["fields"]["context"],
        "Demo.ContextA"
    );
    assert!(entries(&serializer)[0]["fields"].get("options").is_none());
    let strings = query("lenses", path, &["strings"]);
    assert_eq!(entries(&strings)[0]["fields"]["role"], "uri_candidate");
    assert_eq!(
        entries(&strings)[0]["fields"]["ownership"],
        "metadata_log_selected_owner"
    );
    assert_eq!(entries(&strings)[0]["capture"]["original_text_bytes"], 23);
    let ndjson: Value =
        serde_json::from_str(&execute(&cli("ndjson", "lenses", path, &["xaml"])).unwrap()).unwrap();
    assert_eq!(ndjson["schema"], "vitnet.explorer-cli.v1");
    assert_eq!(entries(&ndjson), entries(&query("lenses", path, &["xaml"])));
}

#[test]
fn inspection_exposes_captured_nested_values_without_reconstructing_suffixes() {
    let root = scratch_root();
    let (e, rows) = rich(root.path());
    let path = bundle(root.path(), &e, &rows);
    assert_eq!(
        inspected_text(&path, "lens_xaml", 0, &["documents", "0", "includes", "0"]),
        "Styles.axaml"
    );
    assert_eq!(
        inspected_text(&path, "lens_xaml", 0, &["documents", "0", "keys", "0"]),
        "Accent"
    );
    assert_eq!(
        inspected_text(&path, "lens_serializers", 0, &["declared_roots", "0"]),
        "Demo.Item"
    );
    assert_eq!(
        inspected_text(&path, "lens_serializers", 0, &["options", "0"]),
        "JsonSourceGenerationOptions(WriteIndented = true)"
    );
    assert_eq!(
        inspected_text(
            &path,
            "lens_serializers",
            0,
            &["observed_owner_groups", "0", "owner"]
        ),
        "Demo.ContextA"
    );
    assert_eq!(
        inspected_text(&path, "lens_repetitions", 0, &["contexts", "0", "context"]),
        "Demo.ContextA"
    );
    let cost = child_path(&path, "lens_arguments", 0, &["cost", "additive_bytes"]);
    assert_eq!(
        inspect(&path, "lens_arguments", 0, &cost, 0)["display"],
        "40"
    );
    assert_eq!(
        inspected_text(&path, "sources", 0, &["annotations", "0", "target"]),
        "return"
    );
    // Retained previews, not recoverable full metadata strings, are the public record.
    let long = "é".repeat(2500);
    let previews = [
        json!({"bytes":7,"logical_offset":0,"preview":{"text":"complete","original_bytes":8,"truncated":false}}),
        json!({"bytes":8,"logical_offset":7,"preview":{"text":"retained","original_bytes":100,"truncated":true}}),
        json!({"bytes":9,"logical_offset":15}),
        json!({"bytes":10,"logical_offset":24,"preview":{"text":long,"original_bytes":6000,"truncated":true}}),
    ].iter().map(vitnet_attribution::lenses::metadata_string).collect::<Vec<_>>();
    seal_catalog(&path, "lens_metadata_strings", &previews);
    let page = query("lenses", &path, &["strings"]);
    assert_eq!(entries(&page)[0]["capture"]["upstream_truncated"], false);
    assert_eq!(entries(&page)[1]["capture"]["original_text_bytes"], 100);
    assert_eq!(entries(&page)[1]["capture"]["captured_text_bytes"], 8);
    assert_eq!(entries(&page)[1]["capture"]["upstream_truncated"], true);
    assert_eq!(
        entries(&page)[2]["capture"]["original_text_bytes"],
        Value::Null
    );
    assert_eq!(
        entries(&page)[2]["capture"]["captured_text_bytes"],
        Value::Null
    );
    assert_eq!(
        inspected_text(&path, "lens_metadata_strings", 1, &["preview", "text"]),
        "retained"
    );
    let indices = child_path(&path, "lens_metadata_strings", 3, &["preview", "text"]);
    let first = inspect(&path, "lens_metadata_strings", 3, &indices, 0);
    assert_eq!(first["text"], "é".repeat(2048));
    assert_eq!(first["total_bytes"], 5000);
    assert_eq!(first["next_start"], 4096);
    let last = inspect(&path, "lens_metadata_strings", 3, &indices, 4096);
    assert_eq!(last["text"], "é".repeat(452));
    assert_eq!(last["next_start"], Value::Null);
    assert_eq!(
        entries(&page)[3]["fields"]["text"].as_str().unwrap().len(),
        512
    );
    assert_eq!(
        entries(&page)[3]["capture"]["fields_truncated"],
        json!(["text"])
    );
    seal_catalog(
        &path,
        "lens_coverage",
        &[json!({"children":(0..101).collect::<Vec<_>>()})],
    );
    let indices = child_path(&path, "lens_coverage", 0, &["children"]);
    let first = inspect(&path, "lens_coverage", 0, &indices, 0);
    assert_eq!(first["entries"].as_array().unwrap().len(), 100);
    assert_eq!(first["entries"][99]["index"], 99);
    assert_eq!(first["next_start"], 100);
    let last = inspect(&path, "lens_coverage", 0, &indices, 100);
    assert_eq!(last["entries"][0]["summary"], "100");
    assert_eq!(last["next_start"], Value::Null);
}

// The fixture continuation has no control characters; parse its PowerShell quoted arguments.
fn resume(command: &str) -> Cli {
    let mut args = Vec::new();
    let mut token = String::new();
    let mut quoted = false;
    for c in command.chars() {
        if c == '\'' {
            quoted = !quoted;
        } else if c == ' ' && !quoted {
            if !token.is_empty() {
                args.push(std::mem::take(&mut token));
            }
        } else {
            token.push(c);
        }
    }
    if !token.is_empty() {
        args.push(token);
    }
    assert!(!quoted);
    Cli::try_parse_from(args).unwrap()
}

#[test]
fn lens_continuations_preserve_generation_selectors_and_exact_ordinals() {
    let root = scratch_root();
    let (e, rows) = rich(root.path());
    let path = bundle(root.path(), &e, &rows);
    let generation = read_json(&path.join("bundle.json"))["generation"]
        .as_str()
        .unwrap()
        .to_owned();
    let expected = vec!["0", "1", "2"];
    let mut parsed = cli(
        "json",
        "lenses",
        &path,
        &[
            "feature-owners",
            "--contains",
            "source_name_candidate",
            "--assembly",
            "App",
            "--namespace",
            "Demo",
            "--limit",
            "1",
            "--max-batches",
            "1",
            "--timeout-ms",
            "30000",
        ],
    );
    let mut collected = Vec::new();
    for turn in 0..5 {
        let value: Value = serde_json::from_str(&execute(&parsed).unwrap()).unwrap();
        assert_eq!(value["generation"], generation);
        collected.extend(ordinals(&value));
        if value["next_command"].is_null() {
            assert_eq!(turn, 3);
            assert_eq!(value["data"]["next_after"], Value::Null);
            break;
        }
        let command = value["next_command"].as_str().unwrap();
        parsed = resume(command);
        let Command::Explore(args) = &parsed.command else {
            panic!("not explore")
        };
        let ExploreCommand::Lenses(args) = &args.command else {
            panic!("not lenses")
        };
        assert_eq!(args.contains, "source_name_candidate");
        assert_eq!(args.assembly.as_deref(), Some("App"));
        assert_eq!(args.namespace.as_deref(), Some("Demo"));
        assert_eq!(args.page.generation.as_deref(), Some(generation.as_str()));
        assert_eq!(
            (args.page.limit, args.page.max_batches, args.page.timeout_ms),
            (1, 1, 30000)
        );
        assert_eq!(
            args.page.after.unwrap().to_string(),
            collected.last().unwrap().as_str()
        );
    }
    assert_eq!(collected, expected);
    let remaining = query(
        "lenses",
        &path,
        &[
            "feature-owners",
            "--contains",
            "source_name_candidate",
            "--assembly",
            "App",
            "--namespace",
            "Demo",
            "--after",
            "1",
        ],
    );
    assert_eq!(ordinals(&remaining), ["2"]);
    assert_owner_alias_continuation(&path);
}

fn assert_owner_alias_continuation(path: &Path) {
    let selected = query(
        "lenses",
        path,
        &[
            "costs",
            "--contains",
            "Demo",
            "--owner",
            "Demo.Page",
            "--limit",
            "1",
        ],
    );
    let parsed = resume(selected["next_command"].as_str().unwrap());
    let Command::Explore(args) = parsed.command else {
        panic!("not explore")
    };
    let ExploreCommand::Lenses(args) = args.command else {
        panic!("not lenses")
    };
    assert_eq!(args.owner.as_deref(), Some("Demo.Page"));
    assert!(
        selected["next_command"]
            .as_str()
            .unwrap()
            .contains("'costs'")
    );
}

#[test]
fn footprint_reconciles_owner_tiers_namespace_and_project_hints() {
    let root = scratch_root();
    let (e, rows) = rich(root.path());
    let path = bundle(root.path(), &e, &rows);
    let all = query("footprint", &path, &["--limit", "1"]);
    assert_eq!(all["data"]["schema"], "vitnet.feature-footprint.v1");
    assert_eq!(all["data"]["generation"], all["generation"]);
    assert_eq!(
        all["data"]["ledger"],
        json!({
            "additive_bytes":100,"overlapping_bytes":9,"methods_bytes":64,"types_bytes":20,
            "blobs_bytes":16,"other_additive_bytes":0,"metadata_lower_bound_bytes":40,"identities":9,
            "canonical_shared_identities":0,"candidate_owner_bytes":94,"unresolved_bytes":6,
        })
    );
    assert_eq!(all["data"]["matched_owner_groups"], 8);
    assert_eq!(all["data"]["scanned"], 8);
    assert_eq!(entries(&all).len(), 8);
    assert_eq!(all["data"]["complete"], true);
    let demo = query("footprint", &path, &["--namespace", "Demo"]);
    assert_eq!(
        demo["data"]["ledger"],
        json!({
            "additive_bytes":90,"overlapping_bytes":9,"methods_bytes":60,"types_bytes":20,
            "blobs_bytes":10,"other_additive_bytes":0,"metadata_lower_bound_bytes":20,"identities":7,
            "canonical_shared_identities":0,"candidate_owner_bytes":90,
        })
    );
    assert_eq!(demo["data"]["matched_owner_groups"], 5);
    assert!(
        entries(&demo)
            .iter()
            .any(|r| r["namespace"] == "Demo.Child")
    );
    assert!(
        !entries(&demo)
            .iter()
            .any(|r| r["namespace"] == "Demonstration")
    );
    let project = query("footprint", &path, &["--project", "App.csproj"]);
    assert_eq!(project["data"]["selectors"]["assembly"], "App");
    assert!(
        project["data"]["project_basis"]
            .as_str()
            .unwrap()
            .contains("recorded textual")
    );
    assert_eq!(project["data"]["ledger"]["additive_bytes"], 94);
    assert_eq!(
        query("footprint", &path, &["--owner", "Demo.Page"])["data"]["ledger"]["additive_bytes"],
        40
    );
    assert_eq!(
        query("footprint", &path, &["--assembly", "app"])["data"]["ledger"],
        json!({})
    );
    expect_error(
        "footprint",
        &path,
        &["--project", "Missing.csproj"],
        "explorer.project",
    );
    expect_error(
        "footprint",
        &path,
        &["--project", "App.csproj", "--assembly", "Other"],
        "explorer.query",
    );
    // Reader-only managed tier proves ledger partitioning without claiming a captured token join.
    let mut owner = catalog(&path, "lens_feature_owners")[0].clone();
    owner["evidence_tier"] = json!("managed_symbol_join");
    seal_catalog(&path, "lens_feature_owners", &[owner]);
    let typed = query("footprint", &path, &[]);
    assert_eq!(typed["data"]["ledger"]["typed_owner_bytes"], 40);
    assert!(
        typed["data"]["ledger"]
            .get("candidate_owner_bytes")
            .is_none()
    );
}

fn owner(name: &str, bytes: u64) -> Value {
    serde_json::to_value(vitnet_attribution::lenses::Owner {
        assembly: "App".into(),
        namespace: "Demo".into(),
        owner: name.into(),
        evidence_tier: "source_name_candidate".into(),
        cost: vitnet_attribution::lenses::Cost {
            additive_bytes: bytes,
            methods_bytes: bytes,
            identities: 1,
            ..vitnet_attribution::lenses::Cost::default()
        },
        ..vitnet_attribution::lenses::Owner::default()
    })
    .unwrap()
}

#[test]
fn footprint_caps_rows_and_examples_with_stable_cursor_scoped_order() {
    let root = scratch_root();
    let path = bundle(root.path(), &evidence(), &[]);
    let mut rows: Vec<_> = (0..21)
        .map(|i| owner(&format!("Demo.Owner{i:02}"), 10))
        .collect();
    for (i, row) in rows.iter_mut().enumerate() {
        row["examples"] = json!([
            {"ordinal":i,"bytes":10,"stream":"Methods","identity":"captured","truncated":false},
            {"ordinal":99,"bytes":12,"stream":"Methods","identity":"shared","truncated":false}
        ]);
    }
    seal_catalog(&path, "lens_feature_owners", &rows);
    let all = query("footprint", &path, &["--limit", "1"]);
    assert_eq!(entries(&all), &rows[..20]);
    assert_eq!(
        all["data"]["ledger"],
        json!({
            "additive_bytes":210,"overlapping_bytes":0,"methods_bytes":210,"types_bytes":0,
            "blobs_bytes":0,"other_additive_bytes":0,"metadata_lower_bound_bytes":0,"identities":21,
            "canonical_shared_identities":0,"candidate_owner_bytes":210,
        })
    );
    assert_eq!(all["data"]["matched_owner_groups"], 21);
    assert_eq!(all["data"]["scanned"], 21);
    assert_eq!(
        all["data"]["examples"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| e["ordinal"].as_u64().unwrap())
            .collect::<Vec<_>>(),
        [99, 0, 1]
    );
    let remaining = query(
        "footprint",
        &path,
        &[
            "--after",
            "10",
            "--generation",
            all["generation"].as_str().unwrap(),
        ],
    );
    assert_eq!(entries(&remaining), &rows[11..]);
    assert_eq!(remaining["data"]["ledger"]["additive_bytes"], 100);
    assert_eq!(remaining["data"]["scanned"], 10);
    assert_eq!(remaining["data"]["matched_owner_groups"], 10);
    assert_eq!(remaining["data"]["complete"], true);
    assert_eq!(remaining["data"]["next_after"], Value::Null);
    assert!(remaining.get("next_command").is_none());
}

fn graph(root: &Path, labels: &[&str]) -> PathBuf {
    let long_root = "é".repeat(180);
    let reason = "λ".repeat(180);
    let dgml = root.join("captured.dgml");
    let mut xml = format!(
        "<DirectedGraph><Nodes><Node Id=\"9\" Label=\"{long_root}\"/><Node Id=\"10\" Label=\"root10\"/>"
    );
    for (i, label) in labels.iter().enumerate() {
        write!(xml, "<Node Id=\"{}\" Label=\"{label}\"/>", i + 2).unwrap();
    }
    xml.push_str("</Nodes><Links>");
    for i in 0..labels.len() {
        write!(xml, "<Link Source=\"9\" Target=\"{}\" Reason=\"{reason}\"/><Link Source=\"10\" Target=\"{}\" Reason=\"alternative\"/>",i+2,i+2).unwrap();
    }
    xml.push_str(
        "<Link Source=\"99\" Target=\"2\" Reason=\"missing-source\"/></Links></DirectedGraph>",
    );
    fs::write(&dgml, xml).unwrap();
    vitnet_dgml::build_index(
        &dgml,
        &IndexOptions {
            cache_root: root.join("graph-cache"),
            memory_limit: 16 << 20,
            selected_entry: None,
            strict_hash: false,
            control: IndexControl::default(),
        },
    )
    .unwrap()
    .index_directory
}
fn with_graph(e: &mut Evidence, graph: &Path) {
    e.artifacts.push(Artifact {
        kind: "scan_index".into(),
        path: graph.into(),
        revision: None,
        blake3: None,
    });
}
fn without_elapsed(mut value: Value) -> Value {
    // The public terminal transport renders graph IDs as exact decimal strings.
    fn wire_ids(value: &mut Value) {
        match value {
            Value::Object(fields) => {
                for (key, value) in fields {
                    if matches!(
                        key.as_str(),
                        "node_id" | "source_id" | "target_id" | "next_after_id" | "next_after_edge"
                    ) && let Some(id) = value.as_u64()
                    {
                        *value = json!(id.to_string());
                    } else {
                        wire_ids(value);
                    }
                }
            }
            Value::Array(values) => values.iter_mut().for_each(wire_ids),
            _ => {}
        }
    }
    value.as_object_mut().unwrap().remove("elapsed_ms");
    wire_ids(&mut value);
    value
}

#[test]
fn cohort_preserves_original_bounded_witnesses_incoming_alternatives_and_roots() {
    let root = scratch_root();
    let graph_path = graph(root.path(), &["SeedA", "SeedB"]);
    let mut e = evidence();
    with_graph(&mut e, &graph_path);
    let path = bundle(
        root.path(),
        &e,
        &[
            row("Methods", "SeedA", 8, true),
            row("Types", "SeedB", 9, true),
        ],
    );
    let cohort = query(
        "cohort-retention",
        &path,
        &["--ordinal", "0,1", "--graph", "scan_index"],
    );
    assert_eq!(cohort["data"]["schema"], "vitnet.cohort-retention.v1");
    assert_eq!(cohort["data"]["generation"], cohort["generation"]);
    assert_eq!(cohort["data"]["graph"], "scan_index");
    assert_eq!(cohort["data"]["complete"], false);
    let mut session = GraphSession::open(&graph_path, MEMORY / 4).unwrap();
    for (ordinal, identity, node_id) in [(0, "SeedA", 2), (1, "SeedB", 3)] {
        let seed = &cohort["data"]["seeds"][ordinal];
        assert_eq!(seed["ordinal"], ordinal.to_string());
        assert_eq!(seed["identity"], identity);
        assert_eq!(seed["status"], "observed_label_match");
        let search = session
            .search(
                identity,
                &SearchOptions {
                    mode: SearchMode::Exact,
                    limit: 3,
                    max_scanned: 100_000,
                    timeout_ms: 1500,
                    preview_bytes: 512,
                    generation: Some(session.generation.clone()),
                    ..SearchOptions::default()
                },
            )
            .unwrap();
        assert_eq!(
            without_elapsed(seed["search"].clone()),
            without_elapsed(json!(search))
        );
        let why = session
            .why(
                node_id,
                &WhyOptions {
                    max_depth: 12,
                    max_paths: 3,
                    max_visited: 5000,
                    max_edges: 25000,
                    timeout_ms: 1500,
                    preview_bytes: 256,
                    generation: Some(session.generation.clone()),
                },
            )
            .unwrap();
        let incoming = session
            .incoming(
                node_id,
                &IncomingOptions {
                    limit: 20,
                    preview_bytes: 256,
                    generation: Some(session.generation.clone()),
                    timeout_ms: 1500,
                    after_edge: None,
                },
            )
            .unwrap();
        assert_original_retention(seed, why, incoming, &session.generation, ordinal);
    }
    let roots = cohort["data"]["observed_roots"].as_array().unwrap();
    assert_eq!(
        roots
            .iter()
            .map(|r| r["node_id"].as_str().unwrap())
            .collect::<Vec<_>>(),
        ["9", "10"]
    );
    assert!(roots.iter().all(|r| r["observed_paths"] == 2));
    assert_eq!(roots[0]["label"], "é".repeat(128));
}

fn assert_original_retention(
    seed: &Value,
    why: impl serde::Serialize,
    incoming: impl serde::Serialize,
    generation: &str,
    ordinal: usize,
) {
    let retained = &seed["witnesses"][0];
    assert_eq!(retained["schema"], "vitnet.attribution-retention.v1");
    assert_eq!(
        without_elapsed(retained["witness"].clone()),
        without_elapsed(json!(why))
    );
    assert_eq!(
        without_elapsed(retained["alternative_incoming"].clone()),
        without_elapsed(json!(incoming))
    );
    assert_eq!(retained["witness"]["generation"], generation);
    assert_eq!(retained["witness"]["paths"].as_array().unwrap().len(), 2);
    assert!(
        retained["annotated_paths"]
            .as_array()
            .unwrap()
            .iter()
            .all(|p| p["anchors"] == json!([]) && p["collapsed_unmapped_nodes"] == 2)
    );
    assert!(retained["caveats"].as_array().unwrap().iter().any(|c| {
        c.as_str()
            .unwrap()
            .contains("not all removal prerequisites")
    }));
    let alternatives = retained["alternative_incoming"]["edges"]
        .as_array()
        .unwrap();
    let long = alternatives.iter().find(|v| v["source_id"] == "9").unwrap();
    assert_eq!(long["source"]["label"], "é".repeat(128));
    assert_eq!(long["source"]["label_bytes"], 360);
    assert_eq!(long["source"]["truncated"], true);
    assert_eq!(long["reason"], "λ".repeat(128));
    assert_eq!(long["reason_bytes"], 360);
    assert_eq!(long["reason_truncated"], true);
    assert!(
        retained["incoming_anchors"]
            .as_array()
            .unwrap()
            .iter()
            .any(|a| a["node_id"] == "9" && a["sources"]["status"] == "unmapped_truncated_label")
    );
    if ordinal == 0 {
        let missing = alternatives
            .iter()
            .find(|v| v["source_id"] == "99")
            .unwrap();
        assert_eq!(missing["source"], Value::Null);
        assert_eq!(missing["reason"], "missing-source");
        assert_eq!(retained["witness"]["missing_nodes"], 1);
    }
}

#[test]
fn cohort_distinguishes_unsearchable_no_match_missing_and_stale_graphs() {
    let root = scratch_root();
    let exact_budget = "é".repeat(512);
    let over_budget = format!("{exact_budget}a");
    let graph_path = graph(root.path(), &["Exact", &exact_budget, &over_budget]);
    let mut e = evidence();
    with_graph(&mut e, &graph_path);
    let mut lossy = row("Methods", "Exact", 1, true);
    lossy.identity_lossy = true;
    let path = bundle(
        root.path(),
        &e,
        &[
            row("Methods", "Exact", 1, true),
            row("Methods", "exact", 1, true),
            lossy,
            row("Types", &exact_budget, 1, true),
            row("Types", &over_budget, 1, true),
        ],
    );
    for (ordinal, status) in [
        (0, "observed_label_match"),
        (1, "no_witness_in_observed_search"),
        (2, "identity_not_searchable_within_exact_label_budget"),
        (3, "observed_label_match"),
        (4, "identity_not_searchable_within_exact_label_budget"),
    ] {
        let ordinal = ordinal.to_string();
        let value = query(
            "cohort-retention",
            &path,
            &["--ordinal", &ordinal, "--graph", "scan_index"],
        );
        let seed = &value["data"]["seeds"][0];
        assert_eq!(seed["status"], status);
        if status == "identity_not_searchable_within_exact_label_budget" {
            assert_eq!(seed["witnesses"], json!([]));
            assert!(seed.get("identity").is_none());
            assert!(seed.get("search").is_none());
        } else {
            assert!(seed["search"]["query"].is_string());
            if status == "no_witness_in_observed_search" {
                assert_eq!(seed["search"]["entries"], json!([]));
                assert_eq!(seed["witnesses"], json!([]));
            }
        }
    }
    expect_error(
        "cohort-retention",
        &path,
        &["--ordinal", "0"],
        "explorer.graph.missing",
    );
    // Change a captured public fingerprint in a separate disposable generation.
    let index = root.path().join("index");
    let mut captured: vitnet_attribution::AttributionIndex =
        serde_json::from_value(read_json(&index.join("index.json"))).unwrap();
    captured.artifacts[0].graph_generation = Some("different-captured-generation".into());
    write_json(&index.join("index.json"), &captured);
    let mut manifest = read_json(&path.join("bundle.json"));
    manifest["index_blake3"] = json!(
        vitnet_attribution::hash_file(&index.join("index.json"))
            .unwrap()
            .1
    );
    reseal(&path, &mut manifest);
    expect_error(
        "cohort-retention",
        &path,
        &["--ordinal", "0", "--graph", "scan_index"],
        "explorer.graph.stale",
    );
    let missing_root = scratch_root();
    let missing = bundle(
        missing_root.path(),
        &evidence(),
        &[row("Methods", "Exact", 1, true)],
    );
    expect_error(
        "cohort-retention",
        &missing,
        &["--ordinal", "0", "--graph", "scan_index"],
        "explorer.graph.missing",
    );
    let duplicate_root = scratch_root();
    let mut duplicate = e.clone();
    duplicate.artifacts.push(duplicate.artifacts[0].clone());
    let duplicate = bundle(
        duplicate_root.path(),
        &duplicate,
        &[row("Methods", "Exact", 1, true)],
    );
    expect_error(
        "cohort-retention",
        &duplicate,
        &["--ordinal", "0", "--graph", "scan_index"],
        "explorer.graph.missing",
    );
}

#[test]
fn public_queries_reject_invalid_bounds_cursors_generations_and_cancellation() {
    let root = scratch_root();
    let path = bundle(root.path(), &evidence(), &[row("Methods", "One", 1, true)]);
    let allowed = "é".repeat(512);
    let too_long = format!("{allowed}a");
    assert_query_page_guards(&path, &allowed, &too_long);
    assert_query_selection_guards(&path, &allowed, &too_long);
    assert_filter_and_inspection_bounds(&path);
    assert_query_cancellation_and_ordinal(&path);
}

fn assert_query_page_guards(path: &Path, allowed: &str, too_long: &str) {
    assert_eq!(
        entries(&query("lenses", path, &["coverage", "--contains", allowed])),
        &Vec::<Value>::new()
    );
    expect_error(
        "lenses",
        path,
        &["coverage", "--contains", too_long],
        "resource.explorer.query",
    );
    for (flag, invalid) in [
        ("--limit", "0"),
        ("--limit", "101"),
        ("--max-batches", "0"),
        ("--timeout-ms", "0"),
        ("--after", "bad"),
    ] {
        let args = [
            "vitnet",
            "explore",
            "lenses",
            path.to_str().unwrap(),
            "coverage",
            flag,
            invalid,
        ];
        assert!(Cli::try_parse_from(args).is_err(), "{flag}={invalid}");
    }
    for limit in ["1", "100"] {
        assert_eq!(
            entries(&query(
                "lenses",
                path,
                &[
                    "coverage",
                    "--limit",
                    limit,
                    "--max-batches",
                    "1",
                    "--timeout-ms",
                    "30000"
                ]
            ))
            .len(),
            1
        );
    }
    // Bypass parser guards through the actual public argument model to pin backend checks.
    for field in ["limit0", "limit101", "batches", "timeout"] {
        let mut parsed = cli("json", "lenses", path, &["coverage"]);
        let Command::Explore(args) = &mut parsed.command else {
            panic!("not explore")
        };
        let ExploreCommand::Lenses(args) = &mut args.command else {
            panic!("not lens")
        };
        match field {
            "limit0" => args.page.limit = 0,
            "limit101" => args.page.limit = 101,
            "batches" => args.page.max_batches = 0,
            _ => args.page.timeout_ms = 0,
        }
        assert_eq!(
            code(&execute(&parsed).unwrap_err()),
            "resource.explorer.query"
        );
    }
}

fn assert_query_selection_guards(path: &Path, allowed: &str, too_long: &str) {
    for command in ["lenses", "records", "footprint", "cohort-retention"] {
        let mut args = match command {
            "lenses" => vec!["coverage"],
            "records" => vec!["lens_coverage"],
            "cohort-retention" => vec!["--ordinal", "0"],
            _ => vec![],
        };
        args.extend(["--generation", "wrong"]);
        expect_error(command, path, &args, "explorer.generation");
    }
    expect_error(
        "lenses",
        path,
        &["coverage", "--after", "1"],
        "explorer.cursor",
    );
    for ordinals in ["0,0", "0,1,2,3"] {
        expect_error(
            "cohort-retention",
            path,
            &["--ordinal", ordinals],
            "resource.explorer.query",
        );
    }
    let mut empty = cli("json", "cohort-retention", path, &["--ordinal", "0"]);
    let Command::Explore(args) = &mut empty.command else {
        panic!("not explore")
    };
    let ExploreCommand::CohortRetention(args) = &mut args.command else {
        panic!("not cohort")
    };
    args.ordinals.clear();
    assert_eq!(
        code(&execute(&empty).unwrap_err()),
        "resource.explorer.query"
    );
    expect_error(
        "lenses",
        path,
        &["arguments", "--after", "0"],
        "explorer.cursor",
    );
    assert_eq!(
        entries(&query("lenses", path, &["arguments"])),
        &Vec::<Value>::new()
    );
    for selector in ["x", allowed] {
        assert_eq!(
            query("footprint", path, &["--owner", selector])["data"]["ledger"],
            json!({})
        );
    }
    for selector in ["", too_long] {
        expect_error(
            "footprint",
            path,
            &["--owner", selector],
            "resource.explorer.query",
        );
    }
}

fn assert_filter_and_inspection_bounds(path: &Path) {
    let key = "é".repeat(64);
    let value = "é".repeat(2048);
    let mut object = serde_json::Map::new();
    for i in 0..7 {
        object.insert(format!("k{i}"), json!("v"));
    }
    object.insert(key.clone(), json!(value));
    seal_catalog(path, "lens_coverage", &[Value::Object(object)]);
    let mut filters = vec!["lens_coverage".to_owned()];
    for i in 0..7 {
        filters.extend(["--filter".into(), format!("k{i}=v")]);
    }
    filters.extend(["--filter".into(), format!("{key}={value}")]);
    let refs: Vec<_> = filters.iter().map(String::as_str).collect();
    assert_eq!(entries(&query("records", path, &refs)).len(), 1);
    let mut too_many = filters.clone();
    too_many.extend(["--filter".into(), "ninth=v".into()]);
    expect_error(
        "records",
        path,
        &too_many.iter().map(String::as_str).collect::<Vec<_>>(),
        "resource.explorer.query",
    );
    for filter in [format!("{key}a=v"), format!("{key}={value}a")] {
        expect_error(
            "records",
            path,
            &["lens_coverage", "--filter", &filter],
            "resource.explorer.query",
        );
    }
    let mut nested = json!("leaf");
    for _ in 0..64 {
        nested = json!([nested]);
    }
    seal_catalog(path, "lens_coverage", &[nested]);
    assert_eq!(
        inspect(path, "lens_coverage", 0, &[0; 64], 0)["text"],
        "leaf"
    );
    let too_deep = vec!["0"; 65].join(",");
    expect_error(
        "inspect",
        path,
        &["0", "--dataset", "lens_coverage", "--path", &too_deep],
        "resource.explorer.path",
    );
}

fn assert_query_cancellation_and_ordinal(path: &Path) {
    let control = IndexControl::default();
    control.cancel();
    for (command, extra) in [
        ("lenses", vec!["coverage"]),
        ("footprint", vec![]),
        ("cohort-retention", vec!["--ordinal", "0"]),
    ] {
        let error =
            execute_with_index_control(&cli("json", command, path, &extra), &control).unwrap_err();
        assert_eq!(code(&error), "resource.cancelled");
    }
    expect_error(
        "cohort-retention",
        path,
        &["--ordinal", "1"],
        "explorer.row",
    );
}

#[test]
fn footprint_rejects_malformed_ledgers_and_checked_overflow() {
    let root = scratch_root();
    let path = bundle(root.path(), &evidence(), &[]);
    for key in LEDGER {
        for invalid in [None, Some(json!("1")), Some(json!(-1))] {
            let mut row = owner("Demo.Owner", 1);
            row.as_object_mut().unwrap().remove(key);
            if let Some(invalid) = invalid {
                row[key] = invalid;
            }
            seal_catalog(&path, "lens_feature_owners", &[row]);
            expect_error("footprint", &path, &[], "explorer.lenses.schema");
        }
        let mut a = owner("Demo.A", 0);
        let mut b = owner("Demo.B", 0);
        a[key] = json!(u64::MAX - 1);
        b[key] = json!(1);
        seal_catalog(&path, "lens_feature_owners", &[a.clone(), b.clone()]);
        assert_eq!(
            query("footprint", &path, &[])["data"]["ledger"][key],
            u64::MAX
        );
        a[key] = json!(u64::MAX);
        seal_catalog(&path, "lens_feature_owners", &[a, b]);
        expect_error("footprint", &path, &[], "explorer.size");
    }
}

#[test]
fn prepare_rejects_option_input_and_record_boundaries() {
    let root = scratch_root();
    let index = import(root.path(), &evidence(), &[]);
    let out = root.path().join("minimum");
    let rejected = prepare(&index, &out, (32 << 20) - 1).unwrap_err();
    assert_eq!(code(&rejected), "resource.explorer.options");
    assert!(!out.exists());
    prepare(&index, &out, 32 << 20).unwrap();
    let original = fs::read(out.join("bundle.json")).unwrap();
    assert_eq!(
        code(&prepare(&index, &out, MEMORY).unwrap_err()),
        "explorer.output.exists"
    );
    assert_eq!(fs::read(out.join("bundle.json")).unwrap(), original);
    let graph_path = graph(root.path(), &["SeedA", "SeedB"]);
    let graph_root = scratch_root();
    let mut e = evidence();
    with_graph(&mut e, &graph_path);
    let graph_index = import(graph_root.path(), &e, &[]);
    let out = graph_root.path().join("three");
    data::prepare_with_policy(
        &graph_index,
        &out,
        &[],
        None,
        &[2, 9, 10],
        "scan_index",
        MEMORY,
        &IndexControl::default(),
        None,
    )
    .unwrap();
    let out = graph_root.path().join("four");
    let error = data::prepare(
        &graph_index,
        &out,
        &[],
        None,
        &[2, 3, 9, 10],
        "scan_index",
        MEMORY,
        &IndexControl::default(),
    )
    .unwrap_err();
    assert_eq!(code(&error), "resource.explorer.options");
    assert!(!out.exists());
    let supplementary = root.path().join("evidence.json");
    for (count, success) in [(16, true), (17, false)] {
        let out = root.path().join(format!("inventories-{count}"));
        let result = data::prepare(
            &index,
            &out,
            &vec![supplementary.clone(); count],
            None,
            &[],
            "scan_index",
            MEMORY,
            &IndexControl::default(),
        );
        if success {
            result.unwrap();
        } else {
            assert_eq!(code(&result.unwrap_err()), "resource.explorer.options");
            assert!(!out.exists());
        }
    }
    assert_preparation_identity_boundaries();
    assert_preparation_catalog_record_boundary();
}

fn assert_preparation_identity_boundaries() {
    for field in ["identities", "identities_blake3"] {
        let bad_root = scratch_root();
        let index = import(
            bad_root.path(),
            &evidence(),
            &[row("Methods", "One", 1, true)],
        );
        let mut captured = read_json(&index.join("index.json"));
        captured[field] = if field == "identities" {
            json!(2)
        } else {
            json!("0".repeat(64))
        };
        write_json(&index.join("index.json"), &captured);
        let out = bad_root.path().join("bad");
        assert_eq!(
            code(&prepare(&index, &out, MEMORY).unwrap_err()),
            "attribution.cache.integrity"
        );
        assert!(!out.exists());
    }
    let big_root = scratch_root();
    let index = import(
        big_root.path(),
        &evidence(),
        &[row(
            "Methods",
            &"x".repeat((MEMORY / 64) as usize + 1),
            1,
            true,
        )],
    );
    let out = big_root.path().join("oversized-input");
    assert_eq!(
        code(&prepare(&index, &out, MEMORY).unwrap_err()),
        "resource.memory_limit"
    );
    assert!(!out.exists());
}

fn assert_preparation_catalog_record_boundary() {
    // Size the actual serialized XAML document, including the catalog newline.
    let memory = 32 << 20;
    let cap = (memory / 64) as usize;
    for extra in [0, 1] {
        let record_root = scratch_root();
        let mut e = evidence();
        let mut doc = XamlDocument {
            path: record_root.path().join("Page.axaml"),
            assembly: "App".into(),
            declared_class: None,
            root_element: "UserControl".into(),
            sha256: "a".repeat(64),
            includes: vec![],
            keys: vec![String::new()],
        };
        let overhead = serde_json::to_vec(&doc).unwrap().len() + 1;
        doc.keys[0] = "x".repeat(cap - overhead + extra);
        assert_eq!(serde_json::to_vec(&doc).unwrap().len() + 1, cap + extra);
        e.xaml_documents.push(doc);
        let index = import(record_root.path(), &e, &[]);
        let out = record_root.path().join("record");
        let result = prepare(&index, &out, memory);
        if extra == 0 {
            result.unwrap();
            assert_eq!(
                fs::read(out.join("catalog_xaml_documents.ndjson"))
                    .unwrap()
                    .len(),
                cap
            );
        } else {
            assert_eq!(code(&result.unwrap_err()), "resource.explorer.record");
            assert!(!out.exists());
        }
    }
}

#[test]
fn catalog_queries_distinguish_integrity_dataset_staleness_and_source_changes() {
    for corruption in [
        "offset-range",
        "data-hash",
        "data-length",
        "offset-hash",
        "oversized-range",
    ] {
        let root = scratch_root();
        let path = bundle(root.path(), &evidence(), &[]);
        let name = "lens_coverage";
        let data_path = path.join(format!("catalog_{name}.ndjson"));
        let offsets_path = path.join(format!("catalog_{name}.offsets"));
        match corruption {
            "data-hash" => {
                let mut bytes = fs::read(&data_path).unwrap();
                bytes[0] = b'[';
                fs::write(&data_path, bytes).unwrap();
            }
            "data-length" => {
                fs::write(&data_path, b"{}\n").unwrap();
            }
            "offset-hash" => {
                let mut bytes = fs::read(&offsets_path).unwrap();
                bytes[0] = 1;
                fs::write(&offsets_path, bytes).unwrap();
            }
            "offset-range" => {
                let mut bytes = fs::read(&offsets_path).unwrap();
                bytes[..8].copy_from_slice(&1_u64.to_le_bytes());
                fs::write(&offsets_path, &bytes).unwrap();
                let mut manifest = read_json(&path.join("bundle.json"));
                manifest["datasets"][name]["offsets_blake3"] =
                    json!(blake3::hash(&bytes).to_hex().to_string());
                reseal(&path, &mut manifest);
            }
            _ => seal_catalog(
                &path,
                name,
                &[json!({"text":"x".repeat((MEMORY/64) as usize)})],
            ),
        }
        expect_error("records", &path, &[name], "explorer.dataset.integrity");
    }
    for source in ["index.json", "identities.ndjson"] {
        let root = scratch_root();
        let path = bundle(root.path(), &evidence(), &[row("Methods", "One", 1, true)]);
        fs::write(root.path().join("index").join(source), b"changed").unwrap();
        expect_error("lenses", &path, &["coverage"], "explorer.source.stale");
    }
    // Changing the original pre-import evidence is not a captured-index mutation.
    let root = scratch_root();
    let path = bundle(root.path(), &evidence(), &[]);
    fs::write(root.path().join("evidence.json"), b"changed after import").unwrap();
    assert_eq!(entries(&query("lenses", &path, &["coverage"])).len(), 1);
    // Reader::check runs after verification, but no public synchronous hook exposes
    // mutation between those operations. No timing/thread race is used to fake it.
}

#[test]
fn footprint_rejects_oversized_full_row_responses() {
    let root = scratch_root();
    let path = bundle(root.path(), &evidence(), &[]);
    let smaller = (0..20)
        .map(|i| owner(&format!("Demo.{i}{}", "é".repeat(5000)), 1))
        .collect::<Vec<_>>();
    seal_catalog(&path, "lens_feature_owners", &smaller);
    let success = query("footprint", &path, &[]);
    assert_eq!(entries(&success), smaller);
    assert_eq!(
        success["data"]["ledger"],
        json!({
            "additive_bytes":20,"overlapping_bytes":0,"methods_bytes":20,"types_bytes":0,
            "blobs_bytes":0,"other_additive_bytes":0,"metadata_lower_bound_bytes":0,"identities":20,
            "canonical_shared_identities":0,"candidate_owner_bytes":20,
        })
    );
    let oversized = (0..20)
        .map(|i| owner(&format!("Demo.{i}{}", "é".repeat(60000)), 1))
        .collect::<Vec<_>>();
    assert!(
        oversized
            .iter()
            .all(|r| serde_json::to_vec(r).unwrap().len() + 1 < (MEMORY / 64) as usize)
    );
    assert!(serde_json::to_vec(&oversized).unwrap().len() > 2 << 20);
    seal_catalog(&path, "lens_feature_owners", &oversized);
    expect_error("footprint", &path, &[], "resource.explorer.response");
}

fn saturated_incoming_graph(root: &Path) -> PathBuf {
    use std::fmt::Write as _;

    let mut nodes = String::new();
    let mut links = String::new();
    for id in 10..31 {
        write!(nodes, "<Node Id=\"{id}\" Label=\"Root{id}\"/>").unwrap();
        write!(
            links,
            "<Link Source=\"{id}\" Target=\"2\" Reason=\"edge{id}\"/>"
        )
        .unwrap();
    }
    let dgml = root.join("saturated.dgml");
    fs::write(
        &dgml,
        format!(
            "<DirectedGraph><Nodes><Node Id=\"2\" Label=\"SeedA\"/>{nodes}</Nodes>\
             <Links>{links}</Links></DirectedGraph>"
        ),
    )
    .unwrap();
    vitnet_dgml::build_index(
        &dgml,
        &IndexOptions {
            cache_root: root.join("graph-cache"),
            memory_limit: 16 << 20,
            selected_entry: None,
            strict_hash: false,
            control: IndexControl::default(),
        },
    )
    .unwrap()
    .index_directory
}

#[test]
fn cohort_preserves_saturated_incoming_cap_cursor_and_original_limit_report() {
    let root = scratch_root();
    let graph_path = saturated_incoming_graph(root.path());
    let mut e = evidence();
    with_graph(&mut e, &graph_path);
    let path = bundle(root.path(), &e, &[row("Methods", "SeedA", 8, true)]);
    let cohort = query(
        "cohort-retention",
        &path,
        &["--ordinal", "0", "--graph", "scan_index"],
    );
    let seeds = cohort["data"]["seeds"].as_array().unwrap();
    assert_eq!(seeds.len(), 1);
    assert_eq!(seeds[0]["status"], "observed_label_match");
    let witnesses = seeds[0]["witnesses"].as_array().unwrap();
    assert_eq!(witnesses.len(), 1);
    let retained = &witnesses[0]["alternative_incoming"];
    assert_eq!(retained["total_edges"], 21);
    assert_eq!(retained["edges"].as_array().unwrap().len(), 20);
    assert_eq!(retained["next_after_edge"], "19");
    assert_eq!(retained["stop_reason"], "limit");
    assert_eq!(retained["node"]["node_id"], "2");
    assert_eq!(retained["node"]["incoming_edges"], 21);
    let mut session = GraphSession::open(&graph_path, MEMORY / 4).unwrap();
    let incoming = session
        .incoming(
            2,
            &IncomingOptions {
                limit: 20,
                preview_bytes: 256,
                generation: Some(session.generation.clone()),
                timeout_ms: 1500,
                after_edge: None,
            },
        )
        .unwrap();
    assert_eq!(
        incoming
            .edges
            .iter()
            .map(|edge| edge.ordinal)
            .collect::<Vec<_>>(),
        (0..20).collect::<Vec<_>>()
    );
    assert_eq!(
        without_elapsed(retained.clone()),
        without_elapsed(json!(incoming))
    );
}

#[test]
fn rich_metadata_coverage_pins_complete_selected_string_summary() {
    let root = scratch_root();
    let (e, rows) = rich(root.path());
    let path = bundle(root.path(), &e, &rows);
    let coverage = catalog(&path, "lens_coverage");
    assert_eq!(coverage.len(), 1);
    let summary = &coverage[0]["metadata_strings"];
    assert_eq!(
        (
            &summary["captured_records"],
            &summary["captured_lower_bound_bytes"],
            &summary["records_with_selected_owner"],
            &summary["truncated_previews"],
        ),
        (&json!(1), &json!(10), &json!(1), &json!(0))
    );
    assert_eq!(
        summary["scope"],
        "Upstream largest-string top-N selection; omissions and preview suffixes cannot be recovered. Selected log owners do not establish exclusive runtime footprint."
    );
    let expected_concentration = [
        ("by_kind", 40, 5),
        ("by_assembly", 40, 1),
        ("by_namespace", 30, 1),
        ("by_type", 20, 1),
        ("unowned", 20, 3),
    ]
    .into_iter()
    .map(|(name, bytes, groups)| {
        (
            name.to_owned(),
            json!({
                "total_bytes": bytes, "reported_bytes": bytes, "omitted_bytes": 0,
                "total_groups": groups, "reported_groups": groups,
                "reported_share_basis_points": 10000
            }),
        )
    })
    .collect::<serde_json::Map<_, _>>();
    assert_eq!(
        summary["metadata_concentration"],
        Value::Object(expected_concentration)
    );
}

#[test]
fn fresh_metadata_ledger_reconciles_type_assembly_and_unowned_without_native_inflation() {
    let root = scratch_root();
    let (e, rows) = rich(root.path());
    let csv = root.path().join("metadata.csv");
    fs::write(
        &csv,
        "Handle, Kind, Name, Children\n\
         00000000, ScopeDefinition, \"App\", \"a\"\n\
         0000000a, NamespaceDefinition, \"Demo\", \"14\"\n\
         00000014, TypeDefinition, \"Demo.Page\", \"1e\"\n\
         0000001e, ConstantStringValue, \"avares://App/Page.axaml\", \"\"\n\
         00000028, ConstantStringValue, \"unowned literal\", \"\"\n\
         00000032, End, \"\", \"\"\n",
    )
    .unwrap();
    let parsed = Cli::try_parse_from([
        "vitnet",
        "--format",
        "json",
        "--memory-limit",
        "128MiB",
        "metadata",
        csv.to_str().unwrap(),
        "--strings",
    ])
    .unwrap();
    let report: Value = serde_json::from_str(&execute(&parsed).unwrap()).unwrap();
    assert_eq!(report["summary"]["metadata_lower_bound_bytes"], 50);
    assert_eq!(report["summary"]["selected_lower_bound_bytes"], 50);
    assert_eq!(
        report["sections"]["by_type"],
        json!([{"name": "App!Demo.Page", "bytes": 20, "records": 2}])
    );
    assert_eq!(
        report["sections"]["by_assembly"],
        json!([{"name": "App", "bytes": 40, "records": 4}])
    );
    let path = bundle(root.path(), &e, &rows);
    let owners = catalog(&path, "lens_feature_owners");
    let metadata = owners
        .iter()
        .filter(|owner| owner["evidence_tier"] == "metadata_name_candidate")
        .collect::<Vec<_>>();
    assert_eq!(metadata.len(), 3);
    for (assembly, owner, bytes) in [
        ("App", "Demo.Page", 20),
        ("App", "_unresolved_owner", 20),
        ("_unowned_metadata", "_unresolved_owner", 10),
    ] {
        let group = metadata
            .iter()
            .find(|group| group["assembly"] == assembly && group["owner"] == owner)
            .unwrap();
        assert_eq!(group["metadata_lower_bound_bytes"], bytes);
        for key in [
            "additive_bytes",
            "overlapping_bytes",
            "methods_bytes",
            "types_bytes",
            "blobs_bytes",
            "identities",
            "canonical_shared_identities",
        ] {
            assert_eq!(group[key], 0, "{assembly}!{owner}: {key}");
        }
    }
    let selected_metadata = metadata
        .iter()
        .map(|owner| owner["metadata_lower_bound_bytes"].as_u64().unwrap())
        .sum::<u64>();
    assert_eq!(selected_metadata, 50);
    let global = query("footprint", &path, &[]);
    assert_eq!(global["data"]["ledger"]["metadata_lower_bound_bytes"], 50);
    assert_eq!(
        global["data"]["ledger"]["metadata_lower_bound_bytes"],
        selected_metadata
    );
    assert_eq!(
        global["data"]["ledger"]["metadata_lower_bound_bytes"],
        report["summary"]["selected_lower_bound_bytes"]
    );
    assert_eq!(global["data"]["ledger"]["additive_bytes"], 100);
    assert_eq!(global["data"]["ledger"]["overlapping_bytes"], 9);
    let snapshot = read_json(&path.join("snapshot.json"));
    assert_eq!(snapshot["ledger"]["metadata_lower_bound_bytes"], 50);
    assert_eq!(snapshot["coverage"]["displayed_accounted_bytes"], 100);
    assert_eq!(snapshot["accounting"]["total_bytes"], Value::Null);
}

//! Phase 2 opportunity consumers: public, in-process, disposable synthetic inputs.
use clap::Parser;
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use vitnet_attribution::model::{
    Artifact, Assembly, EVIDENCE_SCHEMA, Evidence, Generator, GeneratorChecksum, GeneratorLink,
    GeneratorOutput, GeneratorRun, Mapping, Package, Source,
};
use vitnet_cli::explorer::data;
use vitnet_cli::{AppError, Cli, execute, execute_with_index_control};
use vitnet_dgml::{
    GraphSession, IncomingOptions, IndexControl, IndexOptions, WhyOptions, build_index,
};
use vitnet_mstat::CoalescedIdentity;

#[allow(dead_code)]
#[path = "../../vitnet-attribution/tests/common/mod.rs"]
mod common;

const MEMORY: u64 = 128 << 20;

fn evidence() -> Evidence {
    Evidence {
        schema: EVIDENCE_SCHEMA.into(),
        label: "opportunity contracts".into(),
        ..Evidence::default()
    }
}

fn write_json(path: &Path, value: &impl serde::Serialize) {
    fs::write(path, serde_json::to_vec(value).unwrap()).unwrap();
}

fn read_json(path: &Path) -> Value {
    serde_json::from_slice(&fs::read(path).unwrap()).unwrap()
}

fn row(stream: &str, identity: &str, bytes: u64, accounted: bool) -> CoalescedIdentity {
    CoalescedIdentity {
        stream: stream.into(),
        identity: identity.into(),
        bytes,
        accounted,
        records: 7,
        identity_lossy: false,
        raw_identity_blake3: blake3::hash(identity.as_bytes()).to_hex().to_string(),
    }
}

fn import(root: &Path, value: &Evidence, rows: &[CoalescedIdentity]) -> PathBuf {
    let input = root.join("evidence.json");
    write_json(&input, value);
    let index = root.join("index");
    let mut manifest = vitnet_attribution::import(&input, &index, MEMORY, false).unwrap();
    let mut bytes = Vec::new();
    for entry in rows {
        bytes.extend(serde_json::to_vec(entry).unwrap());
        bytes.push(b'\n');
    }
    fs::write(index.join("identities.ndjson"), &bytes).unwrap();
    manifest.identities = rows.len() as u64;
    manifest.identities_blake3 = blake3::hash(&bytes).to_hex().to_string();
    write_json(&index.join("index.json"), &manifest);
    index
}

fn prepare(index: &Path, output: &Path, policy: Option<&Path>) -> data::BundleManifest {
    data::prepare_with_policy(
        index,
        output,
        &[],
        None,
        &[],
        "scan_index",
        MEMORY,
        &IndexControl::default(),
        policy,
    )
    .unwrap()
}

fn bundle(
    root: &Path,
    value: &Evidence,
    rows: &[CoalescedIdentity],
    policy: Option<&Value>,
) -> PathBuf {
    let index = import(root, value, rows);
    let policy_path = policy.map(|value| {
        let path = root.join("policy.json");
        write_json(&path, value);
        path
    });
    let output = root.join("bundle");
    prepare(&index, &output, policy_path.as_deref());
    output
}

fn catalog(bundle: &Path, name: &str) -> Vec<Value> {
    fs::read(bundle.join(format!("catalog_{name}.ndjson")))
        .unwrap()
        .split(|b| *b == b'\n')
        .filter(|line| !line.is_empty())
        .map(|line| serde_json::from_slice(line).unwrap())
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

fn cli(format: &str, command: &str, path: &Path, extra: &[&str]) -> Cli {
    let mut argv = vec![
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
    argv.extend_from_slice(extra);
    Cli::try_parse_from(argv).unwrap()
}

fn output(format: &str, command: &str, path: &Path, extra: &[&str]) -> String {
    execute(&cli(format, command, path, extra)).unwrap()
}

fn query(command: &str, path: &Path, extra: &[&str]) -> Value {
    let result: Value = serde_json::from_str(&output("json", command, path, extra)).unwrap();
    assert_eq!(result["schema"], "vitnet.explorer-cli.v1");
    assert_eq!(result["operation"], command);
    assert_eq!(
        result["generation"],
        read_json(&path.join("bundle.json"))["generation"]
    );
    result
}

fn entries(value: &Value) -> &[Value] {
    value["data"]["entries"].as_array().unwrap()
}
fn ordinals(value: &Value) -> Vec<String> {
    entries(value)
        .iter()
        .map(|v| v["ordinal"].as_str().unwrap().to_owned())
        .collect()
}

fn error_code(error: &AppError) -> &str {
    match error {
        AppError::Unsupported(v) | AppError::Resource(v) | AppError::IoDiagnostic(v) => &v.code,
        AppError::Dgml(v) => &v.diagnostic.code,
        _ => panic!("unexpected error: {error}"),
    }
}

fn assert_error<T>(result: Result<T, AppError>, code: &str, resource: bool) -> AppError {
    let Err(error) = result else {
        panic!("expected {code}, got success");
    };
    assert_eq!(error_code(&error), code, "{error}");
    assert_eq!(matches!(error, AppError::Resource(_)), resource, "{error}");
    error
}

fn expect_error(command: &str, path: &Path, extra: &[&str], code: &str) {
    assert_error(
        execute(&cli("json", command, path, extra)),
        code,
        code.starts_with("resource."),
    );
}

fn mapping(stream: &str, identity: &str, assembly: &str, basis: &str) -> Mapping {
    Mapping {
        stream: stream.into(),
        identity: identity.into(),
        assembly: assembly.into(),
        basis: basis.into(),
        ..Mapping::default()
    }
}

fn source(assembly: &str, type_name: &str, generated: bool) -> Source {
    Source {
        assembly: assembly.into(),
        type_name: type_name.into(),
        member: Some("Run".into()),
        path: PathBuf::from(format!("{assembly}.cs")),
        line: 1,
        end_line: 3,
        kind: "method".into(),
        generated_by: generated.then(|| "Emitter".into()),
        attributes: vec!["RegisterService".into(), "JsonSerializable(Box)".into()],
        ..Source::default()
    }
}

fn seed() -> (Evidence, Vec<CoalescedIdentity>) {
    let mut value = evidence();
    value.assemblies = vec![
        Assembly {
            name: "A".into(),
            package: Some("Legacy/1".into()),
            ..Assembly::default()
        },
        Assembly {
            name: "B".into(),
            ..Assembly::default()
        },
    ];
    value.sources = vec![source("A", "Box", true), source("B", "Node", false)];
    value.generators.push(Generator {
        name: "Emitter".into(),
        version: "2".into(),
        ..Generator::default()
    });
    let rows = vec![
        row("Methods", "A_Box<int>__Run", 11, true),
        row("Methods", "A_Box<__Canon>__Run", 13, true),
        row("Types", "B_Node", 17, true),
        row("Blobs", "opaque", 19, true),
        row("Methods", "AsyncTaskMethodBuilder_XamlIl", 23, true),
        row("Methods", "A_Box<string>__Run", 29, true),
        row("FrozenObjects", "A_Frozen", 31, false),
    ];
    for (i, assembly) in [(0, "A"), (2, "B"), (4, "A"), (4, "B"), (5, "A")] {
        let mut m = mapping(
            &rows[i].stream,
            &rows[i].identity,
            assembly,
            "explicit_fixture",
        );
        if i == 0 || i == 5 {
            m.source_paths.push(PathBuf::from("A.cs"));
        }
        value.mappings.push(m);
    }
    for target in ["net1", "net2"] {
        value.packages.push(Package {
            target: target.into(),
            id: "P".into(),
            version: "1".into(),
            ..Package::default()
        });
    }
    // Explicit unqualified legacy route supplies the "" target alongside
    // framework-qualified inventories, without pretending targets are merged.
    value
        .mappings
        .push(mapping("package", "Legacy/1", "A", "recorded_legacy"));
    for (a, p, target, role) in [
        ("A", "P/1", "net1", "compile"),
        ("A", "P/1", "net1", "runtime"),
        ("B", "Q/1", "net1", "compile"),
        ("B", "R/1", "net1", "runtime"),
        ("A", "S/1", "net2", "compile"),
    ] {
        value.mappings.push(mapping(
            "package",
            p,
            a,
            &format!("assets_resolved_{role}:{target}"),
        ));
    }
    (value, rows)
}

fn policy() -> Value {
    json!({"schema":"vitnet.opportunity-policy.v1","rules":[
        {"id":"box-a","title":"Box A","kind":"generated_pattern","contains":["Box"],"assemblies":["A"],"investigation":"Inspect evidence"},
        {"id":"box-b","title":"Box B","kind":"generic_pattern","contains":["Box"],"assemblies":[],"investigation":"Inspect registrations"}
    ],"capabilities":[{"id":"implementations","title":"Two implementations","assemblies":["A","B"],"investigation":"Compare semantics"}]})
}

fn seeded(root: &Path) -> PathBuf {
    let (value, rows) = seed();
    bundle(root, &value, &rows, Some(&policy()))
}

fn finding<'a>(values: &'a [Value], id: &str) -> &'a Value {
    let matches: Vec<_> = values.iter().filter(|v| v["id"] == id).collect();
    assert_eq!(matches.len(), 1, "finding {id}");
    matches[0]
}

fn budget<'a>(
    values: &'a [Value],
    dimension: &str,
    target: &str,
    name: &str,
    tier: &str,
) -> &'a Value {
    let matches: Vec<_> = values
        .iter()
        .filter(|v| {
            v["dimension"] == dimension
                && v["target"] == target
                && v["name"] == name
                && v["evidence_tier"] == tier
        })
        .collect();
    assert_eq!(matches.len(), 1, "{dimension}/{target}/{name}/{tier}");
    matches[0]
}

fn refingerprint(bundle: &Path, manifest: &mut Value, snapshot: &mut Value) {
    snapshot["generation"] = Value::Null;
    let mut hash = blake3::Hasher::new();
    hash.update(b"vitnet.explorer-generation.v1\0");
    hash.update(manifest["index_blake3"].as_str().unwrap().as_bytes());
    hash.update(manifest["identities_blake3"].as_str().unwrap().as_bytes());
    hash.update(&serde_json::to_vec(snapshot).unwrap());
    let generation = hash.finalize().to_hex().to_string();
    snapshot["generation"] = json!(generation);
    manifest["generation"] = json!(generation);
    write_json(&bundle.join("snapshot.json"), snapshot);
    manifest["snapshot_blake3"] = json!(
        blake3::hash(&fs::read(bundle.join("snapshot.json")).unwrap())
            .to_hex()
            .to_string()
    );
    write_json(&bundle.join("bundle.json"), manifest);
}

// Only synthetic catalog records are rewritten, with independently rebuilt offsets
// and generation, to exercise public value/path validators.
fn rewrite_catalog(bundle: &Path, dataset: &str, records: &[Value]) {
    let mut payload = Vec::new();
    let mut offsets = Vec::new();
    for record in records {
        offsets.extend((payload.len() as u64).to_le_bytes());
        payload.extend(serde_json::to_vec(record).unwrap());
        payload.push(b'\n');
    }
    offsets.extend((payload.len() as u64).to_le_bytes());
    fs::write(bundle.join(format!("catalog_{dataset}.ndjson")), &payload).unwrap();
    fs::write(bundle.join(format!("catalog_{dataset}.offsets")), &offsets).unwrap();
    let mut manifest = read_json(&bundle.join("bundle.json"));
    let mut snapshot = read_json(&bundle.join("snapshot.json"));
    manifest["datasets"][dataset] = json!({"records":records.len(),"data_bytes":payload.len(),
        "blake3":blake3::hash(&payload).to_hex().to_string(),"offsets_blake3":blake3::hash(&offsets).to_hex().to_string()});
    snapshot["datasets"] = manifest["datasets"].clone();
    refingerprint(bundle, &mut manifest, &mut snapshot);
}

fn assert_catalog_integrity(bundle: &Path, dataset: &str, count: usize) {
    let manifest = read_json(&bundle.join("bundle.json"));
    let descriptor = &manifest["datasets"][dataset];
    let payload = fs::read(bundle.join(format!("catalog_{dataset}.ndjson"))).unwrap();
    let offsets = fs::read(bundle.join(format!("catalog_{dataset}.offsets"))).unwrap();
    assert_eq!(descriptor["records"], count);
    assert_eq!(descriptor["data_bytes"], payload.len());
    assert_eq!(
        descriptor["blake3"],
        blake3::hash(&payload).to_hex().to_string()
    );
    assert_eq!(
        descriptor["offsets_blake3"],
        blake3::hash(&offsets).to_hex().to_string()
    );
    let actual: Vec<_> = offsets
        .chunks_exact(8)
        .map(|v| u64::from_le_bytes(v.try_into().unwrap()))
        .collect();
    let mut expected = vec![0];
    for line in payload.split_inclusive(|b| *b == b'\n') {
        assert_eq!(line.last(), Some(&b'\n'));
        let _: Value = serde_json::from_slice(line).unwrap();
        expected.push(expected.last().unwrap() + line.len() as u64);
    }
    assert_eq!(actual, expected);
    assert_eq!(actual.len(), count + 1);
    assert_eq!(actual.last(), Some(&(payload.len() as u64)));
}

#[test]
fn prepare_wrapper_matches_explicit_none_policy() {
    let root = tempfile::tempdir().unwrap();
    let (value, rows) = seed();
    let index = import(root.path(), &value, &rows);
    let before = contents(&index);
    let a = root.path().join("a");
    let b = root.path().join("b");
    let ma = data::prepare(
        &index,
        &a,
        &[],
        None,
        &[],
        "scan_index",
        MEMORY,
        &IndexControl::default(),
    )
    .unwrap();
    let mb = prepare(&index, &b, None);
    for dataset in ["opportunities", "budgets", "opportunity_coverage"] {
        assert_eq!(catalog(&a, dataset), catalog(&b, dataset));
    }
    assert_eq!(ma.index_blake3, mb.index_blake3);
    assert_eq!(ma.identities_blake3, mb.identities_blake3);
    assert_eq!(ma.identities, 7);
    assert_eq!(ma.generation, mb.generation);
    assert_eq!(contents(&index), before);
    for path in [&a, &b] {
        data::Bundle::open(path, MEMORY).unwrap();
        data::verify(path, MEMORY).unwrap();
    }
}

#[test]
fn prepare_policy_preserves_measured_overlap_and_candidate_tiers() {
    let root = tempfile::tempdir().unwrap();
    let path = seeded(root.path());
    let values = catalog(&path, "opportunities");
    for (id, kind) in [("box-a", "generated_pattern"), ("box-b", "generic_pattern")] {
        let record = finding(&values, id);
        assert_eq!(record["additive_bytes"], 53);
        assert_eq!(record["overlapping_bytes"], 0);
        assert_eq!(record["identities"], 3);
        assert_eq!(record["streams"], json!({"Methods":53}));
        assert_eq!(record["selector_terms"], json!(["Box"]));
        assert_eq!(record["kind"], kind);
        assert_eq!(record["evidence_tier"], "producer_name_candidate");
        assert_eq!(record["proposed_savings_bytes"], Value::Null);
        assert_eq!(
            record["examples"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| v["ordinal"].as_u64().unwrap())
                .collect::<Vec<_>>(),
            [5, 1, 0]
        );
    }
    assert_eq!(finding(&values, "box-a")["assemblies"], json!(["A"]));
    assert_eq!(finding(&values, "box-b")["assemblies"], json!([]));
    let coverage = &catalog(&path, "opportunity_coverage")[0];
    assert_eq!(coverage["accounted_bytes"], 112);
    assert_eq!(
        coverage["streams"],
        json!({"Methods":76,"Types":17,"Blobs":19})
    );
    assert_eq!(coverage["policy"], policy());
    let budgets = catalog(&path, "budgets");
    assert_eq!(
        budget(&budgets, "assembly", "", "A", "asserted")["additive_bytes"],
        40
    );
    assert_eq!(
        budget(&budgets, "assembly", "", "A", "producer_prefix_candidate")["additive_bytes"],
        13
    );
}

#[test]
fn empty_capture_has_complete_hashed_empty_catalogs() {
    for captured in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let mut value = evidence();
        if captured {
            let path = root.path().join("empty.mstat");
            fs::write(&path, common::Image::new().bytes()).unwrap();
            value.artifacts.push(Artifact {
                kind: "mstat".into(),
                path,
                revision: None,
                blake3: None,
            });
        }
        let path = bundle(root.path(), &value, &[], None);
        for dataset in ["opportunities", "budgets"] {
            assert_eq!(catalog(&path, dataset), Vec::<Value>::new());
            assert_catalog_integrity(&path, dataset, 0);
            assert_eq!(
                fs::read(path.join(format!("catalog_{dataset}.offsets"))).unwrap(),
                0_u64.to_le_bytes()
            );
        }
        let coverage = catalog(&path, "opportunity_coverage");
        assert_eq!(coverage.len(), 1);
        assert_eq!(coverage[0]["accounted_bytes"], 0);
        assert_eq!(coverage[0]["streams"], json!({}));
        assert_eq!(coverage[0]["source_declarations"], 0);
        assert_eq!(coverage[0]["metadata_dimensions_complete"], Value::Null);
        assert!(
            coverage[0]["limitations"]
                .as_array()
                .unwrap()
                .iter()
                .any(|v| v
                    .as_str()
                    .unwrap()
                    .contains("not proof a generator executed"))
        );
        let snapshot = data::Bundle::open(&path, MEMORY).unwrap().snapshot;
        assert_eq!(
            snapshot["accounting"]["total_bytes"],
            if captured { json!(0) } else { Value::Null }
        );
        data::verify(&path, MEMORY).unwrap();
    }
}

#[test]
fn complete_catalogs_precede_forty_row_snapshot_caps() {
    let root = tempfile::tempdir().unwrap();
    let mut value = evidence();
    let mut rows = Vec::new();
    for i in 0..41 {
        let assembly = format!("A{i:02}");
        value.assemblies.push(Assembly {
            name: assembly.clone(),
            ..Assembly::default()
        });
        for arg in ["int", "string"] {
            let name = format!("{assembly}_Box<{arg}>__Run");
            value
                .mappings
                .push(mapping("Methods", &name, &assembly, "explicit"));
            rows.push(row("Methods", &name, 2, true));
        }
    }
    let path = bundle(root.path(), &value, &rows, None);
    let opportunities = catalog(&path, "opportunities");
    let budgets = catalog(&path, "budgets");
    assert_eq!(opportunities.len(), 41);
    assert_eq!(budgets.len(), 42);
    let expected: BTreeSet<_> = (0..41).map(|i| format!("A{i:02}")).collect();
    assert_eq!(
        budgets
            .iter()
            .filter(|v| v["dimension"] == "assembly")
            .map(|v| v["name"].as_str().unwrap().to_owned())
            .collect::<BTreeSet<_>>(),
        expected
    );
    for record in budgets.iter().filter(|v| v["dimension"] == "assembly") {
        assert_eq!(record["additive_bytes"], 4);
        assert_eq!(record["identities"], 2);
    }
    let fallback = budget(
        &budgets,
        "package",
        "",
        "_unmapped_package_origin",
        "asserted",
    );
    assert_eq!(fallback["additive_bytes"], 164);
    assert_eq!(fallback["identities"], 82);
    assert_eq!(fallback["streams"], json!({"Methods":164}));
    for record in &opportunities {
        assert_eq!(record["kind"], "generic_family");
        assert_eq!(record["additive_bytes"], 4);
        assert_eq!(record["identities"], 2);
    }
    assert_eq!(
        catalog(&path, "opportunity_coverage")[0]["accounted_bytes"],
        164
    );
    assert_eq!(
        catalog(&path, "opportunity_coverage")[0]["streams"],
        json!({"Methods":164})
    );
    let snapshot = data::Bundle::open(&path, MEMORY).unwrap().snapshot;
    assert_eq!(snapshot["opportunities"].as_array().unwrap().len(), 40);
    assert_eq!(snapshot["budgets"].as_array().unwrap().len(), 40);
    assert_eq!(snapshot["opportunity_coverage"]["findings"], 41);
    assert_eq!(snapshot["opportunity_coverage"]["budgets"], 42);
    let last = query("inspect", &path, &["40", "--dataset", "opportunities"]);
    assert_eq!(last["data"]["kind"], "object");
    assert_eq!(
        original_value(&path, "opportunities", 40, &[]),
        opportunities[40]
    );
    assert_eq!(original_value(&path, "budgets", 41, &[]), budgets[41]);
    assert_catalog_integrity(&path, "opportunities", 41);
}

#[test]
fn catalog_hashes_offsets_and_generation_detect_corruption() {
    for count in [0, 1, 3] {
        let root = tempfile::tempdir().unwrap();
        let rows: Vec<_> = (0..count)
            .map(|i| {
                row(
                    "Methods",
                    ["DevTools", "XamlIl", "AsyncTaskMethodBuilder"][usize::try_from(i).unwrap()],
                    i + 1,
                    true,
                )
            })
            .collect();
        let path = bundle(root.path(), &evidence(), &rows, None);
        assert_catalog_integrity(&path, "opportunities", usize::try_from(count).unwrap());
        assert_catalog_integrity(&path, "budgets", 2 * usize::from(count > 0));
        assert_catalog_integrity(&path, "opportunity_coverage", 1);
        data::verify(&path, MEMORY).unwrap();
    }
    for mutation in ["data", "offset", "generation", "semantic_offset"] {
        let root = tempfile::tempdir().unwrap();
        let path = seeded(root.path());
        if mutation == "data" || mutation == "offset" {
            let name = if mutation == "data" {
                "catalog_budgets.ndjson"
            } else {
                "catalog_budgets.offsets"
            };
            let file = path.join(name);
            let mut bytes = fs::read(&file).unwrap();
            bytes[0] ^= 1;
            fs::write(file, bytes).unwrap();
            assert_error(
                data::Bundle::open(&path, MEMORY),
                "explorer.dataset.integrity",
                false,
            );
        } else if mutation == "generation" {
            let mut manifest = read_json(&path.join("bundle.json"));
            manifest["generation"] = json!("wrong");
            write_json(&path.join("bundle.json"), &manifest);
            assert_error(
                data::Bundle::open(&path, MEMORY),
                "explorer.generation",
                false,
            );
        } else {
            let file = path.join("catalog_budgets.offsets");
            let mut bytes = fs::read(&file).unwrap();
            bytes[8..16].copy_from_slice(&0_u64.to_le_bytes());
            fs::write(file, &bytes).unwrap();
            let mut manifest = read_json(&path.join("bundle.json"));
            let mut snapshot = read_json(&path.join("snapshot.json"));
            manifest["datasets"]["budgets"]["offsets_blake3"] =
                json!(blake3::hash(&bytes).to_hex().to_string());
            snapshot["datasets"] = manifest["datasets"].clone();
            refingerprint(&path, &mut manifest, &mut snapshot);
            assert_error(
                data::verify(&path, MEMORY),
                "explorer.dataset.integrity",
                false,
            );
        }
    }
    for name in ["identities.ndjson", "offsets.bin"] {
        let root = tempfile::tempdir().unwrap();
        let path = seeded(root.path());
        let file = if name == "identities.ndjson" {
            PathBuf::from(
                read_json(&path.join("bundle.json"))["attribution_index"]
                    .as_str()
                    .unwrap(),
            )
            .join(name)
        } else {
            path.join(name)
        };
        let original = fs::read(&file).unwrap();
        let mut bytes = original.clone();
        if name == "identities.ndjson" {
            let needle = b"A_Box<int>__Run";
            let at = bytes
                .windows(needle.len())
                .position(|v| v == needle)
                .unwrap();
            bytes[at] = b'Z';
        } else {
            bytes[0] ^= 1;
        }
        assert_eq!(bytes.len(), original.len());
        assert_ne!(bytes, original);
        fs::write(file, bytes).unwrap();
        assert_error(data::verify(&path, MEMORY), "explorer.integrity", false);
    }
}

#[test]
fn coverage_catalog_preserves_report_including_malformed_count() {
    let root = tempfile::tempdir().unwrap();
    let (value, mut rows) = seed();
    rows.push(row("Methods", "Broken<", 5, true));
    let path = bundle(root.path(), &value, &rows, Some(&policy()));
    let coverage = &catalog(&path, "opportunity_coverage")[0];
    assert_eq!(coverage["schema"], "vitnet.opportunities.v1");
    assert_eq!(coverage["malformed_shape_identities"], 1);
    assert_eq!(coverage["source_declarations"], 2);
    assert_eq!(coverage["generated_declarations"], 1);
    assert_eq!(coverage["generator_descriptors"], 1);
    assert_eq!(
        coverage["attribute_occurrences"],
        json!({"RegisterService":2,"JsonSerializable":2})
    );
    assert_eq!(coverage["accounted_bytes"], 117);
    assert_eq!(
        coverage["streams"],
        json!({"Methods":81,"Types":17,"Blobs":19})
    );
    assert_eq!(coverage["policy"], policy());
    assert_eq!(coverage["metadata_dimensions_complete"], Value::Null);
    assert_eq!(
        coverage["metadata_scope"],
        "Captured lower-bound groups. Unowned and upstream-omitted assembly bytes stay in a separate remainder budget."
    );
    assert_eq!(coverage["limitations"].as_array().unwrap().len(), 6);
    assert_eq!(
        coverage.get("metadata_dimensions_complete"),
        Some(&Value::Null)
    );
}

#[test]
fn metadata_lower_bound_is_separate_nonadditive_assembly_evidence() {
    let root = tempfile::tempdir().unwrap();
    let metadata = root.path().join("metadata.csv");
    fs::write(&metadata, b"Handle, Kind, Name, Children\n00000000, ScopeDefinition, \"App\", \"a\"\n0000000a, TypeDefinition, \"Widget\", \"14\"\n00000014, Method, \"Run\", \"\"\n00000028, End, \"\", \"\"\n").unwrap();
    let mut value = evidence();
    value.artifacts.push(Artifact {
        kind: "metadata".into(),
        path: metadata,
        revision: None,
        blake3: None,
    });
    let path = bundle(root.path(), &value, &[], None);
    let budgets = catalog(&path, "budgets");
    let record = budget(
        &budgets,
        "assembly",
        "",
        "App",
        "metadata_record_ownership_lower_bound",
    );
    assert_eq!(record["additive_bytes"], 0);
    assert_eq!(record["identities"], 0);
    assert_eq!(record["overlapping_bytes"], 40);
    assert_eq!(record["streams"], json!({"metadata_lower_bound":40}));
    let filtered = query(
        "records",
        &path,
        &[
            "budgets",
            "--filter",
            "evidence_tier=metadata_record_ownership_lower_bound",
        ],
    );
    assert_eq!(ordinals(&filtered), ["0", "1"]);
    let package_projection = budget(
        &budgets,
        "package",
        "",
        "_unmapped_package_origin",
        "metadata_record_ownership_lower_bound",
    );
    assert_eq!(package_projection["additive_bytes"], 0);
    assert_eq!(package_projection["identities"], 0);
    assert_eq!(package_projection["overlapping_bytes"], 40);
    assert_eq!(
        package_projection["streams"],
        json!({"metadata_lower_bound":40})
    );
    assert_eq!(package_projection["packages"], json!([]));
    assert_eq!(
        catalog(&path, "opportunity_coverage")[0]["accounted_bytes"],
        0
    );
    assert_eq!(
        budgets.len(),
        2,
        "metadata needs one assembly and one separately overlapping target partition: {budgets:?}"
    );
    assert_eq!(catalog(&path, "opportunities"), Vec::<Value>::new());
}

#[test]
fn prepare_assembly_and_package_totals_reconcile_by_target() {
    let root = tempfile::tempdir().unwrap();
    let path = seeded(root.path());
    let values = catalog(&path, "budgets");
    for (name, tier, additive, overlap, identities, streams) in [
        ("A", "asserted", 40, 0, 2, json!({"Methods":40})),
        (
            "A",
            "producer_prefix_candidate",
            13,
            31,
            2,
            json!({"Methods":13,"FrozenObjects":31}),
        ),
        ("B", "asserted", 17, 0, 1, json!({"Types":17})),
        ("_ambiguous", "ambiguous", 23, 0, 1, json!({"Methods":23})),
        ("_unmapped", "unmapped", 19, 0, 1, json!({"Blobs":19})),
    ] {
        let b = budget(&values, "assembly", "", name, tier);
        assert_eq!(
            (
                b["additive_bytes"].as_u64().unwrap(),
                b["overlapping_bytes"].as_u64().unwrap(),
                b["identities"].as_u64().unwrap()
            ),
            (additive, overlap, identities)
        );
        assert_eq!(b["streams"], streams);
        for (target, package, packages) in [
            (
                "",
                if name == "A" {
                    "Legacy/1"
                } else {
                    "_unmapped_package_origin"
                },
                if name == "A" {
                    json!(["Legacy/1"])
                } else {
                    json!([])
                },
            ),
            (
                "net1",
                match name {
                    "A" => "P/1",
                    "B" => "_shared_package_origin",
                    _ => "_unmapped_package_origin",
                },
                match name {
                    "A" => json!(["P/1"]),
                    "B" => json!(["Q/1", "R/1"]),
                    _ => json!([]),
                },
            ),
            (
                "net2",
                if name == "A" {
                    "S/1"
                } else {
                    "_unmapped_package_origin"
                },
                if name == "A" {
                    json!(["S/1"])
                } else {
                    json!([])
                },
            ),
        ] {
            let p = budget(&values, "package", target, package, tier);
            assert_eq!(p["additive_bytes"], additive);
            assert_eq!(p["overlapping_bytes"], overlap);
            assert_eq!(p["identities"], identities);
            assert_eq!(p["streams"], streams);
            assert_eq!(p["packages"], packages);
        }
    }
    assert_eq!(values.len(), 20);
    assert_budget_partition_totals(&values);
    assert_eq!(
        entries(&query("budgets", &path, &["--target", "missing"])),
        [] as [Value; 0]
    );
}

fn assert_budget_partition_totals(values: &[Value]) {
    for (dimension, target) in [
        ("assembly", ""),
        ("package", ""),
        ("package", "net1"),
        ("package", "net2"),
    ] {
        let selected: Vec<_> = values
            .iter()
            .filter(|v| v["dimension"] == dimension && v["target"] == target)
            .collect();
        assert_eq!(
            selected
                .iter()
                .map(|v| v["additive_bytes"].as_u64().unwrap())
                .sum::<u64>(),
            112
        );
        assert_eq!(
            selected
                .iter()
                .map(|v| v["overlapping_bytes"].as_u64().unwrap())
                .sum::<u64>(),
            31
        );
    }
}

#[test]
fn prepare_validation_and_memory_failures_publish_nothing() {
    let root = tempfile::tempdir().unwrap();
    let index = import(root.path(), &evidence(), &[]);
    let before = contents(&index);
    for (memory, success) in [
        ((32 << 20) - 1, false),
        (32 << 20, true),
        ((32 << 20) + 1, true),
    ] {
        let output = root.path().join(format!("memory-{memory}"));
        let result = data::prepare(
            &index,
            &output,
            &[],
            None,
            &[],
            "scan_index",
            memory,
            &IndexControl::default(),
        );
        if success {
            result.unwrap();
            data::verify(&output, memory).unwrap();
        } else {
            assert_error(result, "resource.explorer.options", true);
            assert!(!output.exists());
        }
    }
    let existing = root.path().join("memory-33554432");
    let preserved = contents(&existing);
    assert_error(
        data::prepare(
            &index,
            &existing,
            &[],
            None,
            &[],
            "scan_index",
            MEMORY,
            &IndexControl::default(),
        ),
        "explorer.output.exists",
        false,
    );
    assert_eq!(contents(&existing), preserved);
    let invalid = root.path().join("invalid.json");
    write_json(&invalid, &json!({"schema":"wrong"}));
    let output = root.path().join("invalid");
    assert_error(
        data::prepare_with_policy(
            &index,
            &output,
            &[],
            None,
            &[],
            "scan_index",
            MEMORY,
            &IndexControl::default(),
            Some(&invalid),
        ),
        "opportunities.policy",
        false,
    );
    assert!(!output.exists());
    assert_eq!(contents(&index), before);
    assert_no_staging_directory(root.path());
}

fn assert_no_staging_directory(root: &Path) {
    assert!(!fs::read_dir(root).unwrap().any(|e| {
        e.unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(".vitnet-explorer-")
    }));
}

#[test]
fn prepare_supplemental_inventory_limits_publish_atomically() {
    let root = tempfile::tempdir().unwrap();
    let index = import(root.path(), &evidence(), &[]);
    let before = contents(&index);
    for count in [16, 17] {
        let mut supplemental = Vec::new();
        for n in 0..count {
            let file = root.path().join(format!("supplement-{n}.json"));
            write_json(&file, &evidence());
            supplemental.push(file);
        }
        let output = root.path().join(format!("supplements-{count}"));
        let result = data::prepare(
            &index,
            &output,
            &supplemental,
            None,
            &[],
            "scan_index",
            MEMORY,
            &IndexControl::default(),
        );
        if count == 16 {
            result.unwrap();
            assert_eq!(
                read_json(&output.join("snapshot.json"))["coverage"]["supplemental_inventories"]
                    .as_array()
                    .unwrap()
                    .len(),
                16
            );
        } else {
            assert_error(result, "resource.explorer.options", true);
            assert!(!output.exists());
        }
    }
    assert_eq!(contents(&index), before);
    assert_no_staging_directory(root.path());
}

#[test]
fn prepare_overflow_maps_to_unsupported_without_partial_output() {
    let root = tempfile::tempdir().unwrap();
    let rows = [
        row("Methods", "one", u64::MAX, true),
        row("Types", "two", 1, true),
    ];
    let index = import(root.path(), &evidence(), &rows);
    let before = contents(&index);
    let path = root.path().join("overflow");
    let error = assert_error(
        data::prepare(
            &index,
            &path,
            &[],
            None,
            &[],
            "scan_index",
            MEMORY,
            &IndexControl::default(),
        ),
        "opportunities.size",
        false,
    );
    assert!(matches!(error, AppError::Unsupported(_)));
    assert!(!path.exists());
    assert_eq!(contents(&index), before);
}

#[test]
fn prepare_collector_memory_exhaustion_keeps_resource_mapping_and_source() {
    let root = tempfile::tempdir().unwrap();
    let mut rows = Vec::new();
    for i in 0..1200 {
        for argument in ["int", "string"] {
            rows.push(row(
                "Methods",
                &format!("Family{i}<{argument}>__Run"),
                1,
                true,
            ));
        }
    }
    let index = import(root.path(), &evidence(), &rows);
    let before = contents(&index);
    let low = root.path().join("low");
    assert_error(
        data::prepare(
            &index,
            &low,
            &[],
            None,
            &[],
            "scan_index",
            32 << 20,
            &IndexControl::default(),
        ),
        "resource.opportunities",
        true,
    );
    assert!(!low.exists());
    let high = root.path().join("high");
    prepare(&index, &high, None);
    assert_eq!(catalog(&high, "opportunities").len(), 1200);
    assert_eq!(
        catalog(&high, "opportunity_coverage")[0]["accounted_bytes"],
        2400
    );
    assert_eq!(contents(&index), before);
    data::verify(&high, MEMORY).unwrap();
}

#[test]
fn precancelled_prepare_and_cli_do_not_publish_or_mutate() {
    let root = tempfile::tempdir().unwrap();
    let (value, rows) = seed();
    let index = import(root.path(), &value, &rows);
    let before = contents(&index);
    let control = IndexControl::default();
    control.cancel();
    let output = root.path().join("cancelled");
    assert_error(
        data::prepare(
            &index,
            &output,
            &[],
            None,
            &[],
            "scan_index",
            MEMORY,
            &control,
        ),
        "resource.cancelled",
        true,
    );
    assert!(!output.exists());
    let path = root.path().join("bundle");
    prepare(&index, &path, None);
    let bundle_before = contents(&path);
    for command in ["opportunities", "budgets"] {
        assert_error(
            execute_with_index_control(&cli("json", command, &path, &["--limit", "1"]), &control),
            "resource.cancelled",
            true,
        );
    }
    assert_eq!(contents(&index), before);
    assert_eq!(contents(&path), bundle_before);
}

#[test]
fn old_bundle_missing_catalogs_requires_reprepare() {
    for dataset in ["opportunities", "budgets"] {
        let root = tempfile::tempdir().unwrap();
        let path = seeded(root.path());
        let mut manifest = read_json(&path.join("bundle.json"));
        let mut snapshot = read_json(&path.join("snapshot.json"));
        manifest["datasets"]
            .as_object_mut()
            .unwrap()
            .remove(dataset);
        snapshot["datasets"] = manifest["datasets"].clone();
        refingerprint(&path, &mut manifest, &mut snapshot);
        data::Bundle::open(&path, MEMORY).unwrap();
        let error = assert_error(
            execute(&cli("json", dataset, &path, &[])),
            "explorer.dataset",
            false,
        );
        assert!(error.to_string().contains("reprepare"), "{error}");
    }
}

#[test]
fn opportunities_command_filters_pages_and_binds_generation() {
    let root = tempfile::tempdir().unwrap();
    let path = seeded(root.path());
    let generation = read_json(&path.join("bundle.json"))["generation"]
        .as_str()
        .unwrap()
        .to_owned();
    let records = catalog(&path, "opportunities");
    let expected: Vec<_> = records
        .iter()
        .enumerate()
        .filter(|(_, v)| {
            v["kind"] == "generated_pattern" && v["title"].as_str().unwrap().contains("Box")
        })
        .map(|(i, _)| i.to_string())
        .collect();
    assert_eq!(expected.len(), 1);
    let page = query(
        "opportunities",
        &path,
        &[
            "--kind",
            "generated_pattern",
            "--contains",
            "Box",
            "--limit",
            "1",
            "--generation",
            &generation,
        ],
    );
    assert_eq!(ordinals(&page), expected);
    assert_eq!(entries(&page)[0]["fields"]["id"], "box-a");
    for contains in ["bOX", "does-not-exist"] {
        assert_eq!(
            entries(&query("opportunities", &path, &["--contains", contains])),
            [] as [Value; 0]
        );
    }
    let last = records.len() - 1;
    let final_page = query(
        "opportunities",
        &path,
        &["--after", &(last - 1).to_string(), "--limit", "1"],
    );
    assert_eq!(ordinals(&final_page), [last.to_string()]);
    assert_eq!(final_page["next_command"], Value::Null);
    let exhausted = query("opportunities", &path, &["--after", &last.to_string()]);
    assert_eq!(entries(&exhausted), [] as [Value; 0]);
    assert_eq!(exhausted["data"]["stop_reason"], "complete");
    assert_eq!(records.len(), 7);
    for after in ["7", "8"] {
        expect_error(
            "opportunities",
            &path,
            &["--after", after],
            "explorer.cursor",
        );
    }
}

#[test]
fn budgets_command_filters_dimensions_targets_and_unknowns() {
    let root = tempfile::tempdir().unwrap();
    let path = seeded(root.path());
    let records = catalog(&path, "budgets");
    for (dimension, target, count) in [
        ("assembly", "", 5),
        ("package", "", 5),
        ("package", "net1", 5),
        ("package", "net2", 5),
        ("package", "missing", 0),
    ] {
        let page = query(
            "budgets",
            &path,
            &["--dimension", dimension, "--target", target],
        );
        let expected: Vec<_> = records
            .iter()
            .enumerate()
            .filter(|(_, v)| v["dimension"] == dimension && v["target"] == target)
            .map(|(i, _)| i.to_string())
            .collect();
        assert_eq!(ordinals(&page), expected);
        assert_eq!(entries(&page).len(), count);
        if count > 0 {
            assert_eq!(
                entries(&page)
                    .iter()
                    .map(|v| v["fields"]["additive_bytes"].as_u64().unwrap())
                    .sum::<u64>(),
                112
            );
            let names: BTreeSet<_> = entries(&page)
                .iter()
                .map(|v| v["fields"]["name"].as_str().unwrap())
                .collect();
            assert!(names.contains(if dimension == "assembly" {
                "_ambiguous"
            } else {
                "_unmapped_package_origin"
            }));
            if target == "net1" {
                assert!(names.contains("_shared_package_origin"));
            }
        }
    }
    let numeric = query(
        "records",
        &path,
        &["budgets", "--filter", "additive_bytes=40"],
    );
    let expected: Vec<_> = records
        .iter()
        .enumerate()
        .filter(|(_, v)| v["additive_bytes"] == 40)
        .map(|(i, _)| i.to_string())
        .collect();
    assert_eq!(ordinals(&numeric), expected);
    assert_eq!(entries(&numeric).len(), 4);
    let actual: BTreeSet<_> = entries(&numeric)
        .iter()
        .map(|entry| {
            let fields = &entry["fields"];
            assert_eq!(fields["additive_bytes"], 40);
            (
                fields["dimension"].as_str().unwrap(),
                fields["target"].as_str().unwrap(),
                fields["name"].as_str().unwrap(),
                fields["evidence_tier"].as_str().unwrap(),
            )
        })
        .collect();
    assert_eq!(
        actual,
        BTreeSet::from([
            ("assembly", "", "A", "asserted"),
            ("package", "", "Legacy/1", "asserted"),
            ("package", "net1", "P/1", "asserted"),
            ("package", "net2", "S/1", "asserted"),
        ])
    );
    assert_eq!(
        entries(&query(
            "records",
            &path,
            &["budgets", "--filter", "additive_bytes=41"]
        )),
        [] as [Value; 0]
    );
}

// Interpret only the generated PowerShell single-quoted literal grammar in memory.
// No shell/child process is used to replay continuation commands.
fn resume_argv(command: &str) -> Vec<String> {
    let chars: Vec<_> = command.chars().collect();
    let mut result = Vec::new();
    let mut token = String::new();
    let mut quoted = false;
    let mut present = false;
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if c == '\'' {
            present = true;
            if quoted && chars.get(i + 1) == Some(&'\'') {
                token.push('\'');
                i += 1;
            } else {
                quoted = !quoted;
            }
        } else if c.is_whitespace() && !quoted {
            if present {
                result.push(std::mem::take(&mut token));
                present = false;
            }
        } else {
            token.push(c);
            present = true;
        }
        i += 1;
    }
    assert!(!quoted, "unterminated literal: {command}");
    if present {
        result.push(token);
    }
    result
}

#[test]
fn continuations_preserve_every_cli_selector_and_budget() {
    let root = tempfile::tempdir().unwrap();
    let path = seeded(root.path());
    let records = catalog(&path, "opportunities");
    for format in ["json", "ndjson"] {
        for (command, extra, expected) in [
            (
                "opportunities",
                vec!["--contains", "Box"],
                records
                    .iter()
                    .enumerate()
                    .filter(|(_, v)| {
                        [
                            "box-a",
                            "box-b",
                            "family:Methods:A_Box<>__Run",
                            "generator:Emitter",
                            "async-machinery",
                        ]
                        .contains(&v["id"].as_str().unwrap())
                    })
                    .map(|(i, _)| i.to_string())
                    .collect::<Vec<_>>(),
            ),
            (
                "opportunities",
                vec!["--kind", "generated_pattern", "--contains", "Literal"],
                records
                    .iter()
                    .enumerate()
                    .filter(|(_, v)| {
                        v["kind"] == "generated_pattern"
                            && v["basis"].as_str().unwrap().contains("Literal")
                    })
                    .map(|(i, _)| i.to_string())
                    .collect(),
            ),
            (
                "budgets",
                vec!["--dimension", "package", "--target", "net1"],
                catalog(&path, "budgets")
                    .iter()
                    .enumerate()
                    .filter(|(_, v)| v["dimension"] == "package" && v["target"] == "net1")
                    .map(|(i, _)| i.to_string())
                    .collect(),
            ),
            (
                "records",
                vec!["opportunities", "--filter", "kind=generated_pattern"],
                records
                    .iter()
                    .enumerate()
                    .filter(|(_, v)| v["kind"] == "generated_pattern")
                    .map(|(i, _)| i.to_string())
                    .collect(),
            ),
            (
                "records",
                vec![
                    "opportunities",
                    "--contains",
                    "Literal",
                    "--filter",
                    "kind=generated_pattern",
                    "--filter",
                    "evidence_tier=producer_name_candidate",
                ],
                records
                    .iter()
                    .enumerate()
                    .filter(|(_, v)| {
                        v["kind"] == "generated_pattern"
                            && v["basis"].as_str().unwrap().contains("Literal")
                    })
                    .map(|(i, _)| i.to_string())
                    .collect(),
            ),
        ] {
            assert_selector_continuation(&path, format, command, &extra, &expected, &records);
        }
    }
}

fn assert_selector_continuation(
    path: &Path,
    format: &str,
    command: &str,
    extra: &[&str],
    expected: &[String],
    records: &[Value],
) {
    let mut options = extra.to_vec();
    options.extend([
        "--limit",
        "1",
        "--max-batches",
        "7",
        "--timeout-ms",
        "60000",
    ]);
    let mut page: Value = serde_json::from_str(&output(format, command, path, &options)).unwrap();
    let mut seen = Vec::new();
    let mut continuations = 0;
    loop {
        seen.extend(ordinals(&page));
        let Some(next) = page["next_command"].as_str() else {
            break;
        };
        continuations += 1;
        assert!(continuations < 30, "cursor must progress");
        let argv = resume_argv(next);
        for pair in [
            ["--format", format],
            ["--memory-limit", "134217728B"],
            ["--limit", "1"],
            ["--max-batches", "7"],
            ["--timeout-ms", "60000"],
        ] {
            assert!(argv.windows(2).any(|w| w == pair), "{argv:?}");
        }
        assert!(argv.windows(2).any(|w| w[0] == "--generation"
            && w[1] == read_json(&path.join("bundle.json"))["generation"]));
        for pair in extra.windows(2).filter(|w| w[0].starts_with("--")) {
            assert!(
                argv.windows(2).any(|w| w[0] == pair[0] && w[1] == pair[1]),
                "{argv:?}"
            );
        }
        let parsed = Cli::try_parse_from(argv).unwrap();
        page = serde_json::from_str(&execute(&parsed).unwrap()).unwrap();
    }
    assert!(continuations > 0);
    assert_eq!(
        seen,
        expected,
        "{command} {extra:?}; catalog ids={:?}",
        records.iter().map(|v| &v["id"]).collect::<Vec<_>>()
    );
    assert_eq!(seen.iter().collect::<BTreeSet<_>>().len(), seen.len());
    assert_eq!(page["data"]["stop_reason"], "complete");
}

#[test]
fn json_ndjson_and_table_formats_preserve_contract_caveats() {
    let root = tempfile::tempdir().unwrap();
    let path = seeded(root.path());
    for command in ["opportunities", "budgets"] {
        let mut json: Value =
            serde_json::from_str(&output("json", command, &path, &["--limit", "1"])).unwrap();
        let text = output("ndjson", command, &path, &["--limit", "1"]);
        assert_eq!(text.lines().count(), 1);
        let mut ndjson: Value = serde_json::from_str(&text).unwrap();
        for v in [&mut json, &mut ndjson] {
            v["data"]["elapsed_ms"] = Value::Null;
            v["next_command"] = Value::Null;
        }
        assert_eq!(json, ndjson);
        assert_eq!(json["schema"], "vitnet.explorer-cli.v1");
        let table = output("table", command, &path, &["--limit", "1"]);
        assert!(table.contains("Measured cohorts may overlap"));
        assert!(table.contains("not predicted savings"));
        assert!(table.contains("Continue (PowerShell)"));
        assert!(table.contains("additive_bytes"));
    }
}

#[test]
fn parser_rejects_invalid_kinds_dimensions_and_duplicate_filters() {
    for (command, flag, values) in [
        (
            "opportunities",
            "--kind",
            vec![
                "generated_pattern",
                "generator_output",
                "generic_pattern",
                "generic_family",
                "unexpected_feature",
                "capability_overlap",
            ],
        ),
        ("budgets", "--dimension", vec!["assembly", "package"]),
    ] {
        for value in values {
            cli("json", command, Path::new("unused"), &[flag, value]);
        }
        assert!(
            Cli::try_parse_from(["vitnet", "explore", command, "unused", flag, "unsupported"])
                .is_err()
        );
    }
    assert!(
        Cli::try_parse_from([
            "vitnet", "explore", "inspect", "unused", "0", "--view", "invalid"
        ])
        .is_err()
    );
    let root = tempfile::tempdir().unwrap();
    let path = seeded(root.path());
    expect_error(
        "records",
        &path,
        &[
            "budgets",
            "--filter",
            "dimension=assembly",
            "--filter",
            "dimension=package",
        ],
        "explorer.query",
    );
    expect_error(
        "inspect",
        &path,
        &["0", "--dataset", "opportunities", "--view", "shape"],
        "explorer.query",
    );
}

#[test]
fn unsupported_exact_filter_fields_are_not_permissive_empty_queries() {
    let root = tempfile::tempdir().unwrap();
    let path = seeded(root.path());
    // A typo is not evidence that a valid selector has an empty partition.
    let result = execute(&cli(
        "json",
        "records",
        &path,
        &["budgets", "--filter", "unsupported_field=anything"],
    ));
    match result {
        Ok(envelope) => panic!(
            "expected explorer.query for unsupported_field=anything, got successful envelope: {envelope}"
        ),
        Err(error) => assert_eq!(error_code(&error), "explorer.query"),
    }
}

#[test]
fn query_bounds_use_exact_and_adjacent_byte_limits() {
    let root = tempfile::tempdir().unwrap();
    let path = seeded(root.path());
    for limit in ["1", "100"] {
        assert_eq!(
            entries(&query("opportunities", &path, &["--limit", limit])).len(),
            if limit == "1" {
                1
            } else {
                catalog(&path, "opportunities").len()
            }
        );
    }
    for (flag, invalid) in [
        ("--limit", "0"),
        ("--limit", "101"),
        ("--max-batches", "0"),
        ("--timeout-ms", "0"),
    ] {
        assert!(
            Cli::try_parse_from([
                "vitnet",
                "explore",
                "opportunities",
                "unused",
                flag,
                invalid
            ])
            .is_err()
        );
    }
    for n in [1023, 1024, 1025] {
        let needle = "a".repeat(n);
        let result = execute(&cli(
            "json",
            "opportunities",
            &path,
            &["--contains", &needle],
        ));
        if n <= 1024 {
            assert_eq!(
                entries(&serde_json::from_str::<Value>(&result.unwrap()).unwrap()),
                [] as [Value; 0]
            );
        } else {
            assert_error(result, "resource.explorer.query", true);
        }
    }
    for (n, ok) in [(511, true), (512, true), (513, false)] {
        let needle = "é".repeat(n);
        let result = execute(&cli("json", "budgets", &path, &["--contains", &needle]));
        if ok {
            assert_eq!(
                entries(&serde_json::from_str::<Value>(&result.unwrap()).unwrap()),
                [] as [Value; 0]
            );
        } else {
            assert_error(result, "resource.explorer.query", true);
        }
    }
    let page = query(
        "opportunities",
        &path,
        &["--max-batches", "1", "--timeout-ms", "1", "--limit", "1"],
    );
    assert_eq!(entries(&page).len(), 1);
}

#[test]
fn exact_filter_key_value_and_count_bounds_use_original_records() {
    let root = tempfile::tempdir().unwrap();
    let path = seeded(root.path());
    // Explicit temporary captured records make otherwise absent fields measurable.
    for n in [127, 128, 129] {
        let key = "k".repeat(n);
        rewrite_catalog(&path, "budgets", &[json!({key.clone():"selected"})]);
        let filter = format!("{key}=selected");
        let result = execute(&cli(
            "json",
            "records",
            &path,
            &["budgets", "--filter", &filter],
        ));
        if n <= 128 {
            assert_eq!(
                ordinals(&serde_json::from_str::<Value>(&result.unwrap()).unwrap()),
                ["0"]
            );
        } else {
            assert_error(result, "resource.explorer.query", true);
        }
    }
    for n in [4095, 4096, 4097] {
        let value = "v".repeat(n);
        rewrite_catalog(&path, "budgets", &[json!({"selection":value})]);
        let filter = format!("selection={value}");
        let result = execute(&cli(
            "json",
            "records",
            &path,
            &["budgets", "--filter", &filter],
        ));
        if n <= 4096 {
            assert_eq!(
                ordinals(&serde_json::from_str::<Value>(&result.unwrap()).unwrap()),
                ["0"]
            );
        } else {
            assert_error(result, "resource.explorer.query", true);
        }
    }
    for count in [8, 9] {
        let record: serde_json::Map<_, _> = (0..count)
            .map(|i| (format!("k{i}"), json!("yes")))
            .collect();
        rewrite_catalog(&path, "budgets", &[Value::Object(record)]);
        let mut args = vec!["budgets".to_owned()];
        for i in 0..count {
            args.extend(["--filter".into(), format!("k{i}=yes")]);
        }
        let refs: Vec<_> = args.iter().map(String::as_str).collect();
        let result = execute(&cli("json", "records", &path, &refs));
        if count == 8 {
            assert_eq!(
                ordinals(&serde_json::from_str::<Value>(&result.unwrap()).unwrap()),
                ["0"]
            );
        } else {
            assert_error(result, "resource.explorer.query", true);
        }
    }
}

#[test]
fn generation_changes_and_stale_continuations_fail_explicitly() {
    let root = tempfile::tempdir().unwrap();
    let path = seeded(root.path());
    let before = contents(&path);
    let page = query("opportunities", &path, &["--limit", "1"]);
    let command = page["next_command"].as_str().unwrap();
    let mut argv = resume_argv(command);
    let position = argv.iter().position(|v| v == "--generation").unwrap() + 1;
    argv[position] = "wrong".into();
    assert_error(
        execute(&Cli::try_parse_from(argv).unwrap()),
        "explorer.generation",
        false,
    );
    let other = tempfile::tempdir().unwrap();
    let second = bundle(
        other.path(),
        &evidence(),
        &[row("Methods", "DevTools", 1, true)],
        None,
    );
    let mut argv = resume_argv(command);
    let position = argv
        .iter()
        .position(|v| v == path.to_str().unwrap())
        .unwrap();
    argv[position] = second.to_str().unwrap().into();
    assert_error(
        execute(&Cli::try_parse_from(argv).unwrap()),
        "explorer.generation",
        false,
    );
    let valid = Cli::try_parse_from(resume_argv(command)).unwrap();
    assert_eq!(
        serde_json::from_str::<Value>(&execute(&valid).unwrap()).unwrap()["generation"],
        page["generation"]
    );
    assert_eq!(contents(&path), before);
}

fn field_path(path: &Path, dataset: &str, ordinal: usize, field: &str) -> String {
    let page = query(
        "inspect",
        path,
        &[&ordinal.to_string(), "--dataset", dataset],
    );
    page["data"]["entries"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["key"] == field)
        .unwrap()["index"]
        .to_string()
}

fn original_value(path: &Path, dataset: &str, ordinal: usize, steps: &[u64]) -> Value {
    original_view_value(path, dataset, ordinal, "record", steps)
}

fn original_view_value(
    path: &Path,
    dataset: &str,
    ordinal: usize,
    view: &str,
    steps: &[u64],
) -> Value {
    let positional = steps
        .iter()
        .map(u64::to_string)
        .collect::<Vec<_>>()
        .join(",");
    let ordinal_text = ordinal.to_string();
    let mut args = vec![ordinal_text.as_str(), "--dataset", dataset, "--view", view];
    if !steps.is_empty() {
        args.extend(["--path", positional.as_str()]);
    }
    let page = query("inspect", path, &args);
    match page["data"]["kind"].as_str().unwrap() {
        "string" => json!(complete_view_string(
            path,
            dataset,
            ordinal,
            view,
            &positional
        )),
        "number" | "boolean" | "null" => {
            serde_json::from_str(page["data"]["display"].as_str().unwrap()).unwrap()
        }
        kind @ ("object" | "array") => {
            let mut children = page["data"]["entries"].as_array().unwrap().clone();
            let mut next = page["next_command"].as_str().map(str::to_owned);
            while let Some(command) = next {
                let parsed = Cli::try_parse_from(resume_argv(&command)).unwrap();
                let page: Value = serde_json::from_str(&execute(&parsed).unwrap()).unwrap();
                children.extend(page["data"]["entries"].as_array().unwrap().clone());
                next = page["next_command"].as_str().map(str::to_owned);
            }
            let mut object = serde_json::Map::new();
            let mut array = Vec::new();
            for child in children {
                let mut child_steps = steps.to_vec();
                child_steps.push(child["index"].as_u64().unwrap());
                let value = original_view_value(path, dataset, ordinal, view, &child_steps);
                if kind == "object" {
                    let key_page = query(
                        "inspect",
                        path,
                        &[
                            &ordinal.to_string(),
                            "--dataset",
                            dataset,
                            "--view",
                            view,
                            "--path",
                            &child_steps
                                .iter()
                                .map(u64::to_string)
                                .collect::<Vec<_>>()
                                .join(","),
                            "--key",
                        ],
                    );
                    assert!(key_page["next_command"].is_null(), "fixture keys are short");
                    object.insert(key_page["data"]["text"].as_str().unwrap().into(), value);
                } else {
                    array.push(value);
                }
            }
            if kind == "object" {
                Value::Object(object)
            } else {
                Value::Array(array)
            }
        }
        other => panic!("unsupported value kind {other}"),
    }
}

fn complete_string(path: &Path, dataset: &str, ordinal: usize, positional_path: &str) -> String {
    complete_view_string(path, dataset, ordinal, "record", positional_path)
}

fn complete_view_string(
    path: &Path,
    dataset: &str,
    ordinal: usize,
    view: &str,
    positional_path: &str,
) -> String {
    let mut page = query(
        "inspect",
        path,
        &[
            &ordinal.to_string(),
            "--dataset",
            dataset,
            "--view",
            view,
            "--path",
            positional_path,
        ],
    );
    let mut text = String::new();
    loop {
        assert_eq!(page["data"]["kind"], "string");
        let chunk = page["data"]["text"].as_str().unwrap();
        assert!(chunk.len() <= 4096);
        text.push_str(chunk);
        let Some(next) = page["next_command"].as_str() else {
            break;
        };
        let parsed = Cli::try_parse_from(resume_argv(next)).unwrap();
        let next: Value = serde_json::from_str(&execute(&parsed).unwrap()).unwrap();
        assert!(next["data"]["start"].as_u64().unwrap() > page["data"]["start"].as_u64().unwrap());
        page = next;
    }
    assert_eq!(
        text.len() as u64,
        page["data"]["total_bytes"].as_u64().unwrap()
    );
    text
}

#[test]
fn records_and_inspect_use_original_catalog_ordinals() {
    let root = tempfile::tempdir().unwrap();
    let path = seeded(root.path());
    let records = catalog(&path, "opportunities");
    let ordinal = records.iter().position(|v| v["id"] == "box-b").unwrap();
    assert!(ordinal > 0 && ordinal < records.len() - 1);
    let page = query("records", &path, &["opportunities", "--filter", "id=box-b"]);
    assert_eq!(ordinals(&page), [ordinal.to_string()]);
    for i in [0, ordinal, records.len() - 1] {
        let inspected = query(
            "inspect",
            &path,
            &[
                &i.to_string(),
                "--dataset",
                "opportunities",
                "--view",
                "record",
                "--generation",
                page["generation"].as_str().unwrap(),
            ],
        );
        assert_eq!(inspected["data"]["kind"], "object");
        assert_eq!(original_value(&path, "opportunities", i, &[]), records[i]);
        for field in ["id", "kind", "title", "basis", "investigation"] {
            let position = field_path(&path, "opportunities", i, field);
            assert_eq!(
                complete_string(&path, "opportunities", i, &position),
                records[i][field].as_str().unwrap()
            );
        }
    }
    expect_error(
        "inspect",
        &path,
        &[&records.len().to_string(), "--dataset", "opportunities"],
        "explorer.cursor",
    );
}

#[test]
fn complete_value_navigation_preserves_long_utf8_strings() {
    let root = tempfile::tempdir().unwrap();
    let mut value = evidence();
    let text = format!("{}é{}END-OF-CAPTURE", "a".repeat(4095), "🦀".repeat(1300));
    value.provenance.insert("long".into(), text.clone());
    let identity = format!("A_DevTools{}END-OF-IDENTITY", "é".repeat(3000));
    let path = bundle(
        root.path(),
        &value,
        &[row("Methods", &identity, 37, true)],
        None,
    );
    let position = field_path(&path, "provenance", 0, "value");
    assert_eq!(complete_string(&path, "provenance", 0, &position), text);
    let position = field_path(&path, "identities", 0, "identity");
    assert_eq!(complete_string(&path, "identities", 0, &position), identity);
    let records = catalog(&path, "opportunities");
    let finding = finding(&records, "tooling-demo");
    assert_eq!(finding["examples"][0]["truncated"], true);
    let preview = finding["examples"][0]["identity"].as_str().unwrap();
    assert!(preview.len() <= 512);
    assert!(identity.starts_with(preview));
    assert!(!preview.contains("END-OF-IDENTITY"));
    let children = json!((0..=100).collect::<Vec<_>>());
    rewrite_catalog(&path, "budgets", std::slice::from_ref(&children));
    let first = query("inspect", &path, &["0", "--dataset", "budgets"]);
    assert_eq!(first["data"]["kind"], "array");
    assert_eq!(first["data"]["total"], 101);
    assert_eq!(first["data"]["start"], 0);
    assert_eq!(first["data"]["next_start"], 100);
    assert_eq!(
        first["data"]["entries"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v["index"].as_u64().unwrap())
            .collect::<Vec<_>>(),
        (0..100).collect::<Vec<_>>()
    );
    let parsed = Cli::try_parse_from(resume_argv(first["next_command"].as_str().unwrap())).unwrap();
    let last: Value = serde_json::from_str(&execute(&parsed).unwrap()).unwrap();
    assert_eq!(last["data"]["start"], 100);
    assert_eq!(last["data"]["entries"].as_array().unwrap().len(), 1);
    assert_eq!(last["data"]["entries"][0]["index"], 100);
    assert_eq!(last["data"]["next_start"], Value::Null);
    assert_eq!(last["next_command"], Value::Null);
    assert_eq!(original_value(&path, "budgets", 0, &[100]), 100);
    assert_eq!(original_value(&path, "budgets", 0, &[]), children);
    let end = query(
        "inspect",
        &path,
        &["0", "--dataset", "budgets", "--start", "101"],
    );
    assert_eq!(
        end["data"]["entries"].as_array().unwrap().as_slice(),
        [] as [Value; 0]
    );
    assert_eq!(end["next_command"], Value::Null);
    expect_error(
        "inspect",
        &path,
        &["0", "--dataset", "budgets", "--start", "102"],
        "explorer.cursor",
    );

    let key = format!("{}éEND", "a".repeat(4095));
    rewrite_catalog(&path, "budgets", &[json!({ key.clone(): 7 })]);
    let listing = query("inspect", &path, &["0", "--dataset", "budgets"]);
    assert_eq!(listing["data"]["entries"].as_array().unwrap().len(), 1);
    assert_eq!(listing["data"]["entries"][0]["index"], 0);
    assert_eq!(listing["data"]["entries"][0]["key"], "a".repeat(512));
    assert_eq!(listing["data"]["entries"][0]["key_truncated"], true);
    let first = query(
        "inspect",
        &path,
        &["0", "--dataset", "budgets", "--path", "0", "--key"],
    );
    assert_eq!(first["data"]["kind"], "string");
    assert_eq!(first["data"]["text"], "a".repeat(4095));
    assert_eq!(first["data"]["total_bytes"], 4100);
    assert_eq!(first["data"]["next_start"], 4095);
    let argv = resume_argv(first["next_command"].as_str().unwrap());
    assert!(argv.iter().any(|arg| arg == "--key"));
    let parsed = Cli::try_parse_from(argv).unwrap();
    let last: Value = serde_json::from_str(&execute(&parsed).unwrap()).unwrap();
    assert_eq!(last["data"]["kind"], "string");
    assert_eq!(last["data"]["start"], 4095);
    assert_eq!(last["data"]["text"], "éEND");
    assert_eq!(last["data"]["next_start"], Value::Null);
    assert_eq!(last["next_command"], Value::Null);
    assert_eq!(
        format!(
            "{}{}",
            first["data"]["text"].as_str().unwrap(),
            last["data"]["text"].as_str().unwrap()
        ),
        key
    );
    assert_eq!(original_value(&path, "budgets", 0, &[0]), 7);
}

#[test]
fn value_navigation_rejects_invalid_paths_and_utf8_offsets() {
    let root = tempfile::tempdir().unwrap();
    let path = bundle(
        root.path(),
        &evidence(),
        &[row("Methods", "éZ", 1, true)],
        None,
    );
    let position = field_path(&path, "identities", 0, "identity");
    let valid = query(
        "inspect",
        &path,
        &["0", "--path", &position, "--start", "2"],
    );
    assert_eq!(valid["data"]["text"], "Z");
    let end = query(
        "inspect",
        &path,
        &["0", "--path", &position, "--start", "3"],
    );
    assert_eq!(end["data"]["text"], "");
    assert_eq!(end["next_command"], Value::Null);
    for start in ["1", "4"] {
        expect_error(
            "inspect",
            &path,
            &["0", "--path", &position, "--start", start],
            "explorer.cursor",
        );
    }
    expect_error(
        "inspect",
        &path,
        &["0", "--path", &format!("{position},0")],
        "explorer.cursor",
    );
    expect_error("inspect", &path, &["0", "--path", "999"], "explorer.cursor");
    let mut nested = json!("leaf");
    for _ in 0..64 {
        nested = json!([nested]);
    }
    rewrite_catalog(&path, "budgets", &[nested]);
    let p64 = vec!["0"; 64].join(",");
    assert_eq!(
        query(
            "inspect",
            &path,
            &["0", "--dataset", "budgets", "--path", &p64]
        )["data"]["text"],
        "leaf"
    );
    let p65 = vec!["0"; 65].join(",");
    expect_error(
        "inspect",
        &path,
        &["0", "--dataset", "budgets", "--path", &p65],
        "resource.explorer.path",
    );
    expect_error(
        "inspect",
        &path,
        &["0", "--dataset", "budgets", "--path", "1"],
        "explorer.cursor",
    );
    expect_error(
        "inspect",
        &path,
        &["0", "--dataset", "budgets", "--key"],
        "explorer.cursor",
    );
}

#[test]
fn scalar_value_navigation_requires_zero_start() {
    let root = tempfile::tempdir().unwrap();
    let path = seeded(root.path());
    let budgets = catalog(&path, "budgets");
    let ordinal = budgets
        .iter()
        .position(|v| v["additive_bytes"] == 40)
        .unwrap();
    let position = field_path(&path, "budgets", ordinal, "additive_bytes");
    let scalar = query(
        "inspect",
        &path,
        &[
            &ordinal.to_string(),
            "--dataset",
            "budgets",
            "--path",
            &position,
            "--start",
            "0",
        ],
    );
    assert_eq!(scalar["data"]["kind"], "number");
    assert_eq!(scalar["data"]["display"], "40");
    assert_eq!(scalar["next_command"], Value::Null);
    expect_error(
        "inspect",
        &path,
        &[
            &ordinal.to_string(),
            "--dataset",
            "budgets",
            "--path",
            &position,
            "--start",
            "1",
        ],
        "explorer.cursor",
    );
}

#[test]
fn lossy_locate_and_shape_inspection_remain_explicit() {
    let root = tempfile::tempdir().unwrap();
    let (value, _) = seed();
    let mut entry = row("Methods", "A_Box<�>__Run", 47, true);
    entry.identity_lossy = true;
    let path = bundle(root.path(), &value, &[entry], None);
    let budgets = catalog(&path, "budgets");
    let b = budget(
        &budgets,
        "assembly",
        "",
        "_unmapped",
        "unmapped_lossy_identity",
    );
    assert_eq!(b["additive_bytes"], 47);
    assert_eq!(b["identities"], 1);
    assert_eq!(catalog(&path, "opportunities"), Vec::<Value>::new());
    let located = query("inspect", &path, &["0", "--view", "source"]);
    let status = located["data"]["entries"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["key"] == "status")
        .unwrap()["index"]
        .to_string();
    let status = query(
        "inspect",
        &path,
        &["0", "--view", "source", "--path", &status],
    );
    assert_eq!(status["data"]["text"], "unmapped_lossy_identity");
    expect_error(
        "inspect",
        &path,
        &["0", "--view", "shape"],
        "explorer.shape.lossy",
    );
}

fn xml_escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn graph(root: &Path, nodes: &[(u64, String)], edges: &[(u64, u64, String)]) -> PathBuf {
    let mut xml =
        "<DirectedGraph xmlns=\"http://schemas.microsoft.com/vs/2009/dgml\"><Nodes>".to_owned();
    for (id, label) in nodes {
        write!(xml, "<Node Id=\"{id}\" Label=\"{}\"/>", xml_escape(label)).unwrap();
    }
    xml.push_str("</Nodes><Links>");
    for (source, target, reason) in edges {
        write!(
            xml,
            "<Link Source=\"{source}\" Target=\"{target}\" Reason=\"{}\"/>",
            xml_escape(reason)
        )
        .unwrap();
    }
    xml.push_str("</Links></DirectedGraph>");
    let input = root.join("graph.dgml");
    fs::write(&input, xml).unwrap();
    build_index(
        &input,
        &IndexOptions {
            cache_root: root.join("graph-cache"),
            memory_limit: MEMORY,
            selected_entry: None,
            strict_hash: true,
            control: IndexControl::default(),
        },
    )
    .unwrap()
    .index_directory
}

fn graph_bundle(
    root: &Path,
    nodes: &[(u64, String)],
    edges: &[(u64, u64, String)],
    kinds: &[&str],
) -> (PathBuf, PathBuf) {
    let graph = graph(root, nodes, edges);
    let (mut value, rows) = seed();
    for kind in kinds {
        value.artifacts.push(Artifact {
            kind: (*kind).into(),
            path: graph.clone(),
            revision: None,
            blake3: None,
        });
    }
    let path = bundle(root, &value, &rows, None);
    (path, graph)
}

fn normalize_retention(value: &mut Value) {
    match value {
        Value::Object(values) => {
            values.remove("elapsed_ms");
            for (key, value) in values {
                if ["node_id", "source_id", "target_id", "next_after_edge"].contains(&key.as_str())
                    && value.is_number()
                {
                    *value = Value::String(value.to_string());
                } else {
                    normalize_retention(value);
                }
            }
        }
        Value::Array(values) => values.iter_mut().for_each(normalize_retention),
        _ => {}
    }
}

fn strip_retention_timing(value: &mut Value) {
    match value {
        Value::Object(values) => {
            values.remove("elapsed_ms");
            values.values_mut().for_each(strip_retention_timing);
        }
        Value::Array(values) => values.iter_mut().for_each(strip_retention_timing),
        _ => {}
    }
}

fn expected_retention(path: &Path, graph_path: &Path, node: u64) -> Value {
    let mut session = GraphSession::open(graph_path, MEMORY / 4).unwrap();
    let generation = session.generation.clone();
    let options = WhyOptions {
        max_depth: 12,
        max_paths: 3,
        max_visited: 5000,
        max_edges: 25000,
        timeout_ms: 1500,
        preview_bytes: 256,
        generation: Some(generation.clone()),
    };
    let witness = session.why(node, &options).unwrap();
    let incoming = session
        .incoming(
            node,
            &IncomingOptions {
                limit: 50,
                after_edge: None,
                timeout_ms: 1500,
                preview_bytes: 256,
                generation: Some(generation),
            },
        )
        .unwrap();
    let index_path = read_json(&path.join("bundle.json"))["attribution_index"]
        .as_str()
        .unwrap()
        .to_owned();
    let index = vitnet_attribution::open_index(Path::new(&index_path), MEMORY).unwrap();
    let mut value = serde_json::to_value(vitnet_attribution::annotate_retention(
        &index.evidence,
        witness,
        incoming,
    ))
    .unwrap();
    normalize_retention(&mut value);
    value
}

fn assert_retention(path: &Path, graph_path: &Path, node: u64, kind: &str) -> Value {
    let generation = read_json(&path.join("bundle.json"))["generation"]
        .as_str()
        .unwrap()
        .to_owned();
    let page = query(
        "retention",
        path,
        &[
            &node.to_string(),
            "--graph",
            kind,
            "--generation",
            &generation,
        ],
    );
    assert_eq!(page["data"]["witness"]["node"]["node_id"], node.to_string());
    assert_ne!(page["data"]["witness"]["generation"], page["generation"]);
    let mut actual = page["data"].clone();
    strip_retention_timing(&mut actual);
    assert_eq!(actual, expected_retention(path, graph_path, node));
    assert!(actual["caveats"].as_array().unwrap().iter().any(|v| {
        v.as_str()
            .unwrap()
            .contains("not proof that one registration is the sole retainer")
    }));
    actual
}

#[test]
fn retention_command_preserves_witness_alternatives_and_anchors() {
    let root = tempfile::tempdir().unwrap();
    let nodes = [
        (0, "Root".into()),
        (1, "A_Box<int>__Run".into()),
        (2, "compiler hop".into()),
        (3, "A_Box<string>__Run".into()),
        (4, "B_Node".into()),
    ];
    let edges = [
        (0, 1, String::new()),
        (1, 2, "registration".into()),
        (2, 3, "call".into()),
        (4, 3, "alternative".into()),
    ];
    let (path, graph) = graph_bundle(root.path(), &nodes, &edges, &["scan_index"]);
    let report = assert_retention(&path, &graph, 3, "scan_index");
    assert_eq!(report["alternative_incoming"]["total_edges"], 2);
    assert_eq!(
        report["alternative_incoming"]["edges"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v["reason"].as_str().unwrap())
            .collect::<BTreeSet<_>>(),
        BTreeSet::from(["call", "alternative"])
    );
    let annotated = report["annotated_paths"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["anchors"].as_array().unwrap().len() == 2)
        .unwrap();
    assert_eq!(
        annotated["anchors"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v["node_id"].as_str().unwrap())
            .collect::<Vec<_>>(),
        ["1", "3"]
    );
    assert_eq!(annotated["collapsed_unmapped_nodes"], 2);
    assert_eq!(
        annotated["anchors"][0]["possible_mechanisms"],
        json!([
            "generated_code",
            "serialization_root_annotation",
            "service_registration_annotation"
        ])
    );
}

#[test]
fn retention_command_keeps_no_path_alternate_and_conjunctive_evidence() {
    for case in ["cycle", "alternate", "conjunctive"] {
        let root = tempfile::tempdir().unwrap();
        let nodes = [
            (0, "Root".into()),
            (1, "Primary".into()),
            (2, "Secondary".into()),
            (3, "A_Box<int>__Run".into()),
            (4, "OtherRoot".into()),
        ];
        let edges = match case {
            "cycle" => vec![
                (1, 3, "cycle forward".into()),
                (3, 1, "cycle backward".into()),
            ],
            "alternate" => vec![
                (0, 1, String::new()),
                (4, 2, String::new()),
                (1, 3, "first root".into()),
                (2, 3, "alternate root".into()),
            ],
            _ => vec![
                (0, 1, String::new()),
                (4, 2, String::new()),
                (1, 3, "Primary".into()),
                (2, 3, "Secondary".into()),
            ],
        };
        let (path, graph) = graph_bundle(root.path(), &nodes, &edges, &["scan_index"]);
        let report = assert_retention(&path, &graph, 3, "scan_index");
        if case == "cycle" {
            assert_eq!(
                report["witness"]["paths"].as_array().unwrap().as_slice(),
                [] as [Value; 0]
            );
            assert_eq!(report["witness"]["stop_reason"], "complete");
            assert_eq!(report["alternative_incoming"]["total_edges"], 1);
        } else {
            assert_eq!(report["witness"]["paths"].as_array().unwrap().len(), 2);
            assert_eq!(
                report["alternative_incoming"]["edges"]
                    .as_array()
                    .unwrap()
                    .len(),
                2
            );
            let reasons = report["alternative_incoming"]["edges"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| v["reason"].as_str().unwrap())
                .collect::<BTreeSet<_>>();
            assert_eq!(
                reasons,
                if case == "alternate" {
                    BTreeSet::from(["first root", "alternate root"])
                } else {
                    BTreeSet::from(["Primary", "Secondary"])
                }
            );
        }
        assert!(
            report["witness"]["caveat"]
                .as_str()
                .unwrap()
                .contains("conjunctions")
        );
    }
}

#[test]
fn retention_command_enforces_graph_generation_and_query_limits() {
    for count in [2, 3, 4, 50, 51] {
        let root = tempfile::tempdir().unwrap();
        let mut nodes: Vec<_> = (0..count).map(|i| (i, format!("Root{i}"))).collect();
        nodes.push((100, "A_Box<int>__Run".into()));
        let edges: Vec<_> = (0..count).map(|i| (i, 100, format!("reason{i}"))).collect();
        let (path, graph) = graph_bundle(
            root.path(),
            &nodes,
            &edges,
            &["scan_index", "codegen_index"],
        );
        for kind in ["scan_index", "codegen_index"] {
            let report = assert_retention(&path, &graph, 100, kind);
            assert_eq!(
                report["witness"]["paths"].as_array().unwrap().len(),
                usize::try_from(count.min(3)).unwrap()
            );
            assert_eq!(
                report["witness"]["stop_reason"],
                if count < 3 { "complete" } else { "max_paths" }
            );
            assert_eq!(report["alternative_incoming"]["total_edges"], count);
            assert_eq!(
                report["alternative_incoming"]["edges"]
                    .as_array()
                    .unwrap()
                    .len(),
                usize::try_from(count.min(50)).unwrap()
            );
            assert_eq!(
                report["alternative_incoming"]["next_after_edge"].is_null(),
                count <= 50
            );
        }
    }
    for depth in [11, 12, 13] {
        let root = tempfile::tempdir().unwrap();
        let nodes: Vec<_> = (0..=depth).map(|i| (i, format!("node{i}"))).collect();
        let edges: Vec<_> = (0..depth).map(|i| (i, i + 1, format!("step{i}"))).collect();
        let (path, graph) = graph_bundle(root.path(), &nodes, &edges, &["scan_index"]);
        let report = assert_retention(&path, &graph, depth, "scan_index");
        if depth <= 12 {
            assert_eq!(report["witness"]["paths"].as_array().unwrap().len(), 1);
        } else {
            assert_eq!(
                report["witness"]["paths"].as_array().unwrap().as_slice(),
                [] as [Value; 0]
            );
            assert_eq!(report["witness"]["stop_reason"], "max_depth");
        }
        expect_error(
            "retention",
            &path,
            &[&depth.to_string(), "--graph", "codegen_index"],
            "explorer.graph.missing",
        );
    }
    let root = tempfile::tempdir().unwrap();
    let (path, graph_path) = graph_bundle(
        root.path(),
        &[(0, "root".into()), (1, "target".into())],
        &[(0, 1, "edge".into())],
        &["scan_index"],
    );
    // Rebuild the same unchanged input, preserving its cache key but publishing
    // a fresh generation. Rewriting XML would change the input fingerprint.
    let changed = build_index(
        &root.path().join("graph.dgml"),
        &IndexOptions {
            cache_root: root.path().join("graph-cache"),
            memory_limit: MEMORY,
            selected_entry: None,
            strict_hash: true,
            control: IndexControl::default(),
        },
    )
    .unwrap();
    assert_eq!(changed.index_directory, graph_path);
    expect_error("retention", &path, &["1"], "explorer.graph.stale");
}

#[test]
fn retention_command_enforces_exact_visited_node_reservations() {
    // No timing assertions: these structures distinguish the exact reservations.
    for count in [4999, 5000] {
        let root = tempfile::tempdir().unwrap();
        let mut nodes: Vec<_> = (0..count).map(|i| (i, format!("root{i}"))).collect();
        nodes.push((10000, "target".into()));
        let edges: Vec<_> = (0..count).map(|i| (i, 10000, "retain".into())).collect();
        let (path, _) = graph_bundle(root.path(), &nodes, &edges, &["scan_index"]);
        let report = query("retention", &path, &["10000"]);
        assert_eq!(
            report["data"]["witness"]["visited_nodes"], 5000,
            "fan-in {count}"
        );
        assert_eq!(
            report["data"]["witness"]["stop_reason"],
            if count == 4999 {
                "max_paths"
            } else {
                "max_visited"
            },
            "fan-in {count}"
        );
        assert_eq!(
            report["data"]["witness"]["paths"].as_array().unwrap().len(),
            if count == 4999 { 3 } else { 0 },
            "fan-in {count}"
        );
        assert_eq!(report["data"]["alternative_incoming"]["total_edges"], count);
    }
}

#[test]
fn retention_command_enforces_exact_examined_edge_reservations() {
    for parallel in [24999, 25000] {
        let root = tempfile::tempdir().unwrap();
        let mut edges = vec![(0, 1, "parallel".into()); parallel];
        edges.push((1, 0, "cycle".into()));
        let (path, _) = graph_bundle(
            root.path(),
            &[(0, "cycle-a".into()), (1, "cycle-b".into())],
            &edges,
            &["scan_index"],
        );
        let report = query("retention", &path, &["1"]);
        assert_eq!(
            report["data"]["witness"]["examined_edges"], 25000,
            "parallel {parallel}"
        );
        assert_eq!(
            report["data"]["witness"]["visited_nodes"], 2,
            "parallel {parallel}"
        );
        assert_eq!(
            report["data"]["witness"]["paths"]
                .as_array()
                .unwrap()
                .as_slice(),
            [] as [Value; 0]
        );
        assert_eq!(
            report["data"]["witness"]["stop_reason"],
            if parallel == 24999 {
                "complete"
            } else {
                "max_edges"
            },
            "parallel {parallel}"
        );
        assert_eq!(
            report["data"]["alternative_incoming"]["total_edges"],
            parallel
        );
    }
}

#[test]
fn prepare_selected_node_count_accepts_three_rejects_four_atomically() {
    let root = tempfile::tempdir().unwrap();
    let graph = graph(
        root.path(),
        &[(0, "root".into()), (1, "a".into()), (2, "b".into())],
        &[(0, 1, String::new()), (0, 2, String::new())],
    );
    let mut value = evidence();
    value.artifacts.push(Artifact {
        kind: "scan_index".into(),
        path: graph,
        revision: None,
        blake3: None,
    });
    let index = import(root.path(), &value, &[]);
    let before = contents(&index);
    for nodes in [&[0, 1, 2][..], &[0, 1, 2, 0][..]] {
        let path = root.path().join(format!("nodes-{}", nodes.len()));
        let result = data::prepare(
            &index,
            &path,
            &[],
            None,
            nodes,
            "scan_index",
            MEMORY,
            &IndexControl::default(),
        );
        if nodes.len() == 3 {
            result.unwrap();
            assert_eq!(
                data::Bundle::open(&path, MEMORY).unwrap().snapshot["witnesses"]
                    .as_array()
                    .unwrap()
                    .len(),
                3
            );
        } else {
            assert_error(result, "resource.explorer.options", true);
            assert!(!path.exists());
        }
    }
    assert_eq!(contents(&index), before);
}

#[test]
fn retention_long_labels_preserve_truncation_and_original_evidence() {
    let root = tempfile::tempdir().unwrap();
    let label = format!("A_Box<int>__Run{}LABEL-END", "é".repeat(200));
    let reason = format!("{}REASON-END", "🦀".repeat(100));
    let nodes = [(0, label.clone()), (1, "A_Box<string>__Run".into())];
    let (path, graph) = graph_bundle(
        root.path(),
        &nodes,
        &[(0, 1, reason.clone())],
        &["scan_index"],
    );
    let report = assert_retention(&path, &graph, 1, "scan_index");
    let edge = &report["alternative_incoming"]["edges"][0];
    assert_eq!(edge["reason_truncated"], true);
    assert_eq!(edge["reason_bytes"], reason.len());
    assert!(edge["reason"].as_str().unwrap().len() <= 256);
    assert_eq!(edge["source"]["truncated"], true);
    assert_eq!(
        report["incoming_anchors"][0]["sources"]["status"],
        "unmapped_truncated_label"
    );
    let position = field_path(&path, "graph_scan_index_nodes", 0, "label");
    assert_eq!(
        complete_string(&path, "graph_scan_index_nodes", 0, &position),
        label
    );
    let position = field_path(&path, "graph_scan_index_edges", 0, "reason");
    assert_eq!(
        complete_string(&path, "graph_scan_index_edges", 0, &position),
        reason
    );
}

#[test]
fn prepared_coverage_and_navigation_never_claim_savings_or_sole_cause() {
    let root = tempfile::tempdir().unwrap();
    let path = seeded(root.path());
    let opportunities = catalog(&path, "opportunities");
    assert!(opportunities.len() >= 7);
    for record in &opportunities {
        assert!(record.get("proposed_savings_bytes").is_some());
        assert_eq!(record["proposed_savings_bytes"], Value::Null);
    }
    let generic = opportunities
        .iter()
        .find(|v| v["kind"] == "generic_family")
        .unwrap();
    assert_eq!(generic["canonical_shared_identities"], 1);
    assert_eq!(generic["additive_bytes"], 53);
    let capability = finding(&opportunities, "implementations");
    assert_eq!(capability["evidence_tier"], "policy_candidate");
    assert_eq!(capability["additive_bytes"], 70);
    assert_eq!(capability["overlapping_bytes"], 31);
    assert_eq!(capability["assemblies"], json!(["A", "B"]));
    let limitations = &catalog(&path, "opportunity_coverage")[0]["limitations"];
    assert!(
        limitations
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v.as_str().unwrap().contains("Never sum cohort bytes"))
    );
    assert!(
        limitations
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v.as_str().unwrap().contains("No controlled experiment"))
    );
    let ordinal = opportunities
        .iter()
        .position(|v| v["id"] == "implementations")
        .unwrap();
    let position = field_path(&path, "opportunities", ordinal, "basis");
    assert_eq!(
        complete_string(&path, "opportunities", ordinal, &position),
        capability["basis"].as_str().unwrap()
    );
    assert!(output("table", "opportunities", &path, &[]).contains("not predicted savings"));
    assert_eq!(opportunities.len(), 7);
    let nulls = query(
        "records",
        &path,
        &["opportunities", "--filter", "proposed_savings_bytes=null"],
    );
    assert_eq!(
        ordinals(&nulls),
        (0..7).map(|i| i.to_string()).collect::<Vec<_>>()
    );
    assert_eq!(entries(&nulls).len(), 7);
    for entry in entries(&nulls) {
        let ordinal = entry["ordinal"].as_str().unwrap().parse::<usize>().unwrap();
        assert_eq!(entry["fields"]["id"], opportunities[ordinal]["id"]);
        assert_eq!(
            opportunities[ordinal].get("proposed_savings_bytes"),
            Some(&Value::Null)
        );
    }
    assert_eq!(
        entries(&query(
            "records",
            &path,
            &["opportunities", "--filter", "proposed_savings_bytes=0"]
        )),
        [] as [Value; 0]
    );
}

#[test]
fn generator_outputs_preserve_capture_and_execution_trust() {
    for case in ["absent", "empty", "descriptor", "captured", "observed"] {
        let root = tempfile::tempdir().unwrap();
        let mut value = evidence();
        if case == "descriptor" {
            value.generators.push(Generator {
                name: "Emitter".into(),
                version: "5".into(),
                assembly_path: root.path().join("Emitter.dll"),
                ..Generator::default()
            });
        }
        if ["empty", "captured", "observed"].contains(&case) {
            let outputs = if case == "empty" {
                Vec::new()
            } else {
                vec![GeneratorOutput {
                    path: root.path().join("Generated.cs"),
                    sha256: Some("ab".repeat(32)),
                    build_match: "pdb_checksum_equal".into(),
                    pdb_checksums: vec![GeneratorChecksum {
                        pdb_path: root.path().join("App.pdb"),
                        algorithm: "SHA256".into(),
                        checksum: "cd".repeat(32),
                        status: "captured".into(),
                        assembly_match: "build_matched".into(),
                        target_assembly: Some("App".into()),
                        target_assembly_path: Some(root.path().join("App.dll")),
                    }],
                }]
            };
            value.generator_runs.push(GeneratorRun {
                name: "Emitter".into(),
                version: Some("5".into()),
                project_path: Some(root.path().join("App.csproj")),
                target_assembly: Some("App".into()),
                target_assembly_path: Some(root.path().join("App.dll")),
                configuration: Some("Release".into()),
                target_framework: Some("net10.0".into()),
                status: "captured".into(),
                basis: "recorded_output".into(),
                outputs,
                execution_status: if case == "observed" {
                    "observed"
                } else {
                    "unknown"
                }
                .into(),
                ..GeneratorRun::default()
            });
        }
        let expected = serde_json::to_value(&value.generator_runs).unwrap();
        let path = bundle(root.path(), &value, &[], None);
        assert_eq!(json!(catalog(&path, "generator_runs")), expected);
        let coverage = &catalog(&path, "opportunity_coverage")[0];
        assert_eq!(coverage["generator_runs"], value.generator_runs.len());
        assert_eq!(
            coverage["generator_outputs_captured"],
            usize::from(case == "captured" || case == "observed")
        );
        assert_eq!(
            coverage["generator_execution_observed"],
            usize::from(case == "observed")
        );
        assert_eq!(
            coverage["generator_descriptors"],
            usize::from(case == "descriptor")
        );
        assert_eq!(
            catalog(&path, "opportunities"),
            Vec::<Value>::new(),
            "output capture alone must not fabricate native byte ownership"
        );
        let page = query("records", &path, &["generator_runs"]);
        assert_eq!(entries(&page).len(), value.generator_runs.len());
        if !value.generator_runs.is_empty() {
            let position = field_path(&path, "generator_runs", 0, "execution_status");
            assert_eq!(
                complete_string(&path, "generator_runs", 0, &position),
                value.generator_runs[0].execution_status
            );
            assert_eq!(
                query("inspect", &path, &["0", "--dataset", "generator_runs"])["data"]["kind"],
                "object"
            );
        }
        data::verify(&path, MEMORY).unwrap();
    }
}

#[test]
fn generator_links_preserve_rule_tier_basis_without_verifying_candidates() {
    for populated in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let mut value = evidence();
        if populated {
            for tier in ["asserted", "recorded", "candidate"] {
                value.generator_links.push(GeneratorLink {
                    generator: "Emitter".into(),
                    output_path: root.path().join(format!("{tier}.g.cs")),
                    trigger_source: Some(root.path().join("Input.cs")),
                    trigger_type: Some("Box".into()),
                    trigger_member: Some("Run".into()),
                    trigger_symbol: Some("App_Box__Run".into()),
                    rule: format!("rule-{tier}"),
                    evidence_tier: tier.into(),
                    basis: if tier == "candidate" {
                        "attribute_directory_name_candidate"
                    } else {
                        "supplied_evidence"
                    }
                    .into(),
                });
            }
        }
        let expected = serde_json::to_value(&value.generator_links).unwrap();
        let path = bundle(root.path(), &value, &[], None);
        assert_eq!(json!(catalog(&path, "generator_links")), expected);
        assert_eq!(
            catalog(&path, "opportunity_coverage")[0]["generator_links"],
            if populated { 3 } else { 0 }
        );
        assert_eq!(catalog(&path, "generator_runs"), Vec::<Value>::new());
        assert_eq!(catalog(&path, "opportunities"), Vec::<Value>::new());
        let page = query(
            "records",
            &path,
            &["generator_links", "--filter", "evidence_tier=candidate"],
        );
        assert_eq!(
            ordinals(&page),
            if populated {
                vec!["2".to_owned()]
            } else {
                vec![]
            }
        );
        if populated {
            for i in 0..3 {
                for field in ["rule", "basis", "evidence_tier", "trigger_symbol"] {
                    let position = field_path(&path, "generator_links", i, field);
                    assert_eq!(
                        complete_string(&path, "generator_links", i, &position),
                        expected[i][field].as_str().unwrap()
                    );
                }
            }
        }
    }
}

#[test]
fn typed_symbol_consumption_joins_stream_and_raw_hash_without_promoting_trust() {
    // Legacy optional-symbol compatibility remains distinct from populated import.
    let root = tempfile::tempdir().unwrap();
    let (value, rows) = seed();
    let index = import(root.path(), &value, &rows);
    let mut manifest = read_json(&index.join("index.json"));
    manifest.as_object_mut().unwrap().remove("symbols");
    write_json(&index.join("index.json"), &manifest);
    assert!(
        vitnet_attribution::open_index(&index, MEMORY)
            .unwrap()
            .symbols
            .is_none()
    );
    let path = root.path().join("bundle");
    prepare(&index, &path, None);
    let page = query("inspect", &path, &["1", "--view", "source"]);
    let position = page["data"]["entries"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["key"] == "status")
        .unwrap()["index"]
        .to_string();
    assert_eq!(
        query(
            "inspect",
            &path,
            &["1", "--view", "source", "--path", &position]
        )["data"]["text"],
        "producer_prefix_candidate"
    );
    let budgets = catalog(&path, "budgets");
    assert_eq!(
        budget(&budgets, "assembly", "", "A", "producer_prefix_candidate")["additive_bytes"],
        13
    );
    expect_error(
        "inspect",
        &path,
        &["1", "--view", "symbol"],
        "explorer.symbols.unavailable",
    );
}

fn typed_candidate(
    entry: &CoalescedIdentity,
    token: u32,
    resolution: vitnet_mstat::SymbolResolution,
) -> Value {
    serde_json::to_value(vitnet_mstat::MstatSymbol {
        stream: entry.stream.clone(),
        raw_identity_blake3: entry.raw_identity_blake3.clone(),
        identity: entry.identity.clone(),
        identity_lossy: entry.identity_lossy,
        token,
        kind: if entry.stream == "Types" {
            vitnet_mstat::SymbolKind::Type
        } else {
            vitnet_mstat::SymbolKind::Method
        },
        resolution_basis: vitnet_mstat::SymbolResolutionBasis::ArtifactLocalEcma335,
        resolution,
    })
    .unwrap()
}

fn resolved(
    assembly: &str,
    declaring_type: &str,
    signature: &str,
) -> vitnet_mstat::SymbolResolution {
    vitnet_mstat::SymbolResolution::Resolved {
        assembly: Some(format!("{assembly}, Version=1.0.0.0, Culture=neutral")),
        declaring_type: declaring_type.into(),
        member_name: Some("Run".into()),
        signature: signature.into(),
    }
}

#[test]
fn typed_source_consumer_validates_both_raw_key_components_and_keeps_name_trust_separate() {
    // Direct source matching supplements the populated import/CLI contracts below.
    let mut value = evidence();
    let mut declaration = source("A", "Box", false);
    declaration.sha256 = Some("cd".repeat(32));
    value.sources.push(declaration.clone());
    let matcher = vitnet_attribution::Matcher::new(&value);
    let first = row("Methods", "same display", 11, true);
    let mut other_raw = first.clone();
    other_raw.raw_identity_blake3 = blake3::hash(b"other raw spelling").to_hex().to_string();
    let mut other_stream = first.clone();
    other_stream.stream = "Types".into();
    for entry in [&first, &other_raw, &other_stream] {
        let candidate = typed_candidate(entry, 0x0600_0001, resolved("A", "Box", "void Run()"));
        let located = matcher.locate_symbols(entry, &[candidate]).unwrap();
        assert_eq!(located.status, "managed_symbol_join");
        assert_eq!(located.assemblies, ["A"]);
        assert_eq!(
            serde_json::to_value(located.sources).unwrap(),
            json!([declaration])
        );
        assert!(located.basis.contains("MSTAT-artifact-local"));
        assert!(
            located
                .basis
                .contains("source/build checksum equality is not established")
        );
    }
    for entry in [&other_raw, &other_stream] {
        let wrong = typed_candidate(entry, 0x0600_0001, resolved("A", "Box", "void Run()"));
        let error = matcher.locate_symbols(&first, &[wrong]).unwrap_err();
        assert_eq!(error.diagnostic.code, "symbols.integrity");
    }
    let mut wrong = typed_candidate(&first, 0x0600_0001, resolved("A", "Box", "void Run()"));
    wrong["resolution"]["status"] = json!("unsupported");
    assert_eq!(
        matcher
            .locate_symbols(&first, &[wrong])
            .unwrap_err()
            .diagnostic
            .code,
        "symbols.schema"
    );
    let mut absent = typed_candidate(&first, 0x0600_0001, resolved("A", "Box", "void Run()"));
    absent["resolution"]["assembly"] = Value::Null;
    let located = matcher.locate_symbols(&first, &[absent]).unwrap();
    assert_eq!(located.status, "unmapped_symbol_candidates");
    assert_eq!(located.assemblies, Vec::<String>::new());
    assert_eq!(serde_json::to_value(located.sources).unwrap(), json!([]));
    assert!(located.basis.contains("incomplete/unsupported"));
    assert!(located.basis.contains("not verified typed ownership"));
    for field in ["declaring_type", "signature"] {
        let mut invalid = typed_candidate(&first, 0x0600_0001, resolved("A", "Box", "void Run()"));
        invalid["resolution"]
            .as_object_mut()
            .unwrap()
            .remove(field)
            .unwrap();
        assert_eq!(
            matcher
                .locate_symbols(&first, &[invalid])
                .unwrap_err()
                .diagnostic
                .code,
            "symbols.schema",
            "missing {field}"
        );
    }
}

#[test]
fn typed_source_consumer_retains_conflicts_unresolved_forms_and_explicit_precedence() {
    let mut value = evidence();
    value.sources = vec![source("A", "Box", false), source("B", "Node", false)];
    let entry = row("Methods", "opaque typed producer", 17, true);
    let a = typed_candidate(&entry, 0x0600_0001, resolved("A", "Box", "void Run()"));
    let b = typed_candidate(&entry, 0x0600_0002, resolved("B", "Node", "int Run(int)"));
    let signature_conflict =
        typed_candidate(&entry, 0x0600_0003, resolved("A", "Box", "int Run(int)"));
    let unresolved = typed_candidate(
        &entry,
        0x0a00_0001,
        vitnet_mstat::SymbolResolution::Unresolved {
            reason: "artifact-local unsupported form".into(),
        },
    );
    let matcher = vitnet_attribution::Matcher::new(&value);
    let conflict = matcher
        .locate_symbols(&entry, &[a.clone(), b.clone()])
        .unwrap();
    assert_eq!(conflict.status, "managed_symbol_ambiguous");
    assert_eq!(conflict.assemblies, ["A", "B"]);
    assert_eq!(conflict.sources.len(), 2);
    let conflict = matcher
        .locate_symbols(&entry, &[a.clone(), signature_conflict])
        .unwrap();
    assert_eq!(conflict.status, "managed_symbol_ambiguous");
    assert_eq!(conflict.assemblies, ["A"]);
    assert_eq!(conflict.sources.len(), 1);
    for candidates in [vec![unresolved.clone()], vec![a, unresolved]] {
        let located = matcher.locate_symbols(&entry, &candidates).unwrap();
        assert_eq!(located.status, "unmapped_symbol_candidates");
        assert_eq!(located.assemblies, Vec::<String>::new());
        assert_eq!(serde_json::to_value(located.sources).unwrap(), json!([]));
        assert!(located.basis.contains("incomplete/unsupported"));
        assert!(located.basis.contains("not verified typed ownership"));
    }
    value.mappings.push(mapping(
        "Methods",
        &entry.identity,
        "A",
        "supplied_assertion",
    ));
    let matcher = vitnet_attribution::Matcher::new(&value);
    let assertion = matcher.locate_symbols(&entry, &[b]).unwrap();
    assert_eq!(assertion.status, "asserted");
    assert_eq!(assertion.basis, "supplied_assertion");
    assert_eq!(assertion.assemblies, ["A"]);
    let spelling = row("Methods", "A_Box<int>__Run", 23, true);
    let typed_b = typed_candidate(
        &spelling,
        0x0600_0002,
        resolved("B", "Node", "int Run(int)"),
    );
    let incomplete = typed_candidate(
        &spelling,
        0x0a00_0001,
        vitnet_mstat::SymbolResolution::Unresolved {
            reason: "unsupported artifact-local form".into(),
        },
    );
    let located = matcher
        .locate_symbols(&spelling, &[typed_b, incomplete])
        .unwrap();
    assert_eq!(located.status, "ambiguous");
    assert_eq!(located.assemblies, ["A", "B"]);
    assert_eq!(
        serde_json::to_value(&located.sources).unwrap(),
        json!([value.sources[0]])
    );
    assert!(located.basis.contains("incomplete/unsupported"));
    assert!(located.basis.contains("not verified typed ownership"));
}

#[test]
fn prepared_capability_requires_two_distinct_positive_additive_assemblies() {
    for case in [
        "zero",
        "one",
        "specialized-peer",
        "zero-size-peer",
        "same-assembly",
        "two",
    ] {
        let root = tempfile::tempdir().unwrap();
        let mut value = evidence();
        value.assemblies = vec![
            Assembly {
                name: "A".into(),
                ..Assembly::default()
            },
            Assembly {
                name: "B".into(),
                ..Assembly::default()
            },
        ];
        let mut rows = Vec::new();
        if case != "zero" {
            rows.push(row("Methods", "A_One", 11, true));
        }
        match case {
            "specialized-peer" => rows.push(row("FrozenObjects", "B_One", 31, false)),
            "zero-size-peer" => rows.push(row("Types", "B_One", 0, true)),
            "same-assembly" => rows.push(row("Methods", "A_Two", 17, true)),
            "two" => rows.push(row("Types", "B_One", 17, true)),
            _ => {}
        }
        for entry in &rows {
            value.mappings.push(mapping(
                &entry.stream,
                &entry.identity,
                if entry.identity.starts_with("A_") {
                    "A"
                } else {
                    "B"
                },
                "explicit",
            ));
        }
        let policy = json!({"schema":"vitnet.opportunity-policy.v1","capabilities":[{"id":"both","title":"Both","assemblies":["A","B"],"investigation":"Check semantics"}]});
        let path = bundle(root.path(), &value, &rows, Some(&policy));
        let findings = catalog(&path, "opportunities");
        if case == "two" {
            assert_eq!(findings.len(), 1);
            let finding = finding(&findings, "both");
            assert_eq!(finding["additive_bytes"], 28);
            assert_eq!(finding["overlapping_bytes"], 0);
            assert_eq!(finding["identities"], 2);
            assert_eq!(finding["streams"], json!({"Methods":11,"Types":17}));
            assert_eq!(finding["assemblies"], json!(["A", "B"]));
            assert_eq!(finding["proposed_savings_bytes"], Value::Null);
        } else {
            assert_eq!(
                findings,
                Vec::<Value>::new(),
                "{case} must not manufacture coexistence: {findings:?}"
            );
        }
        assert_eq!(
            catalog(&path, "opportunity_coverage")[0]["accounted_bytes"],
            match case {
                "zero" => 0,
                "same-assembly" | "two" => 28,
                _ => 11,
            }
        );
        assert_eq!(
            entries(&query(
                "opportunities",
                &path,
                &["--kind", "capability_overlap"]
            ))
            .len(),
            usize::from(case == "two")
        );
    }
}

#[test]
fn prepared_families_separate_streams_singletons_lossy_and_specialized_rows() {
    let root = tempfile::tempdir().unwrap();
    let mut lossy = row("Methods", "Box<�>__Run", 23, true);
    lossy.identity_lossy = true;
    let rows = [
        row("Methods", "Box<__Canon>__Run", 11, true),
        row("Methods", "Box<int>__Run", 13, true),
        row("Types", "Box<int>__Run", 17, true),
        row("FrozenObjects", "Box<__Canon>__Run", 19, false),
        lossy,
    ];
    let path = bundle(root.path(), &evidence(), &rows, None);
    let findings = catalog(&path, "opportunities");
    assert_eq!(findings.len(), 1);
    let family = finding(&findings, "family:Methods:Box<>__Run");
    assert_eq!(family["additive_bytes"], 24);
    assert_eq!(family["overlapping_bytes"], 0);
    assert_eq!(family["identities"], 2);
    assert_eq!(family["canonical_shared_identities"], 1);
    assert_eq!(family["streams"], json!({"Methods":24}));
    assert_eq!(
        family["examples"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v["ordinal"].as_u64().unwrap())
            .collect::<Vec<_>>(),
        [1, 0]
    );
    assert_eq!(
        catalog(&path, "opportunity_coverage")[0]["accounted_bytes"],
        64
    );
    assert_eq!(
        catalog(&path, "opportunity_coverage")[0]["streams"],
        json!({"Methods":47,"Types":17})
    );
    let budgets = catalog(&path, "budgets");
    assert_eq!(
        budget(&budgets, "assembly", "", "_unmapped", "unmapped")["overlapping_bytes"],
        19
    );
    assert_eq!(
        budget(
            &budgets,
            "assembly",
            "",
            "_unmapped",
            "unmapped_lossy_identity"
        )["additive_bytes"],
        23
    );
    assert_eq!(
        ordinals(&query(
            "opportunities",
            &path,
            &["--kind", "generic_family"]
        )),
        ["0"]
    );
}

struct ImportedSymbolBundle {
    index: PathBuf,
    bundle: PathBuf,
    entries: Vec<CoalescedIdentity>,
}

fn import_symbol_image(
    root: &Path,
    declarations: &Evidence,
    image: common::Image,
) -> ImportedSymbolBundle {
    import_symbol_bytes(root, declarations, &image.bytes())
}

fn import_symbol_bytes(root: &Path, declarations: &Evidence, bytes: &[u8]) -> ImportedSymbolBundle {
    let input = root.join("captured.mstat");
    fs::write(&input, bytes).unwrap();
    let mut value = declarations.clone();
    value.artifacts.push(Artifact {
        kind: "mstat".into(),
        path: input,
        revision: None,
        blake3: Some(blake3::hash(bytes).to_hex().to_string()),
    });
    let manifest_path = root.join("captured.json");
    write_json(&manifest_path, &value);
    let index = root.join("imported");
    let manifest = vitnet_attribution::import(&manifest_path, &index, MEMORY, false).unwrap();
    assert!(manifest.symbols.is_some());
    let entries: Vec<CoalescedIdentity> = fs::read(index.join("identities.ndjson"))
        .unwrap()
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .map(|line| serde_json::from_slice(line).unwrap())
        .collect();
    assert_eq!(manifest.identities, u64::try_from(entries.len()).unwrap());
    let before = contents(&index);
    let bundle = root.join("prepared");
    prepare(&index, &bundle, None);
    assert_eq!(contents(&index), before);
    data::verify(&bundle, MEMORY).unwrap();
    ImportedSymbolBundle {
        index,
        bundle,
        entries,
    }
}

fn view_field_path(path: &Path, ordinal: usize, view: &str, parent: &str, field: &str) -> String {
    let page = query(
        "inspect",
        path,
        &[&ordinal.to_string(), "--view", view, "--path", parent],
    );
    let position = page["data"]["entries"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["key"] == field)
        .unwrap()["index"]
        .as_u64()
        .unwrap();
    if parent.is_empty() {
        position.to_string()
    } else {
        format!("{parent},{position}")
    }
}

#[test]
fn imported_symbol_navigation_preserves_original_ordinals_and_raw_key_distinctions() {
    let root = tempfile::tempdir().unwrap();
    let mut declarations = evidence();
    declarations.sources.push(source("A", "Box", false));
    let mut image = common::Image::new();
    image.method(b"opaque", 11);
    image.method(b"A_Box<int>__Run", 13);
    image.blob(&"A_Box<int>__Run".encode_utf16().collect::<Vec<_>>(), 23);
    let captured = import_symbol_image(root.path(), &declarations, image);
    assert_eq!(captured.entries.len(), 3);
    let original = contents(&captured.index);
    let manifest = vitnet_attribution::open_index(&captured.index, MEMORY).unwrap();
    let descriptor = manifest.symbols.as_ref().unwrap();
    assert_eq!(descriptor.records, 2);
    let mut symbols =
        vitnet_attribution::SymbolLookup::open(&captured.index, descriptor, MEMORY).unwrap();
    let matcher = vitnet_attribution::Matcher::new(&manifest.evidence);
    for (ordinal, entry) in captured.entries.iter().enumerate() {
        let candidates = symbols
            .get(&entry.stream, &entry.raw_identity_blake3)
            .unwrap();
        let expected_count = usize::from(entry.stream == "Methods");
        let page = query(
            "inspect",
            &captured.bundle,
            &[&ordinal.to_string(), "--view", "symbol"],
        );
        assert_eq!(page["data"]["kind"], "array");
        assert_eq!(page["data"]["total"], expected_count);
        assert_eq!(page["data"]["next_start"], Value::Null);
        assert_eq!(page["next_command"], Value::Null);
        assert_eq!(
            original_view_value(&captured.bundle, "identities", ordinal, "symbol", &[]),
            json!(candidates)
        );
        if expected_count == 1 {
            let candidate = &candidates[0];
            assert_eq!(candidate["identity"], entry.identity);
            assert_eq!(candidate["stream"], "Methods");
            assert_eq!(candidate["raw_identity_blake3"], entry.raw_identity_blake3);
            assert_eq!(candidate["identity_lossy"], false);
            assert_eq!(candidate["token"], 0x0a00_0001_u32);
            assert_eq!(candidate["kind"], "method");
            assert_eq!(candidate["resolution_basis"], "artifact_local_ecma335");
            assert_eq!(candidate["resolution"]["status"], "unresolved");
        }
        let located = matcher.locate_entry(entry, Some(&mut symbols)).unwrap();
        assert_eq!(
            original_view_value(&captured.bundle, "identities", ordinal, "source", &[]),
            serde_json::to_value(&located).unwrap()
        );
        if entry.identity == "opaque" {
            assert_eq!(located.status, "unmapped_symbol_candidates");
            assert_eq!(located.assemblies, Vec::<String>::new());
        } else {
            assert_eq!(located.status, "producer_prefix_candidate");
            assert_eq!(located.assemblies, ["A"]);
        }
    }
    let same_label: Vec<_> = captured
        .entries
        .iter()
        .filter(|entry| entry.identity == "A_Box<int>__Run")
        .collect();
    assert_eq!(same_label.len(), 2);
    assert_ne!(same_label[0].stream, same_label[1].stream);
    assert_ne!(
        same_label[0].raw_identity_blake3,
        same_label[1].raw_identity_blake3
    );
    assert_eq!(
        catalog(&captured.bundle, "opportunity_coverage")[0]["accounted_bytes"],
        47
    );
    let budgets = catalog(&captured.bundle, "budgets");
    assert_eq!(
        budget(&budgets, "assembly", "", "A", "producer_prefix_candidate")["additive_bytes"],
        36
    );
    assert_eq!(
        budget(
            &budgets,
            "assembly",
            "",
            "_unmapped",
            "unmapped_symbol_candidates"
        )["additive_bytes"],
        11
    );
    symbols.check().unwrap();
    assert_eq!(contents(&captured.index), original);
}

#[test]
fn imported_symbol_candidates_page_deduplicated_lookup_not_payload_rows() {
    let root = tempfile::tempdir().unwrap();
    let mut image = common::Image::new();
    for bytes in [11, 13, 17] {
        image.method(b"opaque repeated", bytes);
    }
    let captured = import_symbol_image(root.path(), &evidence(), image);
    assert_eq!(captured.entries.len(), 1);
    assert_eq!(captured.entries[0].records, 3);
    assert_eq!(captured.entries[0].bytes, 41);
    assert_eq!(
        catalog(&captured.bundle, "opportunity_coverage")[0]["accounted_bytes"],
        41
    );
    let manifest = vitnet_attribution::open_index(&captured.index, MEMORY).unwrap();
    assert_eq!(manifest.symbols.as_ref().unwrap().records, 1);
    let payload = fs::read(captured.index.join("symbols.ndjson")).unwrap();
    assert_eq!(
        payload
            .split(|byte| *byte == b'\n')
            .filter(|line| !line.is_empty())
            .count(),
        3
    );
    let page = query("inspect", &captured.bundle, &["0", "--view", "symbol"]);
    assert_eq!(page["data"]["total"], 1);
    assert_eq!(page["data"]["entries"].as_array().unwrap().len(), 1);
    assert_eq!(page["data"]["entries"][0]["index"], 0);
    assert_eq!(page["next_command"], Value::Null);
    let end = query(
        "inspect",
        &captured.bundle,
        &["0", "--view", "symbol", "--start", "1"],
    );
    assert_eq!(
        end["data"]["entries"].as_array().unwrap(),
        &Vec::<Value>::new()
    );
    assert_eq!(end["next_command"], Value::Null);
    for extra in [
        vec!["0", "--view", "symbol", "--start", "2"],
        vec!["0", "--view", "symbol", "--path", "1"],
        vec!["0", "--view", "symbol", "--key"],
        vec!["0", "--view", "symbol", "--path", "0", "--key"],
    ] {
        expect_error("inspect", &captured.bundle, &extra, "explorer.cursor");
    }
    expect_error(
        "inspect",
        &captured.bundle,
        &["1", "--view", "symbol"],
        "explorer.row",
    );
    expect_error(
        "inspect",
        &captured.bundle,
        &["0", "--dataset", "budgets", "--view", "symbol"],
        "explorer.query",
    );
}

fn assert_symbol_continuation(
    command: &str,
    path: &Path,
    ordinal: usize,
    positional: &str,
    start: u64,
) -> Vec<String> {
    let arguments = resume_argv(command);
    let generation = read_json(&path.join("bundle.json"))["generation"]
        .as_str()
        .unwrap()
        .to_owned();
    for pair in [
        ["--view", "symbol"],
        ["--dataset", "identities"],
        ["--path", positional],
        ["--generation", &generation],
        ["--format", "json"],
        ["--memory-limit", "134217728B"],
        ["--start", &start.to_string()],
    ] {
        assert!(
            arguments.windows(2).any(|window| window == pair),
            "{arguments:?}"
        );
    }
    let command_position = arguments
        .iter()
        .position(|argument| argument == "inspect")
        .unwrap();
    assert_eq!(arguments[command_position + 1], path.to_str().unwrap());
    assert_eq!(arguments[command_position + 2], ordinal.to_string());
    arguments
}

#[test]
fn imported_symbol_long_values_replay_generation_bound_continuations_and_keys() {
    let root = tempfile::tempdir().unwrap();
    let identity = format!("{}é{}SYMBOL-END", "a".repeat(4095), "🦀".repeat(1300));
    let mut image = common::Image::new();
    image.method(identity.as_bytes(), 37);
    let captured = import_symbol_image(root.path(), &evidence(), image);
    assert_eq!(captured.entries.len(), 1);
    let positional = view_field_path(&captured.bundle, 0, "symbol", "0", "identity");
    let mut page = query(
        "inspect",
        &captured.bundle,
        &["0", "--view", "symbol", "--path", &positional],
    );
    assert_eq!(page["data"]["kind"], "string");
    assert_eq!(page["data"]["text"], "a".repeat(4095));
    assert_eq!(page["data"]["total_bytes"], identity.len());
    assert_eq!(page["data"]["next_start"], 4095);
    let first_command = page["next_command"].as_str().unwrap().to_owned();
    let mut recovered = page["data"]["text"].as_str().unwrap().to_owned();
    let mut starts = vec![0];
    while let Some(command) = page["next_command"].as_str() {
        let start = page["data"]["next_start"].as_u64().unwrap();
        let arguments =
            assert_symbol_continuation(command, &captured.bundle, 0, &positional, start);
        assert!(!arguments.iter().any(|argument| argument == "--key"));
        page = serde_json::from_str(&execute(&Cli::try_parse_from(arguments).unwrap()).unwrap())
            .unwrap();
        assert_eq!(page["data"]["start"], start);
        let chunk = page["data"]["text"].as_str().unwrap();
        assert!(chunk.len() <= 4096);
        recovered.push_str(chunk);
        starts.push(start);
    }
    assert_eq!(starts, [0, 4095, 8189]);
    assert_eq!(recovered, identity);
    assert_eq!(page["data"]["next_start"], Value::Null);
    let key = query(
        "inspect",
        &captured.bundle,
        &["0", "--view", "symbol", "--path", &positional, "--key"],
    );
    assert_eq!(key["data"]["text"], "identity");
    assert_eq!(key["data"]["total_bytes"], 8);
    assert_eq!(key["next_command"], Value::Null);
    for start in ["4096", &(identity.len() + 1).to_string()] {
        expect_error(
            "inspect",
            &captured.bundle,
            &[
                "0",
                "--view",
                "symbol",
                "--path",
                &positional,
                "--start",
                start,
            ],
            "explorer.cursor",
        );
    }
    let end = query(
        "inspect",
        &captured.bundle,
        &[
            "0",
            "--view",
            "symbol",
            "--path",
            &positional,
            "--start",
            &identity.len().to_string(),
        ],
    );
    assert_eq!(end["data"]["text"], "");
    assert_eq!(end["next_command"], Value::Null);
    assert_stale_symbol_continuation(&first_command, &captured.bundle);
}

fn assert_stale_symbol_continuation(command: &str, source_bundle: &Path) {
    let mut arguments = resume_argv(command);
    let generation = arguments
        .iter()
        .position(|argument| argument == "--generation")
        .unwrap()
        + 1;
    arguments[generation] = "wrong".into();
    assert_error(
        execute(&Cli::try_parse_from(arguments).unwrap()),
        "explorer.generation",
        false,
    );
    let other_root = tempfile::tempdir().unwrap();
    let mut image = common::Image::new();
    image.method(b"different capture", 1);
    let other = import_symbol_image(other_root.path(), &evidence(), image);
    let mut arguments = resume_argv(command);
    let position = arguments
        .iter()
        .position(|argument| argument == source_bundle.to_str().unwrap())
        .unwrap();
    arguments[position] = other.bundle.to_str().unwrap().into();
    assert_error(
        execute(&Cli::try_parse_from(arguments).unwrap()),
        "explorer.generation",
        false,
    );
}

#[test]
fn typed_source_full_assembly_versions_and_owner_components_retain_conflicts() {
    let mut value = evidence();
    value.sources = vec![source("A", "Box", false), source("A", "Node", false)];
    let entry = row("Methods", "opaque", 11, true);
    let first = typed_candidate(&entry, 0x0600_0001, resolved("A", "Box", "void Run()"));
    for (field, replacement, expected_sources) in [
        ("assembly", json!("A, Version=2.0.0.0, Culture=neutral"), 1),
        ("declaring_type", json!("Node"), 2),
        ("member_name", json!("Other"), 1),
        ("signature", json!("int Run(int)"), 1),
    ] {
        let mut second = first.clone();
        second["token"] = json!(0x0600_0002_u32);
        second["resolution"][field] = replacement;
        let located = vitnet_attribution::Matcher::new(&value)
            .locate_symbols(&entry, &[first.clone(), second])
            .unwrap();
        assert_eq!(located.status, "managed_symbol_ambiguous", "{field}");
        assert_eq!(located.assemblies, ["A"], "{field}");
        assert_eq!(located.sources.len(), expected_sources, "{field}");
        assert_eq!(
            serde_json::to_value(&located.sources[0]).unwrap(),
            json!(value.sources[0])
        );
        if expected_sources == 2 {
            assert_eq!(
                serde_json::to_value(&located.sources[1]).unwrap(),
                json!(value.sources[1])
            );
        }
        assert!(
            located
                .basis
                .contains("source/build checksum equality is not established")
        );
    }
}

#[test]
fn typed_source_generic_normalization_preserves_independent_member_candidates() {
    let mut value = evidence();
    let mut declaration = source("A", "global::Ns.Type<T>", false);
    declaration.member = None;
    let mut method = source("A", "Ns.Type`1", false);
    method.member = Some("Run(int)".into());
    let mut overload = method.clone();
    overload.member = Some("Run(string)".into());
    overload.path = PathBuf::from("overload.cs");
    let mut other = method.clone();
    other.member = Some("Other()".into());
    let mut unrelated = method.clone();
    unrelated.type_name = "Ns.Other<T>".into();
    value.sources = vec![declaration, method, overload, other, unrelated];
    let entry = row("Methods", "opaque", 17, true);
    for declaring in ["Ns.Type`1", "Ns.Type<int>", "global::Ns.Type<string>"] {
        let candidate = typed_candidate(
            &entry,
            0x0600_0001,
            resolved("A", declaring, "void Run(int)"),
        );
        let located = vitnet_attribution::Matcher::new(&value)
            .locate_symbols(&entry, &[candidate])
            .unwrap();
        assert_eq!(located.status, "managed_symbol_join");
        assert_eq!(located.assemblies, ["A"]);
        assert_eq!(
            serde_json::to_value(located.sources).unwrap(),
            json!(value.sources[..3])
        );
        assert!(
            located
                .basis
                .contains("independently captured name candidates")
        );
    }
    let mut candidate = typed_candidate(
        &entry,
        0x0200_0001,
        resolved("A", "Ns.Type`1", "class Ns.Type`1"),
    );
    candidate["resolution"]["member_name"] = Value::Null;
    let located = vitnet_attribution::Matcher::new(&value)
        .locate_symbols(&entry, &[candidate])
        .unwrap();
    assert_eq!(located.status, "managed_symbol_join");
    assert_eq!(
        serde_json::to_value(located.sources).unwrap(),
        json!([value.sources[0]])
    );
    for field in ["declaring_type", "signature"] {
        let mut candidate = typed_candidate(
            &entry,
            0x0600_0001,
            resolved("A", "Ns.Type`1", "void Run(int)"),
        );
        candidate["resolution"][field] = Value::Null;
        let error = vitnet_attribution::Matcher::new(&value)
            .locate_symbols(&entry, &[candidate])
            .unwrap_err();
        assert_eq!(error.diagnostic.code, "symbols.schema", "{field}");
    }
}

#[test]
fn incomplete_symbol_candidates_keep_truthful_spelling_fallback_and_owner_union() {
    let mut value = evidence();
    value.sources = vec![
        source("A", "Box", false),
        source("B", "Node", false),
        source("C", "Node", false),
    ];
    let entry = row("Methods", "A_Box<int>__Run", 23, true);
    let unresolved = typed_candidate(
        &entry,
        0x0a00_0001,
        vitnet_mstat::SymbolResolution::Unresolved {
            reason: "unsupported ModuleRef owner".into(),
        },
    );
    let b = typed_candidate(&entry, 0x0600_0002, resolved("B", "Node", "void Run()"));
    let c = typed_candidate(&entry, 0x0600_0003, resolved("C", "Node", "void Run()"));
    for (candidates, status, owners) in [
        (
            vec![unresolved.clone()],
            "producer_prefix_candidate",
            vec!["A"],
        ),
        (vec![b, c, unresolved], "ambiguous", vec!["A", "B", "C"]),
    ] {
        let located = vitnet_attribution::Matcher::new(&value)
            .locate_symbols(&entry, &candidates)
            .unwrap();
        assert_eq!(located.status, status);
        assert_eq!(located.assemblies, owners);
        assert_eq!(
            serde_json::to_value(located.sources).unwrap(),
            json!([value.sources[0]])
        );
        assert!(located.basis.contains("incomplete/unsupported"));
        assert!(located.basis.contains(
            "Remaining spelling associations are candidates, not verified typed ownership"
        ));
    }
}

#[test]
fn imported_symbol_distinct_tokens_keep_original_candidate_indices() {
    let root = tempfile::tempdir().unwrap();
    let mut declarations = evidence();
    declarations.sources.push(source("A", "Box", false));
    let mut image = common::Image::new();
    for bytes in [11, 13, 17] {
        image.method(b"A_Box<int>__Run", bytes);
    }

    let mut bytes = image.bytes();
    // This fixed common Image layout has its TypeDef Name index at byte 798:
    // metadata 640 + table stream 92 + header/counts 52 + Module 10 + Flags 4.
    // Give that data-only type the existing #Strings name "Methods" (index 1),
    // so a MethodDef owner can be resolved instead of rejecting its empty name.
    assert_eq!(&bytes[798..800], &[0, 0]);
    bytes[798..800].copy_from_slice(&1_u16.to_le_bytes());
    // Fixture-only edit: the third ldtoken refers to an existing valid MethodDef;
    // the first two keep the explicit unsupported ModuleRef-owned MemberRef.
    let positions: Vec<_> = bytes
        .windows(6)
        .enumerate()
        .filter_map(|(position, record)| {
            (record == [0xd0, 1, 0, 0, 0x0a, 0x20]).then_some(position)
        })
        .collect();
    assert_eq!(positions.len(), 3);
    let position = positions[2] + 1;
    bytes[position..position + 4].copy_from_slice(&0x0600_0001_u32.to_le_bytes());
    let captured = import_symbol_bytes(root.path(), &declarations, &bytes);
    assert_eq!(captured.entries.len(), 1);
    assert_eq!(captured.entries[0].records, 3);
    assert_eq!(captured.entries[0].bytes, 41);
    let page = query("inspect", &captured.bundle, &["0", "--view", "symbol"]);
    assert_eq!(page["data"]["total"], 2);
    assert_eq!(
        page["data"]["entries"]
            .as_array()
            .unwrap()
            .iter()
            .map(|entry| entry["index"].as_u64().unwrap())
            .collect::<Vec<_>>(),
        [0, 1]
    );
    let tail = query(
        "inspect",
        &captured.bundle,
        &["0", "--view", "symbol", "--start", "1"],
    );
    assert_eq!(tail["data"]["total"], 2);
    assert_eq!(tail["data"]["start"], 1);
    assert_eq!(tail["data"]["entries"].as_array().unwrap().len(), 1);
    assert_eq!(tail["data"]["entries"][0]["index"], 1);
    assert_eq!(tail["next_command"], Value::Null);
    let candidates = original_view_value(&captured.bundle, "identities", 0, "symbol", &[]);
    assert_eq!(candidates[0]["token"], 0x0a00_0001_u32);
    assert_eq!(candidates[0]["resolution"]["status"], "unresolved");
    assert_eq!(candidates[1]["token"], 0x0600_0001_u32);
    assert_eq!(candidates[1]["resolution"]["status"], "resolved");
    assert_eq!(
        original_view_value(&captured.bundle, "identities", 0, "symbol", &[1]),
        candidates[1]
    );
    let end = query(
        "inspect",
        &captured.bundle,
        &["0", "--view", "symbol", "--start", "2"],
    );
    assert_eq!(
        end["data"]["entries"].as_array().unwrap(),
        &Vec::<Value>::new()
    );
    assert_eq!(end["next_command"], Value::Null);
    expect_error(
        "inspect",
        &captured.bundle,
        &["0", "--view", "symbol", "--start", "3"],
        "explorer.cursor",
    );
    let source = original_view_value(&captured.bundle, "identities", 0, "source", &[]);
    assert_eq!(source["status"], "ambiguous");
    assert_eq!(source["assemblies"], json!(["A", "synthetic.mstat"]));
    assert_eq!(source["sources"].as_array().unwrap().len(), 1);
    assert_eq!(source["sources"][0]["type_name"], "Box");
    assert!(
        source["basis"]
            .as_str()
            .unwrap()
            .contains("not verified typed ownership")
    );
}

#[test]
fn relative_generator_capture_paths_survive_import_and_original_catalog_inspection() {
    let root = tempfile::tempdir().unwrap();
    fs::write(
        root.path().join("Output.g.cs"),
        b"synthetic captured output",
    )
    .unwrap();
    fs::write(root.path().join("Input.cs"), b"synthetic captured trigger").unwrap();
    fs::write(
        root.path().join("App.pdb"),
        b"synthetic captured checksum evidence",
    )
    .unwrap();
    let mut input = evidence();
    input.generator_runs.push(GeneratorRun {
        name: "Emitter".into(),
        status: "captured".into(),
        basis: "recorded output".into(),
        execution_status: "unknown".into(),
        outputs: vec![GeneratorOutput {
            path: PathBuf::from("Output.g.cs"),
            build_match: "candidate".into(),
            pdb_checksums: vec![GeneratorChecksum {
                pdb_path: PathBuf::from("App.pdb"),
                algorithm: "SHA256".into(),
                checksum: "ab".repeat(32),
                status: "captured".into(),
                assembly_match: "unknown".into(),
                ..GeneratorChecksum::default()
            }],
            ..GeneratorOutput::default()
        }],
        ..GeneratorRun::default()
    });
    input.generator_links.push(GeneratorLink {
        generator: "Emitter".into(),
        output_path: PathBuf::from("Output.g.cs"),
        trigger_source: Some(PathBuf::from("Input.cs")),
        rule: "literal captured trigger".into(),
        evidence_tier: "candidate".into(),
        basis: "supplied capture".into(),
        ..GeneratorLink::default()
    });
    let path = bundle(root.path(), &input, &[], None);
    let runs = catalog(&path, "generator_runs");
    let links = catalog(&path, "generator_links");
    assert_eq!(
        runs[0]["outputs"][0]["path"],
        json!(root.path().join("Output.g.cs"))
    );
    assert_eq!(
        runs[0]["outputs"][0]["pdb_checksums"][0]["pdb_path"],
        json!(root.path().join("App.pdb"))
    );
    assert_eq!(
        links[0]["output_path"],
        json!(root.path().join("Output.g.cs"))
    );
    assert_eq!(
        links[0]["trigger_source"],
        json!(root.path().join("Input.cs"))
    );
    assert_eq!(original_value(&path, "generator_runs", 0, &[]), runs[0]);
    assert_eq!(original_value(&path, "generator_links", 0, &[]), links[0]);
    let coverage = catalog(&path, "opportunity_coverage");
    assert_eq!(coverage[0]["generator_outputs_captured"], 1);
    assert_eq!(coverage[0]["generator_execution_observed"], 0);
    assert_eq!(coverage[0]["accounted_bytes"], 0);
    assert_eq!(catalog(&path, "opportunities"), Vec::<Value>::new());
}

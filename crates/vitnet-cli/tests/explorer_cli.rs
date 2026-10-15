//! CLI investigation regressions: disposable synthetic bundles, no network/corpus.
use clap::Parser;
use serde_json::{Value, json};
use std::fs;
use std::path::{Path, PathBuf};
use vitnet_attribution::model::{
    Artifact, Assembly, Binary, EVIDENCE_SCHEMA, Evidence, Generator, Mapping, Package, Resource,
    Source,
};
use vitnet_cli::explorer::{ExploreCommand, data};
use vitnet_cli::{AppError, Cli, Command, execute, execute_with_index_control};
use vitnet_dgml::IndexControl;
use vitnet_mstat::CoalescedIdentity;

#[allow(dead_code)]
#[path = "../../vitnet-attribution/tests/common/mod.rs"]
mod common;

const MEMORY: u64 = 128 << 20;
const ORDER: [(u64, u64); 7] = [
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
        label: "Independent CLI fixture".into(),
        ..Evidence::default()
    }
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
    [10, 90, 90, 120, 0, 1000, 45]
        .into_iter()
        .enumerate()
        .map(|(i, bytes)| {
            row(
                match i {
                    5 => "Blobs",
                    6 => "Types",
                    _ => "Methods",
                },
                &format!("Opaque__Row{i}"),
                bytes,
                i != 5,
            )
        })
        .collect()
}

fn write_json(path: &Path, value: &impl serde::Serialize) {
    fs::write(path, serde_json::to_vec(value).unwrap()).unwrap();
}

fn read_json(path: &Path) -> Value {
    serde_json::from_slice(&fs::read(path).unwrap()).unwrap()
}

fn import(root: &Path, value: &Evidence, rows: Option<&[CoalescedIdentity]>) -> PathBuf {
    let input = root.join("evidence.json");
    write_json(&input, value);
    let index = root.join("index");
    vitnet_attribution::import(&input, &index, MEMORY, false).unwrap();
    if let Some(rows) = rows {
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
    index
}

fn bundle(root: &Path, value: &Evidence, rows: Option<&[CoalescedIdentity]>) -> PathBuf {
    let index = import(root, value, rows);
    let output = root.join("bundle");
    data::prepare(
        &index,
        &output,
        &[],
        None,
        &[],
        "scan_index",
        MEMORY,
        &IndexControl::default(),
    )
    .unwrap();
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

fn output(format: &str, command: &str, path: &Path, extra: &[&str]) -> String {
    execute(&cli(format, command, path, extra)).unwrap()
}

fn query(command: &str, path: &Path, extra: &[&str]) -> Value {
    let value: Value = serde_json::from_str(&output("json", command, path, extra)).unwrap();
    assert_eq!(value["schema"], "vitnet.explorer-cli.v1");
    assert_eq!(value["operation"], command);
    assert_eq!(
        value["generation"],
        read_json(&path.join("bundle.json"))["generation"]
    );
    value
}

fn entries(value: &Value) -> &[Value] {
    value["data"]["entries"].as_array().unwrap()
}

fn ordinals(value: &Value) -> Vec<u64> {
    entries(value)
        .iter()
        .map(|v| match &v["ordinal"] {
            Value::String(v) => v.parse().unwrap(),
            v => v.as_u64().unwrap(),
        })
        .collect()
}

fn pairs(value: &Value) -> Vec<(u64, u64)> {
    entries(value)
        .iter()
        .map(|v| (v["bytes"].as_u64().unwrap(), v["ordinal"].as_u64().unwrap()))
        .collect()
}

fn error_code(error: &AppError) -> &str {
    match error {
        AppError::Unsupported(v) | AppError::Resource(v) | AppError::IoDiagnostic(v) => &v.code,
        AppError::Dgml(v) => &v.diagnostic.code,
        other => panic!("unexpected diagnostic: {other}"),
    }
}

fn expect_error(command: &str, path: &Path, extra: &[&str], code: &str) {
    let error = execute(&cli("json", command, path, extra)).unwrap_err();
    assert_eq!(error_code(&error), code, "{error}");
}

fn parser_error(command: &str, extra: &[&str], flag: &str) {
    let mut args = vec!["vitnet", "explore", command, "unused"];
    args.extend_from_slice(extra);
    let error = Cli::try_parse_from(args).unwrap_err();
    assert!(
        matches!(
            error.kind(),
            clap::error::ErrorKind::ValueValidation
                | clap::error::ErrorKind::InvalidValue
                | clap::error::ErrorKind::UnknownArgument
        ),
        "{error}"
    );
    assert!(
        error
            .to_string()
            .to_lowercase()
            .contains(&flag.to_lowercase()),
        "{error}"
    );
}

#[test]
fn pagination_defaults_and_unsigned_budget_validation() {
    for (command, extra) in [
        ("contributors", vec![]),
        ("records", vec!["packages"]),
        ("origins", vec![]),
    ] {
        let parsed = cli("json", command, Path::new("unused"), &extra);
        let Command::Explore(args) = parsed.command else {
            panic!("wrong command")
        };
        let page = match args.command {
            ExploreCommand::Contributors(args) => {
                assert_eq!(args.contains, "");
                args.page
            }
            ExploreCommand::Records(args) => {
                assert_eq!(args.contains, "");
                assert_eq!(args.filters, [] as [(String, String); 0]);
                args.page
            }
            ExploreCommand::Origins(args) => args.page,
            _ => panic!("wrong page command"),
        };
        assert_eq!(
            (
                page.limit,
                page.max_batches,
                page.timeout_ms,
                page.after,
                page.generation
            ),
            (50, 20, 30_000, None, None)
        );
        for (flag, invalid) in [
            (
                "--limit",
                vec!["0", "101", "-1", "1.0", "bad", "18446744073709551616"],
            ),
            (
                "--max-batches",
                vec!["0", "-1", "1.0", "bad", "18446744073709551616"],
            ),
            (
                "--timeout-ms",
                vec!["0", "-1", "+1", "1.0", "bad", "18446744073709551616"],
            ),
            (
                "--after",
                vec!["-1", "+1", "1.0", "bad", "18446744073709551616"],
            ),
        ] {
            for value in invalid {
                let mut tail = extra.clone();
                let joined = format!("{flag}={value}");
                tail.push(&joined);
                parser_error(command, &tail, flag);
            }
        }
        let mut tail = extra.clone();
        tail.extend([
            "--limit",
            "100",
            "--max-batches",
            "1",
            "--timeout-ms",
            "1",
            "--after",
            "18446744073709551615",
        ]);
        cli("json", command, Path::new("unused"), &tail);
    }
}

#[test]
fn contributors_largest_first_ties_default_contains_and_rank_cursor() {
    let root = tempfile::tempdir().unwrap();
    let path = bundle(root.path(), &evidence(), Some(&seed()));
    for tail in [&[][..], &["--contains", ""][..]] {
        let value = query("contributors", &path, tail);
        assert_eq!(pairs(&value), ORDER);
        assert_eq!(value["data"]["order"], "bytes_desc_ordinal_asc");
        assert_eq!(value["data"]["scanned"], 7);
        assert_eq!(value["data"]["batches"], 1);
        assert!(value["data"]["elapsed_ms"].is_u64());
        assert_eq!(value["data"]["stop_reason"], "complete");
        assert_eq!(value["data"]["next_after"], Value::Null);
    }
    assert_eq!(
        ordinals(&query("contributors", &path, &["--after", "2"])),
        [2, 6, 0, 4]
    );
    assert_eq!(
        ordinals(&query("contributors", &path, &["--after", "0"])),
        [3, 1, 2, 6, 0, 4]
    );
    let last = query("contributors", &path, &["--after", "6"]);
    assert_eq!(entries(&last), [] as [Value; 0]);
    assert_eq!(last["data"]["stop_reason"], "complete");
    for size in ["1", "2", "100"] {
        let mut actual = Vec::new();
        let mut after = None::<String>;
        loop {
            let mut tail = vec!["--limit", size];
            if let Some(after) = &after {
                tail.extend(["--after", after]);
            }
            let value = query("contributors", &path, &tail);
            actual.extend(pairs(&value));
            after = value["data"]["next_after"].as_str().map(str::to_owned);
            if after.is_none() {
                break;
            }
            let next = value["next_command"].as_str().unwrap();
            assert!(next.contains("--after"));
            assert!(next.contains("--generation"));
        }
        assert_eq!(actual, ORDER);
    }
}

#[test]
fn contributors_stream_and_literal_search_are_exact() {
    let root = tempfile::tempdir().unwrap();
    let path = bundle(root.path(), &evidence(), Some(&seed()));
    for (stream, expected) in [
        ("Methods", vec![3, 1, 2, 0, 4]),
        ("Types", vec![6]),
        ("Blobs", vec![5]),
        ("methods", vec![]),
        ("Method", vec![]),
        ("Meth", vec![]),
    ] {
        let value = query("contributors", &path, &["--stream", stream]);
        assert_eq!(ordinals(&value), expected, "{stream}");
        assert_eq!(value["data"]["stop_reason"], "complete");
    }
    assert_eq!(
        ordinals(&query("contributors", &path, &["--contains", "Row1"])),
        [1]
    );
    let no_match = query("contributors", &path, &["--contains", "row1"]);
    assert_eq!(entries(&no_match), [] as [Value; 0]);
    assert_eq!(no_match["data"]["stop_reason"], "complete");
    assert_eq!(no_match["data"]["scanned"], 7);
}

fn mapping(identity: &str, assembly: &str) -> Mapping {
    Mapping {
        stream: "Methods".into(),
        identity: identity.into(),
        assembly: assembly.into(),
        basis: "fixed_explicit_evidence".into(),
        ..Mapping::default()
    }
}

fn mapped(root: &Path) -> PathBuf {
    let mut value = evidence();
    let identities = [
        "App_Box<int>__Run<long>",
        "App_Box<string>__Run<short>",
        "App_BoxExtra<int>__Run<long>",
        "Opaque__Run",
        "Unknown__Run",
        "Ambiguous__Run",
    ];
    value.mappings = identities[..3]
        .iter()
        .map(|id| mapping(id, "App"))
        .collect();
    value.mappings.push(mapping(identities[3], "Second"));
    value.mappings.extend([
        mapping(identities[5], "App"),
        mapping(identities[5], "Second"),
    ]);
    let rows: Vec<_> = identities
        .iter()
        .enumerate()
        .map(|(i, id)| row("Methods", id, (i as u64 + 1) * 10, true))
        .collect();
    value.packages = vec![
        Package {
            target: "net10.0".into(),
            id: "Pkg".into(),
            version: "1".into(),
            direct: true,
            dependencies: vec![],
        },
        Package {
            target: "net9.0".into(),
            id: "Pkg".into(),
            version: "2".into(),
            direct: false,
            dependencies: vec![],
        },
        Package {
            target: "net10.0".into(),
            id: "PkgExtra".into(),
            version: "1".into(),
            direct: true,
            dependencies: vec![],
        },
    ];
    value.assemblies = vec![
        Assembly {
            name: "App".into(),
            path: "missing-App.dll".into(),
            types: vec![],
            package: Some("Pkg".into()),
        },
        Assembly {
            name: "Second".into(),
            path: "missing-Second.dll".into(),
            types: vec![],
            package: Some("PkgExtra".into()),
        },
    ];
    value.sources.push(Source {
        assembly: "App".into(),
        type_name: "Box".into(),
        member: Some("Run".into()),
        path: "missing.cs".into(),
        line: 1,
        end_line: 2,
        kind: "method".into(),
        ..Source::default()
    });
    value.mappings[0].source_paths.push("missing.cs".into());
    for target in ["net10.0", "net9.0"] {
        value.mappings.push(Mapping {
            stream: "package".into(),
            identity: "Pkg/1".into(),
            assembly: "App".into(),
            basis: format!("assets_resolved_runtime:{target}"),
            ..Mapping::default()
        });
    }
    bundle(root, &value, Some(&rows))
}

#[test]
fn contributors_exact_assembly_owner_family_and_recorded_family_ordinal() {
    let root = tempfile::tempdir().unwrap();
    let path = mapped(root.path());
    for (flag, name, expected) in [
        ("--assembly", "App", vec![2, 1, 0]),
        ("--assembly", "app", vec![]),
        ("--assembly", "Ap", vec![]),
        ("--assembly", "_unmapped", vec![4]),
        ("--assembly", "_ambiguous", vec![5]),
        ("--owner", "App_Box", vec![1, 0]),
        ("--owner", "App", vec![]),
        ("--owner", "Run", vec![]),
        ("--family", "App_Box<>__Run<>", vec![1, 0]),
        ("--family", "app_Box<>__Run<>", vec![]),
    ] {
        assert_eq!(
            ordinals(&query("contributors", &path, &[flag, name])),
            expected,
            "{flag} {name}"
        );
    }
    let families = query("records", &path, &["generic_families"]);
    let family = entries(&families)
        .iter()
        .find(|v| v["fields"]["family"] == "App_Box<>__Run<>")
        .unwrap();
    let selected = query(
        "contributors",
        &path,
        &["--family-record", family["ordinal"].as_str().unwrap()],
    );
    assert_eq!(ordinals(&selected), [1, 0]);
    let parent = query(
        "contributors",
        &path,
        &["--assembly", "App", "--contains", "string"],
    );
    assert_eq!(ordinals(&parent), [1]);
    assert_eq!(parent["data"]["scope"]["bytes"], 60);
    assert_eq!(parent["data"]["scope"]["identities"], 3);
    assert!(
        parent["data"]["scope"]["basis"]
            .as_str()
            .unwrap()
            .contains("before the text filter")
    );
    for flag in ["--owner", "--family"] {
        let selector = if flag == "--owner" {
            "App_Box"
        } else {
            "App_Box<>__Run<>"
        };
        let value = query(
            "contributors",
            &path,
            &[flag, selector, "--contains", "string"],
        );
        assert_eq!(value["data"]["scope"]["bytes"], 30);
        assert_eq!(value["data"]["scope"]["identities"], 2);
    }
    let combined = query(
        "contributors",
        &path,
        &["--assembly", "App", "--owner", "App_Box"],
    );
    assert_eq!(ordinals(&combined), [1, 0]);
    assert_eq!(combined["data"]["scope"]["bytes"], Value::Null);
    assert!(
        combined["data"]["scope"]["basis"]
            .as_str()
            .unwrap()
            .contains("not a precomputed")
    );
}

#[test]
fn family_conflicts_and_malformed_selectors_are_diagnosed() {
    let error = Cli::try_parse_from([
        "vitnet",
        "explore",
        "contributors",
        "unused",
        "--family",
        "A<>",
        "--family-record",
        "0",
    ])
    .unwrap_err();
    assert_eq!(error.kind(), clap::error::ErrorKind::ArgumentConflict);
    for invalid in ["-1", "+1", "1.5", "bad", "18446744073709551616"] {
        parser_error(
            "contributors",
            &[&format!("--family-record={invalid}")],
            "--family-record",
        );
    }
    let root = tempfile::tempdir().unwrap();
    let path = mapped(root.path());
    expect_error(
        "contributors",
        &path,
        &["--family-record", "999"],
        "explorer.cursor",
    );
    for (flag, len) in [
        ("--contains", 1025),
        ("--stream", 65),
        ("--assembly", 4097),
        ("--owner", 4097),
        ("--family", 4097),
    ] {
        expect_error(
            "contributors",
            &path,
            &[flag, &"x".repeat(len)],
            "resource.explorer.query",
        );
    }
}

#[test]
fn generations_out_of_range_cursors_and_precancellation() {
    let root = tempfile::tempdir().unwrap();
    let path = mapped(root.path());
    let generation = read_json(&path.join("bundle.json"))["generation"]
        .as_str()
        .unwrap()
        .to_owned();
    for (command, base) in [
        ("contributors", vec![]),
        ("records", vec!["packages"]),
        ("origins", vec![]),
        ("inspect", vec!["0"]),
    ] {
        let mut tail = base.clone();
        tail.extend(["--generation", &generation]);
        query(command, &path, &tail);
        let mut tail = base.clone();
        tail.extend(["--generation", "stale"]);
        expect_error(command, &path, &tail, "explorer.generation");
        if command != "inspect" {
            let mut tail = base.clone();
            tail.extend(["--after", "18446744073709551615"]);
            expect_error(command, &path, &tail, "explorer.cursor");
        }
    }
    expect_error("inspect", &path, &["999"], "explorer.row");
    for (command, tail) in [
        ("summary", vec![]),
        ("datasets", vec![]),
        ("contributors", vec![]),
        ("records", vec!["packages"]),
        ("origins", vec![]),
        ("inspect", vec!["0"]),
    ] {
        let parsed = cli("json", command, &path, &tail);
        let control = IndexControl::default();
        control.cancel();
        let error = execute_with_index_control(&parsed, &control).unwrap_err();
        assert_eq!(error_code(&error), "resource.cancelled");
        let recovered: Value = serde_json::from_str(
            &execute_with_index_control(&parsed, &IndexControl::default()).unwrap(),
        )
        .unwrap();
        assert_eq!(recovered["operation"], command);
        assert_eq!(recovered["generation"], generation);
    }
}

#[test]
fn empty_and_singleton_rankings_have_honest_termination() {
    for rows in [vec![], vec![row("Methods", "Single__Zero", 0, true)]] {
        let root = tempfile::tempdir().unwrap();
        let path = bundle(root.path(), &evidence(), Some(&rows));
        let value = query("contributors", &path, &["--limit", "1"]);
        assert_eq!(
            pairs(&value),
            if rows.is_empty() {
                vec![]
            } else {
                vec![(0, 0)]
            }
        );
        assert_eq!(value["data"]["scanned"], rows.len());
        assert_eq!(value["data"]["stop_reason"], "complete");
        assert_eq!(value["data"]["next_after"], Value::Null);
        assert_eq!(value["next_command"], Value::Null);
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

fn measured(root: &Path, zero: bool, physical: Option<u64>) -> Evidence {
    let mut value = evidence();
    let mut image = common::Image::new();
    if !zero {
        image.method(b"Owner__First", 11);
        image.method(b"Owner__Last", 29);
        image.method(b"Owner__Zero", 0);
    }
    let path = root.join("reported.mstat");
    fs::write(&path, image.bytes()).unwrap();
    value.artifacts.push(artifact("mstat", path));
    if let Some(bytes) = physical {
        value.binaries.push(Binary {
            path: "reported.exe".into(),
            format: "PE".into(),
            architecture: "x64".into(),
            file_bytes: bytes,
            ..Binary::default()
        });
    }
    value
}

#[test]
fn summary_nonadditive_ledger_preserves_exact_totals_and_caveats() {
    let root = tempfile::tempdir().unwrap();
    let mut value = measured(root.path(), false, Some(1000));
    value.binaries.push(Binary {
        path: "helper.so".into(),
        file_bytes: 2000,
        ..Binary::default()
    });
    let metadata = root.path().join("metadata.csv");
    fs::write(&metadata,b"Handle, Kind, Name, Children\n00000000, ScopeDefinition, \"App\", \"a\"\n0000000a, TypeDefinition, \"Widget\", \"14\"\n00000014, Method, \"Run\", \"\"\n00000046, End, \"\", \"\"\n").unwrap();
    value.artifacts.push(artifact("metadata", metadata));
    for (name, bytes, storage) in [
        ("A", 30, "asset"),
        ("B", 30, "asset"),
        ("C", 30, "asset"),
        ("D", 30, "asset"),
        ("Manifest", 800, "manifest_container"),
        ("Avalonia", 900, "avalonia_container"),
    ] {
        value.resources.push(Resource {
            assembly: "App".into(),
            container: "App.resources".into(),
            name: name.into(),
            bytes,
            storage: storage.into(),
            ..Resource::default()
        });
    }
    let path = bundle(root.path(), &value, None);
    let summary = query("summary", &path, &[]);
    let ledger = &summary["data"]["ledger"];
    assert_eq!(summary["data"]["accounting"]["total_bytes"], 40);
    for (key, expected) in [
        ("accounted_bytes", 40),
        ("physical_total_bytes", 3000),
        ("metadata_lower_bound_bytes", 70),
        ("resource_asset_bytes", 120),
        ("resource_container_bytes", 1700),
    ] {
        assert_eq!(ledger[key], expected, "{key}");
    }
    assert!(
        ledger["resource_basis"]
            .as_str()
            .unwrap()
            .contains("neither inventory sum is additive")
    );
    assert!(
        ledger["accounting_basis"]
            .as_str()
            .unwrap()
            .contains("not a physical executable sum")
    );
    assert!(
        summary["data"]["caveats"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v
                .as_str()
                .is_some_and(|v| v.contains("overlapping projections, never extra totals")))
    );
    let table = output("table", "summary", &path, &[]);
    for expected in [
        "Reported object total: 40 B",
        "Physical binary inventory: 3 KB (3000 B)",
        "Metadata lower bound (overlapping): 70 B",
        "Resource child assets (overlapping): 120 B",
        "Resource containers (overlapping children): 1.7 KB (1700 B)",
        "100.00%",
        "not proof of one executable",
    ] {
        assert!(table.contains(expected), "{expected}\n{table}");
    }
    let machine: Value = serde_json::from_str(&output("ndjson", "summary", &path, &[])).unwrap();
    assert_eq!(machine, summary);
}

#[test]
fn summary_known_zero_and_unknown_accounting_and_physical_are_distinct() {
    for (known, physical) in [
        (false, None),
        (false, Some(0)),
        (true, None),
        (true, Some(0)),
    ] {
        let root = tempfile::tempdir().unwrap();
        let mut value = if known {
            measured(root.path(), true, physical)
        } else {
            evidence()
        };
        if !known && let Some(bytes) = physical {
            value.binaries.push(Binary {
                path: "zero.exe".into(),
                file_bytes: bytes,
                ..Binary::default()
            });
        }
        let path = bundle(root.path(), &value, None);
        let summary = query("summary", &path, &[]);
        assert_eq!(
            summary["data"]["accounting"]["total_bytes"],
            if known { json!(0) } else { Value::Null }
        );
        assert_eq!(
            summary["data"]["ledger"]["physical_total_bytes"],
            physical.map_or(Value::Null, |v| json!(v))
        );
        let table = output("table", "summary", &path, &[]);
        assert!(table.contains(if known {
            "Reported object total: 0 B"
        } else {
            "Reported object total: Unknown"
        }));
        assert!(table.contains(if physical.is_some() {
            "Physical binary inventory: 0 B"
        } else {
            "Physical binary inventory: Unknown"
        }));
        assert!(
            !table.contains("0.00%"),
            "zero/unknown denominator:\n{table}"
        );
    }
}

#[test]
fn contributor_percentages_use_global_accounted_and_parent_not_page_sums() {
    let root = tempfile::tempdir().unwrap();
    let mut value = measured(root.path(), false, None);
    value.mappings = vec![
        mapping("Owner__First", "One"),
        mapping("Owner__Last", "Two"),
    ];
    // Keep measured reported total 40; the fourth row is explicitly overlapping.
    let rows = [
        row("Methods", "Owner__First", 11, true),
        row("Methods", "Owner__Last", 29, true),
        row("Methods", "Owner__Zero", 0, true),
        row("FrozenObjects", "Overlap", 1000, false),
    ];
    let path = bundle(root.path(), &value, Some(&rows));
    let all = query("contributors", &path, &[]);
    assert_eq!(pairs(&all), [(1000, 3), (29, 1), (11, 0), (0, 2)]);
    assert_eq!(all["data"]["scope"]["bytes"], 40);
    assert_eq!(entries(&all)[0]["accounted"], false);
    let table = output("table", "contributors", &path, &["--contains", "First"]);
    let line = table
        .lines()
        .find(|line| line.contains("Owner__First"))
        .unwrap();
    assert_eq!(
        line.split_whitespace().filter(|v| *v == "27.50%").count(),
        3,
        "{line}"
    );
    assert!(table.contains("Accounted bytes in this page: 11 B (27.50% of parent)"));
    let parent = output("table", "contributors", &path, &["--assembly", "One"]);
    let line = parent
        .lines()
        .find(|line| line.contains("Owner__First"))
        .unwrap();
    let percentages: Vec<_> = line
        .split_whitespace()
        .filter(|v| v.ends_with('%'))
        .collect();
    assert_eq!(percentages, ["27.50%", "100.00%", "100.00%"]);
    assert!(parent.contains("Accounted bytes in this page: 11 B (100.00% of parent)"));
    let full = output("table", "contributors", &path, &[]);
    for (identity, expected) in [
        ("Owner__Last", ["72.50%", "72.50%", "72.50%"]),
        ("Owner__First", ["27.50%", "27.50%", "100.00%"]),
        ("Owner__Zero", ["0.00%", "0.00%", "100.00%"]),
    ] {
        let line = full.lines().find(|line| line.contains(identity)).unwrap();
        assert_eq!(
            line.split_whitespace()
                .filter(|v| v.ends_with('%'))
                .collect::<Vec<_>>(),
            expected
        );
    }
    assert!(full.contains("Accounted bytes in this page: 40 B (100.00% of parent)"));
    let zero = output("table", "contributors", &path, &["--contains", "Zero"]);
    assert!(
        zero.lines()
            .find(|v| v.contains("Owner__Zero"))
            .unwrap()
            .contains("0.00%")
    );
    let overlap = output("table", "contributors", &path, &["--contains", "Overlap"]);
    let line = overlap
        .lines()
        .find(|v| v.contains("FrozenObjects"))
        .unwrap();
    assert!(line.contains("Overlap") && line.contains("Unknown"));
    assert!(
        !line.contains("2500.00%"),
        "unaccounted row must not borrow accounted denominator"
    );
    let unknown_root = tempfile::tempdir().unwrap();
    let unknown = bundle(
        unknown_root.path(),
        &evidence(),
        Some(&[row("Methods", "Unmeasured__Zero", 0, true)]),
    );
    let table = output("table", "contributors", &unknown, &[]);
    assert!(
        table
            .lines()
            .find(|v| v.contains("Unmeasured__Zero"))
            .unwrap()
            .contains("Unknown")
    );
}

fn rich(root: &Path) -> PathBuf {
    let mut value = evidence();
    value.provenance.insert("long".into(), "é🙂".repeat(1500));
    for i in 0..101 {
        value.generators.push(Generator {
            name: format!("generator-{i:03}"),
            version: "1".into(),
            assembly_path: "missing.dll".into(),
            generated_files: (0..61)
                .map(|j| format!("generated-{j:03}.cs").into())
                .collect(),
            input_symbols: (0..121).map(|j| format!("symbol-{j:03}")).collect(),
        });
        value
            .provenance
            .insert(format!("key-{i:03}"), format!("value-{i:03}"));
    }
    for i in 0..201 {
        value.packages.push(Package {
            target: if i % 2 == 0 { "net10.0" } else { "net9.0" }.into(),
            id: format!("package-{i:03}"),
            version: "1".into(),
            direct: i % 2 == 0,
            dependencies: vec![],
        });
        value.resources.push(Resource {
            assembly: "App".into(),
            container: "synthetic".into(),
            name: format!("resource-{i:03}"),
            bytes: if i == 0 { 9_007_199_254_740_993 } else { 7 },
            storage: "asset".into(),
            ..Resource::default()
        });
    }
    let rows: Vec<_> = (0..101)
        .map(|i| row("Methods", &format!("Widget{i:03}<int>__Run"), 101 - i, true))
        .collect();
    bundle(root, &value, Some(&rows))
}

#[test]
fn datasets_report_complete_uncapped_catalog_and_capture_limitations() {
    let root = tempfile::tempdir().unwrap();
    let path = rich(root.path());
    let value = query("datasets", &path, &[]);
    let datasets = value["data"]["datasets"].as_array().unwrap();
    for (name, count) in [
        ("identities", 101),
        ("generic_families", 101),
        ("generators", 101),
        ("provenance", 102),
        ("resources", 201),
        ("packages", 201),
        ("package_routes", 201),
        ("mstat_summary", 0),
        ("comparison", 0),
    ] {
        let matches: Vec<_> = datasets.iter().filter(|v| v["name"] == name).collect();
        assert_eq!(matches.len(), 1, "{name}");
        assert_eq!(matches[0]["records"], count, "{name}");
    }
    assert_eq!(value["data"]["complete"], true);
    assert_eq!(value["data"]["ranking_available"], true);
    assert_eq!(value["data"]["generators_captured"], 101);
    assert!(
        value["data"]["scope"]
            .as_str()
            .unwrap()
            .contains("not original source contents")
    );
    assert!(
        value["data"]["comparison_scope"]
            .as_str()
            .unwrap()
            .contains("upstream comparison top-N")
    );
    let table = output("table", "datasets", &path, &[]);
    assert!(
        table.contains("Complete captured dataset catalog")
            && table.contains("201")
            && table.contains("explore records")
    );
}

#[test]
fn records_repeatable_exact_filters_nested_contains_and_paging() {
    let root = tempfile::tempdir().unwrap();
    let path = rich(root.path());
    let selected = query(
        "records",
        &path,
        &[
            "packages",
            "--filter",
            "target=net10.0",
            "--filter",
            "direct=true",
            "--contains",
            "package-00",
        ],
    );
    assert_eq!(ordinals(&selected), [0, 1, 2, 3, 4]);
    assert_eq!(
        entries(&selected)
            .iter()
            .map(|v| v["fields"]["id"].as_str().unwrap())
            .collect::<Vec<_>>(),
        [
            "package-000",
            "package-002",
            "package-004",
            "package-006",
            "package-008"
        ]
    );
    assert!(
        entries(&selected)
            .iter()
            .all(|v| v["fields"]["target"] == "net10.0")
    );
    assert_eq!(
        entries(&query(
            "records",
            &path,
            &["packages", "--filter", "direct=1"]
        )),
        [] as [Value; 0]
    );
    assert_eq!(
        entries(&query(
            "records",
            &path,
            &["packages", "--contains", "Package-"]
        )),
        [] as [Value; 0]
    );
    let first = query("records", &path, &["packages", "--limit", "100"]);
    assert_eq!(ordinals(&first), (0..100).collect::<Vec<_>>());
    assert_eq!(first["data"]["next_after"], "99");
    assert_eq!(first["data"]["scanned"], 100);
    assert_eq!(first["data"]["stop_reason"], "limit");
    let second = query(
        "records",
        &path,
        &["packages", "--limit", "100", "--after", "99"],
    );
    assert_eq!(ordinals(&second), (100..200).collect::<Vec<_>>());
    let last = query("records", &path, &["packages", "--after", "199"]);
    assert_eq!(ordinals(&last), [200]);
    assert_eq!(last["data"]["stop_reason"], "complete");
    assert_eq!(last["data"]["next_after"], Value::Null);
    let nested = query(
        "records",
        &path,
        &["generators", "--contains", "symbol-120", "--limit", "100"],
    );
    assert_eq!(entries(&nested).len(), 100);
    let number = query(
        "records",
        &path,
        &["resources", "--filter", "bytes=9007199254740993"],
    );
    assert_eq!(ordinals(&number), [0]);
    assert_eq!(
        entries(&number)[0]["fields"]["bytes"].as_u64(),
        Some(9_007_199_254_740_993)
    );
    let empty = query("records", &path, &["comparison"]);
    assert_eq!(empty["data"]["stop_reason"], "complete");
    assert_eq!(empty["data"]["scanned"], 0);
}

#[test]
fn records_invalid_filters_datasets_and_query_budgets_are_explicit() {
    for filter in ["bad", "=value"] {
        parser_error("records", &["packages", "--filter", filter], "--filter");
    }
    let root = tempfile::tempdir().unwrap();
    let path = rich(root.path());
    expect_error(
        "records",
        &path,
        &["packages", "--filter", "id=a", "--filter", "id=b"],
        "explorer.query",
    );
    for dataset in ["unknown", "../packages", "Packages"] {
        expect_error("records", &path, &[dataset], "explorer.dataset");
    }
    expect_error(
        "records",
        &path,
        &["packages", "--contains", &"x".repeat(1025)],
        "resource.explorer.query",
    );
    expect_error(
        "records",
        &path,
        &["packages", "--filter", &format!("{}=x", "k".repeat(129))],
        "resource.explorer.query",
    );
    expect_error(
        "records",
        &path,
        &["packages", "--filter", &format!("id={}", "x".repeat(4097))],
        "resource.explorer.query",
    );
    let filters: Vec<_> = (0..9).map(|i| format!("k{i}=v")).collect();
    let mut tail = vec!["packages"];
    for filter in &filters {
        tail.extend(["--filter", filter]);
    }
    expect_error("records", &path, &tail, "resource.explorer.query");
}

#[test]
fn origins_exact_assembly_package_target_and_continuation_keep_recorded_basis() {
    let root = tempfile::tempdir().unwrap();
    let path = mapped(root.path());
    let value = query("origins", &path, &["--assembly", "App"]);
    assert_eq!(entries(&value).len(), 3);
    for (flag, name, expected) in [
        ("--assembly", "Ap", 0),
        ("--assembly", "app", 0),
        ("--package", "Pkg", 1),
        ("--package", "Pkg/1", 2),
        ("--package", "Pk", 0),
        ("--target", "net10.0", 1),
        ("--target", "net10", 0),
    ] {
        let result = query("origins", &path, &[flag, name]);
        assert_eq!(entries(&result).len(), expected, "{flag} {name}");
        assert_eq!(result["data"]["stop_reason"], "complete");
    }
    let combined = query(
        "origins",
        &path,
        &[
            "--assembly",
            "App",
            "--package",
            "Pkg/1",
            "--target",
            "net9.0",
        ],
    );
    assert_eq!(entries(&combined).len(), 1);
    assert_eq!(entries(&combined)[0]["fields"]["target"], "net9.0");
    let all = query("origins", &path, &[]);
    let mut captured = Vec::new();
    let mut cursor = None::<String>;
    loop {
        let mut tail = vec!["--limit", "1"];
        if let Some(cursor) = &cursor {
            tail.extend(["--after", cursor]);
        }
        let value = query("origins", &path, &tail);
        captured.extend(entries(&value).iter().cloned());
        cursor = value["data"]["next_after"].as_str().map(str::to_owned);
        if cursor.is_none() {
            break;
        }
    }
    assert_eq!(captured, entries(&all));
    let table = output("table", "origins", &path, &[]);
    assert!(
        table.contains("associations, not compiler retention, exclusive bytes or removable size")
    );
    for flag in ["--assembly", "--package", "--target"] {
        expect_error(
            "origins",
            &path,
            &[flag, &"x".repeat(4097)],
            "resource.explorer.query",
        );
    }
}

fn child(value: &Value, key: &str) -> String {
    entries(value)
        .iter()
        .find(|v| v["key"] == key)
        .unwrap_or_else(|| panic!("missing field {key}: {value}"))["index"]
        .as_u64()
        .unwrap()
        .to_string()
}

#[test]
fn inspect_defaults_original_ordinal_full_record_and_field_key() {
    let root = tempfile::tempdir().unwrap();
    let path = bundle(root.path(), &evidence(), Some(&seed()));
    let default = query("inspect", &path, &["1"]);
    let explicit = query(
        "inspect",
        &path,
        &[
            "1",
            "--dataset",
            "identities",
            "--view",
            "record",
            "--start",
            "0",
        ],
    );
    assert_eq!(default, explicit);
    assert_eq!(default["data"]["kind"], "object");
    let identity = child(&default, "identity");
    let bytes = child(&default, "bytes");
    let name = query("inspect", &path, &["1", "--path", &identity]);
    assert_eq!(name["data"]["kind"], "string");
    assert_eq!(name["data"]["text"], "Opaque__Row1");
    assert_eq!(name["data"]["start"], 0);
    assert_eq!(name["data"]["total_bytes"], 12);
    assert_eq!(name["data"]["next_start"], Value::Null);
    let number = query("inspect", &path, &["1", "--path", &bytes]);
    assert_eq!(
        number["data"],
        json!({"kind":"number","display":"90","next_start":null,"generation":default["generation"]})
    );
    let key = query("inspect", &path, &["1", "--path", &identity, "--key"]);
    assert_eq!(key["data"]["text"], "identity");
    expect_error("inspect", &path, &["1", "--key"], "explorer.cursor");
    expect_error(
        "inspect",
        &path,
        &["1", "--path", &bytes, "--start", "1"],
        "explorer.cursor",
    );
}

#[test]
#[allow(clippy::too_many_lines)] // Contrast recorded, absent and lossy evidence through both views.
fn inspect_source_shape_missing_and_lossy_evidence_are_honest() {
    let root = tempfile::tempdir().unwrap();
    let path = mapped(root.path());
    let source = query("inspect", &path, &["0", "--view", "source"]);
    assert_eq!(source["data"]["kind"], "object");
    let status = child(&source, "status");
    assert_eq!(
        query(
            "inspect",
            &path,
            &["0", "--view", "source", "--path", &status]
        )["data"]["text"],
        "asserted"
    );
    let assemblies = child(&source, "assemblies");
    let list = query(
        "inspect",
        &path,
        &["0", "--view", "source", "--path", &assemblies],
    );
    assert_eq!(list["data"]["kind"], "array");
    assert_eq!(list["data"]["total"], 1);
    assert_eq!(entries(&list)[0]["summary"], "App");
    let sources_index = child(&source, "sources");
    let sources = query(
        "inspect",
        &path,
        &["0", "--view", "source", "--path", &sources_index],
    );
    assert_eq!(sources["data"]["total"], 1);
    let item_path = format!("{sources_index},0");
    let recorded_source = query(
        "inspect",
        &path,
        &["0", "--view", "source", "--path", &item_path],
    );
    let path_index = child(&recorded_source, "path");
    let path_path = format!("{item_path},{path_index}");
    let recorded_path = query(
        "inspect",
        &path,
        &["0", "--view", "source", "--path", &path_path],
    );
    assert_eq!(
        recorded_path["data"]["text"],
        json!(root.path().join("missing.cs"))
    );
    let absent = query("inspect", &path, &["4", "--view", "source"]);
    let status = child(&absent, "status");
    assert_eq!(
        query(
            "inspect",
            &path,
            &["4", "--view", "source", "--path", &status]
        )["data"]["text"],
        "unmapped"
    );
    let shape = query("inspect", &path, &["0", "--view", "shape"]);
    let family = child(&shape, "family");
    assert_eq!(
        query(
            "inspect",
            &path,
            &["0", "--view", "shape", "--path", &family]
        )["data"]["text"],
        "App_Box<>__Run<>"
    );
    let absent_shape = query("inspect", &path, &["4", "--view", "shape"]);
    assert_eq!(
        absent_shape["data"],
        json!({"kind":"null","display":"null","next_start":null,"generation":absent_shape["generation"]})
    );
    for view in ["source", "shape"] {
        expect_error(
            "inspect",
            &path,
            &["0", "--dataset", "packages", "--view", view],
            "explorer.query",
        );
    }
    let table = output("table", "inspect", &path, &["0", "--view", "source"]);
    assert!(
        table.contains("do not prove retention or savings"),
        "{table}"
    );
    let lossy_root = tempfile::tempdir().unwrap();
    let mut lossy = row("Methods", "Bad<\u{fffd}>__Run", 1, true);
    lossy.identity_lossy = true;
    let lossy_path = bundle(lossy_root.path(), &evidence(), Some(&[lossy]));
    expect_error(
        "inspect",
        &lossy_path,
        &["0", "--view", "shape"],
        "explorer.shape.lossy",
    );
    let source = query("inspect", &lossy_path, &["0", "--view", "source"]);
    let status = child(&source, "status");
    assert_eq!(
        query(
            "inspect",
            &lossy_path,
            &["0", "--view", "source", "--path", &status]
        )["data"]["text"],
        "unmapped_lossy_identity"
    );
}

#[test]
fn inspect_array_pages_and_comma_positional_paths_reconstruct_captured_values() {
    let root = tempfile::tempdir().unwrap();
    let path = rich(root.path());
    let generator = query("inspect", &path, &["0", "--dataset", "generators"]);
    let evidence_index = child(&generator, "evidence");
    let captured = query(
        "inspect",
        &path,
        &["0", "--dataset", "generators", "--path", &evidence_index],
    );
    let symbols_index = child(&captured, "input_symbols");
    let positional = format!("{evidence_index},{symbols_index}");
    let first = query(
        "inspect",
        &path,
        &["0", "--dataset", "generators", "--path", &positional],
    );
    assert_eq!(first["data"]["kind"], "array");
    assert_eq!(first["data"]["total"], 121);
    assert_eq!(entries(&first).len(), 100);
    assert_eq!(first["data"]["next_start"], 100);
    assert_eq!(entries(&first)[0]["index"], 0);
    assert_eq!(entries(&first)[99]["summary"], "symbol-099");
    let second = query(
        "inspect",
        &path,
        &[
            "0",
            "--dataset",
            "generators",
            "--path",
            &positional,
            "--start",
            "100",
        ],
    );
    assert_eq!(entries(&second).len(), 21);
    assert_eq!(entries(&second)[0]["index"], 100);
    assert_eq!(entries(&second)[20]["summary"], "symbol-120");
    assert_eq!(second["data"]["next_start"], Value::Null);
    let scalar_path = format!("{positional},120");
    assert_eq!(
        query(
            "inspect",
            &path,
            &["0", "--dataset", "generators", "--path", &scalar_path]
        )["data"]["text"],
        "symbol-120"
    );
    expect_error(
        "inspect",
        &path,
        &[
            "0",
            "--dataset",
            "generators",
            "--path",
            &scalar_path,
            "--key",
        ],
        "explorer.cursor",
    );
    let empty = query(
        "inspect",
        &path,
        &[
            "0",
            "--dataset",
            "generators",
            "--path",
            &positional,
            "--start",
            "121",
        ],
    );
    assert_eq!(entries(&empty), [] as [Value; 0]);
    assert_eq!(empty["data"]["next_start"], Value::Null);
    expect_error(
        "inspect",
        &path,
        &[
            "0",
            "--dataset",
            "generators",
            "--path",
            &positional,
            "--start",
            "122",
        ],
        "explorer.cursor",
    );
}

#[test]
fn inspect_utf8_chunk_boundaries_full_text_and_invalid_offsets() {
    let root = tempfile::tempdir().unwrap();
    let path = rich(root.path());
    // BTreeMap provenance keys put long after key-000..key-100.
    let record = query("inspect", &path, &["101", "--dataset", "provenance"]);
    let value_index = child(&record, "value");
    let first = query(
        "inspect",
        &path,
        &["101", "--dataset", "provenance", "--path", &value_index],
    );
    assert_eq!(first["data"]["kind"], "string");
    assert_eq!(first["data"]["total_bytes"], 9000);
    assert_eq!(first["data"]["text"], "é🙂".repeat(682) + "é");
    assert_eq!(first["data"]["next_start"], 4094);
    let mut text = first["data"]["text"].as_str().unwrap().to_owned();
    let mut cursor = first["data"]["next_start"].as_u64();
    while let Some(start) = cursor {
        let start = start.to_string();
        let value = query(
            "inspect",
            &path,
            &[
                "101",
                "--dataset",
                "provenance",
                "--path",
                &value_index,
                "--start",
                &start,
            ],
        );
        let chunk = value["data"]["text"].as_str().unwrap();
        assert!(chunk.len() <= 4096);
        text.push_str(chunk);
        cursor = value["data"]["next_start"].as_u64();
    }
    assert_eq!(text, "é🙂".repeat(1500));
    for start in ["1", "3", "9001", "18446744073709551615"] {
        expect_error(
            "inspect",
            &path,
            &[
                "101",
                "--dataset",
                "provenance",
                "--path",
                &value_index,
                "--start",
                start,
            ],
            "explorer.cursor",
        );
    }
    let end = query(
        "inspect",
        &path,
        &[
            "101",
            "--dataset",
            "provenance",
            "--path",
            &value_index,
            "--start",
            "9000",
        ],
    );
    assert_eq!(end["data"]["text"], "");
    assert_eq!(end["data"]["next_start"], Value::Null);
    let legal = query(
        "inspect",
        &path,
        &[
            "101",
            "--dataset",
            "provenance",
            "--path",
            &value_index,
            "--start",
            "2",
        ],
    );
    assert!(legal["data"]["text"].as_str().unwrap().starts_with("🙂é"));
}

#[test]
fn inspect_rejects_malformed_signed_and_overdeep_paths_without_repair() {
    for path in [
        "",
        "1,",
        ",1",
        "1,,2",
        "-1",
        "+1",
        "1.0",
        "a",
        "18446744073709551616",
    ] {
        parser_error("inspect", &["0", &format!("--path={path}")], "--path");
    }
    for value in ["-1", "+1", "1.0", "a", "18446744073709551616"] {
        parser_error("inspect", &[value], "ordinal");
        parser_error("inspect", &["0", &format!("--start={value}")], "--start");
    }
    let root = tempfile::tempdir().unwrap();
    let path = bundle(root.path(), &evidence(), Some(&seed()));
    expect_error("inspect", &path, &["0", "--path", "999"], "explorer.cursor");
    let record = query("inspect", &path, &["0"]);
    let index = child(&record, "bytes");
    expect_error(
        "inspect",
        &path,
        &["0", "--path", &format!("{index},0")],
        "explorer.cursor",
    );
    let overdeep = vec!["0"; 65].join(",");
    expect_error(
        "inspect",
        &path,
        &["0", "--path", &overdeep],
        "resource.explorer.path",
    );
}

#[test]
fn table_controls_are_escaped_and_shortened_previews_point_to_full_inspect() {
    let root = tempfile::tempdir().unwrap();
    let original = format!("Owner__\n\r\t\u{1b}[31m\u{7}\u{202e}{}", "é🙂".repeat(200));
    let path = bundle(
        root.path(),
        &evidence(),
        Some(&[row("Methods", &original, 1235, true)]),
    );
    let ranked = query("contributors", &path, &[]);
    let preview = &entries(&ranked)[0];
    assert_eq!(preview["truncated"], true);
    assert!(preview["identity"].as_str().unwrap().len() <= 512);
    assert_eq!(preview["identity_bytes"], original.len());
    let table = output("table", "contributors", &path, &[]);
    assert!(table.contains("1.24 KB"));
    assert!(table.contains(r"Owner__\n\r\t\u{1b}[31m\u{7}\u{202e}"));
    assert!(table.contains("[display shortened]") && table.contains("explore inspect"));
    for control in ['\r', '\t', '\u{1b}', '\u{7}', '\u{202e}'] {
        assert!(!table.contains(control), "{control:?}");
    }
    let record = query("inspect", &path, &["0"]);
    let index = child(&record, "identity");
    let full = query("inspect", &path, &["0", "--path", &index]);
    assert_eq!(full["data"]["text"], original);
    let table = output("table", "inspect", &path, &["0", "--path", &index]);
    assert!(table.contains(r"\u{1b}"));
    assert!(!table.contains('\u{1b}'));
    let records = output("table", "records", &path, &["identities"]);
    assert!(records.contains("Previews are bounded") && records.contains("explore inspect"));
    assert!(!records.contains('\u{1b}'));
}

fn refingerprint(path: &Path, manifest: &mut Value, snapshot: &mut Value) {
    snapshot["generation"] = Value::Null;
    let mut hash = blake3::Hasher::new();
    hash.update(b"vitnet.explorer-generation.v1\0");
    hash.update(manifest["index_blake3"].as_str().unwrap().as_bytes());
    hash.update(manifest["identities_blake3"].as_str().unwrap().as_bytes());
    hash.update(&serde_json::to_vec(snapshot).unwrap());
    let generation = hash.finalize().to_hex().to_string();
    snapshot["generation"] = json!(generation);
    manifest["generation"] = json!(generation);
    let payload = serde_json::to_vec(snapshot).unwrap();
    manifest["snapshot_blake3"] = json!(blake3::hash(&payload).to_hex().to_string());
    fs::write(path.join("snapshot.json"), payload).unwrap();
    write_json(&path.join("bundle.json"), manifest);
}

#[test]
fn legacy_missing_ranking_is_rejected_not_silently_snapshot_top() {
    let root = tempfile::tempdir().unwrap();
    let path = bundle(root.path(), &evidence(), Some(&seed()));
    let mut manifest = read_json(&path.join("bundle.json"));
    let mut snapshot = read_json(&path.join("snapshot.json"));
    manifest.as_object_mut().unwrap().remove("ranking");
    snapshot.as_object_mut().unwrap().remove("ranking");
    refingerprint(&path, &mut manifest, &mut snapshot);
    data::verify(&path, MEMORY).unwrap();
    expect_error("contributors", &path, &[], "explorer.ranking.unavailable");
    let catalog = query("datasets", &path, &[]);
    assert_eq!(catalog["data"]["ranking_available"], false);
    assert_eq!(catalog["data"]["complete"], true);
    let summary = query("summary", &path, &[]);
    assert_eq!(summary["data"]["accounting"]["total_bytes"], Value::Null);
    assert_eq!(summary["data"]["coverage"]["identities"], 7);
}

#[test]
#[allow(clippy::too_many_lines)] // Reconcile sparse empty, partial and resumed scans in one fixture.
fn sparse_search_fills_across_empty_partial_batches_and_preserves_scan_cursor() {
    let root = tempfile::tempdir().unwrap();
    let rows: Vec<_> = (0..100_005)
        .map(|i| {
            row(
                "Methods",
                if [0, 100_003, 100_004].contains(&i) {
                    "Owner__Needle"
                } else {
                    "Owner__Other"
                },
                1,
                true,
            )
        })
        .collect();
    let path = bundle(root.path(), &evidence(), Some(&rows));
    let bounded = query(
        "contributors",
        &path,
        &[
            "--contains",
            "Absent",
            "--limit",
            "3",
            "--max-batches",
            "1",
            "--timeout-ms",
            "60000",
        ],
    );
    assert_eq!(entries(&bounded), [] as [Value; 0]);
    assert_eq!(bounded["data"]["stop_reason"], "max_batches");
    let after: u64 = bounded["data"]["next_after"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();
    assert_eq!(bounded["data"]["scanned"].as_u64().unwrap(), after + 1);
    assert!(after < 100_004);
    assert_eq!(bounded["data"]["batches"], 1);
    let table = output(
        "table",
        "contributors",
        &path,
        &["--contains", "Absent", "--max-batches", "1"],
    );
    assert!(table.contains("not a complete no-match result"));
    assert!(!table.contains("End of captured dataset reached"));
    let partial = query(
        "contributors",
        &path,
        &[
            "--contains",
            "Needle",
            "--limit",
            "3",
            "--max-batches",
            "1",
            "--timeout-ms",
            "60000",
        ],
    );
    assert_eq!(ordinals(&partial), [0]);
    assert_eq!(partial["data"]["stop_reason"], "max_batches");
    assert!(partial["data"]["scanned"].as_u64().unwrap() > 1);
    let full = query(
        "contributors",
        &path,
        &[
            "--contains",
            "Needle",
            "--limit",
            "3",
            "--max-batches",
            "200",
            "--timeout-ms",
            "60000",
        ],
    );
    assert_eq!(ordinals(&full), [0, 100_003, 100_004]);
    assert_eq!(full["data"]["scanned"], 100_005);
    assert!(full["data"]["batches"].as_u64().unwrap() > 1);
    assert_eq!(full["data"]["stop_reason"], "complete");
    assert_eq!(full["data"]["next_after"], Value::Null);
    let empty_initial = query(
        "contributors",
        &path,
        &[
            "--contains",
            "Needle",
            "--after",
            "0",
            "--limit",
            "2",
            "--max-batches",
            "200",
            "--timeout-ms",
            "60000",
        ],
    );
    assert_eq!(ordinals(&empty_initial), [100_003, 100_004]);
    assert_eq!(empty_initial["data"]["scanned"], 100_004);
    assert!(empty_initial["data"]["batches"].as_u64().unwrap() > 1);
}

#[test]
fn continuation_commands_preserve_format_budgets_filters_generation_not_output() {
    let root = tempfile::tempdir().unwrap();
    let path = mapped(root.path());
    let generation = read_json(&path.join("bundle.json"))["generation"]
        .as_str()
        .unwrap()
        .to_owned();
    for format in ["json", "ndjson"] {
        let mut parsed = cli(
            format,
            "contributors",
            &path,
            &[
                "--stream",
                "Methods",
                "--assembly",
                "App",
                "--owner",
                "App_Box",
                "--family",
                "App_Box<>__Run<>",
                "--contains",
                "Run",
                "--limit",
                "1",
                "--max-batches",
                "7",
                "--timeout-ms",
                "54321",
            ],
        );
        parsed.quiet = true;
        parsed.progress = vitnet_cli::ModeArg::Always;
        parsed.output = Some(root.path().join("do-not-overwrite.json"));
        let value: Value = serde_json::from_str(&execute(&parsed).unwrap()).unwrap();
        let expected = format!(
            "vitnet --memory-limit 134217728B --format {format} --quiet --progress always explore contributors '{}' --contains 'Run' --stream 'Methods' --assembly 'App' --owner 'App_Box' --family 'App_Box<>__Run<>' --after 4 --limit 1 --max-batches 7 --timeout-ms 54321 --generation '{generation}'",
            path.display()
        );
        assert_eq!(value["next_command"], expected);
        assert!(!value["next_command"].as_str().unwrap().contains("--output"));
    }
    let record = query(
        "records",
        &path,
        &[
            "packages",
            "--filter",
            "version=1",
            "--filter",
            "direct=true",
            "--contains",
            "Pkg",
            "--limit",
            "1",
        ],
    );
    assert_eq!(
        record["next_command"],
        format!(
            "vitnet --memory-limit 134217728B --format json --progress never explore records '{}' 'packages' --contains 'Pkg' --filter 'version=1' --filter 'direct=true' --after 0 --limit 1 --max-batches 20 --timeout-ms 30000 --generation '{generation}'",
            path.display()
        )
    );
    let origins = query(
        "origins",
        &path,
        &["--assembly", "App", "--package", "Pkg/1", "--limit", "1"],
    );
    let next = origins["next_command"].as_str().unwrap();
    assert!(next.contains("--assembly 'App' --package 'Pkg/1'"));
    assert!(next.ends_with(&format!("--generation '{generation}'")));
}

// Replace only owned fixture catalog bytes, with independent offsets/hashes and
// generation. This allows unusual-but-valid captured records without source seams.
fn replace_catalog(path: &Path, name: &str, records: &[Value]) {
    let mut payload = Vec::new();
    let mut offsets = Vec::new();
    for record in records {
        offsets.extend((payload.len() as u64).to_le_bytes());
        payload.extend(serde_json::to_vec(record).unwrap());
        payload.push(b'\n');
    }
    offsets.extend((payload.len() as u64).to_le_bytes());
    fs::write(path.join(format!("catalog_{name}.ndjson")), &payload).unwrap();
    fs::write(path.join(format!("catalog_{name}.offsets")), &offsets).unwrap();
    let descriptor = json!({"records":records.len(),"data_bytes":payload.len(),
        "blake3":blake3::hash(&payload).to_hex().to_string(),
        "offsets_blake3":blake3::hash(&offsets).to_hex().to_string()});
    let mut manifest = read_json(&path.join("bundle.json"));
    let mut snapshot = read_json(&path.join("snapshot.json"));
    manifest["datasets"][name] = descriptor.clone();
    snapshot["datasets"][name] = descriptor;
    refingerprint(path, &mut manifest, &mut snapshot);
}

#[test]
fn records_and_origins_auto_batch_empty_partial_pages_with_exact_scan_totals() {
    let root = tempfile::tempdir().unwrap();
    let path = bundle(root.path(), &evidence(), None);
    let records:Vec<_>=(0..100_005).map(|i|json!({
        "assembly":if [0,100_003,100_004].contains(&i) {"Needle"} else {"Other"},
        "package":"Pkg/1","target":"net10.0","basis":"fixed_explicit_evidence",
        "caveat":"Recorded package origin, not compiler retention, exclusive byte ownership or removable size."
    })).collect();
    replace_catalog(&path, "assembly_links", &records);
    for (command, selector) in [
        (
            "records",
            vec!["assembly_links", "--filter", "assembly=Needle"],
        ),
        ("origins", vec!["--assembly", "Needle"]),
    ] {
        let mut tail = selector.clone();
        tail.extend([
            "--limit",
            "3",
            "--max-batches",
            "1",
            "--timeout-ms",
            "60000",
        ]);
        let bounded = query(command, &path, &tail);
        assert_eq!(ordinals(&bounded), [0]);
        assert_eq!(bounded["data"]["stop_reason"], "max_batches");
        let after: u64 = bounded["data"]["next_after"]
            .as_str()
            .unwrap()
            .parse()
            .unwrap();
        assert_eq!(bounded["data"]["scanned"].as_u64().unwrap(), after + 1);
        assert!(after < 100_003);
        let mut tail = selector.clone();
        tail.extend([
            "--limit",
            "3",
            "--max-batches",
            "200",
            "--timeout-ms",
            "60000",
        ]);
        let full = query(command, &path, &tail);
        assert_eq!(ordinals(&full), [0, 100_003, 100_004]);
        assert_eq!(full["data"]["scanned"], 100_005);
        assert!(full["data"]["batches"].as_u64().unwrap() > 1);
        assert_eq!(full["data"]["stop_reason"], "complete");
        assert_eq!(full["data"]["next_after"], Value::Null);
        let mut tail = selector.clone();
        tail.extend([
            "--limit",
            "2",
            "--after",
            "0",
            "--max-batches",
            "200",
            "--timeout-ms",
            "60000",
        ]);
        let empty_first = query(command, &path, &tail);
        assert_eq!(ordinals(&empty_first), [100_003, 100_004]);
        assert_eq!(empty_first["data"]["scanned"], 100_004);
        assert!(empty_first["data"]["batches"].as_u64().unwrap() > 1);
    }
}

#[test]
fn inspect_object_boundaries_scalar_boolean_null_and_empty_array() {
    let root = tempfile::tempdir().unwrap();
    let path = bundle(root.path(), &evidence(), None);
    let record: Value = (0..101)
        .map(|i| (format!("key-{i:03}"), json!(i)))
        .collect::<serde_json::Map<_, _>>()
        .into();
    replace_catalog(
        &path,
        "provenance",
        &[record, json!({"boolean":false,"empty":[],"null":null})],
    );
    let first = query("inspect", &path, &["0", "--dataset", "provenance"]);
    assert_eq!(entries(&first).len(), 100);
    assert_eq!(first["data"]["total"], 101);
    assert_eq!(first["data"]["next_start"], 100);
    assert_eq!(entries(&first)[99]["key"], "key-099");
    assert_eq!(entries(&first)[99]["summary"], "99");
    let last = query(
        "inspect",
        &path,
        &["0", "--dataset", "provenance", "--start", "100"],
    );
    assert_eq!(entries(&last).len(), 1);
    assert_eq!(entries(&last)[0]["key"], "key-100");
    assert_eq!(entries(&last)[0]["index"], 100);
    assert_eq!(last["data"]["next_start"], Value::Null);
    let empty = query(
        "inspect",
        &path,
        &["0", "--dataset", "provenance", "--start", "101"],
    );
    assert_eq!(entries(&empty), [] as [Value; 0]);
    expect_error(
        "inspect",
        &path,
        &["0", "--dataset", "provenance", "--start", "102"],
        "explorer.cursor",
    );
    for (index, kind, display) in [
        ("0", "boolean", Some("false")),
        ("1", "array", None),
        ("2", "null", Some("null")),
    ] {
        let value = query(
            "inspect",
            &path,
            &["1", "--dataset", "provenance", "--path", index],
        );
        assert_eq!(value["data"]["kind"], kind);
        assert_eq!(value["data"]["next_start"], Value::Null);
        if let Some(display) = display {
            assert_eq!(value["data"]["display"], display);
        } else {
            assert_eq!(entries(&value), [] as [Value; 0]);
            assert_eq!(value["data"]["total"], 0);
        }
    }
}

#[test]
fn json_and_table_response_byte_budgets_are_enforced_after_rendering() {
    let root = tempfile::tempdir().unwrap();
    let path = bundle(root.path(), &evidence(), None);
    let keys = [
        "name",
        "family",
        "package",
        "id",
        "version",
        "target",
        "assembly",
        "type_name",
        "member",
        "stream",
        "dimension",
        "status",
        "storage",
        "container",
        "path",
        "basis",
    ];
    for (character, json_fails) in [('\u{202e}', false), ('\u{1b}', true)] {
        let record: Value = keys
            .iter()
            .map(|key| ((*key).to_owned(), json!(character.to_string().repeat(512))))
            .collect::<serde_json::Map<_, _>>()
            .into();
        replace_catalog(&path, "provenance", &vec![record; 100]);
        if json_fails {
            expect_error(
                "records",
                &path,
                &["provenance", "--limit", "100"],
                "resource.explorer.response",
            );
        } else {
            let value = query("records", &path, &["provenance", "--limit", "100"]);
            assert_eq!(entries(&value).len(), 100);
            assert_eq!(value["data"]["stop_reason"], "complete");
        }
        let error = execute(&cli(
            "table",
            "records",
            &path,
            &["provenance", "--limit", "100"],
        ))
        .unwrap_err();
        assert_eq!(error_code(&error), "resource.explorer.response");
        let small = query("records", &path, &["provenance", "--limit", "1"]);
        assert_eq!(entries(&small).len(), 1);
        assert_eq!(small["data"]["next_after"], "0");
    }
}

#[test]
fn progress_is_stderr_only_and_quiet_suppresses_it() {
    let root = tempfile::tempdir().unwrap();
    let path = bundle(root.path(), &evidence(), Some(&seed()));
    for quiet in [false, true] {
        let mut command = std::process::Command::new(env!("CARGO_BIN_EXE_vitnet"));
        command.args([
            "--format",
            "json",
            "--memory-limit",
            "128MiB",
            "--progress",
            "always",
            "--color",
            "never",
        ]);
        if quiet {
            command.arg("--quiet");
        }
        let result = command
            .args([
                "explore",
                "contributors",
                path.to_str().unwrap(),
                "--limit",
                "1",
            ])
            .output()
            .unwrap();
        assert!(result.status.success(), "{result:?}");
        let value: Value = serde_json::from_slice(&result.stdout).unwrap();
        assert_eq!(pairs(&value), [(1000, 5)]);
        assert_eq!(value["schema"], "vitnet.explorer-cli.v1");
        let stderr = String::from_utf8(result.stderr).unwrap();
        if quiet {
            assert_eq!(stderr, "");
        } else {
            assert!(
                stderr.contains("Scanned 1 positions in 1 batches; 1 / 1 rows"),
                "{stderr}"
            );
        }
    }
}

#[test]
fn rust_blob_glossary_uses_pinned_shared_asset_and_rejects_unknown_names() {
    let root = tempfile::tempdir().unwrap();
    let rows = [
        row("Blobs", "Metadata", 2, true),
        row("Blobs", "ResourceData", 1, true),
        row("Blobs", "metadata", 0, true),
        row("Blobs", "constructor", 0, true),
    ];
    let path = bundle(root.path(), &evidence(), Some(&rows));
    let table = output("table", "contributors", &path, &[]);
    assert!(table.contains("Metadata: Native reflection metadata"));
    assert!(table.contains(
        "Encoded NativeAOT metadata for retained types, methods, fields, signatures and constants."
    ));
    assert!(table.contains("https://github.com/dotnet/runtime/blob/2eb7113245f7c536ab876dca5e3533fb96c81bbf/src/coreclr/tools/aot/ILCompiler.Compiler/Compiler/MetadataManager.cs"));
    assert!(table.contains("ResourceData: Embedded resource payloads"));
    assert!(!table.contains("\nmetadata:") && !table.contains("\nconstructor:"));
}

#[test]
fn machine_records_preserve_large_unsigned_bytes_and_invalid_identity_filters() {
    let root = tempfile::tempdir().unwrap();
    let path = rich(root.path());
    for format in ["json", "ndjson"] {
        let value: Value = serde_json::from_str(&output(
            format,
            "records",
            &path,
            &["resources", "--filter", "bytes=9007199254740993"],
        ))
        .unwrap();
        assert_eq!(value["schema"], "vitnet.explorer-cli.v1");
        assert_eq!(ordinals(&value), [0]);
        assert_eq!(
            entries(&value)[0]["fields"]["bytes"].as_u64(),
            Some(9_007_199_254_740_993)
        );
    }
    expect_error(
        "records",
        &path,
        &["identities", "--filter", "bytes=7"],
        "explorer.query",
    );
    let filtered = query(
        "records",
        &path,
        &[
            "identities",
            "--filter",
            "stream=Methods",
            "--filter",
            "owner=Widget000",
        ],
    );
    assert_eq!(ordinals(&filtered), [0]);
    assert_eq!(entries(&filtered)[0]["summary"], "Widget000<int>__Run");
}

#[test]
fn inspect_and_origin_continuations_preserve_positional_key_and_target_selectors() {
    let root = tempfile::tempdir().unwrap();
    let fixture = root.path().join("space and 'quote'");
    fs::create_dir(&fixture).unwrap();
    let path = mapped(&fixture);
    let key = "é".repeat(2500);
    replace_catalog(&path, "provenance", &[json!({key.clone():"captured"})]);
    let inspected = query(
        "inspect",
        &path,
        &["0", "--dataset", "provenance", "--path", "0", "--key"],
    );
    assert_eq!(inspected["data"]["text"], "é".repeat(2048));
    assert_eq!(inspected["data"]["next_start"], 4096);
    let generation = inspected["generation"].as_str().unwrap();
    let quoted = path.to_str().unwrap().replace('\'', "''");
    assert_eq!(
        inspected["next_command"],
        format!(
            "vitnet --memory-limit 134217728B --format json --progress never explore inspect '{quoted}' 0 --dataset 'provenance' --view 'record' --path '0' --key --generation '{generation}' --start 4096"
        )
    );
    let last = query(
        "inspect",
        &path,
        &[
            "0",
            "--dataset",
            "provenance",
            "--path",
            "0",
            "--key",
            "--start",
            "4096",
        ],
    );
    assert_eq!(last["data"]["text"], "é".repeat(452));
    assert_eq!(last["data"]["next_start"], Value::Null);
    replace_catalog(
        &path,
        "assembly_links",
        &[
            json!({"assembly":"App","package":"Pkg/1","target":"net10.0","basis":"runtime"}),
            json!({"assembly":"App","package":"Pkg/1","target":"net10.0","basis":"compile"}),
        ],
    );
    let origins = query(
        "origins",
        &path,
        &[
            "--assembly",
            "App",
            "--package",
            "Pkg/1",
            "--target",
            "net10.0",
            "--limit",
            "1",
        ],
    );
    assert_eq!(
        origins["next_command"],
        format!(
            "vitnet --memory-limit 134217728B --format json --progress never explore origins '{quoted}' --assembly 'App' --package 'Pkg/1' --target 'net10.0' --after 0 --limit 1 --max-batches 20 --timeout-ms 30000 --generation '{}'",
            origins["generation"].as_str().unwrap()
        )
    );
    let path2 = fixture.join("second");
    fs::create_dir(&path2).unwrap();
    let second = mapped(&path2);
    let families = query("records", &second, &["generic_families"]);
    let family = entries(&families)
        .iter()
        .find(|v| v["fields"]["family"] == "App_Box<>__Run<>")
        .unwrap();
    let family_record = family["ordinal"].as_str().unwrap();
    let value = query(
        "contributors",
        &second,
        &["--family-record", family_record, "--limit", "1"],
    );
    assert!(value["next_command"].as_str().unwrap().contains(&format!(
        "--family-record {family_record} --after 4 --limit 1"
    )));
}

#[test]
fn query_budget_last_accepted_boundaries_and_sixty_four_step_path() {
    let root = tempfile::tempdir().unwrap();
    let path = bundle(root.path(), &evidence(), Some(&seed()));
    for (flag, size) in [
        ("--contains", 1024),
        ("--stream", 64),
        ("--assembly", 4096),
        ("--owner", 4096),
        ("--family", 4096),
    ] {
        let value = query("contributors", &path, &[flag, &"x".repeat(size)]);
        assert_eq!(entries(&value), [] as [Value; 0]);
        assert_eq!(value["data"]["stop_reason"], "complete");
    }
    for flag in ["--assembly", "--package", "--target"] {
        let value = query("origins", &path, &[flag, &"x".repeat(4096)]);
        assert_eq!(entries(&value), [] as [Value; 0]);
        assert_eq!(value["data"]["stop_reason"], "complete");
    }
    let key = "k".repeat(128);
    let text = "v".repeat(4096);
    let record = json!({key.clone():text.clone(),"k1":1,"k2":2,"k3":3,"k4":4,"k5":5,"k6":6,"k7":7});
    replace_catalog(&path, "provenance", &[record]);
    let filters: Vec<_> = std::iter::once(format!("{key}={text}"))
        .chain((1..8).map(|i| format!("k{i}={i}")))
        .collect();
    let mut tail = vec!["provenance"];
    for filter in &filters {
        tail.extend(["--filter", filter]);
    }
    let value = query("records", &path, &tail);
    assert_eq!(ordinals(&value), [0]);
    assert_eq!(value["data"]["stop_reason"], "complete");
    let mut deep = json!("leaf");
    for _ in 0..64 {
        deep = json!([deep]);
    }
    replace_catalog(&path, "provenance", &[deep]);
    let positional = vec!["0"; 64].join(",");
    let value = query(
        "inspect",
        &path,
        &["0", "--dataset", "provenance", "--path", &positional],
    );
    assert_eq!(value["data"]["kind"], "string");
    assert_eq!(value["data"]["text"], "leaf");
    assert_eq!(value["data"]["next_start"], Value::Null);
}

#[test]
fn captured_graph_catalog_records_and_inspection_keep_node_ids_and_csr_ordinals() {
    let root = tempfile::tempdir().unwrap();
    let graph = root.path().join("tiny.dgml");
    fs::write(&graph,r#"<DirectedGraph><Nodes><Node Id="9" Label="root"/><Node Id="2" Label="target"/><Node Id="7" Label="unused"/></Nodes><Links><Link Source="9" Target="2" Reason="edge-reason"/></Links></DirectedGraph>"#).unwrap();
    let built = vitnet_dgml::build_index(
        &graph,
        &vitnet_dgml::IndexOptions {
            cache_root: root.path().join("graph-cache"),
            memory_limit: 16 << 20,
            selected_entry: None,
            strict_hash: false,
            control: IndexControl::default(),
        },
    )
    .unwrap();
    let mut value = evidence();
    value
        .artifacts
        .push(artifact("scan_index", built.index_directory));
    let path = bundle(root.path(), &value, None);
    let catalog = query("datasets", &path, &[]);
    for (name, count) in [("graph_scan_index_nodes", 3), ("graph_scan_index_edges", 1)] {
        let descriptor = catalog["data"]["datasets"]
            .as_array()
            .unwrap()
            .iter()
            .find(|v| v["name"] == name)
            .unwrap();
        assert_eq!(descriptor["records"], count);
        assert_eq!(descriptor["storage"], "immutable_graph");
    }
    let first = query(
        "records",
        &path,
        &["graph_scan_index_nodes", "--limit", "1"],
    );
    assert_eq!(ordinals(&first), [2]);
    assert_eq!(entries(&first)[0]["summary"], "target");
    assert_eq!(first["data"]["next_after"], "2");
    assert_eq!(first["data"]["order"], "node_id");
    let rest = query(
        "records",
        &path,
        &["graph_scan_index_nodes", "--after", "2"],
    );
    assert_eq!(ordinals(&rest), [7, 9]);
    assert_eq!(rest["data"]["stop_reason"], "complete");
    let edges = query("records", &path, &["graph_scan_index_edges"]);
    assert_eq!(ordinals(&edges), [0]);
    assert_eq!(entries(&edges)[0]["summary"], "9 -> 2: edge-reason");
    assert_eq!(edges["data"]["order"], "global_csr_edge_ordinal");
    let node = query(
        "inspect",
        &path,
        &["9", "--dataset", "graph_scan_index_nodes"],
    );
    let label = child(&node, "label");
    assert_eq!(
        query(
            "inspect",
            &path,
            &["9", "--dataset", "graph_scan_index_nodes", "--path", &label]
        )["data"]["text"],
        "root"
    );
    let edge = query(
        "inspect",
        &path,
        &["0", "--dataset", "graph_scan_index_edges"],
    );
    let reason = child(&edge, "reason");
    assert_eq!(
        query(
            "inspect",
            &path,
            &[
                "0",
                "--dataset",
                "graph_scan_index_edges",
                "--path",
                &reason
            ]
        )["data"]["text"],
        "edge-reason"
    );
    expect_error(
        "records",
        &path,
        &["graph_scan_index_nodes", "--filter", "label=root"],
        "explorer.query",
    );
    expect_error(
        "records",
        &path,
        &["graph_codegen_index_nodes"],
        "explorer.graph.missing",
    );
}

#[test]
fn continuation_terminal_controls_and_apostrophes_preserve_exact_selector_expressions() {
    let root = tempfile::tempdir().unwrap();
    let selector = "a'\n\u{1b}\u{202e}z";
    let rows = [
        row("Methods", &format!("Owner__{selector}1"), 1, true),
        row("Methods", &format!("Owner__{selector}2"), 2, true),
    ];
    let path = bundle(root.path(), &evidence(), Some(&rows));
    let value = query(
        "contributors",
        &path,
        &["--contains", selector, "--limit", "1"],
    );
    assert_eq!(ordinals(&value), [1]);
    let next = value["next_command"].as_str().unwrap();
    assert!(
        next.contains("--contains ('a''' + [char]10 + '' + [char]27 + '' + [char]8238 + 'z')"),
        "{next}"
    );
    assert!(next.contains("--after 0 --limit 1"));
    assert!(next.starts_with(
        "vitnet --memory-limit 134217728B --format json --progress never explore contributors "
    ));
    for control in ['\n', '\u{1b}', '\u{202e}'] {
        assert!(!next.contains(control), "{next}");
    }
    let table = output(
        "table",
        "contributors",
        &path,
        &["--contains", selector, "--limit", "1"],
    );
    assert!(table.contains("Continue (PowerShell):"));
    assert!(
        table.contains("[char]10") && table.contains("[char]27") && table.contains("[char]8238")
    );
    assert!(!table.contains('\u{1b}') && !table.contains('\u{202e}'));
}

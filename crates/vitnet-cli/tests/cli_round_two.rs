//! Independent public-CLI regressions for the ten investigation improvements.
//! All evidence is synthetic and confined to disposable directories.
use clap::Parser;
use serde_json::{Value, json};
use std::fs;
use std::path::{Path, PathBuf};
use vitnet_attribution::model::{
    Artifact, Binary, EVIDENCE_SCHEMA, Evidence, Generator, Mapping, Resource, Source,
};
use vitnet_cli::explorer::data;
use vitnet_cli::{AppError, Cli, execute, execute_with_index_control};
use vitnet_core::{ByteSize, OptionError};
use vitnet_dgml::IndexControl;
use vitnet_mstat::CoalescedIdentity;

#[allow(dead_code)]
#[path = "../../vitnet-attribution/tests/common/mod.rs"]
mod common;

const MEMORY: u64 = 128 << 20;

fn evidence() -> Evidence {
    Evidence {
        schema: EVIDENCE_SCHEMA.into(),
        label: "Independent round-two fixture".into(),
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
        records: 1,
        accounted,
        identity_lossy: false,
        raw_identity_blake3: blake3::hash(identity.as_bytes()).to_hex().to_string(),
    }
}

fn seed() -> Vec<CoalescedIdentity> {
    vec![
        row("Methods", "Owner__Small", 999, true),
        row("Methods", "Owner__EqualA", 1000, true),
        row("Methods", "Owner__EqualB", 1000, true),
        row("Methods", "Owner__Large", 1024, true),
        row("Methods", "Owner__Zero", 0, true),
        row("FrozenObjects", "Owner__Overlap", 9000, false),
        row("Types", "Other", 1001, true),
    ]
}

fn bundle(root: &Path, value: &Evidence, rows: Option<&[CoalescedIdentity]>) -> PathBuf {
    fs::create_dir_all(root).unwrap();
    let input = root.join("evidence.json");
    write_json(&input, value);
    let index = root.join("index");
    vitnet_attribution::import(&input, &index, MEMORY, false).unwrap();
    if let Some(rows) = rows {
        let mut payload = Vec::new();
        for value in rows {
            payload.extend(serde_json::to_vec(value).unwrap());
            payload.push(b'\n');
        }
        fs::write(index.join("identities.ndjson"), &payload).unwrap();
        let mut manifest = read_json(&index.join("index.json"));
        manifest["identities"] = json!(rows.len());
        manifest["identities_blake3"] = json!(blake3::hash(&payload).to_hex().to_string());
        write_json(&index.join("index.json"), &manifest);
    }
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

fn measured(root: &Path, method: i32, metadata: Option<i32>, resource: Option<i32>) -> Evidence {
    fs::create_dir_all(root).unwrap();
    let mut image = common::Image::new();
    image.method(b"Owner__Run", method);
    for (name, bytes) in [("Metadata", metadata), ("ResourceData", resource)] {
        if let Some(bytes) = bytes {
            image.blob(&name.encode_utf16().collect::<Vec<_>>(), bytes);
        }
    }
    let path = root.join("reported.mstat");
    fs::write(&path, image.bytes()).unwrap();
    let mut value = evidence();
    value.artifacts.push(Artifact {
        kind: "mstat".into(),
        path,
        revision: None,
        blake3: None,
    });
    value
}

fn captured(root: &Path) -> Evidence {
    let mut value = measured(root, 120, Some(30), Some(50));
    value.binaries.push(Binary {
        path: "captured-only.exe".into(),
        format: "PE".into(),
        architecture: "x64".into(),
        file_bytes: 500,
        ..Binary::default()
    });
    value.resources = vec![
        Resource {
            assembly: "App".into(),
            container: "App.resources".into(),
            name: "asset".into(),
            bytes: 7,
            storage: "asset".into(),
            ..Resource::default()
        },
        Resource {
            assembly: "App".into(),
            container: "App.resources".into(),
            name: "container".into(),
            bytes: 40,
            storage: "manifest_container".into(),
            ..Resource::default()
        },
    ];
    value.sources.push(Source {
        assembly: "App".into(),
        type_name: "Box".into(),
        member: Some("Run".into()),
        path: "not-fetched source.cs".into(),
        line: 17,
        end_line: 23,
        kind: "method".into(),
        generated_by: Some("CapturedGenerator".into()),
        ..Source::default()
    });
    value.generators.push(Generator {
        name: "CapturedGenerator".into(),
        version: "1".into(),
        assembly_path: "not-fetched generator.dll".into(),
        generated_files: vec!["not-fetched source.cs".into()],
        input_symbols: vec!["App.Box".into()],
    });
    value.mappings.push(Mapping {
        stream: "Methods".into(),
        identity: "App_Box<int>__Run<long>".into(),
        assembly: "App".into(),
        source_paths: vec!["not-fetched source.cs".into()],
        basis: "fixed_explicit_evidence".into(),
    });
    value
}

fn captured_rows() -> Vec<CoalescedIdentity> {
    let mut lossy = row("FrozenObjects", "App_Broken\u{fffd}<int>", 15, false);
    lossy.identity_lossy = true;
    vec![
        row("Methods", "App_Box<int>__Run<long>", 120, true),
        row("Blobs", "Metadata", 30, true),
        row("Blobs", "ResourceData", 50, true),
        row("FrozenObjects", "App_Overlap", 250, false),
        row("Methods", "App_Zero", 0, true),
        lossy,
        row("Blobs", "UnknownBucket", 0, true),
    ]
}

fn summary_at<'a>(page: &'a Value, key: &str) -> &'a Value {
    &page["entries"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["key"] == key)
        .unwrap_or_else(|| panic!("missing {key}: {page}"))["summary"]
}

fn parse(format: &str, tail: &[&str]) -> Cli {
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
    ];
    args.extend_from_slice(tail);
    Cli::try_parse_from(args).unwrap()
}

fn output(format: &str, tail: &[&str]) -> String {
    execute(&parse(format, tail)).unwrap()
}

fn query(command: &str, path: &Path, extra: &[&str]) -> Value {
    let mut tail = vec![command, path.to_str().unwrap()];
    tail.extend_from_slice(extra);
    let value: Value = serde_json::from_str(&output("json", &tail)).unwrap();
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
        .map(|value| value["ordinal"].as_u64().unwrap())
        .collect()
}

fn code(error: &AppError) -> &str {
    match error {
        AppError::Unsupported(value)
        | AppError::Resource(value)
        | AppError::IoDiagnostic(value) => &value.code,
        AppError::Dgml(value) => &value.diagnostic.code,
        other => panic!("unexpected diagnostic: {other}"),
    }
}

fn expect_error(format: &str, tail: &[&str], expected: &str) {
    let error = execute(&parse(format, tail)).unwrap_err();
    assert_eq!(code(&error), expected, "{error}");
}

#[test]
fn accounted_filter_keeps_rank_cursors_order_and_parent_denominator() {
    let root = tempfile::tempdir().unwrap();
    let path = bundle(root.path(), &evidence(), Some(&seed()));
    assert_eq!(
        ordinals(&query("contributors", &path, &[])),
        [5, 3, 6, 1, 2, 0, 4]
    );
    let page = query("contributors", &path, &["--accounted-only", "--limit", "2"]);
    assert_eq!(ordinals(&page), [3, 6]);
    assert_eq!(page["data"]["scanned"], 3);
    assert_eq!(page["data"]["next_after"], "2");
    assert_eq!(page["data"]["scope"]["bytes"], 5024);
    assert_eq!(page["data"]["scope"]["identities"], 6);
    assert_eq!(page["data"]["total"], 7);
    assert!(
        entries(&page)
            .iter()
            .all(|entry| entry["accounted"] == true)
    );
    let next = page["next_command"].as_str().unwrap();
    assert!(next.contains("--accounted-only"), "{next}");
    assert!(next.contains("--after 2"), "{next}");
    assert!(next.contains("--generation"), "{next}");
    let rest = query("contributors", &path, &["--accounted-only", "--after", "2"]);
    assert_eq!(ordinals(&rest), [1, 2, 0, 4]);
    assert_eq!(rest["data"]["scope"]["bytes"], 5024);
    assert_eq!(rest["data"]["stop_reason"], "complete");
    assert_eq!(rest["next_command"], Value::Null);
    let overlap = query(
        "contributors",
        &path,
        &["--accounted-only", "--stream", "FrozenObjects"],
    );
    assert_eq!(ordinals(&overlap), Vec::<u64>::new());
    assert_eq!(overlap["data"]["scanned"], 7);
}

#[test]
fn thresholds_are_inclusive_human_sized_and_intersect_before_paging() {
    let root = tempfile::tempdir().unwrap();
    let path = bundle(root.path(), &evidence(), Some(&seed()));
    for (min, max, expected) in [
        ("1KB", "1KB", vec![1, 2]),
        ("999B", "1001B", vec![6, 1, 2, 0]),
        ("1001B", "1KiB", vec![3, 6]),
        ("0B", "0B", vec![4]),
        ("1025B", "8999B", vec![]),
    ] {
        let value = query(
            "contributors",
            &path,
            &["--min-bytes", min, "--max-bytes", max],
        );
        assert_eq!(ordinals(&value), expected, "{min}..={max}");
        assert_eq!(value["data"]["scope"]["bytes"], 5024);
        assert_eq!(value["data"]["stop_reason"], "complete");
    }
    assert_eq!(
        ordinals(&query("contributors", &path, &["--min-bytes", "1KiB"])),
        [5, 3]
    );
    assert_eq!(
        ordinals(&query("contributors", &path, &["--max-bytes", "999B"])),
        [0, 4]
    );
    let selected = query(
        "contributors",
        &path,
        &[
            "--min-bytes",
            "1KB",
            "--max-bytes",
            "1KiB",
            "--stream",
            "Methods",
            "--contains",
            "Equal",
            "--accounted-only",
            "--limit",
            "1",
            "--max-batches",
            "3",
            "--timeout-ms",
            "12345",
        ],
    );
    assert_eq!(ordinals(&selected), [1]);
    assert_eq!(selected["data"]["scanned"], 4);
    assert_eq!(selected["data"]["next_after"], "3");
    assert_eq!(selected["data"]["scope"]["bytes"], 4023);
    let next = selected["next_command"].as_str().unwrap();
    for expected in [
        "--min-bytes",
        "--max-bytes",
        "--accounted-only",
        "--stream 'Methods'",
        "--contains 'Equal'",
        "--limit 1",
        "--max-batches 3",
        "--timeout-ms 12345",
        "--progress never",
        "--format json",
        "--memory-limit",
    ] {
        assert!(next.contains(expected), "{expected}: {next}");
    }
}

#[test]
fn filters_handle_empty_singleton_and_zero_rankings() {
    for rows in [vec![], vec![row("Methods", "Single", 0, true)]] {
        let root = tempfile::tempdir().unwrap();
        let path = bundle(root.path(), &evidence(), Some(&rows));
        let value = query(
            "contributors",
            &path,
            &[
                "--accounted-only",
                "--min-bytes",
                "0B",
                "--max-bytes",
                "0B",
                "--limit",
                "1",
            ],
        );
        assert_eq!(
            ordinals(&value),
            if rows.is_empty() { vec![] } else { vec![0] }
        );
        assert_eq!(value["data"]["scanned"], rows.len());
        assert_eq!(value["data"]["stop_reason"], "complete");
        assert_eq!(value["data"]["next_after"], Value::Null);
    }
}

#[test]
fn threshold_invalid_and_inverted_ranges_are_diagnosed() {
    for flag in ["--min-bytes", "--max-bytes"] {
        for invalid in ["-1B", "oops", "1XB", "18446744073709551616B"] {
            let argument = format!("{flag}={invalid}");
            let args = ["vitnet", "explore", "contributors", "unused", &argument];
            let error = Cli::try_parse_from(args).unwrap_err();
            assert!(error.to_string().contains(flag), "{error}");
        }
    }
    let root = tempfile::tempdir().unwrap();
    let path = bundle(root.path(), &evidence(), Some(&seed()));
    expect_error(
        "json",
        &[
            "contributors",
            path.to_str().unwrap(),
            "--min-bytes",
            "1001B",
            "--max-bytes",
            "1KB",
        ],
        "explorer.query",
    );
}

#[test]
fn exact_matches_complete_identity_not_display_preview() {
    let root = tempfile::tempdir().unwrap();
    let long = format!("{}__Tail", "X".repeat(600));
    let rows = [
        row("Methods", "Owner__Run", 20, true),
        row("Methods", "Owner__RunMore", 30, true),
        row("Types", "Owner__Run", 10, true),
        row("Methods", &long, 40, true),
    ];
    let path = bundle(root.path(), &evidence(), Some(&rows));
    assert_eq!(
        ordinals(&query("contributors", &path, &["--contains", "Owner__Run"])),
        [1, 0, 2]
    );
    assert_eq!(
        ordinals(&query(
            "contributors",
            &path,
            &["--contains", "Owner__Run", "--exact"]
        )),
        [0, 2]
    );
    for selector in ["owner__Run", "Run", &long[..512]] {
        assert_eq!(
            ordinals(&query(
                "contributors",
                &path,
                &["--contains", selector, "--exact"]
            )),
            Vec::<u64>::new(),
            "{selector}"
        );
    }
    let selected = query("contributors", &path, &["--contains", &long, "--exact"]);
    assert_eq!(ordinals(&selected), [3]);
    assert_eq!(entries(&selected)[0]["identity"], "X".repeat(512));
    assert_eq!(entries(&selected)[0]["identity_bytes"], 606);
    assert_eq!(entries(&selected)[0]["truncated"], true);
    let page = query(
        "contributors",
        &path,
        &["--contains", "Owner__Run", "--exact", "--limit", "1"],
    );
    assert_eq!(ordinals(&page), [0]);
    let next = page["next_command"].as_str().unwrap();
    assert!(next.contains("--exact"), "{next}");
    assert!(next.contains("--contains 'Owner__Run'"), "{next}");
}

#[test]
fn exact_empty_and_selector_size_boundaries() {
    let root = tempfile::tempdir().unwrap();
    let boundary = "a".repeat(1024);
    let rows = [
        row("Methods", "", 0, true),
        row("Methods", &boundary, 1, true),
    ];
    let path = bundle(root.path(), &evidence(), Some(&rows));
    assert_eq!(ordinals(&query("contributors", &path, &[])), [1, 0]);
    assert_eq!(ordinals(&query("contributors", &path, &["--exact"])), [0]);
    assert_eq!(
        ordinals(&query(
            "contributors",
            &path,
            &["--exact", "--contains", &boundary]
        )),
        [1]
    );
    for exact in [false, true] {
        let oversize = "a".repeat(1025);
        let mut tail = vec![
            "contributors",
            path.to_str().unwrap(),
            "--contains",
            &oversize,
        ];
        if exact {
            tail.push("--exact");
        }
        expect_error("json", &tail, "resource.explorer.query");
    }
}

#[test]
fn columns_are_ordered_table_only_and_continuations_preserve_selectors() {
    let root = tempfile::tempdir().unwrap();
    let value = measured(root.path(), 5024, Some(0), None);
    let path = bundle(root.path(), &value, Some(&seed()));
    let base = [
        "contributors",
        path.to_str().unwrap(),
        "--accounted-only",
        "--limit",
        "1",
    ];
    let default = output("table", &base);
    assert!(default.contains("Ordinal       Size           % total   % parent  Cumul % parent Role       Stream    Identity preview"), "{default}");
    let mut selected = base.to_vec();
    selected.extend(["--columns", "identity,bytes,ordinal"]);
    let table = output("table", &selected);
    assert!(table.contains("\nIDENTITY  BYTES  ORDINAL\n"), "{table}");
    assert!(table.contains("Owner__Large  1024  3\n"), "{table}");
    assert!(!table.contains("Cumul % parent"), "{table}");
    assert!(
        table.contains("--columns 'identity,bytes,ordinal'"),
        "{table}"
    );
    let mut all = base.to_vec();
    all.extend([
        "--columns",
        "ordinal,size,bytes,total,parent,cumulative,role,stream,identity",
    ]);
    let table = output("table", &all);
    assert!(
        table.contains(
            "\nORDINAL  SIZE  BYTES  TOTAL  PARENT  CUMULATIVE  ROLE  STREAM  IDENTITY\n"
        ),
        "{table}"
    );
    // Accounted totals are reconstructed from the complete cache, not just the
    // single row selected for display: 1024 / 5024 -> 20.38%.
    assert!(
        table.contains("3  1.02 KB  1024  20.38%  20.38%  20.38%  Additive  Methods  Owner__Large"),
        "{table}"
    );
    for format in ["json", "ndjson"] {
        expect_error(format, &selected, "explorer.columns.format");
    }
}

#[test]
fn columns_reject_unknown_duplicate_and_empty_choices() {
    for columns in ["bogus", "identity,bogus", "", "identity,,bytes", "Identity"] {
        let error = Cli::try_parse_from([
            "vitnet",
            "explore",
            "contributors",
            "unused",
            "--columns",
            columns,
        ])
        .unwrap_err();
        assert!(error.to_string().contains("--columns"), "{error}");
    }
    let root = tempfile::tempdir().unwrap();
    let path = bundle(root.path(), &evidence(), Some(&seed()));
    for columns in ["bytes,bytes", "identity,bytes,identity"] {
        expect_error(
            "table",
            &["contributors", path.to_str().unwrap(), "--columns", columns],
            "explorer.columns",
        );
    }
}

fn graph_artifact(root: &Path) -> Artifact {
    let graph = root.join("captured.dgml");
    fs::write(
        &graph,
        r#"<DirectedGraph><Nodes><Node Id="0" Label="root"/><Node Id="1" Label="unused"/></Nodes><Links/></DirectedGraph>"#,
    )
    .unwrap();
    let built = vitnet_dgml::build_index(
        &graph,
        &vitnet_dgml::IndexOptions {
            cache_root: root.join("graph-cache"),
            memory_limit: 16 << 20,
            selected_entry: None,
            strict_hash: false,
            control: IndexControl::default(),
        },
    )
    .unwrap();
    Artifact {
        kind: "scan_index".into(),
        path: built.index_directory,
        revision: None,
        blake3: None,
    }
}

fn dataset_names(value: &Value) -> Vec<&str> {
    value["data"]["datasets"]
        .as_array()
        .unwrap()
        .iter()
        .map(|item| item["name"].as_str().unwrap())
        .collect()
}

#[test]
#[allow(clippy::too_many_lines)] // One catalog fixture contrasts intersecting selectors, zeros and stable full totals.
fn datasets_filter_literal_storage_nonempty_preserving_full_totals() {
    let root = tempfile::tempdir().unwrap();
    let mut value = evidence();
    value.artifacts.push(graph_artifact(root.path()));
    value.sources.push(Source {
        path: "not-fetched.cs".into(),
        assembly: "App".into(),
        type_name: "Owner".into(),
        line: 1,
        end_line: 2,
        kind: "type".into(),
        ..Source::default()
    });
    let path = bundle(root.path(), &value, Some(&seed()));
    let full = query("datasets", &path, &[]);
    let total = dataset_names(&full).len();
    assert!(total > 10);
    assert_eq!(full["data"]["total_datasets"], total);
    assert_eq!(full["data"]["returned_datasets"], total);
    assert_eq!(
        full["data"]["selection"],
        json!({"contains":"","storage":null,"nonempty":false})
    );
    let identities = query("datasets", &path, &["--storage", "original-index"]);
    assert_eq!(dataset_names(&identities), ["identities"]);
    assert_eq!(identities["data"]["datasets"][0]["records"], 7);
    assert_eq!(identities["data"]["total_datasets"], total);
    assert_eq!(identities["data"]["returned_datasets"], 1);
    let graph = query("datasets", &path, &["--storage", "immutable-graph"]);
    assert_eq!(
        dataset_names(&graph),
        ["graph_scan_index_nodes", "graph_scan_index_edges"]
    );
    assert_eq!(graph["data"]["datasets"][0]["records"], 2);
    assert_eq!(graph["data"]["datasets"][1]["records"], 0);
    let nonempty = query(
        "datasets",
        &path,
        &[
            "--storage",
            "immutable-graph",
            "--contains",
            "scan_index",
            "--nonempty",
        ],
    );
    assert_eq!(dataset_names(&nonempty), ["graph_scan_index_nodes"]);
    assert_eq!(nonempty["data"]["total_datasets"], total);
    assert_eq!(nonempty["data"]["returned_datasets"], 1);
    assert_eq!(nonempty["data"]["complete"], true);
    assert_eq!(
        nonempty["data"]["selection"],
        json!({"contains":"scan_index","storage":"immutable_graph","nonempty":true})
    );
    let sources = query(
        "datasets",
        &path,
        &["--storage", "bundle", "--contains", "sources", "--nonempty"],
    );
    assert_eq!(dataset_names(&sources), ["sources"]);
    assert_eq!(sources["data"]["datasets"][0]["records"], 1);
    for contains in ["Sources", "source.*", "not_captured"] {
        let empty = query("datasets", &path, &["--contains", contains]);
        assert_eq!(dataset_names(&empty), Vec::<&str>::new());
        assert_eq!(empty["data"]["total_datasets"], total);
        assert_eq!(empty["data"]["returned_datasets"], 0);
        assert_eq!(empty["data"]["complete"], true);
    }
    let filtered = query("datasets", &path, &["--contains", "packages", "--nonempty"]);
    assert_eq!(dataset_names(&filtered), Vec::<&str>::new());
    assert_eq!(filtered["data"]["ranking_available"], true);
    let table = output(
        "table",
        &["datasets", path.to_str().unwrap(), "--contains", "Sources"],
    );
    assert!(
        table.contains(&format!("0 / {total} captured datasets")),
        "{table}"
    );
    assert!(
        table.contains("No captured dataset matches these discovery filters."),
        "{table}"
    );
    assert_eq!(table.matches("Dataset selection:").count(), 1, "{table}");
    let nonempty_table = output(
        "table",
        &[
            "datasets",
            path.to_str().unwrap(),
            "--storage",
            "immutable-graph",
        ],
    );
    assert_eq!(
        nonempty_table.matches("Dataset selection:").count(),
        1,
        "{nonempty_table}"
    );
    assert!(
        nonempty_table.contains(&format!("2 / {total} captured datasets")),
        "{nonempty_table}"
    );
    let ndjson: Value = serde_json::from_str(&output(
        "ndjson",
        &[
            "datasets",
            path.to_str().unwrap(),
            "--storage",
            "original-index",
        ],
    ))
    .unwrap();
    assert_eq!(ndjson, identities);
    for invalid in ["Original-Index", "original_index", "disk", ""] {
        let error = Cli::try_parse_from([
            "vitnet",
            "explore",
            "datasets",
            "unused",
            "--storage",
            invalid,
        ])
        .unwrap_err();
        assert!(error.to_string().contains("--storage"), "{error}");
    }
    expect_error(
        "json",
        &[
            "datasets",
            path.to_str().unwrap(),
            "--contains",
            &"x".repeat(1025),
        ],
        "resource.explorer.query",
    );
}

#[test]
fn byte_size_si_binary_case_zero_maximum_and_overflow_boundaries() {
    for (suffix, multiplier) in [
        ("B", 1_u64),
        ("KB", 1000),
        ("MB", 1_000_000),
        ("GB", 1_000_000_000),
        ("TB", 1_000_000_000_000),
        ("PB", 1_000_000_000_000_000),
        ("EB", 1_000_000_000_000_000_000),
        ("KiB", 1 << 10),
        ("MiB", 1 << 20),
        ("GiB", 1 << 30),
        ("TiB", 1 << 40),
        ("PiB", 1 << 50),
        ("EiB", 1 << 60),
    ] {
        for spelling in [suffix.to_owned(), suffix.to_ascii_lowercase()] {
            assert_eq!(format!("0{spelling}").parse::<ByteSize>().unwrap().0, 0);
            assert_eq!(
                format!("1{spelling}").parse::<ByteSize>().unwrap().0,
                multiplier
            );
            assert_eq!(
                format!(" 2{spelling} ").parse::<ByteSize>().unwrap().0,
                2 * multiplier
            );
        }
        let maximum = u64::MAX / multiplier;
        assert_eq!(
            format!("{maximum}{suffix}").parse::<ByteSize>().unwrap().0,
            maximum * multiplier
        );
        if multiplier != 1 {
            let input = format!("{}{suffix}", maximum + 1);
            assert_eq!(
                input.parse::<ByteSize>(),
                Err(OptionError::ByteSizeOverflow(input))
            );
        }
    }
    assert_eq!(
        "18446744073709551615".parse::<ByteSize>().unwrap().0,
        u64::MAX
    );
    for input in [
        "",
        "B",
        "-1B",
        "+1KB",
        "1.5KB",
        "1 KB",
        "1XB",
        "18446744073709551616B",
    ] {
        assert_eq!(
            input.parse::<ByteSize>(),
            Err(OptionError::InvalidByteSize(input.into()))
        );
    }
}

fn glossary(extra: &[&str]) -> Value {
    let mut tail = vec!["glossary"];
    tail.extend_from_slice(extra);
    let value: Value = serde_json::from_str(&output("json", &tail)).unwrap();
    assert_eq!(value["schema"], "vitnet.explorer-cli.v1");
    assert_eq!(value["operation"], "glossary");
    assert_eq!(value["generation"], Value::Null);
    value
}

fn bucket_names(value: &Value) -> Vec<&str> {
    value["data"]["buckets"]
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect()
}

#[test]
fn glossary_has_nine_pinned_buckets_exact_names_and_machine_coherence() {
    let full = glossary(&[]);
    assert_eq!(full["data"]["total_buckets"], 9);
    assert_eq!(full["data"]["returned_buckets"], 9);
    assert_eq!(
        bucket_names(&full),
        [
            "ArrayOfFrozenObjects",
            "DehydratedData",
            "ExternalReferencesTable",
            "GenericMethodsHashtable",
            "Metadata",
            "MethodGenericDictionary",
            "ReflectionInvokeMap",
            "ResourceData",
            "TypeGenericDictionary",
        ]
    );
    let selected = glossary(&["Metadata"]);
    assert_eq!(bucket_names(&selected), ["Metadata"]);
    assert_eq!(selected["data"]["returned_buckets"], 1);
    let bucket = &selected["data"]["buckets"]["Metadata"];
    assert_eq!(bucket["title"], "Native reflection metadata");
    assert_eq!(
        bucket["description"],
        "Encoded NativeAOT metadata for retained types, methods, fields, signatures and constants."
    );
    assert_eq!(bucket["view"], "Evidence");
    assert!(
        bucket["source"]
            .as_str()
            .unwrap()
            .contains("2eb7113245f7c536ab876dca5e3533fb96c81bbf")
    );
    let machine: Value =
        serde_json::from_str(&output("ndjson", &["glossary", "Metadata"])).unwrap();
    assert_eq!(machine, selected);
    let table = output("table", &["glossary", "Metadata"]);
    assert!(
        table.contains("Pinned compiler glossary: 1 / 9 buckets"),
        "{table}"
    );
    assert!(
        table.contains("Metadata: Native reflection metadata"),
        "{table}"
    );
    assert!(
        table.contains(bucket["description"].as_str().unwrap()),
        "{table}"
    );
    for unknown in ["metadata", "Meta", "NotABucket", ""] {
        expect_error("json", &["glossary", unknown], "explorer.glossary");
    }
}

#[test]
fn glossary_searches_names_titles_descriptions_and_investigation_case_insensitively() {
    for (selector, expected) in [
        ("resourcedata", vec!["ResourceData"]),
        ("PREINITIALIZED FROZEN", vec!["ArrayOfFrozenObjects"]),
        ("POINTER RELOCATIONS", vec!["DehydratedData"]),
        (
            "DICTIONARY LAYOUT",
            vec!["MethodGenericDictionary", "TypeGenericDictionary"],
        ),
        ("no such compiler bucket", vec![]),
    ] {
        let selected = glossary(&["--contains", selector]);
        assert_eq!(bucket_names(&selected), expected, "{selector}");
        assert_eq!(selected["data"]["returned_buckets"], expected.len());
        assert_eq!(selected["data"]["total_buckets"], 9);
    }
    assert_eq!(bucket_names(&glossary(&["--contains", ""])).len(), 9);
    let boundary = "z".repeat(1024);
    assert_eq!(bucket_names(&glossary(&["--contains", &boundary])).len(), 0);
    expect_error(
        "json",
        &["glossary", "--contains", &"z".repeat(1025)],
        "resource.explorer.query",
    );
    let table = output(
        "table",
        &["glossary", "--contains", "no such compiler bucket"],
    );
    assert!(
        table.contains("Pinned compiler glossary: 0 / 9 buckets"),
        "{table}"
    );
    assert!(
        table.contains("No pinned compiler bucket matches this search."),
        "{table}"
    );
    let conflict = Cli::try_parse_from([
        "vitnet",
        "explore",
        "glossary",
        "Metadata",
        "--contains",
        "Metadata",
    ])
    .unwrap_err();
    assert_eq!(conflict.kind(), clap::error::ErrorKind::ArgumentConflict);
}

#[test]
fn explain_original_ordinals_roles_source_shape_glossary_and_full_commands() {
    let root = tempfile::tempdir().unwrap();
    let path = bundle(root.path(), &captured(root.path()), Some(&captured_rows()));
    let method = query("explain", &path, &["0"]);
    assert_eq!(method["data"]["identity"]["ordinal"], 0);
    assert_eq!(
        method["data"]["identity"]["identity"],
        "App_Box<int>__Run<long>"
    );
    assert_eq!(method["data"]["identity"]["bytes"], 120);
    assert_eq!(method["data"]["identity"]["accounted"], true);
    assert_eq!(method["data"]["accounted_total_bytes"], 200);
    assert_eq!(method["data"]["source"]["kind"], "object");
    assert_eq!(summary_at(&method["data"]["source"], "sources"), "1 items");
    assert_eq!(
        summary_at(&method["data"]["source"], "assemblies"),
        "1 items"
    );
    assert_eq!(method["data"]["shape"]["status"], "available");
    assert_eq!(method["data"]["shape"]["page"]["kind"], "object");
    assert_eq!(
        summary_at(&method["data"]["shape"]["page"], "family"),
        "App_Box<>__Run<>"
    );
    assert_eq!(
        summary_at(&method["data"]["shape"]["page"], "arguments"),
        "2 items"
    );
    assert_eq!(method["data"]["bucket"], Value::Null);
    let generation = method["generation"].as_str().unwrap();
    for view in ["record", "source", "shape"] {
        let command = method["data"]["commands"][view].as_str().unwrap();
        assert!(command.contains(" explore inspect "), "{command}");
        assert!(
            command.contains(&format!(" 0 --view '{view}'")),
            "{command}"
        );
        assert!(
            command.contains(&format!("--generation '{generation}'")),
            "{command}"
        );
    }
    let table = output("table", &["explain", path.to_str().unwrap(), "0"]);
    assert!(table.contains("role: Additive"), "{table}");
    assert!(table.contains("Size: 120 B"), "{table}");
    assert!(
        table.contains("Share of accounted total: 60.00%"),
        "{table}"
    );
    let overlap = query("explain", &path, &["3"]);
    assert_eq!(overlap["data"]["identity"]["bytes"], 250);
    assert_eq!(overlap["data"]["identity"]["accounted"], false);
    assert_eq!(overlap["data"]["shape"]["status"], "not_generic");
    let table = output("table", &["explain", path.to_str().unwrap(), "3"]);
    assert!(table.contains("role: Overlap"), "{table}");
    assert!(
        table.contains("Share of accounted total: Overlap"),
        "{table}"
    );
    let metadata = query("explain", &path, &["1"]);
    assert_eq!(
        metadata["data"]["bucket"]["title"],
        "Native reflection metadata"
    );
    assert_eq!(metadata["data"]["identity"]["bytes"], 30);
    assert_eq!(
        query("explain", &path, &["6"])["data"]["bucket"],
        Value::Null
    );
    let zero = output("table", &["explain", path.to_str().unwrap(), "4"]);
    assert!(zero.contains("Size: 0 B"), "{zero}");
    assert!(zero.contains("Share of accounted total: 0.00%"), "{zero}");
    let ndjson: Value =
        serde_json::from_str(&output("ndjson", &["explain", path.to_str().unwrap(), "0"])).unwrap();
    assert_eq!(ndjson["data"]["identity"], method["data"]["identity"]);
    assert_eq!(ndjson["data"]["source"], method["data"]["source"]);
    assert_eq!(ndjson["data"]["shape"], method["data"]["shape"]);
}

#[test]
fn explain_lossy_empty_unknown_zero_and_generation_failures_are_explicit() {
    let root = tempfile::tempdir().unwrap();
    let path = bundle(root.path(), &captured(root.path()), Some(&captured_rows()));
    let lossy = query("explain", &path, &["5"]);
    assert_eq!(lossy["data"]["identity"]["identity_lossy"], true);
    assert_eq!(
        lossy["data"]["shape"],
        json!({"status":"unavailable_lossy_identity","page":null})
    );
    assert_eq!(lossy["data"]["commands"]["shape"], Value::Null);
    assert_eq!(
        summary_at(&lossy["data"]["source"], "status"),
        "unmapped_lossy_identity"
    );
    assert_eq!(summary_at(&lossy["data"]["source"], "sources"), "0 items");
    expect_error(
        "json",
        &["explain", path.to_str().unwrap(), "7"],
        "explorer.row",
    );
    expect_error(
        "json",
        &[
            "explain",
            path.to_str().unwrap(),
            "0",
            "--generation",
            "stale",
        ],
        "explorer.generation",
    );
    for ordinal in ["-1", "+1", "1.5", "18446744073709551616"] {
        assert!(Cli::try_parse_from(["vitnet", "explore", "explain", "unused", ordinal]).is_err());
    }
    let empty = bundle(&root.path().join("empty"), &evidence(), Some(&[]));
    expect_error(
        "json",
        &["explain", empty.to_str().unwrap(), "0"],
        "explorer.row",
    );
    let unknown = bundle(
        &root.path().join("unknown"),
        &evidence(),
        Some(&[row("Methods", "Opaque", 0, true)]),
    );
    let value = query("explain", &unknown, &["0"]);
    assert_eq!(value["data"]["accounted_total_bytes"], Value::Null);
    assert_eq!(value["data"]["shape"]["status"], "not_generic");
    assert_eq!(summary_at(&value["data"]["source"], "sources"), "0 items");
    let table = output("table", &["explain", unknown.to_str().unwrap(), "0"]);
    assert!(
        table.contains("Share of accounted total: Unknown"),
        "{table}"
    );
    let zero_value = measured(&root.path().join("zero"), 0, None, None);
    let zero = bundle(&root.path().join("zero"), &zero_value, None);
    assert_eq!(
        query("explain", &zero, &["0"])["data"]["accounted_total_bytes"],
        0
    );
    let table = output("table", &["explain", zero.to_str().unwrap(), "0"]);
    assert!(
        table.contains("Share of accounted total: Unknown"),
        "{table}"
    );
}

#[test]
fn explain_long_identity_many_sources_and_shape_stay_bounded_and_inspectable() {
    let root = tempfile::tempdir().unwrap();
    let identity = format!("App_Box<{}>__Run", vec!["int"; 150].join(","));
    let mut value = measured(root.path(), 1000, None, None);
    value.mappings.push(Mapping {
        stream: "Methods".into(),
        identity: identity.clone(),
        assembly: "App".into(),
        source_paths: vec!["captured-only.cs".into()],
        basis: "fixed_explicit_evidence".into(),
    });
    for line in 1..=150 {
        value.sources.push(Source {
            assembly: "App".into(),
            type_name: "Box".into(),
            member: Some("Run".into()),
            path: "captured-only.cs".into(),
            line,
            end_line: line,
            kind: "method".into(),
            ..Source::default()
        });
    }
    let path = bundle(
        root.path(),
        &value,
        Some(&[row("Methods", &identity, 1000, true)]),
    );
    let explanation = query("explain", &path, &["0"]);
    let data = &explanation["data"];
    assert_eq!(data["identity"]["truncated"], true);
    assert_eq!(data["identity"]["identity_bytes"], identity.len());
    assert_eq!(data["identity"]["identity"].as_str().unwrap().len(), 512);
    assert_eq!(summary_at(&data["source"], "sources"), "150 items");
    assert_eq!(summary_at(&data["shape"]["page"], "arguments"), "150 items");
    assert_eq!(data["source"]["kind"], "object");
    assert_eq!(data["shape"]["page"]["kind"], "object");
    assert!(serde_json::to_vec(data).unwrap().len() < 10_000);
    for (view, key, expected) in [("source", "sources", 150), ("shape", "arguments", 150)] {
        let page = if view == "source" {
            &data["source"]
        } else {
            &data["shape"]["page"]
        };
        let child = page["entries"]
            .as_array()
            .unwrap()
            .iter()
            .find(|item| item["key"] == key)
            .unwrap();
        let position = child["index"].to_string();
        let first = query(
            "inspect",
            &path,
            &["0", "--view", view, "--path", &position],
        );
        assert_eq!(first["data"]["kind"], "array");
        assert_eq!(first["data"]["total"], expected);
        assert_eq!(first["data"]["entries"].as_array().unwrap().len(), 100);
        assert_eq!(first["data"]["next_start"], 100);
        let rest = query(
            "inspect",
            &path,
            &["0", "--view", view, "--path", &position, "--start", "100"],
        );
        assert_eq!(rest["data"]["entries"].as_array().unwrap().len(), 50);
        assert_eq!(rest["data"]["next_start"], Value::Null);
        if view == "shape" {
            assert_eq!(first["data"]["entries"][0]["summary"], "int");
            assert_eq!(rest["data"]["entries"][49]["summary"], "int");
        }
        assert!(
            data["commands"][view]
                .as_str()
                .unwrap()
                .contains(&format!("--view '{view}'"))
        );
    }
}

// Legacy-capture partitions are constructed only in disposable fixtures.
// The production API verifies this independently recomputed fingerprint.
fn legacy_without_catalog_ranking(path: &Path) {
    let mut manifest = read_json(&path.join("bundle.json"));
    let mut snapshot = read_json(&path.join("snapshot.json"));
    manifest.as_object_mut().unwrap().remove("datasets");
    manifest.as_object_mut().unwrap().remove("ranking");
    snapshot.as_object_mut().unwrap().remove("datasets");
    snapshot.as_object_mut().unwrap().remove("ranking");
    write_fingerprinted_snapshot(path, &mut manifest, &mut snapshot);
}

fn write_fingerprinted_snapshot(path: &Path, manifest: &mut Value, snapshot: &mut Value) {
    snapshot["generation"] = Value::Null;
    let mut hash = blake3::Hasher::new();
    hash.update(b"vitnet.explorer-generation.v1\0");
    hash.update(manifest["index_blake3"].as_str().unwrap().as_bytes());
    hash.update(manifest["identities_blake3"].as_str().unwrap().as_bytes());
    hash.update(&serde_json::to_vec(&*snapshot).unwrap());
    let generation = hash.finalize().to_hex().to_string();
    snapshot["generation"] = json!(generation);
    manifest["generation"] = json!(generation);
    let encoded = serde_json::to_vec(&*snapshot).unwrap();
    manifest["snapshot_blake3"] = json!(blake3::hash(&encoded).to_hex().to_string());
    fs::write(path.join("snapshot.json"), encoded).unwrap();
    write_json(&path.join("bundle.json"), manifest);
}

#[test]
fn coverage_distinguishes_complete_capture_bounded_preview_and_missing_physical() {
    let root = tempfile::tempdir().unwrap();
    let rows: Vec<_> = (1..=105)
        .map(|bytes| row("Methods", &format!("Opaque__{bytes}"), bytes, true))
        .collect();
    let path = bundle(
        root.path(),
        &measured(root.path(), 5565, None, None),
        Some(&rows),
    );
    let coverage = query("coverage", &path, &[]);
    let data = &coverage["data"];
    assert_eq!(data["complete_catalog"], true);
    assert_eq!(data["ranking_available"], true);
    assert_eq!(data["identities"], 105);
    assert_eq!(data["accounted_bytes"], 5565);
    assert_eq!(data["physical_bytes"], Value::Null);
    assert_eq!(data["sources_captured"], 0);
    assert_eq!(data["generators_captured"], 0);
    assert_eq!(data["preview"]["contributors_shown"], 100);
    assert_eq!(data["preview"]["displayed_accounted_bytes"], 5550);
    assert_eq!(data["preview"]["remaining_accounted_bytes"], 15);
    assert_eq!(data["graphs"], json!([]));
    let datasets = query("datasets", &path, &[]);
    assert_eq!(data["datasets"], dataset_names(&datasets).len());
    let limitations = data["limitations"].to_string();
    assert!(limitations.contains("not complete original source"));
    assert!(limitations.contains("not capture coverage"));
    assert!(limitations.contains("not a full integrity audit"));
    let table = output("table", &["coverage", path.to_str().unwrap()]);
    assert!(table.contains("Physical inventory: Unknown"), "{table}");
    assert!(
        table.contains("No dependency graph was captured."),
        "{table}"
    );
    assert!(table.contains("Complete byte ranking: true"), "{table}");
    let machine: Value =
        serde_json::from_str(&output("ndjson", &["coverage", path.to_str().unwrap()])).unwrap();
    assert_eq!(machine, coverage);
}

#[test]
fn coverage_reports_source_generator_graph_known_zero_and_legacy_absence() {
    let root = tempfile::tempdir().unwrap();
    let mut value = captured(root.path());
    value.artifacts.push(graph_artifact(root.path()));
    let path = bundle(root.path(), &value, Some(&captured_rows()));
    let full = query("coverage", &path, &[]);
    assert_eq!(full["data"]["sources_captured"], 1);
    assert_eq!(full["data"]["generators_captured"], 1);
    assert_eq!(full["data"]["physical_bytes"], 500);
    assert_eq!(full["data"]["graphs"][0]["kind"], "scan_index");
    assert_eq!(full["data"]["graphs"][0]["node_count"], 2);
    assert_eq!(full["data"]["graphs"][0]["edge_count"], 0);
    for known in [false, true] {
        let sub = root.path().join(if known { "known" } else { "missing" });
        let mut value = if known {
            measured(&sub, 0, None, None)
        } else {
            evidence()
        };
        if known {
            value.binaries.push(Binary {
                path: "zero.exe".into(),
                file_bytes: 0,
                ..Binary::default()
            });
        }
        let empty = bundle(&sub, &value, Some(&[]));
        let coverage = query("coverage", &empty, &[]);
        assert_eq!(coverage["data"]["identities"], 0);
        assert_eq!(coverage["data"]["ranking_available"], true);
        assert_eq!(coverage["data"]["complete_catalog"], true);
        assert_eq!(coverage["data"]["preview"]["contributors_shown"], 0);
        assert_eq!(
            coverage["data"]["accounted_bytes"],
            if known { json!(0) } else { Value::Null }
        );
        assert_eq!(
            coverage["data"]["physical_bytes"],
            if known { json!(0) } else { Value::Null }
        );
    }
    legacy_without_catalog_ranking(&path);
    let legacy = query("coverage", &path, &[]);
    assert_eq!(legacy["data"]["complete_catalog"], false);
    assert_eq!(legacy["data"]["ranking_available"], false);
    assert_eq!(legacy["data"]["identities"], 7);
    assert_eq!(legacy["data"]["accounted_bytes"], 200);
    assert_eq!(legacy["data"]["sources_captured"], 1);
}

fn action<'a>(guide: &'a Value, purpose: &str) -> &'a Value {
    guide["data"]["actions"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["purpose"] == purpose)
        .unwrap_or_else(|| panic!("missing guide action {purpose}: {guide}"))
}

#[test]
fn guide_follows_captured_facts_and_quotes_reproducible_commands() {
    let root = tempfile::tempdir().unwrap();
    let quoted_root = root.path().join("round's $(literal) directory");
    fs::create_dir_all(&quoted_root).unwrap();
    let mut value = captured(&quoted_root);
    value.artifacts.push(graph_artifact(&quoted_root));
    let path = bundle(&quoted_root, &value, Some(&captured_rows()));
    let guide = query("guide", &path, &[]);
    assert_eq!(guide["data"]["missing_physical_measurement"], false);
    assert_eq!(guide["data"]["sources_captured"], 1);
    let largest = action(&guide, "Inspect the largest additive stream");
    assert_eq!(largest["stream"], "Methods");
    assert_eq!(largest["bytes"], 120);
    assert!(
        largest["command"]
            .as_str()
            .unwrap()
            .contains("--accounted-only --stream 'Methods'")
    );
    let resources = action(&guide, "Review embedded resource inventory");
    assert_eq!(resources["dataset"], "resources");
    assert_eq!(resources["records"], 2);
    assert!(
        resources["reason"]
            .as_str()
            .unwrap()
            .contains("may overlap")
    );
    let generic = action(&guide, "Inspect generic amplification");
    assert_eq!(generic["dataset"], "generic_families");
    assert_eq!(generic["records"], 1);
    let graph = action(&guide, "Locate recorded dependency nodes");
    assert!(
        graph["command"]
            .as_str()
            .unwrap()
            .contains("'graph_scan_index_nodes'")
    );
    let quoted_path = format!("'{}'", path.to_str().unwrap().replace('\'', "''"));
    let generation = guide["generation"].as_str().unwrap();
    for item in guide["data"]["actions"].as_array().unwrap() {
        let command = item["command"].as_str().unwrap();
        assert!(
            command.starts_with(
                "vitnet --memory-limit 134217728B --format json --progress never explore "
            ),
            "{command}"
        );
        assert!(command.contains(&quoted_path), "{command}");
        if item["purpose"] != "Check captured evidence coverage" {
            assert!(
                command.contains(&format!("--generation '{generation}'")),
                "{command}"
            );
        }
    }
    assert!(
        guide["data"]["scope"]
            .as_str()
            .unwrap()
            .contains("do not diagnose causes")
    );
    let table = output("table", &["guide", path.to_str().unwrap()]);
    assert!(
        table
            .contains("Largest captured additive stream, not a claimed cause or savings estimate."),
        "{table}"
    );
    assert!(table.contains(&quoted_path), "{table}");
    let ndjson: Value =
        serde_json::from_str(&output("ndjson", &["guide", path.to_str().unwrap()])).unwrap();
    let nd_command = action(&ndjson, "Inspect the largest additive stream")["command"]
        .as_str()
        .unwrap();
    assert!(nd_command.contains("--format ndjson"));
}

#[test]
fn guide_zero_missing_tied_streams_and_legacy_have_honest_actions() {
    let root = tempfile::tempdir().unwrap();
    let missing = bundle(&root.path().join("empty"), &evidence(), Some(&[]));
    let guide = query("guide", &missing, &[]);
    assert_eq!(guide["data"]["missing_physical_measurement"], true);
    assert_eq!(guide["data"]["sources_captured"], 0);
    assert_eq!(guide["data"]["actions"].as_array().unwrap().len(), 3);
    assert_eq!(action(&guide, "Review capture diagnostics")["records"], 1);
    let diagnostics = query("records", &missing, &["diagnostics"]);
    assert_eq!(
        entries(&diagnostics)[0]["fields"]["code"],
        "evidence.mstat.missing"
    );
    let ranking = action(&guide, "Inspect complete captured contributors");
    assert!(
        ranking["reason"]
            .as_str()
            .unwrap()
            .contains("no measured additive stream")
    );
    let table = output("table", &["guide", missing.to_str().unwrap()]);
    assert!(
        table.contains("Absent physical inventory cannot establish executable size"),
        "{table}"
    );
    assert!(
        table.contains("No source declarations are captured"),
        "{table}"
    );
    let sub = root.path().join("zero");
    let mut value = measured(&sub, 0, None, None);
    value.binaries.push(Binary {
        path: "zero.exe".into(),
        file_bytes: 0,
        ..Binary::default()
    });
    let zero = bundle(&sub, &value, None);
    let guide = query("guide", &zero, &[]);
    assert_eq!(guide["data"]["missing_physical_measurement"], false);
    assert_eq!(
        action(&guide, "Inspect the largest additive stream")["bytes"],
        0
    );
    let sub = root.path().join("tied");
    let tied = bundle(&sub, &measured(&sub, 100, Some(100), None), None);
    let guide = query("guide", &tied, &[]);
    assert_eq!(
        action(&guide, "Inspect the largest additive stream")["stream"],
        "Blobs"
    );
    assert_eq!(
        action(&guide, "Inspect the largest additive stream")["bytes"],
        100
    );
    legacy_without_catalog_ranking(&missing);
    let legacy = query("guide", &missing, &[]);
    let fallback = action(&legacy, "Check legacy inputs before preparing a new bundle");
    assert!(
        fallback["command"]
            .as_str()
            .unwrap()
            .contains(" explore verify ")
    );
    assert!(
        fallback["reason"]
            .as_str()
            .unwrap()
            .contains("no complete byte ranking")
    );
    assert!(
        !legacy["data"]["actions"]
            .as_array()
            .unwrap()
            .iter()
            .any(|item| item["command"].as_str().unwrap().contains("contributors"))
    );
}

fn metadata_artifact(root: &Path, last_offset: &str) -> Artifact {
    let path = root.join("metadata.csv");
    fs::write(
                &path,
                format!("Handle, Kind, Name, Children\n00000000, ScopeDefinition, \"App\", \"{last_offset}\"\n{last_offset}, End, \"\", \"\"\n"),
            )
            .unwrap();
    Artifact {
        kind: "metadata".into(),
        path,
        revision: None,
        blake3: None,
    }
}

fn comparison(before: &Path, after: &Path) -> Value {
    let value: Value = serde_json::from_str(&output(
        "json",
        &["compare", before.to_str().unwrap(), after.to_str().unwrap()],
    ))
    .unwrap();
    assert_eq!(value["schema"], "vitnet.explorer-cli.v1");
    assert_eq!(value["operation"], "compare");
    assert_eq!(
        value["generation"],
        read_json(&after.join("bundle.json"))["generation"]
    );
    assert_eq!(
        value["data"]["before_generation"],
        read_json(&before.join("bundle.json"))["generation"]
    );
    assert_eq!(value["data"]["after_generation"], value["generation"]);
    value
}

fn change_at<'a>(comparison: &'a Value, section: &str, name: &str) -> &'a Value {
    comparison["data"][section]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["name"] == name)
        .unwrap_or_else(|| panic!("missing {section}/{name}: {comparison}"))
}

fn expected_change(
    name: &str,
    role: &str,
    before: Option<u64>,
    after: Option<u64>,
    delta: Option<i128>,
    percent: Option<i128>,
) -> Value {
    json!({"name":name,"role":role,"before_bytes":before,"after_bytes":after,
                "delta_bytes":delta,"change_basis_points":percent})
}

#[test]
#[allow(clippy::too_many_lines)] // One before/after fixture pins separate ledger and additive-stream measurements.
fn compare_exact_signed_ledgers_keep_additive_physical_and_overlap_separate() {
    let root = tempfile::tempdir().unwrap();
    let b = root.path().join("before");
    let a = root.path().join("after");
    let mut before = measured(&b, 100, Some(30), Some(50));
    let mut after = measured(&a, 140, Some(10), None);
    before.artifacts.push(metadata_artifact(&b, "00000040"));
    after.artifacts.push(metadata_artifact(&a, "00000020"));
    before.binaries.push(Binary {
        path: "old.exe".into(),
        file_bytes: 500,
        ..Binary::default()
    });
    after.binaries.push(Binary {
        path: "new.exe".into(),
        file_bytes: 0,
        ..Binary::default()
    });
    for (value, asset, container) in [(&mut before, 7, 40), (&mut after, 12, 20)] {
        value.resources = vec![
            Resource {
                name: "asset".into(),
                assembly: "App".into(),
                container: "App.resources".into(),
                bytes: asset,
                storage: "asset".into(),
                ..Resource::default()
            },
            Resource {
                name: "container".into(),
                assembly: "App".into(),
                container: "App.resources".into(),
                bytes: container,
                storage: "manifest_container".into(),
                ..Resource::default()
            },
        ];
    }
    let before = bundle(&b, &before, None);
    let after = bundle(&a, &after, None);
    let result = comparison(&before, &after);
    assert_eq!(
        result["data"]["measurements"],
        json!([
            expected_change(
                "accounted",
                "reported_total",
                Some(180),
                Some(150),
                Some(-30),
                Some(-1667)
            ),
            expected_change(
                "physical",
                "physical_inventory",
                Some(500),
                Some(0),
                Some(-500),
                Some(-10000)
            ),
            expected_change(
                "metadata_lower_bound",
                "overlap",
                Some(64),
                Some(32),
                Some(-32),
                Some(-5000)
            ),
            expected_change(
                "resource_assets",
                "overlap",
                Some(7),
                Some(12),
                Some(5),
                Some(7143)
            ),
            expected_change(
                "resource_containers",
                "overlap",
                Some(40),
                Some(20),
                Some(-20),
                Some(-5000)
            ),
        ])
    );
    assert_eq!(
        result["data"]["streams"],
        json!([
            expected_change(
                "Blobs",
                "additive_stream",
                Some(80),
                Some(10),
                Some(-70),
                Some(-8750)
            ),
            expected_change(
                "Methods",
                "additive_stream",
                Some(100),
                Some(140),
                Some(40),
                Some(4000)
            ),
        ])
    );
    assert!(
        result["data"]["scope"]
            .as_str()
            .unwrap()
            .contains("not identity-level deltas")
    );
    assert!(
        result["data"]["scope"]
            .as_str()
            .unwrap()
            .contains("overlapping projections are not extra additive totals")
    );
    let table = output(
        "table",
        &["compare", before.to_str().unwrap(), after.to_str().unwrap()],
    );
    assert!(
        table.contains(
            "accounted [reported_total]: 180 B -> 150 B; delta -30 B (-30 B); change -16.67%"
        ),
        "{table}"
    );
    assert!(
        table.contains(
            "Methods [additive_stream]: 100 B -> 140 B; delta +40 B (+40 B); change +40.00%"
        ),
        "{table}"
    );
    let ndjson: Value = serde_json::from_str(&output(
        "ndjson",
        &["compare", before.to_str().unwrap(), after.to_str().unwrap()],
    ))
    .unwrap();
    assert_eq!(ndjson, result);
    let same = comparison(&after, &after);
    assert_eq!(
        change_at(&same, "measurements", "accounted"),
        &expected_change(
            "accounted",
            "reported_total",
            Some(150),
            Some(150),
            Some(0),
            Some(0)
        )
    );
    assert_eq!(
        change_at(&same, "measurements", "physical"),
        &expected_change(
            "physical",
            "physical_inventory",
            Some(0),
            Some(0),
            Some(0),
            None
        )
    );
}

#[test]
fn compare_missing_zero_and_stream_absence_are_not_conflated() {
    let root = tempfile::tempdir().unwrap();
    let missing = bundle(&root.path().join("missing"), &evidence(), Some(&[]));
    let sub = root.path().join("zero");
    let mut zero = measured(&sub, 0, None, None);
    zero.binaries.push(Binary {
        path: "zero.exe".into(),
        file_bytes: 0,
        ..Binary::default()
    });
    let zero = bundle(&sub, &zero, None);
    let sub = root.path().join("positive");
    let positive = bundle(&sub, &measured(&sub, 1000, Some(100), None), None);
    let result = comparison(&missing, &positive);
    assert_eq!(
        change_at(&result, "measurements", "accounted"),
        &expected_change("accounted", "reported_total", None, Some(1100), None, None)
    );
    assert_eq!(
        change_at(&result, "streams", "Blobs"),
        &expected_change("Blobs", "additive_stream", None, Some(100), None, None)
    );
    let result = comparison(&zero, &positive);
    assert_eq!(
        change_at(&result, "measurements", "accounted"),
        &expected_change(
            "accounted",
            "reported_total",
            Some(0),
            Some(1100),
            Some(1100),
            None
        )
    );
    assert_eq!(
        change_at(&result, "streams", "Blobs"),
        &expected_change(
            "Blobs",
            "additive_stream",
            Some(0),
            Some(100),
            Some(100),
            None
        )
    );
    assert_eq!(
        change_at(&result, "measurements", "physical"),
        &expected_change("physical", "physical_inventory", Some(0), None, None, None)
    );
    let reversed = comparison(&positive, &zero);
    assert_eq!(
        change_at(&reversed, "streams", "Blobs"),
        &expected_change(
            "Blobs",
            "additive_stream",
            Some(100),
            Some(0),
            Some(-100),
            Some(-10000)
        )
    );
    let missing_after = comparison(&positive, &missing);
    assert_eq!(
        change_at(&missing_after, "measurements", "accounted"),
        &expected_change("accounted", "reported_total", Some(1100), None, None, None)
    );
    let both_missing = comparison(&missing, &missing);
    assert_eq!(
        change_at(&both_missing, "measurements", "physical"),
        &expected_change("physical", "physical_inventory", None, None, None, None)
    );
    assert_eq!(both_missing["data"]["streams"], json!([]));
    // No resource descriptors is a captured empty inventory, not absent
    // physical/accounting measurements: its exact known zero stays zero.
    assert_eq!(
        change_at(&both_missing, "measurements", "resource_assets"),
        &expected_change(
            "resource_assets",
            "overlap",
            Some(0),
            Some(0),
            Some(0),
            None
        )
    );
    let table = output(
        "table",
        &[
            "compare",
            missing.to_str().unwrap(),
            positive.to_str().unwrap(),
        ],
    );
    assert!(
        table.contains(
            "accounted [reported_total]: Unknown -> 1.1 KB (1100 B); delta Unknown; change Unknown"
        ),
        "{table}"
    );
}

#[test]
fn compare_signed_percent_rounding_covers_exact_half_and_adjacent_values() {
    let root = tempfile::tempdir().unwrap();
    let before = bundle(
        &root.path().join("base"),
        &measured(&root.path().join("base"), 20000, None, None),
        None,
    );
    for (after_bytes, expected_basis) in
        [(19998, -1), (19999, -1), (20000, 0), (20001, 1), (20002, 1)]
    {
        let sub = root.path().join(after_bytes.to_string());
        let after = bundle(&sub, &measured(&sub, after_bytes, None, None), None);
        let result = comparison(&before, &after);
        assert_eq!(
            change_at(&result, "measurements", "accounted")["delta_bytes"],
            json!(i128::from(after_bytes) - 20000)
        );
        assert_eq!(
            change_at(&result, "measurements", "accounted")["change_basis_points"],
            expected_basis
        );
    }
}

#[test]
fn new_reports_precancel_without_io_and_glossary_response_cap() {
    let root = tempfile::tempdir().unwrap();
    let path = bundle(root.path(), &captured(root.path()), Some(&captured_rows()));
    let file = path.to_str().unwrap();
    for tail in [
        vec!["explain", file, "0"],
        vec!["coverage", file],
        vec!["guide", file],
        vec!["compare", file, file],
        vec!["glossary"],
    ] {
        let parsed = parse("json", &tail);
        let control = IndexControl::default();
        control.cancel();
        let error = execute_with_index_control(&parsed, &control).unwrap_err();
        assert_eq!(code(&error), "resource.cancelled");
        let fresh = execute_with_index_control(&parsed, &IndexControl::default()).unwrap();
        let report: Value = serde_json::from_str(&fresh).unwrap();
        assert_eq!(report["operation"], tail[0]);
    }
    let absent = root.path().join("never-created");
    for tail in [
        vec!["explain", absent.to_str().unwrap(), "0"],
        vec!["coverage", absent.to_str().unwrap()],
        vec!["guide", absent.to_str().unwrap()],
        vec!["compare", absent.to_str().unwrap(), file],
        vec!["compare", file, absent.to_str().unwrap()],
    ] {
        let control = IndexControl::default();
        control.cancel();
        let error = execute_with_index_control(&parse("json", &tail), &control).unwrap_err();
        assert_eq!(code(&error), "resource.cancelled");
        expect_error("json", &tail, "attribution.io");
    }
    let parsed = Cli::try_parse_from([
        "vitnet",
        "--format",
        "json",
        "--memory-limit",
        "64KiB",
        "--progress",
        "never",
        "explore",
        "glossary",
    ])
    .unwrap();
    let error = execute(&parsed).unwrap_err();
    assert_eq!(code(&error), "resource.explorer.response");
    let small = glossary(&["Metadata"]);
    assert_eq!(small["data"]["returned_buckets"], 1);
}

#[test]
fn selected_columns_keep_overlap_unknowns_and_cumulative_additive_only() {
    let root = tempfile::tempdir().unwrap();
    let path = bundle(
        root.path(),
        &measured(root.path(), 5024, None, None),
        Some(&seed()),
    );
    let table = output(
        "table",
        &[
            "contributors",
            path.to_str().unwrap(),
            "--limit",
            "3",
            "--columns",
            "ordinal,bytes,total,parent,cumulative,role",
        ],
    );
    assert!(
        table.contains("5  9000  Overlap  Unknown  Unknown  Overlap\n"),
        "{table}"
    );
    assert!(
        table.contains("3  1024  20.38%  20.38%  20.38%  Additive\n"),
        "{table}"
    );
    assert!(
        table.contains("6  1001  19.92%  19.92%  40.31%  Additive\n"),
        "{table}"
    );
    assert!(
        table.contains("Accounted bytes in this page: 2.03 KB (2025 B)"),
        "{table}"
    );
}

#[test]
fn explain_bucket_requires_nonlossy_blob_and_shape_keeps_source_absence_explicit() {
    let root = tempfile::tempdir().unwrap();
    let mut lossy = row("Blobs", "Metadata", 10, true);
    lossy.identity_lossy = true;
    let rows = [
        row("Methods", "Metadata", 10, true),
        lossy,
        row("Methods", "A<int>__Run", 10, true),
    ];
    let path = bundle(root.path(), &evidence(), Some(&rows));
    for ordinal in ["0", "1"] {
        let explanation = query("explain", &path, &[ordinal]);
        assert_eq!(explanation["data"]["bucket"], Value::Null);
        assert_eq!(
            summary_at(&explanation["data"]["source"], "sources"),
            "0 items"
        );
    }
    let generic = query("explain", &path, &["2"]);
    assert_eq!(generic["data"]["shape"]["status"], "available");
    assert_eq!(
        summary_at(&generic["data"]["shape"]["page"], "family"),
        "A<>__Run"
    );
    assert_eq!(summary_at(&generic["data"]["source"], "sources"), "0 items");
    assert_eq!(generic["data"]["accounted_total_bytes"], Value::Null);
}

#[test]
fn guide_preserves_nondefault_global_settings_and_escapes_control_selectors() {
    let root = tempfile::tempdir().unwrap();
    let stream = "Methods'\r\n$(literal)";
    let path = bundle(
        root.path(),
        &evidence(),
        Some(&[row(stream, "Opaque", 10, true)]),
    );
    let parsed = Cli::try_parse_from([
        "vitnet",
        "--quiet",
        "--progress",
        "always",
        "--format",
        "ndjson",
        "--memory-limit",
        "64MiB",
        "explore",
        "guide",
        path.to_str().unwrap(),
    ])
    .unwrap();
    let guide: Value = serde_json::from_str(&execute(&parsed).unwrap()).unwrap();
    let largest = action(&guide, "Inspect the largest additive stream");
    assert_eq!(largest["stream"], stream);
    assert_eq!(largest["bytes"], 10);
    let command = largest["command"].as_str().unwrap();
    assert!(
        command.starts_with(
            "vitnet --memory-limit 67108864B --format ndjson --quiet --progress always"
        ),
        "{command}"
    );
    assert!(
        command.contains("--stream ('Methods''' + [char]13 + '' + [char]10 + '$(literal)')"),
        "{command}"
    );
    assert!(!command.contains('\r'));
    assert!(!command.contains('\n'));
}

#[test]
fn dataset_empty_original_capture_and_selector_boundary_remain_captured() {
    let root = tempfile::tempdir().unwrap();
    let path = bundle(root.path(), &evidence(), Some(&[]));
    let original = query("datasets", &path, &["--storage", "original-index"]);
    assert_eq!(dataset_names(&original), ["identities"]);
    assert_eq!(original["data"]["datasets"][0]["records"], 0);
    let removed = query(
        "datasets",
        &path,
        &["--storage", "original-index", "--nonempty"],
    );
    assert_eq!(dataset_names(&removed), Vec::<&str>::new());
    assert_eq!(removed["data"]["returned_datasets"], 0);
    assert_eq!(
        removed["data"]["total_datasets"],
        original["data"]["total_datasets"]
    );
    assert_eq!(removed["data"]["complete"], true);
    let boundary = query("datasets", &path, &["--contains", &"x".repeat(1024)]);
    assert_eq!(boundary["data"]["returned_datasets"], 0);
    assert_eq!(boundary["data"]["complete"], true);
}

#[test]
fn compare_percentage_immediately_below_half_rounds_to_zero() {
    let root = tempfile::tempdir().unwrap();
    for (before_bytes, expected_basis) in [(19999, 1), (20000, 1), (20001, 0)] {
        let b = root.path().join(format!("b{before_bytes}"));
        let a = root.path().join(format!("a{before_bytes}"));
        let before = bundle(&b, &measured(&b, before_bytes, None, None), None);
        let after = bundle(&a, &measured(&a, before_bytes + 1, None, None), None);
        let result = comparison(&before, &after);
        assert_eq!(
            change_at(&result, "measurements", "accounted")["delta_bytes"],
            1
        );
        assert_eq!(
            change_at(&result, "measurements", "accounted")["change_basis_points"],
            expected_basis
        );
    }
}

#[test]
fn compare_rejects_invalid_measurements_missing_stream_values_and_duplicate_names() {
    let root = tempfile::tempdir().unwrap();
    let path = bundle(root.path(), &measured(root.path(), 100, None, None), None);
    let original_manifest = read_json(&path.join("bundle.json"));
    let original_snapshot = read_json(&path.join("snapshot.json"));
    for invalid in [json!("0"), json!(-1), json!(false)] {
        let mut manifest = original_manifest.clone();
        let mut snapshot = original_snapshot.clone();
        snapshot["ledger"]["physical_total_bytes"] = invalid;
        write_fingerprinted_snapshot(&path, &mut manifest, &mut snapshot);
        expect_error(
            "json",
            &["compare", path.to_str().unwrap(), path.to_str().unwrap()],
            "explorer.accounting",
        );
    }
    for streams in [
        json!([{"name":"Methods","bytes":null}]),
        json!([{"bytes":100}]),
        json!([{"name":"Methods","bytes":100},{"name":"Methods","bytes":100}]),
    ] {
        let mut manifest = original_manifest.clone();
        let mut snapshot = original_snapshot.clone();
        snapshot["accounting"]["streams"] = streams;
        write_fingerprinted_snapshot(&path, &mut manifest, &mut snapshot);
        expect_error(
            "json",
            &["compare", path.to_str().unwrap(), path.to_str().unwrap()],
            "explorer.accounting",
        );
    }
}

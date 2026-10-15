//! Scoped display/report regressions; no production edits or private inputs.
use clap::Parser;
use serde_json::{Value, json};
use std::fs;
use std::path::Path;
use vitnet_attribution::model::{Artifact, EVIDENCE_SCHEMA, Evidence, Resource};
use vitnet_cli::{Cli, execute};

#[allow(dead_code)]
#[path = "../../vitnet-attribution/tests/common/mod.rs"]
mod common;
#[path = "../src/display.rs"]
mod display;

fn run(format: &str, tail: &[&str]) -> String {
    let mut argv = vec![
        "vitnet",
        "--format",
        format,
        "--progress",
        "never",
        "--color",
        "never",
        "--memory-limit",
        "128MiB",
    ];
    argv.extend_from_slice(tail);
    execute(&Cli::try_parse_from(argv).unwrap()).unwrap()
}

fn json_output(args: &[&str]) -> Value {
    serde_json::from_str(&run("json", args)).unwrap()
}

fn lines(args: &[&str]) -> Vec<Value> {
    run("ndjson", args)
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect()
}

fn mstat(path: &Path) {
    let mut image = common::Image::new();
    image.method(b"Owner__First", 1000);
    image.method(b"Owner__Second", 3000);
    image.blob(&"Metadata".encode_utf16().collect::<Vec<_>>(), 1000);
    fs::write(path, image.bytes()).unwrap();
}

#[test]
fn decimal_sizes_round_half_up_rollover_exact_bytes_and_signed_extremes() {
    for (bytes, expected) in [
        (0, "0 B"),
        (999, "999 B"),
        (1000, "1 KB"),
        (1024, "1.02 KB"),
        (1234, "1.23 KB"),
        (1235, "1.24 KB"),
        (999_994, "999.99 KB"),
        (999_995, "1 MB"),
        (1_000_000, "1 MB"),
        (1_000_000_000, "1 GB"),
        (u64::MAX, "18.45 EB"),
    ] {
        assert_eq!(display::bytes(bytes), expected, "{bytes}");
    }
    assert_eq!(display::exact(999), "999 B");
    assert_eq!(display::exact(1000), "1 KB (1000 B)");
    assert_eq!(
        display::exact(9_007_199_254_740_993),
        "9.01 PB (9007199254740993 B)"
    );
    assert_eq!(display::optional(None), "Unknown");
    assert_eq!(display::optional(Some(0)), "0 B");
    assert_eq!(display::signed(-1235), "-1.24 KB (-1235 B)");
    assert_eq!(display::signed(0), "0 B (+0 B)");
    assert_eq!(display::signed(1235), "+1.24 KB (+1235 B)");
    assert_eq!(
        display::signed(i128::MIN),
        "-170141183460469231731.69 EB (-170141183460469231731687303715884105728 B)"
    );
    assert_eq!(
        display::wide_exact(u128::MAX),
        "340282366920938463463.37 EB (340282366920938463463374607431768211455 B)"
    );
}

#[test]
fn percentages_keep_known_zero_unknown_tiny_values_and_uncapped_u128_overlap() {
    for (bytes, total, expected) in [
        (0, None, "Unknown"),
        (1, None, "Unknown"),
        (0, Some(0), "Unknown"),
        (1, Some(0), "Unknown"),
        (0, Some(100), "0.00%"),
        (1, Some(100_000), "0.00%"),
        (1, Some(10_000), "0.01%"),
        (1, Some(20_000), "0.01%"),
        (1, Some(3), "33.33%"),
        (2, Some(3), "66.67%"),
        (150, Some(100), "150.00%"),
        (u64::MAX, Some(u64::MAX), "100.00%"),
        (u64::MAX, Some(1), "1844674407370955161500.00%"),
    ] {
        assert_eq!(display::percent(bytes, total), expected);
    }
    assert_eq!(
        display::basis_points(u128::from(u64::MAX) + 1),
        "184467440737095516.16%"
    );
    assert_eq!(
        display::basis_points(u128::MAX),
        "3402823669209384634633746074317682114.55%"
    );
}

#[test]
fn terminal_text_escapes_controls_and_bidi_without_altering_unicode() {
    assert_eq!(
        display::text("a\n\r\t\u{1b}\u{7}\u{202a}\u{202e}\u{2066}\u{2069}é🙂"),
        r"a\n\r\t\u{1b}\u{7}\u{202a}\u{202e}\u{2066}\u{2069}é🙂"
    );
    assert_eq!(display::text(""), "");
    assert_eq!(display::text("plain é🙂"), "plain é🙂");
}

#[test]
fn metadata_human_sizes_and_proportions_preserve_machine_lower_bounds() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("metadata.csv");
    // Hex offsets: 0, 1000, 4000; final record length remains unknown.
    fs::write(&path,b"Handle, Kind, Name, Children\n00000000, ScopeDefinition, \"App\", \"3e8\"\n000003e8, TypeDefinition, \"Widget\", \"fa0\"\n00000fa0, End, \"\", \"\"\n").unwrap();
    let args = ["metadata", path.to_str().unwrap(), "--group", "kind"];
    let machine = json_output(&args);
    assert_eq!(machine["schema"], "vitnet.metadata.v1");
    assert_eq!(machine["summary"]["metadata_lower_bound_bytes"], 4000);
    assert_eq!(machine["summary"]["selected_lower_bound_bytes"], 4000);
    let table = run("table", &args);
    assert!(
        table.contains("Metadata lower bound: 4 KB (4000 B) across 3 records"),
        "{table}"
    );
    let first = table
        .lines()
        .find(|line| line.contains("ScopeDefinition"))
        .unwrap();
    assert!(
        first.contains("1 KB") && first.contains("25.00%"),
        "{first}"
    );
    let second = table
        .lines()
        .find(|line| line.contains("TypeDefinition"))
        .unwrap();
    assert!(
        second.contains("3 KB") && second.contains("75.00%"),
        "{second}"
    );
    let ndjson = lines(&args);
    let summary = ndjson.iter().find(|v| v["section"] == "summary").unwrap();
    assert_eq!(summary["value"]["metadata_lower_bound_bytes"], 4000);
    let kind = ndjson
        .iter()
        .find(|v| v["section"] == "by_kind" && v["value"]["name"] == "ScopeDefinition")
        .unwrap();
    assert_eq!(kind["value"]["bytes"], 1000);
    assert_eq!(kind["schema"], machine["schema"]);
    let selected_args = [
        "metadata",
        path.to_str().unwrap(),
        "--type",
        "App!Widget",
        "--group",
        "kind",
    ];
    let selected = json_output(&selected_args);
    assert_eq!(selected["summary"]["metadata_lower_bound_bytes"], 4000);
    assert_eq!(selected["summary"]["selected_lower_bound_bytes"], 3000);
    let table = run("table", &selected_args);
    assert!(
        table.contains("Selected lower bound: 3 KB (3000 B)"),
        "{table}"
    );
    let row = table
        .lines()
        .find(|line| line.contains("TypeDefinition"))
        .unwrap();
    assert!(row.contains("75.00%") && row.contains("100.00%"), "{row}");
}

#[test]
fn mstat_summary_stream_proportions_and_top_matched_bases_preserve_json_ndjson() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("reported.mstat");
    mstat(&path);
    let summary_args = ["mstat", "summary", path.to_str().unwrap()];
    let machine = json_output(&summary_args);
    assert_eq!(machine["schema"], "vitnet.mstat-summary.v1");
    assert_eq!(machine["accounted_size_bytes"], 5000);
    let table = run("table", &summary_args);
    assert!(table.contains("Accounted size: 5 KB (5000 B)"), "{table}");
    let methods = table
        .lines()
        .find(|v| v.contains("Methods") && v.contains('%'))
        .unwrap();
    assert!(
        methods.contains("4 KB") && methods.contains("80.00%"),
        "{methods}"
    );
    let blobs = table
        .lines()
        .find(|v| v.contains("Blobs") && v.contains('%'))
        .unwrap();
    assert!(
        blobs.contains("1 KB") && blobs.contains("20.00%"),
        "{blobs}"
    );
    assert!(
        table.contains("Overlap") || table.contains("overlap"),
        "{table}"
    );
    let ndjson = lines(&summary_args);
    assert_eq!(
        ndjson.iter().find(|v| v["section"] == "summary").unwrap()["value"]["accounted_size_bytes"],
        5000
    );
    let args = [
        "mstat",
        "top",
        path.to_str().unwrap(),
        "--stream",
        "Methods",
        "--contains",
        "First",
        "--top",
        "1",
    ];
    let top = json_output(&args);
    assert_eq!(top["schema"], "vitnet.mstat-top.v1");
    assert_eq!(top["accounted_size_bytes"], 5000);
    let section = top["sections"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["name"] == "Methods")
        .unwrap();
    assert_eq!(section["total_bytes"], 4000);
    assert_eq!(section["matched_bytes"], 1000);
    assert_eq!(section["entries"][0]["bytes"], 1000);
    assert_eq!(section["entries"][0]["identity"], "Owner__First");
    let table = run("table", &args);
    let first = table.lines().find(|v| v.contains("Owner__First")).unwrap();
    assert!(
        first.contains("1 KB") && first.contains("20.00%") && first.contains("25.00%"),
        "{table}"
    );
    assert!(table.contains("bounded top list, not a complete inventory"));
    let ndjson = lines(&args);
    let section = ndjson
        .iter()
        .find(|v| v["section"] == "sections" && v["value"]["name"] == "Methods")
        .unwrap();
    assert_eq!(section["value"]["total_bytes"], 4000);
    assert_eq!(section["value"]["entries"][0]["bytes"], 1000);
}

#[test]
fn attribution_report_human_sizes_unknowns_and_overlapping_inventory_keep_machine_bytes() {
    for known in [true, false] {
        let root = tempfile::tempdir().unwrap();
        let mut value = Evidence {
            schema: EVIDENCE_SCHEMA.into(),
            label: "Reporting".into(),
            ..Evidence::default()
        };
        if known {
            let path = root.path().join("reported.mstat");
            mstat(&path);
            value.artifacts.push(Artifact {
                kind: "mstat".into(),
                path,
                revision: None,
                blake3: None,
            });
        }

        value.resources = vec![
            Resource {
                assembly: "App".into(),
                container: "container".into(),
                name: "asset".into(),
                bytes: 1235,
                storage: "asset".into(),
                ..Resource::default()
            },
            Resource {
                assembly: "App".into(),
                container: "container".into(),
                name: "container".into(),
                bytes: 9000,
                storage: "manifest_container".into(),
                ..Resource::default()
            },
        ];
        let manifest = root.path().join("evidence.json");
        fs::write(&manifest, serde_json::to_vec(&value).unwrap()).unwrap();
        let index = root.path().join("index");
        vitnet_attribution::import(&manifest, &index, 128 << 20, false).unwrap();
        let args = ["attribution", "report", index.to_str().unwrap()];
        let machine = json_output(&args);
        assert_eq!(
            machine["accounted_bytes"],
            if known { json!(5000) } else { Value::Null }
        );
        assert_eq!(machine["full_resource_asset_bytes"], 1235);
        assert_eq!(machine["full_resource_container_bytes"], 9000);
        let table = run("table", &args);
        assert!(
            table.contains(if known {
                "Accounted MSTAT bytes: 5 KB (5000 B)"
            } else {
                "Accounted MSTAT bytes: Unknown"
            }),
            "{table}"
        );
        assert!(table.contains("complete assets=1.24 KB (1235 B), containers=9 KB (9000 B)"));
        assert!(table.contains("overlap; do not add to accounted total"));
        if known {
            let first = table.lines().find(|v| v.contains("Owner__First")).unwrap();
            assert!(first.contains("20.00%") && first.contains("1 KB"));
        }
        let ndjson = lines(&args);
        assert_eq!(ndjson.len(), 1);
        assert_eq!(ndjson[0], machine);
    }
}

#[test]
#[allow(clippy::too_many_lines)] // One composition contrasts positive, negative and missing measurements.
fn bloat_brief_human_percentages_unknowns_and_signed_reconciliation_preserve_raw_json() {
    let root = tempfile::tempdir().unwrap();
    let metadata = root.path().join("metadata.csv");
    fs::write(&metadata,b"Handle, Kind, Name, Children\n00000000, ScopeDefinition, \"App\", \"3e8\"\n000003e8, TypeDefinition, \"Widget\", \"fa0\"\n00000fa0, End, \"\", \"\"\n").unwrap();
    for (blob, body, delta, expected, membership) in [
        (
            Some(1700),
            8300,
            Some(-2300),
            "-2.3 KB (-2300 B)",
            "8.3 KB (8300 B)",
        ),
        (
            Some(5700),
            4300,
            Some(1700),
            "+1.7 KB (+1700 B)",
            "4.3 KB (4300 B)",
        ),
        (None, 10000, None, "Unknown", "10 KB (10000 B)"),
    ] {
        let path = root.path().join("reported.mstat");
        let mut image = common::Image::new();
        image.method(b"Newtonsoft__Run", body);
        if let Some(bytes) = blob {
            image.blob(&"Metadata".encode_utf16().collect::<Vec<_>>(), bytes);
        }
        fs::write(&path, image.bytes()).unwrap();
        let args = [
            "bloat",
            "--brief",
            "--metadata",
            metadata.to_str().unwrap(),
            "--mstat",
            path.to_str().unwrap(),
        ];
        let machine = json_output(&args);
        assert_eq!(machine["schema"], "vitnet.bloat-brief.v1");
        assert_eq!(machine["accounting"]["accounted_total_bytes"], 10000);
        assert_eq!(
            machine["reconciliation"]["metadata_csv_lower_bound_bytes"],
            4000
        );
        assert_eq!(
            machine["reconciliation"]["mstat_metadata_blob_bytes"],
            blob.map_or(Value::Null, |bytes| json!(bytes))
        );
        assert_eq!(
            machine["reconciliation"]["blob_minus_lower_bound_bytes"],
            delta.map_or(Value::Null, |bytes| json!(bytes))
        );
        let table = run("table", &args);
        assert!(
            table.contains("accounted_total_bytes: 10 KB (10000 B)"),
            "{table}"
        );
        assert!(
            table.contains(&format!("blob_minus_lower_bound_bytes: {expected}")),
            "{table}"
        );
        assert!(!table.contains("_basis_points:"), "{table}");
        assert_eq!(
            machine["cohort_overlap"]["summed_membership_bytes"],
            body.to_string()
        );
        assert_eq!(
            machine["cohort_overlap"]["membership_amplification_basis_points"],
            "10000"
        );
        let amount = table
            .lines()
            .find(|line| line.trim_start().starts_with("summed_membership_bytes:"))
            .unwrap()
            .trim();
        assert_eq!(amount, format!("summed_membership_bytes: {membership}"));
        let percent = table
            .lines()
            .find(|line| {
                line.trim_start()
                    .starts_with("membership_amplification_percent:")
            })
            .unwrap()
            .trim();
        assert_eq!(percent, "membership_amplification_percent: 100.00%");
        if blob == Some(1700) {
            let fraction = machine["accounting"]["additive_streams"]
                .as_array()
                .unwrap()
                .iter()
                .find(|v| v["name"] == "Blobs")
                .unwrap();
            assert_eq!(fraction["bytes"], 1700);
            assert_eq!(fraction["denominator_bytes"], 10000);
            assert_eq!(fraction["share_basis_points"], 1700);
            assert!(table.contains("share_percent: 17.00%"), "{table}");
            assert!(table.contains("mstat_metadata_blob_bytes: 1.7 KB (1700 B)"));
        } else if blob.is_none() {
            assert!(
                table.contains("mstat_metadata_blob_bytes: Unknown"),
                "{table}"
            );
        }
        assert_eq!(lines(&args), vec![machine]);
    }
}

#[test]
fn mstat_insight_projection_humanizes_bytes_and_percentage_labels_only_in_tables() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("reported.mstat");
    mstat(&path);
    let args = [
        "mstat",
        "methods",
        path.to_str().unwrap(),
        "--contains",
        "First",
    ];
    let machine = json_output(&args);
    assert_eq!(machine["schema"], "vitnet.mstat-methods.v1");
    assert_eq!(machine["data"]["accounted_denominator_bytes"], 5000);
    assert_eq!(machine["data"]["entries"][0]["identity"], "Owner__First");
    assert_eq!(machine["data"]["entries"][0]["body_bytes"], 1000);
    assert_eq!(machine["data"]["entries"][0]["bytes"], 1000);
    assert_eq!(
        machine["data"]["entries"][0]["accounted_basis_points"],
        2000
    );
    let table = run("table", &args);
    assert!(table.contains("accounted_denominator_bytes: 5 KB (5000 B)"));
    assert!(table.contains("body_bytes: 1 KB (1000 B)"));
    assert!(table.contains("bytes: 1 KB (1000 B)"));
    assert!(table.contains("accounted_percent: 20.00%"));
    assert!(!table.contains("accounted_basis_points:"));
    assert_eq!(lines(&args), vec![machine]);
}

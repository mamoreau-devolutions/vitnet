use clap::Parser;
use std::io::Cursor;
use vitnet_cli::{AppError, Cli, Command, FormatArg, GroupArg, ModeArg, analyze_reader, execute};
use vitnet_core::{ByteSize, ExitCode};
use vitnet_metadata::AnalysisOptions;
use vitnet_report::InputDescriptor;

#[test]
#[allow(clippy::too_many_lines)] // Paired CLI validation plus two generation-scoped fixtures.
fn attribution_cli_compare_requires_paired_node_switches_and_preserves_selected_witnesses() {
    for single in ["--before-node", "--after-node"] {
        let error = Cli::try_parse_from([
            "vitnet",
            "attribution",
            "compare",
            "before",
            "after",
            single,
            "1",
        ])
        .unwrap_err();
        assert_eq!(
            error.kind(),
            clap::error::ErrorKind::MissingRequiredArgument
        );
        assert!(error.to_string().contains(if single == "--before-node" {
            "--after-node"
        } else {
            "--before-node"
        }));
    }
    let directory = tempfile::tempdir().unwrap();
    let mut indexes = Vec::new();
    let mut generations = Vec::new();
    for (name, xml) in [
        (
            "before",
            r#"<DirectedGraph><Nodes><Node Id="0" Label="root"/><Node Id="1" Label="target"/></Nodes><Links><Link Source="0" Target="1" Reason="original"/></Links></DirectedGraph>"#,
        ),
        (
            "after",
            r#"<DirectedGraph><Nodes><Node Id="10" Label="root"/><Node Id="11" Label="alternate"/><Node Id="9" Label="target"/></Nodes><Links><Link Source="10" Target="9" Reason="changed"/><Link Source="11" Target="9" Reason="alternate"/></Links></DirectedGraph>"#,
        ),
    ] {
        let graph = directory.path().join(format!("{name}.dgml"));
        std::fs::write(&graph, xml).unwrap();
        let built = vitnet_dgml::build_index(
            &graph,
            &vitnet_dgml::IndexOptions {
                cache_root: directory.path().join(format!("{name}-cache")),
                memory_limit: 16 << 20,
                selected_entry: None,
                strict_hash: false,
                control: vitnet_dgml::IndexControl::default(),
            },
        )
        .unwrap();
        generations.push(built.generation);
        let manifest = directory.path().join(format!("{name}.json"));
        std::fs::write(
            &manifest,
            serde_json::to_vec(&serde_json::json!({
                "schema": "vitnet.evidence.v1", "label": name,
                "artifacts": [{ "kind": "scan_index", "path": built.index_directory }]
            }))
            .unwrap(),
        )
        .unwrap();
        let index = directory.path().join(name);
        let cli = Cli::try_parse_from([
            "vitnet",
            "--format",
            "json",
            "attribution",
            "import",
            manifest.to_str().unwrap(),
            "--index",
            index.to_str().unwrap(),
        ])
        .unwrap();
        execute(&cli).unwrap();
        indexes.push(index);
    }
    let base = [
        "vitnet",
        "--format",
        "json",
        "attribution",
        "compare",
        indexes[0].to_str().unwrap(),
        indexes[1].to_str().unwrap(),
    ];
    let cli = Cli::try_parse_from(base).unwrap();
    let result: serde_json::Value = serde_json::from_str(&execute(&cli).unwrap()).unwrap();
    assert_eq!(result["schema"], "vitnet.attribution-compare.v1");
    assert_eq!(result["retention"], serde_json::Value::Null);
    let mut paired = base.to_vec();
    paired.extend([
        "--before-node",
        "1",
        "--after-node",
        "9",
        "--graph",
        "scan_index",
    ]);
    let cli = Cli::try_parse_from(paired).unwrap();
    let result: serde_json::Value = serde_json::from_str(&execute(&cli).unwrap()).unwrap();
    assert_eq!(
        result["retention"]["before"]["witness"]["generation"],
        generations[0]
    );
    assert_eq!(
        result["retention"]["after"]["witness"]["generation"],
        generations[1]
    );
    assert_eq!(
        result["retention"]["before"]["witness"]["node"]["node_id"],
        1
    );
    assert_eq!(
        result["retention"]["after"]["witness"]["node"]["node_id"],
        9
    );
    assert_eq!(result["retention"]["before_incoming_edges"], 1);
    assert_eq!(result["retention"]["after_incoming_edges"], 2);
    assert_eq!(result["retention"]["incoming_edge_delta"], 1);
    assert_eq!(
        result["retention"]["before"]["witness"]["paths"][0]["reasons"][0],
        "original"
    );
    let mut reasons: Vec<_> = result["retention"]["after"]["witness"]["paths"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p["reasons"][0].as_str().unwrap())
        .collect();
    reasons.sort_unstable();
    assert_eq!(reasons, ["alternate", "changed"]);
}

#[test]
fn attribution_cli_import_report_and_verify_are_versioned_and_offline() {
    let directory = tempfile::tempdir().unwrap();
    let evidence = directory.path().join("evidence.json");
    let index = directory.path().join("attribution");
    std::fs::write(
        &evidence,
        br#"{
  "schema": "vitnet.evidence.v1",
  "label": "synthetic CLI evidence",
  "packages": [{
    "target": "net10.0",
    "id": "Package.One",
    "version": "1.0.0",
    "direct": true,
    "dependencies": []
  }]
}"#,
    )
    .unwrap();
    let import_cli = Cli::try_parse_from([
        "vitnet",
        "--format",
        "json",
        "attribution",
        "import",
        evidence.to_str().unwrap(),
        "--index",
        index.to_str().unwrap(),
    ])
    .unwrap();
    let imported: serde_json::Value = serde_json::from_str(&execute(&import_cli).unwrap()).unwrap();
    assert_eq!(imported["schema"], "vitnet.attribution-import.v1");
    assert_eq!(imported["label"], "synthetic CLI evidence");
    assert_eq!(imported["packages"], 1);
    assert_eq!(imported["identities"], 0);

    let report_cli = Cli::try_parse_from([
        "vitnet",
        "--format",
        "json",
        "attribution",
        "report",
        index.to_str().unwrap(),
        "--top",
        "5",
    ])
    .unwrap();
    let result: serde_json::Value = serde_json::from_str(&execute(&report_cli).unwrap()).unwrap();
    assert_eq!(result["schema"], "vitnet.attribution-report.v1");
    assert_eq!(result["label"], "synthetic CLI evidence");
    assert_eq!(result["accounted_bytes"], serde_json::Value::Null);
    assert_eq!(
        result["package_routes"][0]["shortest_route"][0],
        "Package.One/1.0.0"
    );

    let verify_cli = Cli::try_parse_from([
        "vitnet",
        "--format",
        "json",
        "attribution",
        "verify",
        index.to_str().unwrap(),
    ])
    .unwrap();
    let verified: serde_json::Value = serde_json::from_str(&execute(&verify_cli).unwrap()).unwrap();
    assert_eq!(verified["schema"], "vitnet.attribution-verify.v1");
    assert_eq!(verified["valid_cache"], true);
    assert_eq!(verified["complete_import"], false);
}

#[test]
fn type_drilldown_preserves_record_sizes_filters_strings_and_bounds_previews() {
    let directory = tempfile::tempdir().unwrap();
    let input = directory.path().join("metadata.csv");
    std::fs::write(&input, b"Handle, Kind, Name, Children\n00000000, ScopeDefinition, \"A\", \"a 28\"\n0000000a, TypeDefinition, \"N.T\", \"14\"\n00000014, ConstantStringValue, \"abcdef\", \"\"\n0000001e, Method, \"excluded\", \"\"\n00000028, TypeDefinition, \"N.U\", \"32\"\n00000032, ConstantStringValue, \"other\", \"\"\n0000003c, End, \"\", \"\"\n").unwrap();
    let cli = Cli::try_parse_from([
        "vitnet",
        "--format",
        "json",
        "metadata",
        input.to_str().unwrap(),
        "--type",
        "A!N.T",
        "--strings",
        "--preview-bytes",
        "3",
    ])
    .unwrap();
    let report: serde_json::Value = serde_json::from_str(&execute(&cli).unwrap()).unwrap();
    assert_eq!(report["summary"]["metadata_lower_bound_bytes"], 60);
    assert_eq!(report["summary"]["selected_lower_bound_bytes"], 20);
    assert_eq!(report["summary"]["record_count"], 2);
    assert_eq!(report["sections"]["by_type"][0]["name"], "A!N.T");
    assert_eq!(
        report["sections"]["largest_strings"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        report["sections"]["largest_strings"][0]["preview"]["text"],
        "abc"
    );
    assert_eq!(
        report["sections"]["largest_strings"][0]["preview"]["truncated"],
        true
    );
    let cli = Cli::try_parse_from([
        "vitnet",
        "--format",
        "json",
        "metadata",
        input.to_str().unwrap(),
        "--type",
        "Missing",
    ])
    .unwrap();
    let report: serde_json::Value = serde_json::from_str(&execute(&cli).unwrap()).unwrap();
    assert_eq!(report["summary"]["selected_lower_bound_bytes"], 0);
    assert_eq!(report["summary"]["record_count"], 0);
}

#[test]
fn metadata_command_parses_every_phase_zero_and_one_option() {
    let cli = Cli::try_parse_from([
        "vitnet",
        "--format",
        "json",
        "--output",
        "report.json",
        "--memory-limit",
        "512MiB",
        "--temp-dir",
        "scratch",
        "--threads",
        "3",
        "--progress",
        "always",
        "--color",
        "never",
        "--verbose",
        "--strict",
        "metadata",
        "before.csv",
        "--top",
        "7",
        "--assembly",
        "Product.Core",
        "--group",
        "assembly,namespace,type,kind",
        "--strings",
        "--compare",
        "after.csv",
    ])
    .unwrap();

    assert_eq!(cli.format, FormatArg::Json);
    assert_eq!(
        cli.output.as_deref(),
        Some(std::path::Path::new("report.json"))
    );
    assert_eq!(cli.memory_limit, ByteSize(512 * 1024 * 1024));
    assert_eq!(
        cli.temp_dir.as_deref(),
        Some(std::path::Path::new("scratch"))
    );
    assert_eq!(cli.threads.unwrap().get(), 3);
    assert_eq!(cli.progress, ModeArg::Always);
    assert_eq!(cli.color, ModeArg::Never);
    assert!(!cli.quiet);
    assert!(cli.verbose);
    assert!(cli.strict);
    let Command::Metadata(arguments) = cli.command else {
        panic!("expected metadata command");
    };
    assert_eq!(arguments.input, std::path::PathBuf::from("before.csv"));
    assert_eq!(arguments.top, 7);
    assert_eq!(arguments.assembly.as_deref(), Some("Product.Core"));
    assert_eq!(
        arguments.group,
        vec![
            GroupArg::Assembly,
            GroupArg::Namespace,
            GroupArg::Type,
            GroupArg::Kind,
        ]
    );
    assert!(arguments.strings);
    assert_eq!(arguments.compare, Some("after.csv".into()));
}

#[test]
fn invalid_options_are_rejected_with_exit_code_two() {
    for arguments in [
        vec!["vitnet", "--format", "yaml", "metadata", "a.csv"],
        vec!["vitnet", "--threads", "0", "metadata", "a.csv"],
        vec!["vitnet", "metadata", "a.csv", "--top", "0"],
        vec![
            "vitnet", "mstat", "diff", "a.mstat", "b.mstat", "--top", "0",
        ],
        vec!["vitnet", "--quiet", "--verbose", "metadata", "a.csv"],
    ] {
        let error = Cli::try_parse_from(arguments).unwrap_err();
        assert_eq!(error.exit_code(), ExitCode::InvalidOptions.as_i32());
    }
}

#[test]
fn malformed_metadata_maps_to_typed_exit_code_three() {
    let error = analyze_reader(
        Cursor::new(b"wrong header\n"),
        true,
        &AnalysisOptions::default(),
        InputDescriptor {
            path: Some("bad.csv".into()),
            bytes_read: 13,
        },
    )
    .unwrap_err();
    assert!(matches!(error, AppError::Metadata(_)));
    assert_eq!(error.exit_code(), ExitCode::MalformedInput);
}

#[test]
fn missing_input_maps_to_io_exit_code_four() {
    let cli =
        Cli::try_parse_from(["vitnet", "metadata", "this-file-does-not-exist-vitnet.csv"]).unwrap();
    let error = execute(&cli).unwrap_err();
    assert!(matches!(error, AppError::Io { .. }));
    assert_eq!(error.exit_code(), ExitCode::IoOrCache);
}

#[test]
fn successful_reader_path_produces_versioned_json_lower_bound_fields() {
    let input = b"Handle, Kind, Name, Children\n00000000, Type, \"T\", \"a\"\n0000000a, String, \"value\", \"\"\n";
    let report = analyze_reader(
        Cursor::new(input),
        true,
        &AnalysisOptions::default(),
        InputDescriptor {
            path: None,
            bytes_read: input.len() as u64,
        },
    )
    .unwrap();
    let json = report.to_json().unwrap();
    assert!(json.contains(r#""schema": "vitnet.metadata.v1""#));
    assert!(json.contains(r#""metadata_lower_bound_bytes": 10"#));
    assert_eq!(report.summary.record_count, 2);
    assert!(report.summary.total_is_lower_bound);
    assert!(!report.summary.final_record_size_known);
}

#[test]
fn table_output_states_lower_bound_and_unknown_final_record_size() {
    let directory = tempfile::tempdir().unwrap();
    let input = directory.path().join("metadata.csv");
    std::fs::write(
        &input,
        b"Handle, Kind, Name, Children\n00000000, Type, \"T\", \"\"\n0000000a, String, \"value\", \"\"\n",
    )
    .unwrap();
    let cli = Cli::try_parse_from(["vitnet", "metadata", input.to_str().unwrap()]).unwrap();
    let output = execute(&cli).unwrap();
    assert!(output.contains("Metadata lower bound: 10 B across 2 records"));
    assert!(output.contains("Final record size: unknown"));
    assert!(output.contains("10"));
    assert!(output.contains("1        Type"));
    assert!(!output.contains("exact"));
}

#[test]
fn comparison_mode_reports_signed_kind_delta() {
    let directory = tempfile::tempdir().unwrap();
    let before = directory.path().join("before.csv");
    let after = directory.path().join("after.csv");
    std::fs::write(
        &before,
        b"Handle, Kind, Name, Children\n00000000, Type, \"T\", \"\"\n0000000a, String, \"a\", \"\"\n",
    )
    .unwrap();
    std::fs::write(
        &after,
        b"Handle, Kind, Name, Children\n00000000, Type, \"T\", \"\"\n0000000f, String, \"a\", \"\"\n",
    )
    .unwrap();
    let cli = Cli::try_parse_from([
        "vitnet",
        "--format",
        "json",
        "metadata",
        before.to_str().unwrap(),
        "--compare",
        after.to_str().unwrap(),
    ])
    .unwrap();
    let output = execute(&cli).unwrap();
    let json: serde_json::Value = serde_json::from_str(&output).unwrap();
    assert_eq!(json["schema"], "vitnet.metadata-comparison.v1");
    assert_eq!(json["summary"]["delta_bytes"], 5);
    assert!(
        json["sections"]["by_kind"]["entries"]
            .as_array()
            .unwrap()
            .iter()
            .any(|entry| entry["name"] == "Type" && entry["delta_bytes"] == 5)
    );
}

#[test]
fn resource_limit_and_missing_inputs_use_stable_exit_codes() {
    let tiny_budget = Cli::try_parse_from([
        "vitnet",
        "--memory-limit",
        "1KiB",
        "metadata",
        "missing.csv",
    ])
    .unwrap();
    assert_eq!(
        execute(&tiny_budget).unwrap_err().exit_code(),
        ExitCode::ResourceLimit
    );

    let mstat = Cli::try_parse_from(["vitnet", "mstat", "summary", "a.mstat"]).unwrap();
    assert_eq!(
        execute(&mstat).unwrap_err().exit_code(),
        ExitCode::IoOrCache
    );
    let dgml = Cli::try_parse_from(["vitnet", "dgml", "index", "a.dgml.xml"]).unwrap();
    assert_eq!(execute(&dgml).unwrap_err().exit_code(), ExitCode::IoOrCache);
}

#[test]
fn malformed_mstat_maps_to_typed_exit_code_three() {
    let directory = tempfile::tempdir().unwrap();
    let input = directory.path().join("bad.mstat");
    std::fs::write(&input, b"not a PE").unwrap();
    let cli = Cli::try_parse_from(["vitnet", "mstat", "summary", input.to_str().unwrap()]).unwrap();
    let error = execute(&cli).unwrap_err();
    assert!(matches!(error, AppError::Mstat(_)));
    assert_eq!(error.exit_code(), ExitCode::MalformedInput);
}

#[test]
fn reader_io_failure_uses_exit_code_four() {
    struct FailingReader;

    impl std::io::Read for FailingReader {
        fn read(&mut self, _buffer: &mut [u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("synthetic read failure"))
        }
    }

    let error = analyze_reader(
        FailingReader,
        true,
        &AnalysisOptions::default(),
        InputDescriptor {
            path: Some("broken.csv".into()),
            bytes_read: 0,
        },
    )
    .unwrap_err();
    assert_eq!(error.exit_code(), ExitCode::IoOrCache);
}

#[test]
fn table_group_and_strings_options_control_projected_sections() {
    let directory = tempfile::tempdir().unwrap();
    let input = directory.path().join("metadata.csv");
    std::fs::write(
        &input,
        b"Handle, Kind, Name, Children\n70000000, ScopeDefinition, \"A\", \"7400000a\"\n7400000a, TypeDefinition, \"N.T\", \"34000014\"\n34000014, ConstantStringValue, \"value\", \"\"\n",
    )
    .unwrap();
    let cli = Cli::try_parse_from([
        "vitnet",
        "metadata",
        input.to_str().unwrap(),
        "--group",
        "type",
        "--strings",
    ])
    .unwrap();
    let output = execute(&cli).unwrap();
    assert!(output.contains("By type"));
    assert!(output.contains("A!N.T"));
    assert!(output.contains("Largest strings"));
    assert!(!output.contains("By assembly"));
    assert!(!output.contains("By namespace"));
    assert!(!output.contains("By kind"));
}

#[test]
fn json_and_ndjson_honor_projection_and_keep_the_versioned_schema() {
    let directory = tempfile::tempdir().unwrap();
    let input = directory.path().join("metadata.csv");
    std::fs::write(
        &input,
        b"Handle, Kind, Name, Children\n70000000, ScopeDefinition, \"A\", \"3400000a\"\n3400000a, ConstantStringValue, \"value\", \"\"\n",
    )
    .unwrap();

    let json_cli = Cli::try_parse_from([
        "vitnet",
        "--format",
        "json",
        "metadata",
        input.to_str().unwrap(),
        "--group",
        "assembly",
    ])
    .unwrap();
    let json: serde_json::Value = serde_json::from_str(&execute(&json_cli).unwrap()).unwrap();
    assert_eq!(json["schema"], "vitnet.metadata.v1");
    assert_eq!(json["sections"]["by_assembly"].as_array().unwrap().len(), 1);
    assert_eq!(json["sections"]["by_kind"], serde_json::json!([]));
    assert_eq!(
        json["sections"]["largest_strings"].as_array().unwrap(),
        &Vec::<serde_json::Value>::new()
    );

    let ndjson_cli = Cli::try_parse_from([
        "vitnet",
        "--format",
        "ndjson",
        "metadata",
        input.to_str().unwrap(),
        "--group",
        "kind",
        "--strings",
    ])
    .unwrap();
    let lines = execute(&ndjson_cli).unwrap();
    let values = lines
        .lines()
        .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
        .collect::<Vec<_>>();
    assert!(
        values
            .iter()
            .all(|value| value["schema"] == "vitnet.metadata.v1")
    );
    assert!(values.iter().any(|value| value["section"] == "summary"));
    assert!(values.iter().any(|value| value["section"] == "by_kind"));
    assert!(values.iter().any(|value| value["section"] == "strings"));
}

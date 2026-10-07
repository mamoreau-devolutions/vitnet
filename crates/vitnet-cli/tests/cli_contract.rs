use clap::Parser;
use std::io::Cursor;
use vitnet_cli::{AppError, Cli, Command, FormatArg, GroupArg, ModeArg, analyze_reader, execute};
use vitnet_core::{ByteSize, ExitCode};
use vitnet_metadata::AnalysisOptions;
use vitnet_report::InputDescriptor;

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
fn resource_limit_and_placeholder_commands_use_stable_exit_codes() {
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
    assert_eq!(
        execute(&dgml).unwrap_err().exit_code(),
        ExitCode::MalformedInput
    );
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
    assert!(json["sections"]["by_kind"].as_array().unwrap().is_empty());
    assert!(
        json["sections"]["largest_strings"]
            .as_array()
            .unwrap()
            .is_empty()
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

use super::rules;
use crate::{Cli, execute};
use clap::Parser;
use vitnet_core::ExitCode;

#[test]
fn cohort_configuration_distinguishes_defaults_empty_json_and_resource_errors() {
    let default = rules(None, 1 << 20).unwrap();
    assert_eq!(default.len(), 6);
    assert_eq!(default[0].name, "serialization");
    assert_eq!(default[3].name, "resources");
    assert_eq!(default[4].contains, ["get_", "set_"]);
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("rules.json");
    std::fs::write(&path, b"[]").unwrap();
    assert_eq!(rules(Some(&path), 1 << 20).unwrap(), vec![]);
    std::fs::write(&path, b"{ broken").unwrap();
    let error = rules(Some(&path), 1 << 20).unwrap_err();
    assert_eq!(error.exit_code(), ExitCode::MalformedInput);
    assert!(error.to_string().contains("bloat.rules.json"));
    std::fs::write(&path, [b' '; 1025]).unwrap();
    let error = rules(Some(&path), 16 * 1024).unwrap_err();
    assert_eq!(error.exit_code(), ExitCode::ResourceLimit);
    assert!(error.to_string().contains("resource.rules"));
}

#[test]
fn all_insight_commands_surface_rules_failure_before_input_io() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("rules.json");
    std::fs::write(&path, b"invalid json").unwrap();
    for command in ["methods", "resources", "cohorts", "generics", "insights"] {
        for format in ["table", "json", "ndjson"] {
            let cli = Cli::try_parse_from([
                "vitnet",
                "--format",
                format,
                "mstat",
                command,
                "missing.mstat",
                "--rules",
                path.to_str().unwrap(),
            ])
            .unwrap();
            let error = execute(&cli).unwrap_err();
            assert_eq!(error.exit_code(), ExitCode::MalformedInput);
            assert!(error.to_string().contains("bloat.rules.json"));
        }
    }
}

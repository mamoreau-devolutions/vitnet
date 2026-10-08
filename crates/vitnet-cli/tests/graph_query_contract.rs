use clap::Parser;
use vitnet_cli::{Cli, execute};
use vitnet_dgml::{IndexControl, IndexOptions, build_index};

#[test]
#[allow(clippy::too_many_lines)]
fn cli_search_and_why_share_versioned_ids_and_expose_partial_stops() {
    let directory = tempfile::tempdir().unwrap();
    let input = directory.path().join("graph.xml");
    std::fs::write(&input, br#"<DirectedGraph><Nodes><Node Id="0" Label="Reflection"/><Node Id="1" Label="generated"/></Nodes><Links><Link Source="0" Target="1" Reason=""/></Links></DirectedGraph>"#).unwrap();
    let path = build_index(
        &input,
        &IndexOptions {
            cache_root: directory.path().join("cache"),
            memory_limit: 16 << 20,
            selected_entry: None,
            strict_hash: false,
            control: IndexControl::default(),
        },
    )
    .unwrap()
    .index_directory;
    let cli = Cli::try_parse_from([
        "vitnet",
        "--format",
        "json",
        "dgml",
        "search",
        path.to_str().unwrap(),
        "generated",
        "--limit",
        "1",
    ])
    .unwrap();
    let search: serde_json::Value = serde_json::from_str(&execute(&cli).unwrap()).unwrap();
    assert_eq!(search["schema"], "vitnet.dgml-search.v1");
    assert_eq!(search["entries"][0]["node_id"], 1);
    let cli = Cli::try_parse_from([
        "vitnet",
        "--format",
        "json",
        "dgml",
        "why",
        path.to_str().unwrap(),
        "1",
    ])
    .unwrap();
    let why: serde_json::Value = serde_json::from_str(&execute(&cli).unwrap()).unwrap();
    assert_eq!(why["schema"], "vitnet.dgml-why.v1");
    assert_eq!(why["generation"], search["generation"]);
    assert_eq!(why["paths"][0]["nodes"][0]["label"], "Reflection");
    assert_eq!(why["paths"][0]["reasons"][0], "");
    let cli = Cli::try_parse_from([
        "vitnet",
        "dgml",
        "why",
        path.to_str().unwrap(),
        "1",
        "--max-depth",
        "0",
    ])
    .unwrap();
    assert!(execute(&cli).unwrap().contains("stop: max_depth"));
    for (arguments, schema) in [
        (
            vec!["dgml", "incoming", path.to_str().unwrap(), "1"],
            "vitnet.dgml-incoming.v1",
        ),
        (
            vec!["dgml", "batch", path.to_str().unwrap(), "--ids", "1,0"],
            "vitnet.dgml-batch.v1",
        ),
        (
            vec![
                "dgml",
                "search",
                path.to_str().unwrap(),
                "e",
                "--count-all",
                "--rank",
                "incoming",
                "--limit",
                "1",
            ],
            "vitnet.dgml-search.v1",
        ),
    ] {
        for format in ["json", "ndjson", "table"] {
            let mut args = vec!["vitnet", "--format", format];
            args.extend(&arguments);
            let output = execute(&Cli::try_parse_from(args).unwrap()).unwrap();
            if format == "table" {
                assert_ne!(output, "");
            } else {
                let report: serde_json::Value = serde_json::from_str(&output).unwrap();
                assert_eq!(report["schema"], schema);
                assert_eq!(report["generation"], search["generation"]);
            }
        }
    }
    let cli =
        Cli::try_parse_from(["vitnet", "dgml", "why", path.to_str().unwrap(), "label"]).unwrap();
    assert!(
        execute(&cli)
            .unwrap_err()
            .to_string()
            .contains("dgml.query.id")
    );
}

#[test]
fn daemon_option_rejects_nonquery_commands_without_silent_local_execution() {
    let cli = Cli::try_parse_from([
        "vitnet",
        "--daemon",
        "not-running",
        "metadata",
        "nonexistent.csv",
    ])
    .unwrap();
    assert!(
        execute(&cli)
            .unwrap_err()
            .to_string()
            .contains("daemon.command")
    );
}

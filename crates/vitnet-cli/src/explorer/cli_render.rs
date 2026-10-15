use super::{
    ContributorArgs, ContributorColumn, InspectArgs, InspectView, argument, command_prefix, display,
};
use crate::explorer::{ExploreCommand, diagnostic};
use crate::{AppError, Cli};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;

fn scalar(value: &Value) -> String {
    display::text(
        value
            .as_str()
            .map_or_else(|| value.to_string(), str::to_owned)
            .as_str(),
    )
}

fn array(value: &Value) -> &[Value] {
    value.as_array().map_or(&[], Vec::as_slice)
}

fn field(name: &str, value: &Value) -> String {
    if name == "bytes" || name.ends_with("_bytes") {
        display::optional(value.as_u64())
    } else {
        scalar(value)
    }
}

fn footer(output: &mut String, envelope: &Value) {
    let data = &envelope["data"];
    writeln!(
        output,
        "\nScan: {} positions; {} batches; {} ms; stop={}",
        scalar(&data["scanned"]),
        scalar(&data["batches"]),
        scalar(&data["elapsed_ms"]),
        scalar(&data["stop_reason"])
    )
    .unwrap();
    if let Some(next) = envelope["next_command"].as_str() {
        writeln!(output, "Continue (PowerShell): {}", display::text(next)).unwrap();
    } else if data["stop_reason"] == "complete" {
        output.push_str("End of captured dataset reached.\n");
    }
    if array(&data["entries"]).is_empty() && data["stop_reason"] != "complete" {
        output.push_str("No match in the scanned range; this is not a complete no-match result.\n");
    }
}

fn summary(output: &mut String, value: &Value) {
    let accounting = &value["accounting"];
    let ledger = &value["ledger"];
    let total = accounting["total_bytes"].as_u64();
    writeln!(output, "Size ledger: {}\nReported object total: {}\nPhysical binary inventory: {}\nMetadata lower bound (overlapping): {}\nResource child assets (overlapping): {}\nResource containers (overlapping children): {}",
        scalar(&value["title"]), display::optional(total),
        display::optional(ledger["physical_total_bytes"].as_u64()),
        display::optional(accounting["metadata_lower_bound_bytes"].as_u64()),
        display::optional(ledger["resource_asset_bytes"].as_u64()),
        display::optional(ledger["resource_container_bytes"].as_u64())).unwrap();
    output.push_str(
        "\nAdditive streams\nSize           Exact bytes     % accounted  Identities  Stream\n",
    );
    for stream in array(&accounting["streams"]) {
        writeln!(
            output,
            "{:<14} {:>14} {:>11} {:>11}  {}",
            stream["bytes"]
                .as_u64()
                .map_or_else(|| "Unknown".into(), display::bytes),
            scalar(&stream["bytes"]),
            stream["bytes"]
                .as_u64()
                .map_or_else(|| "Unknown".into(), |bytes| display::percent(bytes, total)),
            scalar(&stream["identities"]),
            scalar(&stream["name"])
        )
        .unwrap();
    }
    if !ledger.is_object() {
        output
            .push_str("\nLegacy bundle: reprepare for corrected resource/container accounting.\n");
    }
    if let Some(basis) = ledger["accounting_basis"].as_str() {
        writeln!(output, "\n{}", display::text(basis)).unwrap();
    }
    if let Some(basis) = ledger["resource_basis"].as_str() {
        writeln!(output, "{}", display::text(basis)).unwrap();
    }
    let shown = value["coverage"]["displayed_accounted_bytes"].as_u64();
    writeln!(
        output,
        "Bundled contributor preview: {} / {}. This is not complete ranking coverage.",
        display::optional(shown),
        display::optional(total)
    )
    .unwrap();
    output.push_str("Missing physical measurements stay Unknown; supplied binaries are an inventory sum, not proof of one executable.\n");
    output.push_str("Next: explore contributors <bundle>, explore datasets <bundle>, explore records <bundle> resources.\n");
}

fn datasets(output: &mut String, value: &Value) {
    output.push_str("Complete captured dataset catalog\nRecords       Stored size      Storage             Dataset\n");
    for dataset in array(&value["datasets"]) {
        writeln!(
            output,
            "{:>12}  {:<16} {:<19} {}",
            scalar(&dataset["records"]),
            display::optional(dataset["data_bytes"].as_u64()),
            scalar(&dataset["storage"]),
            scalar(&dataset["name"])
        )
        .unwrap();
    }
    if let Some(total) = value["total_datasets"].as_u64() {
        writeln!(output, "Dataset selection: {} / {total} captured datasets. Filtering does not remove captured evidence.", scalar(&value["returned_datasets"])).unwrap();
        if array(&value["datasets"]).is_empty() {
            output.push_str("No captured dataset matches these discovery filters.\n");
        }
    }
    writeln!(
        output,
        "\nComplete captured catalogs: {}; complete byte ranking: {}",
        scalar(&value["complete"]),
        scalar(&value["ranking_available"])
    )
    .unwrap();
    for key in ["scope", "comparison_scope"] {
        writeln!(output, "{}", scalar(&value[key])).unwrap();
    }
    for inventory in array(&value["supplements"]) {
        writeln!(output, "Supplement: {}", scalar(inventory)).unwrap();
    }
    output.push_str("Next: explore records <bundle> <dataset>; use --filter field=value for exact captured fields.\n");
}

fn contributor_cells(
    row: &Value,
    bytes: u64,
    accounted: bool,
    total: Option<u64>,
    parent: Option<u64>,
    cumulative: u64,
) -> BTreeMap<ContributorColumn, String> {
    BTreeMap::from([
        (ContributorColumn::Ordinal, scalar(&row["ordinal"])),
        (ContributorColumn::Size, display::bytes(bytes)),
        (ContributorColumn::Bytes, bytes.to_string()),
        (
            ContributorColumn::Total,
            if accounted {
                display::percent(bytes, total)
            } else {
                "Overlap".into()
            },
        ),
        (
            ContributorColumn::Parent,
            if accounted {
                display::percent(bytes, parent)
            } else {
                "Unknown".into()
            },
        ),
        (
            ContributorColumn::Cumulative,
            if accounted {
                display::percent(cumulative, parent)
            } else {
                "Unknown".into()
            },
        ),
        (
            ContributorColumn::Role,
            if accounted {
                "Additive".into()
            } else {
                "Overlap".into()
            },
        ),
        (ContributorColumn::Stream, scalar(&row["stream"])),
        (
            ContributorColumn::Identity,
            format!(
                "{}{}{}",
                scalar(&row["identity"]),
                if row["truncated"] == true {
                    " [display shortened]"
                } else {
                    ""
                },
                if row["identity_lossy"] == true {
                    " [upstream lossy]"
                } else {
                    ""
                }
            ),
        ),
    ])
}

fn contributors(
    output: &mut String,
    args: &ContributorArgs,
    envelope: &Value,
    snapshot: &Value,
) -> Result<(), AppError> {
    let value = &envelope["data"];
    let total = snapshot["accounting"]["total_bytes"].as_u64();
    let parent = value["scope"]["bytes"].as_u64();
    writeln!(output, "Complete captured byte ranking ({})\nAccounted total: {}\nParent before text filter: {}\nScope basis: {}",
        scalar(&value["order"]), display::optional(total), display::optional(parent), scalar(&value["scope"]["basis"])).unwrap();
    if args.columns.is_empty() {
        output.push_str("\nOrdinal       Size           % total   % parent  Cumul % parent Role       Stream    Identity preview\n");
    } else {
        writeln!(
            output,
            "\n{}",
            args.columns
                .iter()
                .map(|column| column.name().to_ascii_uppercase())
                .collect::<Vec<_>>()
                .join("  ")
        )
        .unwrap();
    }
    if args.accounted_only || args.min_bytes.is_some() || args.max_bytes.is_some() || args.exact {
        output.push_str("Parent denominator remains the complete partition before text, byte-range and accounting filters.\n");
    }
    let mut cumulative = 0_u64;
    let mut buckets = BTreeSet::new();
    for row in array(&value["entries"]) {
        let bytes = row["bytes"]
            .as_u64()
            .ok_or_else(|| diagnostic("explorer.invariant", "ranked row lacks unsigned bytes"))?;
        let accounted = row["accounted"]
            .as_bool()
            .ok_or_else(|| diagnostic("explorer.invariant", "ranked row lacks accounting role"))?;
        if accounted {
            cumulative = cumulative
                .checked_add(bytes)
                .ok_or_else(|| diagnostic("explorer.size", "displayed byte overflow"))?;
        }
        let cells = contributor_cells(row, bytes, accounted, total, parent, cumulative);
        if args.columns.is_empty() {
            writeln!(
                output,
                "{:>12}  {:<13} {:>9} {:>10} {:>15} {:<10} {:<9} {}",
                cells[&ContributorColumn::Ordinal],
                cells[&ContributorColumn::Size],
                cells[&ContributorColumn::Total],
                cells[&ContributorColumn::Parent],
                cells[&ContributorColumn::Cumulative],
                cells[&ContributorColumn::Role],
                cells[&ContributorColumn::Stream],
                cells[&ContributorColumn::Identity],
            )
            .unwrap();
        } else {
            let selected = args
                .columns
                .iter()
                .map(|column| cells[column].as_str())
                .collect::<Vec<_>>();
            writeln!(output, "{}", selected.join("  ")).unwrap();
        }
        if row["stream"] == "Blobs"
            && let Some(identity) = row["identity"].as_str()
            && row["truncated"] != true
        {
            buckets.insert(identity);
        }
    }
    writeln!(
        output,
        "\nAccounted bytes in this page: {} ({} of parent). Cumulative share resets on each page.",
        display::exact(cumulative),
        display::percent(cumulative, parent)
    )
    .unwrap();
    for name in buckets {
        if let Some(bucket) = super::super::glossary::lookup(name)? {
            writeln!(
                output,
                "\n{name}: {}\n{}\nInvestigate: {}\nProducer: {}",
                bucket.title, bucket.description, bucket.investigation, bucket.source
            )
            .unwrap();
        }
    }
    output.push_str("Owner prefixes and assembly candidates are not exclusive source ownership or predicted savings.\n");
    output.push_str("Inspect using the ORIGINAL ordinal above, not rank position: explore inspect <bundle> <ordinal> --view source|shape.\n");
    footer(output, envelope);
    Ok(())
}

fn records(output: &mut String, command: &ExploreCommand, envelope: &Value) {
    if matches!(command, ExploreCommand::Origins(_)) {
        output.push_str("Recorded origins: associations, not compiler retention, exclusive bytes or removable size.\n");
    }
    writeln!(
        output,
        "Complete captured inventory: {} records; order={}",
        scalar(&envelope["data"]["total"]),
        scalar(&envelope["data"]["order"])
    )
    .unwrap();
    for row in array(&envelope["data"]["entries"]) {
        writeln!(
            output,
            "\n#{}  {}",
            scalar(&row["ordinal"]),
            scalar(&row["summary"])
        )
        .unwrap();
        if let Some(fields) = row["fields"].as_object() {
            for (name, value) in fields {
                writeln!(output, "  {}: {}", display::text(name), field(name, value)).unwrap();
            }
        } else {
            for name in ["bytes", "stream"] {
                if let Some(value) = row.get(name) {
                    writeln!(output, "  {name}: {}", field(name, value)).unwrap();
                }
            }
        }
        if row["capture"]["upstream_truncated"] == true {
            output.push_str(
                "  Upstream text was truncated; the original omitted text was not captured.\n",
            );
        }
        let shortened = array(&row["capture"]["fields_truncated"]);
        if !shortened.is_empty() {
            writeln!(
                output,
                "  Display shortened: {}. Open inspect for full captured values.",
                shortened.iter().map(scalar).collect::<Vec<_>>().join(", ")
            )
            .unwrap();
        }
    }
    output.push_str(
        "\nInventory containers may overlap child assets; projections are not extra accounted size or removable-byte estimates.\nPreviews are bounded; graph ordinals are node IDs or global CSR edge ordinals.\n",
    );
    output.push_str("Next: explore inspect <bundle> <ordinal> --dataset <dataset>; origins use dataset assembly_links.\n");
    footer(output, envelope);
}

fn inspect_base(cli: &Cli, args: &InspectArgs, generation: &str) -> String {
    let mut output = format!("{} explore inspect", command_prefix(cli));
    argument(&mut output, "", &args.bundle.to_string_lossy());
    write!(output, " {}", args.ordinal).unwrap();
    argument(&mut output, "--dataset", &args.dataset);
    argument(
        &mut output,
        "--view",
        match args.view {
            InspectView::Record => "record",
            InspectView::Source => "source",
            InspectView::Shape => "shape",
            InspectView::Symbol => "symbol",
        },
    );
    if !args.path.is_empty() {
        argument(
            &mut output,
            "--path",
            &args
                .path
                .iter()
                .map(u64::to_string)
                .collect::<Vec<_>>()
                .join(","),
        );
    }
    if args.key {
        output.push_str(" --key");
    }
    argument(&mut output, "--generation", generation);
    output
}

pub(super) fn inspect_resume(
    cli: &Cli,
    args: &InspectArgs,
    value: &Value,
    generation: &str,
) -> Value {
    value["next_start"].as_u64().map_or(Value::Null, |start| {
        json!(format!(
            "{} --start {start}",
            inspect_base(cli, args, generation)
        ))
    })
}

fn inspect(output: &mut String, cli: &Cli, args: &InspectArgs, envelope: &Value) {
    let value = &envelope["data"];
    writeln!(
        output,
        "Captured {} #{}; {:?} view; kind={}",
        display::text(&args.dataset),
        args.ordinal,
        args.view,
        scalar(&value["kind"])
    )
    .unwrap();
    match value["kind"].as_str() {
        Some("string") => {
            writeln!(
                output,
                "UTF-8 bytes: start={}, total={}\n{}",
                scalar(&value["start"]),
                scalar(&value["total_bytes"]),
                scalar(&value["text"])
            )
            .unwrap();
            output
                .push_str("Terminal controls are escaped; JSON preserves captured text exactly.\n");
        }
        Some("object" | "array") => {
            output.push_str("String summaries are bounded previews; descend to read complete captured values.\n");
            writeln!(
                output,
                "Index   Kind      Key / captured preview ({} children)",
                scalar(&value["total"])
            )
            .unwrap();
            for entry in array(&value["entries"]) {
                writeln!(
                    output,
                    "{:>6}  {:<9} {}{}: {}",
                    scalar(&entry["index"]),
                    scalar(&entry["kind"]),
                    scalar(&entry["key"]),
                    if entry["key_truncated"] == true {
                        " [key shortened; --key reads full name]"
                    } else {
                        ""
                    },
                    scalar(&entry["summary"])
                )
                .unwrap();
            }
            let mut child = args.clone();
            child.key = false;
            child.path.clear();
            let path = args.path.iter().map(u64::to_string).collect::<Vec<_>>();
            writeln!(
                output,
                "Descend: {} --path {}<child-index>",
                display::text(&inspect_base(
                    cli,
                    &child,
                    envelope["generation"].as_str().unwrap_or("")
                )),
                if path.is_empty() {
                    String::new()
                } else {
                    format!("{},", path.join(","))
                }
            )
            .unwrap();
        }
        _ => {
            writeln!(output, "{}", scalar(&value["display"])).unwrap();
        }
    }
    if let Some(next) = envelope["next_command"].as_str() {
        writeln!(output, "Continue (PowerShell): {}", display::text(next)).unwrap();
    }
    output.push_str("Captured values only. Upstream omissions cannot be reconstructed; source candidates and parsed shapes do not prove retention or savings.\n");
}

#[allow(clippy::too_many_lines)] // Explicit renderers keep each operation's accounting contract visible.
pub(super) fn table(
    cli: &Cli,
    command: &ExploreCommand,
    envelope: &Value,
    snapshot: &Value,
) -> Result<String, AppError> {
    let mut output = format!("Bundle generation: {}\n", scalar(&envelope["generation"]));
    match command {
        ExploreCommand::Summary { .. } => summary(&mut output, &envelope["data"]),
        ExploreCommand::Datasets(_) => datasets(&mut output, &envelope["data"]),
        ExploreCommand::Contributors(args) => contributors(&mut output, args, envelope, snapshot)?,
        ExploreCommand::Records(_)
        | ExploreCommand::Lenses(_)
        | ExploreCommand::Origins(_)
        | ExploreCommand::Opportunities(_)
        | ExploreCommand::Budgets(_) => {
            records(&mut output, command, envelope);
            if matches!(
                command,
                ExploreCommand::Opportunities(_) | ExploreCommand::Budgets(_)
            ) {
                output.push_str("Measured cohorts may overlap; additive budgets reconcile only within one dimension/target. These are not predicted savings.\nInspect the original ordinal with --dataset opportunities|budgets; full evidence remains in the captured record.\n");
            }
        }
        ExploreCommand::Retention(_) => {
            let data = &envelope["data"];
            writeln!(
                output,
                "Annotated compiler retention: stop={}; visited={}\n",
                scalar(&data["witness"]["stop_reason"]),
                scalar(&data["witness"]["visited_nodes"])
            )
            .unwrap();
            for path in array(&data["annotated_paths"]) {
                writeln!(output, "Root kind: {}", scalar(&path["root_kind"])).unwrap();
                for anchor in array(&path["anchors"]) {
                    writeln!(
                        output,
                        "  Node {}: {}\n    Association: {}; possible mechanisms: {}",
                        scalar(&anchor["node_id"]),
                        scalar(&anchor["producer_label"]),
                        scalar(&anchor["sources"]["status"]),
                        scalar(&anchor["possible_mechanisms"])
                    )
                    .unwrap();
                }
            }
            for caveat in array(&data["caveats"]) {
                writeln!(output, "{}", scalar(caveat)).unwrap();
            }
        }
        ExploreCommand::Inspect(args) => inspect(&mut output, cli, args, envelope),
        ExploreCommand::Footprint(_) => {
            let value = &envelope["data"];
            output.push_str("Feature footprint: measured owner accounting, not removable size.\n");
            for (key, value) in value["ledger"]
                .as_object()
                .ok_or_else(|| diagnostic("explorer.invariant", "feature ledger missing"))?
            {
                writeln!(output, "{}: {}", key, field(key, value)).unwrap();
            }
            writeln!(
                output,
                "Complete: {}; stop={}; scanned={}\n{}",
                scalar(&value["complete"]),
                scalar(&value["stop_reason"]),
                scalar(&value["scanned"]),
                scalar(&value["scope"])
            )
            .unwrap();
            if !value["next_after"].is_null() {
                writeln!(
                    output,
                    "Resume remaining owner range with --after {} --generation {}",
                    scalar(&value["next_after"]),
                    scalar(&envelope["generation"])
                )
                .unwrap();
            }
        }
        ExploreCommand::CohortRetention(_) => {
            output.push_str(
                "Representative retention evidence (not every path or sole prerequisites)\n",
            );
            for root in array(&envelope["data"]["observed_roots"]) {
                writeln!(
                    output,
                    "Node {}: {} [{}]; {} observed paths",
                    scalar(&root["node_id"]),
                    scalar(&root["label"]),
                    scalar(&root["root_kind"]),
                    scalar(&root["observed_paths"])
                )
                .unwrap();
            }
            for seed in array(&envelope["data"]["seeds"]) {
                writeln!(
                    output,
                    "Identity {}: {}",
                    scalar(&seed["ordinal"]),
                    scalar(&seed["status"])
                )
                .unwrap();
            }
            writeln!(output, "{}", scalar(&envelope["data"]["scope"])).unwrap();
        }
        _ => {
            return Err(diagnostic(
                "explorer.invariant",
                "unsupported terminal renderer",
            ));
        }
    }
    Ok(output)
}

use super::{ExplainArgs, GlossaryArgs, argument, command_prefix, request, serialize};
use crate::explorer::server::{Backend, Query};
use crate::explorer::{ExploreCommand, attribution, data, diagnostic, glossary};
use crate::{AppError, Cli, display};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::path::Path;
use vitnet_dgml::IndexControl;

fn check(control: &IndexControl) -> Result<(), AppError> {
    if control.is_cancelled() {
        Err(diagnostic(
            "resource.cancelled",
            "terminal investigation cancelled",
        ))
    } else {
        Ok(())
    }
}

fn envelope(operation: &str, generation: Option<&str>, value: Value) -> Value {
    let mut report =
        json!({"schema":"vitnet.explorer-cli.v1","operation":operation,"generation":generation});
    report["data"] = value;
    report
}

pub(super) fn execute(
    cli: &Cli,
    command: &ExploreCommand,
    control: &IndexControl,
) -> Result<String, AppError> {
    check(control)?;
    let report = match command {
        ExploreCommand::Glossary(args) => envelope("glossary", None, glossary_report(args)?),
        ExploreCommand::Compare { before, after } => {
            let before = ledger(before, cli.memory_limit.0, control)?;
            let after = ledger(after, cli.memory_limit.0, control)?;
            envelope("compare", Some(&after.generation), compare(&before, &after))
        }
        _ => {
            let (path, expected, operation) = match command {
                ExploreCommand::Explain(args) => {
                    (&args.bundle, args.generation.as_deref(), "explain")
                }
                ExploreCommand::Coverage { bundle } => (bundle, None, "coverage"),
                ExploreCommand::Guide { bundle } => (bundle, None, "guide"),
                _ => {
                    return Err(diagnostic(
                        "explorer.invariant",
                        "not a connected terminal report",
                    ));
                }
            };
            let bundle = data::Bundle::open(path, cli.memory_limit.0)?;
            let generation = &bundle.manifest.generation;
            if expected.is_some_and(|expected| expected != generation) {
                return Err(diagnostic(
                    "explorer.generation",
                    "bundle generation differs; restart the query",
                ));
            }
            let index = vitnet_attribution::open_index(
                &bundle.manifest.attribution_index,
                cli.memory_limit.0,
            )
            .map_err(attribution)?;
            let mut backend = Backend::new(&bundle, &index, cli.memory_limit.0)?;
            let value = if let ExploreCommand::Explain(args) = command {
                explain(cli, args, &bundle, &mut backend, control)?
            } else {
                let catalog = backend.query(&request(generation, Query::Catalog {}), control)?;
                if matches!(command, ExploreCommand::Coverage { .. }) {
                    coverage(&bundle, &catalog)
                } else {
                    guide(cli, path, &bundle, &catalog)
                }
            };
            envelope(operation, Some(generation), value)
        }
    };
    check(control)?;
    serialize(cli, &report, || table(&report))
}

fn bundle_command(cli: &Cli, path: &Path, verb: &str) -> String {
    let mut command = format!("{} explore {verb}", command_prefix(cli));
    argument(&mut command, "", &path.to_string_lossy());
    command
}

fn inspect_command(cli: &Cli, args: &ExplainArgs, generation: &str, view: &str) -> String {
    let mut command = bundle_command(cli, &args.bundle, "inspect");
    write!(command, " {}", args.ordinal).unwrap();
    argument(&mut command, "--view", view);
    argument(&mut command, "--generation", generation);
    command
}

fn explain(
    cli: &Cli,
    args: &ExplainArgs,
    bundle: &data::Bundle,
    backend: &mut Backend<'_>,
    control: &IndexControl,
) -> Result<Value, AppError> {
    check(control)?;
    let entry = backend.row(args.ordinal)?;
    let generation = &bundle.manifest.generation;
    let source = backend.query(
        &request(
            generation,
            Query::SourceValue {
                ordinal: args.ordinal,
                path: Vec::new(),
                start: 0,
                key: false,
            },
        ),
        control,
    )?;
    let shape = if entry.identity_lossy {
        json!({"status":"unavailable_lossy_identity","page":null})
    } else {
        let page = backend.query(
            &request(
                generation,
                Query::IdentityShapeValue {
                    ordinal: args.ordinal,
                    path: Vec::new(),
                    start: 0,
                    key: false,
                },
            ),
            control,
        )?;
        json!({"status":if page["kind"] == "null" { "not_generic" } else { "available" },"page":page})
    };
    let bucket = if entry.stream == "Blobs" && !entry.identity_lossy {
        glossary::lookup(&entry.identity)?
    } else {
        None
    };
    let total = bundle.snapshot["accounting"]["total_bytes"].clone();
    Ok(json!({
        "identity":data::Row::new(&entry,args.ordinal),
        "accounted_total_bytes":total,
        "source":source,"shape":shape,"bucket":bucket,
        "commands":{
            "record":inspect_command(cli,args,generation,"record"),
            "source":inspect_command(cli,args,generation,"source"),
            "shape":if entry.identity_lossy { None } else { Some(inspect_command(cli,args,generation,"shape")) },
        },
        "scope":"Bounded recorded evidence. Source candidates and parsed producer shapes do not establish retention, exclusive physical ownership or removable bytes."
    }))
}

fn glossary_report(args: &GlossaryArgs) -> Result<Value, AppError> {
    let mut buckets = glossary::catalog()?;
    let total = buckets.len();
    if let Some(name) = &args.bucket {
        if !buckets.contains_key(name) {
            return Err(diagnostic(
                "explorer.glossary",
                "unknown exact compiler bucket name",
            ));
        }
        buckets.retain(|key, _| key == name);
    }
    if let Some(contains) = &args.contains {
        if contains.len() > 1024 {
            return Err(diagnostic(
                "resource.explorer.query",
                "glossary selector exceeds 1024 bytes",
            ));
        }
        let contains = contains.to_lowercase();
        buckets.retain(|name, bucket| {
            [
                name.as_str(),
                &bucket.title,
                &bucket.description,
                &bucket.investigation,
            ]
            .into_iter()
            .any(|text| text.to_lowercase().contains(&contains))
        });
    }
    Ok(
        json!({"total_buckets":total,"returned_buckets":buckets.len(),"buckets":buckets,
        "scope":"Pinned Microsoft producer descriptions, not measurements or proven causes for a particular build."}),
    )
}

fn coverage(bundle: &data::Bundle, catalog: &Value) -> Value {
    json!({
        "complete_catalog":catalog["complete"],"ranking_available":catalog["ranking_available"],
        "identities":bundle.manifest.identities,
        "datasets":catalog["datasets"].as_array().map(Vec::len),
        "sources_captured":catalog["sources_captured"],"generators_captured":catalog["generators_captured"],
        "accounted_bytes":bundle.snapshot["accounting"]["total_bytes"],
        "physical_bytes":bundle.snapshot["ledger"]["physical_total_bytes"],
        "preview":bundle.snapshot["coverage"],
        "graphs":bundle.snapshot["graphs"],
        "scope":catalog["scope"],"comparison_scope":catalog["comparison_scope"],
        "limitations":[
            "Complete means complete captured data, not complete original source or producer attributes.",
            "Snapshot preview coverage is not capture coverage or complete byte-ranking coverage.",
            "Graph presence, selected witnesses and source descriptor counts do not measure retention-path coverage.",
            "This is evidence readiness, not a full integrity audit; use explore verify for fingerprints."
        ]
    })
}

fn dataset_count(catalog: &Value, name: &str) -> Option<u64> {
    catalog["datasets"]
        .as_array()?
        .iter()
        .find(|dataset| dataset["name"] == name)?["records"]
        .as_u64()
}

#[allow(clippy::too_many_lines)]
fn guide(cli: &Cli, path: &Path, bundle: &data::Bundle, catalog: &Value) -> Value {
    let generation = &bundle.manifest.generation;
    let mut actions = vec![json!({"purpose":"Check captured evidence coverage",
        "reason":"Separate complete captured data from bounded previews and missing measurements.",
        "command":bundle_command(cli,path,"coverage")})];
    if catalog["ranking_available"] == true {
        let largest = bundle.snapshot["accounting"]["streams"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|stream| Some((stream["bytes"].as_u64()?, stream["name"].as_str()?)))
            .max_by(|left, right| left.0.cmp(&right.0).then_with(|| right.1.cmp(left.1)));
        let mut command = bundle_command(cli, path, "contributors");
        argument(&mut command, "--generation", generation);
        command.push_str(" --accounted-only");
        if let Some((bytes, name)) = largest {
            argument(&mut command, "--stream", name);
            actions.push(json!({"purpose":"Inspect the largest additive stream","stream":name,"bytes":bytes,
                "reason":"Largest captured additive stream, not a claimed cause or savings estimate.","command":command}));
        } else {
            actions.push(json!({"purpose":"Inspect complete captured contributors",
                "reason":"Ranking exists but no measured additive stream denominator is captured.","command":command}));
        }
    } else {
        actions.push(json!({"purpose":"Check legacy inputs before preparing a new bundle",
            "reason":"This bundle has no complete byte ranking. Verification does not create missing capture.",
            "command":bundle_command(cli,path,"verify")}));
    }
    for (dataset, purpose, reason) in [
        (
            "opportunities",
            "Inspect ranked bloat investigations",
            "Measured cohorts overlap and do not predict savings.",
        ),
        (
            "budgets",
            "Review cross-stream ownership budgets",
            "Reconcile assembly partitions and each package target separately; unknown costs remain visible.",
        ),
        (
            "generator_runs",
            "Review actual generator output capture",
            "Referenced analyzers, output files, execution and compiled checksum trust are independent evidence.",
        ),
        (
            "generator_links",
            "Inspect captured generator input triggers",
            "Supplied assertions and syntax candidates are not generator execution telemetry.",
        ),
        (
            "resources",
            "Review embedded resource inventory",
            "Asset and container inventories may overlap; neither is extra accounted size.",
        ),
        (
            "generic_families",
            "Inspect generic amplification",
            "Recorded family membership is not exclusive bytes or source-language instantiation count.",
        ),
        (
            "assembly_links",
            "Trace recorded assembly/package origins",
            "Recorded origins do not prove compiler retention or removable size.",
        ),
        (
            "diagnostics",
            "Review capture diagnostics",
            "Diagnostics can explain missing measurements or limitations, not erase them.",
        ),
    ] {
        if let Some(count) = dataset_count(catalog, dataset).filter(|count| *count != 0) {
            let mut command = bundle_command(
                cli,
                path,
                if dataset == "assembly_links" {
                    "origins"
                } else {
                    "records"
                },
            );
            if dataset != "assembly_links" {
                argument(&mut command, "", dataset);
            }
            argument(&mut command, "--generation", generation);
            actions.push(json!({"purpose":purpose,"dataset":dataset,"records":count,"reason":reason,"command":command}));
        }
    }
    if let Some(graph) = bundle.snapshot["graphs"]
        .as_array()
        .and_then(|graphs| graphs.first())
    {
        if let Some(kind) = graph["kind"].as_str() {
            let mut command = bundle_command(cli, path, "records");
            argument(&mut command, "", &format!("graph_{kind}_nodes"));
            argument(&mut command, "--generation", generation);
            actions.push(json!({"purpose":"Locate recorded dependency nodes","reason":"Graph node IDs are not identity ordinals; degree is not byte size.","command":command}));
        }
    }
    json!({"actions":actions,
        "accounted_bytes":bundle.snapshot["accounting"]["total_bytes"],
        "missing_physical_measurement":bundle.snapshot["ledger"]["physical_total_bytes"].is_null(),
        "sources_captured":catalog["sources_captured"],
        "scope":"Investigation suggestions follow captured facts. They do not diagnose causes or recommend deleting bytes.",
        "physical_note":"Absent physical inventory cannot establish executable size; capture new physical evidence and prepare a new bundle."})
}

struct Ledger {
    generation: String,
    measures: BTreeMap<&'static str, Option<u64>>,
    streams: BTreeMap<String, u64>,
}

fn measurement(value: &Value) -> Result<Option<u64>, AppError> {
    if value.is_null() {
        return Ok(None);
    }
    value.as_u64().map(Some).ok_or_else(|| {
        diagnostic(
            "explorer.accounting",
            "captured measurement is not unsigned bytes",
        )
    })
}

fn ledger(path: &Path, memory: u64, control: &IndexControl) -> Result<Ledger, AppError> {
    check(control)?;
    let bundle = data::Bundle::open(path, memory)?;
    // Only compact ledger values survive this load; do not retain both snapshots.
    let mut measures = BTreeMap::new();
    for (name, value) in [
        ("accounted", &bundle.snapshot["accounting"]["total_bytes"]),
        (
            "physical",
            &bundle.snapshot["ledger"]["physical_total_bytes"],
        ),
        (
            "metadata_lower_bound",
            &bundle.snapshot["accounting"]["metadata_lower_bound_bytes"],
        ),
        (
            "resource_assets",
            &bundle.snapshot["ledger"]["resource_asset_bytes"],
        ),
        (
            "resource_containers",
            &bundle.snapshot["ledger"]["resource_container_bytes"],
        ),
    ] {
        measures.insert(name, measurement(value)?);
    }
    let mut streams = BTreeMap::new();
    if let Some(entries) = bundle.snapshot["accounting"]["streams"].as_array() {
        for stream in entries {
            check(control)?;
            let name = stream["name"]
                .as_str()
                .ok_or_else(|| diagnostic("explorer.accounting", "stream has no captured name"))?;
            let bytes = measurement(&stream["bytes"])?.ok_or_else(|| {
                diagnostic(
                    "explorer.accounting",
                    "additive stream has no byte measurement",
                )
            })?;
            if streams.insert(name.to_owned(), bytes).is_some() {
                return Err(diagnostic(
                    "explorer.accounting",
                    "duplicate captured stream",
                ));
            }
        }
    }
    Ok(Ledger {
        generation: bundle.manifest.generation,
        measures,
        streams,
    })
}

fn change(name: &str, role: &str, before: Option<u64>, after: Option<u64>) -> Value {
    let delta = before
        .zip(after)
        .map(|(before, after)| i128::from(after) - i128::from(before));
    let percent = delta
        .zip(before.filter(|before| *before != 0))
        .map(|(delta, before)| {
            let hundredths =
                (delta.unsigned_abs() * 10_000 + u128::from(before) / 2) / u128::from(before);
            let hundredths =
                i128::try_from(hundredths).expect("u64 byte delta basis points fit i128");
            if delta < 0 { -hundredths } else { hundredths }
        });
    json!({"name":name,"role":role,"before_bytes":before,"after_bytes":after,
        "delta_bytes":delta,"change_basis_points":percent})
}

fn compare(before: &Ledger, after: &Ledger) -> Value {
    let measurements = [
        "accounted",
        "physical",
        "metadata_lower_bound",
        "resource_assets",
        "resource_containers",
    ]
    .into_iter()
    .map(|name| {
        change(
            name,
            match name {
                "accounted" => "reported_total",
                "physical" => "physical_inventory",
                _ => "overlap",
            },
            before.measures[name],
            after.measures[name],
        )
    })
    .collect::<Vec<_>>();
    let names: BTreeSet<_> = before.streams.keys().chain(after.streams.keys()).collect();
    let streams = names
        .into_iter()
        .map(|name| {
            let value = |ledger: &Ledger| {
                ledger
                    .streams
                    .get(name)
                    .copied()
                    .or_else(|| ledger.measures["accounted"].map(|_| 0))
            };
            change(name, "additive_stream", value(before), value(after))
        })
        .collect::<Vec<_>>();
    json!({"before_generation":before.generation,"after_generation":after.generation,
        "measurements":measurements,"streams":streams,
        "scope":"Compact captured-ledger comparison, not identity-level deltas or a savings prediction. Physical inventories may contain different binaries; overlapping projections are not extra additive totals.",
        "percent_basis":"Signed change divided by before bytes; missing or zero before measurements have no defined percentage."})
}

fn scalar(value: &Value) -> String {
    value
        .as_str()
        .map_or_else(|| value.to_string(), display::text)
}

fn page(output: &mut String, value: &Value) {
    if let Some(entries) = value["entries"].as_array() {
        for entry in entries {
            writeln!(
                output,
                "  {}: {}",
                scalar(&entry["key"]),
                scalar(&entry["summary"])
            )
            .unwrap();
        }
    }
}

#[allow(clippy::too_many_lines)]
fn table(report: &Value) -> Result<String, AppError> {
    let value = &report["data"];
    let mut output = String::new();
    if !report["generation"].is_null() {
        writeln!(
            output,
            "Bundle generation: {}",
            scalar(&report["generation"])
        )
        .unwrap();
    }
    match report["operation"].as_str() {
        Some("explain") => {
            let identity = &value["identity"];
            writeln!(output,"Contributor #{}: {}\nStream: {}; role: {}\nSize: {}\nShare of accounted total: {}\nCaptured identity: {} bytes{}{}",
                scalar(&identity["ordinal"]),scalar(&identity["identity"]),scalar(&identity["stream"]),
                if identity["accounted"] == true { "Additive" } else { "Overlap" },
                display::optional(identity["bytes"].as_u64()),
                if identity["accounted"] == true { identity["bytes"].as_u64().map_or_else(|| "Unknown".into(), |bytes| display::percent(bytes,value["accounted_total_bytes"].as_u64())) } else { "Overlap".into() },
                scalar(&identity["identity_bytes"]),if identity["truncated"] == true { "; display shortened" } else { "" },
                if identity["identity_lossy"] == true { "; upstream lossy" } else { "" }).unwrap();
            output.push_str("\nRecorded source evidence (bounded):\n");
            page(&mut output, &value["source"]);
            writeln!(
                output,
                "\nProducer shape: {}",
                scalar(&value["shape"]["status"])
            )
            .unwrap();
            page(&mut output, &value["shape"]["page"]);
            if value["bucket"].is_object() {
                writeln!(
                    output,
                    "\nCompiler bucket: {}\n{}\nInvestigate: {}\nProducer: {}",
                    scalar(&value["bucket"]["title"]),
                    scalar(&value["bucket"]["description"]),
                    scalar(&value["bucket"]["investigation"]),
                    scalar(&value["bucket"]["source"])
                )
                .unwrap();
            }
            if let Some(commands) = value["commands"].as_object() {
                for (purpose, command) in commands.iter().filter(|(_, command)| !command.is_null())
                {
                    writeln!(output, "Full {purpose} (PowerShell): {}", scalar(command)).unwrap();
                }
            }
        }
        Some("coverage") => {
            writeln!(output,"Captured evidence coverage\nComplete captured catalog: {}\nComplete byte ranking: {}\nCaptured identities: {}\nDataset choices: {}\nSource declarations: {}\nGenerator descriptors: {}\nPhysical inventory: {}\nBundled contributor preview: {} / {} ({})",
                scalar(&value["complete_catalog"]),scalar(&value["ranking_available"]),scalar(&value["identities"]),
                scalar(&value["datasets"]),scalar(&value["sources_captured"]),scalar(&value["generators_captured"]),
                display::optional(value["physical_bytes"].as_u64()),display::optional(value["preview"]["displayed_accounted_bytes"].as_u64()),
                display::optional(value["accounted_bytes"].as_u64()),
                value["preview"]["displayed_accounted_bytes"].as_u64().map_or_else(|| "Unknown".into(), |bytes| display::percent(bytes,value["accounted_bytes"].as_u64()))).unwrap();
            if let Some(graphs) = value["graphs"].as_array() {
                for graph in graphs {
                    writeln!(
                        output,
                        "Captured graph {}: {} nodes; {} edges",
                        scalar(&graph["kind"]),
                        scalar(&graph["node_count"]),
                        scalar(&graph["edge_count"])
                    )
                    .unwrap();
                }
                if graphs.is_empty() {
                    output.push_str("No dependency graph was captured.\n");
                }
            }
            if let Some(limitations) = value["limitations"].as_array() {
                for limitation in limitations {
                    writeln!(output, "{}", scalar(limitation)).unwrap();
                }
            }
        }
        Some("guide") => {
            output.push_str("Fact-based investigation guide\n");
            if let Some(actions) = value["actions"].as_array() {
                for (index, action) in actions.iter().enumerate() {
                    writeln!(
                        output,
                        "\n{}. {}\n{}\nPowerShell: {}",
                        index + 1,
                        scalar(&action["purpose"]),
                        scalar(&action["reason"]),
                        scalar(&action["command"])
                    )
                    .unwrap();
                    if let Some(bytes) = action["bytes"].as_u64() {
                        writeln!(
                            output,
                            "Measured {}: {} ({} of accounted total)",
                            scalar(&action["stream"]),
                            display::exact(bytes),
                            display::percent(bytes, value["accounted_bytes"].as_u64())
                        )
                        .unwrap();
                    }
                    if let Some(count) = action["records"].as_u64() {
                        writeln!(
                            output,
                            "Captured {}: {count} records",
                            scalar(&action["dataset"])
                        )
                        .unwrap();
                    }
                }
            }
            if value["missing_physical_measurement"] == true {
                writeln!(output, "\n{}", scalar(&value["physical_note"])).unwrap();
            }
            if value["sources_captured"] == 0 {
                output.push_str("No source declarations are captured; source associations are not complete original source coverage.\n");
            }
        }
        Some("glossary") => {
            writeln!(
                output,
                "Pinned compiler glossary: {} / {} buckets",
                scalar(&value["returned_buckets"]),
                scalar(&value["total_buckets"])
            )
            .unwrap();
            if let Some(buckets) = value["buckets"].as_object() {
                for (name, bucket) in buckets {
                    writeln!(
                        output,
                        "\n{}: {}\n{}\nInvestigate: {}\nBrowser view: {}\nProducer: {}",
                        display::text(name),
                        scalar(&bucket["title"]),
                        scalar(&bucket["description"]),
                        scalar(&bucket["investigation"]),
                        scalar(&bucket["view"]),
                        scalar(&bucket["source"])
                    )
                    .unwrap();
                }
                if buckets.is_empty() {
                    output.push_str("No pinned compiler bucket matches this search.\n");
                }
            }
        }
        Some("compare") => {
            writeln!(
                output,
                "Before generation: {}\nCaptured ledger changes",
                scalar(&value["before_generation"])
            )
            .unwrap();
            for key in ["measurements", "streams"] {
                if let Some(rows) = value[key].as_array() {
                    for row in rows {
                        let delta = if row["delta_bytes"].is_null() {
                            "Unknown".into()
                        } else {
                            display::signed(
                                row["delta_bytes"].to_string().parse::<i128>().map_err(
                                    |error| diagnostic("explorer.accounting", error.to_string()),
                                )?,
                            )
                        };
                        let percent = if row["change_basis_points"].is_null() {
                            "Unknown".into()
                        } else {
                            let basis = row["change_basis_points"]
                                .to_string()
                                .parse::<i128>()
                                .map_err(|error| {
                                    diagnostic("explorer.accounting", error.to_string())
                                })?;
                            format!(
                                "{}{}",
                                match basis.cmp(&0) {
                                    std::cmp::Ordering::Less => "-",
                                    std::cmp::Ordering::Greater => "+",
                                    std::cmp::Ordering::Equal => "",
                                },
                                display::basis_points(basis.unsigned_abs())
                            )
                        };
                        writeln!(
                            output,
                            "{} [{}]: {} -> {}; delta {}; change {}",
                            scalar(&row["name"]),
                            scalar(&row["role"]),
                            display::optional(row["before_bytes"].as_u64()),
                            display::optional(row["after_bytes"].as_u64()),
                            delta,
                            percent
                        )
                        .unwrap();
                    }
                }
            }
            writeln!(output, "{}", scalar(&value["percent_basis"])).unwrap();
        }
        _ => {
            return Err(diagnostic(
                "explorer.invariant",
                "unsupported connected report renderer",
            ));
        }
    }
    writeln!(output, "\n{}", scalar(&value["scope"])).unwrap();
    Ok(output)
}

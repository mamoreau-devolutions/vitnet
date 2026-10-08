use crate::{AppError, BatchArgs, Cli, FormatArg};
use clap::Subcommand;
use serde::Serialize;
use std::fmt::Write as _;
use std::path::PathBuf;
use vitnet_attribution::{AttributionError, AttributionReport};

#[derive(Clone, Debug, Subcommand)]
pub enum AttributionCommand {
    /// Atomically persist build evidence and full coalesced MSTAT identities.
    Import {
        evidence: PathBuf,
        #[arg(long)]
        index: PathBuf,
    },
    /// Show complete attribution coverage and bounded contributors.
    Report {
        index: PathBuf,
        #[arg(long, value_parser = crate::parse_positive_usize, default_value_t = 20)]
        top: usize,
        #[arg(long)]
        contains: Option<String>,
    },
    /// Find declarations and generated implementations for an exact identity.
    Source { index: PathBuf, identity: String },
    /// Annotate retention without confusing compiler reachability with execution.
    Explain {
        index: PathBuf,
        node_id: u64,
        #[arg(long, value_parser = ["scan_index", "codegen_index"], default_value = "scan_index")]
        graph: String,
        #[arg(long, value_parser = crate::parse_positive_usize, default_value_t = 20)]
        incoming_limit: usize,
        #[command(flatten)]
        options: BatchArgs,
    },
    /// Compare physical native sizes, MSTAT identities, and recorded provenance.
    Compare {
        before: PathBuf,
        after: PathBuf,
        #[arg(long, value_parser = crate::parse_positive_usize, default_value_t = 20)]
        top: usize,
        #[arg(long, requires = "after_node")]
        before_node: Option<u64>,
        #[arg(long, requires = "before_node")]
        after_node: Option<u64>,
        #[arg(long, value_parser = ["scan_index", "codegen_index"], default_value = "scan_index")]
        graph: String,
        #[command(flatten)]
        options: BatchArgs,
    },
    /// Verify cached identities and check live artifact fingerprints for drift.
    Verify { index: PathBuf },
}

fn classify(error: AttributionError) -> AppError {
    if error.diagnostic.code.starts_with("resource.") {
        AppError::Resource(error.diagnostic)
    } else if error.diagnostic.code.rsplit('.').next() == Some("io") {
        AppError::IoDiagnostic(error.diagnostic)
    } else {
        AppError::Unsupported(error.diagnostic)
    }
}

fn json<T: Serialize>(cli: &Cli, value: &T) -> Result<String, AppError> {
    match cli.format {
        FormatArg::Ndjson => serde_json::to_string(value).map_err(AppError::Json),
        FormatArg::Json | FormatArg::Table => {
            serde_json::to_string_pretty(value).map_err(AppError::Json)
        }
    }
}

#[allow(clippy::too_many_lines)]
fn report_table(report: &AttributionReport) -> String {
    let mut text = format!(
        "Build evidence: {}\nAccounted MSTAT bytes: {}\n",
        report.label,
        report
            .accounted_bytes
            .map_or_else(|| "unknown".into(), |bytes| bytes.to_string())
    );
    writeln!(
        text,
        "Metadata lower bound: {}",
        report
            .metadata_lower_bound_bytes
            .map_or_else(|| "unknown".into(), |bytes| bytes.to_string())
    )
    .unwrap();
    for group in &report.metadata_type_sources {
        writeln!(
            text,
            "{:>16} {} [{}]",
            group.lower_bound_bytes, group.qualified_type, group.status
        )
        .unwrap();
        for source in &group.sources {
            writeln!(text, "  {}:{}", source.path.display(), source.line).unwrap();
        }
    }
    text.push_str("\nComplete accounting mapping coverage (candidate != verified)\n");
    for (status, bytes) in &report.accounted_mapping_bytes {
        writeln!(text, "{bytes:>16}  {status}").unwrap();
    }
    for (heading, groups) in [
        ("Assembly associations", &report.assembly_groups),
        ("Package associations", &report.package_groups),
    ] {
        writeln!(text, "\n{heading} (bounded display)").unwrap();
        for group in groups {
            writeln!(
                text,
                "{:>16}  {} [{}]",
                group.bytes, group.name, group.mapping_status
            )
            .unwrap();
        }
    }
    text.push_str("\nSource and generated-code candidates\n");
    for contributor in &report.contributors {
        writeln!(
            text,
            "{} {:>12} {} [{}]",
            contributor.stream, contributor.bytes, contributor.identity, contributor.sources.status
        )
        .unwrap();
        for source in &contributor.sources.sources {
            writeln!(
                text,
                "  {}:{} ({})",
                source.path.display(),
                source.line,
                source
                    .generated_by
                    .as_deref()
                    .unwrap_or("authored declaration")
            )
            .unwrap();
        }
    }
    text.push_str("\nGenerator amplification (associated bytes, not build-tool DLL size)\n");
    for generator in &report.generators {
        writeln!(
            text,
            "{} {}: {} inputs, {} emitted files, {} declarations; candidate={} asserted={} B",
            generator.name,
            generator.version,
            generator.declared_inputs,
            generator.generated_files,
            generator.generated_declarations,
            generator.candidate_accounted_bytes,
            generator.asserted_accounted_bytes
        )
        .unwrap();
    }
    text.push_str("\nGeneric families (distinct parsed shapes, not instantiation counts)\n");
    for family in &report.generic_families {
        writeln!(
            text,
            "{} {:>12} {}: {} shapes, {} shared shapes, kinds={:?}",
            family.stream,
            family.bytes,
            family.family,
            family.distinct_shapes,
            family.canonical_shared_shapes,
            family.argument_kinds
        )
        .unwrap();
    }
    writeln!(
        text,
        "\nResource rows: visible={} B; complete assets={} B, containers={} B (overlap)",
        report.displayed_resource_bytes,
        report.full_resource_asset_bytes,
        report.full_resource_container_bytes
    )
    .unwrap();
    for resource in &report.resources {
        writeln!(
            text,
            "{:>16} {}!{}!{} [{}]",
            resource.bytes, resource.assembly, resource.container, resource.name, resource.storage
        )
        .unwrap();
    }
    writeln!(
        text,
        "\n{} content-hash duplicate groups",
        report.duplicate_assets.len()
    )
    .unwrap();
    for route in &report.package_routes {
        writeln!(
            text,
            "{} {}: {}{}",
            route.target,
            route.package,
            route
                .shortest_route
                .as_ref()
                .map_or_else(|| "route unknown".into(), |path| path.join(" -> ")),
            if route.cyclic_target {
                " [cyclic target]"
            } else {
                ""
            }
        )
        .unwrap();
    }
    for diagnostic in &report.diagnostics {
        writeln!(text, "\n{}: {}", diagnostic.code, diagnostic.message).unwrap();
    }
    for caveat in &report.caveats {
        writeln!(text, "\nCaution: {caveat}").unwrap();
    }
    text
}

fn verify_index(cli: &Cli, index: &std::path::Path) -> Result<String, AppError> {
    let imported = vitnet_attribution::open_index(index, cli.memory_limit.0).map_err(classify)?;
    vitnet_attribution::visit_identities(index, &imported, cli.memory_limit.0, |_| Ok(()))
        .map_err(classify)?;
    let diagnostics = vitnet_attribution::verify_artifacts(&imported).map_err(classify)?;
    if !diagnostics.is_empty() {
        return Err(AppError::Unsupported(Box::new(
            vitnet_core::Diagnostic::malformed(
                "attribution.verify.drift",
                serde_json::to_string(&diagnostics).map_err(AppError::Json)?,
            ),
        )));
    }
    json(
        cli,
        &serde_json::json!({
            "schema":"vitnet.attribution-verify.v1", "valid_cache":true,
            "identities":imported.identities, "import_diagnostic_count": imported.diagnostics.len(),
            "complete_import": imported.diagnostics.is_empty(),
        }),
    )
}

pub(super) fn execute(cli: &Cli, command: &AttributionCommand) -> Result<String, AppError> {
    let memory = cli.memory_limit.0;
    match command {
        AttributionCommand::Import { evidence, index } => {
            let imported = vitnet_attribution::import(evidence, index, memory, cli.strict)
                .map_err(classify)?;
            json(
                cli,
                &serde_json::json!({
                    "schema": "vitnet.attribution-import.v1", "index": index,
                    "label": imported.evidence.label, "identities": imported.identities,
                    "accounted_bytes": imported.mstat.as_ref().map(|summary| summary.accounted_size_bytes),
                    "source_declarations": imported.evidence.sources.len(),
                    "packages": imported.evidence.packages.len(),
                    "generators": imported.evidence.generators.len(),
                    "resource_assets": imported.evidence.resources.len(),
                    "diagnostic_count": imported.diagnostics.len(),
                    "diagnostics": imported.diagnostics.iter().take(20).collect::<Vec<_>>()
                }),
            )
        }
        AttributionCommand::Report {
            index,
            top,
            contains,
        } => {
            let report = vitnet_attribution::report(index, memory, *top, contains.as_deref())
                .map_err(classify)?;
            if cli.format == FormatArg::Table {
                Ok(report_table(&report))
            } else {
                json(cli, &report)
            }
        }
        AttributionCommand::Source { index, identity } => {
            let report =
                vitnet_attribution::locate_source(index, identity, memory).map_err(classify)?;
            json(cli, &report)
        }
        AttributionCommand::Explain {
            index,
            node_id,
            graph,
            incoming_limit,
            options,
        } => {
            let report = vitnet_attribution::explain(
                index,
                *node_id,
                graph,
                memory,
                &options.into(),
                *incoming_limit,
            )
            .map_err(classify)?;
            json(cli, &report)
        }
        AttributionCommand::Compare {
            before,
            after,
            top,
            before_node,
            after_node,
            graph,
            options,
        } => {
            let mut report =
                vitnet_attribution::compare(before, after, memory, *top).map_err(classify)?;
            if let (Some(before_node), Some(after_node)) = (before_node, after_node) {
                report.retention = Some(
                    vitnet_attribution::compare_retention(
                        before,
                        after,
                        *before_node,
                        *after_node,
                        graph,
                        memory,
                        &options.into(),
                    )
                    .map_err(classify)?,
                );
            }
            json(cli, &report)
        }
        AttributionCommand::Verify { index } => verify_index(cli, index),
    }
}

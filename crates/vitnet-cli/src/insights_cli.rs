use super::{
    AppError, Cli, FormatArg, GroupArg, MetadataArgs, MstatCommand, analyze_path, cache_error,
};
use clap::Args;
use serde::Serialize;
use serde_json::Value;
use std::fmt::Write as _;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use vitnet_core::Diagnostic;
use vitnet_mstat::{
    CohortRule, InsightKind, InsightProjection, InsightsOptions, MstatError, insights_path,
    project_insights_path,
};
mod brief;

#[derive(Clone, Debug, Args)]
pub struct InsightArgs {
    pub input: PathBuf,
    #[arg(long, value_parser = super::parse_positive_usize, default_value_t = 20)]
    pub top: usize,
    #[arg(long, value_parser = clap::builder::NonEmptyStringValueParser::new())]
    pub contains: Option<String>,
    /// JSON array of literal rules. Omitted: documented starter heuristics.
    #[arg(long)]
    pub rules: Option<PathBuf>,
}

#[derive(Clone, Debug, Args)]
pub struct BloatArgs {
    /// Show a compact, interpreted evidence report instead of all raw projections.
    #[arg(long)]
    pub brief: bool,
    #[arg(long)]
    pub metadata: PathBuf,
    #[arg(long)]
    pub mstat: PathBuf,
    #[arg(long)]
    pub rules: Option<PathBuf>,
    #[arg(long, value_parser = super::parse_positive_usize, default_value_t = 20)]
    pub top: usize,
    #[arg(long)]
    pub scan_index: Option<PathBuf>,
    #[arg(long)]
    pub codegen_index: Option<PathBuf>,
}

pub(super) fn mstat_error(error: MstatError) -> AppError {
    if error.diagnostic.code == "mstat.io" {
        AppError::IoDiagnostic(error.diagnostic)
    } else if error.diagnostic.code.starts_with("resource.") {
        AppError::Resource(error.diagnostic)
    } else {
        AppError::Mstat(error)
    }
}

fn rules(path: Option<&Path>, memory_limit: u64) -> Result<Vec<CohortRule>, AppError> {
    let Some(path) = path else {
        return Ok([
            ("serialization", &["Newtonsoft", "JsonSerializer"][..]),
            ("compiled-xaml", &["XamlIl", "XamlIL"][..]),
            ("cloud-sdks", &["Amazon.", "Azure.", "Google."][..]),
            ("resources", &["Resources", "resources", "Avalonia"][..]),
            ("property-accessors", &["get_", "set_"][..]),
            ("generic-shaped", &["<"][..]),
        ]
        .map(|(name, patterns)| CohortRule {
            name: name.into(),
            contains: patterns.iter().map(|pattern| (*pattern).into()).collect(),
            stream: None,
        })
        .into());
    };
    let limit = (memory_limit / 16).min(1 << 20);
    let mut bytes = Vec::new();
    File::open(path)
        .map_err(|source| AppError::Io {
            path: path.into(),
            source,
        })?
        .take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|source| AppError::Io {
            path: path.into(),
            source,
        })?;
    if bytes.len() as u64 > limit {
        return Err(AppError::Resource(Box::new(Diagnostic::malformed(
            "resource.rules",
            "cohort-rule file exceeds 1 MiB or its share of the memory budget",
        ))));
    }
    serde_json::from_slice(&bytes).map_err(|cause| {
        let mut diagnostic = Diagnostic::malformed("bloat.rules.json", cause.to_string());
        diagnostic.input_path = Some(path.into());
        AppError::Unsupported(Box::new(diagnostic))
    })
}

pub(super) fn execute_mstat(cli: &Cli, command: &MstatCommand) -> Result<String, AppError> {
    let (MstatCommand::Methods(args)
    | MstatCommand::Resources(args)
    | MstatCommand::Generics(args)
    | MstatCommand::Cohorts(args)
    | MstatCommand::Insights(args)) = command
    else {
        unreachable!("existing MSTAT commands are dispatched by the parent");
    };
    let options = InsightsOptions {
        top: args.top,
        contains: args.contains.clone(),
        rules: rules(args.rules.as_deref(), cli.memory_limit.0)?,
    };
    if matches!(command, MstatCommand::Insights(_)) {
        let report =
            insights_path(&args.input, cli.memory_limit.0, &options).map_err(mstat_error)?;
        return projection(
            cli,
            args,
            &options,
            &report.summary,
            "vitnet.mstat-insights.v1",
            &report,
        );
    }
    let kind = match command {
        MstatCommand::Methods(_) => InsightKind::Methods,
        MstatCommand::Resources(_) => InsightKind::Resources,
        MstatCommand::Generics(_) => InsightKind::Generics,
        MstatCommand::Cohorts(_) => InsightKind::Cohorts,
        _ => unreachable!("combined and existing MSTAT commands are dispatched separately"),
    };
    let report = project_insights_path(&args.input, cli.memory_limit.0, &options, kind)
        .map_err(mstat_error)?;
    match &report.data {
        InsightProjection::Methods(data) => projection(
            cli,
            args,
            &options,
            &report.summary,
            "vitnet.mstat-methods.v1",
            data,
        ),
        InsightProjection::Resources(data) => projection(
            cli,
            args,
            &options,
            &report.summary,
            "vitnet.mstat-resources.v1",
            data,
        ),
        InsightProjection::Generics(data) => projection(
            cli,
            args,
            &options,
            &report.summary,
            "vitnet.mstat-generics.v1",
            data,
        ),
        InsightProjection::Cohorts(data) => projection(
            cli,
            args,
            &options,
            &report.summary,
            "vitnet.mstat-cohorts.v1",
            data,
        ),
    }
}

#[derive(Serialize)]
struct InsightEnvelope<'a, T> {
    schema: &'static str,
    input: &'a Path,
    summary: &'a vitnet_mstat::MstatSummary,
    top: usize,
    contains: &'a Option<String>,
    rules: &'a [CohortRule],
    data: &'a T,
}

fn projection<T: Serialize>(
    cli: &Cli,
    args: &InsightArgs,
    options: &InsightsOptions,
    summary: &vitnet_mstat::MstatSummary,
    schema: &'static str,
    data: &T,
) -> Result<String, AppError> {
    render(
        cli.format,
        &InsightEnvelope {
            schema,
            input: &args.input,
            summary,
            top: options.top,
            contains: &options.contains,
            rules: &options.rules,
            data,
        },
    )
}

#[derive(Serialize)]
struct Reconciliation {
    metadata_csv_lower_bound_bytes: u64,
    mstat_metadata_blob_bytes: Option<u64>,
    metadata_blob_records: u64,
    blob_minus_lower_bound_bytes: Option<i128>,
    caveat: &'static str,
}

#[derive(Serialize)]
struct BloatReport {
    schema: &'static str,
    metadata: vitnet_report::MetadataEnvelope,
    mstat: vitnet_mstat::MstatInsights,
    rules: Vec<CohortRule>,
    graph_generations: Vec<vitnet_dgml::DgmlCacheInfo>,
    reconciliation: Reconciliation,
    caveats: [&'static str; 4],
}

pub(super) fn execute_bloat(cli: &Cli, args: &BloatArgs) -> Result<String, AppError> {
    let metadata = analyze_path(
        &args.metadata,
        cli.strict,
        &MetadataArgs {
            input: args.metadata.clone(),
            top: args.top,
            assembly: None,
            type_name: None,
            contains: None,
            preview_bytes: 256,
            group: vec![
                GroupArg::Assembly,
                GroupArg::Namespace,
                GroupArg::Type,
                GroupArg::Kind,
            ],
            strings: true,
            compare: None,
        },
        cli.memory_limit.0,
        args.top,
    )?;
    let options = InsightsOptions {
        top: args.top,
        contains: None,
        rules: rules(args.rules.as_deref(), cli.memory_limit.0)?,
    };
    let mstat = insights_path(&args.mstat, cli.memory_limit.0, &options).map_err(mstat_error)?;
    let mut graphs = Vec::new();
    for path in [&args.scan_index, &args.codegen_index]
        .into_iter()
        .flatten()
    {
        graphs.push(vitnet_dgml::cache_info(path).map_err(cache_error)?);
    }
    let reconciliation = Reconciliation {
        metadata_csv_lower_bound_bytes: metadata.summary.metadata_lower_bound_bytes,
        mstat_metadata_blob_bytes: (mstat.metadata_blob_records > 0)
            .then_some(mstat.metadata_blob_bytes),
        metadata_blob_records: mstat.metadata_blob_records,
        blob_minus_lower_bound_bytes: (mstat.metadata_blob_records > 0).then(|| {
            i128::from(mstat.metadata_blob_bytes)
                - i128::from(metadata.summary.metadata_lower_bound_bytes)
        }),
        caveat: "CSV lacks the final record end. Difference is observed, not a universal correction; inputs are not proven to be from the same build.",
    };
    let report = BloatReport {
        schema: "vitnet.bloat.v1",
        metadata,
        mstat,
        rules: options.rules,
        graph_generations: graphs,
        reconciliation,
        caveats: [
            "MSTAT accounted total is Methods + Types + Blobs, not executable file size. Specialized streams overlap Blobs.",
            "Cohorts and generic-shaped families classify literal opaque names; overlaps are not exclusive ownership or removable-byte estimates.",
            "Metadata aggregate dimensions describe the same bytes and must not be added together.",
            "Optional graph generations provide provenance and counts, not a guaranteed MSTAT symbol join. Investigate candidate IDs with search/incoming/batch.",
        ],
    };
    if args.brief {
        render(cli.format, &brief::build(&report, args)?)
    } else {
        render(cli.format, &report)
    }
}

fn render<T: Serialize>(format: FormatArg, report: &T) -> Result<String, AppError> {
    match format {
        FormatArg::Json => serde_json::to_string_pretty(report).map_err(AppError::Json),
        FormatArg::Ndjson => serde_json::to_string(report).map_err(AppError::Json),
        FormatArg::Table => {
            let mut output = String::new();
            table_value(
                &serde_json::to_value(report).map_err(AppError::Json)?,
                0,
                &mut output,
            );
            Ok(output)
        }
    }
}

#[cfg(test)]
mod tests;

fn table_value(value: &Value, depth: usize, output: &mut String) {
    let indent = "  ".repeat(depth);
    match value {
        Value::Object(fields) => {
            for (name, value) in fields {
                if value.is_object() || value.is_array() {
                    writeln!(output, "{indent}{name}:").unwrap();
                    table_value(value, depth + 1, output);
                } else {
                    writeln!(
                        output,
                        "{indent}{name}: {}",
                        value
                            .as_str()
                            .map_or_else(|| value.to_string(), str::to_owned)
                    )
                    .unwrap();
                }
            }
        }
        Value::Array(items) => {
            for item in items {
                writeln!(output, "{indent}-").unwrap();
                table_value(item, depth + 1, output);
            }
        }
        _ => {
            writeln!(
                output,
                "{indent}{}",
                value
                    .as_str()
                    .map_or_else(|| value.to_string(), str::to_owned)
            )
            .unwrap();
        }
    }
}

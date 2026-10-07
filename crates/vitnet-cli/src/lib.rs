use clap::{Args, Parser, Subcommand, ValueEnum};
use serde::Serialize;
use std::fmt::Write as _;
use std::fs::File;
use std::io::Read;
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};
use vitnet_core::{ByteSize, Diagnostic, ExitCode, ResourceBudget};
use vitnet_dgml::{DgmlError, DgmlStats, StatsOptions, analyze_stats};
use vitnet_metadata::{
    Aggregate, AnalysisOptions, MetadataError, StreamingDecoder,
    analyze_stream_with_aggregate_limit,
};
use vitnet_mstat::{MstatError, MstatSummary, summarize_path};
use vitnet_report::{InputDescriptor, MetadataComparisonEnvelope, MetadataEnvelope};

const DEFAULT_MEMORY_LIMIT: u64 = 2 * 1024 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub enum FormatArg {
    Table,
    Json,
    Ndjson,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub enum ModeArg {
    Auto,
    Always,
    Never,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub enum GroupArg {
    Assembly,
    Namespace,
    Type,
    Kind,
}

#[derive(Clone, Debug, Parser)]
#[command(name = "vitnet", version, about = "NativeAOT size diagnostics")]
pub struct Cli {
    #[arg(long, value_enum, default_value_t = FormatArg::Table, global = true)]
    pub format: FormatArg,
    #[arg(long, global = true)]
    pub output: Option<PathBuf>,
    #[arg(long, default_value_t = default_memory_limit(), global = true)]
    pub memory_limit: ByteSize,
    #[arg(long, global = true)]
    pub temp_dir: Option<PathBuf>,
    #[arg(long, global = true)]
    pub threads: Option<NonZeroUsize>,
    #[arg(long, value_enum, default_value_t = ModeArg::Auto, global = true)]
    pub progress: ModeArg,
    #[arg(long, value_enum, default_value_t = ModeArg::Auto, global = true)]
    pub color: ModeArg,
    #[arg(long, conflicts_with = "verbose", global = true)]
    pub quiet: bool,
    #[arg(long, conflicts_with = "quiet", global = true)]
    pub verbose: bool,
    #[arg(long, global = true)]
    pub strict: bool,
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Clone, Debug, Subcommand)]
pub enum Command {
    Metadata(MetadataArgs),
    Mstat(PlaceholderCommand<MstatCommand>),
    /// `NativeAOT` dependency-graph analysis.
    Dgml(PlaceholderCommand<DgmlCommand>),
}

#[derive(Clone, Debug, Args)]
pub struct PlaceholderCommand<T: Subcommand> {
    #[command(subcommand)]
    pub command: T,
}

#[derive(Clone, Debug, Subcommand)]
pub enum MstatCommand {
    Summary { input: PathBuf },
    Diff { before: PathBuf, after: PathBuf },
}

#[derive(Clone, Debug, Subcommand)]
pub enum DgmlCommand {
    Index {
        input: PathBuf,
    },
    Stats {
        input: PathBuf,
        #[arg(long, value_parser = parse_positive_usize, default_value_t = 50)]
        top: usize,
    },
    Search {
        input: PathBuf,
        query: String,
    },
    Why {
        input: PathBuf,
        query: String,
    },
}

#[derive(Clone, Debug, Args)]
pub struct MetadataArgs {
    /// Metadata CSV path, or `-` for standard input.
    pub input: PathBuf,
    #[arg(long, value_parser = parse_positive_usize, default_value_t = 50)]
    pub top: usize,
    #[arg(long)]
    pub assembly: Option<String>,
    #[arg(long, value_enum, value_delimiter = ',', default_values_t = [GroupArg::Assembly, GroupArg::Namespace, GroupArg::Type, GroupArg::Kind])]
    pub group: Vec<GroupArg>,
    #[arg(long)]
    pub strings: bool,
    #[arg(long)]
    pub compare: Option<PathBuf>,
}

fn parse_positive_usize(value: &str) -> Result<usize, String> {
    let parsed = value
        .parse::<usize>()
        .map_err(|_| format!("`{value}` is not a positive integer"))?;
    if parsed == 0 {
        Err("value must be at least 1".into())
    } else {
        Ok(parsed)
    }
}

fn default_memory_limit() -> ByteSize {
    let mut system = sysinfo::System::new();
    system.refresh_memory();
    ByteSize((system.total_memory() / 4).min(DEFAULT_MEMORY_LIMIT))
}

#[derive(Debug)]
pub enum AppError {
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    IoDiagnostic(Box<Diagnostic>),
    Metadata(MetadataError),
    Dgml(DgmlError),
    Mstat(MstatError),
    Resource(Box<Diagnostic>),
    Unsupported(Box<Diagnostic>),
    Json(serde_json::Error),
}

impl AppError {
    #[must_use]
    pub const fn exit_code(&self) -> ExitCode {
        match self {
            Self::Io { .. } | Self::IoDiagnostic(_) => ExitCode::IoOrCache,
            Self::Metadata(_) | Self::Dgml(_) | Self::Mstat(_) | Self::Unsupported(_) => {
                ExitCode::MalformedInput
            }
            Self::Resource(_) => ExitCode::ResourceLimit,
            Self::Json(_) => ExitCode::InternalInvariant,
        }
    }
}

impl std::fmt::Display for AppError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io { path, source } => write!(formatter, "{}: {source}", path.display()),
            Self::Metadata(error) => error.fmt(formatter),
            Self::Dgml(error) => error.fmt(formatter),
            Self::Mstat(error) => error.fmt(formatter),
            Self::IoDiagnostic(diagnostic)
            | Self::Resource(diagnostic)
            | Self::Unsupported(diagnostic) => diagnostic.fmt(formatter),
            Self::Json(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for AppError {}

/// Analyzes a metadata stream without requiring a filesystem input.
///
/// # Errors
///
/// Returns a typed malformed-input or resource-limit error.
pub fn analyze_reader<R: Read>(
    reader: R,
    strict: bool,
    options: &AnalysisOptions,
    input: InputDescriptor,
) -> Result<MetadataEnvelope, AppError> {
    analyze_reader_with_limits(
        reader,
        strict,
        options,
        input,
        DEFAULT_MEMORY_LIMIT,
        options.top,
    )
}

fn analyze_reader_with_limits<R: Read>(
    reader: R,
    strict: bool,
    options: &AnalysisOptions,
    input: InputDescriptor,
    memory_limit: u64,
    aggregate_limit: usize,
) -> Result<MetadataEnvelope, AppError> {
    let record_limit = usize::try_from((memory_limit / 2).min(64 * 1024 * 1024))
        .unwrap_or(64 * 1024 * 1024)
        .max(32 * 1024);
    let analysis = analyze_stream_with_aggregate_limit(
        StreamingDecoder::new(reader, 64 * 1024, strict).with_record_limit(record_limit),
        options.clone(),
        strict,
        memory_limit,
        aggregate_limit,
    )
    .map_err(classify_metadata_error)?;
    Ok(MetadataEnvelope::new(
        env!("CARGO_PKG_VERSION"),
        input,
        analysis,
        Vec::new(),
    ))
}

fn classify_metadata_error(error: MetadataError) -> AppError {
    if error.diagnostic.code.starts_with("resource.") {
        AppError::Resource(error.diagnostic)
    } else if error.diagnostic.code == "metadata.io" {
        AppError::IoDiagnostic(error.diagnostic)
    } else {
        AppError::Metadata(error)
    }
}

/// Executes a parsed Phase 0/1 command.
///
/// # Errors
///
/// Returns an I/O, malformed-input, resource, unsupported-command, or
/// serialization error with a stable exit-code mapping.
pub fn execute(cli: &Cli) -> Result<String, AppError> {
    match &cli.command {
        Command::Metadata(arguments) => execute_metadata(cli, arguments),
        Command::Mstat(arguments) => execute_mstat(cli, &arguments.command),
        Command::Dgml(arguments) => execute_dgml(cli, &arguments.command),
    }
}

fn execute_mstat(cli: &Cli, command: &MstatCommand) -> Result<String, AppError> {
    validate_resources(cli)?;
    match command {
        MstatCommand::Summary { input } => {
            let summary = summarize_path(input, cli.memory_limit.0).map_err(|error| {
                if error.diagnostic.code == "mstat.io" {
                    AppError::IoDiagnostic(error.diagnostic)
                } else if error.diagnostic.code.starts_with("resource.") {
                    AppError::Resource(error.diagnostic)
                } else {
                    AppError::Mstat(error)
                }
            })?;
            render_mstat_summary(cli.format, &summary)
        }
        MstatCommand::Diff { .. } => Err(unsupported("mstat diff", "Phase 3")),
    }
}

fn render_mstat_summary(format: FormatArg, summary: &MstatSummary) -> Result<String, AppError> {
    match format {
        FormatArg::Json => serde_json::to_string_pretty(summary).map_err(AppError::Json),
        FormatArg::Ndjson => {
            let mut lines = vec![
                serde_json::to_string(&serde_json::json!({
                    "schema": summary.schema,
                    "section": "summary",
                    "value": {
                        "format_version": summary.format_version,
                        "assembly": summary.assembly,
                        "input_bytes": summary.input_bytes,
                        "accounted_size_bytes": summary.accounted_size_bytes,
                        "mangled_names_bytes": summary.mangled_names_bytes,
                        "methods": summary.methods,
                        "frozen_objects": summary.frozen_objects,
                        "deduplicated_methods": summary.deduplicated_methods,
                        "peak_tracked_memory_bytes": summary.peak_tracked_memory_bytes,
                    },
                }))
                .map_err(AppError::Json)?,
            ];
            for category in &summary.categories {
                lines.push(ndjson_line(&summary.schema, "categories", category)?);
            }
            Ok(lines.join("\n"))
        }
        FormatArg::Table => {
            let mut output = format!(
                "MSTAT {}.{}: {}\nAccounted size: {} B\nInput: {} B\nMangled names: {} B\nTracked memory peak: {} B\n",
                summary.format_version.major,
                summary.format_version.minor,
                summary.assembly,
                summary.accounted_size_bytes,
                summary.input_bytes,
                summary.mangled_names_bytes,
                summary.peak_tracked_memory_bytes,
            );
            output
                .push_str("\nStreams\nRecords      Items        Size (B)     Encoded (B)  Name\n");
            for category in &summary.categories {
                writeln!(
                    &mut output,
                    "{:<12} {:<12} {:<12} {:<12} {}",
                    category.records,
                    category.items,
                    category.aggregate_size_bytes,
                    category.encoded_bytes,
                    category.name,
                )
                .expect("writing to String cannot fail");
            }
            writeln!(
                &mut output,
                "\nMethods: bodies {} B, GC info {} B, EH info {} B",
                summary.methods.body_bytes,
                summary.methods.gc_info_bytes,
                summary.methods.exception_info_bytes,
            )
            .expect("writing to String cannot fail");
            writeln!(
                &mut output,
                "Frozen objects: owned {} / {} B, unowned {} / {} B",
                summary.frozen_objects.owned_records,
                summary.frozen_objects.owned_bytes,
                summary.frozen_objects.unowned_records,
                summary.frozen_objects.unowned_bytes,
            )
            .expect("writing to String cannot fail");
            writeln!(
                    &mut output,
                    "Deduplicated methods: {} groups, {} folded methods; savings not estimated in summary mode",
                    summary.deduplicated_methods.groups,
                    summary.deduplicated_methods.folded_methods,
                )
                .expect("writing to String cannot fail");
            Ok(output)
        }
    }
}

fn execute_dgml(cli: &Cli, command: &DgmlCommand) -> Result<String, AppError> {
    validate_resources(cli)?;
    match command {
        DgmlCommand::Stats { input, top } => {
            let input_bytes = input
                .metadata()
                .map_err(|source| AppError::Io {
                    path: input.clone(),
                    source,
                })?
                .len();
            let file = File::open(input).map_err(|source| AppError::Io {
                path: input.clone(),
                source,
            })?;
            let stats = analyze_stats(
                file,
                StatsOptions {
                    top: *top,
                    memory_limit: cli.memory_limit.0,
                    input_bytes,
                },
            )
            .map_err(|mut error| {
                error.diagnostic.input_path = Some(input.clone());
                if error.diagnostic.code.starts_with("resource.") {
                    AppError::Resource(error.diagnostic)
                } else {
                    AppError::Dgml(error)
                }
            })?;
            render_dgml_stats(cli.format, &stats)
        }
        DgmlCommand::Index { .. } | DgmlCommand::Search { .. } | DgmlCommand::Why { .. } => Err(
            unsupported("dgml", "the remaining Phase 4 and Phase 5 index/query work"),
        ),
    }
}

fn render_dgml_stats(format: FormatArg, stats: &DgmlStats) -> Result<String, AppError> {
    match format {
        FormatArg::Json => serde_json::to_string_pretty(stats).map_err(AppError::Json),
        FormatArg::Ndjson => {
            let mut lines = vec![
                serde_json::to_string(&serde_json::json!({
                    "schema": stats.schema,
                    "section": "summary",
                    "value": {
                        "input_bytes": stats.input_bytes,
                        "node_count": stats.node_count,
                        "edge_count": stats.edge_count,
                        "max_node_id": stats.max_node_id,
                        "duplicate_node_ids": stats.duplicate_node_ids,
                        "unresolved_endpoints": stats.unresolved_endpoints,
                        "peak_tracked_memory_bytes": stats.peak_tracked_memory_bytes,
                    },
                }))
                .map_err(AppError::Json)?,
            ];
            for reason in &stats.reasons {
                lines.push(ndjson_line(&stats.schema, "reasons", reason)?);
            }
            for bucket in &stats.in_degree_distribution {
                lines.push(ndjson_line(
                    &stats.schema,
                    "in_degree_distribution",
                    bucket,
                )?);
            }
            for entry in &stats.largest_fan_in {
                lines.push(ndjson_line(&stats.schema, "largest_fan_in", entry)?);
            }
            Ok(lines.join("\n"))
        }
        FormatArg::Table => {
            let mut output = format!(
                "DGML: {} nodes, {} edges\nInput: {} B\nDuplicate node IDs: {}\nUnresolved endpoints: {}\nTracked memory peak: {} B\n",
                stats.node_count,
                stats.edge_count,
                stats.input_bytes,
                stats.duplicate_node_ids,
                stats.unresolved_endpoints,
                stats.peak_tracked_memory_bytes,
            );
            output.push_str("\nLargest fan-in\nEdges        Node ID\n");
            for entry in &stats.largest_fan_in {
                writeln!(
                    &mut output,
                    "{:<12} {}",
                    entry.incoming_edges, entry.node_id
                )
                .expect("writing to String cannot fail");
            }
            output.push_str("\nIn-degree distribution\nEdges        Nodes\n");
            for bucket in &stats.in_degree_distribution {
                writeln!(
                    &mut output,
                    "{:<12} {}",
                    bucket.incoming_edges, bucket.nodes
                )
                .expect("writing to String cannot fail");
            }
            output.push_str("\nReasons\nEdges        Reason\n");
            for reason in &stats.reasons {
                writeln!(&mut output, "{:<12} {}", reason.count, reason.name)
                    .expect("writing to String cannot fail");
            }
            Ok(output)
        }
    }
}

fn unsupported(command: &str, phase: &str) -> AppError {
    let mut diagnostic = Diagnostic::malformed(
        format!("{command}.not_implemented"),
        format!("`vitnet {command}` is a stable placeholder and is not implemented in Phase 1"),
    );
    diagnostic.guidance = Some(format!("implement this command during {phase}"));
    AppError::Unsupported(Box::new(diagnostic))
}

fn execute_metadata(cli: &Cli, arguments: &MetadataArgs) -> Result<String, AppError> {
    validate_resources(cli)?;
    let mut before = analyze_path(
        &arguments.input,
        cli.strict,
        arguments,
        cli.memory_limit.0,
        if arguments.compare.is_some() {
            usize::MAX
        } else {
            arguments.top
        },
    )?;
    if let Some(after_path) = &arguments.compare {
        if arguments.input == Path::new("-") || after_path == Path::new("-") {
            return Err(AppError::Unsupported(Box::new(Diagnostic::malformed(
                "metadata.compare.stdin",
                "comparison mode requires two seek-independent file paths",
            ))));
        }
        let after = analyze_path(
            after_path,
            cli.strict,
            arguments,
            cli.memory_limit.0,
            usize::MAX,
        )?;
        let mut comparison =
            MetadataComparisonEnvelope::new(env!("CARGO_PKG_VERSION"), &before, &after);
        comparison.truncate(arguments.top);
        return render_comparison(cli.format, &comparison, arguments);
    }
    project_analysis(&mut before, arguments);
    render_analysis(cli.format, &before, arguments)
}

fn project_analysis(report: &mut MetadataEnvelope, arguments: &MetadataArgs) {
    if !arguments.group.contains(&GroupArg::Kind) {
        report.sections.by_kind.clear();
    }
    if !arguments.group.contains(&GroupArg::Assembly) {
        report.sections.by_assembly.clear();
    }
    if !arguments.group.contains(&GroupArg::Namespace) {
        report.sections.by_namespace.clear();
    }
    if !arguments.group.contains(&GroupArg::Type) {
        report.sections.by_type.clear();
    }
    if !arguments.strings {
        report.sections.largest_strings.clear();
    }
}

fn validate_resources(cli: &Cli) -> Result<(), AppError> {
    if cli.memory_limit.0 < 64 * 1024 {
        let mut diagnostic = Diagnostic::malformed(
            "resource.memory_limit",
            "memory limit is too small for the decoder and report state",
        );
        diagnostic.expected = Some("at least 64 KiB".into());
        diagnostic.actual = Some(format!("{} bytes", cli.memory_limit.0));
        return Err(AppError::Resource(Box::new(diagnostic)));
    }
    if let Some(directory) = &cli.temp_dir
        && !directory.is_dir()
    {
        return Err(AppError::Io {
            path: directory.clone(),
            source: std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "temporary directory does not exist",
            ),
        });
    }
    let workers = cli.threads.map_or_else(
        || {
            std::thread::available_parallelism()
                .map_or(1, NonZeroUsize::get)
                .min(8)
        },
        NonZeroUsize::get,
    );
    let budget = ResourceBudget::new(cli.memory_limit.0, u64::MAX, workers, None);
    budget.check(64 * 1024, 0).map_err(|error| {
        AppError::Resource(Box::new(Diagnostic::malformed(
            "resource.configuration",
            error.to_string(),
        )))
    })?;
    Ok(())
}

fn analyze_path(
    path: &Path,
    strict: bool,
    arguments: &MetadataArgs,
    memory_limit: u64,
    aggregate_limit: usize,
) -> Result<MetadataEnvelope, AppError> {
    let options = AnalysisOptions {
        assembly_filter: arguments
            .assembly
            .as_ref()
            .map(|assembly| assembly.as_bytes().to_vec()),
        top: arguments.top,
        preview_bytes: 256,
    };
    if path == Path::new("-") {
        return analyze_reader_with_limits(
            std::io::stdin().lock(),
            strict,
            &options,
            InputDescriptor {
                path: None,
                bytes_read: 0,
            },
            memory_limit,
            aggregate_limit,
        );
    }
    let bytes_read = path.metadata().map_or(0, |metadata| metadata.len());
    let file = File::open(path).map_err(|source| AppError::Io {
        path: path.to_owned(),
        source,
    })?;
    analyze_reader_with_limits(
        file,
        strict,
        &options,
        InputDescriptor {
            path: Some(path.to_owned()),
            bytes_read,
        },
        memory_limit,
        aggregate_limit,
    )
    .map_err(|mut error| {
        match &mut error {
            AppError::Metadata(metadata) => {
                metadata.diagnostic.input_path = Some(path.to_owned());
            }
            AppError::Mstat(mstat) => {
                mstat.diagnostic.input_path = Some(path.to_owned());
            }
            AppError::Dgml(dgml) => {
                dgml.diagnostic.input_path = Some(path.to_owned());
            }
            AppError::IoDiagnostic(diagnostic)
            | AppError::Resource(diagnostic)
            | AppError::Unsupported(diagnostic) => {
                diagnostic.input_path = Some(path.to_owned());
            }
            AppError::Io { .. } | AppError::Json(_) => {}
        }
        error
    })
}

fn render_analysis(
    format: FormatArg,
    report: &MetadataEnvelope,
    arguments: &MetadataArgs,
) -> Result<String, AppError> {
    match format {
        FormatArg::Json => report.to_json().map_err(AppError::Json),
        FormatArg::Ndjson => render_ndjson(report, arguments),
        FormatArg::Table => Ok(render_table(report, arguments)),
    }
}

fn render_comparison(
    format: FormatArg,
    report: &MetadataComparisonEnvelope,
    arguments: &MetadataArgs,
) -> Result<String, AppError> {
    match format {
        FormatArg::Json => serde_json::to_string_pretty(report).map_err(AppError::Json),
        FormatArg::Ndjson => {
            let mut lines = Vec::new();
            for (section, comparison) in comparison_sections(report, arguments) {
                for entry in &comparison.entries {
                    lines.push(
                        serde_json::to_string(&serde_json::json!({
                            "schema": report.schema,
                            "section": section,
                            "value": entry,
                        }))
                        .map_err(AppError::Json)?,
                    );
                }
            }
            Ok(lines.join("\n"))
        }
        FormatArg::Table => {
            let mut output = format!(
                "Metadata lower-bound delta: {:+} B\n",
                report.summary.delta_bytes
            );
            for (section, comparison) in comparison_sections(report, arguments) {
                writeln!(&mut output, "\n{}", heading(section))
                    .expect("writing to String cannot fail");
                for entry in comparison.entries.iter().take(arguments.top) {
                    writeln!(
                        &mut output,
                        "{:+} B  {} B -> {} B  {}",
                        entry.delta_bytes, entry.before_bytes, entry.after_bytes, entry.name
                    )
                    .expect("writing to String cannot fail");
                }
            }
            Ok(output)
        }
    }
}

fn render_ndjson(report: &MetadataEnvelope, arguments: &MetadataArgs) -> Result<String, AppError> {
    let mut lines = vec![
        serde_json::to_string(&serde_json::json!({
            "schema": report.schema,
            "section": "summary",
            "value": report.summary,
        }))
        .map_err(AppError::Json)?,
    ];
    for (section, entries) in analysis_sections(report, arguments) {
        for entry in entries {
            lines.push(ndjson_line(&report.schema, section, entry)?);
        }
    }
    if arguments.strings {
        for entry in &report.sections.largest_strings {
            lines.push(ndjson_line(&report.schema, "strings", entry)?);
        }
    }
    Ok(lines.join("\n"))
}

fn ndjson_line<T: Serialize>(schema: &str, section: &str, value: &T) -> Result<String, AppError> {
    serde_json::to_string(&serde_json::json!({
        "schema": schema,
        "section": section,
        "value": value,
    }))
    .map_err(AppError::Json)
}

fn render_table(report: &MetadataEnvelope, arguments: &MetadataArgs) -> String {
    let mut output = format!(
        "Metadata lower bound: {} B across {} records\n",
        report.summary.metadata_lower_bound_bytes, report.summary.observed_record_count
    );
    if report.summary.selected_lower_bound_bytes != report.summary.metadata_lower_bound_bytes {
        writeln!(
            &mut output,
            "Selected lower bound: {} B across {} records",
            report.summary.selected_lower_bound_bytes, report.summary.record_count
        )
        .expect("writing to String cannot fail");
    }
    output.push_str("Final record size: unknown\n");
    match report.sections.limit_status {
        vitnet_metadata::LimitStatus::OverByAtLeast { bytes, limit, .. } => {
            writeln!(
                &mut output,
                "NativeAOT limit:      {limit} B\nStatus:               OVER by at least {bytes} B"
            )
            .expect("writing to String cannot fail");
        }
        vitnet_metadata::LimitStatus::AtOrBelowHeadroomUnknown { limit, .. } => {
            writeln!(
                &mut output,
                "NativeAOT limit:      {limit} B\nStatus:               at or below limit; remaining headroom unknown"
            )
            .expect("writing to String cannot fail");
        }
    }
    for (section, entries) in analysis_sections(report, arguments) {
        render_aggregate_section(&mut output, heading(section), entries, report);
    }
    if arguments.strings {
        output.push_str("\nLargest strings\nBytes        Offset       Value\n");
        for entry in &report.sections.largest_strings {
            let ellipsis = if entry.preview.truncated { "..." } else { "" };
            writeln!(
                &mut output,
                "{:<12} {:<12} {}{}",
                entry.bytes, entry.logical_offset, entry.preview.text, ellipsis
            )
            .expect("writing to String cannot fail");
        }
    }
    render_aggregate_section(
        &mut output,
        "Unowned metadata",
        &report.sections.unowned,
        report,
    );
    output
}

fn render_aggregate_section(
    output: &mut String,
    title: &str,
    entries: &[Aggregate],
    report: &MetadataEnvelope,
) {
    writeln!(output, "\n{title}\nBytes        Percent  Records  Name")
        .expect("writing to String cannot fail");
    let denominator = report.summary.selected_lower_bound_bytes;
    for entry in entries {
        let percentage_tenths = if denominator == 0 {
            0
        } else {
            u128::from(entry.bytes) * 1_000 / u128::from(denominator)
        };
        writeln!(
            output,
            "{:<12} {:>5}.{}%  {:<7}  {}",
            entry.bytes,
            percentage_tenths / 10,
            percentage_tenths % 10,
            entry.records,
            entry.name
        )
        .expect("writing to String cannot fail");
    }
}

fn analysis_sections<'a>(
    report: &'a MetadataEnvelope,
    arguments: &MetadataArgs,
) -> Vec<(&'static str, &'a [Aggregate])> {
    let mut sections = Vec::new();
    for group in &arguments.group {
        let value = match group {
            GroupArg::Assembly => ("by_assembly", report.sections.by_assembly.as_slice()),
            GroupArg::Namespace => ("by_namespace", report.sections.by_namespace.as_slice()),
            GroupArg::Type => ("by_type", report.sections.by_type.as_slice()),
            GroupArg::Kind => ("by_kind", report.sections.by_kind.as_slice()),
        };
        if !sections.iter().any(|(name, _)| *name == value.0) {
            sections.push(value);
        }
    }
    sections
}

fn comparison_sections<'a>(
    report: &'a MetadataComparisonEnvelope,
    arguments: &MetadataArgs,
) -> Vec<(&'static str, &'a vitnet_metadata::Comparison)> {
    let mut sections = Vec::new();
    for group in &arguments.group {
        let value = match group {
            GroupArg::Assembly => ("by_assembly", &report.sections.by_assembly),
            GroupArg::Namespace => ("by_namespace", &report.sections.by_namespace),
            GroupArg::Type => ("by_type", &report.sections.by_type),
            GroupArg::Kind => ("by_kind", &report.sections.by_kind),
        };
        if !sections.iter().any(|(name, _)| *name == value.0) {
            sections.push(value);
        }
    }
    sections.push(("unowned", &report.sections.unowned));
    sections
}

fn heading(section: &str) -> &str {
    match section {
        "by_assembly" => "By assembly",
        "by_namespace" => "By namespace",
        "by_type" => "By type",
        "by_kind" => "By kind",
        "unowned" => "Unowned metadata",
        other => other,
    }
}

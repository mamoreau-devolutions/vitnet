use clap::{Args, Parser, Subcommand, ValueEnum};
use serde::Serialize;
use std::fmt::Write as _;
use std::fs::File;
use std::io::Read;
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};
use vitnet_core::{ByteSize, Diagnostic, ExitCode, ResourceBudget};
use vitnet_dgml::{
    DgmlCacheInfo, DgmlCachePruneReport, DgmlCacheVerification, DgmlError, DgmlIndexReport,
    DgmlStats, GraphSession, IncomingOptions, IndexControl, IndexOptions, SearchMode,
    SearchOptions, SearchRank, StatsOptions, WhyOptions, analyze_stats, build_index, cache_info,
    prune_cache, verify_cache,
};
use vitnet_metadata::{
    Aggregate, AnalysisOptions, MetadataError, StreamingDecoder,
    analyze_stream_with_aggregate_limit,
};
use vitnet_mstat::{MstatDiff, MstatError, MstatSummary, diff_paths, summarize_path, top_path};
use vitnet_report::{InputDescriptor, MetadataComparisonEnvelope, MetadataEnvelope};

mod attribution_cli;
pub mod daemon;
mod display;
pub mod explorer;
mod insights_cli;
pub use attribution_cli::AttributionCommand;
pub use insights_cli::{BloatArgs, InsightArgs};

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
    /// Use an already-running local Windows named-pipe graph daemon.
    #[arg(long, global = true)]
    pub daemon: Option<String>,
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Clone, Debug, Subcommand)]
pub enum Command {
    /// Inspect complete captured evidence in the terminal or bounded local browser.
    Explore(PlaceholderCommand<explorer::ExploreCommand>),
    /// Import and query generic build, source, package and generator evidence.
    Attribution(PlaceholderCommand<AttributionCommand>),
    /// Reconcile metadata and MSTAT evidence without adding overlapping breakdowns.
    Bloat(BloatArgs),
    Metadata(MetadataArgs),
    Mstat(PlaceholderCommand<MstatCommand>),
    /// `NativeAOT` dependency-graph analysis.
    Dgml(PlaceholderCommand<DgmlCommand>),
    /// Inspect and maintain immutable vitnet cache generations.
    Cache(PlaceholderCommand<CacheCommand>),
    /// Manage a foreground Windows named-pipe query daemon.
    Daemon(PlaceholderCommand<DaemonCommand>),
}

#[derive(Clone, Debug, Subcommand)]
pub enum DaemonCommand {
    Serve {
        #[arg(long)]
        pipe: String,
    },
    Status {
        #[arg(long)]
        pipe: String,
    },
    Stop {
        #[arg(long)]
        pipe: String,
    },
}

#[derive(Clone, Debug, Args)]
pub struct PlaceholderCommand<T: Subcommand> {
    #[command(subcommand)]
    pub command: T,
}

#[derive(Clone, Debug, Subcommand)]
pub enum MstatCommand {
    /// Rank method identities with separate body, GC and exception-info costs.
    Methods(InsightArgs),
    /// Reconcile resource groups by assembly, culture and resource name.
    Resources(InsightArgs),
    /// Apply explicit overlapping literal-symbol cohort rules.
    Cohorts(InsightArgs),
    /// Rank literal prefixes of generic-shaped producer names (heuristic).
    Generics(InsightArgs),
    /// Produce all four insight projections from the same input.
    Insights(InsightArgs),
    /// Rank the largest producer identities, preserving exact size accounting.
    Top {
        input: PathBuf,
        #[arg(long, value_parser = parse_positive_usize, default_value_t = 50)]
        top: usize,
        #[arg(long)]
        contains: Option<String>,
        #[arg(long, value_parser = ["Methods", "Types", "Blobs", "RvaFields", "FrozenObjects", "ManifestResources", "DeduplicatedMethods"])]
        stream: Option<String>,
    },
    Summary {
        input: PathBuf,
    },
    Diff {
        before: PathBuf,
        after: PathBuf,
        #[arg(long, value_parser = parse_positive_usize, default_value_t = 50)]
        top: usize,
    },
}

#[derive(Clone, Debug, Subcommand)]
pub enum DgmlCommand {
    Index {
        input: PathBuf,
        #[arg(long)]
        cache_dir: Option<PathBuf>,
        #[arg(long)]
        entry: Option<String>,
    },
    Stats {
        input: PathBuf,
        #[arg(long, value_parser = parse_positive_usize, default_value_t = 50)]
        top: usize,
    },
    Search {
        input: PathBuf,
        query: String,
        /// Count every match in the scanned range instead of stopping at the display limit.
        #[arg(long)]
        count_all: bool,
        #[arg(long, value_enum, default_value_t = SearchRankArg::Id)]
        rank: SearchRankArg,
        #[arg(long, value_enum, default_value_t = SearchModeArg::Contains)]
        mode: SearchModeArg,
        #[arg(long)]
        ignore_case: bool,
        #[arg(long, value_parser = parse_positive_usize, default_value_t = 50)]
        limit: usize,
        #[arg(long)]
        after_id: Option<u64>,
        #[arg(long, default_value_t = 5_000_000)]
        max_scanned: u64,
        #[arg(long, default_value_t = 30_000)]
        timeout_ms: u64,
        #[arg(long, value_parser = parse_positive_usize, default_value_t = 256)]
        preview_bytes: usize,
        #[arg(long)]
        generation: Option<String>,
    },
    /// Page the immediate incoming dependencies of one node.
    Incoming {
        input: PathBuf,
        node_id: u64,
        #[arg(long, value_parser = parse_positive_usize, default_value_t = 50)]
        limit: usize,
        #[arg(long)]
        after_edge: Option<u64>,
        #[arg(long, default_value_t = 5000)]
        timeout_ms: u64,
        #[arg(long, value_parser = parse_positive_usize, default_value_t = 256)]
        preview_bytes: usize,
        #[arg(long)]
        generation: Option<String>,
    },
    /// Explain multiple IDs using one generation and a shared total traversal budget.
    Batch {
        input: PathBuf,
        #[arg(long, value_delimiter = ',', required = true)]
        ids: Vec<u64>,
        #[command(flatten)]
        options: BatchArgs,
    },
    Why {
        input: PathBuf,
        query: String,
        #[arg(long, default_value_t = 16)]
        max_depth: usize,
        #[arg(long, default_value = "3")]
        max_paths: NonZeroUsize,
        #[arg(long, default_value = "10000")]
        max_visited: NonZeroUsize,
        #[arg(long, default_value_t = 100_000)]
        max_edges: u64,
        #[arg(long, default_value_t = 5000)]
        timeout_ms: u64,
        #[arg(long, default_value = "256")]
        preview_bytes: NonZeroUsize,
        #[arg(long)]
        generation: Option<String>,
    },
}

#[derive(Clone, Debug, Args)]
pub struct BatchArgs {
    #[arg(long, default_value_t = 16)]
    pub max_depth: usize,
    #[arg(long, value_parser = parse_positive_usize, default_value_t = 3)]
    pub max_paths: usize,
    #[arg(long, value_parser = parse_positive_usize, default_value_t = 10_000)]
    pub max_visited: usize,
    #[arg(long, default_value_t = 100_000)]
    pub max_edges: u64,
    #[arg(long, default_value_t = 5000)]
    pub timeout_ms: u64,
    #[arg(long, value_parser = parse_positive_usize, default_value_t = 256)]
    pub preview_bytes: usize,
    #[arg(long)]
    pub generation: Option<String>,
}

impl From<&BatchArgs> for WhyOptions {
    fn from(value: &BatchArgs) -> Self {
        Self {
            max_depth: value.max_depth,
            max_paths: value.max_paths,
            max_visited: value.max_visited,
            max_edges: value.max_edges,
            timeout_ms: value.timeout_ms,
            preview_bytes: value.preview_bytes,
            generation: value.generation.clone(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub enum SearchRankArg {
    Id,
    Incoming,
}

impl From<SearchRankArg> for SearchRank {
    fn from(value: SearchRankArg) -> Self {
        match value {
            SearchRankArg::Id => Self::Id,
            SearchRankArg::Incoming => Self::Incoming,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub enum SearchModeArg {
    Id,
    Exact,
    Prefix,
    Contains,
}

impl From<SearchModeArg> for SearchMode {
    fn from(value: SearchModeArg) -> Self {
        match value {
            SearchModeArg::Id => Self::Id,
            SearchModeArg::Exact => Self::Exact,
            SearchModeArg::Prefix => Self::Prefix,
            SearchModeArg::Contains => Self::Contains,
        }
    }
}

#[derive(Clone, Debug, Subcommand)]
pub enum CacheCommand {
    Info { path: PathBuf },
    Verify { path: PathBuf },
    Prune { path: PathBuf },
}

#[derive(Clone, Debug, Args)]
pub struct MetadataArgs {
    /// Metadata CSV path, or `-` for standard input.
    pub input: PathBuf,
    #[arg(long, value_parser = parse_positive_usize, default_value_t = 50)]
    pub top: usize,
    #[arg(long)]
    pub assembly: Option<String>,
    /// Exact owning type from the by-type report, including its assembly prefix.
    #[arg(long = "type")]
    pub type_name: Option<String>,
    /// Literal case-sensitive substring of resolved assembly, namespace or type.
    #[arg(long, value_parser = clap::builder::NonEmptyStringValueParser::new())]
    pub contains: Option<String>,
    /// Maximum UTF-8 bytes per string preview.
    #[arg(long, value_parser = parse_positive_usize, default_value_t = 256)]
    pub preview_bytes: usize,
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
    execute_with_index_control(cli, &IndexControl::default())
}

/// Executes commands with cooperative DGML index cancellation and progress.
///
/// # Errors
///
/// Returns the same typed diagnostics as [`execute`].
pub fn execute_with_index_control(cli: &Cli, control: &IndexControl) -> Result<String, AppError> {
    if cli.daemon.is_some()
        && !matches!(&cli.command,
        Command::Dgml(arguments) if matches!(arguments.command, DgmlCommand::Search { .. } | DgmlCommand::Why { .. } | DgmlCommand::Incoming { .. } | DgmlCommand::Batch { .. }))
    {
        return Err(AppError::Unsupported(Box::new(Diagnostic::malformed(
            "daemon.command",
            "--daemon supports only dgml search, why, incoming and batch",
        ))));
    }
    match &cli.command {
        Command::Explore(arguments) => {
            validate_resources(cli)?;
            explorer::execute(cli, &arguments.command, control)
        }
        Command::Attribution(arguments) => {
            validate_resources(cli)?;
            attribution_cli::execute(cli, &arguments.command)
        }
        Command::Bloat(arguments) => {
            validate_resources(cli)?;
            insights_cli::execute_bloat(cli, arguments)
        }
        Command::Metadata(arguments) => execute_metadata(cli, arguments),
        Command::Mstat(arguments) => execute_mstat(cli, &arguments.command),
        Command::Dgml(arguments) => execute_dgml(cli, &arguments.command, control),
        Command::Cache(arguments) => execute_cache(cli, &arguments.command),
        Command::Daemon(arguments) => execute_daemon(cli, &arguments.command),
    }
}

fn daemon_diagnostic(diagnostic: Box<Diagnostic>) -> AppError {
    if diagnostic.code.starts_with("resource.") {
        AppError::Resource(diagnostic)
    } else if diagnostic.code.starts_with("io.") {
        AppError::IoDiagnostic(diagnostic)
    } else {
        AppError::Unsupported(diagnostic)
    }
}

fn daemon_query<T: serde::de::DeserializeOwned>(
    cli: &Cli,
    pipe: &str,
    request: &daemon::Request,
) -> Result<T, AppError> {
    let response =
        daemon::call(pipe, request).map_err(|error| daemon_diagnostic(error.diagnostic))?;
    if !response.ok {
        return Err(daemon_diagnostic(Box::new(response.error.ok_or_else(
            || {
                AppError::IoDiagnostic(Box::new(Diagnostic::malformed(
                    "io.daemon.protocol",
                    "failed response lacks a diagnostic",
                )))
            },
        )?)));
    }
    if response.error.is_some() {
        return Err(AppError::IoDiagnostic(Box::new(Diagnostic::malformed(
            "io.daemon.protocol",
            "successful response contains a failure diagnostic",
        ))));
    }
    if cli.verbose {
        eprintln!("daemon session reused: {}", response.session_reused);
    }
    serde_json::from_value(response.data.ok_or_else(|| {
        AppError::IoDiagnostic(Box::new(Diagnostic::malformed(
            "io.daemon.protocol",
            "successful response lacks data",
        )))
    })?)
    .map_err(|error| {
        AppError::IoDiagnostic(Box::new(Diagnostic::malformed(
            "io.daemon.protocol",
            format!("invalid query response: {error}"),
        )))
    })
}

fn execute_daemon(cli: &Cli, command: &DaemonCommand) -> Result<String, AppError> {
    validate_resources(cli)?;
    if let DaemonCommand::Serve { pipe } = command {
        daemon::serve(pipe, cli.memory_limit.0)
            .map_err(|error| daemon_diagnostic(error.diagnostic))?;
        return Ok("Daemon stopped; graph sessions released.".into());
    }
    let (pipe, request) = match command {
        DaemonCommand::Status { pipe } => (pipe, daemon::Request::Health),
        DaemonCommand::Stop { pipe } => (pipe, daemon::Request::Shutdown),
        DaemonCommand::Serve { .. } => unreachable!(),
    };
    let response: serde_json::Value = daemon_query(cli, pipe, &request)?;
    match cli.format {
        FormatArg::Ndjson => serde_json::to_string(&response).map_err(AppError::Json),
        FormatArg::Json | FormatArg::Table => {
            serde_json::to_string_pretty(&response).map_err(AppError::Json)
        }
    }
}

fn execute_mstat(cli: &Cli, command: &MstatCommand) -> Result<String, AppError> {
    validate_resources(cli)?;
    match command {
        MstatCommand::Top {
            input,
            top,
            contains,
            stream,
        } => {
            let report = top_path(
                input,
                cli.memory_limit.0,
                *top,
                contains.as_deref(),
                stream.as_deref(),
            )
            .map_err(|error| {
                if error.diagnostic.code == "mstat.io" {
                    AppError::IoDiagnostic(error.diagnostic)
                } else if error.diagnostic.code.starts_with("resource.") {
                    AppError::Resource(error.diagnostic)
                } else {
                    AppError::Mstat(error)
                }
            })?;
            match cli.format {
                FormatArg::Json => serde_json::to_string_pretty(&report).map_err(AppError::Json),
                FormatArg::Ndjson => report
                    .sections
                    .iter()
                    .map(|section| ndjson_line(&report.schema, "sections", section))
                    .collect::<Result<Vec<_>, _>>()
                    .map(|lines| lines.join("\n")),
                FormatArg::Table => {
                    let mut output = format!(
                        "MSTAT accounted size: {}\nIdentities are opaque producer symbols, not DGML IDs. Breakdowns overlap accounted streams.\n",
                        display::exact(report.accounted_size_bytes)
                    );
                    for section in &report.sections {
                        writeln!(&mut output, "\n{}{}: matched {} / {} across {} identities\nSize          % total    % stream   Records  Identity",
                            section.name, if section.accounted { "" } else { " [overlapping breakdown]" },
                            display::exact(section.matched_bytes), display::exact(section.total_bytes), section.matched_identities).unwrap();
                        let displayed = section
                            .entries
                            .iter()
                            .map(|entry| u128::from(entry.bytes))
                            .sum::<u128>();
                        for entry in &section.entries {
                            writeln!(
                                &mut output,
                                "{:<13} {:>9} {:>10} {:<8} {}{}",
                                display::bytes(entry.bytes),
                                if section.accounted {
                                    display::percent(entry.bytes, Some(report.accounted_size_bytes))
                                } else {
                                    "Overlap".into()
                                },
                                display::percent(entry.bytes, Some(section.total_bytes)),
                                entry.records,
                                display::text(&entry.identity),
                                if entry.truncated {
                                    " [display shortened]"
                                } else {
                                    ""
                                }
                            )
                            .unwrap();
                        }
                        writeln!(&mut output, "Shown: {displayed} B / {} matched bytes; this is a bounded top list, not a complete inventory.", section.matched_bytes).unwrap();
                    }
                    Ok(output)
                }
            }
        }
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
        MstatCommand::Diff { before, after, top } => {
            let report = diff_paths(before, after, cli.memory_limit.0, *top).map_err(|error| {
                if error.diagnostic.code == "mstat.io" {
                    AppError::IoDiagnostic(error.diagnostic)
                } else if error.diagnostic.code.starts_with("resource.") {
                    AppError::Resource(error.diagnostic)
                } else {
                    AppError::Mstat(error)
                }
            })?;
            render_mstat_diff(cli.format, &report)
        }
        _ => insights_cli::execute_mstat(cli, command),
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
                "MSTAT {}.{}: {}\nAccounted size: {}\nInput (MSTAT file, not executable): {}\nMangled names: {}\nTracked memory peak: {}\n",
                summary.format_version.major,
                summary.format_version.minor,
                display::text(&summary.assembly),
                display::exact(summary.accounted_size_bytes),
                display::exact(summary.input_bytes),
                display::exact(summary.mangled_names_bytes),
                display::exact(summary.peak_tracked_memory_bytes),
            );
            output
                .push_str("\nStreams\nRecords      Items        Size          % total    Encoded       Role          Name\n");
            for category in &summary.categories {
                writeln!(
                    &mut output,
                    "{:<12} {:<12} {:<13} {:>9} {:<13} {:<13} {}",
                    category.records,
                    category.items,
                    display::bytes(category.aggregate_size_bytes),
                    if matches!(category.name.as_str(), "Methods" | "Types" | "Blobs") {
                        display::percent(
                            category.aggregate_size_bytes,
                            Some(summary.accounted_size_bytes),
                        )
                    } else {
                        "Overlap".into()
                    },
                    display::bytes(category.encoded_bytes),
                    if matches!(category.name.as_str(), "Methods" | "Types" | "Blobs") {
                        "Additive"
                    } else {
                        "Overlapping"
                    },
                    category.name,
                )
                .expect("writing to String cannot fail");
            }
            writeln!(
                &mut output,
                "\nMethods: bodies {}, GC info {}, EH info {}",
                display::exact(summary.methods.body_bytes),
                display::exact(summary.methods.gc_info_bytes),
                display::exact(summary.methods.exception_info_bytes),
            )
            .expect("writing to String cannot fail");
            writeln!(
                &mut output,
                "Frozen objects (overlaps Blobs): owned {} / {}, unowned {} / {}",
                summary.frozen_objects.owned_records,
                display::exact(summary.frozen_objects.owned_bytes),
                summary.frozen_objects.unowned_records,
                display::exact(summary.frozen_objects.unowned_bytes),
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

fn render_mstat_diff(format: FormatArg, report: &MstatDiff) -> Result<String, AppError> {
    match format {
        FormatArg::Json => serde_json::to_string_pretty(report).map_err(AppError::Json),
        FormatArg::Ndjson => {
            let mut lines = vec![
                serde_json::to_string(&serde_json::json!({
                    "schema": report.schema,
                    "section": "summary",
                    "value": {
                        "before_assembly": report.before_assembly,
                        "after_assembly": report.after_assembly,
                        "before_input_bytes": report.before_input_bytes,
                        "after_input_bytes": report.after_input_bytes,
                        "total_delta_bytes": report.total_delta_bytes,
                        "before_deduplicated_methods": report.before_deduplicated_methods,
                        "after_deduplicated_methods": report.after_deduplicated_methods,
                        "reconciliation": report.reconciliation,
                        "peak_tracked_memory_bytes": report.peak_tracked_memory_bytes,
                    },
                }))
                .map_err(AppError::Json)?,
            ];
            for section in &report.sections {
                lines.push(ndjson_line(&report.schema, "section", section)?);
                for entry in &section.entries {
                    lines.push(ndjson_line(
                        &report.schema,
                        &format!("{}.entries", section.name),
                        entry,
                    )?);
                }
            }
            Ok(lines.join("\n"))
        }
        FormatArg::Table => {
            let mut output = format!(
                "MSTAT accounted delta: {}\n{} -> {}\nTracked memory peak: {}\n",
                display::signed(report.total_delta_bytes),
                display::text(&report.before_assembly),
                display::text(&report.after_assembly),
                display::exact(report.peak_tracked_memory_bytes),
            );
            for section in &report.sections {
                writeln!(
                    &mut output,
                    "\n{}{}: {} ({} added, {} removed, {} changed)",
                    section.name,
                    if section.accounted {
                        ""
                    } else {
                        " [breakdown]"
                    },
                    display::signed(section.delta_bytes),
                    section.added,
                    section.removed,
                    section.changed,
                )
                .expect("writing to String cannot fail");
                for entry in &section.entries {
                    writeln!(
                        &mut output,
                        "{}  {} -> {} records  {}",
                        display::signed(entry.delta_bytes),
                        entry.before_records,
                        entry.after_records,
                        display::text(&entry.identity),
                    )
                    .expect("writing to String cannot fail");
                }
            }
            Ok(output)
        }
    }
}

#[allow(clippy::too_many_lines)]
fn execute_dgml(
    cli: &Cli,
    command: &DgmlCommand,
    control: &IndexControl,
) -> Result<String, AppError> {
    validate_resources(cli)?;
    match command {
        DgmlCommand::Index {
            input,
            cache_dir,
            entry,
        } => {
            let cache_root = cache_dir.clone().unwrap_or_else(|| {
                cli.temp_dir.clone().unwrap_or_else(|| {
                    input
                        .parent()
                        .unwrap_or_else(|| Path::new("."))
                        .join(".vitnet-cache")
                })
            });
            let report = build_index(
                input,
                &IndexOptions {
                    cache_root,
                    memory_limit: cli.memory_limit.0,
                    selected_entry: entry.clone(),
                    strict_hash: cli.strict,
                    control: control.clone(),
                },
            )
            .map_err(|mut error| {
                error.diagnostic.input_path = Some(input.clone());
                if error.diagnostic.code.starts_with("resource.")
                    || error.diagnostic.code == "dgml.index.locked"
                {
                    AppError::Resource(error.diagnostic)
                } else if error.diagnostic.code.starts_with("io.") {
                    AppError::IoDiagnostic(error.diagnostic)
                } else {
                    AppError::Dgml(error)
                }
            })?;
            render_dgml_index(cli.format, &report)
        }
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
        DgmlCommand::Search {
            input,
            query,
            count_all,
            rank,
            mode,
            ignore_case,
            limit,
            after_id,
            max_scanned,
            timeout_ms,
            preview_bytes,
            generation,
        } => {
            validate_resources(cli)?;
            let options = SearchOptions {
                count_all: *count_all,
                rank: (*rank).into(),
                mode: (*mode).into(),
                ignore_case: *ignore_case,
                limit: *limit,
                after_id: *after_id,
                max_scanned: *max_scanned,
                timeout_ms: *timeout_ms,
                preview_bytes: *preview_bytes,
                generation: generation.clone(),
            };
            let report: vitnet_dgml::SearchReport = if let Some(pipe) = &cli.daemon {
                daemon_query(
                    cli,
                    pipe,
                    &daemon::Request::Search {
                        index: std::fs::canonicalize(input).map_err(|source| AppError::Io {
                            path: input.clone(),
                            source,
                        })?,
                        query: query.clone(),
                        options,
                    },
                )?
            } else {
                GraphSession::open(input, cli.memory_limit.0)
                    .map_err(cache_error)?
                    .search(query, &options)
                    .map_err(cache_error)?
            };
            match cli.format {
                FormatArg::Json => serde_json::to_string_pretty(&report).map_err(AppError::Json),
                FormatArg::Ndjson => serde_json::to_string(&report).map_err(AppError::Json),
                FormatArg::Table => {
                    let mut output = format!(
                        "DGML search: {} matches ({} shown, {} omitted); scanned {} slots in {} ms\nGeneration: {}\nStatus: {} (counts/ranks cover this scanned range only; not byte sizes)\nNode ID      Incoming     Label\n",
                        report.matched_nodes,
                        report.entries.len(),
                        report.omitted_matches,
                        report.scanned_nodes,
                        report.elapsed_ms,
                        report.generation,
                        report.stop_reason
                    );
                    for entry in report.entries {
                        writeln!(
                            &mut output,
                            "{:<12} {:<12} {}{}",
                            entry.node_id,
                            entry.incoming_edges,
                            entry.label,
                            if entry.truncated { "..." } else { "" }
                        )
                        .unwrap();
                    }
                    if let Some(after) = report.next_after_id {
                        writeln!(
                            &mut output,
                            "Continue: --after-id {after} --generation {}",
                            report.generation
                        )
                        .unwrap();
                    }
                    Ok(output)
                }
            }
        }
        DgmlCommand::Incoming {
            input,
            node_id,
            limit,
            after_edge,
            timeout_ms,
            preview_bytes,
            generation,
        } => {
            validate_resources(cli)?;
            let options = IncomingOptions {
                limit: *limit,
                after_edge: *after_edge,
                timeout_ms: *timeout_ms,
                preview_bytes: *preview_bytes,
                generation: generation.clone(),
            };
            let report: vitnet_dgml::IncomingReport = if let Some(pipe) = &cli.daemon {
                daemon_query(
                    cli,
                    pipe,
                    &daemon::Request::Incoming {
                        index: canonical_index(input)?,
                        node_id: *node_id,
                        options,
                    },
                )?
            } else {
                GraphSession::open(input, cli.memory_limit.0)
                    .map_err(cache_error)?
                    .incoming(*node_id, &options)
                    .map_err(cache_error)?
            };
            render_query(cli.format, &report, || {
                let mut output = format!(
                    "Incoming {}: {}\nGeneration: {}\n{} / {} edges; stop: {}\n",
                    node_id,
                    report.node.label,
                    report.generation,
                    report.edges.len(),
                    report.total_edges,
                    report.stop_reason
                );
                for edge in &report.edges {
                    writeln!(
                        &mut output,
                        "{}: {} -> {} [{}{}] {}",
                        edge.ordinal,
                        edge.source_id,
                        edge.target_id,
                        edge.reason,
                        if edge.reason_truncated { "..." } else { "" },
                        edge.source
                            .as_ref()
                            .map_or("[missing source]", |node| node.label.as_str())
                    )
                    .unwrap();
                }
                if let Some(after) = report.next_after_edge {
                    writeln!(
                        &mut output,
                        "Continue: --after-edge {after} --generation {}",
                        report.generation
                    )
                    .unwrap();
                }
                writeln!(&mut output, "{}", report.caveat).unwrap();
                output
            })
        }
        DgmlCommand::Batch {
            input,
            ids,
            options,
        } => {
            validate_resources(cli)?;
            let options = WhyOptions::from(options);
            let report: vitnet_dgml::BatchReport = if let Some(pipe) = &cli.daemon {
                daemon_query(
                    cli,
                    pipe,
                    &daemon::Request::Batch {
                        index: canonical_index(input)?,
                        ids: ids.clone(),
                        options,
                    },
                )?
            } else {
                GraphSession::open(input, cli.memory_limit.0)
                    .map_err(cache_error)?
                    .batch(ids, &options)
                    .map_err(cache_error)?
            };
            render_query(cli.format, &report, || {
                let mut output = format!(
                    "Batch: {} / {} IDs; stop: {}\nGeneration: {}\nTotal work: {} edges / {} visits\n",
                    report.reports.len(),
                    report.requested_nodes,
                    report.stop_reason,
                    report.generation,
                    report.examined_edges,
                    report.visited_nodes
                );
                for item in &report.reports {
                    writeln!(
                        &mut output,
                        "\n{}: {} (stop: {})",
                        item.node.node_id, item.node.label, item.stop_reason
                    )
                    .unwrap();
                    for path in &item.paths {
                        writeln!(&mut output, "Witness: {}", path.root_kind).unwrap();
                        for (position, node) in path.nodes.iter().enumerate() {
                            writeln!(&mut output, "  {}: {}", node.node_id, node.label).unwrap();
                            if let Some(reason) = path.reasons.get(position) {
                                writeln!(
                                    &mut output,
                                    "    --[{}{}]-->",
                                    reason,
                                    if path.reasons_truncated[position] {
                                        "..."
                                    } else {
                                        ""
                                    }
                                )
                                .unwrap();
                            }
                        }
                    }
                }
                output.push_str("\nCompletion means all requested IDs were processed; each witness retains its own stop/caveat. Fan-in is not byte size.\n");
                output
            })
        }
        DgmlCommand::Why {
            input,
            query,
            max_depth,
            max_paths,
            max_visited,
            max_edges,
            timeout_ms,
            preview_bytes,
            generation,
        } => {
            validate_resources(cli)?;
            let id = query.parse::<u64>().map_err(|_| {
                AppError::Dgml(DgmlError {
                    diagnostic: Box::new(Diagnostic::malformed(
                        "dgml.query.id",
                        "why requires a numeric node ID from dgml search",
                    )),
                })
            })?;
            let options = WhyOptions {
                max_depth: *max_depth,
                max_paths: max_paths.get(),
                max_visited: max_visited.get(),
                max_edges: *max_edges,
                timeout_ms: *timeout_ms,
                preview_bytes: preview_bytes.get(),
                generation: generation.clone(),
            };
            let report: vitnet_dgml::WhyReport = if let Some(pipe) = &cli.daemon {
                daemon_query(
                    cli,
                    pipe,
                    &daemon::Request::Why {
                        index: std::fs::canonicalize(input).map_err(|source| AppError::Io {
                            path: input.clone(),
                            source,
                        })?,
                        node_id: id,
                        options,
                    },
                )?
            } else {
                GraphSession::open(input, cli.memory_limit.0)
                    .map_err(cache_error)?
                    .why(id, &options)
                    .map_err(cache_error)?
            };
            match cli.format {
                FormatArg::Json => serde_json::to_string_pretty(&report).map_err(AppError::Json),
                FormatArg::Ndjson => serde_json::to_string(&report).map_err(AppError::Json),
                FormatArg::Table => {
                    let mut output = format!(
                        "Why {}: {}\nVisited: {} nodes, {} edges; stop: {}\n",
                        id,
                        report.node.label,
                        report.visited_nodes,
                        report.examined_edges,
                        report.stop_reason
                    );
                    for path in &report.paths {
                        writeln!(&mut output, "\nWitness ({})", path.root_kind).unwrap();
                        for (index, node) in path.nodes.iter().enumerate() {
                            writeln!(
                                &mut output,
                                "{}: {}{}",
                                node.node_id,
                                node.label,
                                if node.truncated { "..." } else { "" }
                            )
                            .unwrap();
                            if let Some(reason) = path.reasons.get(index) {
                                writeln!(
                                    &mut output,
                                    "  --[{reason}{}]-->",
                                    if path.reasons_truncated[index] {
                                        "..."
                                    } else {
                                        ""
                                    }
                                )
                                .unwrap();
                            }
                        }
                    }
                    writeln!(&mut output, "\n{}", report.caveat).unwrap();
                    Ok(output)
                }
            }
        }
    }
}

fn canonical_index(input: &Path) -> Result<PathBuf, AppError> {
    std::fs::canonicalize(input).map_err(|source| AppError::Io {
        path: input.into(),
        source,
    })
}

fn render_query<T: Serialize>(
    format: FormatArg,
    report: &T,
    table: impl FnOnce() -> String,
) -> Result<String, AppError> {
    match format {
        FormatArg::Json => serde_json::to_string_pretty(report).map_err(AppError::Json),
        FormatArg::Ndjson => serde_json::to_string(report).map_err(AppError::Json),
        FormatArg::Table => Ok(table()),
    }
}

fn render_dgml_index(format: FormatArg, report: &DgmlIndexReport) -> Result<String, AppError> {
    match format {
        FormatArg::Json => serde_json::to_string_pretty(report).map_err(AppError::Json),
        FormatArg::Ndjson => serde_json::to_string(report).map_err(AppError::Json),
        FormatArg::Table => Ok(format!(
            "DGML index: {}\nGeneration: {}\nNodes: {}\nEdges: {}\nIndex size: {}\nTracked memory peak: {}\nUnresolved endpoints: {}\n",
            report.index_directory.display(),
            report.generation,
            report.manifest.node_count,
            report.manifest.edge_count,
            display::exact(report.index_bytes),
            display::exact(report.peak_tracked_memory_bytes),
            report.manifest.unresolved_endpoints,
        )),
    }
}

fn execute_cache(cli: &Cli, command: &CacheCommand) -> Result<String, AppError> {
    validate_resources(cli)?;
    match command {
        CacheCommand::Info { path } => {
            let value = cache_info(path).map_err(cache_error)?;
            render_cache_info(cli.format, &value)
        }
        CacheCommand::Verify { path } => {
            let value = verify_cache(path).map_err(cache_error)?;
            render_cache_verification(cli.format, &value)
        }
        CacheCommand::Prune { path } => {
            let value = prune_cache(path).map_err(cache_error)?;
            render_cache_prune(cli.format, &value)
        }
    }
}

fn cache_error(error: DgmlError) -> AppError {
    if error.diagnostic.code == "dgml.index.locked"
        || error.diagnostic.code.starts_with("resource.")
    {
        AppError::Resource(error.diagnostic)
    } else if error.diagnostic.code.starts_with("io.") {
        AppError::IoDiagnostic(error.diagnostic)
    } else {
        AppError::Dgml(error)
    }
}

fn render_cache_info(format: FormatArg, value: &DgmlCacheInfo) -> Result<String, AppError> {
    match format {
        FormatArg::Json => serde_json::to_string_pretty(value).map_err(AppError::Json),
        FormatArg::Ndjson => serde_json::to_string(value).map_err(AppError::Json),
        FormatArg::Table => Ok(format!(
            "DGML cache: {}\nGeneration: {}\nNodes: {}\nEdges: {}\nSize: {}\n",
            value.index_directory.display(),
            value.generation,
            value.manifest.node_count,
            value.manifest.edge_count,
            display::exact(value.index_bytes),
        )),
    }
}

fn render_cache_verification(
    format: FormatArg,
    value: &DgmlCacheVerification,
) -> Result<String, AppError> {
    match format {
        FormatArg::Json => serde_json::to_string_pretty(value).map_err(AppError::Json),
        FormatArg::Ndjson => serde_json::to_string(value).map_err(AppError::Json),
        FormatArg::Table => Ok(format!(
            "DGML cache verified: {}\nGeneration: {}\nFiles: {}\nSize: {}\n",
            value.index_directory.display(),
            value.generation,
            value.files_verified,
            display::exact(value.index_bytes),
        )),
    }
}

fn render_cache_prune(format: FormatArg, value: &DgmlCachePruneReport) -> Result<String, AppError> {
    match format {
        FormatArg::Json => serde_json::to_string_pretty(value).map_err(AppError::Json),
        FormatArg::Ndjson => serde_json::to_string(value).map_err(AppError::Json),
        FormatArg::Table => Ok(format!(
            "DGML cache pruned: {}\nCurrent generation: {}\nGenerations removed: {}\nTemporary directories removed: {}\nBytes removed: {}\n",
            value.index_directory.display(),
            value.current_generation,
            value.generations_removed,
            value.temporary_directories_removed,
            display::exact(value.bytes_removed),
        )),
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
                "DGML: {} nodes, {} edges\nInput: {}\nDuplicate node IDs: {}\nUnresolved endpoints: {}\nTracked memory peak: {}\n",
                stats.node_count,
                stats.edge_count,
                display::exact(stats.input_bytes),
                stats.duplicate_node_ids,
                stats.unresolved_endpoints,
                display::exact(stats.peak_tracked_memory_bytes),
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
        type_filter: arguments
            .type_name
            .as_ref()
            .map(|name| name.as_bytes().to_vec()),
        contains_filter: arguments
            .contains
            .as_ref()
            .map(|name| name.as_bytes().to_vec()),
        top: arguments.top,
        preview_bytes: arguments.preview_bytes,
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
                "Metadata lower-bound delta: {}\n",
                display::signed(report.summary.delta_bytes)
            );
            for (section, comparison) in comparison_sections(report, arguments) {
                writeln!(&mut output, "\n{}", heading(section))
                    .expect("writing to String cannot fail");
                for entry in comparison.entries.iter().take(arguments.top) {
                    writeln!(
                        &mut output,
                        "{}  {} -> {}  {}",
                        display::signed(entry.delta_bytes),
                        display::exact(entry.before_bytes),
                        display::exact(entry.after_bytes),
                        display::text(&entry.name)
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
    for (section, coverage) in &report.sections.concentration {
        lines.push(ndjson_line(
            &report.schema,
            &format!("{section}_concentration"),
            coverage,
        )?);
    }
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
        "Metadata lower bound: {} across {} records\n",
        display::exact(report.summary.metadata_lower_bound_bytes),
        report.summary.observed_record_count
    );
    if report.summary.selected_lower_bound_bytes != report.summary.metadata_lower_bound_bytes {
        writeln!(
            &mut output,
            "Selected lower bound: {} across {} records",
            display::exact(report.summary.selected_lower_bound_bytes),
            report.summary.record_count
        )
        .expect("writing to String cannot fail");
    }
    output.push_str("Final record size: unknown\n");
    match report.sections.limit_status {
        vitnet_metadata::LimitStatus::OverByAtLeast { bytes, limit, .. } => {
            writeln!(
                &mut output,
                "NativeAOT limit:      {}\nStatus:               OVER by at least {}",
                display::exact(limit),
                display::exact(bytes)
            )
            .expect("writing to String cannot fail");
        }
        vitnet_metadata::LimitStatus::AtOrBelowHeadroomUnknown { limit, .. } => {
            writeln!(
                &mut output,
                "NativeAOT limit:      {}\nStatus:               at or below limit; remaining headroom unknown",
                display::exact(limit)
            )
            .expect("writing to String cannot fail");
        }
    }
    for (section, entries) in analysis_sections(report, arguments) {
        render_aggregate_section(&mut output, heading(section), entries, report);
        if let Some(coverage) = report.sections.concentration.get(section) {
            writeln!(
                &mut output,
                "Top coverage: {} / {} ({}) across {} / {} groups; omitted {}",
                display::exact(coverage.reported_bytes),
                display::exact(coverage.total_bytes),
                display::percent(coverage.reported_bytes, Some(coverage.total_bytes)),
                coverage.reported_groups,
                coverage.total_groups,
                display::exact(coverage.omitted_bytes)
            )
            .unwrap();
        }
    }
    if arguments.strings {
        output.push_str("\nLargest strings\nSize          % selected Offset       Value\n");
        for entry in &report.sections.largest_strings {
            let ellipsis = if entry.preview.truncated { "..." } else { "" };
            writeln!(
                &mut output,
                "{:<13} {:>9} {:<12} {}{}",
                display::bytes(entry.bytes),
                display::percent(entry.bytes, Some(report.summary.selected_lower_bound_bytes)),
                entry.logical_offset,
                display::text(&entry.preview.text),
                ellipsis
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
    writeln!(
        output,
        "\n{title}\nSize          % total    % selected Records  Name"
    )
    .expect("writing to String cannot fail");
    let denominator = report.summary.selected_lower_bound_bytes;
    for entry in entries {
        writeln!(
            output,
            "{:<13} {:>9} {:>10} {:<7}  {}",
            display::bytes(entry.bytes),
            display::percent(entry.bytes, Some(report.summary.metadata_lower_bound_bytes)),
            display::percent(entry.bytes, Some(denominator)),
            entry.records,
            display::text(&entry.name)
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

use super::server::{Backend, Query, QueryRequest};
use super::{ExploreCommand, PAGE_LIMIT, RESPONSE_LIMIT, attribution, data, diagnostic};
use crate::{AppError, Cli, FormatArg, ModeArg, display};
use clap::{Args, ValueEnum};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::io::IsTerminal;
use std::path::PathBuf;
use std::time::{Duration, Instant};
use vitnet_core::ByteSize;
use vitnet_dgml::IndexControl;

#[path = "cli_render.rs"]
mod render;
#[path = "cli_reports.rs"]
mod reports;

fn unsigned(value: &str) -> Result<u64, String> {
    if !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()) {
        value
            .parse()
            .map_err(|_| "unsigned value exceeds u64".into())
    } else {
        Err("expected an unsigned decimal value".into())
    }
}

fn page_limit(value: &str) -> Result<usize, String> {
    let value = crate::parse_positive_usize(value)?;
    if value > PAGE_LIMIT {
        Err(format!("page limit must be between 1 and {PAGE_LIMIT}"))
    } else {
        Ok(value)
    }
}

fn positive_time(value: &str) -> Result<u64, String> {
    let value = unsigned(value)?;
    if value == 0 {
        Err("timeout must be positive".into())
    } else {
        Ok(value)
    }
}

#[derive(Clone, Debug, Args)]
pub struct PageArgs {
    #[arg(long, value_parser = page_limit, default_value_t = 50)]
    pub limit: usize,
    /// Automatically continue at most this many bounded scan batches.
    #[arg(long, value_parser = crate::parse_positive_usize, default_value_t = 20)]
    pub max_batches: usize,
    /// Total scan deadline checked between bounded batches.
    #[arg(long, value_parser = positive_time, default_value_t = 30_000)]
    pub timeout_ms: u64,
    /// Resume after this rank position or dataset ordinal, not a display row number.
    #[arg(long, value_parser = unsigned)]
    pub after: Option<u64>,
    /// Refuse a cursor from a different immutable bundle generation.
    #[arg(long)]
    pub generation: Option<String>,
}

#[derive(Clone, Debug, Args)]
pub struct ContributorArgs {
    pub bundle: PathBuf,
    #[arg(long, default_value = "")]
    pub contains: String,
    #[arg(long)]
    pub stream: Option<String>,
    #[arg(long)]
    pub assembly: Option<String>,
    #[arg(long)]
    pub owner: Option<String>,
    #[arg(long, conflicts_with = "family_record")]
    pub family: Option<String>,
    #[arg(long, value_parser = unsigned, conflicts_with = "family")]
    pub family_record: Option<u64>,
    /// Show only additive identities, excluding overlapping projections.
    #[arg(long)]
    pub accounted_only: bool,
    /// Inclusive minimum size, for example 1MB or 64KiB.
    #[arg(long)]
    pub min_bytes: Option<ByteSize>,
    /// Inclusive maximum size.
    #[arg(long)]
    pub max_bytes: Option<ByteSize>,
    /// Match --contains against the complete identity exactly.
    #[arg(long)]
    pub exact: bool,
    /// Table-only columns, in the requested order.
    #[arg(long, value_delimiter = ',', value_enum)]
    pub columns: Vec<ContributorColumn>,
    #[command(flatten)]
    pub page: PageArgs,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, ValueEnum)]
pub enum ContributorColumn {
    Ordinal,
    Size,
    Bytes,
    Total,
    Parent,
    Cumulative,
    Role,
    Stream,
    Identity,
}

impl ContributorColumn {
    fn name(self) -> &'static str {
        match self {
            Self::Ordinal => "ordinal",
            Self::Size => "size",
            Self::Bytes => "bytes",
            Self::Total => "total",
            Self::Parent => "parent",
            Self::Cumulative => "cumulative",
            Self::Role => "role",
            Self::Stream => "stream",
            Self::Identity => "identity",
        }
    }
}

impl ContributorArgs {
    fn check(&self, format: FormatArg) -> Result<(), AppError> {
        if self
            .min_bytes
            .zip(self.max_bytes)
            .is_some_and(|(min, max)| min > max)
        {
            return Err(diagnostic(
                "explorer.query",
                "--min-bytes exceeds --max-bytes",
            ));
        }
        let unique: std::collections::BTreeSet<_> = self.columns.iter().collect();
        if unique.len() != self.columns.len() {
            return Err(diagnostic("explorer.columns", "duplicate table column"));
        }
        if !self.columns.is_empty() && format != FormatArg::Table {
            return Err(diagnostic(
                "explorer.columns.format",
                "--columns requires --format table",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub enum DatasetStorage {
    Bundle,
    OriginalIndex,
    ImmutableGraph,
}

impl DatasetStorage {
    fn name(self) -> &'static str {
        match self {
            Self::Bundle => "bundle",
            Self::OriginalIndex => "original_index",
            Self::ImmutableGraph => "immutable_graph",
        }
    }
}

#[derive(Clone, Debug, Args)]
pub struct DatasetArgs {
    pub bundle: PathBuf,
    /// Literal, case-sensitive substring of the dataset name.
    #[arg(long, default_value = "")]
    pub contains: String,
    #[arg(long, value_enum)]
    pub storage: Option<DatasetStorage>,
    /// Exclude captured datasets whose record count is zero.
    #[arg(long)]
    pub nonempty: bool,
}

#[derive(Clone, Debug, Args)]
pub struct ExplainArgs {
    pub bundle: PathBuf,
    /// Original identity ordinal, not rank position or graph node ID.
    #[arg(value_parser = unsigned)]
    pub ordinal: u64,
    #[arg(long)]
    pub generation: Option<String>,
}

#[derive(Clone, Debug, Args)]
pub struct GlossaryArgs {
    /// Exact pinned compiler bucket name.
    #[arg(conflicts_with = "contains")]
    pub bucket: Option<String>,
    /// Case-insensitive search of bucket names and explanations.
    #[arg(long)]
    pub contains: Option<String>,
}

#[derive(Clone, Debug, Args)]
pub struct RecordArgs {
    pub bundle: PathBuf,
    pub dataset: String,
    #[arg(long, default_value = "")]
    pub contains: String,
    /// Exact captured field=value filter; repeat for intersecting fields.
    #[arg(long = "filter", value_parser = field_filter)]
    pub filters: Vec<(String, String)>,
    #[command(flatten)]
    pub page: PageArgs,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum LensView {
    FeatureOwners,
    Xaml,
    Serializers,
    Repetitions,
    Arguments,
    Costs,
    Reflection,
    Strings,
    Coverage,
}

impl LensView {
    fn dataset(self) -> &'static str {
        match self {
            Self::FeatureOwners => "lens_feature_owners",
            Self::Xaml => "lens_xaml",
            Self::Serializers => "lens_serializers",
            Self::Repetitions => "lens_repetitions",
            Self::Arguments => "lens_arguments",
            Self::Costs => "lens_costs",
            Self::Reflection => "lens_reflection",
            Self::Strings => "lens_metadata_strings",
            Self::Coverage => "lens_coverage",
        }
    }
}

#[derive(Clone, Debug, Args)]
pub struct LensArgs {
    pub bundle: PathBuf,
    #[arg(value_enum)]
    pub view: LensView,
    #[arg(long, default_value = "")]
    pub contains: String,
    #[arg(long)]
    pub assembly: Option<String>,
    #[arg(long)]
    pub namespace: Option<String>,
    #[arg(long)]
    pub owner: Option<String>,
    #[command(flatten)]
    pub page: PageArgs,
}

#[derive(Clone, Debug, Args)]
pub struct FeatureArgs {
    pub bundle: PathBuf,
    #[arg(long)]
    pub assembly: Option<String>,
    /// Include this namespace and its dot-boundary descendants.
    #[arg(long)]
    pub namespace: Option<String>,
    #[arg(long)]
    pub owner: Option<String>,
    /// Exact captured project path; assembly is only a recorded textual hint.
    #[arg(long)]
    pub project: Option<String>,
    #[command(flatten)]
    pub page: PageArgs,
}

#[derive(Clone, Debug, Args)]
pub struct CohortArgs {
    pub bundle: PathBuf,
    #[arg(long="ordinal", value_delimiter=',', required=true, value_parser=unsigned)]
    pub ordinals: Vec<u64>,
    #[arg(long, value_parser=["scan_index","codegen_index"], default_value="codegen_index")]
    pub graph: String,
    #[arg(long)]
    pub generation: Option<String>,
}

fn field_filter(value: &str) -> Result<(String, String), String> {
    value
        .split_once('=')
        .filter(|(key, _)| !key.is_empty())
        .map(|(key, value)| (key.to_owned(), value.to_owned()))
        .ok_or_else(|| "use --filter field=value".into())
}

#[derive(Clone, Debug, Args)]
pub struct OriginArgs {
    pub bundle: PathBuf,
    #[arg(long)]
    pub assembly: Option<String>,
    #[arg(long)]
    pub package: Option<String>,
    #[arg(long)]
    pub target: Option<String>,
    #[command(flatten)]
    pub page: PageArgs,
}

#[derive(Clone, Debug, Args)]
pub struct OpportunityArgs {
    pub bundle: PathBuf,
    #[arg(long, default_value = "")]
    pub contains: String,
    #[arg(long, value_parser = ["generated_pattern", "generator_output", "generic_pattern", "generic_family", "unexpected_feature", "capability_overlap"])]
    pub kind: Option<String>,
    #[command(flatten)]
    pub page: PageArgs,
}

#[derive(Clone, Debug, Args)]
pub struct BudgetArgs {
    pub bundle: PathBuf,
    #[arg(long, default_value = "")]
    pub contains: String,
    #[arg(long, value_parser = ["assembly", "package"])]
    pub dimension: Option<String>,
    #[arg(long)]
    pub target: Option<String>,
    #[command(flatten)]
    pub page: PageArgs,
}

#[derive(Clone, Debug, Args)]
pub struct RetentionArgs {
    pub bundle: PathBuf,
    /// Compiler graph node ID, not a contributor ordinal.
    #[arg(value_parser = unsigned)]
    pub node_id: u64,
    #[arg(long, value_parser = ["scan_index", "codegen_index"], default_value = "scan_index")]
    pub graph: String,
    #[arg(long)]
    pub generation: Option<String>,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum InspectView {
    Record,
    Source,
    Shape,
    Symbol,
}

#[derive(Clone, Debug, Args)]
pub struct InspectArgs {
    pub bundle: PathBuf,
    #[arg(value_parser = unsigned)]
    pub ordinal: u64,
    #[arg(long, default_value = "identities")]
    pub dataset: String,
    #[arg(long, value_enum, default_value_t = InspectView::Record)]
    pub view: InspectView,
    /// Positional child indices, in the exact order shown by inspect.
    #[arg(long, value_delimiter = ',', value_parser = unsigned)]
    pub path: Vec<u64>,
    /// String UTF-8 byte offset or object/array child offset.
    #[arg(long, value_parser = unsigned, default_value_t = 0)]
    pub start: u64,
    /// Read the full field name at the selected object child.
    #[arg(long)]
    pub key: bool,
    #[arg(long)]
    pub generation: Option<String>,
}

impl PageArgs {
    fn check(&self) -> Result<(), AppError> {
        if self.limit == 0
            || self.limit > PAGE_LIMIT
            || self.max_batches == 0
            || self.timeout_ms == 0
        {
            return Err(diagnostic(
                "resource.explorer.query",
                "invalid terminal page budgets",
            ));
        }
        Ok(())
    }
}

fn request(generation: &str, query: Query) -> QueryRequest {
    QueryRequest {
        request_id: "terminal".into(),
        generation: generation.into(),
        query,
    }
}

fn page_query(
    command: &ExploreCommand,
    after: Option<u64>,
    limit: usize,
) -> Result<Query, AppError> {
    Ok(match command {
        ExploreCommand::Lenses(args) => Query::Records {
            dataset: args.view.dataset().into(),
            contains: args.contains.clone(),
            filters: [
                ("assembly", &args.assembly),
                ("namespace", &args.namespace),
                ("owner", &args.owner),
            ]
            .into_iter()
            .filter_map(|(key, value)| value.clone().map(|value| (key.into(), value)))
            .collect(),
            after,
            limit,
        },
        ExploreCommand::Contributors(args) => Query::RankedRows {
            contains: args.contains.clone(),
            stream: args.stream.clone(),
            assembly: args.assembly.clone(),
            owner: args.owner.clone(),
            family: args.family.clone(),
            family_record: args.family_record,
            accounted_only: args.accounted_only,
            min_bytes: args.min_bytes.map(|bytes| bytes.0),
            max_bytes: args.max_bytes.map(|bytes| bytes.0),
            exact: args.exact,
            after,
            limit,
        },
        ExploreCommand::Records(args) => {
            let mut filters = BTreeMap::new();
            for (key, value) in &args.filters {
                if filters.insert(key.clone(), value.clone()).is_some() {
                    return Err(diagnostic("explorer.query", "duplicate exact filter field"));
                }
            }
            Query::Records {
                dataset: args.dataset.clone(),
                contains: args.contains.clone(),
                filters,
                after,
                limit,
            }
        }
        ExploreCommand::Origins(args) => Query::Related {
            assembly: args.assembly.clone(),
            package: args.package.clone(),
            target: args.target.clone(),
            after,
            limit,
        },
        ExploreCommand::Opportunities(args) => Query::Records {
            dataset: "opportunities".into(),
            contains: args.contains.clone(),
            filters: args
                .kind
                .as_ref()
                .map(|kind| BTreeMap::from([("kind".into(), kind.clone())]))
                .unwrap_or_default(),
            after,
            limit,
        },
        ExploreCommand::Budgets(args) => Query::Records {
            dataset: "budgets".into(),
            contains: args.contains.clone(),
            filters: [
                args.dimension
                    .as_ref()
                    .map(|v| ("dimension".into(), v.clone())),
                args.target.as_ref().map(|v| ("target".into(), v.clone())),
            ]
            .into_iter()
            .flatten()
            .collect(),
            after,
            limit,
        },
        _ => {
            return Err(diagnostic(
                "explorer.invariant",
                "not a terminal page command",
            ));
        }
    })
}

fn cursor(value: &Value) -> Result<Option<u64>, AppError> {
    match value {
        Value::Null => Ok(None),
        Value::String(value) => unsigned(value)
            .map(Some)
            .map_err(|message| diagnostic("explorer.cursor", message)),
        _ => Err(diagnostic(
            "explorer.cursor",
            "backend cursor is not a decimal string",
        )),
    }
}

#[allow(clippy::too_many_lines)]
fn progressive_page(
    cli: &Cli,
    command: &ExploreCommand,
    page: &PageArgs,
    backend: &mut Backend<'_>,
    generation: &str,
    control: &IndexControl,
) -> Result<Value, AppError> {
    page.check()?;
    let started = Instant::now();
    let mut entries = Vec::new();
    let mut after = page.after;
    let mut scanned = 0_u64;
    let mut batches = 0_usize;
    let mut retained = 0_usize;
    let mut result = Value::Null;
    loop {
        if batches > 0 && control.is_cancelled() {
            result["stop_reason"] = json!("cancelled");
            break;
        }
        let query = page_query(command, after, page.limit - entries.len())?;
        result = match backend.query(&request(generation, query), control) {
            Err(AppError::Resource(error)) if batches > 0 && error.code == "resource.cancelled" => {
                result["stop_reason"] = json!("cancelled");
                break;
            }
            other => other?,
        };
        batches += 1;
        let count = result["scanned"]
            .as_u64()
            .ok_or_else(|| diagnostic("explorer.invariant", "page is missing scanned count"))?;
        scanned = scanned
            .checked_add(count)
            .ok_or_else(|| diagnostic("explorer.size", "scan count overflow"))?;
        let next = cursor(&result["next_after"])?;
        if next.is_some_and(|next| after.is_some_and(|after| next < after)) {
            return Err(diagnostic(
                "explorer.cursor",
                "backend cursor moved backwards",
            ));
        }
        let batch = result["entries"]
            .as_array_mut()
            .ok_or_else(|| diagnostic("explorer.invariant", "page is missing entries"))?;
        for entry in batch.drain(..) {
            retained = retained
                .checked_add(serde_json::to_vec(&entry).map_err(AppError::Json)?.len())
                .ok_or_else(|| diagnostic("resource.explorer.response", "page size overflow"))?;
            if retained as u64 > (cli.memory_limit.0 / 16).min(RESPONSE_LIMIT as u64) {
                return Err(diagnostic(
                    "resource.explorer.response",
                    "terminal page exceeds response budget; reduce --limit",
                ));
            }
            entries.push(entry);
        }
        if entries.len() > page.limit {
            return Err(diagnostic(
                "explorer.invariant",
                "backend exceeded page limit",
            ));
        }
        if !cli.quiet
            && (cli.progress == ModeArg::Always
                || (cli.progress == ModeArg::Auto && std::io::stderr().is_terminal()))
        {
            eprintln!(
                "Scanned {scanned} positions in {batches} batches; {} / {} rows",
                entries.len(),
                page.limit
            );
        }
        let stop = result["stop_reason"]
            .as_str()
            .ok_or_else(|| diagnostic("explorer.invariant", "page has no stopping reason"))?;
        if control.is_cancelled() || stop == "cancelled" {
            result["stop_reason"] = json!("cancelled");
            break;
        }
        if stop == "complete" {
            if next.is_some() {
                return Err(diagnostic(
                    "explorer.cursor",
                    "complete scan has a continuation",
                ));
            }
            break;
        }
        if !matches!(stop, "limit" | "max_scanned" | "timeout") {
            return Err(diagnostic(
                "explorer.invariant",
                "unsupported backend stopping reason",
            ));
        }
        if next.is_none() {
            return Err(diagnostic(
                "explorer.cursor",
                "incomplete scan lost its continuation",
            ));
        }
        if entries.len() == page.limit {
            result["stop_reason"] = json!("limit");
            break;
        }
        if batches >= page.max_batches {
            result["stop_reason"] = json!("max_batches");
            break;
        }
        if started.elapsed() >= Duration::from_millis(page.timeout_ms) {
            result["stop_reason"] = json!("timeout");
            break;
        }
        if next == after {
            result["stop_reason"] = json!("no_progress");
            break;
        }
        after = next;
    }
    result["entries"] = json!(entries);
    result["scanned"] = json!(scanned);
    result["batches"] = json!(batches);
    result["elapsed_ms"] = json!(u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX));
    Ok(result)
}

fn inspect_query(args: &InspectArgs) -> Result<Query, AppError> {
    if !matches!(args.view, InspectView::Record) && args.dataset != "identities" {
        return Err(diagnostic(
            "explorer.query",
            "source and shape views require the identities dataset",
        ));
    }
    Ok(match args.view {
        InspectView::Record => Query::RecordValue {
            dataset: args.dataset.clone(),
            ordinal: args.ordinal,
            path: args.path.clone(),
            start: args.start,
            key: args.key,
        },
        InspectView::Source => Query::SourceValue {
            ordinal: args.ordinal,
            path: args.path.clone(),
            start: args.start,
            key: args.key,
        },
        InspectView::Shape => Query::IdentityShapeValue {
            ordinal: args.ordinal,
            path: args.path.clone(),
            start: args.start,
            key: args.key,
        },
        InspectView::Symbol => Query::SymbolValue {
            ordinal: args.ordinal,
            path: args.path.clone(),
            start: args.start,
            key: args.key,
        },
    })
}

fn feature_page(
    args: &FeatureArgs,
    backend: &mut Backend<'_>,
    generation: &str,
    control: &IndexControl,
) -> Result<Value, AppError> {
    args.page.check()?;
    let started = Instant::now();
    let mut after = args.page.after;
    let mut ledger: BTreeMap<String, u64> = BTreeMap::new();
    let mut rows = Vec::new();
    let mut examples: Vec<Value> = Vec::new();
    let mut scanned = 0_u64;
    let mut matched = 0_u64;
    let mut result = Value::Null;
    for batch in 0..args.page.max_batches {
        result = backend.query(
            &request(
                generation,
                Query::FeatureFootprint {
                    assembly: args.assembly.clone(),
                    namespace: args.namespace.clone(),
                    owner: args.owner.clone(),
                    project: args.project.clone(),
                    after,
                },
            ),
            control,
        )?;
        for (key, value) in result["ledger"]
            .as_object()
            .ok_or_else(|| diagnostic("explorer.invariant", "feature ledger missing"))?
        {
            let bytes = value
                .as_u64()
                .ok_or_else(|| diagnostic("explorer.invariant", "feature counter not unsigned"))?;
            let total = ledger.entry(key.clone()).or_default();
            *total = total
                .checked_add(bytes)
                .ok_or_else(|| diagnostic("explorer.size", "feature ledger overflow"))?;
        }
        scanned =
            scanned
                .checked_add(result["scanned"].as_u64().ok_or_else(|| {
                    diagnostic("explorer.invariant", "feature scan count missing")
                })?)
                .ok_or_else(|| diagnostic("explorer.size", "feature scan overflow"))?;
        matched =
            matched
                .checked_add(result["matched_owner_groups"].as_u64().ok_or_else(|| {
                    diagnostic("explorer.invariant", "feature group count missing")
                })?)
                .ok_or_else(|| diagnostic("explorer.size", "feature group overflow"))?;
        rows.extend(
            result["entries"]
                .as_array()
                .ok_or_else(|| diagnostic("explorer.invariant", "feature owners missing"))?
                .iter()
                .take(20_usize.saturating_sub(rows.len()))
                .cloned(),
        );
        examples.extend(
            result["examples"]
                .as_array()
                .ok_or_else(|| diagnostic("explorer.invariant", "feature examples missing"))?
                .iter()
                .cloned(),
        );
        examples.sort_by(|a, b| {
            b["bytes"]
                .as_u64()
                .cmp(&a["bytes"].as_u64())
                .then_with(|| a["ordinal"].as_u64().cmp(&b["ordinal"].as_u64()))
        });
        examples.dedup_by(|a, b| a["ordinal"] == b["ordinal"]);
        examples.truncate(3);
        let next = cursor(&result["next_after"])?;
        if result["complete"] == true || control.is_cancelled() {
            break;
        }
        if batch + 1 == args.page.max_batches {
            result["stop_reason"] = json!("max_batches");
            break;
        }
        if started.elapsed() >= Duration::from_millis(args.page.timeout_ms) {
            result["stop_reason"] = json!("timeout");
            break;
        }
        if next.is_none() || next == after {
            result["stop_reason"] = json!("no_progress");
            break;
        }
        after = next;
    }
    result["ledger"] = json!(ledger);
    result["entries"] = json!(rows);
    result["examples"] = json!(examples);
    result["scanned"] = json!(scanned);
    result["matched_owner_groups"] = json!(matched);
    result["scope"] = json!(
        "Ledger aggregates disjoint scanned batches starting at the supplied cursor. Complete means the remaining owner range was exhausted; metadata and specialized streams overlap native totals. Candidates do not establish exclusive physical ownership or removable bytes."
    );
    Ok(result)
}

#[allow(clippy::too_many_lines)]
pub(super) fn execute(
    cli: &Cli,
    command: &ExploreCommand,
    control: &IndexControl,
) -> Result<String, AppError> {
    if matches!(
        command,
        ExploreCommand::Explain(_)
            | ExploreCommand::Compare { .. }
            | ExploreCommand::Coverage { .. }
            | ExploreCommand::Glossary(_)
            | ExploreCommand::Guide { .. }
    ) {
        return reports::execute(cli, command, control);
    }
    let (path, page, expected, operation) = match command {
        ExploreCommand::Lenses(args) => (
            &args.bundle,
            Some(&args.page),
            args.page.generation.as_deref(),
            "lenses",
        ),
        ExploreCommand::Footprint(args) => (
            &args.bundle,
            None,
            args.page.generation.as_deref(),
            "footprint",
        ),
        ExploreCommand::CohortRetention(args) => (
            &args.bundle,
            None,
            args.generation.as_deref(),
            "cohort-retention",
        ),
        ExploreCommand::Summary { bundle } => (bundle, None, None, "summary"),
        ExploreCommand::Datasets(args) => (&args.bundle, None, None, "datasets"),
        ExploreCommand::Contributors(args) => (
            &args.bundle,
            Some(&args.page),
            args.page.generation.as_deref(),
            "contributors",
        ),
        ExploreCommand::Records(args) => (
            &args.bundle,
            Some(&args.page),
            args.page.generation.as_deref(),
            "records",
        ),
        ExploreCommand::Origins(args) => (
            &args.bundle,
            Some(&args.page),
            args.page.generation.as_deref(),
            "origins",
        ),
        ExploreCommand::Inspect(args) => {
            (&args.bundle, None, args.generation.as_deref(), "inspect")
        }
        ExploreCommand::Opportunities(args) => (
            &args.bundle,
            Some(&args.page),
            args.page.generation.as_deref(),
            "opportunities",
        ),
        ExploreCommand::Budgets(args) => (
            &args.bundle,
            Some(&args.page),
            args.page.generation.as_deref(),
            "budgets",
        ),
        ExploreCommand::Retention(args) => {
            (&args.bundle, None, args.generation.as_deref(), "retention")
        }
        _ => {
            return Err(diagnostic(
                "explorer.invariant",
                "not a terminal investigation command",
            ));
        }
    };
    if control.is_cancelled() {
        return Err(diagnostic(
            "resource.cancelled",
            "terminal investigation cancelled",
        ));
    }
    if let ExploreCommand::Contributors(args) = command {
        args.check(cli.format)?;
    }
    let bundle = data::Bundle::open(path, cli.memory_limit.0)?;
    let generation = &bundle.manifest.generation;
    if expected.is_some_and(|expected| expected != generation) {
        return Err(diagnostic(
            "explorer.generation",
            "bundle generation differs; restart the query without the old cursor",
        ));
    }
    let index =
        vitnet_attribution::open_index(&bundle.manifest.attribution_index, cli.memory_limit.0)
            .map_err(attribution)?;
    let mut backend = Backend::new(&bundle, &index, cli.memory_limit.0)?;
    let value = if let Some(page) = page {
        progressive_page(cli, command, page, &mut backend, generation, control)?
    } else {
        match command {
            ExploreCommand::Footprint(args) => {
                feature_page(args, &mut backend, generation, control)?
            }
            ExploreCommand::CohortRetention(args) => backend.query(
                &request(
                    generation,
                    Query::CohortRetention {
                        graph: args.graph.clone(),
                        ordinals: args.ordinals.clone(),
                    },
                ),
                control,
            )?,
            ExploreCommand::Summary { .. } => {
                let catalog = backend.query(&request(generation, Query::Catalog {}), control)?;
                json!({"title":bundle.snapshot["title"],"accounting":bundle.snapshot["accounting"],
                    "ledger":bundle.snapshot["ledger"],"coverage":bundle.snapshot["coverage"],"catalog":catalog,
                    "caveats":bundle.snapshot["caveats"]})
            }
            ExploreCommand::Datasets(args) => {
                let mut catalog =
                    backend.query(&request(generation, Query::Catalog {}), control)?;
                filter_datasets(&mut catalog, args)?;
                catalog
            }
            ExploreCommand::Inspect(args) => {
                backend.query(&request(generation, inspect_query(args)?), control)?
            }
            ExploreCommand::Retention(args) => backend.query(
                &request(
                    generation,
                    Query::AnnotatedWhy {
                        graph: args.graph.clone(),
                        node_id: args.node_id.to_string(),
                    },
                ),
                control,
            )?,
            _ => {
                return Err(diagnostic(
                    "explorer.invariant",
                    "terminal command has no query",
                ));
            }
        }
    };
    let mut envelope = json!({"schema":"vitnet.explorer-cli.v1","operation":operation,
        "generation":generation,"data":value});
    if page.is_some() {
        envelope["next_command"] = value_resume(cli, command, &envelope["data"], generation)?;
    } else if let ExploreCommand::Inspect(args) = command {
        envelope["next_command"] = render::inspect_resume(cli, args, &envelope["data"], generation);
    }
    serialize(cli, &envelope, || {
        render::table(cli, command, &envelope, &bundle.snapshot)
    })
}

fn serialize(
    cli: &Cli,
    envelope: &Value,
    table: impl FnOnce() -> Result<String, AppError>,
) -> Result<String, AppError> {
    let serialized = serde_json::to_string(envelope).map_err(AppError::Json)?;
    if serialized.len() as u64 > (cli.memory_limit.0 / 16).min(RESPONSE_LIMIT as u64) {
        return Err(diagnostic(
            "resource.explorer.response",
            "terminal response exceeds budget; reduce --limit",
        ));
    }
    let output = match cli.format {
        FormatArg::Json => serde_json::to_string_pretty(envelope).map_err(AppError::Json)?,
        FormatArg::Ndjson => serialized,
        FormatArg::Table => table()?,
    };
    if output.len() as u64 > (cli.memory_limit.0 / 16).min(RESPONSE_LIMIT as u64) {
        return Err(diagnostic(
            "resource.explorer.response",
            "rendered terminal response exceeds budget; reduce --limit",
        ));
    }
    Ok(output)
}

fn argument(output: &mut String, flag: &str, value: &str) {
    let mut quoted = "'".to_owned();
    let mut expression = false;
    for character in value.chars() {
        if display::terminal_control(character) {
            write!(quoted, "' + [char]{} + '", u32::from(character)).unwrap();
            expression = true;
        } else if character == '\'' {
            quoted.push_str("''");
        } else {
            quoted.push(character);
        }
    }
    quoted.push('\'');
    if expression {
        quoted = format!("({quoted})");
    }
    if flag.is_empty() {
        write!(output, " {quoted}").unwrap();
    } else {
        write!(output, " {flag} {quoted}").unwrap();
    }
}

fn command_prefix(cli: &Cli) -> String {
    let mut output = format!("vitnet --memory-limit {}", cli.memory_limit);
    match cli.format {
        FormatArg::Table => {}
        FormatArg::Json => output.push_str(" --format json"),
        FormatArg::Ndjson => output.push_str(" --format ndjson"),
    }
    if cli.quiet {
        output.push_str(" --quiet");
    }
    match cli.progress {
        ModeArg::Auto => {}
        ModeArg::Always => output.push_str(" --progress always"),
        ModeArg::Never => output.push_str(" --progress never"),
    }
    output
}

fn selector(output: &mut String, flag: &str, value: Option<&str>) {
    if let Some(value) = value {
        argument(output, flag, value);
    }
}

fn filter_datasets(value: &mut Value, args: &DatasetArgs) -> Result<(), AppError> {
    if args.contains.len() > 1024 {
        return Err(diagnostic(
            "resource.explorer.query",
            "dataset selector exceeds 1024 bytes",
        ));
    }
    let datasets = value["datasets"]
        .as_array_mut()
        .ok_or_else(|| diagnostic("explorer.invariant", "catalog is missing datasets"))?;
    let total = datasets.len();
    datasets.retain(|dataset| {
        dataset["name"]
            .as_str()
            .is_some_and(|name| name.contains(&args.contains))
            && args
                .storage
                .is_none_or(|storage| dataset["storage"].as_str() == Some(storage.name()))
            && (!args.nonempty || dataset["records"].as_u64().is_some_and(|count| count != 0))
    });
    let returned = datasets.len();
    value["total_datasets"] = json!(total);
    value["returned_datasets"] = json!(returned);
    value["selection"] = json!({"contains":args.contains,"storage":args.storage.map(DatasetStorage::name),"nonempty":args.nonempty});
    Ok(())
}

#[allow(clippy::too_many_lines)] // Preserve every selector in the command-specific continuation.
fn value_resume(
    cli: &Cli,
    command: &ExploreCommand,
    value: &Value,
    generation: &str,
) -> Result<Value, AppError> {
    let Some(after) = cursor(&value["next_after"])? else {
        return Ok(Value::Null);
    };
    let (mut output, page) = match command {
        ExploreCommand::Lenses(args) => {
            let mut output = format!("{} explore lenses", command_prefix(cli));
            argument(&mut output, "", &args.bundle.to_string_lossy());
            argument(
                &mut output,
                "",
                args.view
                    .to_possible_value()
                    .ok_or_else(|| diagnostic("explorer.invariant", "lens view has no CLI name"))?
                    .get_name(),
            );
            argument(&mut output, "--contains", &args.contains);
            for (flag, value) in [
                ("--assembly", &args.assembly),
                ("--namespace", &args.namespace),
                ("--owner", &args.owner),
            ] {
                selector(&mut output, flag, value.as_deref());
            }
            (output, &args.page)
        }
        ExploreCommand::Contributors(args) => {
            let mut output = format!("{} explore contributors", command_prefix(cli));
            argument(&mut output, "", &args.bundle.to_string_lossy());
            argument(&mut output, "--contains", &args.contains);
            for (flag, value) in [
                ("--stream", &args.stream),
                ("--assembly", &args.assembly),
                ("--owner", &args.owner),
                ("--family", &args.family),
            ] {
                selector(&mut output, flag, value.as_deref());
            }
            if let Some(ordinal) = args.family_record {
                write!(output, " --family-record {ordinal}").unwrap();
            }
            if args.accounted_only {
                output.push_str(" --accounted-only");
            }
            if args.exact {
                output.push_str(" --exact");
            }
            for (flag, value) in [
                ("--min-bytes", args.min_bytes),
                ("--max-bytes", args.max_bytes),
            ] {
                if let Some(bytes) = value {
                    write!(output, " {flag} {bytes}").unwrap();
                }
            }
            if !args.columns.is_empty() {
                argument(
                    &mut output,
                    "--columns",
                    &args
                        .columns
                        .iter()
                        .map(|column| column.name())
                        .collect::<Vec<_>>()
                        .join(","),
                );
            }
            (output, &args.page)
        }

        ExploreCommand::Records(args) => {
            let mut output = format!("{} explore records", command_prefix(cli));
            argument(&mut output, "", &args.bundle.to_string_lossy());
            argument(&mut output, "", &args.dataset);
            argument(&mut output, "--contains", &args.contains);
            for (key, value) in &args.filters {
                argument(&mut output, "--filter", &format!("{key}={value}"));
            }
            (output, &args.page)
        }
        ExploreCommand::Origins(args) => {
            let mut output = format!("{} explore origins", command_prefix(cli));
            argument(&mut output, "", &args.bundle.to_string_lossy());
            for (flag, value) in [
                ("--assembly", &args.assembly),
                ("--package", &args.package),
                ("--target", &args.target),
            ] {
                selector(&mut output, flag, value.as_deref());
            }
            (output, &args.page)
        }
        ExploreCommand::Opportunities(args) => {
            let mut output = format!("{} explore opportunities", command_prefix(cli));
            argument(&mut output, "", &args.bundle.to_string_lossy());
            argument(&mut output, "--contains", &args.contains);
            selector(&mut output, "--kind", args.kind.as_deref());
            (output, &args.page)
        }
        ExploreCommand::Budgets(args) => {
            let mut output = format!("{} explore budgets", command_prefix(cli));
            argument(&mut output, "", &args.bundle.to_string_lossy());
            argument(&mut output, "--contains", &args.contains);
            selector(&mut output, "--dimension", args.dimension.as_deref());
            selector(&mut output, "--target", args.target.as_deref());
            (output, &args.page)
        }
        _ => return Err(diagnostic("explorer.invariant", "not a resumable page")),
    };
    write!(
        output,
        " --after {after} --limit {} --max-batches {} --timeout-ms {}",
        page.limit, page.max_batches, page.timeout_ms
    )
    .unwrap();
    argument(&mut output, "--generation", generation);
    Ok(json!(output))
}

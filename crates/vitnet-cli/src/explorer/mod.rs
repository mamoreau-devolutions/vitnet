//! Bounded, local-only evidence workspaces and offline HTML reports.

mod catalog;
mod cli;
pub mod data;
mod glossary;
mod ranking;
pub mod server;

use crate::{AppError, Cli};
use clap::Subcommand;
use std::io::Write;
use std::path::PathBuf;
use vitnet_core::Diagnostic;
use vitnet_dgml::IndexControl;

pub const SNAPSHOT_LIMIT: u64 = 8 * 1024 * 1024;
pub const RESPONSE_LIMIT: usize = 2 * 1024 * 1024;
pub const PREVIEW_BYTES: usize = 512;
pub const DISPLAY_LIMIT: usize = 100;
pub const PAGE_LIMIT: usize = 100;
pub const QUERY_TIMEOUT_MS: u64 = 1500;
pub const MAX_SCANNED: u64 = 100_000;

#[derive(Clone, Debug, Subcommand)]
pub enum ExploreCommand {
    /// Show the accounted ledger, physical evidence and overlapping projections.
    Summary { bundle: PathBuf },
    /// Page the complete byte ranking, not the bounded snapshot top list.
    Contributors(cli::ContributorArgs),
    /// List every captured dataset, including supplemental and graph inventories.
    Datasets(cli::DatasetArgs),
    /// Search or page one complete captured dataset.
    Records(cli::RecordArgs),
    /// Follow recorded assembly/package origins (not retention or removable bytes).
    Origins(cli::OriginArgs),
    /// Navigate a captured record, source candidates or parsed producer shape.
    Inspect(cli::InspectArgs),
    /// Explain one contributor with connected recorded evidence and next commands.
    Explain(cli::ExplainArgs),
    /// Compare compact ledgers from two captured builds, not identity savings.
    Compare { before: PathBuf, after: PathBuf },
    /// Distinguish captured evidence coverage from bounded snapshot previews.
    Coverage { bundle: PathBuf },
    /// Browse the pinned compiler glossary without opening a bundle.
    Glossary(cli::GlossaryArgs),
    /// Suggest concrete investigations based only on captured build facts.
    Guide { bundle: PathBuf },
    /// Rank evidence-backed opportunities, not predicted removable bytes.
    Opportunities(cli::OpportunityArgs),
    /// Inspect reconciled assembly/package budgets with explicit attribution tiers.
    Budgets(cli::BudgetArgs),
    /// Browse connected owner, XAML, serializer, generic, reflection and metadata lenses.
    Lenses(cli::LensArgs),
    /// Reconcile a feature's owner ledger with explicit batch bounds and uncertainty.
    Footprint(cli::FeatureArgs),
    /// Group bounded retention witnesses for one to three representative identities.
    CohortRetention(cli::CohortArgs),
    /// Annotate a selected compiler node's bounded root witnesses with source evidence.
    Retention(cli::RetentionArgs),
    /// Stream complete evidence once into an immutable, bounded browsing bundle.
    Prepare {
        index: PathBuf,
        #[arg(long)]
        bundle: PathBuf,
        /// Supplemental local inventory; never treated as compiler retention proof.
        #[arg(long)]
        evidence: Vec<PathBuf>,
        #[arg(long)]
        before: Option<PathBuf>,
        /// Optional local feature/pattern policy; never executable code.
        #[arg(long)]
        opportunity_policy: Option<PathBuf>,
        /// Include at most three selected offline retention witnesses.
        #[arg(long, value_delimiter = ',')]
        node: Vec<u64>,
        #[arg(long, value_parser = ["scan_index", "codegen_index"], default_value = "scan_index")]
        graph: String,
    },
    /// Export a portable, self-contained HTML snapshot (not the full graph).
    Export {
        bundle: PathBuf,
        #[arg(long)]
        html: PathBuf,
        /// Remove source paths, diagnostic details and provenance values from export.
        #[arg(long)]
        redact_paths: bool,
    },
    /// Serve read-only, authenticated browsing on IPv4 loopback until stopped.
    Browse {
        bundle: PathBuf,
        #[arg(long, default_value_t = 0)]
        port: u16,
        #[arg(long)]
        open: bool,
    },
    /// Verify bundle sidecars, snapshot and original identity/index fingerprints.
    Verify { bundle: PathBuf },
}

pub(super) fn diagnostic(code: &str, message: impl Into<String>) -> AppError {
    let diagnostic = Box::new(Diagnostic::malformed(code, message));
    if code.starts_with("resource.") {
        AppError::Resource(diagnostic)
    } else if code.starts_with("io.") {
        AppError::IoDiagnostic(diagnostic)
    } else {
        AppError::Unsupported(diagnostic)
    }
}

pub(super) fn attribution(error: vitnet_attribution::AttributionError) -> AppError {
    diagnostic(&error.diagnostic.code, error.diagnostic.message)
}

pub(super) fn io(error: impl std::fmt::Display) -> AppError {
    diagnostic("io.explorer", error.to_string())
}

pub(super) fn preview(value: &str, limit: usize) -> (String, bool) {
    let mut end = value.len().min(limit);
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    (value[..end].to_owned(), end != value.len())
}

pub(super) fn asset(path: &str) -> Option<(&'static str, &'static str)> {
    match path {
        "/style.css" => Some(("text/css; charset=utf-8", include_str!("assets/style.css"))),
        "/app.js" => Some((
            "text/javascript; charset=utf-8",
            include_str!("assets/app.js"),
        )),
        "/layout.js" => Some((
            "text/javascript; charset=utf-8",
            include_str!("assets/layout.js"),
        )),
        _ => None,
    }
}

pub(super) fn html(snapshot: &serde_json::Value, offline: bool) -> Result<String, AppError> {
    let data = serde_json::to_string(snapshot)
        .map_err(AppError::Json)?
        .replace('<', "\\u003c")
        .replace('>', "\\u003e")
        .replace('&', "\\u0026")
        .replace('\u{2028}', "\\u2028")
        .replace('\u{2029}', "\\u2029");
    let rendered = include_str!("assets/index.html")
        .replace("<!--VITNET_STYLE-->", include_str!("assets/style.css"))
        .replace(
            "/*VITNET_OFFLINE*/false",
            if offline { "true" } else { "false" },
        )
        .replace(
            "/*VITNET_WORKER*/null",
            &serde_json::to_string(include_str!("assets/layout.js")).map_err(AppError::Json)?,
        )
        .replace("/*VITNET_FORMAT*/", include_str!("assets/format.js"))
        .replace(
            "/*VITNET_INVESTIGATION*/",
            &include_str!("assets/investigation.js")
                .replace("/*VITNET_BUCKETS*/{}", include_str!("assets/buckets.json")),
        )
        .replace("/*VITNET_APP*/", include_str!("assets/app.js"))
        .replacen("/*VITNET_DATA*/null", &data, 1);
    Ok(if offline {
        rendered.replace("<head>", "<head><meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; worker-src blob:; img-src data:; connect-src 'none'; base-uri 'none'; form-action 'none'\">")
    } else {
        rendered
    })
}

fn redact(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::Object(values) => {
            for (key, value) in values {
                if key == "provenance" || key == "provenance_changes" {
                    *value = serde_json::json!({"redacted": "Exported provenance values omitted"});
                } else if key == "path"
                    || key.ends_with("_path")
                    || key.ends_with("_paths")
                    || key == "generated_files"
                    || key == "message"
                {
                    *value = serde_json::Value::String("<redacted>".into());
                } else {
                    redact(value);
                }
            }
        }
        serde_json::Value::Array(values) => values.iter_mut().for_each(redact),
        _ => {}
    }
}

/// Executes the explorer commands without altering source indexes.
///
/// # Errors
///
/// Returns explicit I/O, integrity, schema and resource diagnostics.
pub fn execute(
    cli: &Cli,
    command: &ExploreCommand,
    control: &IndexControl,
) -> Result<String, AppError> {
    match command {
        ExploreCommand::Prepare {
            index,
            bundle,
            evidence,
            before,
            opportunity_policy,
            node,
            graph,
        } => {
            let manifest = data::prepare_with_policy(
                index,
                bundle,
                evidence,
                before.as_deref(),
                node,
                graph,
                cli.memory_limit.0,
                control,
                opportunity_policy.as_deref(),
            )?;
            serde_json::to_string_pretty(&manifest).map_err(AppError::Json)
        }
        ExploreCommand::Export {
            bundle,
            html: path,
            redact_paths,
        } => {
            let opened = data::Bundle::open(bundle, cli.memory_limit.0)?;
            let mut snapshot = opened.snapshot;
            if *redact_paths {
                redact(&mut snapshot);
            }
            let rendered = html(&snapshot, true)?;
            let parent = path
                .parent()
                .filter(|path| !path.as_os_str().is_empty())
                .unwrap_or_else(|| std::path::Path::new("."));
            let mut output = tempfile::NamedTempFile::new_in(parent).map_err(io)?;
            output.write_all(rendered.as_bytes()).map_err(io)?;
            output.as_file().sync_all().map_err(io)?;
            output.persist_noclobber(path).map_err(io)?;
            Ok(format!(
                "Exported bounded offline report: {}",
                path.display()
            ))
        }
        ExploreCommand::Browse { bundle, port, open } => {
            if cli.output.is_some() {
                return Err(diagnostic(
                    "explorer.output",
                    "--output is not supported for a foreground browser server",
                ));
            }
            server::serve(bundle, cli.memory_limit.0, *port, *open, control)?;
            Ok("Explorer stopped; sessions released.".into())
        }
        ExploreCommand::Verify { bundle } => {
            data::verify(bundle, cli.memory_limit.0)?;
            Ok("Explorer bundle and original identity cache verified.".into())
        }
        _ => cli::execute(cli, command, control),
    }
}

use super::{PAGE_LIMIT, RESPONSE_LIMIT, attribution, data, diagnostic, io};
use crate::AppError;
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::Path;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant, SystemTime};
use vitnet_attribution::{AttributionIndex, Matcher};
use vitnet_dgml::{GraphSession, IncomingOptions, IndexControl, SearchMode, SearchOptions};

const REQUEST_LIMIT: usize = 16 * 1024;
const HEADER_LIMIT: usize = 8 * 1024;
const CONNECTION_LIMIT: usize = 4;

#[cfg(test)]
#[path = "server_tests.rs"]
mod tests;

#[derive(Debug, Deserialize)]
struct QueryRequest {
    request_id: String,
    generation: String,
    #[serde(flatten)]
    query: Query,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
enum Query {
    Rows {
        #[serde(default)]
        contains: String,
        stream: Option<String>,
        assembly: Option<String>,
        owner: Option<String>,
        after: Option<u64>,
        #[serde(default = "default_page")]
        limit: usize,
    },
    Source {
        ordinal: u64,
    },
    GraphSearch {
        graph: String,
        query: String,
        mode: SearchMode,
        after_id: Option<String>,
    },
    Incoming {
        graph: String,
        node_id: String,
        after_edge: Option<String>,
    },
    Why {
        graph: String,
        node_id: String,
    },
}

fn default_page() -> usize {
    50
}

fn number(value: &str) -> Result<u64, AppError> {
    value.parse().map_err(|_| {
        diagnostic(
            "explorer.cursor",
            "node and edge cursors must be unsigned decimal strings",
        )
    })
}

struct Backend<'a> {
    bundle: &'a data::Bundle,
    index: &'a AttributionIndex,
    matcher: Matcher<'a>,
    identities: File,
    offsets: File,
    identity_modified: SystemTime,
    index_modified: SystemTime,
    memory: u64,
    graphs: BTreeMap<String, GraphSession>,
}

impl<'a> Backend<'a> {
    fn new(
        bundle: &'a data::Bundle,
        index: &'a AttributionIndex,
        memory: u64,
    ) -> Result<Self, AppError> {
        let (identities, offsets) = data::open_readers(bundle)?;
        Ok(Self {
            bundle,
            index,
            matcher: Matcher::new(&index.evidence),
            identities,
            offsets,
            identity_modified: fs::metadata(
                bundle.manifest.attribution_index.join("identities.ndjson"),
            )
            .map_err(io)?
            .modified()
            .map_err(io)?,
            index_modified: fs::metadata(bundle.manifest.attribution_index.join("index.json"))
                .map_err(io)?
                .modified()
                .map_err(io)?,
            memory,
            graphs: BTreeMap::new(),
        })
    }

    fn check_source(&self) -> Result<(), AppError> {
        let identity = fs::metadata(
            self.bundle
                .manifest
                .attribution_index
                .join("identities.ndjson"),
        )
        .map_err(io)?;
        let index =
            fs::metadata(self.bundle.manifest.attribution_index.join("index.json")).map_err(io)?;
        if identity.len() != self.bundle.manifest.identity_file_bytes
            || identity.modified().map_err(io)? != self.identity_modified
            || index.modified().map_err(io)? != self.index_modified
        {
            return Err(diagnostic(
                "explorer.source.stale",
                "input changed during browsing; prepare a new immutable bundle",
            ));
        }
        Ok(())
    }

    fn row(&mut self, ordinal: u64) -> Result<vitnet_mstat::CoalescedIdentity, AppError> {
        data::read_identity(
            &mut self.identities,
            &mut self.offsets,
            ordinal,
            self.bundle.manifest.identities,
            self.bundle.manifest.identity_file_bytes,
            self.memory,
        )
    }

    fn graph(&mut self, kind: &str, control: &IndexControl) -> Result<&mut GraphSession, AppError> {
        if !matches!(kind, "scan_index" | "codegen_index") {
            return Err(diagnostic(
                "explorer.graph.kind",
                "choose scan_index or codegen_index",
            ));
        }
        if !self.graphs.contains_key(kind) {
            let artifacts: Vec<_> = self
                .index
                .artifacts
                .iter()
                .filter(|artifact| artifact.available && artifact.kind == kind)
                .collect();
            if artifacts.len() != 1 {
                return Err(diagnostic(
                    "explorer.graph.missing",
                    "exactly one imported graph of this kind is required",
                ));
            }
            let artifact = artifacts[0];
            let graph =
                GraphSession::open(&artifact.path, self.memory / 4).map_err(AppError::Dgml)?;
            if artifact.graph_generation.as_deref() != Some(&graph.generation) {
                return Err(diagnostic(
                    "explorer.graph.stale",
                    "graph generation differs from imported build evidence",
                ));
            }
            self.graphs.insert(kind.into(), graph);
        }
        let graph = self
            .graphs
            .get_mut(kind)
            .ok_or_else(|| diagnostic("explorer.invariant", "graph session was not inserted"))?;
        graph.set_control(control.clone());
        Ok(graph)
    }

    #[allow(clippy::too_many_lines)]
    fn query(&mut self, request: &QueryRequest, control: &IndexControl) -> Result<Value, AppError> {
        self.check_source()?;
        if request.generation != self.bundle.manifest.generation {
            return Err(diagnostic(
                "explorer.generation",
                "bundle generation differs; reload the workspace",
            ));
        }
        let mut value = match &request.query {
            Query::Rows {
                contains,
                stream,
                assembly,
                owner,
                after,
                limit,
            } => {
                if *limit == 0
                    || *limit > PAGE_LIMIT
                    || contains.len() > 1024
                    || stream.as_ref().is_some_and(|stream| stream.len() > 64)
                    || assembly.as_ref().is_some_and(|value| value.len() > 4096)
                    || owner.as_ref().is_some_and(|value| value.len() > 4096)
                {
                    return Err(diagnostic(
                        "resource.explorer.query",
                        "row page or search term exceeds browser budgets",
                    ));
                }
                let started = Instant::now();
                let start = after.map_or(Some(0), |ordinal| ordinal.checked_add(1));
                if after.is_some_and(|ordinal| ordinal >= self.bundle.manifest.identities) {
                    return Err(diagnostic(
                        "explorer.cursor",
                        "row cursor is outside this bundle",
                    ));
                }
                let mut entries = Vec::new();
                let mut next = *after;
                let mut scanned = 0;
                let mut stop = "complete";
                for ordinal in start
                    .into_iter()
                    .flat_map(|start| start..self.bundle.manifest.identities)
                {
                    if control.is_cancelled() {
                        stop = "cancelled";
                        break;
                    }
                    if scanned >= super::MAX_SCANNED {
                        stop = "max_scanned";
                        break;
                    }
                    if started.elapsed() >= Duration::from_millis(super::QUERY_TIMEOUT_MS) {
                        stop = "timeout";
                        break;
                    }
                    let entry = self.row(ordinal)?;
                    scanned += 1;
                    next = Some(ordinal);
                    let owner_match = owner.as_ref().is_none_or(|filter| {
                        let prefix = entry
                            .identity
                            .split_once("__")
                            .map_or(entry.identity.as_str(), |(prefix, _)| prefix);
                        prefix.split_once('<').map_or(prefix, |(family, _)| family) == filter
                    });
                    if stream.as_ref().is_none_or(|stream| entry.stream == *stream)
                        && entry.identity.contains(contains)
                        && owner_match
                        && assembly.as_ref().is_none_or(|filter| {
                            if entry.identity_lossy {
                                return filter == "_unmapped";
                            }
                            let located = self.matcher.locate(&entry.stream, &entry.identity);
                            if located.assemblies.len() == 1 {
                                located.assemblies[0] == *filter
                            } else if located.assemblies.is_empty() {
                                filter == "_unmapped"
                            } else {
                                filter == "_ambiguous"
                            }
                        })
                    {
                        entries.push(data::Row::new(&entry, ordinal));
                        if entries.len() == *limit {
                            if ordinal + 1 != self.bundle.manifest.identities {
                                stop = "limit";
                            }
                            break;
                        }
                    }
                }
                if stop == "complete" {
                    next = None;
                }
                json!({"generation":request.generation,"entries":entries,"next_after":next,"scanned":scanned,
                    "stop_reason":stop,"elapsed_ms":elapsed(started),"order":"cache_ordinal"})
            }
            Query::Source { ordinal } => {
                if control.is_cancelled() {
                    return Err(diagnostic("resource.cancelled", "source query cancelled"));
                }
                let entry = self.row(*ordinal)?;
                data::details(&self.matcher, &entry, *ordinal)
            }
            Query::GraphSearch {
                graph,
                query,
                mode,
                after_id,
            } => {
                if query.is_empty() || query.len() > 1024 {
                    return Err(diagnostic(
                        "explorer.search",
                        "graph search needs 1..=1024 bytes",
                    ));
                }
                let session = self.graph(graph, control)?;
                let options = SearchOptions {
                    mode: *mode,
                    limit: 50,
                    after_id: after_id.as_deref().map(number).transpose()?,
                    max_scanned: super::MAX_SCANNED,
                    timeout_ms: super::QUERY_TIMEOUT_MS,
                    preview_bytes: 256,
                    generation: Some(session.generation.clone()),
                    ..SearchOptions::default()
                };
                serde_json::to_value(session.search(query, &options).map_err(AppError::Dgml)?)
                    .map_err(AppError::Json)?
            }
            Query::Incoming {
                graph,
                node_id,
                after_edge,
            } => {
                let session = self.graph(graph, control)?;
                let options = IncomingOptions {
                    limit: 50,
                    after_edge: after_edge.as_deref().map(number).transpose()?,
                    timeout_ms: super::QUERY_TIMEOUT_MS,
                    preview_bytes: 256,
                    generation: Some(session.generation.clone()),
                };
                serde_json::to_value(
                    session
                        .incoming(number(node_id)?, &options)
                        .map_err(AppError::Dgml)?,
                )
                .map_err(AppError::Json)?
            }
            Query::Why { graph, node_id } => {
                let session = self.graph(graph, control)?;
                let options = data::why_options(&session.generation);
                serde_json::to_value(
                    session
                        .why(number(node_id)?, &options)
                        .map_err(AppError::Dgml)?,
                )
                .map_err(AppError::Json)?
            }
        };
        stringify_ids(&mut value);
        Ok(value)
    }
}

fn elapsed(start: Instant) -> u64 {
    u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX)
}

fn stringify_ids(value: &mut Value) {
    match value {
        Value::Object(values) => {
            for (key, value) in values {
                if matches!(
                    key.as_str(),
                    "node_id" | "source_id" | "target_id" | "next_after_id" | "next_after_edge"
                ) && value.is_number()
                {
                    *value = Value::String(value.to_string());
                } else {
                    stringify_ids(value);
                }
            }
        }
        Value::Array(values) => values.iter_mut().for_each(stringify_ids),
        _ => {}
    }
}

struct Request {
    method: String,
    path: String,
    body: Vec<u8>,
}

#[allow(clippy::too_many_lines)] // Validate framing and authority together before admitting a body.
fn parse_request(
    stream: &mut TcpStream,
    address: SocketAddr,
    token: &str,
) -> Result<Request, AppError> {
    let mut bytes = Vec::new();
    let (method, path, length, header_bytes) = loop {
        if bytes.len() >= HEADER_LIMIT {
            return Err(diagnostic(
                "resource.explorer.headers",
                "HTTP headers exceed 8 KiB",
            ));
        }
        let mut buffer = [0; 1024];
        let count = stream.read(&mut buffer).map_err(io)?;
        if count == 0 {
            return Err(diagnostic("explorer.http", "incomplete HTTP request"));
        }
        bytes.extend_from_slice(&buffer[..count]);
        let mut headers = [httparse::EMPTY_HEADER; 32];
        let mut parsed = httparse::Request::new(&mut headers);
        let status = parsed
            .parse(&bytes)
            .map_err(|error| diagnostic("explorer.http", error.to_string()))?;
        let httparse::Status::Complete(header_bytes) = status else {
            continue;
        };
        if header_bytes > HEADER_LIMIT || parsed.version != Some(1) {
            return Err(diagnostic(
                "explorer.http",
                "HTTP/1.1 and bounded headers are required",
            ));
        }
        let values = |name: &str| {
            parsed
                .headers
                .iter()
                .filter(|header| header.name.eq_ignore_ascii_case(name))
                .map(|header| header.value)
                .collect::<Vec<_>>()
        };
        let host = values("host");
        let expected_host = address.to_string();
        if host.len() != 1 || host[0] != expected_host.as_bytes() {
            return Err(diagnostic(
                "explorer.host",
                "Host must match the exact loopback endpoint",
            ));
        }
        let origin = values("origin");
        let expected_origin = format!("http://{address}");
        if origin.len() > 1
            || origin
                .first()
                .is_some_and(|value| *value != expected_origin.as_bytes())
        {
            return Err(diagnostic(
                "explorer.origin",
                "cross-origin requests are rejected",
            ));
        }
        if !values("transfer-encoding").is_empty() {
            return Err(diagnostic(
                "explorer.http",
                "chunked request bodies are not supported",
            ));
        }
        let lengths = values("content-length");
        if lengths.len() > 1 {
            return Err(diagnostic(
                "explorer.http",
                "duplicate Content-Length is rejected",
            ));
        }
        let length = lengths.first().map_or(Ok(0), |value| {
            std::str::from_utf8(value)
                .map_err(|_| diagnostic("explorer.http", "Content-Length must be decimal ASCII"))?
                .parse::<usize>()
                .map_err(|_| diagnostic("explorer.http", "invalid Content-Length"))
        })?;
        if length > REQUEST_LIMIT {
            return Err(diagnostic(
                "resource.explorer.request",
                "request body exceeds 16 KiB",
            ));
        }
        let method = parsed
            .method
            .ok_or_else(|| diagnostic("explorer.http", "missing method"))?
            .to_owned();
        let path = parsed
            .path
            .ok_or_else(|| diagnostic("explorer.http", "missing target"))?
            .to_owned();
        if path.starts_with("/api/") {
            let auth = values("authorization");
            let expected = format!("Bearer {token}");
            if auth.len() != 1 || !constant_time_eq(auth[0], expected.as_bytes()) {
                return Err(diagnostic(
                    "explorer.authorization",
                    "valid session capability required",
                ));
            }
            let content_type = values("content-type");
            if content_type.len() != 1 || content_type[0] != b"application/json" {
                return Err(diagnostic(
                    "explorer.content_type",
                    "API bodies must be application/json",
                ));
            }
        }
        break (method, path, length, header_bytes);
    };
    while bytes.len() < header_bytes + length {
        let mut buffer = [0; 1024];
        let remaining = (header_bytes + length - bytes.len()).min(buffer.len());
        let count = stream.read(&mut buffer[..remaining]).map_err(io)?;
        if count == 0 {
            return Err(diagnostic("explorer.http", "truncated request body"));
        }
        bytes.extend_from_slice(&buffer[..count]);
    }
    if bytes.len() != header_bytes + length {
        return Err(diagnostic(
            "explorer.http",
            "pipelined or trailing request bytes are rejected",
        ));
    }
    Ok(Request {
        method,
        path,
        body: bytes[header_bytes..].to_vec(),
    })
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }

    left.iter()
        .zip(right)
        .fold(0_u8, |difference, (left, right)| {
            difference | (left ^ right)
        })
        == 0
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8] = b"0123456789abcdef";
    bytes
        .iter()
        .flat_map(|byte| {
            [
                char::from(DIGITS[usize::from(byte >> 4)]),
                char::from(DIGITS[usize::from(byte & 15)]),
            ]
        })
        .collect()
}

fn response(
    stream: &mut TcpStream,
    status: u16,
    content_type: &str,
    body: &[u8],
    nonce: &str,
) -> Result<(), AppError> {
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        409 => "Conflict",
        413 => "Content Too Large",
        429 => "Too Many Requests",
        _ => "Internal Server Error",
    };
    let header = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nReferrer-Policy: no-referrer\r\nContent-Security-Policy: default-src 'none'; script-src 'nonce-{nonce}'; style-src 'nonce-{nonce}'; connect-src 'self'; worker-src blob:; img-src data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'\r\n\r\n",
        body.len()
    );
    stream.write_all(header.as_bytes()).map_err(io)?;
    stream.write_all(body).map_err(io)
}

fn error_parts(error: &AppError) -> (&str, String) {
    match error {
        AppError::Unsupported(value)
        | AppError::IoDiagnostic(value)
        | AppError::Resource(value) => (&value.code, value.message.clone()),
        AppError::Dgml(value) => (&value.diagnostic.code, value.diagnostic.message.clone()),
        AppError::Mstat(value) => (&value.diagnostic.code, value.diagnostic.message.clone()),
        AppError::Metadata(value) => (&value.diagnostic.code, value.diagnostic.message.clone()),
        _ => ("io.explorer", error.to_string()),
    }
}

fn error_response(stream: &mut TcpStream, error: &AppError, nonce: &str) -> Result<(), AppError> {
    let (code, message) = error_parts(error);
    let status = if matches!(
        code,
        "explorer.authorization" | "explorer.origin" | "explorer.host"
    ) {
        403
    } else if code == "explorer.busy" {
        429
    } else if code.contains("stale") || code.contains("generation") || code == "explorer.request_id"
    {
        409
    } else if code.starts_with("resource.") {
        413
    } else if code.starts_with("io.") {
        500
    } else {
        400
    };
    let bytes = serde_json::to_vec(&json!({"error":{"code":code,"message":message}}))
        .map_err(AppError::Json)?;
    response(stream, status, "application/json", &bytes, nonce)
}

type Active = Mutex<BTreeMap<String, IndexControl>>;

struct ActiveRequest<'a> {
    active: &'a Active,
    id: String,
}
impl Drop for ActiveRequest<'_> {
    fn drop(&mut self) {
        if let Ok(mut active) = self.active.lock() {
            active.remove(&self.id);
        } else {
            eprintln!("explorer.lock: cancellation registry poisoned during cleanup");
        }
    }
}

fn valid_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Cancel {
    request_id: String,
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn handle(
    stream: &mut TcpStream,
    address: SocketAddr,
    token: &str,
    nonce: &str,
    page: &str,
    snapshot: &[u8],
    backend: &Mutex<Backend<'_>>,
    active: &Active,
    shutdown: &IndexControl,
) -> Result<(), AppError> {
    let request = parse_request(stream, address, token)?;
    if request.method == "GET" {
        if !request.body.is_empty() {
            return Err(diagnostic("explorer.http", "GET bodies are not accepted"));
        }
        if request.path == "/" {
            return response(
                stream,
                200,
                "text/html; charset=utf-8",
                page.as_bytes(),
                nonce,
            );
        }
        if let Some((content_type, body)) = super::asset(&request.path) {
            return response(stream, 200, content_type, body.as_bytes(), nonce);
        }
        return response(stream, 404, "text/plain", b"Not found", nonce);
    }
    if request.method != "POST" || !request.path.starts_with("/api/") {
        return response(stream, 405, "text/plain", b"Method not allowed", nonce);
    }
    match request.path.as_str() {
        "/api/snapshot" => {
            let value: Value = serde_json::from_slice(&request.body)
                .map_err(|error| diagnostic("explorer.request.json", error.to_string()))?;
            if value != json!({}) {
                return Err(diagnostic(
                    "explorer.request",
                    "snapshot body must be an empty object",
                ));
            }
            response(stream, 200, "application/json", snapshot, nonce)
        }
        "/api/shutdown" => {
            let value: Value = serde_json::from_slice(&request.body)
                .map_err(|error| diagnostic("explorer.request.json", error.to_string()))?;
            if value != json!({}) {
                return Err(diagnostic(
                    "explorer.request",
                    "shutdown body must be an empty object",
                ));
            }
            shutdown.cancel();
            for control in active.lock().map_err(io)?.values() {
                control.cancel();
            }
            response(
                stream,
                200,
                "application/json",
                br#"{"stopped":true}"#,
                nonce,
            )
        }
        "/api/cancel" => {
            let cancel: Cancel = serde_json::from_slice(&request.body)
                .map_err(|error| diagnostic("explorer.request.json", error.to_string()))?;
            if !valid_id(&cancel.request_id) {
                return Err(diagnostic("explorer.request_id", "invalid request ID"));
            }
            let active = active.lock().map_err(io)?;
            let found = active.get(&cancel.request_id);
            if let Some(control) = found {
                control.cancel();
            }
            let bytes = serde_json::to_vec(&json!({"cancelled":found.is_some()}))
                .map_err(AppError::Json)?;
            response(stream, 200, "application/json", &bytes, nonce)
        }
        "/api/query" => {
            let query: QueryRequest = serde_json::from_slice(&request.body)
                .map_err(|error| diagnostic("explorer.request.json", error.to_string()))?;
            if !valid_id(&query.request_id) {
                return Err(diagnostic("explorer.request_id", "invalid request ID"));
            }
            let control = IndexControl::default();
            {
                let mut active = active.lock().map_err(io)?;
                if active.contains_key(&query.request_id) {
                    return Err(diagnostic(
                        "explorer.request_id",
                        "request ID is already active",
                    ));
                }
                active.insert(query.request_id.clone(), control.clone());
            }
            let _guard = ActiveRequest {
                active,
                id: query.request_id.clone(),
            };
            let mut backend = backend.try_lock().map_err(|_| {
                diagnostic(
                    "explorer.busy",
                    "one expensive query is already active; cancel it or retry",
                )
            })?;
            let value = backend.query(&query, &control)?;
            let bytes = serde_json::to_vec(&value).map_err(AppError::Json)?;
            if bytes.len() > RESPONSE_LIMIT {
                return Err(diagnostic(
                    "resource.explorer.response",
                    "query response exceeds 2 MiB",
                ));
            }
            response(stream, 200, "application/json", &bytes, nonce)
        }
        _ => response(stream, 404, "text/plain", b"Not found", nonce),
    }
}

fn open_browser(url: &str) -> Result<(), AppError> {
    #[cfg(windows)]
    let status = std::process::Command::new("rundll32.exe")
        .args(["url.dll,FileProtocolHandler", url])
        .status()
        .map_err(io)?;
    #[cfg(target_os = "macos")]
    let status = std::process::Command::new("open")
        .arg(url)
        .status()
        .map_err(io)?;
    #[cfg(all(unix, not(target_os = "macos")))]
    let status = std::process::Command::new("xdg-open")
        .arg(url)
        .status()
        .map_err(io)?;
    #[cfg(not(any(windows, unix)))]
    return Err(diagnostic(
        "explorer.open.unsupported",
        "automatic browser opening is unavailable; open the printed loopback URL",
    ));
    #[cfg(any(windows, unix))]
    if !status.success() {
        return Err(diagnostic(
            "io.explorer.open",
            "browser launcher failed; rerun without --open",
        ));
    }
    Ok(())
}

/// Serves bounded read-only evidence on a local ephemeral TCP listener.
///
/// # Errors
///
/// Returns explicit startup, cache, binding, random-source and I/O diagnostics.
#[allow(clippy::too_many_lines)]
pub fn serve(
    directory: &Path,
    memory: u64,
    port: u16,
    open: bool,
    control: &IndexControl,
) -> Result<(), AppError> {
    let bundle = data::Bundle::open(directory, memory)?;
    let index = vitnet_attribution::open_index(&bundle.manifest.attribution_index, memory)
        .map_err(attribution)?;
    if index.identities != bundle.manifest.identities
        || index.identities_blake3 != bundle.manifest.identities_blake3
    {
        return Err(diagnostic(
            "explorer.source.stale",
            "original identity manifest differs from bundle",
        ));
    }
    let backend = Mutex::new(Backend::new(&bundle, &index, memory)?);
    let listener = TcpListener::bind(("127.0.0.1", port)).map_err(io)?;
    listener.set_nonblocking(true).map_err(io)?;
    let address = listener.local_addr().map_err(io)?;
    let mut entropy = [0; 32];
    getrandom::fill(&mut entropy).map_err(io)?;
    let token = hex(&entropy);
    getrandom::fill(&mut entropy).map_err(io)?;
    let nonce = hex(&entropy);
    let snapshot = serde_json::to_vec(&bundle.snapshot).map_err(AppError::Json)?;
    if snapshot.len() > RESPONSE_LIMIT {
        return Err(diagnostic(
            "resource.explorer.snapshot",
            "live bootstrap exceeds 2 MiB; use the offline export or a smaller projection",
        ));
    }
    let page = super::html(
        &json!({
            "schema":"vitnet.explorer-snapshot.v1","bootstrap":true,
            "limits":{"graph_nodes":200,"graph_edges":500,"page_rows":100}
        }),
        false,
    )?
    .replace("<script", &format!("<script nonce=\"{nonce}\""))
    .replace("<style", &format!("<style nonce=\"{nonce}\""));
    let url = format!("http://{address}/#token={token}");
    println!("Explorer: {url}");
    println!(
        "Local only; Ctrl+C or Stop server releases readers. Browser graph cap: 200 nodes / 500 edges."
    );
    std::io::stdout().flush().map_err(io)?;
    if open {
        open_browser(&url)?;
    }
    let active = Active::default();
    let connections = AtomicUsize::new(0);
    std::thread::scope(|scope| -> Result<(), AppError> {
        let mut handles = Vec::new();
        while !control.is_cancelled() {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    stream.set_nonblocking(false).map_err(io)?;
                    stream
                        .set_read_timeout(Some(Duration::from_secs(5)))
                        .map_err(io)?;
                    stream
                        .set_write_timeout(Some(Duration::from_secs(5)))
                        .map_err(io)?;
                    if connections.load(Ordering::Acquire) >= CONNECTION_LIMIT {
                        response(
                            &mut stream,
                            429,
                            "text/plain",
                            b"Connection budget exhausted",
                            &nonce,
                        )?;
                        continue;
                    }
                    connections.fetch_add(1, Ordering::AcqRel);
                    let (token, nonce, page, snapshot, backend, active, connections) = (
                        &token,
                        &nonce,
                        &page,
                        &snapshot,
                        &backend,
                        &active,
                        &connections,
                    );
                    handles.push(scope.spawn(move || {
                        if let Err(error) = handle(
                            &mut stream,
                            address,
                            token,
                            nonce,
                            page,
                            snapshot,
                            backend,
                            active,
                            control,
                        ) {
                            if let Err(write_error) = error_response(&mut stream, &error, nonce) {
                                eprintln!(
                                    "io.explorer.response: {write_error}; original error: {error}"
                                );
                            }
                        }
                        connections.fetch_sub(1, Ordering::AcqRel);
                    }));
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(error) => return Err(io(error)),
            }
            let mut position = 0;
            while position < handles.len() {
                if handles[position].is_finished() {
                    handles
                        .swap_remove(position)
                        .join()
                        .map_err(|_| diagnostic("explorer.worker", "HTTP worker panicked"))?;
                } else {
                    position += 1;
                }
            }
        }
        for request in active.lock().map_err(io)?.values() {
            request.cancel();
        }
        for handle in handles {
            handle
                .join()
                .map_err(|_| diagnostic("explorer.worker", "HTTP worker panicked"))?;
        }
        Ok(())
    })
}

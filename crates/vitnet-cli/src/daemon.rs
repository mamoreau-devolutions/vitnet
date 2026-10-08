//! Local, bounded HTTP queries over Windows named pipes.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use vitnet_core::Diagnostic;

pub const RESPONSE_SCHEMA: &str = "vitnet.daemon-response.v1";

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum Request {
    Health,
    Shutdown,
    Search {
        index: PathBuf,
        query: String,
        options: vitnet_dgml::SearchOptions,
    },
    Why {
        index: PathBuf,
        node_id: u64,
        options: vitnet_dgml::WhyOptions,
    },
    Incoming {
        index: PathBuf,
        node_id: u64,
        options: vitnet_dgml::IncomingOptions,
    },
    Batch {
        index: PathBuf,
        ids: Vec<u64>,
        options: vitnet_dgml::WhyOptions,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Response {
    pub schema: String,
    pub ok: bool,
    pub data: Option<serde_json::Value>,
    pub error: Option<Diagnostic>,
    pub session_reused: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DaemonError {
    pub diagnostic: Box<Diagnostic>,
}

impl std::fmt::Display for DaemonError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.diagnostic.fmt(formatter)
    }
}

impl std::error::Error for DaemonError {}

fn error(code: &str, message: impl Into<String>) -> DaemonError {
    DaemonError {
        diagnostic: Box::new(Diagnostic::malformed(code, message)),
    }
}

/// Serves local requests until an acknowledged shutdown, then releases all sessions.
///
/// # Errors
///
/// Returns typed pipe, runtime, worker, or unsupported-platform diagnostics.
pub fn serve(pipe: &str, memory_limit: u64) -> Result<(), DaemonError> {
    #[cfg(windows)]
    {
        windows::serve(pipe, memory_limit)
    }
    #[cfg(not(windows))]
    {
        let _ = (pipe, memory_limit);
        Err(error(
            "daemon.unsupported",
            "the query daemon requires Windows named pipes",
        ))
    }
}

/// Makes one bounded HTTP request without starting a daemon.
///
/// Query failures are returned as `Response { ok: false, error: Some(..) }`;
/// transport/protocol failures return `Err`, preserving their pipe-specific cause.
///
/// # Errors
///
/// Returns typed transport, protocol, limit, or unsupported-platform diagnostics.
pub fn call(pipe: &str, request: &Request) -> Result<Response, DaemonError> {
    #[cfg(windows)]
    {
        windows::call(pipe, request)
    }
    #[cfg(not(windows))]
    {
        let _ = (pipe, request);
        Err(error(
            "daemon.unsupported",
            "the query daemon requires Windows named pipes",
        ))
    }
}

#[cfg(windows)]
mod windows {
    use super::{DaemonError, RESPONSE_SCHEMA, Request, Response, error};
    use bytes::Bytes;
    use http_body_util::{BodyExt, Full};
    use hyper::body::{Body, Incoming};
    use hyper::http::{Method, StatusCode, header};
    use hyper::service::service_fn;
    use hyper_util::rt::{TokioIo, TokioTimer};
    use serde::Serialize;
    use std::collections::VecDeque;
    use std::convert::Infallible;
    use std::io::{self, Write};
    use std::path::{Path, PathBuf};
    use std::pin::Pin;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::mpsc::{SyncSender, TrySendError, sync_channel};
    use std::task::{Context, Poll};
    use std::time::{Duration, Instant};
    use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
    use tokio::net::windows::named_pipe::{ClientOptions, NamedPipeServer, ServerOptions};
    use tokio::runtime::{Builder, Runtime};
    use tokio::sync::oneshot;
    use tokio::time::timeout;
    use vitnet_dgml::GraphSession;

    pub(super) const MAX_REQUEST_BYTES: usize = 1024 * 1024;
    pub(super) const MAX_RESPONSE_BYTES: usize = 16 * 1024 * 1024;
    const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
    const READ_TIMEOUT: Duration = Duration::from_secs(5);
    const REQUEST_TIMEOUT: Duration = Duration::from_secs(35);
    const CONNECTION_TIMEOUT: Duration = Duration::from_secs(40);
    const MAX_QUERY_MS: u64 = 30_000;
    const MAX_SESSIONS: usize = 2;
    const MAX_HEADER_BYTES: usize = 16 * 1024;

    type HttpResponse = hyper::Response<Full<Bytes>>;
    type Job = (Request, oneshot::Sender<Response>);

    fn runtime() -> Result<Runtime, DaemonError> {
        if tokio::runtime::Handle::try_current().is_ok() {
            return Err(error(
                "io.daemon.runtime",
                "synchronous daemon functions cannot run inside an async runtime",
            ));
        }
        Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|cause| error("io.daemon.runtime", cause.to_string()))
    }

    fn pipe_path(pipe: &str) -> Result<String, DaemonError> {
        let name = pipe.strip_prefix(r"\\.\pipe\").unwrap_or(pipe);
        if name.is_empty()
            || name.len() > 200
            || name
                .chars()
                .any(|ch| ch == '\\' || ch == '/' || ch.is_control())
        {
            return Err(error(
                "io.daemon.pipe_name",
                "use a local pipe name or \\\\.\\pipe\\name, without separators or control characters",
            ));
        }
        Ok(format!(r"\\.\pipe\{name}"))
    }

    fn new_server(pipe: &str, first: bool) -> Result<NamedPipeServer, DaemonError> {
        create_server(pipe, first)
            .map_err(|cause| error("io.daemon.pipe_create", format!("{pipe}: {cause}")))
    }

    fn create_server(pipe: &str, first: bool) -> io::Result<NamedPipeServer> {
        ServerOptions::new()
            .first_pipe_instance(first)
            .reject_remote_clients(true)
            .max_instances(2)
            .in_buffer_size(64 * 1024)
            .out_buffer_size(64 * 1024)
            .create(pipe)
    }

    async fn next_server(pipe: &str) -> Result<NamedPipeServer, DaemonError> {
        timeout(CONNECT_TIMEOUT, async {
            loop {
                match create_server(pipe, false) {
                    Ok(listener) => return Ok(listener),
                    // Cancelled overlapped reads retain retired handles until
                    // IOCP dispatch; yielding lets Tokio release that slot.
                    Err(cause) if cause.raw_os_error() == Some(231) => {
                        tokio::time::sleep(Duration::from_millis(20)).await;
                    }
                    Err(cause) => {
                        return Err(error("io.daemon.pipe_create", format!("{pipe}: {cause}")));
                    }
                }
            }
        })
        .await
        .map_err(|_| {
            error(
                "io.daemon.pipe_create_timeout",
                format!("{pipe}: pipe instance handoff exceeded 3 seconds"),
            )
        })?
    }

    pub(super) fn serve(pipe: &str, memory_limit: u64) -> Result<(), DaemonError> {
        let pipe = pipe_path(pipe)?;
        let runtime = runtime()?;
        let listener = {
            let _entered = runtime.enter();
            new_server(&pipe, true)?
        };
        let (sender, receiver) = sync_channel::<Job>(1);
        let worker = std::thread::Builder::new()
            .name("vitnet-daemon-queries".into())
            .spawn(move || {
                let mut state = State::new(memory_limit);
                while let Ok((request, reply)) = receiver.recv() {
                    let response = state.query(request);
                    // A timed-out/disconnected caller does not cancel or duplicate graph work.
                    let _ = reply.send(response);
                }
            })
            .map_err(|cause| error("io.daemon.worker", cause.to_string()))?;
        let result = runtime.block_on(serve_async(&pipe, listener, sender));
        let joined = worker
            .join()
            .map_err(|_| error("io.daemon.worker", "graph worker panicked"));
        result.and(joined)
    }

    async fn serve_async(
        pipe: &str,
        mut listener: NamedPipeServer,
        sender: SyncSender<Job>,
    ) -> Result<(), DaemonError> {
        loop {
            listener
                .connect()
                .await
                .map_err(|cause| error("io.daemon.pipe_accept", format!("{pipe}: {cause}")))?;
            let next = next_server(pipe).await?;
            let mut stream = listener;
            let prefix = match read_head(&mut stream).await {
                Ok(prefix) => prefix,
                Err(cause) => {
                    eprintln!("{cause}");
                    if let Err(cause) = reject_http(&mut stream, cause).await {
                        eprintln!("{cause}");
                    }
                    if let Err(cause) = wait_closed(&mut stream).await {
                        eprintln!("{cause}");
                    }
                    drop(stream);
                    listener = next;
                    continue;
                }
            };
            let shutdown = Arc::new(AtomicBool::new(false));
            let service = service_fn({
                let sender = sender.clone();
                let shutdown = Arc::clone(&shutdown);
                move |request| handle(request, sender.clone(), Arc::clone(&shutdown))
            });
            let mut builder = hyper::server::conn::http1::Builder::new();
            builder
                .keep_alive(false)
                .max_headers(32)
                .max_buf_size(MAX_HEADER_BYTES)
                .timer(TokioTimer::new())
                .header_read_timeout(READ_TIMEOUT);
            let connection = builder.serve_connection(
                TokioIo::new(PrefixedPipe {
                    stream: &mut stream,
                    prefix: Bytes::from(prefix),
                }),
                service,
            );
            let completed = match timeout(CONNECTION_TIMEOUT, connection).await {
                Ok(Ok(())) => true,
                Ok(Err(cause)) => {
                    eprintln!("{}", error("io.daemon.http", format!("{pipe}: {cause}")));
                    false
                }
                Err(_) => {
                    eprintln!("io.daemon.timeout: {pipe}: HTTP connection exceeded 40 seconds");
                    false
                }
            };
            if let Err(cause) = wait_closed(&mut stream).await {
                eprintln!("{cause}");
            }
            drop(stream);
            if completed && shutdown.load(Ordering::Acquire) {
                return Ok(());
            }
            listener = next;
        }
    }

    async fn wait_closed(stream: &mut NamedPipeServer) -> Result<(), DaemonError> {
        timeout(READ_TIMEOUT, async {
            let mut buffer = [0; 4096];
            let mut discarded = 0_usize;
            loop {
                match stream.read(&mut buffer).await {
                    Ok(0) => return Ok(()),
                    Ok(count) => {
                        discarded = discarded.saturating_add(count);
                        if discarded > MAX_REQUEST_BYTES {
                            return Err(body_limit("request", MAX_REQUEST_BYTES));
                        }
                    }
                    Err(cause) if cause.raw_os_error() == Some(233) => return Ok(()),
                    Err(cause) => {
                        return Err(error(
                            "io.daemon.http",
                            format!("HTTP close acknowledgement: {cause}"),
                        ));
                    }
                }
            }
        })
        .await
        .map_err(|_| {
            error(
                "io.daemon.timeout",
                "client did not close after its response within 5 seconds",
            )
        })?
    }

    // Preflight lets malformed wire headers receive our diagnostic envelope rather
    // than Hyper's empty automatic 400. Hyper still handles all body framing.
    async fn read_head(stream: &mut NamedPipeServer) -> Result<Vec<u8>, DaemonError> {
        timeout(READ_TIMEOUT, async {
            let mut bytes = Vec::new();
            let mut buffer = [0; 4096];
            loop {
                let remaining = MAX_HEADER_BYTES - bytes.len();
                if remaining == 0 {
                    return Err(error(
                        "resource.daemon.headers",
                        "HTTP headers exceed 16384 bytes",
                    ));
                }
                let capacity = remaining.min(buffer.len());
                let read = stream
                    .read(&mut buffer[..capacity])
                    .await
                    .map_err(|cause| {
                        error("io.daemon.http", format!("HTTP header read: {cause}"))
                    })?;
                if read == 0 {
                    return Err(error(
                        "io.daemon.http",
                        "pipe closed before complete HTTP headers",
                    ));
                }
                bytes.extend_from_slice(&buffer[..read]);
                if bytes.windows(4).any(|part| part == b"\r\n\r\n") {
                    validate_head(&bytes)?;
                    return Ok(bytes);
                }
            }
        })
        .await
        .map_err(|_| error("io.daemon.timeout", "HTTP header read exceeded 5 seconds"))?
    }

    fn validate_head(bytes: &[u8]) -> Result<(), DaemonError> {
        let mut headers = [httparse::EMPTY_HEADER; 32];
        let mut request = httparse::Request::new(&mut headers);
        let parsed = request.parse(bytes).map_err(|cause| {
            if cause == httparse::Error::TooManyHeaders {
                error("resource.daemon.headers", "HTTP request exceeds 32 headers")
            } else {
                error("io.daemon.http", format!("invalid HTTP headers: {cause}"))
            }
        })?;
        if !parsed.is_complete() {
            return Err(error("io.daemon.http", "incomplete HTTP headers"));
        }
        request
            .method
            .unwrap_or("")
            .parse::<Method>()
            .map_err(|cause| error("io.daemon.http", format!("invalid HTTP method: {cause}")))?;
        request
            .path
            .unwrap_or("")
            .parse::<hyper::Uri>()
            .map_err(|cause| error("io.daemon.http", format!("invalid HTTP URI: {cause}")))?;
        let mut content_length = None;
        let mut chunked = false;
        for field in request.headers {
            header::HeaderName::from_bytes(field.name.as_bytes()).map_err(|cause| {
                error("io.daemon.http", format!("invalid header name: {cause}"))
            })?;
            header::HeaderValue::from_bytes(field.value).map_err(|cause| {
                error("io.daemon.http", format!("invalid header value: {cause}"))
            })?;
            if field.name.eq_ignore_ascii_case("content-length") {
                if content_length.is_some()
                    || field.value.is_empty()
                    || !field.value.iter().all(u8::is_ascii_digit)
                {
                    return Err(error(
                        "io.daemon.http",
                        "invalid or repeated Content-Length",
                    ));
                }
                let length = std::str::from_utf8(field.value)
                    .ok()
                    .and_then(|value| value.parse::<u64>().ok())
                    .ok_or_else(|| error("io.daemon.http", "invalid Content-Length"))?;
                if length > MAX_REQUEST_BYTES as u64 {
                    return Err(body_limit("request", MAX_REQUEST_BYTES));
                }
                content_length = Some(length);
            } else if field.name.eq_ignore_ascii_case("transfer-encoding") {
                if chunked
                    || !field.value.eq_ignore_ascii_case(b"chunked")
                    || request.version != Some(1)
                {
                    return Err(error(
                        "io.daemon.http",
                        "only one HTTP/1.1 chunked Transfer-Encoding is supported",
                    ));
                }
                chunked = true;
            }
        }
        if chunked && content_length.is_some() {
            return Err(error(
                "io.daemon.http",
                "Content-Length cannot accompany Transfer-Encoding",
            ));
        }
        Ok(())
    }

    async fn reject_http(
        stream: &mut NamedPipeServer,
        cause: DaemonError,
    ) -> Result<(), DaemonError> {
        let response = failure_http(cause);
        let status = response.status();
        let body = response
            .into_body()
            .collect()
            .await
            .expect("infallible full body")
            .to_bytes();
        let head = format!(
            "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        timeout(READ_TIMEOUT, async {
            stream.write_all(head.as_bytes()).await?;
            stream.write_all(&body).await?;
            stream.flush().await
        })
        .await
        .map_err(|_| {
            error(
                "io.daemon.timeout",
                "HTTP rejection write exceeded 5 seconds",
            )
        })?
        .map_err(|cause| error("io.daemon.http", format!("HTTP rejection write: {cause}")))
    }

    struct PrefixedPipe<'a> {
        stream: &'a mut NamedPipeServer,
        prefix: Bytes,
    }

    impl AsyncRead for PrefixedPipe<'_> {
        fn poll_read(
            mut self: Pin<&mut Self>,
            context: &mut Context<'_>,
            buffer: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            if self.prefix.is_empty() {
                return Pin::new(&mut *self.stream).poll_read(context, buffer);
            }
            let count = self.prefix.len().min(buffer.remaining());
            buffer.put_slice(&self.prefix.split_to(count));
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncWrite for PrefixedPipe<'_> {
        fn poll_write(
            mut self: Pin<&mut Self>,
            context: &mut Context<'_>,
            bytes: &[u8],
        ) -> Poll<io::Result<usize>> {
            Pin::new(&mut *self.stream).poll_write(context, bytes)
        }

        fn poll_flush(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut *self.stream).poll_flush(context)
        }

        fn poll_shutdown(
            mut self: Pin<&mut Self>,
            context: &mut Context<'_>,
        ) -> Poll<io::Result<()>> {
            Pin::new(&mut *self.stream).poll_shutdown(context)
        }
    }

    async fn handle(
        request: hyper::Request<Incoming>,
        sender: SyncSender<Job>,
        shutdown: Arc<AtomicBool>,
    ) -> Result<HttpResponse, Infallible> {
        let response = match timeout(REQUEST_TIMEOUT, process(request, &sender, &shutdown)).await {
            Ok(Ok(response)) => response,
            Ok(Err(cause)) => failure_http(cause),
            Err(_) => failure_http(error(
                "io.daemon.timeout",
                "HTTP request exceeded 35 seconds",
            )),
        };
        Ok(response)
    }

    async fn process(
        request: hyper::Request<Incoming>,
        sender: &SyncSender<Job>,
        shutdown: &AtomicBool,
    ) -> Result<HttpResponse, DaemonError> {
        let health = request.method() == Method::GET && request.uri() == "/health";
        if !health && request.method() != Method::POST {
            return Err(error("io.daemon.method", "use POST /query or GET /health"));
        }
        if !health && request.uri() != "/query" {
            return Err(error("io.daemon.path", "the query endpoint is /query"));
        }
        if request
            .headers()
            .get(header::CONTENT_TYPE)
            .is_some_and(|value| value != "application/json")
        {
            return Err(error(
                "io.daemon.content_type",
                "request Content-Type must be application/json",
            ));
        }
        let body = timeout(
            READ_TIMEOUT,
            read_body(request.into_body(), MAX_REQUEST_BYTES, "request"),
        )
        .await
        .map_err(|_| error("io.daemon.timeout", "request body read exceeded 5 seconds"))??;
        let operation: Request = if health {
            if !body.is_empty() {
                return Err(error("io.daemon.json", "GET /health cannot have a body"));
            }
            Request::Health
        } else {
            serde_json::from_slice(&body)
                .map_err(|cause| error("io.daemon.json", format!("invalid query JSON: {cause}")))?
        };
        let stopping = matches!(operation, Request::Shutdown);
        let (reply, receive) = oneshot::channel();
        sender
            .try_send((operation, reply))
            .map_err(|cause| match cause {
                TrySendError::Full(_) => error(
                    "resource.daemon.busy",
                    "graph worker is busy; retry after the active query completes",
                ),
                TrySendError::Disconnected(_) => error("io.daemon.worker", "graph worker stopped"),
            })?;
        let response = receive.await.map_err(|_| {
            error(
                "io.daemon.worker",
                "graph worker failed to return a response",
            )
        })?;
        let successful_shutdown = stopping && response.ok;
        let result = response_http(&response, StatusCode::OK)?;
        if successful_shutdown {
            shutdown.store(true, Ordering::Release);
        }
        Ok(result)
    }

    fn failure(cause: DaemonError, reused: bool) -> Response {
        Response {
            schema: RESPONSE_SCHEMA.into(),
            ok: false,
            data: None,
            error: Some(*cause.diagnostic),
            session_reused: reused,
        }
    }

    fn failure_http(cause: DaemonError) -> HttpResponse {
        let status = if cause.diagnostic.code == "resource.daemon.busy"
            || cause.diagnostic.code == "io.daemon.worker"
        {
            StatusCode::SERVICE_UNAVAILABLE
        } else if cause.diagnostic.code.starts_with("resource.daemon.") {
            StatusCode::PAYLOAD_TOO_LARGE
        } else if cause.diagnostic.code == "io.daemon.timeout" {
            StatusCode::REQUEST_TIMEOUT
        } else {
            StatusCode::BAD_REQUEST
        };
        // Fixed-size local diagnostics cannot exceed the response cap.
        match response_http(&failure(cause, false), status) {
            Ok(response) => response,
            Err(cause) => {
                eprintln!("{cause}");
                let mut response = hyper::Response::new(Full::new(Bytes::from_static(
                    br#"{"schema":"vitnet.daemon-response.v1","ok":false,"data":null,"error":{"code":"io.daemon.json","message":"error response serialization failed"},"session_reused":false}"#,
                )));
                *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
                response
            }
        }
    }

    fn response_http(response: &Response, status: StatusCode) -> Result<HttpResponse, DaemonError> {
        let bytes = encode(response, MAX_RESPONSE_BYTES, "response")?;
        let mut response = hyper::Response::new(Full::new(Bytes::from(bytes)));
        *response.status_mut() = status;
        response.headers_mut().insert(
            header::CONTENT_TYPE,
            header::HeaderValue::from_static("application/json"),
        );
        response.headers_mut().insert(
            header::CONNECTION,
            header::HeaderValue::from_static("close"),
        );
        Ok(response)
    }

    async fn read_body<B>(mut body: B, limit: usize, kind: &str) -> Result<Vec<u8>, DaemonError>
    where
        B: Body<Data = Bytes> + Unpin,
        B::Error: std::error::Error,
    {
        let expected = body.size_hint().lower();
        if expected > limit as u64 {
            return Err(body_limit(kind, limit));
        }
        let mut bytes = Vec::new();
        while let Some(frame) = body.frame().await {
            let frame = frame.map_err(|cause| {
                error(
                    "io.daemon.body",
                    format!(
                        "{kind} body after {} bytes (expected at least {expected}): {}",
                        bytes.len(),
                        error_chain(&cause)
                    ),
                )
            })?;
            if let Ok(data) = frame.into_data() {
                if data.len() > limit.saturating_sub(bytes.len()) {
                    return Err(body_limit(kind, limit));
                }
                bytes.extend_from_slice(&data);
            }
        }
        Ok(bytes)
    }

    fn error_chain(cause: &dyn std::error::Error) -> String {
        let mut message = cause.to_string();
        let mut source = cause.source();
        for _ in 0..8 {
            let Some(cause) = source else { break };
            message.push_str(": ");
            message.push_str(&cause.to_string());
            source = cause.source();
        }
        message
    }

    fn body_limit(kind: &str, limit: usize) -> DaemonError {
        error(
            &format!("resource.daemon.{kind}_body"),
            format!("{kind} body exceeds {limit} bytes"),
        )
    }

    struct BoundedWriter {
        bytes: Vec<u8>,
        limit: usize,
        exceeded: bool,
    }

    impl Write for BoundedWriter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if bytes.len() > self.limit.saturating_sub(self.bytes.len()) {
                self.exceeded = true;
                return Err(io::Error::other("HTTP body exceeds its byte limit"));
            }
            self.bytes.extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    fn encode<T: Serialize>(value: &T, limit: usize, kind: &str) -> Result<Vec<u8>, DaemonError> {
        let mut writer = BoundedWriter {
            bytes: Vec::new(),
            limit,
            exceeded: false,
        };
        serde_json::to_writer(&mut writer, value).map_err(|cause| {
            if writer.exceeded {
                body_limit(kind, limit)
            } else {
                error(
                    "io.daemon.json",
                    format!("cannot serialize {kind}: {cause}"),
                )
            }
        })?;
        Ok(writer.bytes)
    }

    struct State {
        memory_limit: u64,
        sessions: VecDeque<(PathBuf, GraphSession)>,
        started: Instant,
        requests: u64,
        opens: u64,
        hits: u64,
        evictions: u64,
    }

    impl State {
        fn new(memory_limit: u64) -> Self {
            Self {
                memory_limit,
                sessions: VecDeque::new(),
                started: Instant::now(),
                requests: 0,
                opens: 0,
                hits: 0,
                evictions: 0,
            }
        }

        fn session(&mut self, index: &Path) -> Result<(&mut GraphSession, bool), DaemonError> {
            let key = index.canonicalize().map_err(|cause| {
                error(
                    "io.daemon.index_path",
                    format!("{}: {cause}", index.display()),
                )
            })?;
            let reused = if let Some(position) =
                self.sessions.iter().position(|(path, _)| *path == key)
            {
                let entry = self
                    .sessions
                    .remove(position)
                    .expect("known session position");
                self.sessions.push_back(entry);
                self.hits = self.hits.saturating_add(1);
                true
            } else {
                if self.sessions.len() == MAX_SESSIONS {
                    self.sessions.pop_front();
                    self.evictions = self.evictions.saturating_add(1);
                }
                let session =
                    GraphSession::open(&key, self.memory_limit).map_err(|cause| DaemonError {
                        diagnostic: cause.diagnostic,
                    })?;
                self.sessions.push_back((key, session));
                self.opens = self.opens.saturating_add(1);
                false
            };
            Ok((
                &mut self.sessions.back_mut().expect("opened session").1,
                reused,
            ))
        }

        fn query(&mut self, request: Request) -> Response {
            self.requests = self.requests.saturating_add(1);
            let mut reused = false;
            let result = match request {
                Request::Health => Ok(serde_json::json!({
                    "schema": "vitnet.daemon-health.v1",
                    "elapsed_ms": u64::try_from(self.started.elapsed().as_millis()).unwrap_or(u64::MAX),
                    "requests": self.requests,
                    "sessions": self.sessions.len(),
                    "session_limit": MAX_SESSIONS,
                    "session_opens": self.opens,
                    "session_hits": self.hits,
                    "session_evictions": self.evictions,
                    "generations": self.sessions.iter().map(|(_, session)| &session.generation).collect::<Vec<_>>(),
                })),
                Request::Shutdown => {
                    self.sessions.clear();
                    Ok(serde_json::json!({ "shutdown": true }))
                }
                Request::Search {
                    index,
                    query,
                    mut options,
                } => self.session(&index).and_then(|(session, hit)| {
                    reused = hit;
                    options.timeout_ms = options.timeout_ms.min(MAX_QUERY_MS);
                    let report = session
                        .search(&query, &options)
                        .map_err(|cause| DaemonError {
                            diagnostic: cause.diagnostic,
                        })?;
                    report_value(&report)
                }),
                Request::Why {
                    index,
                    node_id,
                    mut options,
                } => self.session(&index).and_then(|(session, hit)| {
                    reused = hit;
                    options.timeout_ms = options.timeout_ms.min(MAX_QUERY_MS);
                    let report = session
                        .why(node_id, &options)
                        .map_err(|cause| DaemonError {
                            diagnostic: cause.diagnostic,
                        })?;
                    report_value(&report)
                }),
                Request::Incoming {
                    index,
                    node_id,
                    mut options,
                } => self.session(&index).and_then(|(session, hit)| {
                    reused = hit;
                    options.timeout_ms = options.timeout_ms.min(MAX_QUERY_MS);
                    let report =
                        session
                            .incoming(node_id, &options)
                            .map_err(|cause| DaemonError {
                                diagnostic: cause.diagnostic,
                            })?;
                    report_value(&report)
                }),
                Request::Batch {
                    index,
                    ids,
                    mut options,
                } => self.session(&index).and_then(|(session, hit)| {
                    reused = hit;
                    options.timeout_ms = options.timeout_ms.min(MAX_QUERY_MS);
                    let report = session.batch(&ids, &options).map_err(|cause| DaemonError {
                        diagnostic: cause.diagnostic,
                    })?;
                    report_value(&report)
                }),
            };
            match result {
                Ok(data) => Response {
                    schema: RESPONSE_SCHEMA.into(),
                    ok: true,
                    data: Some(data),
                    error: None,
                    session_reused: reused,
                },
                Err(cause) => failure(cause, reused),
            }
        }
    }

    fn report_value<T: Serialize>(report: &T) -> Result<serde_json::Value, DaemonError> {
        let bytes = encode(report, MAX_RESPONSE_BYTES, "response")?;
        serde_json::from_slice(&bytes)
            .map_err(|cause| error("io.daemon.json", format!("cannot decode report: {cause}")))
    }

    pub(super) fn call(pipe: &str, request: &Request) -> Result<Response, DaemonError> {
        let pipe = pipe_path(pipe)?;
        let bytes = encode(request, MAX_REQUEST_BYTES, "request")?;
        runtime()?.block_on(async {
            timeout(CONNECTION_TIMEOUT, call_async(&pipe, bytes))
                .await
                .map_err(|_| {
                    error(
                        "io.daemon.timeout",
                        format!("{pipe}: call exceeded 40 seconds"),
                    )
                })?
        })
    }

    async fn call_async(pipe: &str, bytes: Vec<u8>) -> Result<Response, DaemonError> {
        let client = timeout(CONNECT_TIMEOUT, async {
            loop {
                match ClientOptions::new().open(pipe) {
                    Ok(client) => return Ok(client),
                    Err(cause) if cause.raw_os_error() == Some(231) => {
                        tokio::time::sleep(Duration::from_millis(20)).await;
                    }
                    Err(cause) => {
                        return Err(error("io.daemon.pipe_connect", format!("{pipe}: {cause}")));
                    }
                }
            }
        })
        .await
        .map_err(|_| {
            error(
                "io.daemon.pipe_connect_timeout",
                format!("{pipe}: pipe busy for 3 seconds"),
            )
        })??;
        let (mut sender, connection) = timeout(
            READ_TIMEOUT,
            hyper::client::conn::http1::handshake(TokioIo::new(client)),
        )
        .await
        .map_err(|_| {
            error(
                "io.daemon.timeout",
                format!("{pipe}: HTTP handshake exceeded 5 seconds"),
            )
        })?
        .map_err(|cause| error("io.daemon.http", format!("{pipe}: {cause}")))?;
        let mut driver = tokio::spawn(connection);
        let result = timeout(REQUEST_TIMEOUT, exchange(pipe, &mut sender, bytes))
            .await
            .map_err(|_| {
                error(
                    "io.daemon.timeout",
                    format!("{pipe}: request exceeded 35 seconds"),
                )
            })
            .and_then(std::convert::identity);
        drop(sender);
        let completed = if result.is_ok() {
            if let Ok(completed) = timeout(READ_TIMEOUT, &mut driver).await {
                completed
            } else {
                driver.abort();
                let _ = driver.await;
                return Err(error(
                    "io.daemon.timeout",
                    format!("{pipe}: HTTP connection completion exceeded 5 seconds"),
                ));
            }
        } else {
            driver.abort();
            driver.await
        };
        match completed {
            Ok(Err(cause)) if result.is_ok() => {
                return Err(error(
                    "io.daemon.http",
                    format!("{pipe}: {}", error_chain(&cause)),
                ));
            }
            Ok(_) => {}
            Err(cause) if cause.is_cancelled() => {}
            Err(cause) => return Err(error("io.daemon.runtime", cause.to_string())),
        }
        result
    }

    async fn exchange(
        pipe: &str,
        sender: &mut hyper::client::conn::http1::SendRequest<Full<Bytes>>,
        bytes: Vec<u8>,
    ) -> Result<Response, DaemonError> {
        let request = hyper::Request::builder()
            .method(Method::POST)
            .uri("/query")
            .header(header::HOST, "localhost")
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::CONNECTION, "close")
            .body(Full::new(Bytes::from(bytes)))
            .map_err(|cause| error("io.daemon.http", cause.to_string()))?;
        let response = sender
            .send_request(request)
            .await
            .map_err(|cause| error("io.daemon.http", format!("{pipe}: {cause}")))?;
        let status = response.status();
        if response
            .headers()
            .get(header::CONTENT_TYPE)
            .is_none_or(|value| value != "application/json")
        {
            return Err(error(
                "io.daemon.protocol",
                format!("{pipe}: HTTP {status} did not return application/json"),
            ));
        }
        let body = timeout(
            READ_TIMEOUT,
            read_body(response.into_body(), MAX_RESPONSE_BYTES, "response"),
        )
        .await
        .map_err(|_| {
            error(
                "io.daemon.timeout",
                format!("{pipe}: response body read exceeded 5 seconds"),
            )
        })??;
        let response: Response = serde_json::from_slice(&body).map_err(|cause| {
            error(
                "io.daemon.json",
                format!("{pipe}: invalid response JSON: {cause}"),
            )
        })?;
        if response.schema != RESPONSE_SCHEMA
            || (response.ok && (response.data.is_none() || response.error.is_some()))
            || (!response.ok && (response.error.is_none() || response.data.is_some()))
            || (response.ok && !status.is_success())
        {
            return Err(error(
                "io.daemon.protocol",
                format!("{pipe}: inconsistent HTTP {status} response envelope"),
            ));
        }
        if !status.is_success() {
            return Err(DaemonError {
                diagnostic: Box::new(response.error.expect("validated error")),
            });
        }
        Ok(response)
    }

    #[cfg(test)]
    mod tests {
        use super::{MAX_REQUEST_BYTES, MAX_RESPONSE_BYTES, encode, read_body, runtime};
        use bytes::Bytes;
        use hyper::body::{Body, Frame};
        use std::collections::VecDeque;
        use std::convert::Infallible;
        use std::pin::Pin;
        use std::task::{Context, Poll};

        struct Chunks(VecDeque<Bytes>);

        impl Body for Chunks {
            type Data = Bytes;
            type Error = Infallible;

            fn poll_frame(
                mut self: Pin<&mut Self>,
                _context: &mut Context<'_>,
            ) -> Poll<Option<Result<Frame<Bytes>, Infallible>>> {
                Poll::Ready(self.0.pop_front().map(|bytes| Ok(Frame::data(bytes))))
            }
        }

        #[test]
        fn serialized_bodies_accept_exact_caps_and_reject_one_more_byte() {
            for (kind, cap) in [
                ("request", MAX_REQUEST_BYTES),
                ("response", MAX_RESPONSE_BYTES),
            ] {
                let exact = "x".repeat(cap - 2);
                assert_eq!(encode(&exact, cap, kind).unwrap().len(), cap);
                let over = "x".repeat(cap - 1);
                assert_eq!(
                    encode(&over, cap, kind).unwrap_err().diagnostic.code,
                    format!("resource.daemon.{kind}_body")
                );
            }
        }

        #[test]
        fn unadvertised_body_frames_enforce_the_accumulated_byte_limit() {
            runtime().unwrap().block_on(async {
                for kind in ["request", "response"] {
                    let exact = Chunks(VecDeque::from([
                        Bytes::from_static(b"ab"),
                        Bytes::from_static(b"cd"),
                    ]));
                    assert_eq!(read_body(exact, 4, kind).await.unwrap(), b"abcd");
                    let over = Chunks(VecDeque::from([
                        Bytes::from_static(b"ab"),
                        Bytes::from_static(b"cde"),
                    ]));
                    assert_eq!(
                        read_body(over, 4, kind).await.unwrap_err().diagnostic.code,
                        format!("resource.daemon.{kind}_body")
                    );
                }
            });
        }
    }
}

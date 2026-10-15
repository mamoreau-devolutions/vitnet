//! Explicitly approved HTTP integration exception: only owned ephemeral loopback children.
use serde_json::{Value, json};
use std::fmt::Write as _;
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};
use vitnet_attribution::model::{Artifact, EVIDENCE_SCHEMA, Evidence, Mapping, Source};
use vitnet_cli::explorer::data;
use vitnet_dgml::{IndexControl, IndexOptions, build_index};
use vitnet_mstat::CoalescedIdentity;

const MEMORY: u64 = 128 << 20;
const WAIT: Duration = Duration::from_secs(15);

fn write_json(path: &Path, value: &impl serde::Serialize) {
    fs::write(path, serde_json::to_vec(value).unwrap()).unwrap();
}

fn row(identity: &str, stream: &str, bytes: u64) -> CoalescedIdentity {
    CoalescedIdentity {
        stream: stream.into(),
        identity: identity.into(),
        bytes,
        accounted: true,
        identity_lossy: false,
        records: 1,
        raw_identity_blake3: blake3::hash(identity.as_bytes()).to_hex().to_string(),
    }
}

struct Fixture {
    root: tempfile::TempDir,
    index: PathBuf,
    bundle: PathBuf,
    generation: String,
}

impl Fixture {
    fn new(rows: &[CoalescedIdentity], graph: Option<&str>) -> Self {
        Self::with_evidence(
            rows,
            graph,
            Evidence {
                schema: EVIDENCE_SCHEMA.into(),
                label: "private fixture".into(),
                ..Evidence::default()
            },
        )
    }

    fn with_evidence(
        rows: &[CoalescedIdentity],
        graph: Option<&str>,
        mut evidence: Evidence,
    ) -> Self {
        let root = tempfile::tempdir().unwrap();
        if let Some(xml) = graph {
            let input = root.path().join("graph.xml");
            fs::write(&input, xml).unwrap();
            let indexed = build_index(
                &input,
                &IndexOptions {
                    cache_root: root.path().join("graph-cache"),
                    memory_limit: MEMORY,
                    selected_entry: None,
                    strict_hash: false,
                    control: IndexControl::default(),
                },
            )
            .unwrap();
            evidence.artifacts.push(Artifact {
                kind: "scan_index".into(),
                path: indexed.index_directory,
                revision: None,
                blake3: None,
            });
        }
        let manifest = root.path().join("evidence.json");
        write_json(&manifest, &evidence);
        let index = root.path().join("index");
        let mut imported = vitnet_attribution::import(&manifest, &index, MEMORY, false).unwrap();
        let mut bytes = Vec::new();
        for row in rows {
            bytes.extend(serde_json::to_vec(row).unwrap());
            bytes.push(b'\n');
        }
        fs::write(index.join("identities.ndjson"), &bytes).unwrap();
        imported.identities = u64::try_from(rows.len()).unwrap();
        imported.identities_blake3 = blake3::hash(&bytes).to_hex().to_string();
        write_json(&index.join("index.json"), &imported);
        let bundle = root.path().join("bundle");
        let prepared = data::prepare(
            &index,
            &bundle,
            &[],
            None,
            &[],
            "scan_index",
            MEMORY,
            &IndexControl::default(),
        )
        .unwrap();
        Self {
            root,
            index,
            bundle,
            generation: prepared.generation,
        }
    }

    fn small() -> Self {
        Self::new(
            &[
                row("Owner__alpha", "Methods", 11),
                row("Owner__beta", "Methods", 22),
                row("Owner__alpha_blob", "Blobs", 33),
                row("Owner__omega", "Methods", 44),
            ],
            None,
        )
    }
}

struct Response {
    status: u16,
    headers: String,
    body: Vec<u8>,
}

impl Response {
    fn read(stream: &mut TcpStream) -> Self {
        let mut bytes = Vec::new();
        if let Err(error) = stream.take((2 << 20) + 16_384).read_to_end(&mut bytes) {
            // Windows resets rejected connections with unread request bytes. Still
            // demand a complete response below; a reset alone is never evidence.
            assert_eq!(error.kind(), std::io::ErrorKind::ConnectionReset, "{error}");
        }
        let split = bytes
            .windows(4)
            .position(|part| part == b"\r\n\r\n")
            .expect("HTTP response header");
        let headers = String::from_utf8(bytes[..split].to_vec()).unwrap();
        let status = headers.split_whitespace().nth(1).unwrap().parse().unwrap();
        let length: usize = headers
            .lines()
            .find_map(|line| line.strip_prefix("Content-Length: "))
            .unwrap()
            .parse()
            .unwrap();
        let body = bytes[split + 4..].to_vec();
        assert_eq!(body.len(), length);
        assert!(headers.contains("Connection: close"));
        assert!(headers.contains("Cache-Control: no-store"));
        assert!(body.len() <= 2 << 20);
        Self {
            status,
            headers,
            body,
        }
    }

    fn json(&self) -> Value {
        serde_json::from_slice(&self.body).unwrap()
    }

    fn error(&self, status: u16, code: &str) {
        assert_eq!(
            self.status,
            status,
            "{}",
            String::from_utf8_lossy(&self.body)
        );
        assert!(self.headers.contains("Content-Type: application/json"));
        let body = self.json();
        assert_eq!(body["error"]["code"], code);
        assert_ne!(body["error"]["message"].as_str().unwrap(), "");
        assert_eq!(body.as_object().unwrap().len(), 1);
        assert_eq!(body["error"].as_object().unwrap().len(), 2);
        for forbidden in [
            "entries",
            "row",
            "snapshot",
            "sources",
            "generation",
            "identities",
        ] {
            assert!(body.get(forbidden).is_none(), "error leaks {forbidden}");
        }
    }
}

struct Server {
    child: Child,
    address: SocketAddr,
    token: String,
}

impl Server {
    fn start(fixture: &Fixture) -> Self {
        let mut child = Command::new(env!("CARGO_BIN_EXE_vitnet"))
            .args(["--memory-limit", "128MiB", "explore", "browse"])
            .arg(&fixture.bundle)
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap();
        let stdout = child.stdout.take().unwrap();
        let (sender, receiver) = mpsc::channel();
        std::thread::spawn(move || {
            let mut first = String::new();
            let mut reader = BufReader::new(stdout);
            let result = reader.read_line(&mut first);
            let _ = sender.send((result, first));
            // Keep draining our child's pipe through graceful shutdown.
            let _ = std::io::copy(&mut reader, &mut std::io::sink());
        });
        // Own child is immediately guarded, including readiness parsing failure.
        let mut owned = Self {
            child,
            address: "127.0.0.1:0".parse().unwrap(),
            token: String::new(),
        };
        let (read, first) = receiver
            .recv_timeout(WAIT)
            .expect("owned explorer readiness deadline");
        read.unwrap();
        let url = first
            .trim()
            .strip_prefix("Explorer: http://")
            .expect("first stdout Explorer URL");
        let (address, token) = url
            .split_once("/#token=")
            .expect("fragment-only capability");
        owned.address = address.parse().unwrap();
        owned.token = token.into();
        assert!(owned.address.ip().is_loopback());
        assert!(owned.address.is_ipv4());
        assert_ne!(owned.address.port(), 0);
        assert_eq!(owned.token.len(), 64);
        assert!(owned.token.bytes().all(|byte| byte.is_ascii_hexdigit()));
        owned
    }

    fn connect(&self) -> TcpStream {
        let stream = TcpStream::connect_timeout(&self.address, WAIT).unwrap();
        stream.set_read_timeout(Some(WAIT)).unwrap();
        stream.set_write_timeout(Some(WAIT)).unwrap();
        stream
    }

    fn raw(&self, bytes: &[u8]) -> Response {
        let mut stream = self.connect();
        stream.write_all(bytes).unwrap();
        stream.shutdown(Shutdown::Write).unwrap();
        Response::read(&mut stream)
    }

    fn request(&self, method: &str, path: &str, body: &[u8], extra: &str) -> Response {
        let mut bytes = format!(
            "{method} {path} HTTP/1.1\r\nHost: {}\r\n{extra}Content-Length: {}\r\n\r\n",
            self.address,
            body.len()
        )
        .into_bytes();
        bytes.extend_from_slice(body);
        self.raw(&bytes)
    }

    fn auth(&self) -> String {
        format!(
            "Authorization: Bearer {}\r\nContent-Type: application/json\r\n",
            self.token
        )
    }

    fn post(&self, path: &str, body: &Value) -> Response {
        self.request(
            "POST",
            path,
            &serde_json::to_vec(body).unwrap(),
            &self.auth(),
        )
    }

    fn query(&self, fixture: &Fixture, mut query: Value) -> Response {
        query["request_id"] = json!("contract");
        query["generation"] = json!(fixture.generation);
        self.post("/api/query", &query)
    }

    fn stop(&mut self) {
        let response = self.post("/api/shutdown", &json!({}));
        assert_eq!(response.status, 200);
        assert_eq!(response.json(), json!({"stopped":true}));
        let deadline = Instant::now() + WAIT;
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                assert!(status.success(), "owned child failed {status}");
                break;
            }
            assert!(Instant::now() < deadline, "owned child shutdown deadline");
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        if matches!(self.child.try_wait(), Ok(None)) {
            if !self.token.is_empty() && !std::thread::panicking() {
                let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| self.stop()));
            }
            if matches!(self.child.try_wait(), Ok(None)) {
                // Child::kill targets only the PID this fixture owns, never a name.
                let _ = self.child.kill();
                let _ = self.child.wait();
            }
        }
    }
}

#[test]
fn all_api_capabilities_exact_host_origin_and_content_type_are_enforced_without_data() {
    let fixture = Fixture::small();
    let mut server = Server::start(&fixture);
    for path in [
        "/api/query",
        "/api/cancel",
        "/api/shutdown",
        "/api/snapshot",
        "/api/unknown",
    ] {
        server
            .request("POST", path, b"{}", "Content-Type: application/json\r\n")
            .error(403, "explorer.authorization");
        server
            .request(
                "POST",
                path,
                b"{}",
                "Authorization: Bearer wrong\r\nContent-Type: application/json\r\n",
            )
            .error(403, "explorer.authorization");
        let duplicate = format!(
            "{}Authorization: Bearer {}\r\n",
            server.auth(),
            server.token
        );
        server
            .request("POST", path, b"{}", &duplicate)
            .error(403, "explorer.authorization");
    }
    for host in [
        "localhost:0".to_string(),
        "127.0.0.2:0".into(),
        format!("localhost:{}", server.address.port()),
        format!("127.0.0.1:{}", server.address.port().wrapping_add(1)),
    ] {
        let request = format!(
            "POST /api/query HTTP/1.1\r\nHost: {host}\r\n{}Content-Length: 2\r\n\r\n{{}}",
            server.auth()
        );
        server.raw(request.as_bytes()).error(403, "explorer.host");
    }
    let duplicate_host = format!(
        "POST /api/query HTTP/1.1\r\nHost: {0}\r\nHost: {0}\r\n{1}Content-Length: 2\r\n\r\n{{}}",
        server.address,
        server.auth()
    );
    server
        .raw(duplicate_host.as_bytes())
        .error(403, "explorer.host");
    for origin in [
        "null".to_string(),
        "http://example.invalid".into(),
        format!("http://localhost:{}", server.address.port()),
        format!("http://{}/", server.address),
    ] {
        server
            .request(
                "POST",
                "/api/query",
                b"{}",
                &format!("{}Origin: {origin}\r\n", server.auth()),
            )
            .error(403, "explorer.origin");
    }
    let extra = format!(
        "{}Origin: http://{}\r\nOrigin: http://{}\r\n",
        server.auth(),
        server.address,
        server.address
    );
    server
        .request("POST", "/api/query", b"{}", &extra)
        .error(403, "explorer.origin");
    for content_type in ["", "text/plain", "application/json; charset=utf-8"] {
        let extra = format!(
            "Authorization: Bearer {}\r\n{}",
            server.token,
            if content_type.is_empty() {
                String::new()
            } else {
                format!("Content-Type: {content_type}\r\n")
            }
        );
        server
            .request("POST", "/api/cancel", br#"{"request_id":"absent"}"#, &extra)
            .error(400, "explorer.content_type");
    }
    let body = json!({"request_id":"absent"});
    let accepted = server.request(
        "POST",
        "/api/cancel",
        &serde_json::to_vec(&body).unwrap(),
        &format!("{}Origin: http://{}\r\n", server.auth(), server.address),
    );
    assert_eq!(accepted.status, 200);
    assert_eq!(accepted.json(), json!({"cancelled":false}));
    server.stop();
}

#[test]
#[allow(clippy::too_many_lines)] // One owned server proves the static/API dispatch contract.
fn static_whitelist_methods_json_validation_and_cancel_shutdown_contracts() {
    let fixture = Fixture::small();
    let mut server = Server::start(&fixture);
    for (path, mime) in [
        ("/", "text/html"),
        ("/app.js", "text/javascript"),
        ("/layout.js", "text/javascript"),
        ("/style.css", "text/css"),
    ] {
        let response = server.request("GET", path, b"", "");
        assert_eq!(response.status, 200);
        assert!(response.headers.contains(mime));
        assert!(response.headers.contains("X-Content-Type-Options: nosniff"));
        assert!(response.headers.contains("frame-ancestors 'none'"));
        assert_ne!(response.body, [] as [u8; 0]);
        if path == "/" {
            let page = String::from_utf8(response.body).unwrap();
            assert!(
                !page.contains("private fixture"),
                "unauthenticated bootstrap leaks evidence"
            );
            let nonce = response
                .headers
                .split("script-src 'nonce-")
                .nth(1)
                .unwrap()
                .split('\'')
                .next()
                .unwrap();
            assert!(page.contains(&format!("nonce=\"{nonce}\"")));
            for tag in ["<script", "<style"] {
                for opening in page
                    .split(tag)
                    .skip(1)
                    .map(|part| part.split('>').next().unwrap())
                {
                    assert!(
                        opening.contains(&format!("nonce=\"{nonce}\"")),
                        "unprotected {tag} tag: {opening}"
                    );
                }
            }
            assert!(
                !page.contains(&server.token),
                "bootstrap must not disclose capability"
            );
        }
    }
    for path in [
        "/../../index.json",
        "/bundle.json",
        "/identities.ndjson",
        "/snapshot.json",
        "/app.js?x",
        "/api/unknown",
        "/%2e%2e/index.json",
    ] {
        let response = server.request("GET", path, b"", &server.auth());
        assert_eq!(response.status, 404);
        assert_eq!(response.body, b"Not found");
    }
    for method in ["PUT", "DELETE", "OPTIONS"] {
        let response = server.request(method, "/api/query", b"{}", &server.auth());
        assert_eq!(response.status, 405);
        assert_eq!(response.body, b"Method not allowed");
    }
    server
        .request("GET", "/", b"x", "")
        .error(400, "explorer.http");
    for path in [
        "/api/query",
        "/api/cancel",
        "/api/shutdown",
        "/api/snapshot",
    ] {
        server
            .request("POST", path, b"{", &server.auth())
            .error(400, "explorer.request.json");
    }
    server
        .post("/api/shutdown", &json!({"extra":true}))
        .error(400, "explorer.request");
    server
        .post("/api/snapshot", &json!({"extra":true}))
        .error(400, "explorer.request");
    let snapshot = server.post("/api/snapshot", &json!({}));
    assert_eq!(snapshot.status, 200);
    assert_eq!(snapshot.json()["title"], "private fixture");
    assert_eq!(snapshot.json()["generation"], fixture.generation);
    server
        .post("/api/cancel", &json!({"request_id":"id","extra":true}))
        .error(400, "explorer.request.json");
    for id in ["", "with space", "bad/slash", &"a".repeat(65)] {
        server
            .post("/api/cancel", &json!({"request_id":id}))
            .error(409, "explorer.request_id");
        server.post("/api/query", &json!({"request_id":id,"generation":fixture.generation,"action":"rows","contains":"","stream":null,"after":null,"limit":50})).error(409, "explorer.request_id");
    }
    let response = server.post("/api/cancel", &json!({"request_id":"a".repeat(64)}));
    assert_eq!(response.status, 200);
    assert_eq!(response.json(), json!({"cancelled":false}));
    server
        .query(&fixture, json!({"action":"unknown"}))
        .error(400, "explorer.request.json");
    server
        .query(&fixture, json!({"action":"rows","unexpected":true}))
        .error(400, "explorer.request.json");
    server.stop();
}

#[test]
fn body_header_and_framing_budgets_reject_overflow_trailing_and_pipeline() {
    let fixture = Fixture::small();
    let mut server = Server::start(&fixture);
    let payload = br#"{"request_id":"absent"}"#;
    let mut exact = payload.to_vec();
    exact.resize(16 * 1024, b' ');
    let response = server.request("POST", "/api/cancel", &exact, &server.auth());
    assert_eq!(response.status, 200);
    assert_eq!(response.json(), json!({"cancelled":false}));
    let too_large = format!(
        "POST /api/cancel HTTP/1.1\r\nHost: {}\r\n{}Content-Length: 16385\r\n\r\n",
        server.address,
        server.auth()
    );
    server
        .raw(too_large.as_bytes())
        .error(413, "resource.explorer.request");
    let oversized = format!(
        "GET / HTTP/1.1\r\nHost: {}\r\nX-Fill: {}",
        server.address,
        "x".repeat(8192)
    );
    server
        .raw(oversized.as_bytes())
        .error(413, "resource.explorer.headers");
    let base = format!("GET / HTTP/1.1\r\nHost: {}\r\nX-Fill: ", server.address);
    let ending = "\r\nContent-Length: 0\r\n\r\n";
    let exact_header = format!(
        "{base}{}{ending}",
        "x".repeat(8192 - base.len() - ending.len())
    );
    let response = server.raw(exact_header.as_bytes());
    assert_eq!(response.status, 200);
    assert!(String::from_utf8_lossy(&response.body).contains("bounded explorer"));
    for suffix in [
        "Content-Length: -1\r\n\r\n",
        "Content-Length: invalid\r\n\r\n",
        "Content-Length: 18446744073709551616\r\n\r\n",
        "Content-Length: 0\r\nContent-Length: 0\r\n\r\n",
        "Transfer-Encoding: chunked\r\n\r\n",
        "Content-Length: 0\r\n\r\ntrailing",
        "Content-Length: 0\r\n\r\nGET / HTTP/1.1\r\nHost: wrong\r\n\r\n",
        "Content-Length: 4\r\n\r\nx",
    ] {
        let bytes = format!("GET / HTTP/1.1\r\nHost: {}\r\n{suffix}", server.address);
        server.raw(bytes.as_bytes()).error(400, "explorer.http");
    }
    server
        .raw(format!("GET / HTTP/1.0\r\nHost: {}\r\n\r\n", server.address).as_bytes())
        .error(400, "explorer.http");
    server.stop();
}

#[test]
#[allow(clippy::too_many_lines)] // Keep keyset state transitions and validation partitions together.
fn rows_replace_filters_keyset_pages_and_source_ordinals_are_exact_and_bounded() {
    let fixture = Fixture::small();
    let mut server = Server::start(&fixture);
    let first = server.query(
        &fixture,
        json!({"action":"rows","contains":"","stream":null,"after":null,"limit":2}),
    );
    assert_eq!(first.status, 200);
    let first = first.json();
    assert_eq!(first["generation"], fixture.generation);
    assert_eq!(
        first["entries"]
            .as_array()
            .unwrap()
            .iter()
            .map(|row| row["ordinal"].as_u64().unwrap())
            .collect::<Vec<_>>(),
        [0, 1]
    );
    assert_eq!(first["entries"][0]["identity"], "Owner__alpha");
    assert_eq!(first["entries"][1]["bytes"], 22);
    assert_eq!(first["next_after"], 1);
    assert_eq!(first["scanned"], 2);
    assert_eq!(first["stop_reason"], "limit");
    let last = server.query(&fixture, json!({"action":"rows","contains":"","stream":null,"after":first["next_after"],"limit":2})).json();
    assert_eq!(
        last["entries"]
            .as_array()
            .unwrap()
            .iter()
            .map(|row| row["ordinal"].as_u64().unwrap())
            .collect::<Vec<_>>(),
        [2, 3]
    );
    assert_eq!(last["next_after"], Value::Null);
    assert_eq!(last["stop_reason"], "complete");
    let empty = server
        .query(
            &fixture,
            json!({"action":"rows","contains":"","stream":null,"after":3,"limit":50}),
        )
        .json();
    assert_eq!(empty["entries"], json!([]));
    assert_eq!(empty["scanned"], 0);
    assert_eq!(empty["next_after"], Value::Null);
    let filter = server
        .query(
            &fixture,
            json!({"action":"rows","contains":"alpha","stream":"Blobs","after":null,"limit":50}),
        )
        .json();
    assert_eq!(filter["entries"].as_array().unwrap().len(), 1);
    assert_eq!(filter["entries"][0]["ordinal"], 2);
    assert_eq!(filter["entries"][0]["bytes"], 33);
    assert_eq!(filter["scanned"], 4);
    let replacement = server
        .query(
            &fixture,
            json!({"action":"rows","contains":"beta","stream":"Methods","after":null,"limit":50}),
        )
        .json();
    assert_eq!(replacement["entries"].as_array().unwrap().len(), 1);
    assert_eq!(replacement["entries"][0]["ordinal"], 1);
    let missing = server
        .query(
            &fixture,
            json!({"action":"rows","contains":"","stream":"Missing","after":null,"limit":50}),
        )
        .json();
    assert_eq!(missing["entries"], json!([]));
    assert_eq!(missing["stop_reason"], "complete");
    for (ordinal, identity, bytes) in [(0, "Owner__alpha", 11), (3, "Owner__omega", 44)] {
        let response = server.query(&fixture, json!({"action":"source","ordinal":ordinal}));
        assert_eq!(response.status, 200);
        let detail = response.json();
        assert_eq!(detail["row"]["ordinal"], ordinal);
        assert_eq!(detail["row"]["identity"], identity);
        assert_eq!(detail["row"]["bytes"], bytes);
        assert_eq!(detail["sources"]["status"], "unmapped");
        assert_eq!(detail["total_sources"], 0);
        assert_eq!(detail["sources"]["sources"], json!([]));
    }
    server
        .query(&fixture, json!({"action":"source","ordinal":4}))
        .error(400, "explorer.row");
    for query in [
        json!({"action":"rows","after":4}),
        json!({"action":"rows","after":u64::MAX}),
    ] {
        server.query(&fixture, query).error(400, "explorer.cursor");
    }
    for query in [
        json!({"action":"rows","limit":0}),
        json!({"action":"rows","limit":101}),
        json!({"action":"rows","contains":"x".repeat(1025)}),
        json!({"action":"rows","stream":"x".repeat(65)}),
    ] {
        server
            .query(&fixture, query)
            .error(413, "resource.explorer.query");
    }
    let allowed = server.query(
        &fixture,
        json!({"action":"rows","limit":100,"contains":"x".repeat(1024),"stream":"x".repeat(64)}),
    );
    assert_eq!(allowed.status, 200);
    assert_eq!(allowed.json()["entries"], json!([]));
    server.post("/api/query", &json!({"request_id":"stale","generation":"old","action":"rows","contains":"","stream":null,"after":null,"limit":50})).error(409, "explorer.generation");
    server.stop();
}

#[test]
fn full_identity_search_and_empty_bundle_are_not_preview_or_cursor_shortcuts() {
    let fixture = Fixture::new(
        &[row(&format!("{}TAIL", "é".repeat(300)), "Methods", 7)],
        None,
    );
    let mut server = Server::start(&fixture);
    let found = server
        .query(
            &fixture,
            json!({"action":"rows","contains":"TAIL","stream":null,"after":null,"limit":50}),
        )
        .json();
    assert_eq!(found["entries"].as_array().unwrap().len(), 1);
    assert_eq!(found["entries"][0]["identity"], "é".repeat(256));
    assert_eq!(found["entries"][0]["identity_bytes"], 604);
    assert_eq!(found["entries"][0]["truncated"], true);
    assert_eq!(found["entries"][0]["bytes"], 7);
    assert_eq!(found["stop_reason"], "complete");
    server.stop();
    let empty = Fixture::new(&[], None);
    let mut server = Server::start(&empty);
    let response = server.query(
        &empty,
        json!({"action":"rows","contains":"","stream":null,"after":null,"limit":50}),
    );
    assert_eq!(response.status, 200);
    assert_eq!(response.json()["entries"], json!([]));
    assert_eq!(response.json()["scanned"], 0);
    assert_eq!(response.json()["next_after"], Value::Null);
    server
        .query(&empty, json!({"action":"source","ordinal":0}))
        .error(400, "explorer.row");
    server
        .query(&empty, json!({"action":"rows","after":0}))
        .error(400, "explorer.cursor");
    server.stop();
}

fn graph_xml() -> String {
    let mut xml = String::from("<DirectedGraph><Nodes>");
    for id in 0..65 {
        write!(xml, "<Node Id=\"{id}\" Label=\"match-{id}\"/>").unwrap();
    }
    for (id, label) in [
        (100_u64, "target"),
        (200, "cycle-a"),
        (201, "cycle-b"),
        (999, "match-large"),
    ] {
        write!(xml, "<Node Id=\"{id}\" Label=\"{label}\"/>").unwrap();
    }
    xml.push_str("</Nodes><Links>");
    for id in 0..65 {
        write!(
            xml,
            "<Link Source=\"{id}\" Target=\"100\" Reason=\"{}\"/>",
            if id == 0 {
                String::new()
            } else {
                format!("because-{id}")
            }
        )
        .unwrap();
    }
    xml.push_str("<Link Source=\"200\" Target=\"201\" Reason=\"forward\"/><Link Source=\"201\" Target=\"200\" Reason=\"back\"/></Links></DirectedGraph>");
    xml
}

#[test]
#[allow(clippy::too_many_lines)] // Pages and witnesses share a single graph generation.
fn http_graph_search_incoming_and_why_preserve_string_ids_pages_reasons_and_cycles() {
    let fixture = Fixture::new(&[], Some(&graph_xml()));
    let mut server = Server::start(&fixture);
    let first = server.query(&fixture, json!({"action":"graph_search","graph":"scan_index","query":"match","mode":"prefix","after_id":null}));
    assert_eq!(first.status, 200);
    let first = first.json();
    assert_eq!(first["schema"], "vitnet.dgml-search.v1");
    assert_eq!(first["entries"].as_array().unwrap().len(), 50);
    assert_eq!(first["entries"][0]["node_id"], "0");
    assert_eq!(first["next_after_id"], "49");
    assert_eq!(first["stop_reason"], "limit");
    let rest = server.query(&fixture, json!({"action":"graph_search","graph":"scan_index","query":"match","mode":"prefix","after_id":first["next_after_id"]})).json();
    assert_eq!(rest["entries"].as_array().unwrap().len(), 16);
    assert_eq!(rest["entries"][0]["node_id"], "50");
    assert_eq!(rest["entries"][15]["node_id"], "999");
    assert_eq!(rest["stop_reason"], "complete");
    assert_eq!(rest["next_after_id"], Value::Null);
    let contains = server.query(&fixture, json!({"action":"graph_search","graph":"scan_index","query":"large","mode":"contains","after_id":null}));
    assert_eq!(contains.status, 200);
    assert_eq!(
        contains.json()["entries"]
            .as_array()
            .unwrap()
            .iter()
            .map(|entry| entry["node_id"].as_str().unwrap())
            .collect::<Vec<_>>(),
        ["999"]
    );
    for (mode, query, ids) in [
        ("exact", "match-large", vec!["999"]),
        ("exact", "match", vec![]),
        ("id", "999", vec!["999"]),
        ("id", "998", vec![]),
    ] {
        let response = server.query(&fixture, json!({"action":"graph_search","graph":"scan_index","query":query,"mode":mode,"after_id":null}));
        assert_eq!(response.status, 200);
        assert_eq!(
            response.json()["entries"]
                .as_array()
                .unwrap()
                .iter()
                .map(|entry| entry["node_id"].as_str().unwrap())
                .collect::<Vec<_>>(),
            ids
        );
    }
    let incoming = server.query(
        &fixture,
        json!({"action":"incoming","graph":"scan_index","node_id":"100","after_edge":null}),
    );
    assert_eq!(incoming.status, 200);
    let incoming = incoming.json();
    assert_eq!(incoming["schema"], "vitnet.dgml-incoming.v1");
    assert_eq!(incoming["total_edges"], 65);
    assert_eq!(incoming["edges"].as_array().unwrap().len(), 50);
    assert_eq!(incoming["edges"][0]["source_id"], "0");
    assert_eq!(incoming["edges"][0]["reason"], "");
    assert_eq!(incoming["edges"][1]["reason"], "because-1");
    assert_eq!(incoming["next_after_edge"], "49");
    let remaining = server.query(&fixture, json!({"action":"incoming","graph":"scan_index","node_id":"100","after_edge":incoming["next_after_edge"]})).json();
    assert_eq!(remaining["edges"].as_array().unwrap().len(), 15);
    assert_eq!(remaining["edges"][0]["source_id"], "50");
    assert_eq!(remaining["edges"][14]["source_id"], "64");
    assert_eq!(remaining["next_after_edge"], Value::Null);
    let why = server
        .query(
            &fixture,
            json!({"action":"why","graph":"scan_index","node_id":"100"}),
        )
        .json();
    assert_eq!(why["schema"], "vitnet.dgml-why.v1");
    assert_eq!(why["generation"], first["generation"]);
    assert_eq!(why["node"]["node_id"], "100");
    assert_eq!(why["paths"].as_array().unwrap().len(), 3);
    assert_eq!(why["stop_reason"], "max_paths");
    assert_eq!(why["paths"][0]["nodes"][0]["node_id"], "0");
    assert_eq!(why["paths"][0]["reasons"][0], "");
    assert!(
        why["caveat"]
            .as_str()
            .unwrap()
            .contains("conjunctions, not independent sufficient causes")
    );
    let cycle = server
        .query(
            &fixture,
            json!({"action":"why","graph":"scan_index","node_id":"201"}),
        )
        .json();
    assert_eq!(cycle["paths"], json!([]));
    assert_eq!(cycle["stop_reason"], "complete");
    assert_eq!(cycle["repeated_nodes"], 1);
    assert_eq!(cycle["visited_nodes"], 2);
    assert_eq!(cycle["examined_edges"], 2);
    assert!(cycle["caveat"].as_str().unwrap().contains("not byte sizes"));
    for query in [
        json!({"action":"graph_search","graph":"scan_index","query":"match","mode":"prefix","after_id":"-1"}),
        json!({"action":"incoming","graph":"scan_index","node_id":"not-id","after_edge":null}),
        json!({"action":"incoming","graph":"scan_index","node_id":"100","after_edge":"18446744073709551616"}),
        json!({"action":"why","graph":"scan_index","node_id":"1.5"}),
    ] {
        server.query(&fixture, query).error(400, "explorer.cursor");
    }
    server
        .query(
            &fixture,
            json!({"action":"why","graph":"other","node_id":"100"}),
        )
        .error(400, "explorer.graph.kind");
    server
        .query(
            &fixture,
            json!({"action":"why","graph":"codegen_index","node_id":"100"}),
        )
        .error(400, "explorer.graph.missing");
    for term in ["", &"x".repeat(1025)] {
        server.query(&fixture, json!({"action":"graph_search","graph":"scan_index","query":term,"mode":"contains","after_id":null})).error(400, "explorer.search");
    }
    server.query(&fixture, json!({"action":"graph_search","graph":"scan_index","query":"match","mode":"invalid","after_id":null})).error(400, "explorer.request.json");
    server.stop();
}

#[test]
fn four_held_connections_exhaust_budget_and_release_after_completion() {
    let fixture = Fixture::small();
    let mut server = Server::start(&fixture);
    let mut held = Vec::new();
    for _ in 0..4 {
        let mut stream = server.connect();
        stream
            .write_all(
                format!("GET /style.css HTTP/1.1\r\nHost: {}\r\n", server.address).as_bytes(),
            )
            .unwrap();
        held.push(stream);
    }
    let response = server.request("GET", "/style.css", b"", "");
    assert_eq!(response.status, 429);
    assert_eq!(response.body, b"Connection budget exhausted");
    for mut stream in held {
        stream.write_all(b"Content-Length: 0\r\n\r\n").unwrap();
        stream.shutdown(Shutdown::Write).unwrap();
        let response = Response::read(&mut stream);
        assert_eq!(
            response.status,
            200,
            "held response: {}",
            String::from_utf8_lossy(&response.body)
        );
        assert!(response.headers.contains("text/css"));
    }
    let response = server.query(&fixture, json!({"action":"source","ordinal":0}));
    assert_eq!(response.status, 200);
    assert_eq!(response.json()["row"]["identity"], "Owner__alpha");
    server.stop();
}

#[test]
fn stale_live_identity_and_corrupt_ordinal_ranges_fail_without_returning_rows() {
    for mutation in [
        "equal-offsets",
        "past-end",
        "oversized",
        "json-range",
        "reverse-offsets",
        "identity-json",
        "identity-length",
    ] {
        let fixture = Fixture::small();
        let mut server = Server::start(&fixture);
        if mutation.starts_with("identity") {
            let path = fixture.index.join("identities.ndjson");
            let mut bytes = fs::read(&path).unwrap();
            if mutation == "identity-length" {
                bytes.push(b' ');
            } else {
                bytes[0] = b'!';
            }
            fs::write(path, bytes).unwrap();
            server
                .query(&fixture, json!({"action":"source","ordinal":0}))
                .error(409, "explorer.source.stale");
        } else {
            let path = fixture.bundle.join("offsets.bin");
            let mut bytes = fs::read(&path).unwrap();
            if mutation == "json-range" {
                bytes[..8].copy_from_slice(&1_u64.to_le_bytes());
                fs::write(path, bytes).unwrap();
                server
                    .query(&fixture, json!({"action":"source","ordinal":0}))
                    .error(400, "explorer.row.json");
                server.stop();
                continue;
            }
            if mutation == "reverse-offsets" {
                bytes[..8].copy_from_slice(&2_u64.to_le_bytes());
            }
            let end = match mutation {
                "equal-offsets" | "reverse-offsets" => 0,
                "past-end" => u64::MAX,
                "oversized" => MEMORY / 64 + 1,
                _ => unreachable!(),
            };
            bytes[8..16].copy_from_slice(&end.to_le_bytes());
            fs::write(path, bytes).unwrap();
            server
                .query(&fixture, json!({"action":"source","ordinal":0}))
                .error(400, "explorer.offsets");
        }
        server.stop();
    }
}

#[test]
fn filtered_empty_partial_pages_preserve_progress_until_complete() {
    let rows: Vec<_> = (0..100_001)
        .map(|id| row(&format!("Owner__{id:06}"), "Methods", 1))
        .collect();
    let fixture = Fixture::new(&rows, None);
    let mut server = Server::start(&fixture);
    let mut after = Value::Null;
    let mut previous = None;
    let mut total = 0_u64;
    loop {
        let response = server.query(
            &fixture,
            json!({"action":"rows","contains":"no-match","stream":null,"after":after,"limit":50}),
        );
        assert_eq!(response.status, 200);
        let page = response.json();
        assert_eq!(page["entries"], json!([]));
        let scanned = page["scanned"].as_u64().unwrap();
        assert!(scanned <= 100_000);
        total += scanned;
        if page["stop_reason"] == "complete" {
            assert_eq!(page["next_after"], Value::Null);
            break;
        }
        assert!(["timeout", "max_scanned"].contains(&page["stop_reason"].as_str().unwrap()));
        let next = page["next_after"]
            .as_u64()
            .expect("partial empty page must retain cursor");
        assert!(previous.is_none_or(|last| next > last));
        assert_eq!(next + 1, total);
        previous = Some(next);
        after = json!(next);
        assert!(total <= 100_001);
    }
    assert_eq!(total, 100_001);
    assert!(
        previous.is_some(),
        "bounded query must produce an empty partial page"
    );
    server.stop();
    // Temporary fixture lives through child shutdown; no named pipe is ever used.
    assert!(fixture.root.path().exists());
}

#[test]
fn response_budget_rejects_large_source_details_not_present_in_bootstrap_projection() {
    let mut evidence = Evidence {
        schema: EVIDENCE_SCHEMA.into(),
        label: "bounded bootstrap".into(),
        ..Evidence::default()
    };
    for id in 0..50 {
        evidence.sources.push(Source {
            assembly: "App".into(),
            type_name: "Widget".into(),
            member: Some("Run".into()),
            path: PathBuf::from(format!("missing-{id}.cs")),
            line: 1,
            end_line: 1,
            kind: "method".into(),
            attributes: vec!["\\".repeat(1024); 40],
            ..Source::default()
        });
    }
    evidence.mappings.push(Mapping {
        stream: "Methods".into(),
        identity: "App_Widget__Run".into(),
        assembly: "App".into(),
        source_paths: evidence
            .sources
            .iter()
            .map(|source| source.path.clone())
            .collect(),
        basis: "synthetic exact association".into(),
    });
    let mut rows: Vec<_> = (0..100)
        .map(|id| row(&format!("Other__{id}"), "Methods", 100))
        .collect();
    rows.push(row("App_Widget__Run", "Methods", 1));
    let fixture = Fixture::with_evidence(&rows, None, evidence);
    let mut server = Server::start(&fixture);
    let bootstrap = server.post("/api/snapshot", &json!({}));
    assert_eq!(bootstrap.status, 200);
    assert_eq!(bootstrap.json()["coverage"]["contributors_shown"], 100);
    assert!(bootstrap.json()["details"].get("100").is_none());
    server
        .query(&fixture, json!({"action":"source","ordinal":100}))
        .error(413, "resource.explorer.response");
    // Rejection releases the query slot rather than poisoning the next request.
    let following = server.query(&fixture, json!({"action":"source","ordinal":0}));
    assert_eq!(following.status, 200);
    assert_eq!(following.json()["row"]["identity"], "Other__0");
    server.stop();
}

#[test]
fn http_why_enforces_depth_visit_and_edge_budgets_without_timing_assertions() {
    let mut xml = String::from("<DirectedGraph><Nodes>");
    for id in 0..5001 {
        write!(xml, "<Node Id=\"{id}\" Label=\"cycle-{id}\"/>").unwrap();
    }
    for id in [6000, 6500, 7000] {
        write!(xml, "<Node Id=\"{id}\" Label=\"budget-{id}\"/>").unwrap();
    }
    for id in 8000..8015 {
        write!(xml, "<Node Id=\"{id}\" Label=\"deep-{id}\"/>").unwrap();
    }
    xml.push_str("</Nodes><Links>");
    for id in 0..5001 {
        write!(xml, "<Link Source=\"{id}\" Target=\"{id}\" Reason=\"cycle\"/><Link Source=\"{id}\" Target=\"6000\" Reason=\"wide\"/>").unwrap();
    }
    xml.push_str("<Link Source=\"6500\" Target=\"6500\" Reason=\"cycle\"/>");
    for _ in 0..25_001 {
        xml.push_str("<Link Source=\"6500\" Target=\"7000\" Reason=\"parallel\"/>");
    }
    for id in 8000..8014 {
        write!(
            xml,
            "<Link Source=\"{id}\" Target=\"{}\" Reason=\"deep\"/>",
            id + 1
        )
        .unwrap();
    }
    xml.push_str("</Links></DirectedGraph>");
    let fixture = Fixture::new(&[], Some(&xml));
    let mut server = Server::start(&fixture);
    let wide = server.query(
        &fixture,
        json!({"action":"why","graph":"scan_index","node_id":"6000"}),
    );
    assert_eq!(wide.status, 200);
    let wide = wide.json();
    assert_eq!(wide["stop_reason"], "max_visited");
    assert_eq!(wide["visited_nodes"], 5000);
    assert_eq!(wide["paths"], json!([]));
    let edges = server.query(
        &fixture,
        json!({"action":"why","graph":"scan_index","node_id":"7000"}),
    );
    assert_eq!(edges.status, 200);
    let edges = edges.json();
    assert_eq!(edges["stop_reason"], "max_edges");
    assert_eq!(edges["examined_edges"], 25_000);
    assert_eq!(edges["paths"], json!([]));
    let depth = server.query(
        &fixture,
        json!({"action":"why","graph":"scan_index","node_id":"8014"}),
    );
    assert_eq!(depth.status, 200);
    let depth = depth.json();
    assert_eq!(depth["stop_reason"], "max_depth");
    assert_eq!(depth["paths"], json!([]));
    server.stop();
}

#[test]
fn changed_graph_generation_is_rejected_even_when_bundle_index_hash_is_consistent() {
    let mut fixture = Fixture::new(&[], Some(&graph_xml()));
    let mut imported = vitnet_attribution::open_index(&fixture.index, MEMORY).unwrap();
    imported
        .artifacts
        .iter_mut()
        .find(|artifact| artifact.kind == "scan_index")
        .unwrap()
        .graph_generation = Some("not-the-imported-generation".into());
    write_json(&fixture.index.join("index.json"), &imported);
    let mut manifest: data::BundleManifest =
        serde_json::from_slice(&fs::read(fixture.bundle.join("bundle.json")).unwrap()).unwrap();
    manifest.index_blake3 = vitnet_attribution::hash_file(&fixture.index.join("index.json"))
        .unwrap()
        .1;
    let snapshot_path = fixture.bundle.join("snapshot.json");
    let mut snapshot: Value = serde_json::from_slice(&fs::read(&snapshot_path).unwrap()).unwrap();
    snapshot["generation"] = Value::Null;
    let mut fingerprint = blake3::Hasher::new();
    fingerprint.update(b"vitnet.explorer-generation.v1\0");
    fingerprint.update(manifest.index_blake3.as_bytes());
    fingerprint.update(manifest.identities_blake3.as_bytes());
    fingerprint.update(&serde_json::to_vec(&snapshot).unwrap());
    manifest.generation = fingerprint.finalize().to_hex().to_string();
    fixture.generation.clone_from(&manifest.generation);
    snapshot["generation"] = json!(manifest.generation);
    write_json(&snapshot_path, &snapshot);
    manifest.snapshot_blake3 = vitnet_attribution::hash_file(&snapshot_path).unwrap().1;
    write_json(&fixture.bundle.join("bundle.json"), &manifest);
    let mut server = Server::start(&fixture);
    server
        .query(
            &fixture,
            json!({"action":"why","graph":"scan_index","node_id":"100"}),
        )
        .error(409, "explorer.graph.stale");
    server.stop();
}

#[test]
fn owner_and_assembly_filters_replace_selection_including_generic_ambiguous_and_lossy_rows() {
    let mut evidence = Evidence {
        schema: EVIDENCE_SCHEMA.into(),
        ..Evidence::default()
    };
    for (identity, assembly) in [
        ("Owner<int>__a", "App"),
        ("Other__b", "App"),
        ("Other__b", "Second"),
    ] {
        evidence.mappings.push(Mapping {
            stream: "Methods".into(),
            identity: identity.into(),
            assembly: assembly.into(),
            source_paths: vec![],
            basis: "asserted fixture".into(),
        });
    }
    let mut lossy = row("Lossy__c", "Methods", 3);
    lossy.identity_lossy = true;
    let fixture = Fixture::with_evidence(
        &[
            row("Owner<int>__a", "Methods", 1),
            row("Other__b", "Methods", 2),
            lossy,
            row("Absent__d", "Methods", 4),
        ],
        None,
        evidence,
    );
    let mut server = Server::start(&fixture);
    for (filter, ordinals) in [
        (json!({"owner":"Owner"}), vec![0]),
        (json!({"owner":"Missing"}), vec![]),
        (json!({"assembly":"App"}), vec![0]),
        (json!({"assembly":"_ambiguous"}), vec![1]),
        (json!({"assembly":"_unmapped"}), vec![2, 3]),
        (json!({"assembly":"Missing"}), vec![]),
        (json!({"owner":"Other","assembly":"_ambiguous"}), vec![1]),
        (json!({"owner":"Other","assembly":"App"}), vec![]),
    ] {
        let mut query = filter;
        query["action"] = json!("rows");
        query["limit"] = json!(50);
        let response = server.query(&fixture, query);
        assert_eq!(response.status, 200);
        assert_eq!(
            response.json()["entries"]
                .as_array()
                .unwrap()
                .iter()
                .map(|row| row["ordinal"].as_u64().unwrap())
                .collect::<Vec<_>>(),
            ordinals
        );
        assert_eq!(response.json()["stop_reason"], "complete");
    }
    for field in ["owner", "assembly"] {
        let mut query = json!({"action":"rows","limit":50});
        query[field] = json!("x".repeat(4096));
        let response = server.query(&fixture, query.clone());
        assert_eq!(response.status, 200);
        assert_eq!(response.json()["entries"], json!([]));
        query[field] = json!("x".repeat(4097));
        server
            .query(&fixture, query)
            .error(413, "resource.explorer.query");
    }
    server.stop();
}

#[test]
fn source_row_size_guard_is_distinct_from_file_end_and_json_integrity_guards() {
    let rows: Vec<_> = (0..2100)
        .map(|id| row(&format!("Owner__{id:04}{}", "x".repeat(1024)), "Methods", 1))
        .collect();
    let fixture = Fixture::new(&rows, None);
    let mut server = Server::start(&fixture);
    let end = MEMORY / 64 + 1;
    assert!(
        fs::metadata(fixture.index.join("identities.ndjson"))
            .unwrap()
            .len()
            > end
    );
    let path = fixture.bundle.join("offsets.bin");
    let mut offsets = fs::read(&path).unwrap();
    offsets[8..16].copy_from_slice(&end.to_le_bytes());
    fs::write(path, offsets).unwrap();
    server
        .query(&fixture, json!({"action":"source","ordinal":0}))
        .error(400, "explorer.offsets");
    server.stop();
}

#[test]
fn live_index_drift_has_its_own_stale_rejection_without_timestamp_sleep() {
    let fixture = Fixture::small();
    let mut server = Server::start(&fixture);
    let path = fixture.index.join("index.json");
    let previous = fs::metadata(&path).unwrap().modified().unwrap();
    let mut bytes = fs::read(&path).unwrap();
    bytes.push(b' ');
    fs::write(&path, bytes).unwrap();
    let distinct = std::time::SystemTime::UNIX_EPOCH + Duration::from_secs(86_400);
    assert_ne!(previous, distinct);
    std::fs::File::options()
        .write(true)
        .open(&path)
        .unwrap()
        .set_times(std::fs::FileTimes::new().set_modified(distinct))
        .unwrap();
    server
        .query(&fixture, json!({"action":"source","ordinal":0}))
        .error(409, "explorer.source.stale");
    server.stop();
}

#[test]
#[allow(clippy::too_many_lines)] // Prove paired public denial and exact authenticated projection.
fn live_bootstrap_is_public_limits_only_and_snapshot_requires_independent_capability() {
    let private_path = PathBuf::from("PRIVATE-SOURCE-FILE.cs");
    let private_identity = "PrivateOwner__PRIVATE-METHOD";
    let fixture = Fixture::with_evidence(
        &[row(private_identity, "Methods", 41)],
        None,
        Evidence {
            schema: EVIDENCE_SCHEMA.into(),
            label: "PRIVATE-TITLE".into(),
            sources: vec![Source {
                assembly: "PrivateAssembly".into(),
                type_name: "PrivateType".into(),
                path: private_path.clone(),
                line: 3,
                end_line: 7,
                ..Source::default()
            }],
            mappings: vec![Mapping {
                stream: "Methods".into(),
                identity: private_identity.into(),
                assembly: "PrivateAssembly".into(),
                source_paths: vec![private_path],
                basis: "private asserted association".into(),
            }],
            ..Evidence::default()
        },
    );
    let mut server = Server::start(&fixture);
    let public = server.request("GET", "/", b"", "");
    assert_eq!(public.status, 200);
    let page = String::from_utf8(public.body).unwrap();
    let bootstrap: Value = serde_json::from_str(
        page.split_once("const SNAPSHOT = ")
            .unwrap()
            .1
            .lines()
            .next()
            .unwrap()
            .strip_suffix(';')
            .unwrap(),
    )
    .unwrap();
    assert_eq!(
        bootstrap,
        json!({
            "schema":"vitnet.explorer-snapshot.v1",
            "bootstrap":true,
            "limits":{"graph_nodes":200,"graph_edges":500,"page_rows":100}
        })
    );
    for private in [
        "PRIVATE-TITLE",
        "PRIVATE-SOURCE-FILE.cs",
        "PrivateAssembly",
        "PrivateType",
        private_identity,
        &fixture.generation,
        &server.token,
    ] {
        assert!(!page.contains(private), "public bootstrap leaks {private}");
    }
    let nonce = public
        .headers
        .split("script-src 'nonce-")
        .nth(1)
        .unwrap()
        .split('\'')
        .next()
        .unwrap();
    assert_eq!(nonce.len(), 64);
    assert!(nonce.bytes().all(|byte| byte.is_ascii_hexdigit()));
    assert_ne!(nonce, server.token);
    for tag in ["<script", "<style"] {
        let openings: Vec<_> = page
            .split(tag)
            .skip(1)
            .map(|part| part.split('>').next().unwrap())
            .collect();
        assert_ne!(openings, [] as [&str; 0]);
        for opening in openings {
            assert!(opening.contains(&format!("nonce=\"{nonce}\"")));
        }
    }
    server
        .request(
            "POST",
            "/api/snapshot",
            b"{}",
            "Content-Type: application/json\r\n",
        )
        .error(403, "explorer.authorization");
    // The public CSP nonce must not double as the private session capability.
    server
        .request(
            "POST",
            "/api/snapshot",
            b"{}",
            &format!("Authorization: Bearer {nonce}\r\nContent-Type: application/json\r\n"),
        )
        .error(403, "explorer.authorization");
    let authenticated = server.post("/api/snapshot", &json!({}));
    assert_eq!(authenticated.status, 200);
    assert!(
        authenticated
            .headers
            .contains("Content-Type: application/json")
    );
    let actual = authenticated.json();
    assert_eq!(actual["schema"], "vitnet.explorer-snapshot.v1");
    assert_eq!(actual["generation"], fixture.generation);
    assert_eq!(actual["title"], "PRIVATE-TITLE");
    assert!(actual.get("bootstrap").is_none());
    assert_eq!(actual["contributors"][0]["identity"], private_identity);
    assert_eq!(
        actual["details"]["0"]["sources"]["sources"][0]["path"],
        json!(fixture.root.path().join("PRIVATE-SOURCE-FILE.cs"))
    );
    let prepared: Value =
        serde_json::from_slice(&fs::read(fixture.bundle.join("snapshot.json")).unwrap()).unwrap();
    assert_eq!(
        actual, prepared,
        "authenticated snapshot is the exact prepared projection"
    );
    server.stop();
}

#[test]
#[allow(clippy::too_many_lines)] // Each decoy violates one of the four intersected predicates.
fn combined_filters_intersect_complete_identity_stream_assembly_and_exact_owner() {
    let owner = format!("Owner{}", "o".repeat(520));
    let assembly = format!("Assembly{}A", "a".repeat(520));
    let other_assembly = format!("Assembly{}B", "a".repeat(520));
    let member = "x".repeat(600);
    let identity = format!("{owner}<int>__{member}TAIL");
    let mut rows = vec![
        row(&identity, "Methods", 11),
        row(&identity, "Blobs", 12),
        row(&format!("{owner}<int>__{member}MISS"), "Methods", 13),
        row(&format!("{owner}Extra<int>__{member}TAIL"), "Methods", 14),
        row(&format!("{owner}<int>__{member}TAIL_ASM"), "Methods", 15),
        row(&format!("{owner}<int>__{member}TAIL_AMBIG"), "Methods", 16),
        row(
            &format!("{owner}<int>__{member}TAIL_UNMAPPED"),
            "Methods",
            17,
        ),
        row(&format!("{owner}<int>__{member}TAIL_LOSSY"), "Methods", 18),
        row("PlainOwner__member<T>TAIL", "Methods", 19),
    ];
    rows[7].identity_lossy = true;
    let mut evidence = Evidence {
        schema: EVIDENCE_SCHEMA.into(),
        ..Evidence::default()
    };
    for (ordinal, assemblies) in [
        (0, vec![&assembly]),
        (1, vec![&assembly]),
        (2, vec![&assembly]),
        (3, vec![&assembly]),
        (4, vec![&other_assembly]),
        (5, vec![&assembly, &other_assembly]),
        // A lossy row stays _unmapped even when an asserted mapping exists.
        (7, vec![&assembly]),
        (8, vec![&assembly]),
    ] {
        for mapped_assembly in assemblies {
            evidence.mappings.push(Mapping {
                stream: rows[ordinal].stream.clone(),
                identity: rows[ordinal].identity.clone(),
                assembly: mapped_assembly.clone(),
                source_paths: vec![],
                basis: "complete-identity asserted association".into(),
            });
        }
    }
    let fixture = Fixture::with_evidence(&rows, None, evidence);
    let mut server = Server::start(&fixture);
    for (assembly_filter, owner_filter, expected) in [
        (assembly.as_str(), owner.as_str(), vec![0]),
        (other_assembly.as_str(), owner.as_str(), vec![4]),
        ("_ambiguous", owner.as_str(), vec![5]),
        ("_unmapped", owner.as_str(), vec![6, 7]),
        (assembly.as_str(), "Owner", vec![]),
        (assembly.as_str(), "PlainOwner", vec![8]),
    ] {
        let response = server.query(
            &fixture,
            json!({
                "action":"rows","assembly":assembly_filter,"stream":"Methods",
                "contains":"TAIL","owner":owner_filter,"after":null,"limit":50
            }),
        );
        assert_eq!(response.status, 200);
        let page = response.json();
        assert_eq!(
            page["entries"]
                .as_array()
                .unwrap()
                .iter()
                .map(|entry| entry["ordinal"].as_u64().unwrap())
                .collect::<Vec<_>>(),
            expected,
            "assembly={assembly_filter}, owner={owner_filter}"
        );
        assert_eq!(page["scanned"], 9);
        assert_eq!(page["stop_reason"], "complete");
        assert_eq!(page["next_after"], Value::Null);
        if expected == [0] {
            let entry = &page["entries"][0];
            assert_eq!(entry["identity"], &identity[..512]);
            assert_eq!(entry["identity_bytes"], identity.len());
            assert_eq!(entry["truncated"], true);
            assert_eq!(entry["bytes"], 11);
            assert_eq!(entry["stream"], "Methods");
            assert_eq!(
                entry["raw_identity_blake3"],
                blake3::hash(identity.as_bytes()).to_hex().to_string()
            );
            assert!(!entry["identity"].as_str().unwrap().contains("TAIL"));
        }
    }
    server.stop();
}

#[test]
fn fragmented_headers_and_body_are_accepted_by_owned_loopback_server() {
    let fixture = Fixture::small();
    let mut server = Server::start(&fixture);
    let body = serde_json::to_vec(&json!({
        "request_id":"fragmented","generation":fixture.generation,
        "action":"rows","stream":"Methods","contains":"beta","limit":50
    }))
    .unwrap();
    let header = format!(
        "POST /api/query HTTP/1.1\r\nHost: {}\r\n{}Content-Length: {}\r\n\r\n",
        server.address,
        server.auth(),
        body.len()
    );
    let mut stream = server.connect();
    stream.set_nodelay(true).unwrap();
    // Intentional fragment delays exercise blocking reads; they do not race
    // query completion or assert that any response arrives within X milliseconds.
    for fragment in [
        &header.as_bytes()[..17],
        &header.as_bytes()[17..header.len() - 1],
        &header.as_bytes()[header.len() - 1..],
        &body[..9],
        &body[9..body.len() - 2],
    ] {
        stream.write_all(fragment).unwrap();
        std::thread::sleep(Duration::from_millis(30));
    }
    stream.write_all(&body[body.len() - 2..]).unwrap();
    stream.shutdown(Shutdown::Write).unwrap();
    let response = Response::read(&mut stream);
    assert_eq!(
        response.status,
        200,
        "fragmented response: {}",
        String::from_utf8_lossy(&response.body)
    );
    let page = response.json();
    assert_eq!(page["generation"], fixture.generation);
    assert_eq!(page["entries"].as_array().unwrap().len(), 1);
    assert_eq!(page["entries"][0]["ordinal"], 1);
    assert_eq!(page["entries"][0]["identity"], "Owner__beta");
    assert_eq!(page["entries"][0]["bytes"], 22);
    assert_eq!(page["scanned"], 4);
    assert_eq!(page["stop_reason"], "complete");
    assert_eq!(page["next_after"], Value::Null);
    let followup = server.query(&fixture, json!({"action":"source","ordinal":0}));
    assert_eq!(followup.status, 200);
    assert_eq!(followup.json()["row"]["identity"], "Owner__alpha");
    server.stop();
}

//! Public investigation regressions against independently specified fixtures.
//! Approved HTTP exception: ephemeral loopback, owned children, bounded I/O only.
use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};
use vitnet_attribution::model::{
    Artifact, Assembly, EVIDENCE_SCHEMA, Evidence, ManagedType, Mapping, Package, Resource, Source,
};
use vitnet_cli::explorer::data;
use vitnet_dgml::{IndexControl, IndexOptions, build_index};
use vitnet_mstat::CoalescedIdentity;

#[allow(dead_code)]
#[path = "../../vitnet-attribution/tests/common/mod.rs"]
mod common;

const MEMORY: u64 = 128 << 20;
const WAIT: Duration = Duration::from_secs(15);
const BODY_LIMIT: usize = 2 << 20;

fn write_json(path: &Path, value: &impl serde::Serialize) {
    fs::write(path, serde_json::to_vec(value).unwrap()).unwrap();
}

fn evidence() -> Evidence {
    Evidence {
        schema: EVIDENCE_SCHEMA.into(),
        label: "independent investigation fixture".into(),
        ..Evidence::default()
    }
}

fn row(identity: &str, stream: &str, bytes: u64) -> CoalescedIdentity {
    CoalescedIdentity {
        identity: identity.into(),
        stream: stream.into(),
        bytes,
        accounted: true,
        identity_lossy: false,
        records: 1,
        raw_identity_blake3: blake3::hash(identity.as_bytes()).to_hex().to_string(),
    }
}

fn seed() -> Vec<CoalescedIdentity> {
    let mut rows: Vec<_> = [10, 90, 90, 120, 0, 1000, 45]
        .into_iter()
        .enumerate()
        .map(|(ordinal, bytes)| {
            row(
                &format!("App_Box<int>__Run<V{ordinal}>"),
                match ordinal {
                    5 => "Blobs",
                    6 => "Types",
                    _ => "Methods",
                },
                bytes,
            )
        })
        .collect();
    rows[1].records = 2;
    rows[5].accounted = false;
    rows
}

fn mapping(stream: &str, identity: &str, assembly: &str, paths: Vec<PathBuf>) -> Mapping {
    Mapping {
        stream: stream.into(),
        identity: identity.into(),
        assembly: assembly.into(),
        source_paths: paths,
        basis: "fixed asserted fixture".into(),
    }
}

fn source(root: &Path, file: &str, assembly: &str, type_name: &str) -> Source {
    Source {
        assembly: assembly.into(),
        type_name: type_name.into(),
        member: Some("Run".into()),
        path: root.join(file),
        line: 7,
        end_line: 12,
        kind: "method".into(),
        ..Source::default()
    }
}

struct Fixture {
    root: tempfile::TempDir,
    index: PathBuf,
    bundle: PathBuf,
    generation: String,
}

impl Fixture {
    fn new(rows: &[CoalescedIdentity]) -> Self {
        Self::with(rows, |_| (evidence(), Vec::new()))
    }

    fn with(
        rows: &[CoalescedIdentity],
        make: impl FnOnce(&Path) -> (Evidence, Vec<Evidence>),
    ) -> Self {
        let root = tempfile::tempdir().unwrap();
        let (base, extras) = make(root.path());
        let manifest = root.path().join("evidence.json");
        write_json(&manifest, &base);
        let index = root.path().join("index");
        let mut imported = vitnet_attribution::import(&manifest, &index, MEMORY, false).unwrap();
        let mut payload = Vec::new();
        for entry in rows {
            payload.extend(serde_json::to_vec(entry).unwrap());
            payload.push(b'\n');
        }
        fs::write(index.join("identities.ndjson"), &payload).unwrap();
        imported.identities = u64::try_from(rows.len()).unwrap();
        imported.identities_blake3 = blake3::hash(&payload).to_hex().to_string();
        write_json(&index.join("index.json"), &imported);
        let paths: Vec<_> = extras
            .iter()
            .enumerate()
            .map(|(n, extra)| {
                let path = root.path().join(format!("supplemental-{n}.json"));
                write_json(&path, extra);
                path
            })
            .collect();
        let bundle = root.path().join("bundle");
        let prepared = data::prepare(
            &index,
            &bundle,
            &paths,
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

    fn base_bundle(&self) -> (PathBuf, String) {
        let path = self.root.path().join("base-only");
        let prepared = data::prepare(
            &self.index,
            &path,
            &[],
            None,
            &[],
            "scan_index",
            MEMORY,
            &IndexControl::default(),
        )
        .unwrap();
        (path, prepared.generation)
    }

    fn legacy(&mut self, remove_catalogs: bool) {
        let mut manifest: Value =
            serde_json::from_slice(&fs::read(self.bundle.join("bundle.json")).unwrap()).unwrap();
        let mut snapshot: Value =
            serde_json::from_slice(&fs::read(self.bundle.join("snapshot.json")).unwrap()).unwrap();
        for value in [&mut manifest, &mut snapshot] {
            value.as_object_mut().unwrap().remove("ranking");
            if remove_catalogs {
                for name in ["scopes", "assembly_links"] {
                    value["datasets"].as_object_mut().unwrap().remove(name);
                }
            }
        }
        snapshot["generation"] = Value::Null;
        let mut hash = blake3::Hasher::new();
        hash.update(b"vitnet.explorer-generation.v1\0");
        hash.update(manifest["index_blake3"].as_str().unwrap().as_bytes());
        hash.update(manifest["identities_blake3"].as_str().unwrap().as_bytes());
        hash.update(&serde_json::to_vec(&snapshot).unwrap());
        self.generation = hash.finalize().to_hex().to_string();
        snapshot["generation"] = json!(self.generation);
        manifest["generation"] = json!(self.generation);
        let encoded = serde_json::to_vec(&snapshot).unwrap();
        manifest["snapshot_blake3"] = json!(blake3::hash(&encoded).to_hex().to_string());
        fs::write(self.bundle.join("snapshot.json"), encoded).unwrap();
        write_json(&self.bundle.join("bundle.json"), &manifest);
    }
}

struct Response {
    status: u16,
    body: Vec<u8>,
}

impl Response {
    fn read(stream: &mut TcpStream) -> Self {
        let deadline = Instant::now() + WAIT;
        let mut bytes = Vec::new();
        let budget = BODY_LIMIT + 16_384;
        loop {
            let remaining = deadline
                .checked_duration_since(Instant::now())
                .expect("owned response deadline");
            stream.set_read_timeout(Some(remaining)).unwrap();
            let mut buffer = [0; 8192];
            match stream.read(&mut buffer) {
                Ok(0) => break,
                Ok(count) => {
                    bytes.extend_from_slice(&buffer[..count]);
                    assert!(bytes.len() <= budget, "response read budget exceeded");
                }
                Err(error) if error.kind() == std::io::ErrorKind::ConnectionReset => break,
                Err(error) => panic!("owned HTTP read failed: {error}"),
            }
        }
        // A reset is acceptable only with a complete, bounded HTTP response.
        let split = bytes
            .windows(4)
            .position(|part| part == b"\r\n\r\n")
            .expect("complete response header");
        let header = std::str::from_utf8(&bytes[..split]).unwrap();
        let status = header.split_whitespace().nth(1).unwrap().parse().unwrap();
        let length: usize = header
            .lines()
            .find_map(|line| line.strip_prefix("Content-Length: "))
            .expect("response length")
            .parse()
            .unwrap();
        assert!(length <= BODY_LIMIT);
        assert!(header.contains("Content-Type: application/json"));
        assert!(header.contains("Connection: close"));
        assert!(header.contains("Cache-Control: no-store"));
        let body = bytes[split + 4..].to_vec();
        assert_eq!(body.len(), length, "incomplete HTTP rejection or response");
        Self { status, body }
    }

    fn json(&self) -> Value {
        serde_json::from_slice(&self.body).unwrap()
    }

    fn ok(&self) -> Value {
        assert_eq!(self.status, 200, "{}", String::from_utf8_lossy(&self.body));
        self.json()
    }

    fn error(&self, status: u16, code: &str) {
        assert_eq!(
            self.status,
            status,
            "{}",
            String::from_utf8_lossy(&self.body)
        );
        let value = self.json();
        assert_eq!(value.as_object().unwrap().len(), 1);
        assert_eq!(value["error"].as_object().unwrap().len(), 2);
        assert_eq!(value["error"]["code"], code);
        assert_ne!(value["error"]["message"].as_str().unwrap(), "");
        for key in [
            "entries",
            "shape",
            "row",
            "snapshot",
            "sources",
            "generation",
            "scope",
        ] {
            assert!(value.get(key).is_none(), "error leaks partial {key}");
        }
    }
}

struct Server {
    child: Child,
    reader: Option<JoinHandle<()>>,
    address: SocketAddr,
    token: String,
    generation: String,
}

impl Server {
    fn start(fixture: &Fixture) -> Self {
        Self::at(&fixture.bundle, &fixture.generation)
    }

    fn at(bundle: &Path, generation: &str) -> Self {
        let child = Command::new(env!("CARGO_BIN_EXE_vitnet"))
            .args(["--memory-limit", "128MiB", "explore", "browse"])
            .arg(bundle)
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap();
        // Guard ownership before taking stdout, launching a reader, or parsing readiness.
        let mut owned = Self {
            child,
            reader: None,
            address: "127.0.0.1:0".parse().unwrap(),
            token: String::new(),
            generation: generation.into(),
        };
        let stdout = owned.child.stdout.take().unwrap();
        let (sender, receiver) = mpsc::channel();
        owned.reader = Some(std::thread::spawn(move || {
            let mut reader = BufReader::new(stdout);
            let mut first = String::new();
            let read = (&mut reader).take(4096).read_line(&mut first);
            let _ = sender.send((read, first));
            let _ = std::io::copy(&mut reader, &mut std::io::sink());
        }));
        let (read, first) = receiver
            .recv_timeout(WAIT)
            .expect("owned readiness deadline");
        read.unwrap();
        assert!(
            first.ends_with('\n') && first.len() <= 4096,
            "bounded readiness line"
        );
        let url = first
            .trim()
            .strip_prefix("Explorer: http://")
            .expect("Explorer URL");
        let (address, token) = url.split_once("/#token=").expect("fragment capability");
        owned.address = address.parse().unwrap();
        owned.token = token.into();
        assert!(owned.address.is_ipv4() && owned.address.ip().is_loopback());
        assert_ne!(owned.address.port(), 0);
        assert_eq!(owned.token.len(), 64);
        assert!(owned.token.bytes().all(|byte| byte.is_ascii_hexdigit()));
        owned
    }

    fn raw(&self, bytes: &[u8]) -> Response {
        let mut stream = TcpStream::connect_timeout(&self.address, WAIT).unwrap();
        stream.set_read_timeout(Some(WAIT)).unwrap();
        stream.set_write_timeout(Some(WAIT)).unwrap();
        stream.write_all(bytes).unwrap();
        stream.shutdown(Shutdown::Write).unwrap();
        let response = Response::read(&mut stream);
        assert!(
            !String::from_utf8_lossy(&response.body).contains(&self.token),
            "response discloses session capability"
        );
        response
    }

    fn auth(&self) -> String {
        format!(
            "Authorization: Bearer {}\r\nContent-Type: application/json\r\n",
            self.token
        )
    }

    fn request(&self, path: &str, body: &[u8], headers: &str) -> Response {
        let mut bytes = format!(
            "POST {path} HTTP/1.1\r\nHost: {}\r\n{headers}Content-Length: {}\r\n\r\n",
            self.address,
            body.len(),
        )
        .into_bytes();
        bytes.extend_from_slice(body);
        self.raw(&bytes)
    }

    fn post(&self, path: &str, body: &Value) -> Response {
        self.request(path, &serde_json::to_vec(body).unwrap(), &self.auth())
    }

    fn submit(&self, path: &str, mut query: Value) -> Response {
        if query.get("request_id").is_none() {
            query["request_id"] = json!("investigation");
        }
        if query.get("generation").is_none() {
            query["generation"] = json!(self.generation);
        }
        self.post(path, &query)
    }

    fn ok(&self, path: &str, query: Value) -> Value {
        let carries_generation = query["action"] != "source";
        let value = self.submit(path, query).ok();
        if carries_generation {
            assert_eq!(value["generation"], self.generation);
        }
        value
    }

    fn stop(&mut self) {
        assert_eq!(
            self.post("/api/shutdown", &json!({})).ok(),
            json!({"stopped":true})
        );
        let deadline = Instant::now() + WAIT;
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                assert!(status.success(), "owned child shutdown failed");
                break;
            }
            assert!(Instant::now() < deadline, "owned shutdown deadline");
            std::thread::yield_now();
        }
        if let Some(reader) = self.reader.take() {
            reader.join().unwrap();
        }
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        if !matches!(self.child.try_wait(), Ok(Some(_))) {
            let _ = self.child.kill();
        }
        let _ = self.child.wait();
        if let Some(reader) = self.reader.take() {
            let _ = reader.join();
        }
    }
}

fn ranked(limit: usize) -> Value {
    json!({"action":"ranked_rows","contains":"","stream":null,"assembly":null,
        "owner":null,"family":null,"after":null,"limit":limit})
}

fn relations(limit: usize) -> Value {
    // The canonical endpoint is /api/relations; its action is explicitly "related".
    json!({"action":"related","assembly":null,"package":null,"target":null,
        "after":null,"limit":limit})
}

fn shape(ordinal: u64) -> Value {
    json!({"action":"identity_shape_value","ordinal":ordinal.to_string(),
        "path":[],"start":0,"key":false})
}

fn records(dataset: &str, contains: &str) -> Value {
    json!({"action":"records","dataset":dataset,"contains":contains,
        "filters":{},"after":null,"limit":100})
}

fn original(dataset: &str, ordinal: &Value) -> Value {
    json!({"action":"record_value","dataset":dataset,"ordinal":ordinal,
        "path":[],"start":0,"key":false})
}

fn ordinals(entries: &[Value]) -> Vec<u64> {
    entries
        .iter()
        .map(|entry| entry["ordinal"].as_u64().unwrap())
        .collect()
}

fn semantic(mut value: Value) -> Value {
    value.as_object_mut().unwrap().remove("elapsed_ms");
    value.as_object_mut().unwrap().remove("request_id");
    value
}

#[test]
fn graph_search_limit_defaults_and_boundaries_preserve_progressive_pages() {
    let fixture = Fixture::with(&[], |root| {
        let mut xml = String::from("<DirectedGraph><Nodes>");
        for ordinal in 0..51 {
            write!(xml, "<Node Id=\"{ordinal}\" Label=\"match-{ordinal}\"/>").unwrap();
        }
        xml.push_str("</Nodes><Links/></DirectedGraph>");
        let input = root.join("graph.xml");
        fs::write(&input, xml).unwrap();
        let indexed = build_index(
            &input,
            &IndexOptions {
                cache_root: root.join("graph-cache"),
                memory_limit: MEMORY,
                selected_entry: None,
                strict_hash: false,
                control: IndexControl::default(),
            },
        )
        .unwrap();
        let mut base = evidence();
        base.artifacts.push(Artifact {
            kind: "scan_index".into(),
            path: indexed.index_directory,
            revision: None,
            blake3: None,
        });
        (base, Vec::new())
    });
    let mut server = Server::start(&fixture);
    let query = json!({
        "action":"graph_search", "graph":"scan_index", "query":"match",
        "mode":"prefix", "after_id":null
    });
    for limit in [None, Some(1), Some(49), Some(50)] {
        let page_size = limit.unwrap_or(50);
        let mut request = query.clone();
        if let Some(limit) = limit {
            request["limit"] = json!(limit);
        }
        let mut identities = Vec::new();
        loop {
            let page = server.submit("/api/query", request.clone()).ok();
            assert_eq!(page["schema"], "vitnet.dgml-search.v1");
            let entries = page["entries"].as_array().unwrap();
            assert!(!entries.is_empty() && entries.len() <= page_size);
            identities.extend(
                entries
                    .iter()
                    .map(|entry| entry["node_id"].as_str().unwrap().to_owned()),
            );
            if page["next_after_id"].is_null() {
                assert_eq!(page["stop_reason"], "complete");
                break;
            }
            assert_eq!(entries.len(), page_size);
            assert_eq!(page["stop_reason"], "limit");
            assert_eq!(page["next_after_id"], *identities.last().unwrap());
            assert!(identities.len() < 51, "graph cursor must make progress");
            request["after_id"] = page["next_after_id"].clone();
        }
        assert_eq!(
            identities,
            (0..51)
                .map(|ordinal| ordinal.to_string())
                .collect::<Vec<_>>()
        );
    }
    for limit in [0, 51, 52] {
        let mut request = query.clone();
        request["limit"] = json!(limit);
        server
            .submit("/api/query", request)
            .error(400, "explorer.search");
    }
    server.stop();
}

fn page_all(server: &Server, endpoint: &str, mut query: Value, total: u64) -> Vec<Value> {
    let deadline = Instant::now() + Duration::from_secs(120);
    let mut all = Vec::new();
    let mut previous = None;
    for _ in 0..=total + 1 {
        assert!(Instant::now() < deadline, "page traversal deadline");
        let page = server.ok(endpoint, query.clone());
        assert_eq!(page["total"], total);
        assert_eq!(
            page["order"],
            if endpoint == "/api/rows" {
                "bytes_desc_ordinal_asc"
            } else {
                "dataset_ordinal"
            }
        );
        let scanned = page["scanned"].as_u64().unwrap();
        assert!(scanned <= 100_000);
        if endpoint == "/api/rows" {
            assert!(page["elapsed_ms"].as_f64().unwrap() >= 0.0);
        }
        let entries = page["entries"].as_array().unwrap();
        assert!(entries.len() <= usize::try_from(query["limit"].as_u64().unwrap()).unwrap());
        all.extend(entries.iter().cloned());
        if page["next_after"].is_null() {
            assert_eq!(page["stop_reason"], "complete");
            assert_eq!(
                previous.map_or(0, |old| old + 1) + scanned,
                total,
                "complete means the entire rank/catalog domain was scanned"
            );
            return all;
        }
        let cursor = page["next_after"].as_str().unwrap();
        assert!(!cursor.is_empty() && cursor.bytes().all(|byte| byte.is_ascii_digit()));
        let position = cursor.parse::<u64>().unwrap();
        assert!(position < total && previous.is_none_or(|old| position > old));
        assert_eq!(
            position + 1 - previous.map_or(0, |old| old + 1),
            scanned,
            "continuation must be the last scanned POSITION, not a matched ordinal"
        );
        assert!(
            ["limit", "timeout", "max_scanned"].contains(&page["stop_reason"].as_str().unwrap())
        );
        previous = Some(position);
        query["after"] = json!(cursor);
    }
    panic!("bounded traversal did not complete");
}

fn navigate(server: &Server, query: &Value, path: &[u64], start: u64, key: bool) -> Value {
    let mut request = query.clone();
    request["path"] = json!(path);
    request["start"] = json!(start);
    request["key"] = json!(key);
    server.ok("/api/value", request)
}

fn recover(server: &Server, query: &Value, path: &[u64], key: bool) -> Value {
    let first = navigate(server, query, path, 0, key);
    match first["kind"].as_str().unwrap() {
        "string" => {
            let total = first["total_bytes"].as_u64().unwrap();
            let mut text = String::new();
            let mut page = first;
            loop {
                let chunk = page["text"].as_str().unwrap();
                assert!(chunk.len() <= 4096);
                assert_eq!(page["total_bytes"], total);
                assert_eq!(
                    page["start"].as_u64().unwrap(),
                    u64::try_from(text.len()).unwrap()
                );
                text.push_str(chunk);
                if page["next_start"].is_null() {
                    break;
                }
                let next = page["next_start"].as_u64().unwrap();
                assert_eq!(next, u64::try_from(text.len()).unwrap());
                assert!(next < total && !chunk.is_empty());
                page = navigate(server, query, path, next, key);
            }
            assert_eq!(u64::try_from(text.len()).unwrap(), total);
            json!(text)
        }
        "array" | "object" => {
            let object = first["kind"] == "object";
            let total = first["total"].as_u64().unwrap();
            let mut array = Vec::new();
            let mut map = serde_json::Map::new();
            let mut page = first;
            let mut count = 0;
            loop {
                let children = page["entries"].as_array().unwrap();
                assert!(children.len() <= 100);
                assert_eq!(page["total"], total);
                assert_eq!(page["start"], count);
                for child in children {
                    let index = child["index"].as_u64().unwrap();
                    assert_eq!(index, count);
                    let mut nested = path.to_vec();
                    nested.push(index);
                    let value = recover(server, query, &nested, false);
                    if object {
                        let name = if child["key_truncated"] == true {
                            recover(server, query, &nested, true)
                                .as_str()
                                .unwrap()
                                .to_owned()
                        } else {
                            child["key"].as_str().unwrap().to_owned()
                        };
                        assert!(map.insert(name, value).is_none(), "duplicate object key");
                    } else {
                        array.push(value);
                    }
                    count += 1;
                }
                if page["next_start"].is_null() {
                    break;
                }
                let next = page["next_start"].as_u64().unwrap();
                assert_eq!(next, count);
                assert!(next < total && !children.is_empty());
                page = navigate(server, query, path, next, false);
            }
            assert_eq!(count, total);
            if object {
                Value::Object(map)
            } else {
                Value::Array(array)
            }
        }
        "number" | "boolean" | "null" => {
            assert!(first["next_start"].is_null());
            serde_json::from_str(first["display"].as_str().unwrap()).unwrap()
        }
        other => panic!("unexpected public value kind {other}"),
    }
}

fn field_path(server: &Server, query: &Value, key: &str) -> Vec<u64> {
    let mut start = 0;
    loop {
        let page = navigate(server, query, &[], start, false);
        assert_eq!(page["kind"], "object");
        for child in page["entries"].as_array().unwrap() {
            let index = child["index"].as_u64().unwrap();
            let name = if child["key_truncated"] == true {
                recover(server, query, &[index], true)
            } else {
                child["key"].clone()
            };
            if name == key {
                return vec![index];
            }
        }
        start = page["next_start"]
            .as_u64()
            .expect("captured object field exists");
    }
}

fn assert_scope(value: &Value, bytes: Option<u64>, identities: Option<u64>) {
    assert_eq!(value["scope"]["bytes"], json!(bytes));
    assert_eq!(value["scope"]["identities"], json!(identities));
    assert_ne!(value["scope"]["basis"].as_str().unwrap(), "");
}

fn assert_row(actual: &Value, input: &CoalescedIdentity, ordinal: u64) {
    assert_eq!(actual["ordinal"], ordinal);
    assert_eq!(actual["bytes"], input.bytes);
    assert_eq!(actual["stream"], input.stream);
    assert_eq!(actual["accounted"], input.accounted);
    assert_eq!(actual["records"], input.records);
    assert_eq!(actual["identity_lossy"], input.identity_lossy);
    assert_eq!(actual["raw_identity_blake3"], input.raw_identity_blake3);
    assert_eq!(actual["identity_bytes"], input.identity.len());
    let preview = actual["identity"].as_str().unwrap();
    assert!(preview.len() <= 512 && input.identity.starts_with(preview));
    assert_eq!(actual["truncated"], input.identity.len() > 512);
    if input.identity.len() <= 512 {
        assert_eq!(preview, input.identity);
    } else {
        let next_character = input.identity[preview.len()..].chars().next().unwrap();
        assert!(
            preview.len() + next_character.len_utf8() > 512,
            "preview must fill its UTF-8-safe budget"
        );
    }
}

#[test]
fn ranked_rows_cursor_order_and_filter_pages_are_complete() {
    let rows = seed();
    let fixture = Fixture::new(&rows);
    let mut server = Server::start(&fixture);
    let first = server.ok("/api/rows", ranked(2));
    assert_eq!(ordinals(first["entries"].as_array().unwrap()), [5, 3]);
    assert_eq!(first["next_after"], "1");
    assert_eq!(first["scanned"], 2);
    assert_eq!(first["stop_reason"], "limit");
    assert_eq!(
        semantic(first.clone()),
        semantic(server.ok("/api/query", ranked(2)))
    );
    let mut default_contains = ranked(2);
    default_contains.as_object_mut().unwrap().remove("contains");
    assert_eq!(
        semantic(first),
        semantic(server.ok("/api/rows", default_contains))
    );
    for limit in [1, 2, 100] {
        let entries = page_all(&server, "/api/rows", ranked(limit), 7);
        assert_eq!(ordinals(&entries), [5, 3, 1, 2, 6, 0, 4]);
        for entry in &entries {
            let ordinal = entry["ordinal"].as_u64().unwrap();
            assert_row(entry, &rows[usize::try_from(ordinal).unwrap()], ordinal);
        }
        let mut methods = ranked(limit);
        methods["stream"] = json!("Methods");
        let entries = page_all(&server, "/api/rows", methods, 7);
        assert_eq!(ordinals(&entries), [3, 1, 2, 0, 4]);
    }
    let mut sparse = ranked(1);
    sparse["stream"] = json!("Types");
    let page = server.ok("/api/rows", sparse.clone());
    assert_eq!(ordinals(page["entries"].as_array().unwrap()), [6]);
    assert_eq!(page["scanned"], 5);
    assert_eq!(page["next_after"], "4");
    sparse["after"] = page["next_after"].clone();
    let end = server.ok("/api/rows", sparse);
    assert_eq!(end["entries"], json!([]));
    assert_eq!(end["scanned"], 2);
    assert_eq!(end["stop_reason"], "complete");
    assert!(end["next_after"].is_null());
    let mut absent = ranked(100);
    absent["contains"] = json!("NeverPresent");
    let page = server.ok("/api/rows", absent);
    assert_eq!(page["entries"], json!([]));
    assert_eq!(page["scanned"], 7);
    assert_eq!(page["stop_reason"], "complete");
    assert!(page["next_after"].is_null());
    server.stop();

    // Exact full-page terminal, singleton zero-byte/coalesced, and empty partitions.
    for count in [0_u64, 1, 100] {
        let mut rows: Vec<_> = (0..count)
            .map(|n| row(&format!("Boundary__R{n:03}"), "Methods", n))
            .collect();
        if count == 1 {
            rows[0].records = 2;
        }
        let fixture = Fixture::new(&rows);
        let mut server = Server::start(&fixture);
        let page = server.ok("/api/rows", ranked(100));
        let expected: Vec<_> = (0..count).rev().collect();
        assert_eq!(ordinals(page["entries"].as_array().unwrap()), expected);
        assert_eq!(page["total"], count);
        assert_eq!(page["scanned"], count);
        assert_eq!(page["stop_reason"], "complete");
        assert!(page["next_after"].is_null());
        if count == 1 {
            assert_row(&page["entries"][0], &rows[0], 0);
        }
        server.stop();
    }
}

#[test]
fn ranked_scope_denominators_are_complete_or_explicitly_unknown() {
    let mut rows: Vec<_> = (0..105)
        .map(|n| row(&format!("App_Box<int>__Run<V{n:03}>"), "Methods", n + 1))
        .collect();
    rows.extend((0..101).map(|n| row(&format!("Second_F{n:03}<X>__Run"), "Methods", 1)));
    rows.push(row("App_Type<int>", "Types", 7));
    let fixture = Fixture::with(&rows, |_| {
        let mut base = evidence();
        for entry in &rows {
            base.mappings.push(mapping(
                &entry.stream,
                &entry.identity,
                if entry.identity.starts_with("Second_") {
                    "Second"
                } else {
                    "App"
                },
                vec![],
            ));
        }
        (base, vec![])
    });
    let mut server = Server::start(&fixture);
    for limit in [1, 100] {
        for (selector, expected_bytes, expected_count) in [
            (json!({"stream":"Methods"}), 5666, 206),
            (json!({"stream":"Types"}), 7, 1),
            (json!({"stream":"Methods","assembly":"App"}), 5565, 105),
            (json!({"stream":"Methods","owner":"App_Box"}), 5565, 105),
            (
                json!({"stream":"Methods","family":"App_Box<>__Run<>"}),
                5565,
                105,
            ),
            (json!({"stream":"Methods","assembly":"Missing"}), 0, 0),
            (json!({"stream":"Methods","owner":"Missing"}), 0, 0),
            (json!({"stream":"Methods","family":"Missing<>"}), 0, 0),
        ] {
            let mut query = ranked(limit);
            for (key, value) in selector.as_object().unwrap() {
                query[key] = value.clone();
            }
            let page = server.ok("/api/rows", query);
            assert_eq!(page["total"], 207);
            assert_scope(&page, Some(expected_bytes), Some(expected_count));
        }
        for selector in [
            json!({"stream":"Methods","assembly":"App","owner":"App_Box"}),
            json!({"stream":"Methods","owner":"App_Box","family":"App_Box<>__Run<>"}),
            json!({"stream":"Methods","assembly":"App","family":"App_Box<>__Run<>"}),
            json!({"stream":"Methods","assembly":"App","owner":"App_Box","family":"App_Box<>__Run<>"}),
        ] {
            let mut query = ranked(limit);
            for (key, value) in selector.as_object().unwrap() {
                query[key] = value.clone();
            }
            let page = server.ok("/api/rows", query);
            assert_eq!(page["total"], 207);
            assert_scope(&page, None, None);
            assert_eq!(
                ordinals(page["entries"].as_array().unwrap()),
                if limit == 1 {
                    vec![104]
                } else {
                    (5..105).rev().collect()
                }
            );
            assert_eq!(
                page["scope"]["basis"],
                "Combined filter denominator is not a precomputed additive partition."
            );
        }
        // The captured parent denominator is complete, not the one matching
        // text row or this page. Its basis must disclose the text distinction.
        let mut text = ranked(limit);
        text["contains"] = json!("V104");
        text["stream"] = json!("Methods");
        text["assembly"] = json!("App");
        let page = server.ok("/api/rows", text);
        assert_eq!(page["total"], 207);
        assert_eq!(ordinals(page["entries"].as_array().unwrap()), [104]);
        assert_scope(&page, Some(5565), Some(105));
        assert!(
            page["scope"]["basis"]
                .as_str()
                .unwrap()
                .contains("before the text filter")
        );
    }
    server.stop();
}

#[test]
fn empty_current_capture_has_no_reported_additive_stream_denominator() {
    let fixture = Fixture::new(&[]);
    let mut server = Server::start(&fixture);
    let page = server.ok("/api/rows", ranked(1));
    assert_eq!(page["total"], 0);
    assert_eq!(page["entries"], json!([]));
    assert_scope(&page, None, None);
    assert_eq!(
        page["scope"]["basis"],
        "No additive stream denominator is captured for this scope."
    );
    server.stop();
}

#[test]
fn scope_denominators_keep_lossy_unaccounted_and_ambiguous_buckets_distinct() {
    let mut bucket_rows = vec![
        row("App_Box<int>__Run", "Methods", 40),
        row("App_Box<long>__Run", "Methods", 10),
        row("Broken<__Run", "Methods", 5),
        row("Ambiguous__Run", "Methods", 7),
        row("Unknown__Run", "Methods", 9),
        row("App_Loss�__Run", "Methods", 11),
        row("App_Loss�__Run", "Methods", 13),
    ];
    bucket_rows[0].accounted = false;
    for (n, entry) in bucket_rows.iter_mut().enumerate().skip(5) {
        entry.identity_lossy = true;
        entry.raw_identity_blake3 = blake3::hash(&[0xff, u8::try_from(n).unwrap()])
            .to_hex()
            .to_string();
    }
    let fixture = Fixture::with(&bucket_rows, |_| {
        let mut base = evidence();
        base.assemblies.push(Assembly {
            name: "App".into(),
            ..Assembly::default()
        });
        base.mappings.extend([
            mapping("Methods", "Ambiguous__Run", "App", vec![]),
            mapping("Methods", "Ambiguous__Run", "Second", vec![]),
            mapping("Methods", "App_Loss�__Run", "App", vec![]),
        ]);
        (base, vec![])
    });
    let mut server = Server::start(&fixture);
    for (dimension, name, bytes, identities) in [
        ("family", "App_Box<>__Run", 50, 2),
        ("owner", "App_Box", 10, 1),
        ("assembly", "App", 10, 1),
        ("assembly", "_ambiguous", 7, 1),
        ("assembly", "_unmapped", 38, 4),
        ("owner", "App_Loss�", 24, 2),
    ] {
        let mut query = ranked(1);
        query["stream"] = json!("Methods");
        query[dimension] = json!(name);
        let page = server.ok("/api/rows", query);
        assert_eq!(page["total"], 7);
        assert_scope(&page, Some(bytes), Some(identities));
        assert_eq!(
            page["scope"]["basis"],
            "Complete captured partition before the text filter; assembly associations are evidence-tiered candidates or assertions, not exclusive physical ownership."
        );
    }
    server.stop();
}

fn matcher_rows() -> Vec<CoalescedIdentity> {
    let mut rows = vec![
        row("opaque<int>__Run", "Methods", 50),
        row("App_Looking__Run", "Methods", 40),
        row("Ambiguous__Run", "Methods", 30),
        row("Unknown__Run", "Methods", 20),
        row("App_Loss�__Run", "Methods", 10),
    ];
    rows[4].identity_lossy = true;
    rows[4].raw_identity_blake3 = blake3::hash(&[0xff]).to_hex().to_string();
    rows
}

fn matcher_evidence(root: &Path) -> Evidence {
    let mut base = evidence();
    base.sources.extend([
        source(root, "member.cs", "App", "Box"),
        source(root, "second.cs", "Second", "Looking"),
        source(root, "argument.cs", "App", "Int32"),
    ]);
    base.mappings.extend([
        mapping(
            "Methods",
            "opaque<int>__Run",
            "App",
            vec![root.join("member.cs")],
        ),
        mapping(
            "Methods",
            "App_Looking__Run",
            "Second",
            vec![root.join("second.cs")],
        ),
        mapping("Methods", "Ambiguous__Run", "App", vec![]),
        mapping("Methods", "Ambiguous__Run", "Second", vec![]),
        mapping(
            "Methods",
            "App_Loss�__Run",
            "App",
            vec![root.join("member.cs")],
        ),
        mapping("Types", "int", "App", vec![root.join("argument.cs")]),
    ]);
    base
}

fn assert_matcher(server: &Server, root: &Path, total: u64) {
    for (assembly, expected) in [
        ("App", vec![0]),
        ("Second", vec![1]),
        ("_ambiguous", vec![2]),
        ("_unmapped", vec![3, 4]),
    ] {
        let mut query = ranked(100);
        query["assembly"] = json!(assembly);
        assert_eq!(
            ordinals(&page_all(server, "/api/rows", query, total)),
            expected
        );
    }
    for (ordinal, assemblies, paths, status) in [
        (0, vec!["App"], vec![root.join("member.cs")], "asserted"),
        (1, vec!["Second"], vec![root.join("second.cs")], "asserted"),
        (2, vec!["App", "Second"], vec![], "ambiguous"),
        (3, vec![], vec![], "unmapped"),
        (4, vec![], vec![], "unmapped_lossy_identity"),
    ] {
        let details = server.ok("/api/query", json!({"action":"source","ordinal":ordinal}));
        assert_eq!(details["sources"]["assemblies"], json!(assemblies));
        assert_eq!(details["sources"]["status"], status);
        let actual: Vec<_> = details["sources"]["sources"]
            .as_array()
            .unwrap()
            .iter()
            .map(|item| item["path"].clone())
            .collect();
        assert_eq!(
            actual,
            paths.iter().map(|path| json!(path)).collect::<Vec<_>>()
        );
        if ordinal == 0 {
            let argument = &details["argument_sources"][0];
            assert_eq!(argument["argument"], "int");
            assert_eq!(argument["total_sources"], 1);
            assert_eq!(argument["candidates"]["assemblies"], json!(["App"]));
            assert_eq!(
                argument["candidates"]["sources"][0]["path"],
                json!(root.join("argument.cs"))
            );
            assert!(
                argument["caveat"]
                    .as_str()
                    .unwrap()
                    .contains("not proven managed type arguments or caller sites")
            );
        }
        if ordinal == 4 {
            assert!(details.get("shape").is_none());
            assert!(details.get("argument_sources").is_none());
        }
    }
}

#[test]
fn ranked_family_and_real_matcher_filters_are_exact() {
    let long = format!("App_Box<{}BeyondPreview>__Run", "界".repeat(200));
    let mut rows = vec![
        row("App_Box<int>__Run", "Methods", 100),
        row("App_Box<Other<int>,__Canon>__Run", "Methods", 90),
        row("App_Box<int>__Run<long>", "Methods", 80),
        row("App_BoxExtra<int>__Run", "Methods", 70),
        row("App_Box<int>__Other", "Methods", 60),
        row("App_Box__Run", "Methods", 50),
        row("Broken<__Run", "Methods", 40),
        row("App_Box<int>__Run", "Methods", 30),
        row(&long, "Methods", 20),
        row("App_Box<int>__Run", "Types", 10),
        row("App_Box<int>__Run", "Blobs", 5),
    ];
    rows[7].identity_lossy = true;
    rows[7].raw_identity_blake3 = blake3::hash(b"App_Box<\xff>__Run").to_hex().to_string();
    let fixture = Fixture::new(&rows);
    let mut server = Server::start(&fixture);
    for (family, stream, expected) in [
        ("App_Box<>__Run", Some("Methods"), vec![0, 1, 8]),
        ("App_Box<>__Run<>", Some("Methods"), vec![2]),
        ("App_Box<>__Run", Some("Types"), vec![9]),
        ("App_Box<>__RunX", None, vec![]),
        ("App_Box<>__Ru", None, vec![]),
        ("App_BoxExtra<>__Run", Some("Methods"), vec![3]),
    ] {
        let mut query = ranked(1);
        query["family"] = json!(family);
        query["stream"] = json!(stream);
        assert_eq!(
            ordinals(&page_all(&server, "/api/rows", query, 11)),
            expected
        );
    }
    let mut query = ranked(100);
    query["contains"] = json!("BeyondPreview");
    query["family"] = json!("App_Box<>__Run");
    let entries = page_all(&server, "/api/rows", query, 11);
    assert_eq!(ordinals(&entries), [8]);
    assert_row(&entries[0], &rows[8], 8);
    assert!(
        !entries[0]["identity"]
            .as_str()
            .unwrap()
            .contains("BeyondPreview")
    );
    server.stop();
    let rows = matcher_rows();
    let fixture = Fixture::with(&rows, |root| (matcher_evidence(root), vec![]));
    let mut server = Server::start(&fixture);
    assert_matcher(&server, fixture.root.path(), 5);
    server.stop();
}

#[test]
fn identity_shape_value_is_complete_navigable_and_diagnostic() {
    let cases = [
        (
            "App_Box<int>__Run",
            "App_Box<>__Run",
            json!(["int"]),
            json!([1]),
            false,
        ),
        (
            "App_Box<Other<int>,__Canon>__Run",
            "App_Box<>__Run",
            json!(["Other<int>", "__Canon"]),
            json!([2]),
            true,
        ),
        (
            "App_Box<int>__Run<long>",
            "App_Box<>__Run<>",
            json!(["int", "long"]),
            json!([1, 2]),
            false,
        ),
    ];
    let mut rows: Vec<_> = cases.iter().map(|case| row(case.0, "Methods", 1)).collect();
    rows.extend([
        row("Plain__Run", "Methods", 1),
        row("Broken<__Run", "Methods", 1),
        row("App_Box<int>__Run", "Methods", 1),
    ]);
    rows[5].identity_lossy = true;
    rows[5].raw_identity_blake3 = blake3::hash(b"App_Box<\xff>__Run").to_hex().to_string();
    let fixture = Fixture::new(&rows);
    let mut server = Server::start(&fixture);
    for (ordinal, (name, family, arguments, boundaries, shared)) in cases.iter().enumerate() {
        let query = shape(u64::try_from(ordinal).unwrap());
        assert_eq!(
            recover(&server, &query, &[], false),
            json!({
                "producer_name":name,"family":family,"arguments":arguments,
                "group_boundaries":boundaries,"canonical_shared":shared,
            })
        );
        assert_eq!(
            semantic(server.ok("/api/value", query.clone())),
            semantic(server.ok("/api/query", query.clone()))
        );
        let path = field_path(&server, &query, "family");
        assert_eq!(recover(&server, &query, &path, true), "family");
    }
    assert_eq!(recover(&server, &shape(3), &[], false), Value::Null);
    server
        .submit("/api/value", shape(4))
        .error(400, "attribution.generic.syntax");
    let malformed = server.ok("/api/query", json!({"action":"source","ordinal":4}));
    assert_eq!(
        malformed["shape_diagnostic"]["code"],
        "attribution.generic.syntax"
    );
    assert_ne!(
        malformed["shape_diagnostic"]["message"].as_str().unwrap(),
        ""
    );
    server
        .submit("/api/value", shape(5))
        .error(400, "explorer.shape.lossy");
    server.stop();
}

fn full_shape_fixture(producer: &str, arguments: &[String]) -> Fixture {
    Fixture::with(&[row(producer, "Methods", 55)], |root| {
        let mut base = evidence();
        let mut ordinary_paths = Vec::new();
        for n in 0..51 {
            let mut item = source(root, &format!("member{n:02}.cs"), "App", "Box");
            // One heavy attribute record exercises both caps without exhausting 2 MiB.
            item.attributes = if n == 0 {
                vec!["界".repeat(400); 41]
            } else {
                vec!["CapturedAttribute".into()]
            };
            ordinary_paths.push(item.path.clone());
            base.sources.push(item);
        }
        let candidate_paths: Vec<_> = (0..6)
            .map(|n| {
                let mut item = source(root, &format!("candidate{n}.cs"), "App", "Argument");
                item.member = None;
                let path = item.path.clone();
                base.sources.push(item);
                path
            })
            .collect();
        base.mappings
            .push(mapping("Methods", producer, "App", ordinary_paths));
        for argument in arguments.iter().take(21) {
            base.mappings
                .push(mapping("Types", argument, "App", candidate_paths.clone()));
        }
        (base, vec![])
    })
}

#[test]
fn full_shape_navigation_exceeds_bounded_source_and_argument_projections() {
    let long_argument = format!("{}Tail", "界".repeat(1400));
    let mut arguments = vec![long_argument.clone()];
    arguments.extend((1..55).map(|n| format!("A{n:02}")));
    let mut producer = format!("App_Box<{}>__Run", arguments[0]);
    for argument in &arguments[1..] {
        producer.push('<');
        producer.push_str(argument);
        producer.push('>');
    }
    let family = format!("App_Box<>__Run{}", "<>".repeat(54));
    let fixture = full_shape_fixture(&producer, &arguments);
    let mut server = Server::start(&fixture);
    let details = server.ok("/api/query", json!({"action":"source","ordinal":0}));
    assert_eq!(details["shape"]["family"], family);
    assert_eq!(details["shape"]["argument_count"], 55);
    assert_eq!(details["shape"]["arguments"].as_array().unwrap().len(), 50);
    assert_eq!(details["shape"]["arguments"][0], "界".repeat(1365)); // 4095 UTF-8 bytes.
    assert_eq!(details["shape"]["arguments"][49], "A49");
    assert_eq!(
        details["shape"]["group_boundaries"],
        json!((1..=50).collect::<Vec<_>>())
    );
    assert_eq!(details["shape"]["canonical_shared"], false);
    assert_eq!(details["total_sources"], 51);
    assert_eq!(details["omitted_sources"], 1);
    let ordinary = details["sources"]["sources"].as_array().unwrap();
    assert_eq!(ordinary.len(), 50);
    assert_eq!(
        ordinary[0]["path"],
        json!(fixture.root.path().join("member00.cs"))
    );
    assert_eq!(
        ordinary[49]["path"],
        json!(fixture.root.path().join("member49.cs"))
    );
    assert_eq!(ordinary[0]["attributes"].as_array().unwrap().len(), 40);
    assert_eq!(ordinary[0]["attributes"][0], "界".repeat(341)); // 1023 bytes, no split codepoint.
    let candidates = details["argument_sources"].as_array().unwrap();
    assert_eq!(candidates.len(), 20);
    for (n, argument) in candidates.iter().enumerate() {
        assert_eq!(
            argument["argument"],
            if n == 0 {
                "界".repeat(1365)
            } else {
                format!("A{n:02}")
            }
        );
        assert_eq!(argument["total_sources"], 6);
        assert_eq!(argument["candidates"]["assemblies"], json!(["App"]));
        assert_eq!(argument["candidates"]["status"], "asserted");
        let paths: Vec<_> = argument["candidates"]["sources"]
            .as_array()
            .unwrap()
            .iter()
            .map(|item| item["path"].clone())
            .collect();
        assert_eq!(
            paths,
            (0..5)
                .map(|n| json!(fixture.root.path().join(format!("candidate{n}.cs"))))
                .collect::<Vec<_>>()
        );
        assert!(
            argument["caveat"]
                .as_str()
                .unwrap()
                .contains("not proven managed type arguments or caller sites")
        );
    }
    let query = shape(0);
    assert_eq!(
        recover(&server, &query, &[], false),
        json!({
            "family":family,"arguments":arguments,"group_boundaries":(1..=55).collect::<Vec<_>>(),
            "canonical_shared":false,"producer_name":producer,
        })
    );
    let mut path = field_path(&server, &query, "arguments");
    assert_eq!(recover(&server, &query, &path, false), json!(arguments));
    path.push(0);
    let first = navigate(&server, &query, &path, 0, false);
    assert_eq!(first["text"], "界".repeat(1365));
    assert_eq!(first["next_start"], 4095);
    assert_eq!(recover(&server, &query, &path, false), long_argument);
    let scalar = field_path(&server, &query, "canonical_shared");
    assert_eq!(recover(&server, &query, &scalar, false), false);
    server.stop();
}

type Link = (String, String, String, String);

fn link(assembly: &str, package: &str, target: &str, basis: &str) -> Link {
    (assembly.into(), package.into(), target.into(), basis.into())
}

fn fixed_links() -> BTreeSet<Link> {
    let mut links = BTreeSet::from([
        link("App", "RecordedPkg/1", "", "recorded_assembly_package"),
        link(
            "App",
            "Pkg/1",
            "net10/win-x64",
            "assets_resolved_runtime:net10/win-x64",
        ),
        link(
            "App",
            "Pkg/1",
            "net10/linux-x64",
            "assets_resolved_runtime:net10/linux-x64",
        ),
        link(
            "App",
            "Pkg/1",
            "net10/win-x64",
            "assets_resolved_compile:net10/win-x64",
        ),
        link(
            "Supplemental",
            "SupplementalPkg/2",
            "",
            "recorded_assembly_package",
        ),
        link(
            "Supplemental",
            "SuppPkg/2",
            "net10/win-x64",
            "assets_resolved_runtime:net10/win-x64",
        ),
        link(
            "Other",
            "OtherPkg/3",
            "net10/win-x64",
            "assets_resolved_runtime:net10/win-x64",
        ),
    ]);
    links.extend((0..101).map(|n| {
        link(
            "App",
            &format!("Bulk{n:03}/1"),
            "net10/win-x64",
            "assets_resolved_runtime:net10/win-x64",
        )
    }));
    links
}

fn package_mapping(assembly: &str, package: &str, target: &str, role: &str) -> Mapping {
    let mut entry = mapping("package", package, assembly, vec![]);
    entry.basis = format!("assets_resolved_{role}:{target}");
    entry
}

fn projected_link(entry: &Value) -> Link {
    let fields = &entry["fields"];
    link(
        fields["assembly"].as_str().unwrap(),
        fields["package"].as_str().unwrap(),
        fields["target"].as_str().unwrap(),
        fields["basis"].as_str().unwrap(),
    )
}

fn relation_fixture() -> Fixture {
    let rows = matcher_rows();
    Fixture::with(&rows, |root| {
        let mut base = matcher_evidence(root);
        base.assemblies.push(Assembly {
            name: "App".into(),
            package: Some("RecordedPkg/1".into()),
            ..Assembly::default()
        });
        base.mappings.extend([
            package_mapping("App", "Pkg/1", "net10/win-x64", "runtime"),
            package_mapping("App", "Pkg/1", "net10/linux-x64", "runtime"),
            package_mapping("Other", "OtherPkg/3", "net10/win-x64", "runtime"),
        ]);
        base.mappings.extend(
            (0..101).map(|n| {
                package_mapping("App", &format!("Bulk{n:03}/1"), "net10/win-x64", "runtime")
            }),
        );
        let mut extra = evidence();
        extra.assemblies.push(Assembly {
            name: "Supplemental".into(),
            package: Some("SupplementalPkg/2".into()),
            ..Assembly::default()
        });
        extra.mappings.extend([
            package_mapping("App", "Pkg/1", "net10/win-x64", "runtime"), // exact duplicate
            package_mapping("App", "Pkg/1", "net10/win-x64", "compile"),
            package_mapping("Supplemental", "SuppPkg/2", "net10/win-x64", "runtime"),
            mapping(
                "Methods",
                "opaque<int>__Run",
                "Wrong",
                vec![root.join("conflict.cs")],
            ),
            mapping("Types", "int", "Wrong", vec![root.join("conflict.cs")]),
        ]);
        extra
            .sources
            .push(source(root, "conflict.cs", "Wrong", "Int32"));
        let mut wrong_case = package_mapping("Wrong", "NotALink/9", "net10/win-x64", "runtime");
        wrong_case.stream = "Package".into();
        extra.mappings.push(wrong_case);
        (base, vec![extra])
    })
}

#[test]
fn relations_are_complete_exact_filtered_and_matcher_independent() {
    let fixture = relation_fixture();
    let expected = fixed_links();
    assert_eq!(expected.len(), 108); // Independent seven tuples + 101 bulk tuples.
    let mut server = Server::start(&fixture);
    for limit in [1, 100] {
        for selectors in [
            json!({}),
            json!({"assembly":"App"}),
            json!({"package":"Pkg/1"}),
            json!({"target":"net10/win-x64"}),
            json!({"assembly":"App","package":"Pkg/1","target":"net10/win-x64"}),
            json!({"target":"net10/osx-x64"}),
            json!({"assembly":"Ap"}),
            json!({"package":"Pkg"}),
            json!({"target":"net10/win-x64x"}),
        ] {
            let mut query = relations(limit);
            for (key, value) in selectors.as_object().unwrap() {
                query[key] = value.clone();
            }
            let entries = page_all(&server, "/api/relations", query, 108);
            let wanted: Vec<_> = expected
                .iter()
                .enumerate()
                .filter(|(_, tuple)| {
                    [
                        ("assembly", &tuple.0),
                        ("package", &tuple.1),
                        ("target", &tuple.2),
                    ]
                    .into_iter()
                    .all(|(key, value)| selectors.get(key).is_none_or(|v| v == value.as_str()))
                })
                .map(|(ordinal, tuple)| (ordinal, tuple.clone()))
                .collect();
            assert_eq!(entries.len(), wanted.len());
            for (entry, (ordinal, tuple)) in entries.iter().zip(&wanted) {
                assert_eq!(entry["ordinal"], ordinal.to_string());
                assert_eq!(projected_link(entry), *tuple);
            }
        }
    }
    assert_eq!(
        semantic(server.ok("/api/relations", relations(100))),
        semantic(server.ok("/api/query", relations(100)))
    );
    // Complete originals pin caveats as well as distinct target/basis, not just link counts.
    let entries = page_all(&server, "/api/relations", relations(100), 108);
    for (entry, tuple) in entries.iter().zip(&expected) {
        let captured = recover(
            &server,
            &original("assembly_links", &entry["ordinal"]),
            &[],
            false,
        );
        assert_eq!(
            captured,
            json!({
                "assembly":tuple.0,"package":tuple.1,"target":tuple.2,"basis":tuple.3,
                "caveat":"Recorded package origin, not compiler retention, exclusive byte ownership or removable size.",
            })
        );
        for key in ["retained", "exclusive_bytes", "removable_bytes", "savings"] {
            assert!(captured.get(key).is_none());
        }
    }
    assert_matcher(&server, fixture.root.path(), 5);
    server.stop();
    let (base_path, base_generation) = fixture.base_bundle();
    let mut base_server = Server::at(&base_path, &base_generation);
    assert_matcher(&base_server, fixture.root.path(), 5);
    let base_links = page_all(&base_server, "/api/relations", relations(100), 105);
    let expected_base: BTreeSet<_> = expected
        .into_iter()
        .filter(|tuple| {
            tuple.0 != "Supplemental" && tuple.3 != "assets_resolved_compile:net10/win-x64"
        })
        .collect();
    assert_eq!(
        base_links
            .iter()
            .map(projected_link)
            .collect::<BTreeSet<_>>(),
        expected_base
    );
    base_server.stop();
}

type CapturedRecords = Vec<(String, Value)>;

fn domain_fixture() -> (Fixture, CapturedRecords, [CoalescedIdentity; 1]) {
    let long_value = format!("{}界CapturedNeedle", "a".repeat(4095));
    let boundary_value = format!("{}界Tail", "b".repeat(511));
    let long_name = format!("{}界ResourceNeedle", "r".repeat(511));
    let long_package = format!("{}界PackageNeedle", "p".repeat(511));
    let metadata_text = format!("{}UpstreamOnlyNeedle", "界".repeat(100));
    let identity = format!("App_Box<{long_value}>__Run");
    let rows = [row(&identity, "Methods", 42)];
    let mut captured = Vec::<(String, Value)>::new();
    let fixture = Fixture::with(&rows, |root| {
        let mut base = evidence();
        base.packages.push(Package {
            target: "net10/win-x64".into(),
            id: "MeaningfulPkg".into(),
            version: "1.2.3".into(),
            direct: true,
            dependencies: (0..101).map(|n| format!("Dep{n:03}/1")).collect(),
        });
        for (id, count) in [("EmptyPkg", 0), ("SingletonPkg", 1), ("HundredPkg", 100)] {
            base.packages.push(Package {
                target: "net10/win-x64".into(),
                id: id.into(),
                version: "1".into(),
                direct: false,
                dependencies: (0..count).map(|n| format!("Dep{n:03}/1")).collect(),
            });
        }
        base.packages.push(Package {
            target: "net10/win-x64".into(),
            id: long_package.clone(),
            version: "2".into(),
            ..Package::default()
        });
        // Fixed input order also makes the complete package catalog's order explicit.
        base.packages.sort_by(|left, right| left.id.cmp(&right.id));
        base.assemblies.push(Assembly {
            name: "App".into(),
            path: root.join("App.dll"),
            package: Some("MeaningfulPkg/1.2.3".into()),
            types: vec![ManagedType {
                name: "Box".into(),
                kind: "class".into(),
                members: 3,
            }],
        });
        let mut item = source(root, "Box.cs", "App", "Box");
        item.attributes = vec!["CapturedAttribute".into()];
        item.generated_by = Some("Generator/1".into());
        item.sha256 = Some("11".repeat(32));
        base.sources.push(item);
        base.resources.push(Resource {
            assembly: "App".into(),
            container: "Assets".into(),
            name: long_name.clone(),
            bytes: 37,
            sha256: Some("22".repeat(32)),
            source_path: Some(root.join("asset.bin")),
            storage: "embedded_asset".into(),
        });
        base.provenance.insert("long".into(), long_value.clone());
        base.provenance
            .insert("boundary".into(), boundary_value.clone());
        base.provenance.insert("empty".into(), String::new());
        base.provenance.insert("exact4096".into(), "c".repeat(4096));
        let metadata = root.join("metadata.csv");
        fs::write(&metadata, format!(
            "Handle, Kind, Name, Children\n00000000, ConstantStringValue, \"{metadata_text}\", \"\"\n00000400, End, \"\", \"\"\n",
        )).unwrap();
        base.artifacts.push(Artifact {
            kind: "metadata".into(),
            path: metadata,
            revision: None,
            blake3: None,
        });
        // Fixture serialization is the oracle; no production projection/parser creates it.
        for package in &base.packages {
            captured.push(("packages".into(), serde_json::to_value(package).unwrap()));
        }
        captured.extend([
            (
                "assemblies".into(),
                serde_json::to_value(&base.assemblies[0]).unwrap(),
            ),
            (
                "sources".into(),
                serde_json::to_value(&base.sources[0]).unwrap(),
            ),
            (
                "resource_evidence".into(),
                serde_json::to_value(&base.resources[0]).unwrap(),
            ),
        ]);
        for (key, value) in &base.provenance {
            captured.push(("provenance".into(), json!({"key":key,"value":value})));
        }
        (base, vec![])
    });
    (fixture, captured, rows)
}

#[test]
fn records_project_domain_fields_and_preserve_captured_originals() {
    let (fixture, _, _) = domain_fixture();
    let mut server = Server::start(&fixture);
    for (dataset, expected_fields) in [
        (
            "packages",
            json!({"id":"MeaningfulPkg","version":"1.2.3","target":"net10/win-x64","direct":true}),
        ),
        (
            "assemblies",
            json!({"name":"App","path":fixture.root.path().join("App.dll"),"package":"MeaningfulPkg/1.2.3"}),
        ),
        (
            "sources",
            json!({"assembly":"App","type_name":"Box","member":"Run",
            "path":fixture.root.path().join("Box.cs")}),
        ),
        (
            "resource_evidence",
            json!({"assembly":"App","container":"Assets","bytes":37,
            "storage":"embedded_asset","name":"r".repeat(511)}),
        ),
        (
            "assembly_links",
            json!({"assembly":"App","package":"MeaningfulPkg/1.2.3","target":"",
            "basis":"recorded_assembly_package"}),
        ),
    ] {
        let page = server.ok("/api/records", records(dataset, ""));
        let entry = if dataset == "packages" {
            page["entries"]
                .as_array()
                .unwrap()
                .iter()
                .find(|entry| entry["fields"]["id"] == "MeaningfulPkg")
                .unwrap()
        } else {
            &page["entries"][0]
        };
        assert!(
            entry["ordinal"]
                .as_str()
                .unwrap()
                .bytes()
                .all(|byte| byte.is_ascii_digit())
        );
        for (key, expected) in expected_fields.as_object().unwrap() {
            assert_eq!(
                &entry["fields"][key], expected,
                "readable {dataset}.{key} projection"
            );
        }
        assert!(
            entry["capture"]["scope"]
                .as_str()
                .unwrap()
                .contains("upstream omissions cannot be reconstructed")
        );
        if dataset == "resource_evidence" {
            assert_eq!(entry["capture"]["fields_truncated"], json!(["name"]));
        }
    }
    // Search must examine full captured fields even when every display label hides the needle.
    for (dataset, needle, preview_key, expected_preview) in [
        ("packages", "PackageNeedle", "id", "p".repeat(511)),
        (
            "resource_evidence",
            "ResourceNeedle",
            "name",
            "r".repeat(511),
        ),
        ("provenance", "CapturedNeedle", "value", "a".repeat(512)),
    ] {
        let page = server.ok("/api/records", records(dataset, needle));
        let entries = page["entries"].as_array().unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0]["fields"][preview_key], expected_preview);
        assert_eq!(
            entries[0]["capture"]["fields_truncated"],
            json!([preview_key])
        );
        assert_eq!(entries[0]["capture"]["upstream_truncated"], false);
    }
    server.stop();
}

#[test]
fn captured_originals_preserve_domain_fields_and_collection_boundaries() {
    let (fixture, captured, rows) = domain_fixture();
    let mut server = Server::start(&fixture);
    // The bounded field allowlist is not a serializer for every model field.
    // Source line/kind, resource hashes/paths, and dependencies are pinned here
    // against complete independently serialized originals.
    for dataset in [
        "packages",
        "assemblies",
        "sources",
        "resource_evidence",
        "provenance",
    ] {
        let page = server.ok("/api/records", records(dataset, ""));
        let expected: Vec<_> = captured
            .iter()
            .filter(|item| item.0 == dataset)
            .map(|item| item.1.clone())
            .collect();
        assert_eq!(page["total"], expected.len());
        assert_eq!(page["entries"].as_array().unwrap().len(), expected.len());
        for (entry, expected) in page["entries"].as_array().unwrap().iter().zip(&expected) {
            assert_eq!(
                recover(&server, &original(dataset, &entry["ordinal"]), &[], false),
                *expected
            );
        }
    }
    let packages = server.ok("/api/records", records("packages", ""));
    for (index, count) in [(2_usize, 101_usize), (0, 0), (3, 1), (1, 100)] {
        let query = original("packages", &packages["entries"][index]["ordinal"]);
        let path = field_path(&server, &query, "dependencies");
        let page = navigate(&server, &query, &path, 0, false);
        assert_eq!(page["total"], count);
        assert_eq!(page["entries"].as_array().unwrap().len(), count.min(100));
        assert_eq!(
            page["next_start"],
            if count > 100 { json!(100) } else { Value::Null }
        );
        let end = navigate(&server, &query, &path, u64::try_from(count).unwrap(), false);
        assert_eq!(end["entries"], json!([]));
        assert!(end["next_start"].is_null());
    }
    let empty = server.ok("/api/records", records("binaries", ""));
    assert_eq!(empty["total"], 0);
    assert_eq!(empty["entries"], json!([]));
    assert!(empty["next_after"].is_null());
    let identity_query =
        json!({"action":"identity_value","ordinal":"0","path":[],"start":0,"key":false});
    let complete_identity = recover(&server, &identity_query, &[], false);
    assert_eq!(
        complete_identity,
        serde_json::to_value(&rows[0]).unwrap(),
        "identity_value must preserve the complete cached record, not a Row preview"
    );
    server.stop();
}

#[test]
fn upstream_metadata_truncation_is_explicit_and_not_reconstructed() {
    let (fixture, _, _) = domain_fixture();
    let mut server = Server::start(&fixture);
    let strings = server.ok("/api/records", records("metadata_largest_strings", ""));
    assert_eq!(strings["total"], 1);
    let entry = &strings["entries"][0];
    assert_eq!(entry["fields"]["text"], "界".repeat(85)); // Producer capture cap is 256.
    assert_eq!(entry["fields"]["bytes"], 1024);
    assert_eq!(entry["fields"]["logical_offset"], 0);
    assert_eq!(entry["capture"]["upstream_truncated"], true);
    assert_eq!(entry["capture"]["fields_truncated"], json!([]));
    assert_eq!(entry["capture"]["original_text_bytes"], 318);
    assert_eq!(entry["capture"]["captured_text_bytes"], 255);
    assert_eq!(
        recover(
            &server,
            &original("metadata_largest_strings", &entry["ordinal"]),
            &[],
            false
        ),
        json!({"bytes":1024,"logical_offset":0,
            "preview":{"text":"界".repeat(85),"original_bytes":318,"truncated":true}})
    );
    let unavailable_text = server.ok(
        "/api/records",
        records("metadata_largest_strings", "UpstreamOnlyNeedle"),
    );
    assert_eq!(unavailable_text["total"], 1);
    assert_eq!(unavailable_text["entries"], json!([]));
    assert!(unavailable_text["next_after"].is_null());
    let catalog = server.ok("/api/datasets", json!({"action":"catalog"}));
    assert_eq!(
        catalog["scope"],
        "All captured records, not original source contents, discarded producer attributes, or every possible retention path."
    );
    assert_eq!(
        catalog["comparison_scope"],
        "Captured comparison report; compiler identity deltas retain the upstream comparison top-N limit."
    );
    server.stop();
}

#[test]
fn comparison_originals_retain_real_upstream_top_n_limit() {
    // Real MSTAT artifacts, not forged comparison JSON: 105 fixed positive deltas.
    let root = tempfile::tempdir().unwrap();
    let mut paths = Vec::new();
    for (name, after) in [("before", false), ("after", true)] {
        let mut image = common::Image::new();
        for n in 1..=105_i32 {
            image.method(
                format!("Owner__Delta{n:03}").as_bytes(),
                if after { n + 1 } else { 1 },
            );
        }
        let artifact_path = root.path().join(format!("{name}.mstat"));
        fs::write(&artifact_path, image.bytes()).unwrap();
        let mut base = evidence();
        base.artifacts.push(Artifact {
            kind: "mstat".into(),
            path: artifact_path,
            revision: None,
            blake3: None,
        });
        let manifest = root.path().join(format!("{name}.json"));
        write_json(&manifest, &base);
        let index = root.path().join(name);
        vitnet_attribution::import(&manifest, &index, MEMORY, false).unwrap();
        paths.push(index);
    }
    let bundle = root.path().join("comparison");
    let prepared = data::prepare(
        &paths[1],
        &bundle,
        &[],
        Some(&paths[0]),
        &[],
        "scan_index",
        MEMORY,
        &IndexControl::default(),
    )
    .unwrap();
    let comparison_fixture = Fixture {
        root,
        index: paths[1].clone(),
        bundle,
        generation: prepared.generation,
    };
    let mut server = Server::start(&comparison_fixture);
    let page = server.ok("/api/records", records("comparison", ""));
    assert_eq!(page["total"], 1);
    let query = original("comparison", &page["entries"][0]["ordinal"]);
    let comparison = recover(&server, &query, &[], false);
    assert_eq!(comparison["mstat"]["total_delta_bytes"], 5565);
    assert_eq!(
        comparison["mstat"]["reconciliation"]["total_delta_bytes"],
        5565
    );
    assert_eq!(comparison["mstat"]["reconciliation"]["balanced"], true);
    let methods = comparison["mstat"]["sections"]
        .as_array()
        .unwrap()
        .iter()
        .find(|section| section["name"] == "Methods")
        .unwrap();
    assert_eq!(methods["changed"], 105);
    assert_eq!(methods["delta_bytes"], 5565);
    let deltas = methods["entries"].as_array().unwrap();
    assert_eq!(deltas.len(), 100);
    for (entry, n) in deltas.iter().zip((6..=105).rev()) {
        assert_eq!(entry["identity"], format!("Owner__Delta{n:03}"));
        assert_eq!(entry["before_bytes"], 1);
        assert_eq!(entry["after_bytes"], n + 1);
        assert_eq!(entry["delta_bytes"], n);
    }
    assert_eq!(
        deltas
            .iter()
            .map(|entry| entry["delta_bytes"].as_i64().unwrap())
            .sum::<i64>(),
        5550
    );
    assert_eq!(methods["delta_bytes"].as_i64().unwrap() - 5550, 15);
    let catalog = server.ok("/api/datasets", json!({"action":"catalog"}));
    assert!(
        catalog["comparison_scope"]
            .as_str()
            .unwrap()
            .contains("upstream comparison top-N limit")
    );
    assert!(
        !deltas
            .iter()
            .any(|entry| entry["identity"] == "Owner__Delta001")
    );
    server.stop();
}

#[test]
fn legacy_ranked_rows_is_unavailable_while_old_access_survives() {
    let rows = seed();
    for remove_catalogs in [false, true] {
        let mut fixture = Fixture::with(&rows, |_| {
            let mut base = evidence();
            base.packages.push(Package {
                target: "net10/win-x64".into(),
                id: "LegacyPkg".into(),
                version: "1".into(),
                direct: true,
                dependencies: vec!["Dependency/1".into()],
            });
            base.assemblies.push(Assembly {
                name: "App".into(),
                package: Some("LegacyPkg/1".into()),
                ..Assembly::default()
            });
            (base, vec![])
        });
        fixture.legacy(remove_catalogs);
        let mut server = Server::start(&fixture);
        server
            .submit("/api/rows", ranked(100))
            .error(400, "explorer.ranking.unavailable");
        let old = server.ok(
            "/api/query",
            json!({
                "action":"rows","contains":"","stream":null,"assembly":null,"owner":null,
                "after":null,"limit":100,
            }),
        );
        let entries = old["entries"].as_array().unwrap();
        assert_eq!(ordinals(entries), [0, 1, 2, 3, 4, 5, 6]);
        assert_eq!(old["order"], "cache_ordinal");
        assert!(old["next_after"].is_null());
        for (ordinal, entry) in entries.iter().enumerate() {
            assert_row(entry, &rows[ordinal], u64::try_from(ordinal).unwrap());
        }
        let packages = server.ok("/api/records", records("packages", ""));
        assert_eq!(packages["total"], 1);
        assert_eq!(packages["entries"][0]["fields"]["id"], "LegacyPkg");
        assert_eq!(
            recover(
                &server,
                &original("packages", &packages["entries"][0]["ordinal"]),
                &[],
                false
            ),
            json!({"id":"LegacyPkg","version":"1","target":"net10/win-x64",
                "direct":true,"dependencies":["Dependency/1"]})
        );
        let identity_query =
            json!({"action":"identity_value","ordinal":"1","path":[],"start":0,"key":false});
        let identity = recover(&server, &identity_query, &[], false);
        assert_eq!(identity, serde_json::to_value(&rows[1]).unwrap());
        let catalog = server.ok("/api/datasets", json!({"action":"catalog"}));
        assert_eq!(catalog["ranking_available"], false);
        let datasets: BTreeSet<_> = catalog["datasets"]
            .as_array()
            .unwrap()
            .iter()
            .map(|item| item["name"].as_str().unwrap())
            .collect();
        if remove_catalogs {
            assert!(!datasets.contains("scopes"));
            assert!(!datasets.contains("assembly_links"));
            server
                .submit("/api/records", records("scopes", ""))
                .error(400, "explorer.dataset");
            server
                .submit("/api/relations", relations(1))
                .error(400, "explorer.dataset");
        } else {
            assert!(datasets.contains("scopes") && datasets.contains("assembly_links"));
            let links = page_all(&server, "/api/relations", relations(1), 1);
            assert_eq!(
                projected_link(&links[0]),
                link("App", "LegacyPkg/1", "", "recorded_assembly_package")
            );
        }
        server.stop();
    }
    let fixture = Fixture::new(&[]);
    let mut server = Server::start(&fixture);
    let empty = server.ok("/api/rows", ranked(100));
    assert_eq!(empty["total"], 0);
    assert_eq!(empty["entries"], json!([]));
    assert_eq!(empty["stop_reason"], "complete");
    assert!(empty["next_after"].is_null());
    server.stop();
}

fn validation_fixture() -> Fixture {
    let rows = [
        row("App_Box<a界z>__Run", "Methods", 30),
        row("Plain__Run", "Methods", 20),
        row("App_Box<long>__Run", "Methods", 10),
    ];
    Fixture::with(&rows, |root| {
        let mut base = evidence();
        base.assemblies.push(Assembly {
            name: "App".into(),
            package: Some("Pkg/1".into()),
            ..Assembly::default()
        });
        base.packages.push(Package {
            id: "Pkg".into(),
            version: "1".into(),
            target: "net10/win-x64".into(),
            dependencies: vec!["A/1".into(), "B/1".into()],
            ..Package::default()
        });
        base.sources.push(source(root, "member.cs", "App", "Box"));
        (base, vec![])
    })
}

#[test]
fn new_endpoint_validation_auth_and_errors_are_structured() {
    let fixture = validation_fixture();
    let mut server = Server::start(&fixture);
    for (endpoint, valid, wrong) in [
        ("/api/rows", ranked(1), shape(0)),
        ("/api/value", shape(0), ranked(1)),
        ("/api/relations", relations(1), shape(0)),
    ] {
        let canonical = server.ok(endpoint, valid.clone());
        assert_eq!(
            semantic(canonical),
            semantic(server.ok("/api/query", valid.clone()))
        );
        server
            .submit(endpoint, wrong)
            .error(400, "explorer.request");
        let mut wire = valid.clone();
        wire["generation"] = json!(server.generation);
        wire["request_id"] = json!("validation");
        let encoded = serde_json::to_vec(&wire).unwrap();
        for headers in [
            "Content-Type: application/json\r\n".to_owned(),
            "Authorization: Bearer wrong\r\nContent-Type: application/json\r\n".to_owned(),
            format!(
                "{}Authorization: Bearer {}\r\n",
                server.auth(),
                server.token
            ),
        ] {
            server
                .request(endpoint, &encoded, &headers)
                .error(403, "explorer.authorization");
        }
        server
            .request(endpoint, b"{", &server.auth())
            .error(400, "explorer.request.json");
        let mut stale = valid.clone();
        stale["generation"] = json!("different-generation");
        server
            .submit(endpoint, stale)
            .error(409, "explorer.generation");
        for id in ["", "bad/id", "with space", &"x".repeat(65)] {
            let mut invalid = valid.clone();
            invalid["request_id"] = json!(id);
            server
                .submit(endpoint, invalid)
                .error(409, "explorer.request_id");
        }
        let mut unknown_field = valid.clone();
        unknown_field["unexpected"] = json!(true);
        server
            .submit(endpoint, unknown_field)
            .error(400, "explorer.request.json");
    }
    let bad_host = format!(
        "POST /api/rows HTTP/1.1\r\nHost: example.invalid\r\n{}Content-Length: 2\r\n\r\n{{}}",
        server.auth(),
    );
    server.raw(bad_host.as_bytes()).error(403, "explorer.host");
    server
        .request(
            "/api/rows",
            b"{}",
            &format!("{}Origin: null\r\n", server.auth()),
        )
        .error(403, "explorer.origin");
    let good_origin = format!("{}Origin: http://{}\r\n", server.auth(), server.address);
    let mut origin_wire = ranked(1);
    origin_wire["generation"] = json!(server.generation);
    origin_wire["request_id"] = json!("origin");
    let accepted = server
        .request(
            "/api/rows",
            &serde_json::to_vec(&origin_wire).unwrap(),
            &good_origin,
        )
        .ok();
    assert_eq!(ordinals(accepted["entries"].as_array().unwrap()), [0]);
    server
        .request(
            "/api/rows",
            b"{}",
            &format!(
                "Authorization: Bearer {}\r\nContent-Type: text/plain\r\n",
                server.token,
            ),
        )
        .error(400, "explorer.content_type");
    let body_overflow = format!(
        "POST /api/rows HTTP/1.1\r\nHost: {}\r\n{}Content-Length: 16385\r\n\r\n",
        server.address,
        server.auth(),
    );
    server
        .raw(body_overflow.as_bytes())
        .error(413, "resource.explorer.request");
    server
        .submit("/api/query", json!({"action":"not_an_action"}))
        .error(400, "explorer.request.json");
    server.stop();
}

fn assert_filter_budget_boundary(server: &Server, endpoint: &str, field: &str, length: usize) {
    for size in [length - 1, length, length + 1] {
        let mut query = if endpoint == "/api/rows" {
            ranked(100)
        } else {
            relations(100)
        };
        query[field] = json!("x".repeat(size));
        if size > length {
            server
                .submit(endpoint, query)
                .error(413, "resource.explorer.query");
        } else {
            let page = server.ok(endpoint, query);
            assert_eq!(page["total"], if endpoint == "/api/rows" { 3 } else { 1 });
            assert_eq!(page["entries"], json!([]));
            assert_eq!(page["stop_reason"], "complete");
            assert!(page["next_after"].is_null());
        }
    }
}

#[test]
fn ranked_and_relation_filter_budgets_and_page_boundaries_are_checked() {
    let fixture = validation_fixture();
    let mut server = Server::start(&fixture);
    for (field, length) in [
        ("contains", 1024),
        ("stream", 64),
        ("assembly", 4096),
        ("owner", 4096),
        ("family", 4096),
    ] {
        assert_filter_budget_boundary(&server, "/api/rows", field, length);
    }
    for field in ["assembly", "package", "target"] {
        assert_filter_budget_boundary(&server, "/api/relations", field, 4096);
    }

    for (endpoint, base, total) in [
        ("/api/rows", ranked(100), 3_u64),
        ("/api/relations", relations(100), 1),
    ] {
        for limit in [1, 100] {
            let mut query = base.clone();
            query["limit"] = json!(limit);
            let page = server.ok(endpoint, query);
            assert_eq!(
                page["entries"].as_array().unwrap().len(),
                usize::try_from(total).unwrap().min(limit)
            );
        }
        for limit in [0, 101] {
            let mut query = base.clone();
            query["limit"] = json!(limit);
            server
                .submit(endpoint, query)
                .error(413, "resource.explorer.query");
        }
        let mut terminal = base.clone();
        terminal["after"] = json!((total - 1).to_string());
        let page = server.ok(endpoint, terminal);
        assert_eq!(page["entries"], json!([]));
        assert_eq!(page["scanned"], 0);
        assert_eq!(page["stop_reason"], "complete");
        assert!(page["next_after"].is_null());
        for after in [json!(total.to_string()), json!(u64::MAX.to_string())] {
            let mut query = base.clone();
            query["after"] = after;
            server.submit(endpoint, query).error(400, "explorer.cursor");
        }
        for after in [
            json!(""),
            json!("-1"),
            json!(-1),
            json!("0.5"),
            json!(0.5),
            json!("abc"),
            json!(" 0"),
            json!("0 "),
            json!("18446744073709551616"),
        ] {
            let mut query = base.clone();
            query["after"] = after;
            server
                .submit(endpoint, query)
                .error(400, "explorer.request.json");
        }
        let mut string_zero = base.clone();
        string_zero["after"] = json!("0");
        let mut numeric_zero = base;
        numeric_zero["after"] = json!(0);
        let after_zero = server.ok(endpoint, string_zero);
        assert_eq!(after_zero["scanned"], total - 1);
        assert_eq!(after_zero["stop_reason"], "complete");
        assert!(after_zero["next_after"].is_null());
        if endpoint == "/api/rows" {
            assert_eq!(ordinals(after_zero["entries"].as_array().unwrap()), [1, 2]);
        } else {
            assert_eq!(after_zero["entries"], json!([]));
        }
        assert_eq!(
            semantic(after_zero),
            semantic(server.ok(endpoint, numeric_zero))
        );
    }
    server.stop();
}

#[test]
fn signed_decimal_ranked_cursor_is_not_an_unsigned_decimal_string() {
    let fixture = validation_fixture();
    let mut server = Server::start(&fixture);
    let mut query = ranked(100);
    query["after"] = json!("+0");
    server
        .submit("/api/rows", query)
        .error(400, "explorer.request.json");
    server.stop();
}

#[test]
fn signed_decimal_relation_cursor_is_not_an_unsigned_decimal_string() {
    let fixture = validation_fixture();
    let mut server = Server::start(&fixture);
    let mut query = relations(100);
    query["after"] = json!("+0");
    server
        .submit("/api/relations", query)
        .error(400, "explorer.request.json");
    server.stop();
}

#[test]
fn shape_ordinals_and_request_id_validate_unsigned_and_length_boundaries() {
    let fixture = validation_fixture();
    let mut server = Server::start(&fixture);
    for ordinal in [
        Value::Null,
        json!("-1"),
        json!(-1),
        json!("18446744073709551616"),
    ] {
        let mut query = shape(0);
        query["ordinal"] = ordinal;
        server
            .submit("/api/value", query)
            .error(400, "explorer.request.json");
    }
    let mut missing = shape(0);
    missing.as_object_mut().unwrap().remove("ordinal");
    server
        .submit("/api/value", missing)
        .error(400, "explorer.request.json");
    for ordinal in ["3", "18446744073709551615"] {
        let mut query = shape(0);
        query["ordinal"] = json!(ordinal);
        server
            .submit("/api/value", query)
            .error(400, "explorer.row");
    }
    let mut numeric = shape(0);
    numeric["ordinal"] = json!(0);
    assert_eq!(
        server.ok("/api/value", shape(0)),
        server.ok("/api/value", numeric)
    );
    let mut boundary_id = ranked(1);
    boundary_id["request_id"] = json!("x".repeat(64));
    assert_eq!(
        ordinals(
            server.ok("/api/rows", boundary_id)["entries"]
                .as_array()
                .unwrap()
        ),
        [0]
    );
    server.stop();
}

#[test]
fn shape_ordinals_and_value_navigation_validate_boundaries() {
    let fixture = validation_fixture();
    let mut server = Server::start(&fixture);
    let query = shape(0);
    let arguments = field_path(&server, &query, "arguments");
    let scalar = field_path(&server, &query, "canonical_shared");
    let mut string = arguments.clone();
    string.push(0);
    for (path, start, key, status, code) in [
        (vec![], 6, false, 400, "explorer.cursor"),
        (vec![99], 0, false, 400, "explorer.cursor"),
        (arguments.clone(), 2, false, 400, "explorer.cursor"),
        (
            {
                let mut p = arguments.clone();
                p.push(1);
                p
            },
            0,
            false,
            400,
            "explorer.cursor",
        ),
        (
            {
                let mut p = scalar.clone();
                p.push(0);
                p
            },
            0,
            false,
            400,
            "explorer.cursor",
        ),
        (scalar.clone(), 1, false, 400, "explorer.cursor"),
        (vec![], 0, true, 400, "explorer.cursor"),
        (string.clone(), 0, true, 400, "explorer.cursor"),
        (vec![0; 65], 0, false, 413, "resource.explorer.path"),
        (string.clone(), 2, false, 400, "explorer.cursor"),
        (string.clone(), 3, false, 400, "explorer.cursor"),
        (string.clone(), 6, false, 400, "explorer.cursor"),
    ] {
        let mut invalid = query.clone();
        invalid["path"] = json!(path);
        invalid["start"] = json!(start);
        invalid["key"] = json!(key);
        server.submit("/api/value", invalid).error(status, code);
    }
    for (start, expected) in [(0, "a界z"), (1, "界z"), (4, "z"), (5, "")] {
        let page = navigate(&server, &query, &string, start, false);
        assert_eq!(page["text"], expected);
        assert_eq!(page["total_bytes"], 5);
        assert!(page["next_start"].is_null());
    }
    for (path, start) in [(vec![], 5), (arguments, 1)] {
        let page = navigate(&server, &query, &path, start, false);
        assert_eq!(page["entries"], json!([]));
        assert!(page["next_start"].is_null());
    }
    assert_eq!(recover(&server, &query, &scalar, false), false);
    let packages = server.ok("/api/records", records("packages", ""));
    let package = original("packages", &packages["entries"][0]["ordinal"]);
    let dependencies = field_path(&server, &package, "dependencies");
    let end = navigate(&server, &package, &dependencies, 2, false);
    assert_eq!(end["entries"], json!([]));
    assert!(end["next_start"].is_null());
    let sources = server.ok("/api/records", records("sources", ""));
    let source_query = original("sources", &sources["entries"][0]["ordinal"]);
    let null_path = field_path(&server, &source_query, "sha256");
    assert_eq!(
        recover(&server, &source_query, &null_path, false),
        Value::Null
    );
    let mut invalid = source_query;
    invalid["path"] = json!(null_path);
    invalid["start"] = json!(1);
    server
        .submit("/api/value", invalid)
        .error(400, "explorer.cursor");
    server.stop();
}

fn budget_sequence(server: &Server, contains: &str, expected: &[u64]) {
    let mut query = ranked(100);
    query["contains"] = json!(contains);
    let deadline = Instant::now() + Duration::from_secs(120);
    let mut previous = None;
    let mut seen = Vec::new();
    let mut total_scanned = 0;
    for partial in 0..128 {
        assert!(Instant::now() < deadline, "bounded ranked scan deadline");
        let page = server.ok("/api/rows", query.clone());
        assert_eq!(page["total"], 100_001);
        assert_eq!(page["order"], "bytes_desc_ordinal_asc");
        assert!(page["elapsed_ms"].as_f64().unwrap() >= 0.0);
        let scanned = page["scanned"].as_u64().unwrap();
        assert!(scanned <= 100_000);
        total_scanned += scanned;
        seen.extend(ordinals(page["entries"].as_array().unwrap()));
        if page["next_after"].is_null() {
            assert_eq!(page["stop_reason"], "complete");
            assert_eq!(total_scanned, 100_001);
            assert_eq!(seen, expected);
            assert!(
                partial >= 1,
                "100001 ranks cannot complete in one <=100000 scan"
            );
            return;
        }
        assert_eq!(
            page["entries"],
            json!([]),
            "budget pages before tail have no matches"
        );
        assert!(["timeout", "max_scanned"].contains(&page["stop_reason"].as_str().unwrap()));
        let text = page["next_after"].as_str().unwrap();
        assert!(text.bytes().all(|byte| byte.is_ascii_digit()));
        let position = text.parse::<u64>().unwrap();
        assert!(position < 100_000 && previous.is_none_or(|old| position > old));
        assert_eq!(position + 1 - previous.map_or(0, |old| old + 1), scanned);
        assert!(scanned > 0);
        previous = Some(position);
        query["after"] = json!(text);
    }
    panic!("bounded scan did not reach the independently known tail");
}

#[test]
fn ranked_budget_progress_and_live_sidecar_drift_are_safe() {
    // The sole large HTTP fixture is necessary to cross the public 100000-row scan cap.
    let rows: Vec<_> = (0..100_001_u64)
        .map(|ordinal| {
            let argument = if ordinal == 100_000 {
                "TailNeedle".into()
            } else {
                format!("V{ordinal:06}")
            };
            row(
                &format!("App_Box<int>__Run<{argument}>"),
                "Methods",
                100_001 - ordinal,
            )
        })
        .collect();
    let fixture = Fixture::new(&rows);
    let mut server = Server::start(&fixture);
    budget_sequence(&server, "AbsentEverywhere", &[]);
    budget_sequence(&server, "TailNeedle", &[100_000]);
    let mut tail = ranked(1);
    tail["after"] = json!("99999");
    let page = server.ok("/api/rows", tail);
    assert_eq!(ordinals(page["entries"].as_array().unwrap()), [100_000]);
    assert_row(&page["entries"][0], &rows[100_000], 100_000);
    assert_eq!(page["stop_reason"], "complete");
    assert!(page["next_after"].is_null());
    // Length, not mtime granularity or a sleep, proves drift of the already-open sidecar.
    let sidecar = fixture.bundle.join("ranking.bin");
    let before = fs::metadata(&sidecar).unwrap().len();
    let mut file = fs::OpenOptions::new().append(true).open(&sidecar).unwrap();
    file.write_all(&[0]).unwrap();
    file.sync_all().unwrap();
    drop(file);
    assert_eq!(fs::metadata(&sidecar).unwrap().len(), before + 1);
    server
        .submit("/api/rows", ranked(1))
        .error(409, "explorer.ranking.stale");
    server.stop();
}

#[test]
fn query_cancellation_registry_is_scoped_and_reusable() {
    let fixture = Fixture::with(&[row("App_Box<int>__Run", "Methods", 37)], |_| {
        let mut base = evidence();
        base.assemblies.push(Assembly {
            name: "App".into(),
            package: Some("Pkg/1".into()),
            ..Assembly::default()
        });
        (base, vec![])
    });
    let mut server = Server::start(&fixture);
    assert_eq!(
        server
            .post("/api/cancel", &json!({"request_id":"absent"}))
            .ok(),
        json!({"cancelled":false})
    );
    for (id, endpoint, mut query) in [
        ("completed-ranked", "/api/rows", ranked(1)),
        ("completed-shape", "/api/value", shape(0)),
        ("completed-relations", "/api/relations", relations(1)),
    ] {
        query["request_id"] = json!(id);
        let first = server.ok(endpoint, query.clone());
        match endpoint {
            "/api/rows" => {
                assert_eq!(ordinals(first["entries"].as_array().unwrap()), [0]);
                assert_eq!(first["entries"][0]["bytes"], 37);
                assert_eq!(first["total"], 1);
                assert!(first["next_after"].is_null());
            }
            "/api/value" => {
                assert_eq!(
                    recover(&server, &query, &[], false),
                    json!({
                        "family":"App_Box<>__Run","arguments":["int"],"group_boundaries":[1],
                        "canonical_shared":false,"producer_name":"App_Box<int>__Run",
                    })
                );
            }
            "/api/relations" => {
                assert_eq!(first["total"], 1);
                assert_eq!(first["entries"].as_array().unwrap().len(), 1);
                assert_eq!(
                    projected_link(&first["entries"][0]),
                    link("App", "Pkg/1", "", "recorded_assembly_package")
                );
                assert!(first["next_after"].is_null());
            }
            _ => unreachable!(),
        }
        for _ in 0..2 {
            assert_eq!(
                server.post("/api/cancel", &json!({"request_id":id})).ok(),
                json!({"cancelled":false})
            );
            let reused = server.ok(endpoint, query.clone());
            assert_eq!(semantic(reused), semantic(first.clone()));
        }
        assert_eq!(
            server.post("/api/cancel", &json!({"request_id":id})).ok(),
            json!({"cancelled":false})
        );
    }
    // No public active-work synchronization exists; no sleep/race is used as cancellation proof.
    server.stop();
}

fn long_family_fixture() -> (Fixture, String) {
    let prefix = format!("Z_{}Selected", "界".repeat(200));
    let mut rows: Vec<_> = (0..101)
        .map(|n| row(&format!("A_F{n:03}<int>__Run"), "Methods", 100))
        .collect();
    rows.extend([
        row(&format!("{prefix}<int>__Run"), "Methods", 3),
        row(&format!("{prefix}<long>__Run"), "Methods", 2),
        row(
            &format!("Z_{}Neighbor<int>__Run", "界".repeat(200)),
            "Methods",
            1,
        ),
    ]);
    (Fixture::new(&rows), format!("{prefix}<>__Run"))
}

#[test]
fn family_record_uses_complete_catalog_ordinal_and_original_truncated_family() {
    let (fixture, family) = long_family_fixture();
    let snapshot: Value =
        serde_json::from_slice(&fs::read(fixture.bundle.join("snapshot.json")).unwrap()).unwrap();
    assert_eq!(snapshot["coverage"]["generic_family_count"], 103);
    assert_eq!(snapshot["generic_families"].as_array().unwrap().len(), 100);
    assert!(
        !snapshot["generic_families"]
            .as_array()
            .unwrap()
            .iter()
            .any(|entry| entry["family"] == family)
    );
    let mut server = Server::start(&fixture);
    let page = server.ok("/api/records", records("generic_families", "Selected"));
    assert_eq!(page["total"], 103);
    assert_eq!(page["entries"].as_array().unwrap().len(), 1);
    let entry = &page["entries"][0];
    assert_eq!(entry["ordinal"], "101");
    assert_eq!(entry["fields"]["family"], format!("Z_{}", "界".repeat(170)));
    assert_eq!(entry["capture"]["fields_truncated"], json!(["family"]));
    assert_eq!(entry["capture"]["upstream_truncated"], false);
    assert_eq!(
        recover(
            &server,
            &original("generic_families", &json!("101")),
            &[],
            false
        ),
        json!({"stream":"Methods","family":family,"bytes":5,"identities":2,
            "canonical_shared_identities":0})
    );
    for selector in [json!(101), json!("101")] {
        for limit in [1, 100] {
            let mut query = ranked(limit);
            query["stream"] = json!("Methods");
            query["family_record"] = selector.clone();
            assert_eq!(
                ordinals(&page_all(&server, "/api/rows", query.clone(), 104)),
                [101, 102]
            );
            query["contains"] = json!("<long>");
            let page = server.ok("/api/rows", query);
            assert_eq!(ordinals(page["entries"].as_array().unwrap()), [102]);
            assert_scope(&page, Some(5), Some(2));
            assert!(
                page["scope"]["basis"]
                    .as_str()
                    .unwrap()
                    .contains("before the text filter")
            );
        }
    }
    for (catalog_ordinal, expected_rows) in [(0, vec![0]), (102, vec![103])] {
        let mut query = ranked(100);
        query["family_record"] = json!(catalog_ordinal);
        assert_eq!(
            ordinals(&page_all(&server, "/api/rows", query, 104)),
            expected_rows
        );
    }
    // A spelling is also resolved from the full producer identity, not its Row label.
    let mut query = ranked(100);
    query["family"] = json!(family);
    query["family_record"] = Value::Null;
    assert_eq!(
        ordinals(&page_all(&server, "/api/rows", query, 104)),
        [101, 102]
    );
    server.stop();
}

#[test]
fn family_record_rejects_invalid_ordinals_and_mutually_exclusive_spelling() {
    let (fixture, family) = long_family_fixture();
    let mut server = Server::start(&fixture);
    for value in [
        json!(-1),
        json!("-1"),
        json!(0.5),
        json!("0.5"),
        json!(""),
        json!("abc"),
        json!(" 101"),
        json!("101 "),
        json!("18446744073709551616"),
        json!(true),
        json!([]),
        json!({}),
    ] {
        let mut query = ranked(1);
        query["family_record"] = value;
        server
            .submit("/api/rows", query)
            .error(400, "explorer.request.json");
    }
    for value in [
        json!(103),
        json!("103"),
        json!(u64::MAX),
        json!(u64::MAX.to_string()),
    ] {
        let mut query = ranked(1);
        query["family_record"] = value;
        server
            .submit("/api/rows", query)
            .error(400, "explorer.cursor");
    }
    for spelling in [family.as_str(), ""] {
        let mut query = ranked(1);
        query["family_record"] = json!("101");
        query["family"] = json!(spelling);
        server
            .submit("/api/rows", query)
            .error(400, "explorer.query");
    }
    let mut query = ranked(100);
    query["family_record"] = json!("101");
    query["owner"] = json!(format!("Z_{}Selected", "界".repeat(200)));
    let page = server.ok("/api/rows", query);
    assert_eq!(ordinals(page["entries"].as_array().unwrap()), [101, 102]);
    assert_scope(&page, None, None);
    assert_eq!(
        page["scope"]["basis"],
        "Combined filter denominator is not a precomputed additive partition."
    );
    server.stop();
}

#[test]
fn captured_string_pages_fill_utf8_budget_at_empty_exact_and_split_boundaries() {
    let (fixture, _, _) = domain_fixture();
    let mut server = Server::start(&fixture);
    for (ordinal, expected_preview, expected_text) in [
        ("0", "b".repeat(511), format!("{}界Tail", "b".repeat(511))),
        ("1", String::new(), String::new()),
        ("2", "c".repeat(512), "c".repeat(4096)),
        (
            "3",
            "a".repeat(512),
            format!("{}界CapturedNeedle", "a".repeat(4095)),
        ),
    ] {
        let query = original("provenance", &json!(ordinal));
        let path = field_path(&server, &query, "value");
        let captured = recover(&server, &query, &path, false);
        assert_eq!(captured, expected_text);
        let first = navigate(&server, &query, &path, 0, false);
        if ordinal == "3" {
            assert_eq!(first["text"], "a".repeat(4095));
            assert_eq!(first["next_start"], 4095);
            let tail = navigate(&server, &query, &path, 4095, false);
            assert_eq!(tail["text"], "界CapturedNeedle");
            assert!(tail["next_start"].is_null());
        } else {
            assert_eq!(first["text"], expected_text);
            assert!(first["next_start"].is_null());
        }
        let end = navigate(
            &server,
            &query,
            &path,
            u64::try_from(expected_text.len()).unwrap(),
            false,
        );
        assert_eq!(end["text"], "");
        assert!(end["next_start"].is_null());
        let page = server.ok("/api/records", records("provenance", ""));
        let entry = &page["entries"][ordinal.parse::<usize>().unwrap()];
        assert_eq!(entry["fields"]["value"], expected_preview);
        assert_eq!(
            entry["capture"]["fields_truncated"],
            if ordinal == "1" {
                json!([])
            } else {
                json!(["value"])
            }
        );
        assert_eq!(entry["capture"]["upstream_truncated"], false);
        assert_eq!(entry["capture"]["original_text_bytes"], Value::Null);
        assert_eq!(entry["capture"]["captured_text_bytes"], Value::Null);
    }
    server.stop();
}

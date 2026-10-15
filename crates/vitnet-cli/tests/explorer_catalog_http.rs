//! Full-data HTTP contracts: only synthetic, owned ephemeral loopback children.
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};
use vitnet_attribution::model::{
    Artifact, EVIDENCE_SCHEMA, Evidence, Generator, GeneratorLink, GeneratorOutput, GeneratorRun,
    Mapping, Package, Resource, Source,
};
use vitnet_cli::explorer::data;
use vitnet_dgml::{IndexControl, IndexOptions, build_index};
use vitnet_mstat::CoalescedIdentity;

#[allow(dead_code)]
#[path = "../../vitnet-attribution/tests/common/mod.rs"]
mod common;

const MEMORY: u64 = 128 << 20;
const WAIT: Duration = Duration::from_secs(15);

fn write_json(path: &Path, value: &impl serde::Serialize) {
    fs::write(path, serde_json::to_vec(value).unwrap()).unwrap();
}

fn read_json(path: &Path) -> Value {
    serde_json::from_slice(&fs::read(path).unwrap()).unwrap()
}

fn evidence() -> Evidence {
    Evidence {
        schema: EVIDENCE_SCHEMA.into(),
        label: "synthetic full-data HTTP".into(),
        ..Evidence::default()
    }
}

fn row(identity: &str, bytes: u64) -> CoalescedIdentity {
    CoalescedIdentity {
        stream: "Methods".into(),
        identity: identity.into(),
        bytes,
        records: 1,
        accounted: true,
        identity_lossy: false,
        raw_identity_blake3: blake3::hash(identity.as_bytes()).to_hex().to_string(),
    }
}

fn long_text() -> String {
    // 4-byte and 2-byte scalars cross both the 512-byte preview and 4096-byte page.
    format!("{}END-OF-COMPLETE-TEXT", "🦀é".repeat(1500))
}

struct Fixture {
    root: tempfile::TempDir,
    index: PathBuf,
    bundle: PathBuf,
    generation: String,
}

impl Fixture {
    fn new(value: &Evidence, rows: &[CoalescedIdentity]) -> Self {
        Self::build(value, rows, None)
    }

    fn build(value: &Evidence, rows: &[CoalescedIdentity], graph: Option<&str>) -> Self {
        let root = tempfile::tempdir().unwrap();
        let mut value = value.clone();
        if let Some(xml) = graph {
            let input = root.path().join("synthetic.dgml");
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
            value.artifacts.push(Artifact {
                kind: "scan_index".into(),
                path: indexed.index_directory,
                revision: None,
                blake3: None,
            });
        }
        let input = root.path().join("evidence.json");
        write_json(&input, &value);
        let index = root.path().join("index");
        let mut manifest = vitnet_attribution::import(&input, &index, MEMORY, false).unwrap();
        let mut bytes = Vec::new();
        for row in rows {
            bytes.extend(serde_json::to_vec(row).unwrap());
            bytes.push(b'\n');
        }
        fs::write(index.join("identities.ndjson"), &bytes).unwrap();
        manifest.identities = u64::try_from(rows.len()).unwrap();
        manifest.identities_blake3 = blake3::hash(&bytes).to_hex().to_string();
        write_json(&index.join("index.json"), &manifest);
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

    fn rich() -> Self {
        let mut value = evidence();
        for id in 0..101 {
            value
                .provenance
                .insert(format!("property-{id:03}"), format!("value-{id:03}"));
            value.generators.push(Generator {
                name: format!("generator-{id:03}"),
                version: "1".into(),
                assembly_path: format!("generator-{id:03}.dll").into(),
                generated_files: (0..61)
                    .map(|i| PathBuf::from(format!("generated-{i:03}.cs")))
                    .collect(),
                input_symbols: (0..121).map(|i| format!("input-{i:03}")).collect(),
            });
        }
        for id in 0..201 {
            value.resources.push(Resource {
                assembly: if id % 2 == 0 { "Even" } else { "Odd" }.into(),
                container: "bundle".into(),
                name: format!("resource-{id:03}"),
                bytes: 7,
                storage: "asset".into(),
                sha256: Some("b".repeat(64)),
                ..Resource::default()
            });
            value.packages.push(Package {
                target: "net10.0".into(),
                id: format!("package-{id:03}"),
                version: "1".into(),
                direct: true,
                dependencies: vec![],
            });
        }
        let rows: Vec<_> = (0..101)
            .map(|id| row(&format!("Owner{id:03}<System_Int32>__Run"), 101 - id))
            .collect();
        Self::new(&value, &rows)
    }

    // Generic JSON record fixtures exercise value traversal independently of
    // any particular Evidence schema. They remain valid immutable bundle files
    // with matching hashes/counts/offsets; no production hook or private data.
    fn replace_dataset(&mut self, name: &str, values: &[Value]) {
        let mut bytes = Vec::new();
        let mut offsets = Vec::new();
        for value in values {
            offsets.extend(u64::try_from(bytes.len()).unwrap().to_le_bytes());
            bytes.extend(serde_json::to_vec(value).unwrap());
            bytes.push(b'\n');
        }
        offsets.extend(u64::try_from(bytes.len()).unwrap().to_le_bytes());
        fs::write(self.bundle.join(format!("catalog_{name}.ndjson")), &bytes).unwrap();
        fs::write(
            self.bundle.join(format!("catalog_{name}.offsets")),
            &offsets,
        )
        .unwrap();
        let mut manifest = read_json(&self.bundle.join("bundle.json"));
        manifest["datasets"][name] = json!({
            "records":values.len(), "data_bytes":bytes.len(),
            "blake3":blake3::hash(&bytes).to_hex().to_string(),
            "offsets_blake3":blake3::hash(&offsets).to_hex().to_string(),
        });
        let mut snapshot = read_json(&self.bundle.join("snapshot.json"));
        snapshot["datasets"] = manifest["datasets"].clone();
        self.sync_generation(&mut manifest, &mut snapshot);
        data::verify(&self.bundle, MEMORY).unwrap();
    }

    fn sync_generation(&mut self, manifest: &mut Value, snapshot: &mut Value) {
        snapshot["generation"] = Value::Null;
        let mut fingerprint = blake3::Hasher::new();
        fingerprint.update(b"vitnet.explorer-generation.v1\0");
        fingerprint.update(manifest["index_blake3"].as_str().unwrap().as_bytes());
        fingerprint.update(manifest["identities_blake3"].as_str().unwrap().as_bytes());
        fingerprint.update(&serde_json::to_vec(snapshot).unwrap());
        self.generation = fingerprint.finalize().to_hex().to_string();
        snapshot["generation"] = json!(self.generation);
        manifest["generation"] = json!(self.generation);
        write_json(&self.bundle.join("snapshot.json"), snapshot);
        manifest["snapshot_blake3"] = json!(
            blake3::hash(&fs::read(self.bundle.join("snapshot.json")).unwrap())
                .to_hex()
                .to_string()
        );
        write_json(&self.bundle.join("bundle.json"), manifest);
    }

    fn legacy(&mut self) {
        let mut manifest = read_json(&self.bundle.join("bundle.json"));
        manifest.as_object_mut().unwrap().remove("datasets");
        let mut snapshot = read_json(&self.bundle.join("snapshot.json"));
        snapshot.as_object_mut().unwrap().remove("datasets");
        self.sync_generation(&mut manifest, &mut snapshot);
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
            assert_eq!(error.kind(), std::io::ErrorKind::ConnectionReset, "{error}");
        }
        let split = bytes
            .windows(4)
            .position(|part| part == b"\r\n\r\n")
            .expect("complete HTTP header");
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
        assert!(body.len() <= 2 << 20);
        for guard in [
            "Connection: close",
            "Cache-Control: no-store",
            "X-Content-Type-Options: nosniff",
        ] {
            assert!(headers.contains(guard), "missing {guard}");
        }
        Self {
            status,
            headers,
            body,
        }
    }

    fn json(&self) -> Value {
        serde_json::from_slice(&self.body).unwrap()
    }

    fn ok(&self) -> Value {
        assert_eq!(self.status, 200, "{}", String::from_utf8_lossy(&self.body));
        assert!(self.headers.contains("Content-Type: application/json"));
        self.json()
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
        assert_eq!(
            body.as_object().unwrap().len(),
            1,
            "errors must not leak data"
        );
        assert_eq!(body["error"].as_object().unwrap().len(), 2);
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
            let mut reader = BufReader::new(stdout);
            let mut first = String::new();
            let result = reader.read_line(&mut first);
            let _ = sender.send((result, first));
            let _ = std::io::copy(&mut reader, &mut std::io::sink());
        });
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
            .expect("owned Explorer URL");
        let (address, token) = url
            .split_once("/#token=")
            .expect("fragment-only capability");
        owned.address = address.parse().unwrap();
        owned.token = token.into();
        assert!(owned.address.ip().is_loopback());
        assert_ne!(owned.address.port(), 0);
        assert_eq!(owned.token.len(), 64);
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

    fn auth(&self) -> String {
        format!(
            "Authorization: Bearer {}\r\nContent-Type: application/json\r\n",
            self.token
        )
    }

    fn request(&self, body: &[u8], extra: &str) -> Response {
        let mut bytes = format!(
            "POST /api/query HTTP/1.1\r\nHost: {}\r\n{extra}Content-Length: {}\r\n\r\n",
            self.address,
            body.len()
        )
        .into_bytes();
        bytes.extend(body);
        self.raw(&bytes)
    }

    fn post(&self, path: &str, body: &Value) -> Response {
        let body = serde_json::to_vec(body).unwrap();
        let mut bytes = format!(
            "POST {path} HTTP/1.1\r\nHost: {}\r\n{}Content-Length: {}\r\n\r\n",
            self.address,
            self.auth(),
            body.len()
        )
        .into_bytes();
        bytes.extend(body);
        self.raw(&bytes)
    }

    fn query(&self, fixture: &Fixture, mut query: Value) -> Response {
        query["request_id"] = json!("catalog-contract");
        query["generation"] = json!(fixture.generation);
        self.post("/api/query", &query)
    }

    fn stop(&mut self) {
        let response = self.post("/api/shutdown", &json!({}));
        assert_eq!(response.ok(), json!({"stopped":true}));
        let deadline = Instant::now() + WAIT;
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                assert!(status.success(), "owned child failed {status}");
                break;
            }
            assert!(Instant::now() < deadline, "owned shutdown deadline");
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
                let _ = self.child.kill(); // Only the fixture-owned PID.
                let _ = self.child.wait();
            }
        }
    }
}

fn ordinals(page: &Value) -> Vec<u64> {
    page["entries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| {
            let text = entry["ordinal"]
                .as_str()
                .expect("lossless decimal string ordinal");
            let ordinal: u64 = text.parse().unwrap();
            assert_eq!(text, ordinal.to_string());
            assert!(entry["summary"].as_str().unwrap().len() <= 512);
            ordinal
        })
        .collect()
}

fn field_path(page: &Value, key: &str) -> u64 {
    page["entries"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["key"] == key)
        .unwrap_or_else(|| panic!("missing field {key}: {page}"))["index"]
        .as_u64()
        .unwrap()
}

fn value_query(dataset: &str, ordinal: u64, path: &[u64], start: u64) -> Value {
    json!({"action":"record_value","dataset":dataset,"ordinal":ordinal,"path":path,"start":start})
}

fn all_children(
    server: &Server,
    fixture: &Fixture,
    mut query: Value,
    total: u64,
    kind: &str,
) -> Vec<Value> {
    let mut start = 0_u64;
    let mut entries = Vec::new();
    for _ in 0..=total / 100 + 1 {
        query["start"] = json!(start);
        let page = server.query(fixture, query.clone()).ok();
        assert_eq!(page["kind"], kind);
        assert_eq!(page["total"], total);
        let items = page["entries"].as_array().unwrap();
        assert!(items.len() <= 100);
        for item in items {
            assert_eq!(
                item["index"],
                entries.len(),
                "stable child ordinals without gaps"
            );
            assert!(item["summary"].as_str().unwrap().len() <= 512);
            entries.push(item.clone());
        }
        let end = start + u64::try_from(items.len()).unwrap();
        if end == total {
            assert_eq!(page["next_start"], Value::Null);
            break;
        }
        assert!(!items.is_empty(), "continuation makes progress");
        assert_eq!(page["next_start"], end);
        start = end;
    }
    assert_eq!(u64::try_from(entries.len()).unwrap(), total);
    entries
}

fn full_text(server: &Server, fixture: &Fixture, mut query: Value, expected: &str) {
    let mut actual = String::new();
    for _ in 0..=expected.len() / 4093 + 1 {
        query["start"] = json!(actual.len());
        let page = server.query(fixture, query.clone()).ok();
        assert_eq!(page["kind"], "string");
        assert_eq!(page["total_bytes"], expected.len());
        let text = page["text"].as_str().unwrap();
        assert!(text.len() <= 4096);
        let before = actual.len();
        actual.push_str(text);
        assert_eq!(
            actual,
            expected[..actual.len()],
            "chunk content and byte boundaries"
        );
        if actual.len() == expected.len() {
            assert_eq!(page["next_start"], Value::Null);
            break;
        }
        assert!(actual.len() > before);
        assert_eq!(page["next_start"], actual.len());
    }
    assert_eq!(
        actual, expected,
        "no clipped/duplicated/missing UTF-8 suffix"
    );
}

#[test]
#[allow(clippy::too_many_lines)] // Adjacent text, child and traversal boundaries share one immutable fixture.
fn text_child_and_depth_boundaries_are_exact_including_empty_values_and_huge_integers() {
    let mut fixture = Fixture::new(&evidence(), &[]);
    let huge = "184467440737095516160001";
    let negative = "-184467440737095516160001";
    let strings = [
        String::new(),
        "é".repeat(256),
        "a".repeat(4095),
        "a".repeat(4096),
        "a".repeat(4097),
        format!("abc{}", "🦀".repeat(1024)),
    ];
    let mut values: Vec<_> = strings.iter().map(|text| json!(text)).collect();
    values.push(serde_json::from_str(huge).unwrap());
    values.push(serde_json::from_str(negative).unwrap());
    for count in [1, 99, 100, 101] {
        values.push(json!((0..count).map(|n| n.to_string()).collect::<Vec<_>>()));
    }
    let mut deep = json!("depth-64-value");
    for _ in 0..64 {
        deep = json!([deep]);
    }
    values.push(deep);
    fixture.replace_dataset("evidence_header", &values);
    let mut server = Server::start(&fixture);
    for (ordinal, expected) in strings.iter().enumerate() {
        full_text(
            &server,
            &fixture,
            value_query("evidence_header", ordinal as u64, &[], 0),
            expected,
        );
        let first = server
            .query(
                &fixture,
                value_query("evidence_header", ordinal as u64, &[], 0),
            )
            .ok();
        let first_len = first["text"].as_str().unwrap().len();
        assert_eq!(first_len, [0, 512, 4095, 4096, 4096, 4095][ordinal]);
        assert_eq!(
            first["next_start"],
            if ordinal < 4 {
                Value::Null
            } else {
                json!(first_len)
            }
        );
        let terminal = server
            .query(
                &fixture,
                value_query(
                    "evidence_header",
                    ordinal as u64,
                    &[],
                    expected.len() as u64,
                ),
            )
            .ok();
        assert_eq!(terminal["text"], "");
        assert_eq!(terminal["next_start"], Value::Null);
        server
            .query(
                &fixture,
                value_query(
                    "evidence_header",
                    ordinal as u64,
                    &[],
                    expected.len() as u64 + 1,
                ),
            )
            .error(400, "explorer.cursor");
    }
    for (ordinal, expected) in [(6, huge), (7, negative)] {
        let page = server
            .query(&fixture, value_query("evidence_header", ordinal, &[], 0))
            .ok();
        assert_eq!(page["kind"], "number");
        assert_eq!(page["display"], expected);
        assert_eq!(page["next_start"], Value::Null);
    }
    for (ordinal, total) in [(8, 1), (9, 99), (10, 100), (11, 101)] {
        let entries = all_children(
            &server,
            &fixture,
            value_query("evidence_header", ordinal, &[], 0),
            total,
            "array",
        );
        assert_eq!(entries.first().unwrap()["summary"], "0");
        assert_eq!(entries.last().unwrap()["summary"], (total - 1).to_string());
    }
    full_text(
        &server,
        &fixture,
        value_query("evidence_header", 12, &[0; 64], 0),
        "depth-64-value",
    );
    server
        .query(&fixture, value_query("evidence_header", 12, &[0; 65], 0))
        .error(413, "resource.explorer.path");
    server.stop();
}

#[test]
fn lossy_mapped_looking_identity_never_establishes_source_associations() {
    let mut value = evidence();
    value.sources.push(Source {
        assembly: "App".into(),
        type_name: "Owner".into(),
        member: Some("Run".into()),
        path: "missing.cs".into(),
        line: 1,
        end_line: 1,
        kind: "method".into(),
        ..Source::default()
    });
    value.mappings.push(Mapping {
        stream: "Methods".into(),
        identity: "Owner__Run".into(),
        assembly: "App".into(),
        source_paths: vec!["missing.cs".into()],
        basis: "explicit mapping".into(),
    });
    let exact = row("Owner__Run", 7);
    let mut lossy = row("Owner__Run", 11);
    lossy.identity_lossy = true;
    let fixture = Fixture::new(&value, &[exact, lossy]);
    let mut server = Server::start(&fixture);
    for (ordinal, status, count) in [(0, "asserted", 1_usize), (1, "unmapped_lossy_identity", 0)] {
        let root = server
            .query(&fixture, json!({"action":"source_value","ordinal":ordinal}))
            .ok();
        let status_path = field_path(&root, "status");
        full_text(
            &server,
            &fixture,
            json!({"action":"source_value","ordinal":ordinal,"path":[status_path]}),
            status,
        );
        for field in ["sources", "assemblies"] {
            let path = field_path(&root, field);
            let page = server
                .query(
                    &fixture,
                    json!({"action":"source_value","ordinal":ordinal,"path":[path]}),
                )
                .ok();
            assert_eq!(page["total"], count);
            assert_eq!(page["entries"].as_array().unwrap().len(), count);
            assert_eq!(page["next_start"], Value::Null);
        }
    }
    server.stop();
}

#[test]
fn canonical_rest_resources_match_query_and_reject_wrong_actions_without_data() {
    let fixture = Fixture::build(
        &evidence(),
        &[row("Owner__Run", 7)],
        Some(
            "<DirectedGraph><Nodes><Node Id=\"0\" Label=\"root\"/></Nodes><Links><Link Source=\"0\" Target=\"0\" Reason=\"self\"/></Links></DirectedGraph>",
        ),
    );
    let mut server = Server::start(&fixture);
    for mut query in guarded_actions() {
        query["request_id"] = json!("alias-contract");
        query["generation"] = json!(fixture.generation);
        let appropriate = match query["action"].as_str().unwrap() {
            "catalog" => "/api/datasets",
            "records" => "/api/records",
            _ => "/api/value",
        };
        let canonical = server.post(appropriate, &query).ok();
        assert_eq!(
            canonical,
            server.post("/api/query", &query).ok(),
            "compatible query action shape"
        );
        assert_eq!(canonical["generation"], fixture.generation);
        for path in ["/api/datasets", "/api/records", "/api/value"] {
            if path != appropriate {
                server.post(path, &query).error(400, "explorer.request");
            }
        }
        let body = serde_json::to_vec(&query).unwrap();
        let mut unauthorized = format!("POST {appropriate} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",server.address,body.len()).into_bytes();
        unauthorized.extend(&body);
        server
            .raw(&unauthorized)
            .error(403, "explorer.authorization");
        query["generation"] = json!("stale");
        server
            .post(appropriate, &query)
            .error(409, "explorer.generation");
    }
    server.stop();
}

#[test]
fn opportunity_rest_aliases_enforce_auth_generation_and_dataset_discriminators() {
    let fixture = Fixture::build(
        &evidence(),
        &[row("Box<int>__Run", 19), row("Box<string>__Run", 13)],
        Some(
            "<DirectedGraph><Nodes><Node Id=\"0\" Label=\"Root\"/><Node Id=\"1\" Label=\"Box&lt;int&gt;__Run\"/></Nodes><Links><Link Source=\"0\" Target=\"1\" Reason=\"\"/></Links></DirectedGraph>",
        ),
    );
    let mut server = Server::start(&fixture);
    for (path, mut query) in [
        (
            "/api/opportunities",
            json!({"action":"records","dataset":"opportunities","limit":1}),
        ),
        (
            "/api/budgets",
            json!({"action":"records","dataset":"budgets","filters":{"dimension":"assembly"}}),
        ),
        (
            "/api/retention",
            json!({"action":"annotated_why","graph":"scan_index","node_id":"1"}),
        ),
    ] {
        query["request_id"] = json!("opportunity-alias");
        query["generation"] = json!(fixture.generation);
        let actual = server.post(path, &query).ok();
        let canonical = server.post("/api/query", &query).ok();
        if path == "/api/retention" {
            assert_eq!(actual["witness"]["paths"], canonical["witness"]["paths"]);
            assert_eq!(
                actual["witness"]["generation"],
                canonical["witness"]["generation"]
            );
            assert_eq!(actual["witness"]["node"]["node_id"], "1");
            assert_eq!(actual["alternative_incoming"]["total_edges"], 1);
        } else {
            assert_eq!(actual["generation"], fixture.generation);
            assert_eq!(actual, canonical);
            assert_eq!(ordinals(&actual).len(), 1);
        }
        let mut wrong = query.clone();
        wrong["action"] = json!("records");
        wrong["dataset"] = json!("generator_runs");
        wrong.as_object_mut().unwrap().remove("graph");
        wrong.as_object_mut().unwrap().remove("node_id");
        server.post(path, &wrong).error(400, "explorer.request");
        let body = serde_json::to_vec(&query).unwrap();
        let mut unauthorized = format!(
            "POST {path} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
            server.address,
            body.len()
        )
        .into_bytes();
        unauthorized.extend(body);
        server
            .raw(&unauthorized)
            .error(403, "explorer.authorization");
        query["generation"] = json!("stale");
        server.post(path, &query).error(409, "explorer.generation");
    }
    server.stop();
}

#[test]
fn budget_filter_extensions_are_discovered_beyond_the_first_record() {
    let mut fixture = Fixture::new(&evidence(), &[]);
    fixture.replace_dataset(
        "budgets",
        &[
            json!({"dimension":"assembly"}),
            json!({"dimension":"assembly","selection":"yes"}),
        ],
    );
    let mut server = Server::start(&fixture);
    let page = server
        .query(
            &fixture,
            json!({"action":"records","dataset":"budgets","filters":{"selection":"yes"}}),
        )
        .ok();
    assert_eq!(ordinals(&page), [1]);
    assert_eq!(page["scanned"], 2);
    server
        .query(
            &fixture,
            json!({"action":"records","dataset":"budgets","filters":{"selection_typo":"yes"}}),
        )
        .error(400, "explorer.query");
    server.stop();
}

#[test]
fn connected_lens_http_ledgers_details_and_aliases_preserve_generation_and_scope() {
    let mut value = evidence();
    value.sources.push(Source {
        assembly: "App".into(),
        type_name: "Product.Models.Owner".into(),
        path: "Owner.cs".into(),
        line: 1,
        end_line: 3,
        kind: "class".into(),
        ..Source::default()
    });
    value.mappings.push(Mapping {
        stream: "Methods".into(),
        identity: "App_Owner<int>__Run".into(),
        assembly: "App".into(),
        source_paths: vec!["Owner.cs".into()],
        basis: "synthetic supplied route".into(),
    });
    let fixture = Fixture::new(
        &value,
        &[row("App_Owner<int>__Run", 19), row("unmapped", 7)],
    );
    let mut server = Server::start(&fixture);
    let mut request = json!({"request_id":"lens-http","generation":fixture.generation,
        "action":"feature_footprint","assembly":"App","namespace":"Product.Models"});
    let report = server.post("/api/footprint", &request).ok();
    assert_eq!(report["ledger"]["additive_bytes"], 19);
    assert_eq!(report["ledger"]["methods_bytes"], 19);
    assert_eq!(report["ledger"]["candidate_owner_bytes"], 19);
    assert_eq!(report["complete"], true);
    assert_eq!(report["examples"][0]["ordinal"], 0);
    request["namespace"] = json!("Product.Model");
    assert_eq!(
        server.post("/api/footprint", &request).ok()["matched_owner_groups"],
        0,
        "namespace boundary is not a substring"
    );
    let lens = json!({"request_id":"lens-http","generation":fixture.generation,
        "action":"records","dataset":"lens_feature_owners","filters":{"assembly":"App"}});
    let page = server.post("/api/lenses", &lens).ok();
    assert_eq!(ordinals(&page), [0]);
    let detail = server
        .post(
            "/api/lenses",
            &json!({"request_id":"lens-detail","generation":fixture.generation,
        "action":"lens_detail","dataset":"lens_feature_owners","ordinal":"0"}),
        )
        .ok();
    assert_eq!(detail["record"]["owner"], "Product.Models.Owner");
    assert_eq!(detail["record"]["additive_bytes"], 19);
    server
        .post("/api/lenses", &request)
        .error(400, "explorer.request");
    server
        .post("/api/footprint", &lens)
        .error(400, "explorer.request");
    request["generation"] = json!("stale");
    server
        .post("/api/footprint", &request)
        .error(409, "explorer.generation");
    server.stop();
}

#[test]
fn representative_cohort_http_preserves_original_witnesses_alternatives_and_limits() {
    let fixture = Fixture::build(
        &evidence(),
        &[row("Target", 19)],
        Some(
            "<DirectedGraph><Nodes><Node Id=\"0\" Label=\"Root\"/><Node Id=\"1\" Label=\"Target\"/><Node Id=\"2\" Label=\"Alternative\"/></Nodes><Links><Link Source=\"0\" Target=\"1\" Reason=\"\"/><Link Source=\"2\" Target=\"1\" Reason=\"alternative\"/></Links></DirectedGraph>",
        ),
    );
    let mut server = Server::start(&fixture);
    let mut request = json!({"request_id":"cohort-http","generation":fixture.generation,
        "action":"cohort_retention","graph":"scan_index","ordinals":["0"]});
    let report = server.post("/api/cohort-retention", &request).ok();
    assert_eq!(report["schema"], "vitnet.cohort-retention.v1");
    assert_eq!(report["complete"], false);
    assert_eq!(report["seeds"][0]["search"]["entries"][0]["node_id"], "1");
    assert_eq!(
        report["seeds"][0]["witnesses"][0]["alternative_incoming"]["total_edges"],
        2
    );
    assert_eq!(report["observed_roots"][0]["node_id"], "0");
    for ordinals in [json!([]), json!([0, 0]), json!([0, 1, 2, 3])] {
        request["ordinals"] = ordinals;
        server
            .post("/api/cohort-retention", &request)
            .error(413, "resource.explorer.query");
    }
    server.stop();
}

#[test]
fn generator_run_and_trigger_catalogs_keep_full_records_and_confidence_tiers() {
    let mut value = evidence();
    value.generator_runs.push(GeneratorRun {
        name: "SyntheticEmitter".into(),
        status: "output_unavailable".into(),
        execution_status: "not_observed".into(),
        basis: "synthetic recorded analyzer reference, not proof of execution".into(),
        outputs: vec![GeneratorOutput {
            path: "missing.g.cs".into(),
            build_match: "unknown".into(),
            ..GeneratorOutput::default()
        }],
        ..GeneratorRun::default()
    });
    for id in 0..101 {
        value.generator_links.push(GeneratorLink {
            generator: "SyntheticEmitter".into(),
            output_path: format!("output-{id:03}.g.cs").into(),
            trigger_symbol: Some(format!("trigger-{id:03}")),
            rule: format!("rule-{id:03}"),
            evidence_tier: if id == 100 { "supplied" } else { "candidate" }.into(),
            basis: long_text(),
            ..GeneratorLink::default()
        });
    }
    let fixture = Fixture::new(&value, &[]);
    let mut server = Server::start(&fixture);
    let runs = server
        .query(
            &fixture,
            json!({"action":"records","dataset":"generator_runs"}),
        )
        .ok();
    assert_eq!(ordinals(&runs), [0]);
    let run = server
        .query(&fixture, value_query("generator_runs", 0, &[], 0))
        .ok();
    let execution_status = usize::try_from(field_path(&run, "execution_status")).unwrap();
    assert_eq!(run["entries"][execution_status]["summary"], "not_observed");
    let first = server
        .query(
            &fixture,
            json!({"action":"records","dataset":"generator_links","limit":100}),
        )
        .ok();
    assert_eq!(ordinals(&first), (0..100).collect::<Vec<_>>());
    assert_eq!(first["next_after"], "99");
    let last = server
        .query(
            &fixture,
            json!({"action":"records","dataset":"generator_links","after":"99","limit":100}),
        )
        .ok();
    assert_eq!(ordinals(&last), [100]);
    assert_eq!(last["next_after"], Value::Null);
    let link = server
        .query(&fixture, value_query("generator_links", 100, &[], 0))
        .ok();
    let tier = field_path(&link, "evidence_tier");
    full_text(
        &server,
        &fixture,
        value_query("generator_links", 100, &[tier], 0),
        "supplied",
    );
    let basis = field_path(&link, "basis");
    full_text(
        &server,
        &fixture,
        value_query("generator_links", 100, &[basis], 0),
        &long_text(),
    );
    server.stop();
}

#[test]
fn retention_http_preserves_witness_alternatives_and_source_annotations() {
    let mut value = evidence();
    value.sources.push(Source {
        assembly: "App".into(),
        type_name: "Owner".into(),
        member: Some("Run".into()),
        path: "Owner.cs".into(),
        line: 3,
        end_line: 9,
        kind: "method".into(),
        attributes: vec!["ModuleInitializerAttribute".into()],
        ..Source::default()
    });
    value.mappings.push(Mapping {
        stream: "Methods".into(),
        identity: "Owner__Run".into(),
        assembly: "App".into(),
        source_paths: vec!["Owner.cs".into()],
        basis: "synthetic asserted source mapping".into(),
    });
    let fixture = Fixture::build(
        &value,
        &[row("Owner__Run", 7)],
        Some(
            "<DirectedGraph><Nodes><Node Id=\"0\" Label=\"Root\"/><Node Id=\"1\" Label=\"Owner__Run\"/><Node Id=\"2\" Label=\"Alternative\"/><Node Id=\"3\" Label=\"Target\"/></Nodes><Links><Link Source=\"0\" Target=\"1\" Reason=\"\"/><Link Source=\"1\" Target=\"3\" Reason=\"call\"/><Link Source=\"2\" Target=\"3\" Reason=\"alternative\"/></Links></DirectedGraph>",
        ),
    );
    let mut server = Server::start(&fixture);
    let report = server
        .query(
            &fixture,
            json!({"action":"annotated_why","graph":"scan_index","node_id":"3"}),
        )
        .ok();
    let original = server
        .query(
            &fixture,
            json!({"action":"why","graph":"scan_index","node_id":"3"}),
        )
        .ok();
    assert_eq!(report["schema"], "vitnet.attribution-retention.v1");
    assert_eq!(report["witness"]["paths"], original["paths"]);
    assert_eq!(report["alternative_incoming"]["total_edges"], 2);
    let reasons: BTreeSet<_> = report["alternative_incoming"]["edges"]
        .as_array()
        .unwrap()
        .iter()
        .map(|edge| edge["reason"].as_str().unwrap())
        .collect();
    assert_eq!(reasons, BTreeSet::from(["call", "alternative"]));
    let annotated = &report["annotated_paths"][0];
    assert_eq!(annotated["collapsed_unmapped_nodes"], 2);
    assert_eq!(annotated["anchors"].as_array().unwrap().len(), 1);
    let anchor = &annotated["anchors"][0];
    assert_eq!(anchor["node_id"], "1");
    assert_eq!(anchor["possible_mechanisms"], json!(["module_initializer"]));
    assert_eq!(anchor["total_source_candidates"], 1);
    assert!(
        report["caveats"]
            .as_array()
            .unwrap()
            .iter()
            .any(|caveat| { caveat.as_str().unwrap().contains("sole retainer") })
    );
    server.stop();
}

#[test]
fn symbol_http_pages_full_captured_values_and_reports_absent_capture() {
    let captured = tempfile::tempdir().unwrap();
    let identity = long_text();
    let mut image = common::Image::new();
    image.method(identity.as_bytes(), 11);
    image.method(identity.as_bytes(), 13);
    image.blob(&"not_captured".encode_utf16().collect::<Vec<_>>(), 1);
    let input = captured.path().join("synthetic.mstat");
    fs::write(&input, image.bytes()).unwrap();
    let mut value = evidence();
    value.artifacts.push(Artifact {
        kind: "mstat".into(),
        path: input,
        revision: None,
        blake3: None,
    });
    let mut blob = row("not_captured", 1);
    blob.stream = "Blobs".into();
    let fixture = Fixture::new(&value, &[row(&identity, 24), blob]);
    let mut server = Server::start(&fixture);
    let query = json!({"action":"symbol_value","ordinal":0,"path":[],"start":0});
    let root = server.query(&fixture, query.clone()).ok();
    assert_eq!(root["kind"], "array");
    assert_eq!(root["total"], 1, "identical artifact-local tokens collapse");
    let candidate = server
        .query(
            &fixture,
            json!({"action":"symbol_value","ordinal":0,"path":[0],"start":0}),
        )
        .ok();
    let field = field_path(&candidate, "identity");
    let mut text = query.clone();
    text["path"] = json!([0, field]);
    full_text(&server, &fixture, text, &identity);
    let token = field_path(&candidate, "token");
    let mut token_query = query.clone();
    token_query["path"] = json!([0, token]);
    let token_page = server.query(&fixture, token_query).ok();
    assert_eq!(token_page["kind"], "number");
    assert_eq!(token_page["display"], 0x0a00_0001_u64.to_string());
    let mut alias = query.clone();
    alias["request_id"] = json!("symbol-alias");
    alias["generation"] = json!(fixture.generation);
    assert_eq!(server.post("/api/value", &alias).ok(), root);
    alias["generation"] = json!("stale");
    server
        .post("/api/value", &alias)
        .error(409, "explorer.generation");
    let empty = server
        .query(
            &fixture,
            json!({"action":"symbol_value","ordinal":1,"path":[],"start":0}),
        )
        .ok();
    assert_eq!(empty["total"], 0);
    assert_eq!(empty["entries"], json!([]));
    server.stop();
    let legacy = Fixture::new(&evidence(), &[row("no_sidecar", 1)]);
    let mut server = Server::start(&legacy);
    server
        .query(&legacy, query)
        .error(400, "explorer.symbols.unavailable");
    server.stop();
}

#[test]
fn catalog_counts_and_all_records_pages_reconcile_without_gaps() {
    let fixture = Fixture::rich();
    let mut server = Server::start(&fixture);
    let catalog = server.query(&fixture, json!({"action":"catalog"})).ok();
    assert_eq!(catalog["complete"], true);
    assert!(
        catalog["scope"]
            .as_str()
            .unwrap()
            .contains("discarded producer attributes")
    );
    assert!(
        catalog["comparison_scope"]
            .as_str()
            .unwrap()
            .contains("top-N")
    );
    assert_eq!(catalog["generation"], fixture.generation);
    let descriptors: BTreeMap<_, _> = catalog["datasets"]
        .as_array()
        .unwrap()
        .iter()
        .map(|descriptor| {
            (
                descriptor["name"].as_str().unwrap(),
                descriptor["records"].as_u64().unwrap(),
            )
        })
        .collect();
    for (name, total) in [
        ("groups", descriptors["groups"]),
        ("generic_families", 101),
        ("generators", 101),
        ("provenance", 101),
        ("resources", 201),
        ("package_routes", 201),
        ("packages", 201),
    ] {
        assert_eq!(descriptors[name], total, "{name}");
        let mut after: Option<u64> = None;
        let mut seen = Vec::new();
        let mut scanned = 0_u64;
        for _ in 0..=total / 37 + 1 {
            let page = server
                .query(
                    &fixture,
                    json!({"action":"records","dataset":name,"after":after,"limit":37}),
                )
                .ok();
            assert_eq!(page["generation"], fixture.generation);
            assert_eq!(page["total"], total);
            let ids = ordinals(&page);
            assert!(ids.len() <= 37);
            scanned += page["scanned"].as_u64().unwrap();
            seen.extend(ids);
            if seen.len() as u64 == total {
                assert_eq!(page["next_after"], Value::Null);
                assert_eq!(page["stop_reason"], "complete");
                break;
            }
            assert_eq!(page["stop_reason"], "limit");
            let cursor = page["next_after"].as_str().unwrap().parse::<u64>().unwrap();
            assert_eq!(Some(cursor), seen.last().copied());
            after = Some(cursor);
        }
        assert_eq!(
            seen,
            (0..total).collect::<Vec<_>>(),
            "{name}: stable complete order"
        );
        assert_eq!(scanned, total);
    }
    assert!(descriptors["groups"] >= 101);
    let defaults = server
        .query(&fixture, json!({"action":"records","dataset":"resources"}))
        .ok();
    assert_eq!(ordinals(&defaults), (0..50).collect::<Vec<_>>());
    assert_eq!(defaults["scanned"], 50);
    assert_eq!(defaults["next_after"], "49");
    let maximum = server
        .query(
            &fixture,
            json!({"action":"records","dataset":"resources","limit":100}),
        )
        .ok();
    assert_eq!(ordinals(&maximum), (0..100).collect::<Vec<_>>());
    assert_eq!(maximum["next_after"], "99");
    server.stop();
}

#[test]
fn records_filter_intersections_and_search_past_previews_are_exact() {
    let mut fixture = Fixture::new(&evidence(), &[]);
    let long_key = format!("{}KEY-TAIL", "k".repeat(700));
    fixture.replace_dataset(
        "evidence_header",
        &[
            json!({"name":"alpha","category":"A","bytes":7,"enabled":true,"nullable":null,
            "nested":[{"value":long_text()}], long_key.clone():"needle-in-key"}),
            json!({"name":"alpha-suffix","category":"A","bytes":7,"enabled":false}),
            json!({"name":"beta","category":"B","bytes":8,"enabled":true}),
            json!({"category":"A","bytes":7}),
            json!({"name":"alpha","category":"a","bytes":7,"enabled":true}),
        ],
    );
    let mut server = Server::start(&fixture);
    for (contains, filters, expected) in [
        ("END-OF-COMPLETE-TEXT", json!({}), vec![0]),
        ("KEY-TAIL", json!({}), vec![0]),
        ("needle-in-key", json!({}), vec![0]),
        ("alpha", json!({"category":"A"}), vec![0, 1]),
        (
            "alpha",
            json!({"category":"A","enabled":"true","bytes":"7"}),
            vec![0],
        ),
        ("", json!({"name":"alpha"}), vec![0, 4]),
        ("", json!({"name":"Alpha"}), vec![]),
        ("", json!({"name":"alph"}), vec![]),
        ("", json!({"nullable":"null"}), vec![0]),
        ("beta", json!({"category":"A"}), vec![]),
        ("", json!({"absent":"null"}), vec![]),
        ("", json!({"nested.value":"END-OF-COMPLETE-TEXT"}), vec![]),
        ("end-of-complete-text", json!({}), vec![]),
        ("8", json!({"category":"B"}), vec![2]),
    ] {
        let page = server
            .query(
                &fixture,
                json!({"action":"records","dataset":"evidence_header",
            "contains":contains,"filters":filters}),
            )
            .ok();
        assert_eq!(ordinals(&page), expected, "{contains} + {filters}");
        assert_eq!(
            page["total"], 5,
            "total denotes complete dataset, not matching count"
        );
        assert_eq!(page["scanned"], 5);
        assert_eq!(page["stop_reason"], "complete");
        assert_eq!(page["next_after"], Value::Null);
    }
    let next = server
        .query(
            &fixture,
            json!({"action":"records","dataset":"evidence_header",
        "contains":"alpha","filters":{"category":"A"},"after":"0","limit":1}),
        )
        .ok();
    assert_eq!(ordinals(&next), [1]);
    assert_eq!(next["scanned"], 1);
    assert_eq!(next["next_after"], "1");
    let rest = server
        .query(
            &fixture,
            json!({"action":"records","dataset":"evidence_header",
        "contains":"alpha","filters":{"category":"A"},"after":1,"limit":1}),
        )
        .ok();
    assert_eq!(ordinals(&rest), Vec::<u64>::new());
    assert_eq!(rest["scanned"], 3);
    assert_eq!(rest["next_after"], Value::Null);
    assert_eq!(rest["stop_reason"], "complete");
    server.stop();
}

#[test]
fn empty_singleton_terminal_and_invalid_records_requests_are_explicit() {
    let fixture = Fixture::new(&evidence(), &[]);
    let mut server = Server::start(&fixture);
    let empty = server
        .query(&fixture, json!({"action":"records","dataset":"resources"}))
        .ok();
    assert_eq!(ordinals(&empty), Vec::<u64>::new());
    assert_eq!(empty["total"], 0);
    assert_eq!(empty["scanned"], 0);
    assert_eq!(empty["next_after"], Value::Null);
    assert_eq!(empty["stop_reason"], "complete");
    let one = server
        .query(
            &fixture,
            json!({"action":"records","dataset":"evidence_header","limit":1}),
        )
        .ok();
    assert_eq!(ordinals(&one), [0]);
    assert_eq!(one["entries"][0]["summary"], "synthetic full-data HTTP");
    assert_eq!(one["total"], 1);
    assert_eq!(one["scanned"], 1);
    assert_eq!(one["next_after"], Value::Null);
    assert_eq!(one["stop_reason"], "complete");
    let end = server
        .query(
            &fixture,
            json!({"action":"records","dataset":"evidence_header","after":"0"}),
        )
        .ok();
    assert_eq!(ordinals(&end), Vec::<u64>::new());
    assert_eq!(end["total"], 1);
    assert_eq!(end["scanned"], 0);
    assert_eq!(end["next_after"], Value::Null);
    assert_eq!(end["stop_reason"], "complete");
    for query in [
        json!({"action":"records","dataset":"resources","after":0}),
        json!({"action":"records","dataset":"evidence_header","after":1}),
        json!({"action":"records","dataset":"evidence_header","after":u64::MAX}),
        json!({"action":"record_value","dataset":"evidence_header","ordinal":1}),
    ] {
        server.query(&fixture, query).error(400, "explorer.cursor");
    }
    for name in [
        "",
        "../index",
        "..\\index",
        "resources/../../index",
        "C:\\secret",
        "Resources",
        "snapshot.json",
        "catalog_resources",
        "resources%2f..",
        "not_captured",
    ] {
        for action in ["records", "record_value"] {
            let mut query = json!({"action":action,"dataset":name});
            if action == "record_value" {
                query["ordinal"] = json!(0);
            }
            server.query(&fixture, query).error(400, "explorer.dataset");
        }
    }
    for query in [
        json!({"action":"records","dataset":"evidence_header","limit":0}),
        json!({"action":"records","dataset":"evidence_header","limit":101}),
        json!({"action":"records","dataset":"evidence_header","contains":"x".repeat(1025)}),
        json!({"action":"records","dataset":"evidence_header","filters":{"x":"x".repeat(4097)}}),
        json!({"action":"records","dataset":"evidence_header","filters":{"x".repeat(129):"v"}}),
        json!({"action":"records","dataset":"evidence_header","filters":(0..9).map(|i|(format!("f{i}"),"v")).collect::<BTreeMap<_,_>>()}),
    ] {
        server
            .query(&fixture, query)
            .error(413, "resource.explorer.query");
    }
    let max = server
        .query(
            &fixture,
            json!({"action":"records","dataset":"evidence_header",
        "contains":"x".repeat(1024),"filters":{"x".repeat(128):"x".repeat(4096)},"limit":100}),
        )
        .ok();
    assert_eq!(max["entries"], json!([]));
    assert_eq!(max["scanned"], 1);
    for query in [
        json!({"action":"records","dataset":"evidence_header","after":-1}),
        json!({"action":"records","dataset":"evidence_header","after":"18446744073709551616"}),
        json!({"action":"records","dataset":"evidence_header","after":"1.5"}),
        json!({"action":"records","dataset":"evidence_header","after":true}),
        json!({"action":"records","dataset":"evidence_header","filters":null}),
        json!({"action":"records","dataset":"evidence_header","filters":{"schema":true}}),
        json!({"action":"record_value","dataset":"evidence_header","ordinal":null}),
        json!({"action":"record_value","dataset":"evidence_header","ordinal":0,"path":["label"]}),
    ] {
        server
            .query(&fixture, query)
            .error(400, "explorer.request.json");
    }
    server.stop();
}

#[test]
#[allow(clippy::too_many_lines)] // Preserve traversal, page and invalid-cursor sequences in one fixture.
fn value_pages_reconstruct_nested_lists_keys_utf8_and_exact_primitives() {
    let mut fixture = Fixture::new(&evidence(), &[]);
    let long_key = format!("z{}FULL-KEY-SUFFIX", "é".repeat(2600));
    fixture.replace_dataset(
        "evidence_header",
        &[json!({
            "a_array":(0..121).map(|n| format!("item-{n:03}")).collect::<Vec<_>>(),
            "b_bool":true, "c_empty_array":[], "d_empty_object":{},
            "e_i64":i64::MIN, "f_null":null, "g_u64":u64::MAX,
            "h_string":long_text(), "i_false":false, "j_decimal":1.25,
            "k_nested":[{"child":["first","second"]}],
            "l_object":(0..121).map(|i|(format!("field-{i:03}"),i)).collect::<BTreeMap<_,_>>(),
            long_key.clone():"value at long property name",
        })],
    );
    let mut server = Server::start(&fixture);
    let root = server
        .query(
            &fixture,
            json!({"action":"record_value","dataset":"evidence_header","ordinal":"0"}),
        )
        .ok();
    assert_eq!(root["kind"], "object");
    assert_eq!(root["total"], 13);
    assert_eq!(root["next_start"], Value::Null);
    let fields = root["entries"].as_array().unwrap();
    let expected = [
        "a_array",
        "b_bool",
        "c_empty_array",
        "d_empty_object",
        "e_i64",
        "f_null",
        "g_u64",
        "h_string",
        "i_false",
        "j_decimal",
        "k_nested",
        "l_object",
    ];
    for (index, name) in expected.iter().enumerate() {
        assert_eq!(fields[index]["index"], index);
        assert_eq!(fields[index]["key"], *name);
        assert_eq!(fields[index]["key_truncated"], false);
    }
    assert_eq!(fields[12]["key_truncated"], true);
    assert_eq!(fields[12]["key"].as_str().unwrap().len(), 511);
    assert_eq!(fields[12]["summary"], "value at long property name");
    let items = all_children(
        &server,
        &fixture,
        value_query("evidence_header", 0, &[0], 0),
        121,
        "array",
    );
    assert_eq!(items.first().unwrap()["summary"], "item-000");
    assert_eq!(items[99]["summary"], "item-099");
    assert_eq!(items[100]["summary"], "item-100");
    assert_eq!(items.last().unwrap()["summary"], "item-120");
    assert!(
        items
            .iter()
            .all(|item| item["kind"] == "string" && item["key_truncated"] == false)
    );
    for (index, kind, display) in [
        (1, "boolean", "true"),
        (4, "number", "-9223372036854775808"),
        (5, "null", "null"),
        (6, "number", "18446744073709551615"),
        (8, "boolean", "false"),
        (9, "number", "1.25"),
    ] {
        let page = server
            .query(&fixture, value_query("evidence_header", 0, &[index], 0))
            .ok();
        assert_eq!(page["kind"], kind);
        assert_eq!(page["display"], display);
        assert_eq!(page["next_start"], Value::Null);
        server
            .query(&fixture, value_query("evidence_header", 0, &[index], 1))
            .error(400, "explorer.cursor");
    }
    for (index, kind) in [(2, "array"), (3, "object")] {
        let page = server
            .query(&fixture, value_query("evidence_header", 0, &[index], 0))
            .ok();
        assert_eq!(page["kind"], kind);
        assert_eq!(page["total"], 0);
        assert_eq!(page["entries"], json!([]));
        assert_eq!(page["next_start"], Value::Null);
        server
            .query(&fixture, value_query("evidence_header", 0, &[index], 1))
            .error(400, "explorer.cursor");
    }
    full_text(
        &server,
        &fixture,
        value_query("evidence_header", 0, &[7], 0),
        &long_text(),
    );
    let mut key_query = value_query("evidence_header", 0, &[12], 0);
    key_query["key"] = json!(true);
    full_text(&server, &fixture, key_query, &long_key);
    let object = all_children(
        &server,
        &fixture,
        value_query("evidence_header", 0, &[11], 0),
        121,
        "object",
    );
    assert_eq!(object[0]["key"], "field-000");
    assert_eq!(object[100]["key"], "field-100");
    assert_eq!(object[120]["key"], "field-120");
    assert_eq!(object[120]["summary"], "120");
    full_text(
        &server,
        &fixture,
        value_query("evidence_header", 0, &[10, 0, 0, 1], 0),
        "second",
    );
    let terminal = server
        .query(&fixture, value_query("evidence_header", 0, &[0], 121))
        .ok();
    assert_eq!(terminal["entries"], json!([]));
    assert_eq!(terminal["total"], 121);
    assert_eq!(terminal["next_start"], Value::Null);
    let text_end = server
        .query(
            &fixture,
            value_query("evidence_header", 0, &[7], long_text().len() as u64),
        )
        .ok();
    assert_eq!(text_end["text"], "");
    assert_eq!(text_end["next_start"], Value::Null);
    for query in [
        value_query("evidence_header", 0, &[13], 0),
        value_query("evidence_header", 0, &[0, 121], 0),
        value_query("evidence_header", 0, &[5, 0], 0),
        value_query("evidence_header", 0, &[0], 122),
        value_query("evidence_header", 0, &[7], 1), // inside first 4-byte scalar
        value_query("evidence_header", 0, &[7], long_text().len() as u64 + 1),
        value_query("evidence_header", 0, &[u64::MAX], 0),
        json!({"action":"record_value","dataset":"evidence_header","ordinal":0,"key":true}),
        json!({"action":"record_value","dataset":"evidence_header","ordinal":0,"path":[0,0],"key":true}),
    ] {
        server.query(&fixture, query).error(400, "explorer.cursor");
    }
    server
        .query(&fixture, value_query("evidence_header", 0, &[0; 65], 0))
        .error(413, "resource.explorer.path");
    server.stop();
}

#[test]
fn duplicate_members_and_generator_raw_lists_page_beyond_old_caps() {
    let fixture = Fixture::rich();
    let mut server = Server::start(&fixture);
    let duplicate = server
        .query(&fixture, value_query("duplicate_assets", 0, &[], 0))
        .ok();
    let instances = field_path(&duplicate, "instances");
    let members = all_children(
        &server,
        &fixture,
        value_query("duplicate_assets", 0, &[instances], 0),
        201,
        "array",
    );
    assert_eq!(members.len(), 201);
    let mut resource_names = BTreeSet::new();
    for (ordinal, expected_name) in [
        (0, "resource-000"),
        (19, "resource-038"),
        (20, "resource-040"),
        (100, "resource-200"),
        (200, "resource-199"),
    ] {
        let member = server
            .query(
                &fixture,
                value_query("duplicate_assets", 0, &[instances, ordinal], 0),
            )
            .ok();
        let name = field_path(&member, "name");
        let page = server
            .query(
                &fixture,
                value_query("duplicate_assets", 0, &[instances, ordinal, name], 0),
            )
            .ok();
        resource_names.insert(page["text"].as_str().unwrap().to_string());
        assert_eq!(page["text"], expected_name);
        assert_eq!(page["next_start"], Value::Null);
    }
    assert_eq!(
        resource_names.len(),
        5,
        "separate members remain separately addressable"
    );
    let generator = server
        .query(&fixture, value_query("generators", 100, &[], 0))
        .ok();
    let raw = field_path(&generator, "evidence");
    let descriptor = server
        .query(&fixture, value_query("generators", 100, &[raw], 0))
        .ok();
    let files = field_path(&descriptor, "generated_files");
    let inputs = field_path(&descriptor, "input_symbols");
    let files = all_children(
        &server,
        &fixture,
        value_query("generators", 100, &[raw, files], 0),
        61,
        "array",
    );
    assert_eq!(
        files[60]["summary"],
        fixture
            .root
            .path()
            .join("generated-060.cs")
            .to_str()
            .unwrap()
    );
    let inputs = all_children(
        &server,
        &fixture,
        value_query("generators", 100, &[raw, inputs], 0),
        121,
        "array",
    );
    assert_eq!(inputs[100]["summary"], "input-100");
    assert_eq!(inputs[120]["summary"], "input-120");
    server.stop();
}

#[test]
#[allow(clippy::too_many_lines)] // Identity and source facets prove one complete located contributor.
fn contributor_identity_and_source_values_are_complete() {
    let identity = format!("Owner__{}", long_text());
    let mut value = evidence();
    for id in 0..61 {
        let mut attributes: Vec<_> = (0..45)
            .map(|n| format!("source-{id:03}-attribute-{n:03}"))
            .collect();
        attributes[44] = long_text();
        value.sources.push(Source {
            assembly: "App".into(),
            type_name: "Owner".into(),
            member: Some("Run".into()),
            path: format!("missing-source-{id:03}.cs").into(),
            line: 3,
            end_line: 9,
            kind: long_text(),
            attributes,
            generated_by: Some("synthetic-generator".into()),
            ..Source::default()
        });
    }
    value.mappings.push(Mapping {
        stream: "Methods".into(),
        identity: identity.clone(),
        assembly: "App".into(),
        source_paths: value
            .sources
            .iter()
            .map(|source| source.path.clone())
            .collect(),
        basis: long_text(),
    });
    let mut rows: Vec<_> = (0..100)
        .map(|id| row(&format!("Other__{id:03}"), 100))
        .collect();
    rows.push(row(&identity, 9_007_199_254_740_993));
    rows.push(row("Unmapped__Last", 0));
    let fixture = Fixture::new(&value, &rows);
    let mut server = Server::start(&fixture);
    let root = server
        .query(&fixture, json!({"action":"identity_value","ordinal":"100"}))
        .ok();
    assert_eq!(root["kind"], "object");
    let identity_field = field_path(&root, "identity");
    full_text(
        &server,
        &fixture,
        json!({"action":"identity_value","ordinal":100,"path":[identity_field]}),
        &identity,
    );
    let bytes_field = field_path(&root, "bytes");
    let exact = server
        .query(
            &fixture,
            json!({"action":"identity_value","ordinal":100,"path":[bytes_field]}),
        )
        .ok();
    assert_eq!(exact["display"], "9007199254740993");
    assert_eq!(exact["kind"], "number");
    let found = server.query(&fixture,json!({"action":"records","dataset":"identities","contains":"END-OF-COMPLETE-TEXT","filters":{"stream":"Methods","owner":"Owner"}})).ok();
    assert_eq!(ordinals(&found), [100]);
    assert_eq!(found["entries"][0]["bytes"], 9_007_199_254_740_993_u64);
    assert_eq!(found["total"], 102);
    assert_eq!(found["scanned"], 102);
    assert_eq!(found["entries"][0]["summary"].as_str().unwrap().len(), 511);
    for filters in [
        json!({"stream":"Types"}),
        json!({"owner":"Other"}),
        json!({"assembly":"_unmapped"}),
    ] {
        let rejected = server
            .query(
                &fixture,
                json!({"action":"records","dataset":"identities",
            "contains":"END-OF-COMPLETE-TEXT","filters":filters}),
            )
            .ok();
        assert_eq!(rejected["entries"], json!([]));
        assert_eq!(rejected["next_after"], Value::Null);
        assert_eq!(rejected["stop_reason"], "complete");
    }
    let assembled = server
        .query(
            &fixture,
            json!({"action":"records","dataset":"identities",
        "contains":"END-OF-COMPLETE-TEXT","filters":{"assembly":"App"}}),
        )
        .ok();
    assert_eq!(ordinals(&assembled), [100]);
    let located = server
        .query(&fixture, json!({"action":"source_value","ordinal":"100"}))
        .ok();
    let sources = field_path(&located, "sources");
    let basis = field_path(&located, "basis");
    full_text(
        &server,
        &fixture,
        json!({"action":"source_value","ordinal":100,"path":[basis]}),
        &long_text(),
    );
    let all = all_children(
        &server,
        &fixture,
        json!({"action":"source_value","ordinal":100,"path":[sources]}),
        61,
        "array",
    );
    assert_eq!(all[60]["kind"], "object");
    let last = server
        .query(
            &fixture,
            json!({"action":"source_value","ordinal":100,"path":[sources,60]}),
        )
        .ok();
    let path = field_path(&last, "path");
    full_text(
        &server,
        &fixture,
        json!({"action":"source_value","ordinal":100,"path":[sources,60,path]}),
        fixture
            .root
            .path()
            .join("missing-source-060.cs")
            .to_str()
            .unwrap(),
    );
    for (field, expected) in [("line", "3"), ("end_line", "9")] {
        let field = field_path(&last, field);
        let page = server
            .query(
                &fixture,
                json!({"action":"source_value","ordinal":100,"path":[sources,60,field]}),
            )
            .ok();
        assert_eq!(page["display"], expected);
        assert_eq!(page["next_start"], Value::Null);
    }
    let attributes = field_path(&last, "attributes");
    let all = all_children(
        &server,
        &fixture,
        json!({"action":"source_value","ordinal":100,"path":[sources,60,attributes]}),
        45,
        "array",
    );
    assert_eq!(all[40]["summary"], "source-060-attribute-040");
    full_text(
        &server,
        &fixture,
        json!({"action":"source_value","ordinal":100,"path":[sources,60,attributes,44]}),
        &long_text(),
    );
    let kind = field_path(&last, "kind");
    full_text(
        &server,
        &fixture,
        json!({"action":"source_value","ordinal":100,"path":[sources,60,kind]}),
        &long_text(),
    );
    let missing = server
        .query(&fixture, json!({"action":"source_value","ordinal":101}))
        .ok();
    let status = field_path(&missing, "status");
    full_text(
        &server,
        &fixture,
        json!({"action":"source_value","ordinal":101,"path":[status]}),
        "unmapped",
    );
    let none = field_path(&missing, "sources");
    let empty = server
        .query(
            &fixture,
            json!({"action":"source_value","ordinal":101,"path":[none]}),
        )
        .ok();
    assert_eq!(empty["entries"], json!([]));
    assert_eq!(empty["total"], 0);
    assert_eq!(empty["next_start"], Value::Null);
    for action in ["identity_value", "source_value"] {
        server
            .query(&fixture, json!({"action":action,"ordinal":102}))
            .error(400, "explorer.row");
        server
            .query(
                &fixture,
                json!({"action":action,"ordinal":100,"path":[u64::MAX]}),
            )
            .error(400, "explorer.cursor");
    }
    server.stop();
    assert!(
        fixture.root.path().exists(),
        "fixture is retained through owned shutdown"
    );
}

fn guarded_actions() -> Vec<Value> {
    vec![
        json!({"action":"catalog"}),
        json!({"action":"records","dataset":"evidence_header"}),
        json!({"action":"record_value","dataset":"evidence_header","ordinal":0}),
        json!({"action":"identity_value","ordinal":0}),
        json!({"action":"source_value","ordinal":0}),
        json!({"action":"incoming_edge_value","graph":"scan_index","node_id":"0","ordinal":0}),
    ]
}

#[test]
#[allow(clippy::too_many_lines)] // Every new action independently exercises the transport guards.
fn new_actions_enforce_capability_host_origin_generation_and_framing() {
    let fixture = Fixture::new(&evidence(), &[row("Owner__Run", 7)]);
    let mut server = Server::start(&fixture);
    for mut query in guarded_actions() {
        query["request_id"] = json!("guarded");
        query["generation"] = json!(fixture.generation);
        let body = serde_json::to_vec(&query).unwrap();
        server
            .request(&body, "Content-Type: application/json\r\n")
            .error(403, "explorer.authorization");
        server
            .request(
                &body,
                "Authorization: Bearer wrong\r\nContent-Type: application/json\r\n",
            )
            .error(403, "explorer.authorization");
        server
            .request(
                &body,
                &format!(
                    "{}Authorization: Bearer {}\r\n",
                    server.auth(),
                    server.token
                ),
            )
            .error(403, "explorer.authorization");
        let mut request = format!(
            "POST /api/query HTTP/1.1\r\nHost: localhost:{}\r\n{}Content-Length: {}\r\n\r\n",
            server.address.port(),
            server.auth(),
            body.len()
        )
        .into_bytes();
        request.extend(&body);
        server.raw(&request).error(403, "explorer.host");
        server
            .request(
                &body,
                &format!(
                    "{}Origin: http://localhost:{}\r\n",
                    server.auth(),
                    server.address.port()
                ),
            )
            .error(403, "explorer.origin");
        server
            .request(&body, &format!("{}Origin: null\r\n", server.auth()))
            .error(403, "explorer.origin");
        let mut duplicate_host = format!(
            "POST /api/query HTTP/1.1\r\nHost: {0}\r\nHost: {0}\r\n{1}Content-Length: {2}\r\n\r\n",
            server.address,
            server.auth(),
            body.len()
        )
        .into_bytes();
        duplicate_host.extend(&body);
        server.raw(&duplicate_host).error(403, "explorer.host");
        server
            .request(
                &body,
                &format!(
                    "{}Origin: http://{}\r\nOrigin: null\r\n",
                    server.auth(),
                    server.address
                ),
            )
            .error(403, "explorer.origin");
        server
            .request(
                &body,
                &format!(
                    "Authorization: Bearer {}\r\nContent-Type: text/plain\r\n",
                    server.token
                ),
            )
            .error(400, "explorer.content_type");
        query["generation"] = json!("wrong-generation");
        server
            .post("/api/query", &query)
            .error(409, "explorer.generation");
        query["generation"] = json!(fixture.generation);
        for id in ["", "with space", "bad/slash", &"x".repeat(65)] {
            query["request_id"] = json!(id);
            server
                .post("/api/query", &query)
                .error(409, "explorer.request_id");
        }
        query["request_id"] = json!("guarded");
        let body = serde_json::to_vec(&query).unwrap();
        for extra in ["Content-Length: 0\r\n", "Transfer-Encoding: chunked\r\n"] {
            let mut raw = format!(
                "POST /api/query HTTP/1.1\r\nHost: {}\r\n{}{extra}Content-Length: {}\r\n\r\n",
                server.address,
                server.auth(),
                body.len()
            )
            .into_bytes();
            raw.extend(&body);
            server.raw(&raw).error(400, "explorer.http");
        }
        let mut raw = format!(
            "POST /api/query HTTP/1.1\r\nHost: {}\r\n{}Content-Length: {}\r\n\r\n",
            server.address,
            server.auth(),
            body.len()
        )
        .into_bytes();
        raw.extend(&body);
        raw.extend(b"GET / HTTP/1.1\r\nHost: ignored\r\n\r\n");
        server.raw(&raw).error(400, "explorer.http");
        query["unexpected"] = json!(true);
        let rejected = server.post("/api/query", &query);
        assert_eq!(
            rejected.status, 400,
            "unknown-field rejection for action {}",
            query["action"]
        );
        rejected.error(400, "explorer.request.json");
    }
    let mut accepted =
        json!({"action":"catalog","request_id":"valid","generation":fixture.generation});
    let body = serde_json::to_vec(&accepted).unwrap();
    let good = server
        .request(
            &body,
            &format!("{}Origin: http://{}\r\n", server.auth(), server.address),
        )
        .ok();
    assert_eq!(good["complete"], true);
    accepted["action"] = json!("records");
    accepted["dataset"] = json!("evidence_header");
    let mut boundary = serde_json::to_vec(&accepted).unwrap();
    boundary.resize(16 * 1024, b' ');
    assert_eq!(
        server.request(&boundary, &server.auth()).ok()["entries"][0]["ordinal"],
        "0"
    );
    let overflow = format!(
        "POST /api/query HTTP/1.1\r\nHost: {}\r\n{}Content-Length: 16385\r\n\r\n",
        server.address,
        server.auth()
    );
    server
        .raw(overflow.as_bytes())
        .error(413, "resource.explorer.request");
    server.stop();
}

#[test]
fn cancellation_scope_and_completed_request_ids_do_not_poison_new_actions() {
    let fixture = Fixture::new(&evidence(), &[row("Owner__Run", 7)]);
    let mut server = Server::start(&fixture);
    for query in guarded_actions().into_iter().take(5) {
        server
            .request(
                br#"{"request_id":"catalog-contract"}"#,
                "Content-Type: application/json\r\n",
            )
            .error(403, "explorer.authorization");
        assert_eq!(
            server
                .post("/api/cancel", &json!({"request_id":"catalog-contract"}))
                .ok(),
            json!({"cancelled":false})
        );
        let first = server.query(&fixture, query.clone()).ok();
        assert_eq!(first["generation"], fixture.generation);
        assert_eq!(
            server
                .post("/api/cancel", &json!({"request_id":"catalog-contract"}))
                .ok(),
            json!({"cancelled":false})
        );
        let repeated = server.query(&fixture, query).ok();
        assert_eq!(
            first, repeated,
            "completed controls and request IDs are removed"
        );
    }
    server
        .post("/api/cancel", &json!({"request_id":"bad id"}))
        .error(409, "explorer.request_id");
    server
        .post(
            "/api/cancel",
            &json!({"request_id":"catalog-contract","extra":1}),
        )
        .error(400, "explorer.request.json");
    server.stop();
}

#[test]
fn legacy_catalog_does_not_claim_completeness_or_silently_return_missing_inventory() {
    let mut fixture = Fixture::new(&evidence(), &[row("Owner__Run", 7)]);
    fixture.legacy();
    let mut server = Server::start(&fixture);
    let catalog = server.query(&fixture, json!({"action":"catalog"})).ok();
    assert_eq!(catalog["complete"], false);
    assert_eq!(catalog["generation"], fixture.generation);
    assert_eq!(
        catalog["datasets"],
        json!([{"name":"identities","records":1,"storage":"original_index"}])
    );
    let identities = server
        .query(&fixture, json!({"action":"records","dataset":"identities"}))
        .ok();
    assert_eq!(ordinals(&identities), [0]);
    assert_eq!(identities["entries"][0]["summary"], "Owner__Run");
    server
        .query(&fixture, json!({"action":"records","dataset":"resources"}))
        .error(400, "explorer.dataset");
    server
        .query(&fixture, value_query("evidence_header", 0, &[], 0))
        .error(400, "explorer.dataset");
    server.stop();
}

#[test]
fn changed_live_catalog_or_original_identity_files_fail_without_data() {
    for target in ["catalog", "offsets", "identity"] {
        let fixture = Fixture::new(&evidence(), &[row("Owner__Run", 7)]);
        let mut server = Server::start(&fixture);
        // Open the reader before mutating our synthetic copy, pinning stale
        // detection separately from startup hash validation.
        server
            .query(&fixture, value_query("evidence_header", 0, &[], 0))
            .ok();
        let path = match target {
            "catalog" => fixture.bundle.join("catalog_evidence_header.ndjson"),
            "offsets" => fixture.bundle.join("catalog_evidence_header.offsets"),
            _ => fixture.index.join("identities.ndjson"),
        };
        let mut bytes = fs::read(&path).unwrap();
        let size = bytes.len();
        bytes[0] ^= 1;
        fs::write(&path, &bytes).unwrap();
        assert_eq!(
            fs::metadata(&path).unwrap().len(),
            size as u64,
            "same-length drift"
        );
        let expected = if target == "identity" {
            "explorer.source.stale"
        } else {
            "explorer.dataset.stale"
        };
        server
            .query(&fixture, value_query("evidence_header", 0, &[], 0))
            .error(409, expected);
        if target == "identity" {
            for query in guarded_actions().into_iter().take(5) {
                server.query(&fixture, query).error(409, expected);
            }
        } else {
            server
                .query(
                    &fixture,
                    json!({"action":"records","dataset":"evidence_header"}),
                )
                .error(409, expected);
        }
        server.stop();
    }
}

fn complete_graph_xml() -> String {
    let mut xml = String::from("<DirectedGraph><Nodes>");
    for index in 0..205 {
        let id = index * 2;
        let label = if index == 0 {
            String::new()
        } else if id == 100 {
            long_text()
        } else {
            format!("node-{id:03}")
        };
        write!(
            xml,
            "<Node Id=\"{id}\" Label=\"{label}\" DroppedUpstream=\"not captured\"/>"
        )
        .unwrap();
    }
    xml.push_str("</Nodes><Links>");
    for index in 0..205 {
        let id = index * 2;
        for parallel in 0..3 {
            let reason = if index == 0 && parallel == 0 {
                String::new()
            } else if id == 100 && parallel == 0 {
                long_text()
            } else {
                format!("reason-{id:03}-{parallel}")
            };
            write!(
                xml,
                "<Link Source=\"{id}\" Target=\"400\" Reason=\"{reason}\"/>"
            )
            .unwrap();
        }
    }
    xml.push_str("<Link Source=\"0\" Target=\"408\" Reason=\"last-0\"/><Link Source=\"2\" Target=\"408\" Reason=\"last-2\"/></Links></DirectedGraph>");
    xml
}

#[test]
fn graph_catalog_lists_every_sparse_node_empty_label_and_parallel_global_edge() {
    let fixture = Fixture::build(&evidence(), &[], Some(&complete_graph_xml()));
    let mut server = Server::start(&fixture);
    let catalog = server.query(&fixture, json!({"action":"catalog"})).ok();
    for (name, total) in [
        ("graph_scan_index_nodes", 205),
        ("graph_scan_index_edges", 617),
    ] {
        let descriptor = catalog["datasets"]
            .as_array()
            .unwrap()
            .iter()
            .find(|entry| entry["name"] == name)
            .unwrap();
        assert_eq!(descriptor["records"], total);
        assert_eq!(descriptor["storage"], "immutable_graph");
        let expected: Vec<_> = if name.ends_with("nodes") {
            (0..205).map(|i| i * 2).collect()
        } else {
            (0..617).collect()
        };
        let mut after: Option<u64> = None;
        let mut seen = Vec::new();
        let mut scanned = 0_u64;
        for _ in 0..=total / 47 + 1 {
            let page = server
                .query(
                    &fixture,
                    json!({"action":"records","dataset":name,"after":after,"limit":47}),
                )
                .ok();
            assert_eq!(
                page["total"], total,
                "records total reconciles graph catalog"
            );
            assert_eq!(page["generation"], fixture.generation);
            let ids = ordinals(&page);
            if seen.is_empty() && name.ends_with("nodes") {
                assert_eq!(ids[0], 0);
                assert_eq!(
                    page["entries"][0]["summary"], "",
                    "empty label is a real captured node"
                );
            }
            seen.extend(ids);
            scanned += page["scanned"].as_u64().unwrap();
            if page["next_after"].is_null() {
                assert_eq!(page["stop_reason"], "complete");
                break;
            }
            assert_eq!(page["stop_reason"], "limit");
            let cursor = page["next_after"].as_str().unwrap().parse().unwrap();
            assert_eq!(Some(cursor), seen.last().copied());
            after = Some(cursor);
        }
        assert_eq!(seen, expected);
        assert_eq!(scanned, if name.ends_with("nodes") { 409 } else { 617 });
    }
    let tail = server.query(&fixture,json!({"action":"records","dataset":"graph_scan_index_nodes","contains":"END-OF-COMPLETE-TEXT"})).ok();
    assert_eq!(
        ordinals(&tail),
        [100],
        "node search uses complete labels, not summaries"
    );
    let tail = server.query(&fixture,json!({"action":"records","dataset":"graph_scan_index_edges","contains":"END-OF-COMPLETE-TEXT"})).ok();
    assert_eq!(ordinals(&tail), [150], "edge search uses complete reasons");
    assert_eq!(tail["total"], 617);
    let terminal = server
        .query(
            &fixture,
            json!({"action":"records","dataset":"graph_scan_index_edges","after":"616"}),
        )
        .ok();
    assert_eq!(terminal["entries"], json!([]));
    assert_eq!(terminal["total"], 617);
    assert_eq!(terminal["scanned"], 0);
    assert_eq!(terminal["next_after"], Value::Null);
    server.stop();
}

#[test]
#[allow(clippy::too_many_lines)] // Global and target-local details plus guard partitions share one graph.
fn graph_node_global_edge_and_target_local_values_expose_full_utf8_details() {
    let fixture = Fixture::build(&evidence(), &[], Some(&complete_graph_xml()));
    let mut server = Server::start(&fixture);
    let node = server
        .query(&fixture, value_query("graph_scan_index_nodes", 100, &[], 0))
        .ok();
    let label = field_path(&node, "label");
    full_text(
        &server,
        &fixture,
        value_query("graph_scan_index_nodes", 100, &[label], 0),
        &long_text(),
    );
    let bytes = field_path(&node, "label_bytes");
    let bytes = server
        .query(
            &fixture,
            value_query("graph_scan_index_nodes", 100, &[bytes], 0),
        )
        .ok();
    assert_eq!(bytes["display"], long_text().len().to_string());
    let edge = server
        .query(&fixture, value_query("graph_scan_index_edges", 150, &[], 0))
        .ok();
    let reason = field_path(&edge, "reason");
    full_text(
        &server,
        &fixture,
        value_query("graph_scan_index_edges", 150, &[reason], 0),
        &long_text(),
    );
    for (key, expected) in [
        ("ordinal", "150"),
        ("source_id", "100"),
        ("target_id", "400"),
    ] {
        let field = field_path(&edge, key);
        let page = server
            .query(
                &fixture,
                value_query("graph_scan_index_edges", 150, &[field], 0),
            )
            .ok();
        assert_eq!(page["display"], expected);
        assert_eq!(page["kind"], "number");
    }
    let incoming = server.query(&fixture,json!({"action":"incoming_edge_value","graph":"scan_index","node_id":"400","ordinal":"150"})).ok();
    let incoming_reason = field_path(&incoming, "reason");
    full_text(
        &server,
        &fixture,
        json!({"action":"incoming_edge_value","graph":"scan_index","node_id":"400","ordinal":150,"path":[incoming_reason]}),
        &long_text(),
    );
    let last = server.query(&fixture,json!({"action":"incoming_edge_value","graph":"scan_index","node_id":"408","ordinal":1})).ok();
    let ordinal = field_path(&last, "ordinal");
    let global = server.query(&fixture,json!({"action":"incoming_edge_value","graph":"scan_index","node_id":"408","ordinal":1,"path":[ordinal]})).ok();
    assert_eq!(
        global["display"], "616",
        "target-local ordinal is not global ordinal"
    );
    let reason = field_path(&last, "reason");
    full_text(
        &server,
        &fixture,
        json!({"action":"incoming_edge_value","graph":"scan_index","node_id":"408","ordinal":1,"path":[reason]}),
        "last-2",
    );
    for (query, code) in [
        (
            value_query("graph_scan_index_nodes", 1, &[], 0),
            "dgml.query.node",
        ),
        (
            value_query("graph_scan_index_nodes", 409, &[], 0),
            "dgml.query.node",
        ),
        (
            value_query("graph_scan_index_edges", 617, &[], 0),
            "dgml.query.cursor",
        ),
        (
            json!({"action":"records","dataset":"graph_scan_index_nodes","after":409}),
            "dgml.query.cursor",
        ),
        (
            json!({"action":"records","dataset":"graph_scan_index_edges","after":617}),
            "dgml.query.cursor",
        ),
        (
            json!({"action":"records","dataset":"graph_scan_index_nodes","filters":{"label":"node-002"}}),
            "explorer.query",
        ),
        (
            json!({"action":"incoming_edge_value","graph":"scan_index","node_id":"408","ordinal":2}),
            "dgml.query.cursor",
        ),
        (
            json!({"action":"incoming_edge_value","graph":"scan_index","node_id":"1","ordinal":0}),
            "dgml.query.node",
        ),
        (
            json!({"action":"incoming_edge_value","graph":"scan_index","node_id":"not-an-id","ordinal":0}),
            "explorer.cursor",
        ),
        (
            json!({"action":"incoming_edge_value","graph":"unknown","node_id":"400","ordinal":0}),
            "explorer.graph.kind",
        ),
        (
            json!({"action":"incoming_edge_value","graph":"codegen_index","node_id":"400","ordinal":0}),
            "explorer.graph.missing",
        ),
    ] {
        server.query(&fixture, query).error(400, code);
    }
    assert_eq!(
        server
            .post("/api/cancel", &json!({"request_id":"catalog-contract"}))
            .ok(),
        json!({"cancelled":false})
    );
    let repeated = server
        .query(&fixture, value_query("graph_scan_index_edges", 150, &[], 0))
        .ok();
    assert_eq!(
        edge, repeated,
        "cancel-after-completion cannot poison new graph values"
    );
    server.stop();
}

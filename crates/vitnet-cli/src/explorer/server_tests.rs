//! Private handler contracts with deterministic registry/lock state, no daemon.
use super::*;
use std::net::Shutdown;
use vitnet_attribution::model::{Artifact, EVIDENCE_SCHEMA, Evidence};

#[path = "../../../vitnet-attribution/tests/common/mod.rs"]
#[allow(dead_code)] // Shared fixture also exposes blob construction for other suites.
mod common;

const MEMORY: u64 = 128 << 20;
const TOKEN: &str = "synthetic-capability-not-a-real-session";
const NONCE: &str = "independent-synthetic-csp-nonce";

struct Fixture {
    _directory: tempfile::TempDir,
    bundle: data::Bundle,
    index: AttributionIndex,
}

impl Fixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path();
        let mut image = common::Image::new();
        image.method(b"Owner__Alpha", 11);
        image.method(b"Owner__Beta", 22);
        image.method(b"Owner__Gamma", 33);
        let mstat = root.join("synthetic.mstat");
        fs::write(&mstat, image.bytes()).unwrap();
        let graph_input = root.join("synthetic.dgml");
        fs::write(
            &graph_input,
            r#"<DirectedGraph><Nodes><Node Id="0" Label="root"/><Node Id="1" Label="child"/></Nodes><Links><Link Source="0" Target="1" Reason=""/></Links></DirectedGraph>"#,
        )
        .unwrap();
        let graph = vitnet_dgml::build_index(
            &graph_input,
            &vitnet_dgml::IndexOptions {
                cache_root: root.join("graph-cache"),
                memory_limit: MEMORY,
                selected_entry: None,
                strict_hash: false,
                control: IndexControl::default(),
            },
        )
        .unwrap();
        let evidence = Evidence {
            schema: EVIDENCE_SCHEMA.into(),
            label: "Private deterministic handler fixture".into(),
            artifacts: vec![
                Artifact {
                    kind: "mstat".into(),
                    path: mstat,
                    revision: None,
                    blake3: None,
                },
                Artifact {
                    kind: "scan_index".into(),
                    path: graph.index_directory,
                    revision: None,
                    blake3: None,
                },
            ],
            ..Evidence::default()
        };
        let manifest = root.join("evidence.json");
        fs::write(&manifest, serde_json::to_vec(&evidence).unwrap()).unwrap();
        let index_path = root.join("index");
        let mut index = vitnet_attribution::import(&manifest, &index_path, MEMORY, false).unwrap();
        // Import coalesces in its own key order. Give this handler fixture explicit
        // ordinal order, retaining the same verified accounting totals and hashes.
        let mut identities = Vec::new();
        for (identity, bytes) in [
            ("Owner__Alpha", 11),
            ("Owner__Beta", 22),
            ("Owner__Gamma", 33),
        ] {
            let row = vitnet_mstat::CoalescedIdentity {
                stream: "Methods".into(),
                identity: identity.into(),
                bytes,
                records: 1,
                accounted: true,
                identity_lossy: false,
                raw_identity_blake3: blake3::hash(identity.as_bytes()).to_hex().to_string(),
            };
            identities.extend(serde_json::to_vec(&row).unwrap());
            identities.push(b'\n');
        }
        index.identities_blake3 = blake3::hash(&identities).to_hex().to_string();
        fs::write(index_path.join("identities.ndjson"), identities).unwrap();
        fs::write(
            index_path.join("index.json"),
            serde_json::to_vec(&index).unwrap(),
        )
        .unwrap();
        let bundle_path = root.join("bundle");
        data::prepare(
            &index_path,
            &bundle_path,
            &[],
            None,
            &[],
            "scan_index",
            MEMORY,
            &IndexControl::default(),
        )
        .unwrap();
        let bundle = data::Bundle::open(&bundle_path, MEMORY).unwrap();
        assert_eq!(bundle.manifest.identities, 3);
        Self {
            _directory: directory,
            bundle,
            index,
        }
    }

    fn rows(&self, id: &str, after: Option<u64>) -> Value {
        json!({
            "request_id":id, "generation":self.bundle.manifest.generation,
            "action":"rows", "contains":"", "stream":null,
            "assembly":null, "owner":null, "after":after, "limit":50
        })
    }
}

struct Reply {
    status: u16,
    body: Value,
}

/// Exercise the real parser, handler and error mapping through owned local sockets.
fn exchange(
    backend: &Mutex<Backend<'_>>,
    active: &Active,
    shutdown: &IndexControl,
    path: &str,
    body: &Value,
    token: &str,
) -> Reply {
    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let address = listener.local_addr().unwrap();
    let mut client = TcpStream::connect(address).unwrap();
    let (mut server, _) = listener.accept().unwrap();
    for stream in [&client, &server] {
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(5)))
            .unwrap();
    }
    let bytes = serde_json::to_vec(body).unwrap();
    let headers = format!(
        "POST {path} HTTP/1.1\r\nHost: {address}\r\nOrigin: http://{address}\r\nAuthorization: Bearer {token}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
        bytes.len()
    );
    client.write_all(headers.as_bytes()).unwrap();
    client.write_all(&bytes).unwrap();
    client.shutdown(Shutdown::Write).unwrap();
    if let Err(error) = handle(
        &mut server,
        address,
        TOKEN,
        NONCE,
        "<!doctype html><title>Public test shell</title>",
        b"{}",
        backend,
        active,
        shutdown,
    ) {
        error_response(&mut server, &error, NONCE).unwrap();
    }
    drop(server); // Production closes the connection after exactly one response.
    let mut response = Vec::new();
    client.read_to_end(&mut response).unwrap();
    let split = response
        .windows(4)
        .position(|bytes| bytes == b"\r\n\r\n")
        .unwrap();
    let headers = std::str::from_utf8(&response[..split]).unwrap();
    assert!(headers.contains("\r\nConnection: close"));
    assert!(headers.contains("\r\nContent-Type: application/json"));
    let status = headers.split_whitespace().nth(1).unwrap().parse().unwrap();
    let body = serde_json::from_slice(&response[split + 4..]).unwrap();
    Reply { status, body }
}

fn rejection(reply: &Reply, status: u16, code: &str) {
    assert_eq!(reply.status, status);
    assert_eq!(reply.body["error"]["code"], code);
    let body = reply.body.as_object().unwrap();
    assert_eq!(body.len(), 1, "rejections must not leak query evidence");
    assert!(
        reply.body["error"]["message"]
            .as_str()
            .is_some_and(|text| !text.is_empty())
    );
}

#[test]
fn authenticated_cancel_reaches_the_registered_control_and_rows_preserve_progress() {
    let fixture = Fixture::new();
    let backend = Mutex::new(Backend::new(&fixture.bundle, &fixture.index, MEMORY).unwrap());
    let control = IndexControl::default();
    let decoy = IndexControl::default();
    let active = Active::new(BTreeMap::from([
        ("aaa".into(), decoy.clone()),
        ("running".into(), control.clone()),
    ]));
    let shutdown = IndexControl::default();
    let absent = exchange(
        &backend,
        &active,
        &shutdown,
        "/api/cancel",
        &json!({"request_id":"absent"}),
        TOKEN,
    );
    assert_eq!(absent.status, 200);
    assert_eq!(absent.body, json!({"cancelled":false}));
    assert!(!control.is_cancelled());
    assert!(!decoy.is_cancelled());
    let cancel = json!({"request_id":"running"});
    let denied = exchange(
        &backend,
        &active,
        &shutdown,
        "/api/cancel",
        &cancel,
        "wrong",
    );
    rejection(&denied, 403, "explorer.authorization");
    assert!(
        !control.is_cancelled(),
        "unauthorized cancellation must be inert"
    );
    assert!(!decoy.is_cancelled());
    let reply = exchange(&backend, &active, &shutdown, "/api/cancel", &cancel, TOKEN);
    assert_eq!(reply.status, 200);
    assert_eq!(reply.body, json!({"cancelled":true}));
    assert!(control.is_cancelled());
    assert!(
        active
            .lock()
            .unwrap()
            .get("running")
            .unwrap()
            .is_cancelled()
    );
    assert!(
        !decoy.is_cancelled(),
        "cancellation must target the requested ID only"
    );
    assert_eq!(active.lock().unwrap().len(), 2);
    assert!(!shutdown.is_cancelled());

    // Pass the SAME shared signal, not an independently pre-cancelled substitute.
    let request: QueryRequest = serde_json::from_value(fixture.rows("running", Some(0))).unwrap();
    let stopped = backend.lock().unwrap().query(&request, &control).unwrap();
    assert_eq!(stopped["generation"], fixture.bundle.manifest.generation);
    assert_eq!(stopped["stop_reason"], "cancelled");
    assert_eq!(stopped["next_after"], 0);
    assert_eq!(stopped["scanned"], 0);
    assert_eq!(stopped["entries"], json!([]));
    assert_eq!(stopped["order"], "cache_ordinal");
    let resumed = backend
        .lock()
        .unwrap()
        .query(&request, &IndexControl::default())
        .unwrap();
    assert_eq!(resumed["stop_reason"], "complete");
    assert_eq!(resumed["next_after"], Value::Null);
    assert_eq!(resumed["scanned"], 2);
    assert_eq!(resumed["entries"][0]["ordinal"], 1);
    assert_eq!(resumed["entries"][0]["identity"], "Owner__Beta");
    assert_eq!(resumed["entries"][0]["bytes"], 22);
    assert_eq!(resumed["entries"][1]["ordinal"], 2);
    assert_eq!(resumed["entries"][1]["identity"], "Owner__Gamma");
    assert_eq!(resumed["entries"][1]["bytes"], 33);
    assert_eq!(resumed["entries"].as_array().unwrap().len(), 2);
}

#[test]
fn duplicate_active_id_rejects_without_replacing_or_cancelling_the_original_control() {
    let fixture = Fixture::new();
    let backend = Mutex::new(Backend::new(&fixture.bundle, &fixture.index, MEMORY).unwrap());
    let original = IndexControl::default();
    let active = Active::new(BTreeMap::from([("duplicate".into(), original.clone())]));
    let shutdown = IndexControl::default();
    let reply = exchange(
        &backend,
        &active,
        &shutdown,
        "/api/query",
        &fixture.rows("duplicate", None),
        TOKEN,
    );
    rejection(&reply, 409, "explorer.request_id");
    let registry = active.lock().unwrap();
    assert_eq!(registry.len(), 1);
    assert!(!original.is_cancelled());
    assert!(!registry.get("duplicate").unwrap().is_cancelled());
    // Prove identity of the surviving shared capability, not merely its presence.
    original.cancel();
    assert!(registry.get("duplicate").unwrap().is_cancelled());
    assert!(!shutdown.is_cancelled());
}

#[test]
fn held_backend_rejects_busy_query_then_retries_with_registry_cleanup() {
    let fixture = Fixture::new();
    let backend = Mutex::new(Backend::new(&fixture.bundle, &fixture.index, MEMORY).unwrap());
    let unrelated = IndexControl::default();
    let active = Active::new(BTreeMap::from([("other".into(), unrelated.clone())]));
    let shutdown = IndexControl::default();
    let request = fixture.rows("retry", None);
    let held = backend.lock().unwrap();
    let busy = exchange(&backend, &active, &shutdown, "/api/query", &request, TOKEN);
    rejection(&busy, 429, "explorer.busy");
    {
        let registry = active.lock().unwrap();
        assert_eq!(
            registry.len(),
            1,
            "busy rejection must release only its new ID"
        );
        assert!(registry.contains_key("other"));
        assert!(!registry.get("other").unwrap().is_cancelled());
    }
    assert!(!shutdown.is_cancelled());
    drop(held);
    let reply = exchange(&backend, &active, &shutdown, "/api/query", &request, TOKEN);
    assert_eq!(reply.status, 200);
    assert_eq!(reply.body["generation"], fixture.bundle.manifest.generation);
    assert_eq!(reply.body["stop_reason"], "complete");
    assert_eq!(reply.body["next_after"], Value::Null);
    assert_eq!(reply.body["scanned"], 3);
    let entries = reply.body["entries"].as_array().unwrap();
    assert_eq!(
        entries
            .iter()
            .map(|row| (
                row["ordinal"].as_u64().unwrap(),
                row["bytes"].as_u64().unwrap()
            ))
            .collect::<Vec<_>>(),
        [(0, 11), (1, 22), (2, 33)]
    );
    let registry = active.lock().unwrap();
    assert_eq!(registry.len(), 1, "success must release only its active ID");
    assert!(!unrelated.is_cancelled());
    unrelated.cancel();
    assert!(
        registry.get("other").unwrap().is_cancelled(),
        "unrelated shared control must survive both cleanup paths"
    );
}

#[test]
fn backend_error_cleans_active_id_and_authenticated_shutdown_cancels_every_control() {
    let fixture = Fixture::new();
    let backend = Mutex::new(Backend::new(&fixture.bundle, &fixture.index, MEMORY).unwrap());
    let active = Active::default();
    let shutdown = IndexControl::default();
    let mut wrong = fixture.rows("error", None);
    wrong["generation"] = json!("stale");
    let reply = exchange(&backend, &active, &shutdown, "/api/query", &wrong, TOKEN);
    rejection(&reply, 409, "explorer.generation");
    assert!(
        active.lock().unwrap().is_empty(),
        "backend errors must release active IDs"
    );
    let first = IndexControl::default();
    let second = IndexControl::default();
    active.lock().unwrap().extend([
        ("first".into(), first.clone()),
        ("second".into(), second.clone()),
    ]);
    let reply = exchange(
        &backend,
        &active,
        &shutdown,
        "/api/shutdown",
        &json!({}),
        TOKEN,
    );
    assert_eq!(reply.status, 200);
    assert_eq!(reply.body, json!({"stopped":true}));
    assert!(shutdown.is_cancelled());
    assert!(first.is_cancelled());
    assert!(second.is_cancelled());
    assert_eq!(active.lock().unwrap().len(), 2);
}

#[test]
fn authenticated_cancel_propagates_the_same_control_to_each_graph_action() {
    let fixture = Fixture::new();
    let backend = Mutex::new(Backend::new(&fixture.bundle, &fixture.index, MEMORY).unwrap());
    let control = IndexControl::default();
    let active = Active::new(BTreeMap::from([("graph".into(), control.clone())]));
    let shutdown = IndexControl::default();
    let reply = exchange(
        &backend,
        &active,
        &shutdown,
        "/api/cancel",
        &json!({"request_id":"graph"}),
        TOKEN,
    );
    assert_eq!(reply.status, 200);
    assert_eq!(reply.body, json!({"cancelled":true}));
    assert!(control.is_cancelled());
    let generation = fixture
        .index
        .artifacts
        .iter()
        .find(|artifact| artifact.kind == "scan_index")
        .unwrap()
        .graph_generation
        .as_ref()
        .unwrap();
    for mode in ["id", "contains"] {
        let request: QueryRequest = serde_json::from_value(json!({
            "request_id":"graph", "generation":fixture.bundle.manifest.generation,
            "action":"graph_search", "graph":"scan_index",
            "query":if mode == "id" { "1" } else { "child" },
            "mode":mode, "after_id":"0"
        }))
        .unwrap();
        let report = backend.lock().unwrap().query(&request, &control).unwrap();
        assert_eq!(report["schema"], "vitnet.dgml-search.v1");
        assert_eq!(report["generation"], *generation);
        assert_eq!(report["stop_reason"], "cancelled");
        assert_eq!(report["next_after_id"], "0");
        assert_eq!(report["entries"], json!([]));
        assert_eq!(report["scanned_nodes"], 0);
        assert_eq!(report["matched_nodes"], 0);
    }
    for (node, total) in [("0", 0), ("1", 1)] {
        let request: QueryRequest = serde_json::from_value(json!({
            "request_id":"graph", "generation":fixture.bundle.manifest.generation,
            "action":"incoming", "graph":"scan_index", "node_id":node, "after_edge":"0"
        }))
        .unwrap();
        let report = backend.lock().unwrap().query(&request, &control).unwrap();
        assert_eq!(report["schema"], "vitnet.dgml-incoming.v1");
        assert_eq!(report["generation"], *generation);
        assert_eq!(report["node"]["node_id"], node);
        assert_eq!(report["stop_reason"], "cancelled");
        assert_eq!(report["total_edges"], total);
        assert_eq!(report["next_after_edge"], "0");
        assert_eq!(report["edges"], json!([]));
    }
    let request: QueryRequest = serde_json::from_value(json!({
        "request_id":"graph", "generation":fixture.bundle.manifest.generation,
        "action":"why", "graph":"scan_index", "node_id":"1"
    }))
    .unwrap();
    let report = backend.lock().unwrap().query(&request, &control).unwrap();
    assert_eq!(report["schema"], "vitnet.dgml-why.v1");
    assert_eq!(report["generation"], *generation);
    assert_eq!(report["node"]["node_id"], "1");
    assert_eq!(report["stop_reason"], "cancelled");
    assert_eq!(report["paths"], json!([]));
    assert_eq!(report["visited_nodes"], 1);
    assert_eq!(report["examined_edges"], 0);
    assert_eq!(active.lock().unwrap().len(), 1);
    assert!(!shutdown.is_cancelled());
}

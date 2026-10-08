#[cfg_attr(windows, path = "..\\src\\daemon.rs")]
#[cfg_attr(not(windows), path = "../src/daemon.rs")]
mod daemon;

#[cfg(not(windows))]
#[test]
fn unsupported_platform_returns_explicit_diagnostics() {
    assert_eq!(
        daemon::serve("vitnet-test", 16 << 20)
            .unwrap_err()
            .diagnostic
            .code,
        "daemon.unsupported"
    );
    assert_eq!(
        daemon::call("vitnet-test", &daemon::Request::Health)
            .unwrap_err()
            .diagnostic
            .code,
        "daemon.unsupported"
    );
}

#[cfg(windows)]
mod windows {
    use super::daemon::{self, Request, Response};
    use std::io;
    use std::path::{Path, PathBuf};
    use std::process::{Child, Command, Stdio};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::mpsc::{Receiver, channel};
    use std::thread::JoinHandle;
    use std::time::{Duration, Instant};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::windows::named_pipe::{ClientOptions, ServerOptions};
    use tokio::runtime::Builder;
    use tokio::time::timeout;
    use vitnet_dgml::{
        IndexControl, IndexOptions, SearchOptions, WhyOptions, build_index, prune_cache,
    };

    static NEXT_PIPE: AtomicU64 = AtomicU64::new(0);
    const MEMORY: u64 = 16 << 20;
    const GRAPH: &[u8] = br#"<DirectedGraph><Nodes>
<Node Id="0" Label="root"/><Node Id="1" Label="Alpha"/>
<Node Id="2" Label="Alpha other"/>
</Nodes><Links><Link Source="0" Target="1" Reason="root"/>
<Link Source="1" Target="2" Reason="call"/></Links></DirectedGraph>"#;

    fn unique_pipe() -> String {
        format!(
            "vitnet-daemon-test-{}-{}",
            std::process::id(),
            NEXT_PIPE.fetch_add(1, Ordering::Relaxed)
        )
    }

    struct Server {
        pipe: String,
        finished: Receiver<Result<(), daemon::DaemonError>>,
        thread: Option<JoinHandle<()>>,
    }

    impl Server {
        fn start() -> Self {
            let pipe = unique_pipe();
            let (send, finished) = channel();
            let server_pipe = pipe.clone();
            let thread = std::thread::spawn(move || {
                send.send(daemon::serve(&server_pipe, MEMORY)).unwrap();
            });
            let mut server = Self {
                pipe,
                finished,
                thread: Some(thread),
            };
            let started = Instant::now();
            loop {
                match daemon::call(&server.pipe, &Request::Health) {
                    Ok(response) => {
                        assert!(response.ok, "{response:?}");
                        break;
                    }
                    Err(cause) => {
                        if let Ok(result) = server.finished.try_recv() {
                            server.thread.take().unwrap().join().unwrap();
                            panic!("daemon startup failed: {result:?}");
                        }
                        assert!(started.elapsed() < Duration::from_secs(5), "{cause}");
                        std::thread::sleep(Duration::from_millis(10));
                    }
                }
            }
            server
        }

        fn call(&self, request: &Request) -> Response {
            daemon::call(&self.pipe, request).unwrap()
        }

        fn shutdown(&mut self) -> Response {
            let response = self.call(&Request::Shutdown);
            assert!(response.ok, "{response:?}");
            assert_eq!(response.data.as_ref().unwrap()["shutdown"], true);
            self.finished
                .recv_timeout(Duration::from_secs(5))
                .expect("daemon did not stop after sending shutdown")
                .unwrap();
            self.thread.take().unwrap().join().unwrap();
            response
        }
    }

    impl Drop for Server {
        fn drop(&mut self) {
            if self.thread.is_some() {
                if let Ok(result) = self.finished.try_recv() {
                    self.thread.take().unwrap().join().unwrap();
                    if let Err(cause) = result {
                        eprintln!("test daemon stopped unexpectedly: {cause}");
                    }
                    return;
                }
                self.shutdown();
            }
        }
    }

    struct ProcessServer {
        pipe: String,
        child: Child,
    }

    impl ProcessServer {
        fn start() -> Self {
            let pipe = unique_pipe();
            let child = Command::new(env!("CARGO_BIN_EXE_vitnet"))
                .args([
                    "--memory-limit",
                    "16MiB",
                    "daemon",
                    "serve",
                    "--pipe",
                    &pipe,
                ])
                .stdout(Stdio::null())
                .stderr(Stdio::inherit())
                .spawn()
                .unwrap();
            let mut server = Self { pipe, child };
            let started = Instant::now();
            loop {
                if let Ok(response) = daemon::call(&server.pipe, &Request::Health) {
                    assert!(response.ok);
                    return server;
                }
                assert!(
                    server.child.try_wait().unwrap().is_none(),
                    "daemon process stopped during startup"
                );
                assert!(
                    started.elapsed() < Duration::from_secs(5),
                    "daemon process startup exceeded deadline"
                );
                std::thread::sleep(Duration::from_millis(10));
            }
        }

        fn shutdown(&mut self) {
            let response = daemon::call(&self.pipe, &Request::Shutdown).unwrap();
            assert!(response.ok);
            let started = Instant::now();
            loop {
                if let Some(status) = self.child.try_wait().unwrap() {
                    assert!(status.success(), "daemon exited with {status}");
                    return;
                }
                assert!(
                    started.elapsed() < Duration::from_secs(5),
                    "daemon shutdown exceeded deadline"
                );
                std::thread::sleep(Duration::from_millis(10));
            }
        }
    }

    impl Drop for ProcessServer {
        fn drop(&mut self) {
            if self.child.try_wait().unwrap().is_some() {
                return;
            }
            if let Err(cause) = daemon::call(&self.pipe, &Request::Shutdown) {
                eprintln!("process test cleanup shutdown failed: {cause}");
            }
            let started = Instant::now();
            while started.elapsed() < Duration::from_secs(5) {
                if self.child.try_wait().unwrap().is_some() {
                    return;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            eprintln!(
                "terminating unresponsive test daemon PID {}",
                self.child.id()
            );
            self.child.kill().unwrap();
            self.child.wait().unwrap();
        }
    }

    fn index(directory: &Path, name: &str) -> PathBuf {
        index_graph(directory, name, GRAPH)
    }

    fn index_graph(directory: &Path, name: &str, graph: &[u8]) -> PathBuf {
        let input = directory.join(format!("{name}.xml"));
        std::fs::write(&input, graph).unwrap();
        build_index(
            &input,
            &IndexOptions {
                cache_root: directory.join("cache"),
                memory_limit: MEMORY,
                selected_entry: None,
                strict_hash: false,
                control: IndexControl::default(),
            },
        )
        .unwrap()
        .index_directory
    }

    fn search(index: &Path) -> Request {
        Request::Search {
            index: index.into(),
            query: "Alpha".into(),
            options: SearchOptions::default(),
        }
    }

    fn raw(pipe: &str, request: &[u8]) -> Vec<u8> {
        Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                timeout(Duration::from_secs(10), async {
                    let mut client = loop {
                        match ClientOptions::new().open(format!(r"\\.\pipe\{pipe}")) {
                            Ok(client) => break client,
                            Err(cause) if cause.raw_os_error() == Some(231) => {
                                tokio::time::sleep(Duration::from_millis(10)).await;
                            }
                            Err(cause) => panic!("raw pipe connect failed: {cause}"),
                        }
                    };
                    client.write_all(request).await.unwrap();
                    let mut bytes = Vec::new();
                    let mut buffer = [0; 4096];
                    loop {
                        let count = client.read(&mut buffer).await.unwrap();
                        assert!(count > 0, "pipe closed before a complete HTTP response");
                        bytes.extend_from_slice(&buffer[..count]);
                        if let Some(offset) = bytes.windows(4).position(|part| part == b"\r\n\r\n")
                        {
                            let head = std::str::from_utf8(&bytes[..offset]).unwrap();
                            let length = head
                                .lines()
                                .find_map(|line| {
                                    let (name, value) = line.split_once(':')?;
                                    name.eq_ignore_ascii_case("content-length")
                                        .then(|| value.trim().parse::<usize>().unwrap())
                                })
                                .expect("response must declare its body length");
                            if bytes.len() >= offset + 4 + length {
                                break bytes;
                            }
                        }
                    }
                })
                .await
                .expect("raw request exceeded its test deadline")
            })
    }

    fn http_error(bytes: &[u8], expected_status: &str, expected_code: &str) {
        let text = std::str::from_utf8(bytes).unwrap();
        assert!(text.starts_with(expected_status), "{text}");
        let body = text.split_once("\r\n\r\n").unwrap().1;
        let response: Response = serde_json::from_str(body).unwrap();
        assert_eq!(response.schema, daemon::RESPONSE_SCHEMA);
        assert!(!response.ok);
        assert!(response.data.is_none());
        assert_eq!(response.error.unwrap().code, expected_code);
    }

    #[test]
    fn health_and_shutdown_acknowledgement_release_the_pipe() {
        let mut server = Server::start();
        let health = server.call(&Request::Health);
        assert_eq!(health.schema, daemon::RESPONSE_SCHEMA);
        assert!(health.ok);
        assert!(health.error.is_none());
        assert!(!health.session_reused);
        let data = health.data.unwrap();
        assert_eq!(data["schema"], "vitnet.daemon-health.v1");
        assert_eq!(data["sessions"], 0);
        assert_eq!(data["session_limit"], 2);
        assert!(data["elapsed_ms"].is_u64());
        let get = raw(
            &server.pipe,
            b"GET /health HTTP/1.1\r\nHost: localhost\r\n\r\n",
        );
        assert!(get.starts_with(b"HTTP/1.1 200"));
        server.shutdown();
        assert_eq!(
            daemon::call(&server.pipe, &Request::Health)
                .unwrap_err()
                .diagnostic
                .code,
            "io.daemon.pipe_connect"
        );
    }

    #[test]
    fn incoming_and_batch_match_local_results_and_reuse_generation() {
        let directory = tempfile::tempdir().unwrap();
        let path = index(directory.path(), "expanded");
        let mut server = Server::start();
        let mut session = vitnet_dgml::GraphSession::open(&path, MEMORY).unwrap();
        let options = vitnet_dgml::IncomingOptions::default();
        let local = session.incoming(2, &options).unwrap();
        let remote = server.call(&Request::Incoming {
            index: path.clone(),
            node_id: 2,
            options,
        });
        assert!(remote.ok, "{remote:?}");
        let remote: vitnet_dgml::IncomingReport =
            serde_json::from_value(remote.data.unwrap()).unwrap();
        assert_eq!(remote.generation, local.generation);
        assert_eq!(remote.total_edges, 1);
        assert_eq!(remote.edges[0].source_id, 1);
        assert_eq!(remote.edges[0].target_id, 2);
        assert_eq!(remote.edges[0].reason, local.edges[0].reason);
        let options = WhyOptions::default();
        let local = session.batch(&[2, 1], &options).unwrap();
        let remote = server.call(&Request::Batch {
            index: path,
            ids: vec![2, 1],
            options,
        });
        assert!(remote.ok, "{remote:?}");
        assert!(remote.session_reused);
        let remote: vitnet_dgml::BatchReport =
            serde_json::from_value(remote.data.unwrap()).unwrap();
        assert_eq!(remote.generation, local.generation);
        assert_eq!(remote.examined_edges, local.examined_edges);
        assert_eq!(remote.visited_nodes, local.visited_nodes);
        assert_eq!(remote.reports.len(), 2);
        assert_eq!(
            remote.reports[0].paths[0].reasons,
            local.reports[0].paths[0].reasons
        );
        server.shutdown();
    }

    #[test]
    fn missing_daemon_fails_quickly_and_rejects_remote_pipe_names() {
        let pipe = unique_pipe();
        let started = Instant::now();
        let cause = daemon::call(&pipe, &Request::Health).unwrap_err();
        assert_eq!(cause.diagnostic.code, "io.daemon.pipe_connect");
        assert!(cause.diagnostic.message.contains(&pipe));
        assert!(started.elapsed() < Duration::from_secs(1));
        for name in [r"\\remote\pipe\test", "", r"nested\pipe", "bad\nname"] {
            assert_eq!(
                daemon::call(name, &Request::Health)
                    .unwrap_err()
                    .diagnostic
                    .code,
                "io.daemon.pipe_name"
            );
        }
    }

    #[test]
    fn canonical_sessions_reuse_generation_and_hold_cache_locks_until_shutdown() {
        let directory = tempfile::tempdir().unwrap();
        let index = index(directory.path(), "reuse");
        let mut server = Server::start();
        let first = server.call(&search(&index));
        assert!(first.ok, "{first:?}");
        assert!(!first.session_reused);
        let first_data = first.data.unwrap();
        let generation = first_data["generation"].as_str().unwrap().to_owned();
        assert_eq!(first_data["entries"][0]["node_id"], 1);
        assert_eq!(first_data["entries"][1]["node_id"], 2);
        let second = server.call(&search(&index.join(".")));
        assert!(second.ok);
        assert!(second.session_reused);
        assert_eq!(second.data.unwrap()["generation"], generation);
        assert_eq!(
            prune_cache(&index).unwrap_err().diagnostic.code,
            "dgml.index.locked"
        );
        let why = server.call(&Request::Why {
            index: index.clone(),
            node_id: 2,
            options: WhyOptions::default(),
        });
        assert!(why.ok, "{why:?}");
        assert!(why.session_reused);
        let data = why.data.unwrap();
        assert_eq!(data["generation"], generation);
        assert_eq!(data["node"]["node_id"], 2);
        assert_eq!(data["paths"][0]["nodes"][0]["node_id"], 0);
        let stale = server.call(&Request::Search {
            index: index.clone(),
            query: "Alpha".into(),
            options: SearchOptions {
                generation: Some("not-this-generation".into()),
                ..Default::default()
            },
        });
        assert!(!stale.ok);
        assert!(stale.session_reused);
        assert!(stale.data.is_none());
        assert_eq!(stale.error.unwrap().code, "dgml.query.generation");
        server.shutdown();
        assert_eq!(prune_cache(&index).unwrap().generations_removed, 0);
    }

    #[test]
    fn sequential_large_why_responses_are_delivered_completely() {
        use std::fmt::Write as _;
        let directory = tempfile::tempdir().unwrap();
        let label = "long label ".repeat(400);
        let mut graph = String::from("<DirectedGraph><Nodes>");
        for id in 0..=32 {
            write!(graph, "<Node Id=\"{id}\" Label=\"{label}\"/>").unwrap();
        }
        graph.push_str("</Nodes><Links>");
        for id in 1..=32 {
            write!(
                graph,
                "<Link Source=\"{}\" Target=\"{id}\" Reason=\"call\"/>",
                id - 1
            )
            .unwrap();
        }
        graph.push_str("</Links></DirectedGraph>");
        let index = index_graph(directory.path(), "large-why", graph.as_bytes());
        let request = Request::Why {
            index: index.clone(),
            node_id: 32,
            options: WhyOptions {
                max_depth: 32,
                max_paths: 1,
                max_visited: 128,
                max_edges: 128,
                preview_bytes: label.len(),
                ..Default::default()
            },
        };
        let mut server = Server::start();
        let mut generation = None;
        for iteration in 0..100 {
            let response = daemon::call(&server.pipe, &request)
                .unwrap_or_else(|cause| panic!("Why response {iteration} failed: {cause}"));
            assert!(response.ok, "Why response {iteration}: {response:?}");
            assert_eq!(response.session_reused, iteration != 0);
            assert!(serde_json::to_vec(&response).unwrap().len() > 64 * 1024);
            let data = response.data.unwrap();
            let current = data["generation"].as_str().unwrap().to_owned();
            assert_eq!(generation.get_or_insert_with(|| current.clone()), &current);
            assert_eq!(data["node"]["label"], label);
            let nodes = data["paths"][0]["nodes"].as_array().unwrap();
            assert_eq!(nodes.len(), 33);
            assert_eq!(nodes[0]["node_id"], 0);
            assert_eq!(nodes[32]["node_id"], 32);
            assert_eq!(nodes[32]["label"], label);
        }
        assert!(server.call(&Request::Health).ok);
        server.shutdown();
        assert!(prune_cache(&index).is_ok());
    }

    #[test]
    fn sequential_process_why_responses_are_delivered_completely() {
        let directory = tempfile::tempdir().unwrap();
        let index = index(directory.path(), "process-why");
        let mut server = ProcessServer::start();
        let request = Request::Why {
            index: index.clone(),
            node_id: 2,
            options: WhyOptions {
                max_depth: 32,
                ..Default::default()
            },
        };
        let mut generation = None;
        for iteration in 0..500 {
            let response = daemon::call(&server.pipe, &request)
                .unwrap_or_else(|cause| panic!("process Why response {iteration} failed: {cause}"));
            assert!(
                response.ok,
                "process Why response {iteration}: {response:?}"
            );
            assert_eq!(response.session_reused, iteration != 0);
            let data = response.data.unwrap();
            let current = data["generation"].as_str().unwrap().to_owned();
            assert_eq!(generation.get_or_insert_with(|| current.clone()), &current);
            assert_eq!(data["node"]["node_id"], 2);
            assert_eq!(data["node"]["label"], "Alpha other");
            assert_eq!(data["paths"][0]["nodes"][0]["node_id"], 0);
        }
        server.shutdown();
        assert!(prune_cache(&index).is_ok());
    }

    #[test]
    fn sequential_cli_clients_receive_complete_why_responses() {
        let directory = tempfile::tempdir().unwrap();
        let index = index(directory.path(), "cli-why");
        let mut server = ProcessServer::start();
        let mut generation = None;
        for iteration in 0..100 {
            let output = Command::new(env!("CARGO_BIN_EXE_vitnet"))
                .args([
                    "--format",
                    "json",
                    "--memory-limit",
                    "16MiB",
                    "--daemon",
                    &server.pipe,
                    "dgml",
                    "why",
                ])
                .arg(&index)
                .args(["2", "--max-depth", "32"])
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "CLI Why response {iteration} failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            let data: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
            let current = data["generation"].as_str().unwrap().to_owned();
            assert_eq!(generation.get_or_insert_with(|| current.clone()), &current);
            assert_eq!(data["node"]["node_id"], 2);
            assert_eq!(data["paths"][0]["nodes"][0]["node_id"], 0);
        }
        server.shutdown();
        assert!(prune_cache(&index).is_ok());
    }

    #[test]
    fn two_session_lru_evicts_the_least_recently_used_lock() {
        let directory = tempfile::tempdir().unwrap();
        let a = index(directory.path(), "a");
        let b = index(directory.path(), "b");
        let c = index(directory.path(), "c");
        let mut server = Server::start();
        assert!(!server.call(&search(&a)).session_reused);
        assert!(!server.call(&search(&b)).session_reused);
        assert!(server.call(&search(&a)).session_reused);
        assert!(!server.call(&search(&c)).session_reused);
        assert_eq!(
            prune_cache(&a).unwrap_err().diagnostic.code,
            "dgml.index.locked"
        );
        assert_eq!(
            prune_cache(&c).unwrap_err().diagnostic.code,
            "dgml.index.locked"
        );
        assert!(prune_cache(&b).is_ok());
        let health = server.call(&Request::Health).data.unwrap();
        assert_eq!(health["sessions"], 2);
        assert_eq!(health["session_opens"], 3);
        assert_eq!(health["session_hits"], 1);
        assert_eq!(health["session_evictions"], 1);
        server.shutdown();
        assert!(prune_cache(&a).is_ok());
        assert!(prune_cache(&c).is_ok());
    }

    #[test]
    fn invalid_method_path_json_and_declared_body_limit_return_typed_errors() {
        let mut server = Server::start();
        for (request, code) in [
            ("not HTTP\r\n\r\n", "io.daemon.http"),
            (
                "POST /query HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\nContent-Length: 0\r\n\r\n",
                "io.daemon.http",
            ),
            (
                "POST /query HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\nTransfer-Encoding: chunked\r\n\r\n",
                "io.daemon.http",
            ),
            (
                "PUT /query HTTP/1.1\r\nHost: localhost\r\n\r\n",
                "io.daemon.method",
            ),
            (
                "POST /other HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n",
                "io.daemon.path",
            ),
            (
                "POST /query HTTP/1.1\r\nHost: localhost\r\nContent-Length: 1\r\n\r\n{",
                "io.daemon.json",
            ),
            (
                "POST /query HTTP/1.1\r\nHost: localhost\r\nContent-Type: text/plain\r\nContent-Length: 0\r\n\r\n",
                "io.daemon.content_type",
            ),
        ] {
            http_error(&raw(&server.pipe, request.as_bytes()), "HTTP/1.1 400", code);
        }
        http_error(
            &raw(
                &server.pipe,
                b"POST /query HTTP/1.1\r\nHost: localhost\r\nContent-Length: 1048577\r\n\r\n",
            ),
            "HTTP/1.1 413",
            "resource.daemon.request_body",
        );
        assert!(server.call(&Request::Health).ok);
        server.shutdown();
    }

    #[test]
    fn stalled_request_body_times_out_and_the_daemon_remains_responsive() {
        let mut server = Server::start();
        let started = Instant::now();
        http_error(
            &raw(
                &server.pipe,
                b"POST /query HTTP/1.1\r\nHost: localhost\r\nContent-Length: 1\r\n\r\n",
            ),
            "HTTP/1.1 408",
            "io.daemon.timeout",
        );
        assert!(started.elapsed() >= Duration::from_secs(4));
        assert!(started.elapsed() < Duration::from_secs(8));
        assert!(server.call(&Request::Health).ok);
        server.shutdown();
    }

    #[test]
    fn client_request_limit_and_first_instance_ownership_are_enforced() {
        let mut server = Server::start();
        let cause = daemon::call(
            &server.pipe,
            &Request::Search {
                index: PathBuf::from("unused"),
                query: "a".repeat(1024 * 1024),
                options: SearchOptions::default(),
            },
        )
        .unwrap_err();
        assert_eq!(cause.diagnostic.code, "resource.daemon.request_body");
        assert_eq!(
            daemon::serve(&server.pipe, MEMORY)
                .unwrap_err()
                .diagnostic
                .code,
            "io.daemon.pipe_create"
        );
        assert!(server.call(&Request::Health).ok);
        server.shutdown();
    }

    #[test]
    fn two_pipe_instances_bound_clients_and_busy_connects_have_a_deadline() {
        let mut server = Server::start();
        let runtime = Builder::new_current_thread().enable_all().build().unwrap();
        let clients = runtime.block_on(async {
            timeout(Duration::from_secs(2), async {
                let mut clients = Vec::new();
                while clients.len() < 2 {
                    match ClientOptions::new().open(format!(r"\\.\pipe\{}", server.pipe)) {
                        Ok(client) => clients.push(client),
                        Err(cause) if cause.raw_os_error() == Some(231) => {
                            tokio::time::sleep(Duration::from_millis(10)).await;
                        }
                        Err(cause) => panic!("idle client failed to connect: {cause}"),
                    }
                }
                clients
            })
            .await
            .unwrap()
        });
        let started = Instant::now();
        let result = daemon::call(&server.pipe, &Request::Health);
        drop(clients);
        runtime.block_on(async { tokio::time::sleep(Duration::from_millis(20)).await });
        assert_eq!(
            result.unwrap_err().diagnostic.code,
            "io.daemon.pipe_connect_timeout"
        );
        assert!(started.elapsed() >= Duration::from_secs(2));
        assert!(started.elapsed() < Duration::from_secs(5));
        assert!(server.call(&Request::Health).ok);
        server.shutdown();
    }

    #[test]
    fn expired_client_retaining_its_handle_cannot_stop_pipe_handoffs() {
        let mut server = Server::start();
        let runtime = Builder::new_current_thread().enable_all().build().unwrap();
        let idle = {
            let _entered = runtime.enter();
            ClientOptions::new()
                .open(format!(r"\\.\pipe\{}", server.pipe))
                .unwrap()
        };
        let result = daemon::call(&server.pipe, &Request::Health);
        drop(idle);
        runtime.block_on(async { tokio::time::sleep(Duration::from_millis(20)).await });
        let response = result.unwrap();
        assert!(response.ok, "{response:?}");
        assert_eq!(response.data.unwrap()["sessions"], 0);
        server.shutdown();
    }

    #[test]
    fn query_errors_are_distinct_from_pipe_errors() {
        let directory = tempfile::tempdir().unwrap();
        let mut server = Server::start();
        let response = server.call(&search(&directory.path().join("missing-index")));
        assert!(!response.ok);
        assert!(!response.session_reused);
        assert!(response.data.is_none());
        assert_eq!(response.error.unwrap().code, "io.daemon.index_path");
        let malformed = index(directory.path(), "malformed");
        let response = server.call(&Request::Search {
            index: malformed,
            query: String::new(),
            options: SearchOptions::default(),
        });
        assert!(!response.ok);
        assert_eq!(response.error.unwrap().code, "dgml.query.options");
        server.shutdown();
    }

    #[test]
    fn client_rejects_malformed_and_oversized_http_responses() {
        for (reply, code) in [
            (
                b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 1\r\n\r\n{".as_slice(),
                "io.daemon.json",
            ),
            (
                b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 16777217\r\n\r\n".as_slice(),
                "resource.daemon.response_body",
            ),
            (
                b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n".as_slice(),
                "io.daemon.protocol",
            ),
            (
                b"not HTTP\r\n\r\n".as_slice(),
                "io.daemon.http",
            ),
            (
                b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 10\r\n\r\n{".as_slice(),
                "io.daemon.body",
            ),
        ] {
            let pipe = unique_pipe();
            let runtime = Builder::new_current_thread().enable_all().build().unwrap();
            let listener = {
                let _entered = runtime.enter();
                ServerOptions::new()
                    .first_pipe_instance(true)
                    .reject_remote_clients(true)
                    .create(format!(r"\\.\pipe\{pipe}"))
                    .unwrap()
            };
            let thread = std::thread::spawn(move || {
                runtime.block_on(async {
                    timeout(Duration::from_secs(5), async {
                        listener.connect().await.unwrap();
                        let mut listener = listener;
                        let mut request = [0; 4096];
                        assert!(listener.read(&mut request).await.unwrap() > 0);
                        match listener.write_all(reply).await {
                            Ok(()) => {}
                            Err(cause) if cause.kind() == io::ErrorKind::BrokenPipe => {}
                            Err(cause) => panic!("fake response write failed: {cause}"),
                        }
                        tokio::time::sleep(Duration::from_millis(50)).await;
                    }).await.unwrap();
                });
            });
            let result = daemon::call(&pipe, &Request::Health);
            thread.join().unwrap();
            let cause = result.unwrap_err();
            assert_eq!(cause.diagnostic.code, code);
            if code == "io.daemon.body" {
                assert!(cause.diagnostic.message.contains("after 1 bytes"));
                assert!(cause.diagnostic.message.contains("expected at least 10"));
                assert!(cause.diagnostic.message.contains("end of file before message length reached"));
            }
        }
    }
}

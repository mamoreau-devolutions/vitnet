use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use vitnet_dgml::{IndexOptions, build_index, cache_info, prune_cache, verify_cache};

const GRAPH: &[u8] = br#"<DirectedGraph xmlns="http://schemas.microsoft.com/vs/2009/dgml">
<Nodes>
<Node Id="0" Label="root" />
<Node Id="1" Label="alpha &amp; beta" />
<Node Id="2" Label="alpha &amp; beta" />
</Nodes>
<Links>
<Link Source="0" Target="2" Reason="A" />
<Link Source="1" Target="2" Reason="B &amp; C" />
<Link Source="9" Target="1" Reason="A" />
</Links>
</DirectedGraph>"#;

#[test]
fn builds_and_publishes_immutable_csr_generation() {
    let root = unique_temp("plain");
    let input = root.join("graph.dgml.xml");
    fs::create_dir_all(&root).unwrap();
    fs::write(&input, GRAPH).unwrap();

    let report = build_index(&input, &options(root.join("cache"), None)).unwrap();
    let generation = report
        .index_directory
        .join("generations")
        .join(&report.generation);
    assert_eq!(report.schema, "vitnet.dgml-index.v1");
    assert_eq!(report.manifest.node_count, 3);
    assert_eq!(report.manifest.edge_count, 3);
    assert_eq!(report.manifest.unresolved_endpoints, 1);
    assert_eq!(report.manifest.max_node_id, Some(2));
    assert!(report.manifest.complete);
    assert_eq!(
        fs::read_to_string(report.index_directory.join("CURRENT"))
            .unwrap()
            .trim(),
        report.generation
    );
    assert_eq!(
        fs::metadata(generation.join("nodes.bin")).unwrap().len(),
        48
    );
    assert_eq!(
        fs::metadata(generation.join("target-offsets.bin"))
            .unwrap()
            .len(),
        32
    );
    assert_eq!(
        fs::metadata(generation.join("incoming-edges.bin"))
            .unwrap()
            .len(),
        72
    );
    assert!(fs::metadata(generation.join("labels.fst")).unwrap().len() > 0);
    assert_eq!(
        fs::read(generation.join("target-offsets.bin")).unwrap(),
        [0_u64, 0, 1, 3]
            .iter()
            .flat_map(|value| value.to_le_bytes())
            .collect::<Vec<_>>()
    );
    let incoming = fs::read(generation.join("incoming-edges.bin")).unwrap();
    let expected_incoming = [(9_u64, 0_u64, 1_u32), (0, 0, 1), (1, 1, 5)]
        .iter()
        .flat_map(|(source, reason, length)| {
            [
                source.to_le_bytes().as_slice(),
                reason.to_le_bytes().as_slice(),
                length.to_le_bytes().as_slice(),
                0_u32.to_le_bytes().as_slice(),
            ]
            .concat()
        })
        .collect::<Vec<_>>();
    assert_eq!(incoming, expected_incoming);
    assert_eq!(fs::read(generation.join("reasons.bin")).unwrap(), b"AB & C");
    let labels = fst::Map::new(fs::read(generation.join("labels.fst")).unwrap()).unwrap();
    assert_eq!(labels.len(), 3);
    for node in [1_u64, 2] {
        let key = [b"alpha & beta\0".as_slice(), node.to_be_bytes().as_slice()].concat();
        assert_eq!(labels.get(key), Some(node));
    }
    let checksums: serde_json::Value =
        serde_json::from_slice(&fs::read(generation.join("checksums.json")).unwrap()).unwrap();
    assert_eq!(checksums.as_object().unwrap().len(), 7);
    assert_eq!(
        cache_info(&report.index_directory)
            .unwrap()
            .manifest
            .edge_count,
        3
    );
    assert_eq!(
        verify_cache(&report.index_directory)
            .unwrap()
            .files_verified,
        7
    );

    fs::remove_dir_all(root).unwrap();
}

#[test]
fn verification_detects_corruption_and_prune_preserves_current() {
    let root = unique_temp("cache");
    let input = root.join("graph.dgml.xml");
    let cache = root.join("cache");
    fs::create_dir_all(&root).unwrap();
    fs::write(&input, GRAPH).unwrap();

    let first = build_index(&input, &options(cache.clone(), None)).unwrap();
    let second = build_index(&input, &options(cache, None)).unwrap();
    let stale = second
        .index_directory
        .join("generations")
        .join(".building-stale");
    fs::create_dir(&stale).unwrap();
    fs::write(stale.join("partial"), b"partial").unwrap();
    let prune = prune_cache(&second.index_directory).unwrap();
    assert_eq!(prune.current_generation, second.generation);
    assert_eq!(prune.generations_removed, 1);
    assert_eq!(prune.temporary_directories_removed, 1);
    assert!(
        !second
            .index_directory
            .join("generations")
            .join(first.generation)
            .exists()
    );

    let strings = second
        .index_directory
        .join("generations")
        .join(second.generation)
        .join("strings.bin");
    let mut bytes = fs::read(&strings).unwrap();
    bytes[0] ^= 1;
    fs::write(strings, bytes).unwrap();
    let error = verify_cache(&second.index_directory).unwrap_err();
    assert_eq!(error.diagnostic.code, "dgml.cache.checksum");

    fs::remove_dir_all(root).unwrap();
}

#[test]
fn reads_the_single_selected_zip_entry() {
    let root = unique_temp("zip");
    fs::create_dir_all(&root).unwrap();
    let input = root.join("graph.zip");
    let file = File::create(&input).unwrap();
    let mut archive = zip::ZipWriter::new(file);
    archive
        .start_file(
            "nested/graph.dgml.xml",
            zip::write::SimpleFileOptions::default(),
        )
        .unwrap();
    archive.write_all(GRAPH).unwrap();
    archive.finish().unwrap();

    let report = build_index(&input, &options(root.join("cache"), None)).unwrap();
    assert_eq!(
        report.manifest.selected_entry.as_deref(),
        Some("nested/graph.dgml.xml")
    );
    assert_eq!(report.manifest.node_count, 3);

    fs::remove_dir_all(root).unwrap();
}

#[test]
fn malformed_build_never_publishes_current() {
    let root = unique_temp("malformed");
    let input = root.join("bad.dgml.xml");
    let cache = root.join("cache");
    fs::create_dir_all(&root).unwrap();
    fs::write(&input, b"<DirectedGraph><Node Id=\"0\">").unwrap();

    let error = build_index(&input, &options(cache.clone(), None)).unwrap_err();
    assert_eq!(error.diagnostic.code, "dgml.xml");
    assert!(!contains_named_file(&cache, "CURRENT"));

    fs::remove_dir_all(root).unwrap();
}

#[test]
fn rejects_invalid_roots_sparse_ids_and_oversized_events_without_publication() {
    let root = unique_temp("invalid");
    fs::create_dir_all(&root).unwrap();
    let duplicate = root.join("duplicate.xml");
    fs::write(
        &duplicate,
        b"<DirectedGraph><Node Id=\"0\" Label=\"a\" Id=\"1\"/></DirectedGraph>",
    )
    .unwrap();
    assert_eq!(
        build_index(&duplicate, &options(root.join("duplicate-cache"), None))
            .unwrap_err()
            .diagnostic
            .code,
        "dgml.attribute"
    );
    for (index, (graph, code)) in [
        (b"<Other><DirectedGraph/></Other>".to_vec(), "dgml.root"),
        (b"<DirectedGraph/><DirectedGraph/>".to_vec(), "dgml.root"),
        (b"<DirectedGraph/><Node Id=\"0\"/>".to_vec(), "dgml.root"),
        (b"<DirectedGraph>hello".to_vec(), "dgml.xml"),
        (b"<DirectedGraph><Node Id=\"18446744073709551615\"/></DirectedGraph>".to_vec(), "resource.node_id_range"),
        (b"<DirectedGraph><Node Id=\"0\"/><Link Source=\"0\" Target=\"18446744073709551615\"/></DirectedGraph>".to_vec(), "dgml.edge.target"),
        (b"<DirectedGraph><Node Id=\"0\" Label=\"&#0;\"/></DirectedGraph>".to_vec(), "dgml.attribute"),
        ([b"<DirectedGraph><Node Id=\"0\" Label=\"".as_slice(), &vec![b'x'; 300_000], b"\"/></DirectedGraph>"].concat(), "resource.record_limit"),
    ].into_iter().enumerate() {
        let input = root.join(format!("bad-{index}.xml"));
        let cache = root.join(format!("cache-{index}"));
        fs::write(&input, graph).unwrap();
        let error = build_index(&input, &options(cache.clone(), None)).unwrap_err();
        assert_eq!(error.diagnostic.code, code, "fixture {index}");
        assert!(!contains_named_file(&cache, "CURRENT"));
    }
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn accepts_empty_graphs_and_marks_sparse_empty_labels_as_present() {
    let root = unique_temp("empty");
    fs::create_dir_all(&root).unwrap();
    let input = root.join("graph.xml");
    fs::write(&input, b"<DirectedGraph/>").unwrap();
    let empty = build_index(&input, &options(root.join("cache"), None)).unwrap();
    assert_eq!(empty.manifest.node_count, 0);
    assert_eq!(empty.manifest.edge_count, 0);
    assert_eq!(empty.manifest.max_node_id, None);
    assert!(verify_cache(&empty.index_directory).unwrap().valid);
    fs::write(
        &input,
        b"<DirectedGraph><Node Id=\"2\"/><Node Id=\"2\" Label=\"ignored\"/></DirectedGraph>",
    )
    .unwrap();
    let sparse = build_index(&input, &options(root.join("cache"), None)).unwrap();
    assert_eq!(sparse.manifest.node_count, 1);
    assert_eq!(sparse.manifest.duplicate_node_ids, 1);
    let path = sparse
        .index_directory
        .join("generations")
        .join(sparse.generation);
    let records = fs::read(path.join("nodes.bin")).unwrap();
    assert_eq!(&records[..32], &[0; 32]);
    assert_eq!(&records[44..48], &1_u32.to_le_bytes());
    assert!(verify_cache(&sparse.index_directory).unwrap().valid);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn kernel_lock_excludes_builders_and_pruners_and_recovers_stale_metadata() {
    use fs4::FileExt;
    let root = unique_temp("lock");
    fs::create_dir_all(&root).unwrap();
    let input = root.join("graph.xml");
    fs::write(&input, GRAPH).unwrap();
    let configured = options(root.join("cache"), None);
    let first = build_index(&input, &configured).unwrap();
    let mut lock = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(first.index_directory.join("lock"))
        .unwrap();
    FileExt::lock(&lock).unwrap();
    let error = build_index(&input, &configured).unwrap_err();
    assert_eq!(error.diagnostic.code, "dgml.index.locked");
    assert_eq!(
        prune_cache(&first.index_directory)
            .unwrap_err()
            .diagnostic
            .code,
        "dgml.index.locked"
    );
    assert_eq!(
        cache_info(&first.index_directory)
            .unwrap_err()
            .diagnostic
            .code,
        "dgml.index.locked"
    );
    lock.set_len(0).unwrap();
    lock.write_all(b"interrupted lock metadata").unwrap();
    drop(lock);
    let second = build_index(&input, &configured).unwrap();
    assert_ne!(first.generation, second.generation);
    assert!(verify_cache(&second.index_directory).unwrap().valid);
    let reader = File::open(second.index_directory.join("lock")).unwrap();
    FileExt::lock_shared(&reader).unwrap();
    assert_eq!(
        cache_info(&second.index_directory).unwrap().generation,
        second.generation
    );
    assert_eq!(
        build_index(&input, &configured)
            .unwrap_err()
            .diagnostic
            .code,
        "dgml.index.locked"
    );
    assert_eq!(
        prune_cache(&second.index_directory)
            .unwrap_err()
            .diagnostic
            .code,
        "dgml.index.locked"
    );
    drop(reader);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn competing_builders_publish_exactly_one_valid_generation() {
    use std::sync::{Barrier, OnceLock};
    static ACQUIRED: OnceLock<Barrier> = OnceLock::new();
    static RELEASE: OnceLock<Barrier> = OnceLock::new();
    ACQUIRED.set(Barrier::new(2)).unwrap();
    RELEASE.set(Barrier::new(2)).unwrap();
    let root = unique_temp("concurrent");
    fs::create_dir_all(&root).unwrap();
    let input = root.join("graph.xml");
    fs::write(&input, GRAPH).unwrap();
    let configured = options(root.join("cache"), None);
    let mut first_options = configured.clone();
    first_options.control.progress = Some(|phase, _| {
        if phase == "ingesting XML" {
            ACQUIRED.get().unwrap().wait();
            RELEASE.get().unwrap().wait();
        }
    });
    let first_input = input.clone();
    let first = std::thread::spawn(move || build_index(&first_input, &first_options));
    ACQUIRED.get().unwrap().wait();
    let second = build_index(&input, &configured);
    RELEASE.get().unwrap().wait();
    let published = first.join().unwrap().unwrap();
    assert_eq!(second.unwrap_err().diagnostic.code, "dgml.index.locked");
    assert_eq!(
        fs::read_dir(published.index_directory.join("generations"))
            .unwrap()
            .count(),
        1
    );
    assert_eq!(
        cache_info(&published.index_directory).unwrap().generation,
        published.generation
    );
    assert!(verify_cache(&published.index_directory).unwrap().valid);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn cancellation_preserves_current_and_cleans_partial_generation() {
    use std::sync::{Mutex, OnceLock};
    use vitnet_dgml::IndexControl;
    static ACTIVE: OnceLock<Mutex<IndexControl>> = OnceLock::new();
    let root = unique_temp("cancel");
    fs::create_dir_all(&root).unwrap();
    let input = root.join("graph.xml");
    fs::write(&input, GRAPH).unwrap();
    let mut configured = options(root.join("cache"), None);
    let first = build_index(&input, &configured).unwrap();
    ACTIVE.set(Mutex::new(configured.control.clone())).unwrap();
    configured.control.progress = Some(|phase, _| {
        if phase == "sorting labels" {
            ACTIVE.get().unwrap().lock().unwrap().cancel();
        }
    });
    let error = build_index(&input, &configured).unwrap_err();
    assert_eq!(error.diagnostic.code, "resource.cancelled");
    assert_eq!(
        cache_info(&first.index_directory).unwrap().generation,
        first.generation
    );
    assert_eq!(
        fs::read_dir(first.index_directory.join("generations"))
            .unwrap()
            .count(),
        1
    );
    assert!(verify_cache(&first.index_directory).unwrap().valid);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn input_mutation_during_build_never_replaces_current() {
    use std::sync::OnceLock;
    static INPUT: OnceLock<PathBuf> = OnceLock::new();
    let root = unique_temp("mutation");
    fs::create_dir_all(&root).unwrap();
    let input = root.join("graph.xml");
    fs::write(&input, GRAPH).unwrap();
    let mut configured = options(root.join("cache"), None);
    let first = build_index(&input, &configured).unwrap();
    INPUT.set(input.clone()).unwrap();
    configured.control.progress = Some(|phase, _| {
        if phase == "sorting incoming edges" {
            fs::write(INPUT.get().unwrap(), b"<DirectedGraph/>").unwrap();
        }
    });
    let error = build_index(&input, &configured).unwrap_err();
    assert_eq!(error.diagnostic.code, "dgml.input.changed");
    assert_eq!(
        cache_info(&first.index_directory).unwrap().generation,
        first.generation
    );
    assert_eq!(
        fs::read_dir(first.index_directory.join("generations"))
            .unwrap()
            .count(),
        1
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn rejects_incomplete_checksums_and_invalid_csr_even_when_rehashed() {
    let root = unique_temp("structure");
    fs::create_dir_all(&root).unwrap();
    let input = root.join("graph.xml");
    fs::write(&input, GRAPH).unwrap();
    let report = build_index(&input, &options(root.join("cache"), None)).unwrap();
    let path = report
        .index_directory
        .join("generations")
        .join(report.generation);
    let checksum_path = path.join("checksums.json");
    let original = fs::read(&checksum_path).unwrap();
    fs::write(&checksum_path, b"{}").unwrap();
    assert_eq!(
        verify_cache(&report.index_directory)
            .unwrap_err()
            .diagnostic
            .code,
        "dgml.cache.checksum"
    );
    let offsets_path = path.join("target-offsets.bin");
    fs::write(
        &offsets_path,
        [1_u64, 0, 1, 3]
            .iter()
            .flat_map(|value| value.to_le_bytes())
            .collect::<Vec<_>>(),
    )
    .unwrap();
    let mut checksums: serde_json::Value = serde_json::from_slice(&original).unwrap();
    checksums["target-offsets.bin"] = blake3::hash(&fs::read(offsets_path).unwrap())
        .to_hex()
        .to_string()
        .into();
    fs::write(checksum_path, serde_json::to_vec(&checksums).unwrap()).unwrap();
    assert_eq!(
        verify_cache(&report.index_directory)
            .unwrap_err()
            .diagnostic
            .code,
        "dgml.cache.structure"
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn verification_rejects_rehashed_invalid_label_fst() {
    let root = unique_temp("fst");
    fs::create_dir_all(&root).unwrap();
    let input = root.join("graph.xml");
    fs::write(&input, GRAPH).unwrap();
    let report = build_index(&input, &options(root.join("cache"), None)).unwrap();
    let path = report
        .index_directory
        .join("generations")
        .join(report.generation);
    let fst_path = path.join("labels.fst");
    let mut bytes = fs::read(&fst_path).unwrap();
    bytes[..8].copy_from_slice(&0_u64.to_le_bytes());
    fs::write(fst_path, &bytes).unwrap();
    let checksum_path = path.join("checksums.json");
    let mut checksums: serde_json::Value =
        serde_json::from_slice(&fs::read(&checksum_path).unwrap()).unwrap();
    checksums["labels.fst"] = blake3::hash(&bytes).to_hex().to_string().into();
    fs::write(checksum_path, serde_json::to_vec(&checksums).unwrap()).unwrap();
    assert_eq!(
        verify_cache(&report.index_directory)
            .unwrap_err()
            .diagnostic
            .code,
        "dgml.cache.structure"
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn rejects_ambiguous_zip_and_supports_explicit_selection() {
    let root = unique_temp("zip-selection");
    fs::create_dir_all(&root).unwrap();
    let input = root.join("graph.zip");
    let mut archive = zip::ZipWriter::new(File::create(&input).unwrap());
    for name in ["a.xml", "b.dgml"] {
        archive
            .start_file(name, zip::write::SimpleFileOptions::default())
            .unwrap();
        archive.write_all(GRAPH).unwrap();
    }
    archive.finish().unwrap();
    let cache = root.join("cache");
    assert_eq!(
        build_index(&input, &options(cache.clone(), None))
            .unwrap_err()
            .diagnostic
            .code,
        "dgml.zip.entry"
    );
    let report = build_index(&input, &options(cache, Some("b.dgml".into()))).unwrap();
    assert_eq!(report.manifest.selected_entry.as_deref(), Some("b.dgml"));
    assert_eq!(report.manifest.edge_count, 3);
    fs::remove_dir_all(root).unwrap();
}

fn options(cache_root: PathBuf, selected_entry: Option<String>) -> IndexOptions {
    IndexOptions {
        cache_root,
        memory_limit: 16 * 1024 * 1024,
        selected_entry,
        strict_hash: true,
        control: vitnet_dgml::IndexControl::default(),
    }
}

fn unique_temp(name: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!(
        "vitnet-dgml-index-{name}-{}-{nonce}",
        std::process::id()
    ))
}

fn contains_named_file(path: &Path, name: &str) -> bool {
    let Ok(entries) = fs::read_dir(path) else {
        return false;
    };
    entries.filter_map(Result::ok).any(|entry| {
        entry.file_name() == name
            || (entry.file_type().is_ok_and(|kind| kind.is_dir())
                && contains_named_file(&entry.path(), name))
    })
}

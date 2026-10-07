# NativeAOT DGML profile

`vitnet dgml stats` accepts the XML subset emitted by NativeAOT's dependency
graph writer. It processes the document with a pull parser and does not build
an XML DOM or retain labels or edges.

The expected document shape is:

```xml
<DirectedGraph xmlns="http://schemas.microsoft.com/vs/2009/dgml">
  <Nodes>
    <Node Id="0" Label="..." />
  </Nodes>
  <Links>
    <Link Source="0" Target="1" Reason="..." />
  </Links>
  <Properties>...</Properties>
</DirectedGraph>
```

NativeAOT assigns dense, zero-based decimal node IDs and writes all nodes
before links. Labels are opaque display strings; vitnet does not parse them as
a stable type or method grammar. Parallel links are counted independently.
`Reason=""` is valid for a root link. `Stroke` is only presentation data and
is not treated as a semantic category.

## Statistics

The `vitnet.dgml-stats.v1` JSON document contains:

- input byte, node, and edge counts;
- the maximum observed node ID;
- duplicate node IDs and link endpoints without a preceding node declaration;
- exact reason counts;
- an exact in-degree distribution;
- deterministic top-N node IDs by fan-in; and
- the peak memory charged to parser and aggregation state.

Rankings use descending fan-in and then ascending numeric node ID. Reason
counts use descending count and then ordinal UTF-8 bytes. The report stores
node IDs rather than labels so memory remains independent of label volume.

## Safety and resource behavior

The parser rejects DTDs and general entity references and never follows URLs or
filesystem references. It uses checked node-index arithmetic and reusable XML
buffers. Dense per-node state consists of one fan-in `u32` and one presence
bit, so memory is proportional to the maximum node ID rather than the XML file
size. `--memory-limit` is checked before growing this state.

Malformed XML and invalid/missing numeric IDs return exit code 3. A configured
memory limit returns exit code 5. The input is never modified and no cache or
temporary file is created by `stats`.

Generic DGML permits string IDs, mixed ordering, categories, and implicit
nodes. Those behaviors are intentionally outside this NativeAOT profile.

## Immutable index (`vitnet.dgml-index.v1`)

`dgml index` supports plain XML and stored/deflated ZIP members. It streams
the selected member without writing an extracted copy. Multiple candidate ZIP
members require explicit `--entry`; member paths are identifiers, never
extraction paths.

The index generation uses the layout in the versioned build plan:

| File | Encoding |
| --- | --- |
| `nodes.bin` | Numeric-ID-addressed 16-byte records: little-endian label offset `u64`, length `u32`, flags `u32`; bit 0 means present |
| `strings.bin` | Concatenated UTF-8 label bytes; node lengths delimit labels |
| `labels.fst` | FST map keys: UTF-8 label + NUL + big-endian node ID; values: numeric node IDs |
| `target-offsets.bin` | Little-endian `u64` record offsets, including the final edge-count sentinel |
| `incoming-edges.bin` | 24-byte records: source ID `u64`, reason offset `u64`, reason length `u32`, reserved flags `u32` |
| `reasons.bin` | Deduplicated UTF-8 reason bytes |
| `manifest.json` | Version, input identity, feature flags, counts, completion marker |
| `checksums.json` | Required file names mapped to lowercase BLAKE3 hashes |

CSR offsets count records, not bytes. For target ID `n`, the incoming range is
`offsets[n]..offsets[n+1]`. Empty graphs have no node or edge records and one
zero CSR sentinel. Sparse absent nodes are distinct from present empty labels.
Duplicate IDs retain the first declaration and increment
`duplicate_node_ids`; parallel links retain every record.

Missing source endpoints and holes within the declared target range count as
`unresolved_endpoints`. Targets beyond the declared maximum are rejected, not
allowed to extend the CSR table arbitrarily. Numeric IDs must be less than
`memory_limit / 8`; the minimum indexing budget is 16 MiB. XML events are
limited to `min(memory_limit / 64, 1 MiB)` before parser allocation.
Malformed roots, unclosed elements, DTD/entity events, invalid XML 1.0
label/reason characters, non-numeric IDs, and oversized records fail
explicitly without publication.

The input-specific cache key includes canonical path, input length,
modification timestamp, and selected ZIP member. The manifest adds a
length/prefix/suffix fingerprint and, with `--strict`, a full content hash.
Input identity is checked again before publication. Cache reuse is explicit;
`dgml index` always builds a new generation, even when an older one exists.
`cache verify` checks every required hash plus lengths, FST container version,
key count and root offset, node-label bounds,
presence count, monotone CSR offsets, final sentinel, and reason bounds.
Invalid/unsupported generations return a diagnostic; rebuilding is explicit.
Cache info, verification, and pruning reports respectively use
`vitnet.dgml-cache-info.v1`, `vitnet.dgml-cache-verification.v1`, and
`vitnet.dgml-cache-prune.v1`.

The format is an independent vitnet design, not an interoperability contract
with another analyzer. Outgoing-edge files, optional property sidecars, and
Phase 5 query contracts are not yet implemented.

## Requirement evidence

The focused suite is `cargo test -p vitnet-dgml`. The opt-in logical-size test
is run explicitly in release mode using the command in the README.

| Requirement | Exact test evidence |
| --- | --- |
| Immutable publication, escaped labels/reasons, duplicate-label FST keys, sorted CSR records | `builds_and_publishes_immutable_csr_generation` |
| Plain and selected ZIP ingestion | `reads_the_single_selected_zip_entry`, `rejects_ambiguous_zip_and_supports_explicit_selection` |
| Empty graphs, sparse presence, first-declaration duplicate ownership | `accepts_empty_graphs_and_marks_sparse_empty_labels_as_present` |
| Malformed/truncated XML never publishes | `malformed_build_never_publishes_current` |
| Root, attribute, sparse-ID, dangling-target, and event-size guards | `rejects_invalid_roots_sparse_ids_and_oversized_events_without_publication` |
| Cooperatively interrupted builds preserve the previous generation | `cancellation_preserves_current_and_cleans_partial_generation` |
| Input mutation prevents publication | `input_mutation_during_build_never_replaces_current` |
| Concurrent builders publish exactly one valid generation | `competing_builders_publish_exactly_one_valid_generation` |
| Writer/pruner exclusion, shared-reader safety, stale metadata recovery | `kernel_lock_excludes_builders_and_pruners_and_recovers_stale_metadata` |
| Corruption detection and pruning preservation | `verification_detects_corruption_and_prune_preserves_current` |
| Complete checksum coverage and structural CSR checks | `rejects_incomplete_checksums_and_invalid_csr_even_when_rehashed` |
| FST container validation beyond payload hashing | `verification_rejects_rehashed_invalid_label_fst` |
| Bounded merge fan-in and exact record preservation | `index::tests::bounded_multi_pass_merge_preserves_all_records` |
| Tournament selection with empty, singleton, uneven, and non-power-of-two run sets | `index::tests::tournament_merge_matches_exact_sort_for_empty_singleton_and_uneven_runs` |
| Reused merge buffers preserve shorter/empty labels and remove prior key suffixes | `index::tests::label_refill_reuses_capacity_and_removes_previous_key_suffix` |
| Packed label sorting preserves long prefixes, duplicate labels, empty labels, and UTF-8 keys | `index::tests::packed_label_sort_preserves_long_prefixes_duplicates_and_empty_labels` |
| Packed runs respect their charged budget and preserve records deferred to the next run | `index::tests::packed_label_runs_enforce_budget_without_losing_pending_records` |
| Wider merge fan-in activates at the exact large-sort-budget threshold | `index::tests::merge_fan_in_expands_only_with_a_large_sort_budget` |
| 101 GiB logical graph with exact parallel-edge count and bounded state | `index::tests::indexes_101_gib_logical_graph_with_bounded_state` |
| Optional local corpora with final ingestion guards and expected counts | `index::tests::validates_optional_local_corpus_with_final_ingestion_guards` |

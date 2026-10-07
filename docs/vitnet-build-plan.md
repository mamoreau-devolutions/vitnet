# vitnet: Clean-Room Rust Implementation Plan

## 1. Mission

Build **vitnet**, a new MIT-licensed Rust command-line tool for diagnosing size
bloat in NativeAOT artifacts.

The name combines the .NET-style command naming convention with French
**vite** ("fast"). The tool should make very large NativeAOT metadata logs,
MSTAT files, and DGML dependency graphs practical to inspect on developer
workstations without loading the complete input or graph into memory.

This is a new implementation, not a port or rewrite of Sizoscope source code.
Compatibility with Sizoscope's command-line syntax, output, cache layout, or
internal object model is explicitly not required.

### Primary goals

1. Explain where NativeAOT output size comes from.
2. Handle metadata CSV files in the hundreds of megabytes.
3. Handle MSTAT files near or beyond 1 GiB, subject to the format's real limits.
4. Index and query DGML files in the tens or hundreds of gigabytes.
5. Keep memory usage bounded and configurable.
6. Produce useful terminal, JSON, and NDJSON output.
7. Remain robust against truncated, malformed, adversarial, or partially written
   input.
8. Be usable in local development, CI, and automated optimization workflows.

### Non-goals

- Reproducing Sizoscope's GUI.
- Reproducing Sizoscope's CLI syntax or textual output.
- Reading Sizoscope cache files.
- Copying or translating Sizoscope algorithms or source.
- Supporting arbitrary DGML visualization.
- Building a general-purpose .NET decompiler.
- Providing exact final binary-size attribution where the input format only
  supplies lower bounds or partial accounting.

## 2. Licensing and Clean-Room Rules

The repository must use the **MIT License** and contain SPDX headers or a clear
repository-level license declaration.

Sizoscope is AGPL-licensed. To keep vitnet independently MIT-licensed:

1. Do not copy, translate, mechanically rewrite, or closely imitate Sizoscope
   source code.
2. Do not use Sizoscope's internal type names, file organization, cache format,
   tests, fixtures, comments, or implementation-specific output as design
   material.
3. Derive input-format knowledge from:
   - Microsoft NativeAOT/runtime producer source and documentation.
   - ECMA-335 and PE/COFF specifications.
   - Public DGML documentation.
   - Small independently generated NativeAOT artifacts.
   - Black-box observations of files produced by the NativeAOT toolchain.
4. Record the provenance of every non-obvious format decision in
   `docs/format-provenance.md`.
5. Treat existing tools only as behavioral comparators. Do not inspect their
   implementation while implementing equivalent functionality.
6. Use only MIT-, Apache-2.0-, BSD-, ISC-, Unicode-, or similarly permissive
   dependencies. Review dual-licensed crates carefully.
7. Add `cargo-deny` license/advisory/source checks in CI.
8. Preserve third-party notices when a dependency requires them.

This is an engineering plan, not legal advice. Before public distribution,
have the clean-room process and dependency license report reviewed by someone
responsible for licensing.

## 3. Product Shape

The executable is `vitnet`. Commands are grouped by input family.

```text
vitnet metadata <metadata.csv> [options]
vitnet mstat summary <file.mstat|file.zip> [options]
vitnet mstat diff <before> <after> [options]
vitnet dgml index <graph.dgml.xml|graph.zip> [options]
vitnet dgml stats <graph-or-index> [options]
vitnet dgml search <graph-or-index> <query> [options]
vitnet dgml why <graph-or-index> <query> [options]
vitnet cache info|verify|prune <path> [options]
```

The first implemented and first-class command is `vitnet metadata`.

### Global options

```text
--format table|json|ndjson
--output <path>
--memory-limit <bytes|MiB|GiB>
--temp-dir <path>
--threads <n>
--progress auto|always|never
--color auto|always|never
--quiet
--verbose
--strict
```

All byte totals use unsigned 64-bit integers internally. Signed 128-bit
intermediates are used for diffs so subtraction cannot overflow.

## 4. First Command: `vitnet metadata`

### Purpose

`vitnet metadata` identifies what makes a NativeAOT reflection/stack-trace
metadata blob large. It reads the metadata CSV/log emitted by the NativeAOT
compiler when metadata logging is enabled.

It must work even when compilation failed before producing an MSTAT or final
binary.

### Initial syntax

```text
vitnet metadata app.metadata.csv
vitnet metadata app.metadata.csv --top 50
vitnet metadata app.metadata.csv --assembly RemoteDesktopManager.Core
vitnet metadata app.metadata.csv --group assembly,namespace,type,kind
vitnet metadata app.metadata.csv --strings
vitnet metadata app.metadata.csv --format json
vitnet metadata before.csv --compare after.csv
```

### Required analyses

1. Total observed metadata size.
2. Record count.
3. Size and count by record kind.
4. Size by owning assembly.
5. Size by namespace.
6. Size by type.
7. Largest individual strings.
8. Data not attributable to a type definition.
9. Duplicate-handle resolution.
10. Offset-wrap detection and unwrapping.
11. NativeAOT metadata-limit reporting.
12. Optional before/after comparison.

### Semantic requirements

- Parse quoted CSV fields correctly, including commas, escaped quotes, and
  multiline values.
- Stream records. Do not construct one Rust `String` per input row.
- Use byte slices where possible; decode only fields needed by the selected
  report.
- Intern repeated assembly, namespace, type, and kind strings.
- Use deterministic output ordering: descending bytes, then ordinal name.
- Do not claim an exact final record length when the log supplies only record
  start offsets.
- If the last logged offset is above a known format limit, report:
  `over by at least N bytes`.
- If the last logged offset is at or below the limit, report that remaining
  headroom is unknown unless an exact end offset exists.
- Handle 24-bit or other producer-defined offset wrapping by reconstructing a
  monotonic logical offset. Document the inference and reject impossible
  sequences in strict mode.
- When the same metadata handle appears multiple times, associate references
  with the nearest valid owner according to the independently documented
  producer semantics.
- Bound string previews by bytes and Unicode scalar boundaries.
- Preserve raw byte counts even when input text contains invalid UTF-8. Use
  replacement characters only for display.

### Suggested report

```text
Metadata lower bound: 41,183,314 B across 1,440,352 records
NativeAOT limit:      33,554,431 B
Status:               OVER by at least 7,628,883 B

By kind
Bytes        Percent  Records  Kind
24,426,678   59.3%    566,334  ConstantStringValue
...

By assembly
Bytes        Percent  Assembly
...

Unowned metadata
Bytes        Percent  Records  Kind
...
```

### Metadata implementation strategy

Use a two-stage streaming design:

1. **Decoder stage**
   - Reads a bounded buffer from `Read`.
   - Identifies complete CSV records, including multiline quoted fields.
   - Emits borrowed field ranges into a reusable record buffer.
   - Tracks physical line and logical record numbers for diagnostics.
2. **Aggregator stage**
   - Normalizes offsets.
   - Updates owner maps and aggregates.
   - Stores only interned identifiers, numeric counters, bounded top-N heaps,
     and unresolved-handle state.

For ordinary runs, memory should grow with the number of unique owners and
handles, not with file length.

If unresolved ownership state exceeds the memory budget, spill compact records
to a temporary partition keyed by handle hash, then resolve one partition at a
time.

## 5. MSTAT Support

### Format-discovery phase

Before implementing MSTAT parsing, create an independent format specification:

`docs/formats/mstat.md`

The specification must cite:

- NativeAOT producer source locations and commit hashes.
- PE/COFF sections/directories used.
- ECMA-335 table and heap layouts used.
- NativeAOT-specific global records or payload streams.
- Version differences, including known 2.1 and 2.2 features.
- Size and offset limits imposed by the producer.
- How node IDs relate to DGML nodes, if this is producer-defined.
- Unknown fields and assumptions.

Create a tiny generator project that publishes independently controlled
NativeAOT samples containing:

- One assembly, type, method, and field.
- Generic types and method instantiations.
- Nested types.
- Frozen objects.
- Manifest resources.
- Recognized and unrecognized blobs.
- Satellite assemblies with culture.
- Identical method bodies/folding information.
- An intentionally malformed/truncated sample.

Do not begin the production parser until the small samples can be explained
byte-for-byte by the specification.

### Parsing architecture

1. Open plain files directly and ZIP entries through a streaming reader.
2. Prefer memory mapping for seek-heavy random access to plain files.
3. Never map the entire file into resident memory intentionally; rely on
   page-faulted access and bounded working sets.
4. Parse PE headers with a permissively licensed crate if it exposes every
   required checked offset. Otherwise implement a small checked PE reader.
5. Implement a focused, checked ECMA-335 metadata reader for only the tables and
   heaps required by MSTAT.
6. Keep all on-disk offsets as `u64`.
7. Validate every `offset + length` with checked arithmetic before slicing.
8. Represent metadata handles as compact typed newtypes, not pointers or object
   graphs.
9. Store row data in structure-of-arrays form:
   - sizes
   - aggregate sizes
   - owner handles
   - next-child indexes
   - string offsets
   - node IDs
10. Use numeric indexes throughout the core. Materialize display strings only
    at report boundaries.

### `vitnet mstat summary`

Required reports:

- Total accounted size.
- Assembly ranking.
- Namespace ranking.
- Type ranking.
- Member ranking.
- Blob categories.
- Owned and unowned frozen objects.
- Manifest resources.
- Method-body folding counts and estimated savings, clearly separated from
  accounted totals.
- Culture-aware assembly display.

### `vitnet mstat diff`

Required behavior:

- Structural identity independent of row numbers.
- Assembly identity includes name and culture.
- Type identity includes assembly, namespace, nesting, name, and generic shape.
- Member identity includes declaring type, name, kind, and signature shape.
- Type and method specifications use structural signatures.
- Report additions, removals, and size changes for retained identities.
- Reconcile every section to a signed overall delta.
- Report blob and unowned frozen-object changes explicitly.
- Separate folding-savings estimates from accounted content.
- Emit a machine-readable reconciliation object so CI can verify:
  `sum(section_deltas) == total_delta`.

### MSTAT performance model

- Parsing is one sequential or memory-mapped pass.
- Aggregate sizes are computed while ingesting ownership edges, not recursively
  on every query.
- Diffs use precomputed 64- or 128-bit structural fingerprints followed by
  exact comparison on hash collision.
- Avoid Rust `HashMap<String, ...>` in row-scale structures.
- Use compact open-addressing maps or a high-performance permissively licensed
  hash map after benchmarking.
- Do not build a general object model for all rows.

## 6. DGML Support

### Core constraint

A 20–100 GiB DGML file must never become an in-memory XML DOM or an in-memory
adjacency graph.

### Ingestion

Use a pull-based streaming XML parser with:

- Bounded reusable buffers.
- Entity-expansion disabled.
- DTD/external-resource processing disabled.
- Checked UTF-8 and XML escaping.
- Clear byte-offset diagnostics.
- Support for plain XML and a single selected ZIP entry.

Parse only the DGML information needed by vitnet:

- Node ID.
- Node label/name.
- Link source.
- Link target.
- Link reason/category needed for explanations.
- Optional producer attributes preserved in a compact property sidecar only
  when requested.

### Immutable disk index

Each completed index is an immutable generation directory:

```text
<cache-root>/<input-key>/
  CURRENT
  lock
  generations/
    <generation-id>/
      manifest.json
      strings.bin
      nodes.bin
      labels.fst
      target-offsets.bin
      incoming-edges.bin
      source-offsets.bin          # optional, enabled for outward queries
      outgoing-edges.bin          # optional
      reasons.bin
      checksums.json
```

Recommended logical layouts:

```text
NodeRecord:
  label_offset: u64
  label_len: u32
  flags: u32

EdgeRecord:
  other_node: u64
  reason_offset: u64
  reason_len: u32
  flags: u32
```

`target-offsets.bin` is a CSR-style offset table. Incoming edges for node `n`
occupy:

```text
incoming_edges[target_offsets[n] .. target_offsets[n + 1]]
```

This permits constant-time location and sequential paging without loading the
graph.

### Index construction

Use bounded external-memory passes:

1. Stream node declarations into compact temporary records and string runs.
2. Stream links into fixed-width temporary edge records.
3. Resolve textual IDs to numeric IDs using a disk-backed or partitioned ID
   table.
4. Partition edges by target hash/range.
5. Sort each partition by target ID, then source ID.
6. Merge partitions into final CSR files.
7. Build a compact label-search FST/trigram index.
8. Write checksums and manifest.
9. `fsync` completed files as appropriate.
10. Atomically publish `CURRENT`.

No partially built generation may become visible to readers.

### Cache identity and safety

Manifest fields:

- Canonical input path.
- Input length.
- Last-write timestamp.
- Fast prefix/suffix fingerprint.
- Full content hash when strict validation is requested.
- Parser/index schema version.
- vitnet version.
- Selected DGML entry for ZIP input.
- Node and edge counts.
- Enabled index features.
- Creation time and completion marker.

Requirements:

- Cross-process build lock.
- Stale-lock recovery with PID/start-time validation.
- Cancellation-safe temporary directories.
- Atomic publication.
- Generation reference counting or open-file safety.
- `vitnet cache verify`.
- `vitnet cache prune`.
- Rebuild on schema mismatch or failed checksum.

### `vitnet dgml stats`

Report:

- Node and edge counts.
- File and index sizes.
- In-degree distribution.
- Largest fan-in nodes.
- Category/reason distribution.
- Duplicate IDs, unresolved endpoints, and malformed records.
- Index build duration and peak RSS when available.

### `vitnet dgml search`

Search by:

- Exact node ID.
- Exact label.
- Case-sensitive or insensitive substring.
- Glob.
- Regex with explicit time/size limits.

Always page results. Default limit: 50.

### `vitnet dgml why`

Purpose: explain why a node is rooted in the NativeAOT dependency graph.

Behavior:

1. Resolve the user's query to one or more node IDs.
2. Traverse incoming edges from the indexed CSR files.
3. Use breadth-first search by default to find short root paths.
4. Keep a bounded visited set.
5. Spill visited state to disk or use a disk bitset when the node ID space is
   dense and the memory budget would be exceeded.
6. Detect cycles.
7. Return paged/limited paths.
8. Include link reasons.
9. Allow root classification rules to be selected by graph producer/version.
10. Expose safety limits:

```text
--max-depth <n>
--max-paths <n>
--max-visited <n>
--timeout <duration>
```

Never return a success-shaped empty result after an I/O, cache, or parse error.

## 7. Shared Architecture

### Proposed workspace

```text
vitnet/
  Cargo.toml
  LICENSE
  README.md
  deny.toml
  rust-toolchain.toml
  crates/
    vitnet-cli/
    vitnet-core/
    vitnet-metadata/
    vitnet-mstat/
    vitnet-dgml/
    vitnet-index/
    vitnet-report/
    vitnet-test-support/
  docs/
    architecture.md
    performance-budget.md
    format-provenance.md
    formats/
      metadata-log.md
      mstat.md
      dgml-profile.md
    adr/
  benches/
  fuzz/
  testdata/
    generated/
```

Keep format libraries independent from the CLI so they can be fuzzed and
benchmarked directly.

### Suggested crate evaluation

Evaluate current stable releases rather than pinning this plan's suggestions:

- CLI: `clap`
- Errors: `thiserror`, with `anyhow` only at the executable boundary
- Logging: `tracing`, `tracing-subscriber`
- Serialization: `serde`, `serde_json`
- CSV: benchmark `csv` against a custom borrowed streaming decoder before
  choosing
- XML: benchmark `quick-xml` or an equivalent pull parser
- Memory mapping: `memmap2`
- Parallelism: `rayon` for bounded partition work, not unbounded row fan-out
- Temporary files: `tempfile`
- Hashing: BLAKE3 for cache identity/checksums
- Label index: `fst`
- Progress: `indicatif`, disabled automatically for non-TTY output
- File locking: a small cross-platform locking crate with documented semantics
- Property testing: `proptest`
- Fuzzing: `cargo-fuzz`
- Benchmarks: `criterion` plus end-to-end wall-time/RSS scripts

Every selected dependency must pass the license policy.

### Error model

Define typed errors carrying:

- Input path.
- Optional ZIP entry.
- Byte offset.
- Logical record/row.
- Physical line where relevant.
- Expected value/range.
- Actual value.
- Recovery/rebuild guidance.

Exit codes:

```text
0 success
1 analysis completed with user-selected threshold failure
2 invalid command/options
3 malformed or unsupported input
4 I/O or cache failure
5 resource/safety limit reached
6 internal invariant failure
```

### Resource budgeting

Create a `ResourceBudget` shared service:

- Maximum resident allocation target.
- Maximum temporary disk usage.
- Maximum worker count.
- Cancellation token.
- Deadline.
- Progress counters.

Algorithms request budgeted buffers/partitions. They do not independently
allocate unbounded vectors.

Defaults:

- Memory target: min(2 GiB, 25% of physical RAM), configurable.
- Worker threads: min(logical CPUs, 8), configurable.
- Query result limit: 50.
- Bounded preview: 256 bytes.

### Output stability

Human-readable table output may evolve.

JSON output must be versioned:

```json
{
  "schema": "vitnet.metadata.v1",
  "tool_version": "...",
  "input": { },
  "summary": { },
  "sections": { },
  "diagnostics": []
}
```

Numbers representing byte counts are JSON integers, not formatted strings.

NDJSON is used for result sets that may be very large.

## 8. Performance and Correctness Requirements

### Representative corpus

Use generated fixtures in CI and optional private/local large fixtures for
performance validation.

Known local stress corpus:

```text
Metadata CSV:
C:\Users\mamoreau\.copilot\session-state\74ec4afe-a0a5-48f7-9155-87cb6f8cd5a3\files\aot-size\iter5b-patched-metadata-full-stacktraces\RemoteDesktopManager.metadata.csv
~171 MB

MSTAT:
C:\Users\mamoreau\.copilot\session-state\74ec4afe-a0a5-48f7-9155-87cb6f8cd5a3\files\aot-size\iter5b-patched-metadata-full-stacktraces\RemoteDesktopManager.mstat
~910 MB

Scan DGML:
C:\Users\mamoreau\.copilot\session-state\74ec4afe-a0a5-48f7-9155-87cb6f8cd5a3\files\aot-size\iter5b-patched-metadata-full-stacktraces\RemoteDesktopManager.scan.dgml.xml
~26.7 GB

Codegen DGML:
C:\Users\mamoreau\.copilot\session-state\74ec4afe-a0a5-48f7-9155-87cb6f8cd5a3\files\aot-size\iter5b-patched-metadata-full-stacktraces\RemoteDesktopManager.codegen.dgml.xml
~22.4 GB
```

Never commit private or oversized corpus files.

### Initial performance budgets

Budgets are acceptance thresholds, not aspirational notes:

| Operation | Corpus | Peak RSS target | Initial time target |
|---|---:|---:|---:|
| `metadata` | 171 MB CSV | <= 256 MiB | <= 10 s |
| `mstat summary` | 910 MB MSTAT | <= 1 GiB | <= 15 s |
| `mstat diff` | two ~1 GiB files | <= 2 GiB | <= 60 s |
| `dgml index` | 27 GB DGML | <= 2 GiB | <= 45 min |
| `dgml search` | completed index | <= 256 MiB | <= 1 s |
| `dgml why` first short path | completed index | <= 1 GiB | <= 5 s |

Measure on a documented reference machine. Adjust only with recorded evidence
and an architecture decision record.

### Required metrics

Every benchmark records:

- Wall-clock duration.
- User and kernel CPU time.
- Peak RSS/private bytes.
- Bytes read and written when available.
- Temporary disk peak.
- Node/edge/record counts.
- Cache hit/miss/rebuild state.
- vitnet commit and build profile.

Release/profile-guided builds are used for published performance numbers.
Debug builds are never used for large-corpus performance claims.

## 9. Testing Strategy

### Unit tests

- Checked integer arithmetic and offset ranges.
- CSV quoting/multiline parsing.
- Offset wrapping and impossible sequences.
- Duplicate-handle ownership.
- String preview truncation.
- PE headers and section ranges.
- ECMA-335 compressed integers and table indexes.
- Structural identity and hash-collision fallback.
- DGML escaping and malformed XML.
- CSR offsets and page reads.
- Cache manifest validation.
- Atomic generation publication.

### Property tests

- Decoder never panics for arbitrary bytes.
- Every accepted range lies within the input.
- Sorting is deterministic.
- Diff reconciliation always balances.
- CSR offset tables are monotonic and end at edge count.
- Encoding then decoding generated index records preserves values.

### Fuzz targets

- Metadata CSV logical-record decoder.
- MSTAT PE/metadata headers.
- ECMA-335 signature parser.
- DGML node/link parser.
- Cache manifest reader.
- Label-query parser.

Fuzz targets must have time and allocation limits.

### Integration tests

- Plain and ZIP input.
- Read-only input/cache directory failures.
- Truncated files.
- Invalid options.
- Cancellation during every index phase.
- Concurrent index builders.
- Stale locks.
- Interrupted publication.
- Corrupted cache files.
- Empty graph.
- Cyclic graph.
- Extremely high fan-in node.
- Cross-file MSTAT structural diff.

### Golden tests

Commit only independently generated tiny artifacts and versioned JSON expected
outputs. Human-readable tables should have focused assertions rather than
brittle full snapshots.

## 10. Observability

Use structured tracing spans:

```text
metadata.decode
metadata.aggregate
mstat.pe
mstat.metadata_tables
mstat.aggregate
mstat.diff
dgml.parse
dgml.resolve_ids
dgml.partition
dgml.merge
dgml.publish
dgml.query
```

At `--verbose`, report:

- Current phase.
- Input bytes processed.
- Records/nodes/edges processed.
- Current and peak tracked memory.
- Temporary bytes.
- Throughput.
- Estimated remaining work when defensible.

Do not log record contents by default; metadata strings may contain sensitive
application names or source-derived text.

## 11. Security and Robustness

- Disable XML external entities and DTDs.
- Never follow network URLs from input.
- Sanitize ZIP entry paths; never extract arbitrary paths.
- Reject ZIP bombs using compressed/uncompressed limits and streaming budgets.
- Use checked arithmetic for every file range and allocation size.
- Reject indexes with invalid alignment, counts, or checksums.
- Keep unsafe Rust out of parsers. Isolate unavoidable memory-map casts behind
  a small audited module or use explicit byte decoding.
- Add timeouts/limits to regex search.
- Ensure temporary files use restrictive permissions where supported.
- Avoid embedding absolute paths in exported reports unless requested.

## 12. Delivery Phases

### Phase 0: Repository and clean-room foundation

Deliver:

- Cargo workspace.
- MIT license.
- README mission and non-goals.
- CI on Windows, Linux, and macOS.
- `cargo fmt`, `clippy -D warnings`, tests, `cargo-deny`.
- Provenance and ADR templates.
- CLI shell with global options and versioned JSON envelope.

Acceptance:

- Clean checkout passes CI.
- Dependency licenses are allowed.
- No Sizoscope-derived source or fixtures exist.

### Phase 1: Metadata bloat analyzer

Deliver:

- Streaming CSV decoder.
- Offset normalization.
- Ownership attribution.
- By-kind/assembly/namespace/type/string/unowned reports.
- Metadata-limit semantics.
- JSON/table output.
- Comparison mode.
- Malformed-input diagnostics.

Acceptance:

- All metadata semantic requirements pass.
- 171 MB reference CSV stays within 256 MiB RSS.
- No per-row retained allocation.
- JSON schema documented as `vitnet.metadata.v1`.

### Phase 2: MSTAT format specification and parser

Deliver:

- Independent MSTAT specification with citations.
- Generated tiny fixtures.
- Checked PE and ECMA-335 readers.
- Structure-of-arrays model.
- Summary command.

Acceptance:

- Tiny fixtures explained byte-for-byte.
- Malformed/fuzzed inputs never panic.
- 910 MB reference MSTAT meets the memory target.

### Phase 3: MSTAT diff and folding analysis

Deliver:

- Structural identities/fingerprints.
- Reconciled signed diff.
- Blob/frozen-object/resource changes.
- Method-body folding report.
- JSON schema `vitnet.mstat-diff.v1`.

Acceptance:

- Reconciliation invariant always holds.
- Hash-collision tests prove exact fallback.
- Two large MSTATs fit the diff budget.

### Phase 4: DGML streaming parser and index builder

Deliver:

- Plain/ZIP streaming ingestion.
- Partitioned edge pipeline.
- Immutable index generations.
- Locking, cancellation, progress, validation.
- Stats command.

Acceptance:

- Synthetic 100+ GB logical graph can be generated and indexed with bounded
  memory.
- Interrupted builds never publish.
- Concurrent builders produce one valid generation.
- 27 GB reference DGML remains below 2 GiB RSS.

### Phase 5: DGML search and `why`

Deliver:

- Label index.
- Exact/substring/glob/limited-regex search.
- Paged incoming edges.
- Bounded BFS root-path explanations.
- Cycle diagnostics.

Acceptance:

- Queries never require loading all nodes or edges.
- High-fan-in and cyclic graphs respect limits.
- Cache failures are explicit.

### Phase 6: Hardening and public release

Deliver:

- Fuzzing campaign.
- Cross-platform packaging.
- Shell completions.
- Man pages.
- Benchmark report.
- SBOM and license report.
- Release artifacts and checksums.

Acceptance:

- No known critical/high advisories.
- All large-corpus budgets pass on the reference machine.
- Fresh users can complete the metadata tutorial in under five minutes.

## 13. First Implementation Backlog

Execute in this order:

1. Create repository/workspace and license files.
2. Add CI, formatting, linting, tests, and dependency policy.
3. Define versioned report/error types.
4. Implement byte-size and duration option parsing.
5. Implement reusable input abstraction for plain files/stdin/ZIP entries.
6. Build metadata logical-record decoder.
7. Add malformed/multiline/quoted CSV tests.
8. Document metadata log fields from producer sources.
9. Implement offset normalizer and tests.
10. Implement string interner and compact owner IDs.
11. Implement ownership attribution and spill threshold.
12. Implement aggregators and deterministic top-N.
13. Implement table and JSON reports.
14. Implement comparison mode.
15. Add criterion microbenchmarks.
16. Run the 171 MB corpus and record RSS/time.
17. Optimize only from profiles and allocation evidence.
18. Freeze `vitnet.metadata.v1`.
19. Begin independent MSTAT format specification.

## 14. Definition of Done

vitnet is successful when:

- It can identify the largest sources of NativeAOT metadata bloat from a failed
  build's metadata CSV.
- It can summarize and diff very large MSTATs without exhausting workstation
  memory.
- It can index a 20+ GiB DGML once and answer repeated searches/root-path
  queries from disk.
- Every operation has bounded memory, cancellation, progress, and explicit
  failures.
- Results are deterministic and machine-readable.
- The implementation and tests are demonstrably clean-room and MIT-compatible.

## 15. Ready-to-Paste Fresh Session Prompt

Use the following prompt in a new coding session after creating or selecting an
empty repository:

```text
Build a new Rust CLI named `vitnet` from scratch using the attached
`vitnet-build-plan.md` as the authoritative product and architecture plan.

Start with Phase 0 and Phase 1 only: repository foundation and the
`vitnet metadata` NativeAOT metadata-bloat analyzer. Do not begin MSTAT or DGML
implementation until Phase 1 is complete and benchmarked.

This must be a clean-room MIT-licensed implementation. Do not copy, translate,
or consult Sizoscope source, tests, fixtures, cache formats, or internal design.
Derive metadata-log semantics from Microsoft NativeAOT producer sources and
record citations/commit hashes in `docs/format-provenance.md`. Use only
permissively licensed dependencies and enforce that with `cargo-deny`.

Implement production-quality code, typed errors, versioned JSON output,
streaming quoted/multiline CSV parsing, offset-wrap handling, duplicate-handle
ownership, bounded previews, deterministic top-N reports, unowned metadata
reporting, exact-vs-lower-bound NativeAOT limit semantics, comparison mode,
tests, fuzz-ready parser boundaries, benchmarks, and documentation.

Treat the performance budgets in the plan as acceptance criteria. Measure
wall time and peak RSS on the supplied large metadata corpus if it is
available, but never commit that corpus. Do not retain one allocation per
input record. Finish Phase 1 end-to-end, run formatting/lint/tests/license
checks/benchmarks, and report measured results and any justified deviations
from the plan.
```

# Architecture

The workspace separates command handling, shared contracts, metadata analysis,
and stable serialization:

- `vitnet-core`: byte sizes, diagnostics, exit codes, and `ResourceBudget`.
- `vitnet-metadata`: CSV decoder, 24/25-bit offset normalization, owner-context
  propagation, interning, aggregation, comparison, and preview logic.
- `vitnet-report`: `vitnet.metadata.v1` and comparison envelopes.
- `vitnet-mstat`: checked, zero-copy PE/ECMA-335 and synthetic record-stream
  parsing for MSTAT summaries.
- `vitnet-dgml`: pull-based NativeAOT DGML statistics and bounded external-memory
  immutable graph indexing.
- `vitnet-cli`: argument validation, input selection, and report projection.

## Streaming path

`StreamingDecoder` uses a bounded `BufReader` and one logical-record buffer.
Record completion uses the producer's final-field invariant: the row ends in a
quoted list containing only hexadecimal child handles and whitespace. This is
stronger than generic CSV quote counting and accepts both canonical escaped
quotes and historical producer display names containing bare quoted phrases,
commas, and newlines. The decoder emits raw bytes and allocates only transient
row fields; it never decodes a whole file or retains a `String` per row. A
configurable logical-row limit prevents an adversarial unterminated/multiline
value from growing without bound.

`StreamingAnalyzer` consumes each decoded row immediately. It retains:

- interned unique kind and owner names;
- one compact context per referenced handle;
- aggregate counters;
- the previous record until the next start offset determines its lower-bound
  size; and
- at most `--top` string previews.

The analyzer does not retain decoded records. On the validated 171 MB corpus
with a 256 MiB budget, its conservative tracked-state charge was 176.82 MiB and
process peak working set was 156.82 MiB.
When retained state exceeds `--memory-limit`, analysis stops explicitly with
exit code 5 rather than silently dropping ownership data. Phase 1 does not
implement a disk spill format; `--temp-dir` is reserved and validated so a
future version can add one without changing the CLI.

## Ownership

Producer rows appear in record-start order. Scope, namespace, and type
definitions reference their later children. While streaming, each child handle
receives its nearest prior owner context. A later reference replaces an earlier
one; equal-position references prefer the deeper context. This gives stable
nearest/deepest duplicate-handle behavior without an object graph.

`ScopeDefinition` names identify assemblies. `NamespaceDefinition` names are
segments and are joined through parent contexts. `TypeDefinition` names are
already namespace/nesting-qualified by the producer; vitnet prefixes only the
assembly (`Assembly!Type`) to prevent cross-assembly collisions.

## Lower-bound accounting

The packed textual kind detects whether the producer used 24- or 25-bit physical
offsets. A large backwards transition starts a new matching epoch. Small
backwards transitions are rejected in strict mode. Consecutive logical starts
bound the preceding record; the last record is zero in attributable sections
because its end is unknown. Bytes before the first start are attributed to the
unowned `(metadata prefix)` category so section sums reconcile to the observed
lower bound.

## Safety boundary

Parser code forbids unsafe Rust. Checked arithmetic is used for epochs and
signed `i128` values for comparisons. Decoder and analyzer failures carry
stable codes and available path/byte/record/line context. `decode_metadata_prefix`
is the property-test and fuzz target boundary.

## DGML statistics path

`vitnet-dgml` consumes XML events through `quick-xml` with one reusable event
buffer. It rejects DTD/entity events and parses only numeric node IDs plus link
source, target, and reason attributes. No DOM, labels, or adjacency graph are
retained.

NativeAOT's dense IDs allow one presence bit and one `u32` fan-in counter per
possible node. Reasons are interned only once. Top-N fan-in is selected with a
bounded heap, while the in-degree histogram is accumulated after the stream.
All output ordering is deterministic.

## DGML index path

The index streams plain XML or one selected ZIP member into a UTF-8 label
sidecar, 16-byte node records, 24-byte temporary label records, 32-byte temporary
edge records, and a deduplicated reason sidecar. Only a node-presence bitset and
interned reason table remain in memory during ingestion. Sparse node records
carry an explicit presence flag; duplicate declarations keep the first label.
The pull reader limits each XML event before the event buffer can grow without
bound.

Labels are packed into a bounded UTF-8 arena and sorted through compact
node-ID/range records, avoiding one heap allocation per label during sorting.
No random comparisons touch a memory-mapped multi-gigabyte label file. Edges
are sorted by target, source, reason offset/length, and flags. Both pipelines
use multi-pass merges with 64 KiB per-run buffers. Merge fan-in is 16 for
small sort budgets and 128 when the sort budget is at least 256 MiB. The wider
bounded merge avoids an intermediate read/write pass when all runs fit;
the smaller-budget path retains its original buffer/handle bound.
Tournament trees update only the winning run's path rather than comparing
every head for every emitted record. Label merge heads reuse their byte
buffers, including the temporary FST key suffix, instead of allocating a new
buffer per node. The on-disk keys and records remain unchanged.
The Windows CLI selects mimalloc as its global allocator after measuring both
allocators against the full local graphs. Libraries, fuzz hosts, and other
platforms retain the system allocator; no cross-platform allocator speedup
is assumed.
Labels become an FST keyed by UTF-8 label, NUL separator, and big-endian node
ID. Incoming edges become 24-byte records with a CSR offset table. Parallel
links are preserved.

NativeAOT's pinned producer already emits numeric IDs, so the generalized
text-ID resolution/hash partition pass in the plan is unnecessary for this
profile. Generic string-ID DGML is explicitly rejected rather than guessed.
The implemented external sort partitions by bounded sorted run, not by hash.

Generation files are checksummed and synced before their build directory is
renamed. A synced temporary pointer atomically replaces `CURRENT` using
`tempfile::persist`, including on Windows. A persistent lock file holds a
kernel exclusive build/prune lock or shared inspection/verification lock.
Dropping the handle or process termination releases the lock; stale PID/start
metadata is overwritten only after successfully acquiring it. The lock file
is never unlinked, avoiding split-lock races.

Readers keep a shared cache lock for their entire operation; builders/pruners
fail explicitly if the cache is in use. This conservative policy avoids
generation deletion races without pretending to support simultaneous
publication and readers yet. Phase 5 must retain equivalent lifetime protection
for query readers.

Cancellation is checked between XML batches, sort runs, merge batches, hash
chunks, and before publication. Phase callbacks are opt-in and sent to stderr
by the CLI. RAII removes the exact uncommitted build directory on ordinary
errors/cancellation; forced process termination leaves a hidden build for
`cache prune`. Input size, modification time, and prefix/suffix fingerprint
are rechecked before publication; strict mode also repeats the full input hash.
Filesystem/I/O failures remain explicit.

### Turso evaluation

Turso is not a production dependency or a replacement for the disk index.
An isolated local prototype compares batched disk-table ingestion with the
custom sidecars; synthetic short-label measurements do not establish RDM
scalability.

At the user's suggestion, the conceptual reference was
[`devolutions/cirup@28ae91e0c5c075beddffe426b7dd512a8aca00eb`](https://github.com/devolutions/cirup/tree/28ae91e0c5c075beddffe426b7dd512a8aca00eb).
Its
[`query_backend.rs`](https://github.com/devolutions/cirup/blob/28ae91e0c5c075beddffe426b7dd512a8aca00eb/cirup_core/src/query_backend.rs)
Turso path uses an in-memory database with lazy materialization of regular
tables from retained resource vectors and chunked inserts. Its separate
[`vtab.rs`](https://github.com/devolutions/cirup/blob/28ae91e0c5c075beddffe426b7dd512a8aca00eb/cirup_core/src/vtab.rs)
virtual-table adapter is for rusqlite, not the Turso path.

Lazy SQL views over bounded query results are a useful future option, but
materializing all graph rows or retaining resource vectors would violate the
large-graph memory contract. The repository exposed no license declaration at
that revision, so no Cirup code is copied, translated, vendored, or depended
upon. Only the architectural distinction is recorded here.

## MSTAT summary path

`vitnet-mstat` maps an input read-only and validates PE sections, the CLI
metadata directory, `#~` and `#Strings`, required table widths, and synthetic
method bodies through borrowed slices. It does not create a general managed
metadata object model or retain a record per type or method.

Each of the seven MSTAT 2.2 streams is decoded with an exact opcode state
machine and aggregated immediately. Accounted totals use the compatibility
`Methods + Types + Blobs` view; the specialized RVA-field, frozen-object, and
resource streams are exposed as breakdowns without double-counting them.

## MSTAT structural diff path

Diff mode maps both inputs read-only and performs the same checked MSTAT 2.2
parse. When both arguments name the same path, one mapping is reused. Each
record-scale inventory entry contains only a 128-bit BLAKE3 fingerprint, a
borrowed identity range, checked byte and record totals, and compact source
metadata. Resource identities are the only synthesized values and combine
assembly name/culture with the exact resource name.

Inventories are sorted by fingerprint and complete identity bytes, then
duplicate identities are coalesced and merged linearly. Exact bytes are always
compared after a fingerprint match, including collision cases. Top-N output is
bounded and deterministic by absolute delta, signed delta, then identity.
Only selected display identities are allocated. Accounted section deltas are
checked against the overall signed delta before a report is returned.

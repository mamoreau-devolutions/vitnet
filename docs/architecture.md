# Phase 0/1 architecture

The workspace separates command handling, shared contracts, metadata analysis,
and stable serialization:

- `vitnet-core`: byte sizes, diagnostics, exit codes, and `ResourceBudget`.
- `vitnet-metadata`: CSV decoder, 24/25-bit offset normalization, owner-context
  propagation, interning, aggregation, comparison, and preview logic.
- `vitnet-report`: `vitnet.metadata.v1` and comparison envelopes.
- `vitnet-cli`: argument validation, input selection, report projection, and
  Phase 2-5 placeholders.

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

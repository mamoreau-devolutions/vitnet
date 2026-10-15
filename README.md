# vitnet

For component attribution, concentration, method/resource breakdowns and
batched retention evidence, see the [bloat-analysis workflow](docs/bloat-analysis.md).
To connect those bytes to dependency routes, source/generator declarations,
embedded assets and controlled native-build changes, see the
[build and source attribution workflow](docs/attribution.md).
For navigable budget diagrams, contributor/source inspection and bounded
retention graphs, use the [visual explorer](docs/explorer.md).

For nonobvious dependency, generated-code and repeated-pattern investigations,
use [evidence-backed opportunities](docs/opportunities.md). New imports preserve
typed NativeAOT tokens/signatures; new bundles expose ranked findings,
cross-stream assembly/package budgets, generator-output/trigger capture and
source-annotated retention. Unknown ownership and overlapping cohorts remain
explicit; findings are not predicted savings.

The **Investigate** tab adds connected feature footprints, XAML owner/helper
drilldowns, serializer roots/options and repetition, generic argument heat maps,
expansion costs, representative retention roots, applied reflection annotation
targets, and metadata string composition/ownership. Source capture can retain
XAML structure and parameter/return/generic-parameter annotations; older
captures keep those gaps visible. Native costs and overlapping projections
remain distinct, and product requirements remain your decision.

```powershell
vitnet --memory-limit 2GiB explore prepare .\build-index --bundle .\explorer-bundle
vitnet --memory-limit 2GiB explore browse .\explorer-bundle --open
vitnet explore export .\explorer-bundle --html .\size-report.html
```

The portable report works offline. Live browsing queries small indexed slices;
neither mode loads the whole dependency graph into the browser. **All data**
in the live report exposes every captured inventory and stored graph record
through authenticated local APIs, with nested-field and full-text pagination.
New bundles retain complete datasets independently of the bounded charts;
legacy bundles must be prepared again to recover discarded inventory rows.
New prepared reports also provide complete byte-ranked contributor/family
drilldowns, accounted-total and parent-scope proportions, recorded package
origins, a producer-grounded compiler-bucket glossary, and cancellable automatic
search continuation. The size ledger keeps physical evidence and overlapping
resource/metadata projections separate; missing measurements stay unknown.

The same prepared data is available **directly in the terminal**, without
starting a web server:

```powershell
vitnet explore summary .\explorer-bundle
vitnet explore contributors .\explorer-bundle --stream Methods --limit 25
vitnet explore datasets .\explorer-bundle
vitnet explore records .\explorer-bundle resources --filter assembly=Product.Core
vitnet explore origins .\explorer-bundle --assembly Product.Core
vitnet explore inspect .\explorer-bundle 123 --view source
vitnet explore inspect .\explorer-bundle 123 --view shape
vitnet explore inspect .\explorer-bundle 123 --view symbol
vitnet explore opportunities .\explorer-bundle
vitnet explore budgets .\explorer-bundle --dimension package
vitnet explore lenses .\explorer-bundle serializers
vitnet explore lenses .\explorer-bundle arguments
vitnet explore footprint .\explorer-bundle --assembly Product.Core --namespace Product.Models
vitnet explore cohort-retention .\explorer-bundle --ordinal 12,35 --graph codegen_index
vitnet explore retention .\explorer-bundle 456 --graph scan_index
vitnet explore explain .\explorer-bundle 123
vitnet explore guide .\explorer-bundle
vitnet explore coverage .\explorer-bundle
vitnet explore compare .\before-bundle .\after-bundle
vitnet explore glossary Metadata
vitnet explore contributors .\explorer-bundle --accounted-only --min-bytes 1MB --columns 'ordinal,size,identity'
vitnet explore datasets .\explorer-bundle --storage bundle --nonempty --contains resource
```

Terminal tables use decimal human sizes, total/parent proportions and explicit
overlap/unknown labels. Contributor and inventory searches automatically
continue bounded scan batches, keep just one page, and print generation-pinned
continuation commands. Inspection pages complete captured values rather than
silently cutting off long identities, arrays or source candidates. The existing
analyzer JSON/NDJSON schemas still expose exact raw bytes; new terminal explorer
queries use `vitnet.explorer-cli.v1`. See the
[terminal investigation workflow](docs/explorer.md#terminal-investigation).
Connected explanations combine bounded source/shape evidence and full-inspection
commands; comparisons keep missing measurements distinct from zero. Ranking
supports inclusive byte ranges and exact identity matching, while optional
columns simplify tables without changing captured records. The ten-improvement
design is versioned in [the CLI plan](docs/cli-investigation-plan.md).

`vitnet` is a clean-room, MIT-licensed Rust command-line tool for explaining
size bloat in NativeAOT artifacts. It provides bounded-memory analyzers for
NativeAOT metadata logs, MSTAT files, and very large dependency graphs.

It does not reproduce another tool's GUI, CLI, cache, object model, tests, or
implementation. It does not claim an exact final metadata size: producer
handles contain record **start** offsets, so the final record length is
unknown and all totals are explicitly lower bounds.

## Install from source

The workspace uses Rust 1.85 or newer. Windows MSVC builds also need the C
toolchain from Visual Studio Build Tools for the CLI's mimalloc allocator.

```console
cargo build --release -p vitnet-cli
target/release/vitnet --version
```

On Windows the executable is `target\release\vitnet.exe`.

## Metadata tutorial

Start with a compact overview:

```console
vitnet metadata app.metadata.csv --top 25
```

Show the largest strings and select report groups:

```console
vitnet metadata app.metadata.csv --strings --group assembly,namespace,type,kind
```

Restrict attribution to one owning assembly:

```console
vitnet metadata app.metadata.csv --assembly Product.Core --top 50
```

Drill into one exact `by_type` key and its owned strings:

```console
vitnet metadata app.metadata.csv --type "Product.Core!Product.JsonContext+<>c" --strings --preview-bytes 120
```

Type and assembly filters intersect. Filtering attribution does not alter
consecutive-record sizes or the whole-input lower bound. Namespace/type names
are already qualified by the producer, not reconstructed from repeated prefixes.

Write stable, versioned JSON:

```console
vitnet --format json --output metadata.json metadata app.metadata.csv --strings
```

Compare two logs. Deltas use signed 128-bit arithmetic:

```console
vitnet --format json metadata before.csv --compare after.csv --top 100
```

Use `-` to read a single analysis from standard input. Comparison mode requires
two file paths.

```console
Get-Content app.metadata.csv -Raw | vitnet metadata -
```

## MSTAT summary

Summarize a NativeAOT MSTAT 2.2 file using a read-only memory map:

```console
vitnet --format json --output mstat-summary.json mstat summary app.mstat
```

The `vitnet.mstat-summary.v1` report separates method bodies, GC and exception
information, types, blobs, RVA fields, frozen objects, resources, and folded
methods. `accounted_size_bytes` avoids double-counting the specialized streams
that MSTAT 2.x also includes in `Blobs`. See
[`docs/formats/mstat.md`](docs/formats/mstat.md).

Compare two MSTAT 2.2 files by stable producer identity rather than metadata
row number:

```console
vitnet --format json --output mstat-diff.json mstat diff before.mstat after.mstat --top 50
```

The `vitnet.mstat-diff.v1` report lists additions, removals, and retained
identity size changes for every accounted stream and specialized breakdown.
Its reconciliation object makes the signed accounted delta independently
checkable. Only bounded top changes are converted to display strings.

Rank contributors before choosing what to investigate:

```console
vitnet mstat top app.mstat --top 20
vitnet mstat top app.mstat --stream Methods --contains JsonContext --top 20
vitnet mstat top app.mstat --stream ManifestResources --contains Resources
```

Top mode coalesces complete producer identities, matches case-sensitive
substrings, and reports both total and matched bytes for each stream. Specialized
breakdowns overlap `Blobs`; do not add them to accounted totals. Resource names
are decoded from UTF-16 and displayed as `assembly!resource`; names/symbols
remain opaque, not speculative managed-method reconstructions.

## DGML statistics

Process a NativeAOT scan or codegen graph without building a DOM or retaining
the edge set:

```console
vitnet --format json --output graph-stats.json dgml stats app.scan.dgml.xml --top 50
```

The `vitnet.dgml-stats.v1` report includes node/edge totals, reason counts,
in-degree distribution, largest fan-in node IDs, duplicate IDs, unresolved
endpoints, and tracked peak memory. Memory is proportional to the maximum
numeric node ID, not the input byte size. See
[`docs/formats/dgml-profile.md`](docs/formats/dgml-profile.md).

## DGML disk index

Build an immutable, disk-backed index for a NativeAOT graph:

```console
vitnet --memory-limit 2GiB --progress always dgml index app.scan.dgml.xml --cache-dir graph-cache
vitnet --format json dgml index app.codegen.dgml.xml --cache-dir graph-cache
```

ZIP inputs are streamed without extraction. A ZIP with multiple `.xml`/`.dgml`
members requires `--entry <member-name>`; a ZIP with one member selects it
automatically. `--strict` additionally records a full BLAKE3 input hash.

The report names the input-specific **index directory** inside `graph-cache`.
Use that directory, not the cache root, for maintenance:

```console
vitnet cache info <index-directory>
vitnet cache verify <index-directory>
vitnet cache prune <index-directory>
```

Verification checks all required payload hashes, record shapes, node presence,
and CSR offsets. Pruning removes interrupted builds and superseded generations
while preserving `CURRENT`. Competing builds, verification, and pruning are
protected by operating-system file locks. Ctrl+C cancels an index build
cooperatively without publishing a partial generation.

Indexing uses packed label arenas, reusable merge buffers, and tournament-tree
selection rather than an in-memory graph or a multi-gigabyte label mapping.
There are at most 128 merge inputs when the sort budget is at least 256 MiB,
or 16 for smaller budgets. Indexing needs at least 16 MiB of
configured memory and enough free disk for the old generation, new generation,
and temporary runs. `temporary_bytes` reports temporary data remaining at
successful completion (zero), not peak disk consumption. Numeric IDs are
bounded relative to the memory budget to reject pathological sparse CSR
allocations. Labels/reasons must contain valid XML 1.0 text.
The Windows CLI uses mimalloc, selected by full-corpus throughput measurements;
other platforms retain their system allocator. Index formats are unchanged.
See [`docs/performance-budget.md`](docs/performance-budget.md) for measured
strategy comparisons and their limitations.

## Bounded graph investigation

Use the existing input-specific index directory, not XML or the cache root:

```console
vitnet dgml search <index-directory> JsonContext --limit 10
vitnet dgml search <index-directory> JsonContext --mode prefix --ignore-case
vitnet dgml search <index-directory> 12345 --mode id
vitnet dgml why <index-directory> 12345 --max-depth 32 --max-visited 50000
```

Search matches complete labels and truncates only previews. Results are ordered
by numeric ID. `limit`, `max_scanned`, or `timeout` results include a resumable
`--after-id` cursor and `--generation` token; `complete` means the search reached
the end. Defaults inspect at most five million slots in 30 seconds; raise
`--max-scanned` explicitly for a whole-index search. Labels are scanned through
bounded buffers, never loaded into an in-memory FST or graph.

Why returns shortest incoming BFS witnesses with the original edge reasons.
Depth, visited-node, examined-edge, path, and timeout caps are explicit; partial
results name their stopping condition. Root names are arbitrary producer labels.
An empty-reason edge follows NativeAOT's root convention; a zero-in-degree node
alone is only a candidate. Conditional `Primary`/`Secondary` links encode
conjunctions, so a single path does not prove one condition sufficient. Fan-in
and reachability are evidence, not byte-savings estimates.

An optional Windows foreground daemon retains up to two bounded graph sessions:

```console
vitnet --memory-limit 256MiB daemon serve --pipe vitnet-local
vitnet daemon status --pipe vitnet-local
vitnet --daemon vitnet-local dgml search <index-directory> JsonContext --limit 10
vitnet --daemon vitnet-local dgml why <index-directory> 12345
vitnet daemon stop --pipe vitnet-local
```

Run `serve` in a separate terminal; the CLI never silently starts a service.
HTTP travels only over a local Windows named pipe, not a TCP listener. Queries
remain bounded; the daemon retains file readers and generation locks, not
multi-gigabyte graph data. Requests are capped at 1 MiB and responses at 16 MiB;
connect/read/request deadlines and a bounded serialized worker prevent
unbounded client/job queues. Stop it before rebuilding or pruning an index it
holds. Query memory limits come from `daemon serve`; a client's global memory
option does not resize the running server. Index paths are resolved on the
client so the daemon may run from a different directory.
Standalone commands remain available on other platforms. See
[`docs/dogfooding.md`](docs/dogfooding.md) for the five-step analysis workflow.

For a compact interpreted cross-input report:

```console
vitnet bloat --metadata <metadata.csv> --mstat <image.mstat> --brief
vitnet --format json bloat --metadata <metadata.csv> --mstat <image.mstat> --brief --rules <rules.json>
```

The brief separates additive streams from overlapping evidence, quantifies
method auxiliary costs, top-list coverage, resource cultures, cohort overlaps
and predicate gaps, and supplies bounded contributor follow-up argument arrays.
Density/auxiliary rerankings apply only to displayed source candidates, not
global rankings or proven removable bytes. It uses the independent
`vitnet.bloat-brief.v1` schema. Its additive `investigation` section
(`vitnet.bloat-investigation.v1`) also shows exact blob buckets, dehydration
accounting limits, diagnostic artifact bytes, full method-size bands, visible
assembly/culture consolidation, repeated resource-name clues, directional
cohort overlap, per-stream unmatched bytes, optional literal spelling hints,
and proven 80/90/95% coverage prefixes.

Existing report fields retain their meaning; MSTAT insights add blob detail,
Methods add full-population bands, and Cohorts add once-counted stream unions.
All CLI selectors and starter rules remain generic.

To correlate accounting with build, dependency, source, generator, resource,
native-image, and immutable graph evidence, first collect a versioned local
bundle and import it into an immutable attribution index:

```console
dotnet tools\vitnet-evidence\bin\Debug\net10.0\vitnet-evidence.dll --output evidence.json --source-root D:\work\sample --binlog D:\work\sample\build.binlog --assets D:\work\sample\obj\project.assets.json --assembly D:\work\sample\bin\Release\net10.0\Sample.dll --mstat D:\work\sample\Sample.mstat
vitnet attribution import evidence.json --index sample.attribution
vitnet attribution report sample.attribution --top 30
vitnet attribution source sample.attribution Sample_Project_Widget__Run
vitnet attribution explain sample.attribution 12345 --graph scan_index
vitnet attribution compare before.attribution after.attribution --top 30
vitnet attribution verify sample.attribution
```

The optional .NET collector only reads existing local artifacts; it does not
build the analyzed project, execute generators, load application assemblies, or
run the application. The Rust CLI does not require .NET once evidence has been
collected. Name-derived ownership remains a candidate, explicit mappings retain
their evidence basis, generator output bytes are not generator DLL size,
resource inventories overlap containers, and graph reachability is not runtime
execution or a savings estimate. See
[`docs/evidence-collector.md`](docs/evidence-collector.md) and
[`docs/attribution-plan.md`](docs/attribution-plan.md).

Useful global controls include:

- `--memory-limit 256MiB` bounds retained analysis state and the largest
  logical CSV/XML record. Integer sizes accept bytes, decimal KB through EB
  and binary KiB through EiB; 1 MB is 1,000,000 bytes, not 1 MiB.
- `--temp-dir <path>` selects the DGML cache root when `--cache-dir` is absent;
  otherwise indexes default to `.vitnet-cache` beside the input. Metadata
  analysis still has no disk spill.
- `--threads <n>` sets the worker ceiling used by shared resource policy.
- `--strict` rejects malformed quoting and backwards offsets that cannot be
  explained by a 25-bit rollover; DGML indexing records a full input hash.
- `--progress auto|always|never` controls DGML index phase messages on stderr;
  `--quiet` suppresses them.
- `--format table|json|ndjson` selects human, stable document, or streaming
  machine output.

Malformed input exits with code 3, I/O failures with 4, resource-limit failures
with 5, and internal invariants with 6. Invalid CLI options use code 2.

## Output semantics

- `metadata_lower_bound_bytes` is the observed whole-input lower bound.
- `producer_offset_bits` records whether the log used the legacy 24-bit or
  current 25-bit packed-handle layout.
- `selected_lower_bound_bytes` is the attributed lower bound after assembly/type
  filters.
- `record_count` is the selected record count;
  `observed_record_count` is the whole-input count.
- The prefix before the first record start is reported as unowned
  `(metadata prefix)`.
- Invalid UTF-8 is preserved for byte accounting and replaced only in bounded
  display previews.
- Rankings are deterministic: descending bytes, then ordinal UTF-8 display
  name.

The JSON contract is documented in
[`docs/formats/metadata-json-v1.md`](docs/formats/metadata-json-v1.md).

## Development

```console
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace
cargo bench -p vitnet-metadata --bench metadata_decoder
cargo deny check
cargo deny --manifest-path fuzz/Cargo.toml check
```

Fuzz targets for metadata, MSTAT, and DGML parser boundaries are under `fuzz/`
and can be run with `cargo fuzz run metadata_decoder`, `mstat_summary`, or
`dgml_stats` after installing `cargo-fuzz`.
Compilation-only validation uses
`cargo check --manifest-path fuzz/Cargo.toml --bins`. On Windows MSVC,
linking fuzz executables also requires the `/include:main` linker argument,
which `cargo-fuzz` supplies. Unsanitized, uninstrumented executable smoke
checks are not a coverage-guided fuzzing campaign.
CI compiles these boundaries and enforces dependency policy for both the
workspace and the separate fuzz package, including libFuzzer's permissive
NCSA license.

Bounded numeric-ID/label search and root witnesses are implemented. Regex/glob
search, outgoing adjacency, and whole-graph size/savings attribution are not.

The opt-in 101 GiB logical-graph benchmark generates its input in memory a
record at a time; no 101 GiB fixture is stored:

```console
cargo test --release -p vitnet-dgml --lib indexes_101_gib_logical_graph_with_bounded_state -- --ignored --nocapture
```

See [`docs/vitnet-build-plan.md`](docs/vitnet-build-plan.md) for the phased
roadmap and [`docs/format-provenance.md`](docs/format-provenance.md) for the
clean-room evidence behind format decisions.

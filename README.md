# vitnet

`vitnet` is a clean-room, MIT-licensed Rust command-line tool for explaining
size bloat in NativeAOT artifacts. It provides bounded-memory analyzers for
NativeAOT metadata logs, MSTAT files, and very large dependency graphs.

It does not reproduce another tool's GUI, CLI, cache, object model, tests, or
implementation. It does not claim an exact final metadata size: producer
handles contain record **start** offsets, so the final record length is
unknown and all totals are explicitly lower bounds.

## Install from source

The workspace uses Rust 1.85 or newer.

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

Indexing uses bounded sort runs and at most 16 merge inputs at a time, not an
in-memory graph or a multi-gigabyte label mapping. It needs at least 16 MiB of
configured memory and enough free disk for the old generation, new generation,
and temporary runs. `temporary_bytes` reports temporary data remaining at
successful completion (zero), not peak disk consumption. Numeric IDs are
bounded relative to the memory budget to reject pathological sparse CSR
allocations. Labels/reasons must contain valid XML 1.0 text.

Useful global controls include:

- `--memory-limit 256MiB` bounds retained analysis state and the largest
  logical CSV/XML record.
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
- `selected_lower_bound_bytes` is the attributed lower bound after an assembly
  filter.
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

DGML search/why remain stable placeholders for Phase 5. Index building,
statistics, and cache maintenance are implemented.

The opt-in 101 GiB logical-graph benchmark generates its input in memory a
record at a time; no 101 GiB fixture is stored:

```console
cargo test --release -p vitnet-dgml --lib indexes_101_gib_logical_graph_with_bounded_state -- --ignored --nocapture
```

See [`docs/vitnet-build-plan.md`](docs/vitnet-build-plan.md) for the phased
roadmap and [`docs/format-provenance.md`](docs/format-provenance.md) for the
clean-room evidence behind format decisions.

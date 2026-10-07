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

Useful global controls include:

- `--memory-limit 256MiB` bounds retained analysis state and the largest
  logical CSV/XML record.
- `--temp-dir <path>` validates the directory reserved for future spill/index
  work.
- `--threads <n>` sets the worker ceiling used by shared resource policy.
- `--strict` rejects malformed quoting and backwards offsets that cannot be
  explained by a 25-bit rollover.
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
```

Fuzz targets for metadata, MSTAT, and DGML parser boundaries are under `fuzz/`
and can be run with `cargo fuzz run metadata_decoder`, `mstat_summary`, or
`dgml_stats` after installing `cargo-fuzz`.

`vitnet mstat diff` and DGML index/search/why expose stable placeholders and
return typed unsupported-input diagnostics. They require the structural MSTAT
identity and immutable external-memory DGML index phases in the roadmap.

See [`docs/vitnet-build-plan.md`](docs/vitnet-build-plan.md) for the phased
roadmap and [`docs/format-provenance.md`](docs/format-provenance.md) for the
clean-room evidence behind format decisions.

# vitnet

`vitnet` is a clean-room, MIT-licensed Rust command-line tool for explaining
size bloat in NativeAOT artifacts. Phase 1 provides a bounded-memory analyzer
for the metadata CSV produced by `NativeMetadataWriter`.

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

Useful global controls include:

- `--memory-limit 256MiB` bounds retained ownership and aggregation state and
  the largest logical CSV record.
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

The fuzz-ready decoder target is under `fuzz/` and can be run with
`cargo fuzz run metadata_decoder` after installing `cargo-fuzz`.

`vitnet mstat` and `vitnet dgml` expose stable Phase 2-5 command placeholders
and return a typed unsupported-input diagnostic. No MSTAT or DGML parser is
implemented in Phase 0/1.

See [`docs/vitnet-build-plan.md`](docs/vitnet-build-plan.md) for the phased
roadmap and [`docs/format-provenance.md`](docs/format-provenance.md) for the
clean-room evidence behind format decisions.

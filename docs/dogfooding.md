# Five bloat-analysis dogfooding iterations

These iterations used the authorized local RDM metadata CSV, MSTAT and both
prebuilt DGML indexes. Private inputs, graph labels, generated reports and
indexes remain outside Git. The examples use synthetic product names.

| Iteration | Tried / deficiency | Improvement / retry |
| --- | --- | --- |
| 1 | Top metadata types identified generated helpers, but namespace prefixes repeated and individual helpers could not be isolated. | Intern producer-qualified namespaces directly; add exact `--type` and bounded `--preview-bytes`. One helper owned 2,877,107 B, including 1,776,236 B in 42,625 string records, without changing the 41,183,314 B whole-input lower bound. |
| 2 | MSTAT summary totals did not say which identities contributed bytes. | Add `mstat top`, exact stream selection and full-identity substring filtering. Largest blob categories measured 139,555,436 B and 114,657,161 B; the largest generated serializer method measured 455,641 B. Breakdown streams remain non-additive. |
| 3 | Large graph indexes existed, but searching for a size-report candidate was a placeholder. | Add bounded ID/exact/prefix/substring search with numeric cursor and generation guard. Serializer matches appeared after 1,335,093 slots in 163 ms; compiled-XAML matches after 235,150 slots in 23 ms. Full no-match scans verified all 52,181,085 codegen and 62,163,504 scan labels. |
| 4 | A graph node ID and fan-in count did not explain why generated code was retained. | Add bounded incoming BFS with original reasons and explicit root classifications. A serializer candidate traced to a `Reflection` root through a reflectable method body and relocation links: five nodes/four edges in 1 ms. Cycles, structural terminals and partial stops are not presented as proven roots. |
| 5 | Repeated tiny graph queries reopened readers; resource identities displayed interleaved UTF-16 bytes/NULs. | Add an optional bounded two-session Windows HTTP-over-named-pipe daemon, and decode/filter resource suffixes as aligned UTF-16. Resource-name filtering isolated 27,164,839 B across 18 UI-resource identities. Persistent sessions retain readers/locks, not the graph. |

## Investigation recipe

Find byte contributors first:

```console
vitnet metadata app.metadata.csv --top 20 --strings
vitnet metadata app.metadata.csv --type "Product.Core!Product.JsonContext+<>c" --strings
vitnet mstat top app.mstat --top 20
vitnet mstat top app.mstat --stream Methods --contains JsonContext
vitnet mstat top app.mstat --stream ManifestResources --contains UIResources
```

MSTAT symbols and DGML labels use producer-specific opaque displays; there is
no guaranteed cross-format identity join. Search a distinctive full symbol or
substring, inspect the returned complete-label length/preview, then use its
numeric ID:

```console
vitnet dgml search <index-directory> JsonContext --limit 10 --preview-bytes 512
vitnet dgml why <index-directory> 12345 --max-depth 32 --max-visited 50000
```

Follow a partial search using the printed `--after-id` and `--generation`.
Increase the work budget explicitly when a default five-million-slot scan does
not reach the candidate. A truncated preview still matches the full label.
For frequent tiny queries, run the daemon in another terminal:

```console
vitnet daemon serve --pipe vitnet-analysis --memory-limit 256MiB
vitnet --daemon vitnet-analysis dgml search <index-directory> JsonContext
vitnet --daemon vitnet-analysis dgml why <index-directory> 12345
vitnet daemon status --pipe vitnet-analysis
vitnet daemon stop --pipe vitnet-analysis
```

The daemon does not load MSTAT/metadata inputs or materialize DGML rows.
Generation locks remain held until LRU eviction or shutdown; stop the daemon
before rebuilding/pruning a retained index.

## What the evidence suggests

Generated serializer metadata has substantial repeated method/string
attribution, while the graph witness specifically identifies reflection
retention. Investigate generation breadth and reflection-root policy together;
do not infer that trimming one witness automatically removes its entire
attributed size.

Embedded resources are a separate large contributor. Inspect resource packages,
localized UI-resource sets and platform-specific payloads before focusing only
on method bodies. Compiled XAML population methods are another concrete code
candidate: a scan witness reached startup code through generated view registration
and an instance-method conditional dependency. That is evidence to inspect
registration breadth, not proof that a single side of the condition is sufficient.
The CSV metadata lower bound was 13 B below MSTAT's metadata blob
size on this input; that is a corpus observation, not a universal correction.

Fan-in, witnesses, and resource identities do not estimate reclaimed bytes.
Validate any production change by comparing rebuilt MSTAT/metadata outputs,
not by subtracting overlapping breakdowns or assuming one path is the only root.

## Measured boundedness

Release full-label no-match scans completed in 7.190 s (codegen) and 8.571 s
(scan), each with about 10.74 MiB peak working set and a 32 MiB configured
budget. Exact slot counts and `stop_reason: complete` were checked. The
metadata type drilldown completed in 1.438 s with 182.67 MiB peak working set.
MSTAT top completed in 2.062 s with about 1,003 MiB working set, including
read-only mapped pages, and about 234 MiB sampled private memory.

These are warm/unspecified-cache Windows measurements, not controlled
cold-cache guarantees. CLI wall time includes process startup, serialization
and sampling; report `elapsed_ms` covers the query itself. A daemon is an
optional workflow convenience: reopening tiny bounded sessions is already
cheap, so speedup must be measured rather than assumed.

The daemon retained both real graph generations at 12.17 MiB peak working set
and 12.84 MiB current private bytes after the query batch. Health recorded two
session opens and five hits. Five repeated codegen queries and scan search/why
all succeeded, with standalone/daemon report equality checked excluding
elapsed time. The first transport trial produced a response-body read error;
its exact native-I/O cause was not captured or reproduced by stress tests.
Client teardown was hardened to await bounded Hyper driver completion instead
of unconditionally aborting it. The RDM rerun completed sequential responses
and graceful shutdown before releasing graph locks; no query retries were added.

Five separate CLI process launches took 40-90 ms each with or without the
daemon. This small, warm, uncontrolled sample does **not** establish a useful
CLI speedup. The proven benefit is bounded reusable graph sessions for a
long-lived client, not keeping tens of gigabytes of data resident.

## Focused regression evidence

| Behavior | Exact evidence |
| --- | --- |
| Correct qualified names and type/string drilldown accounting | `streaming_analysis_preserves_producer_qualified_names`, `type_drilldown_preserves_record_sizes_filters_strings_and_bounds_previews` |
| Ranked/coalesced contributors, exact matching and overlapping streams | `top_identities_coalesce_sizes_filter_exact_bytes_and_mark_overlapping_streams` |
| Bounded Unicode identity display and aligned resource-string filtering | `identity_previews_bound_utf8_and_filters_respect_utf16_alignment` |
| Full-label, sparse-ID, generation/work bounds and Unicode/corruption guards | `search_pages_full_labels_by_numeric_cursor_and_handles_sparse_ids`, `search_reports_work_limits_and_rejects_generation_and_corruption`, `full_unicode_and_duplicate_labels_match_before_preview_and_cursor_bounds` |
| Reason-preserving witnesses, traversal bounds, cycles and reader lifetime | `why_preserves_reason_direction_bounds_and_reader_lifetime`, `why_terminates_cycles_and_reports_unresolved_sources` |
| Versioned CLI query composition and explicit daemon routing | `cli_search_and_why_share_versioned_ids_and_expose_partial_stops`, `daemon_option_rejects_nonquery_commands_without_silent_local_execution` |
| Sequential responses larger than 64 KiB over a unique pipe | `sequential_large_why_responses_are_delivered_completely` (100 complete successive responses), `sequential_process_why_responses_are_delivered_completely`, `sequential_cli_clients_receive_complete_why_responses` |
| Two-session reuse, bounded eviction and generation lock release | `canonical_sessions_reuse_generation_and_hold_cache_locks_until_shutdown`, `two_session_lru_evicts_the_least_recently_used_lock` |

Clean validation used `cargo test --workspace`, explicit workspace doc-tests,
`cargo clippy --workspace --all-targets --all-features -- -D warnings`,
format checks, both cargo-deny graphs, all three compiled fuzz targets, and a
release build. Native fuzz executable smoke runs were uninstrumented; they
are not a sanitizer/coverage-guided campaign. Both complete real indexes passed
normal seven-file checksum/structure verification without rebuilding.

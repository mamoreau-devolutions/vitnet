# Performance budget

The subsequent [ten-wave measurement ledger](performance-waves.md) records
candidate decisions and semantic equality after the
[ten bloat-analysis improvements](bloat-analysis.md).

## Visual explorer

The [explorer](explorer.md) was exercised against the unchanged full local
attribution cache (3,705,889 identities) and both immutable graph generations:
62,163,504 / 52,181,085 nodes and 82,043,250 / 67,938,326 edges. No graph
was rebuilt, copied into an export or loaded into browser memory.

Release measurements on the same Windows reference machine:

| Operation / artifact | Result |
| --- | ---: |
| Complete bundle preparation, three supplemental inventories, two witnesses | 20.202 s |
| Preparation peak sampled working set | 632,426,496 B (603.1 MiB) |
| Offset sidecar | 29,647,120 B |
| Snapshot JSON | 787,208 B (0.75 MiB) |
| Self-contained HTML | 893,943 B (0.85 MiB) |
| Local server readiness, including imported evidence | 1.536 s |
| Server peak / post-navigation working set | 615.5 / 258.4 MiB |
| Offline / authenticated live initial browser load | 184 / 205 ms |
| Browser JavaScript heap at end of navigation | 5,785,456 B |
| Maximum connected document elements in sampled views | 1,208 |
| Worker stress: 1,000 nodes / 5,000 cyclic edges submitted, capped to 200 / 500 | 8.8 ms |
| Main-thread interval delay during twelve expand/reset/reselect cycles, p95 / max | 10.7 / 11.0 ms |

Headless installed Edge was used at 1440x1000 and 390x844. Checks covered all
eight views, keyboard icicle zoom, offline generation-bound root paths,
authenticated bootstrap, row/source queries, exact graph ID search, incoming
and why queries, empty partial-page continuation, cancellation and stale-result
isolation. Every sampled table stayed at or below 100 rows and each graph sheet
within 200 nodes / 500 edges. The portable root-path example rendered twelve
nodes and eleven edges; a deeper selected target retained its honest
`max_depth` stop instead of fabricating a root.

Preparation was sampled at 100 ms intervals. Browser load and interval-delay
values are diagnostic warm-local samples, not cold-cache, cross-browser,
worst-case or frame-rate guarantees. The worker stress tests bounded layout,
not the paint cost of every possible 200-node sheet. Connected DOM counts
exclude detached nodes awaiting garbage collection; the reported heap is an
end-of-run value, not a browser-process peak.

Source evidence, not graph size, dominates explorer server startup memory.
Preparation reserves a bounded share for aggregate keys and fails explicitly
on excess cardinality. Live text search is limited to 100,000 records/slots
or cooperative 1.5-second checkpoints per batch; completing the whole graph
can require many continuation pages. The memory option is not an RSS cap.
Full checksum verification remains an explicit `explore verify` operation.

The final release replay passed 38 browser cases with no page/console errors.
Its refreshed HTML was 894,309 B; offline/live loads were 147/379 ms and the
twelve interaction cycles had 12.4/12.8 ms p95/maximum interval delay. Two
no-match graph pages each stopped at exactly 100,000 indexed slots, retaining
string cursors `99999` and `199999` for continuation (6/5 ms). Slots include
holes: these timings do not predict dense label-search cost. The replay also
confirmed the 1,208 connected-element bound and shut down only its own explorer.
The same warm-local and non-worst-case limitations apply to this replay.

## Bounded analysis dogfooding

Five try/improve/retry iterations are recorded in [`dogfooding.md`](dogfooding.md).
Release query measurements used the already verified full RDM index generations;
there was no XML reparse/reindex or whole-graph memory map:

| Operation | Verified scope | Wall time | Peak working set |
| --- | --- | ---: | ---: |
| Exact no-match codegen label scan | 52,181,085 slots, complete | 7.190 s | 10.73 MiB |
| Exact no-match scan label scan | 62,163,504 slots, complete | 8.571 s | 10.74 MiB |
| Metadata exact type drilldown | 1,440,352 input records | 1.438 s | 182.67 MiB |
| MSTAT top, all streams | complete compact inventory | 2.062 s | 1,003 MiB |
| Daemon after both graph sessions used | two generations retained, no graph rows | batch completed | 12.17 MiB |

Label scans used a 32 MiB budget. MSTAT top private memory was about 234 MiB;
working set includes read-only mapped corpus pages, unlike tracked heap state.
Server current private bytes after the batch were 12.84 MiB. Separate tiny-query
CLI process launches took 40-90 ms both directly and through the daemon; this
small uncontrolled warm-cache sample does not establish a CLI speedup. The
benefit demonstrated is bounded session reuse and identical query results, not
faster input indexing or bulk scans. Sampling used 10 ms intervals on the same
Windows reference machine; cache state and concurrent load were not controlled.

## Metadata foundation

Phase 1 acceptance for the private/local 171 MB metadata CSV is at most 256 MiB
peak RSS/private working set and at most 10 seconds in a release build.

Reference validation on 2026-10-07:

| Metric | Result |
| --- | ---: |
| Input bytes | 171 MB class |
| Records | 1,440,352 |
| Observed metadata lower bound | 41,183,314 B |
| Wall time | 2.284 s |
| User / kernel CPU | 2.031 s / 0.203 s |
| Peak sampled working set | 132.45 MiB |
| Conservative tracked-state charge | 176.82 MiB |
| Bytes read / written | 170,892,892 B / 52,002 B |
| Temporary disk | 0 B |
| Output | `vitnet.metadata.v1` |

The command was a release build with `--strict --memory-limit 256MiB`, JSON
output, and `--strings`. It detected the current 25-bit producer layout. The
local input and generated report are not repository fixtures. Working-set
sampling read the Windows process working-set counter at 10 ms intervals.

Reference machine: Intel Core Ultra 9 285HX (24 logical processors), 63.5 GiB
RAM, Windows 11 Enterprise 10.0.26200.

Published performance claims must use release or profile-guided builds. Run the
Criterion microbenchmark with:

```console
cargo bench -p vitnet-metadata --bench metadata_decoder
```

The current decode-and-aggregate result for 10,000 synthetic rows is
67.62-68.07 MiB/s (median 67.86 MiB/s, 7.57 ms).

## MSTAT summary

The 910,090,240-byte local MSTAT corpus was processed by a release build with
`--memory-limit 1GiB`:

| Metric | Result |
| --- | ---: |
| Wall time | 1.053 s |
| User / kernel CPU | 0.094 s / 0.062 s |
| Peak sampled working set | 57.12 MiB |
| Tracked Rust state | 64 KiB |
| Bytes read / written | 910,090,240 B / 1,767 B |
| Temporary disk | 0 B |
| Methods / types | 1,723,042 / 1,518,302 |
| Frozen / folded methods | 447,086 / 727,774 |
| Accounted size | 1,062,414,426 B |
| Output | `vitnet.mstat-summary.v1` |

The input is read through a read-only memory map, so operating-system mapped
pages and file-cache behavior are represented by process working set rather
than `peak_tracked_memory_bytes`. This result is below the 1 GiB / 15 second
MSTAT summary acceptance budget.

## MSTAT structural diff

The 910,090,240-byte local MSTAT corpus was compared with itself by a release
build using `--memory-limit 2GiB --top 50`:

| Metric | Result |
| --- | ---: |
| Wall time | 4.919 s |
| Peak sampled working set | 1,202.98 MiB |
| Conservative tracked inventory state | 425,396,246 B |
| Total / reconciled delta | 0 B / balanced |
| Added / removed / changed identities | 0 / 0 / 0 |
| Temporary disk | 0 B |
| Output | `vitnet.mstat-diff.v1` |

The identical-path case reuses one read-only mapping while independently
building and comparing both inventories. This exercises full parsing,
fingerprinting, sorting, exact identity comparison, section reconciliation,
and serialization. The result is below the plan's 2 GiB / 60 second MSTAT
diff budget. The local input and generated report are not repository fixtures.

## DGML statistics

Both private/local RDM graphs were processed by a release build with
`--memory-limit 2GiB` and `--top 50`:

| Metric | Scan graph | Codegen graph |
| --- | ---: | ---: |
| Input bytes | 26,725,172,016 B | 22,356,612,496 B |
| Nodes | 62,163,504 | 52,181,085 |
| Edges | 82,043,250 | 67,938,326 |
| Wall time | 86.524 s | 49.551 s |
| User CPU | 77.844 s | 42.344 s |
| Kernel CPU | 7.266 s | 5.969 s |
| Peak sampled working set | 253.50 MiB | 214.07 MiB |
| Conservative tracked state | 277,122,845 B | 277,099,278 B |
| Output bytes | 35,212 B | 15,113 B |
| Temporary disk | 0 B | 0 B |
| Duplicate IDs / unresolved endpoints | 0 / 0 | 0 / 0 |
| Output | `vitnet.dgml-stats.v1` | `vitnet.dgml-stats.v1` |

The parser streamed 49.1 GB of XML without a DOM, retained edge set, cache, or
temporary files. The two runs observed dense IDs (`max_id == nodes - 1`) and
three exact in-degree buckets. The DGML plan defines a 45-minute budget for the
more expensive index build; statistics currently complete in under 90
seconds.

All measurements above used 50 ms process sampling except MSTAT, which used
2 ms sampling because of its much shorter run. Reference machine: Intel Core
Ultra 9 285HX (24 logical processors), 63.5 GiB RAM, Windows 11 Enterprise
10.0.26200.

## DGML disk index

Both private/local RDM graphs were indexed completely with release builds,
`--memory-limit 2GiB`, plain XML input, and non-strict input identity checking:

| Metric | Scan graph | Codegen graph |
| --- | ---: | ---: |
| Input bytes | 26,725,172,016 B | 22,356,612,496 B |
| Nodes | 62,163,504 | 52,181,085 |
| Edges | 82,043,250 | 67,938,326 |
| Index-build wall time | 734.017 s | 914.567 s |
| Peak sampled working set | 540.44 MiB | 540.08 MiB |
| Conservative tracked state | 549,453,824 B | 549,453,824 B |
| Published index bytes | 25,493,255,913 B | 21,403,608,306 B |
| Duplicate IDs / unresolved endpoints | 0 / 0 | 0 / 0 |
| Final checksum/structure verification | 7 required files, valid | 7 required files, valid |
| Final verification wall time | 14.897 s | 11.579 s |
| Output | `vitnet.dgml-index.v1` | `vitnet.dgml-index.v1` |

Both builds meet the plan's 2 GiB / 45-minute index budget. Process working
set was sampled at 100 ms intervals. The index builds ran sequentially, but
the codegen build overlapped separate ingestion-guard and synthetic tests;
neither cold-cache state nor concurrent system load was controlled. Index
build times exclude subsequent verification/pruning. The final release CLI
verified each complete generation after rebuilding; structural validation
scans each sidecar once, not once per checksum. Pruning preserved both
published generations and removed a 36,208,748,382-byte interrupted codegen
build. Peak temporary disk usage was not measured.

The first scan implementation used random label comparisons over a large
mapping and reached 15,953.48 MiB. Replacing that path with bounded owned-label
sort runs removed the whole-file residency problem. No private input, label,
generated index, or report is a repository fixture.

### Index-throughput strategy comparison

Full-corpus release measurements on the same Windows reference machine used
the same 2 GiB budget and unchanged index schema:

| Strategy | Scan wall time | Codegen wall time | Scan peak working set | Codegen peak working set |
| --- | ---: | ---: | ---: | ---: |
| Published original bounded index | 734.017 s | 914.567 s | 540.44 MiB | 540.08 MiB |
| Packed label arenas, reusable heads, tournament merge, 16-way fan-in, system allocator | 707.265 s | 524.101 s | 535.76 MiB | 534.57 MiB |
| Same pipeline, budget-gated 128-way fan-in, system allocator | 587.347 s | 491.775 s | 535.86 MiB | 534.82 MiB |
| Same wide-merge pipeline, mimalloc 0.1.52 | 503.586 s | 417.098 s | 537.70 MiB | 536.25 MiB |
| Winning Windows CLI, final production repeat | 509.776 s | 406.102 s | 537.76 MiB | 560.59 MiB |

The mimalloc strategy won on both inputs. The final production repeat is
30.55% and 55.60% below the published scan/codegen times, respectively.
Against the same wide-merge pipeline with the system allocator, the allocator
prototype reduced time by 14.26% and 15.19%. Its peak sampled private bytes
were 546.90 MiB and 546.99 MiB; the production repeat reached 546.97 MiB and
601.85 MiB. Both private bytes and working set remained below 2 GiB.
The Windows CLI therefore selects mimalloc; other platforms retain their
system allocator because no corresponding allocator comparison was performed.
The wrapper and native allocator pass the production cargo-deny policy.

Each candidate preserved all six binary payload BLAKE3 hashes exactly:
nodes, strings, label FST, CSR offsets, incoming edges, and reasons.
Normal verification separately checked all seven required files and their
structures. Generation timestamps are intentionally excluded from old/new
payload equality. Counts, parallel edges, duplicate ownership, and index
schema are unchanged.

The wider fan-in is enabled only with at least 256 MiB of sort budget. Smaller
budgets retain 16 inputs, while 128 inputs avoid an intermediate write/read
pass when all label runs fit. Both paths have bounded file handles and
64 KiB reader buffers; tournament selection updates only one root path.
Packed labels avoid per-record allocation during sorting, and reused heads
avoid allocating a new label buffer for every merged record.

A separate generated fixed-width edge experiment compared Rust's
`sort_unstable` with a safe LSD radix sorter. Five alternating repetitions
checked exact sorted-record equality; input cloning was outside the timer,
and radix scratch allocation was inside:

| Shape / records | Comparison-sort median | Radix-sort median |
| --- | ---: | ---: |
| Random / 250,000 | 7.040 ms | 13.254 ms |
| Source-grouped / 250,000 | 7.150 ms | 12.485 ms |
| Ordered / 250,000 | 0.534 ms | 0.612 ms |
| Random / 2,000,000 | 76.487 ms | 152.329 ms |
| Source-grouped / 2,000,000 | 77.022 ms | 140.298 ms |
| Ordered / 2,000,000 | 3.477 ms | 3.529 ms |

Comparison sorting remains the production choice; radix did not win these
tests. No database backend or index-format change was introduced.

Full graph builds ran sequentially. Cold-cache state and external system load
were not controlled; the initial 16-way run overlapped short validation/build
commands. There was one full run per input/candidate followed by the winning
production CLI repeat, not a statistical
benchmark campaign, so these results establish the fastest measured option,
not an unconditional fastest algorithm. Times exclude verification/pruning,
and peak temporary disk consumption was not measured. Allocator prototypes,
measurement artifacts, and all private data remain outside the repository.

The final Windows CLI also reran the other local corpora after the global
allocator change, preserving the exact metadata totals, MSTAT accounted size,
and balanced zero-delta MSTAT self-comparison:

| Allocator regression check | Wall time | Peak working set | Peak private bytes | Budget |
| --- | ---: | ---: | ---: | ---: |
| Strict metadata, with strings | 1.789 s | 179.09 MiB | 196.48 MiB | 256 MiB |
| MSTAT summary | 1.403 s | 791.38 MiB | 13.57 MiB | 1 GiB |
| MSTAT self-diff | 4.099 s | 1,205.94 MiB | 444.66 MiB | 2 GiB |

These short checks sampled at 10 ms and include report loading in wall time.
Mapped-file residency affects MSTAT working set independently of heap:
a system-allocator summary control also reached 798.55 MiB working set,
with 6.85 MiB private bytes. No new mapped-file memory regression is inferred
from comparison with the much smaller historical summary working set.

The final ingestion guards were also exercised independently against both
full inputs: scan took 112.325 s at 19.46 MiB, and codegen took 351.271 s at
18.24 MiB. These checks assert the expected node/edge counts but do not
replace the full index-build measurements above.

## DGML logical-size acceptance

The original opt-in `indexes_101_gib_logical_graph_with_bounded_state` release test
generated 108,447,925,960 logical link bytes (just over 101 GiB) without storing
the XML input. It indexed 26,220,485 parallel edges between two declared nodes,
with a repeated 4 KiB reason:

| Metric | Result |
| --- | ---: |
| Wall time, including test-process startup/cleanup | 205.364 s |
| Index pipeline elapsed time | 205.096 s |
| Peak sampled working set | 18.57 MiB |
| Tracked ingestion state | 6,557,856 B |
| Configured ingestion memory | 64 MiB |
| Sort-run budget | 8 MiB |
| Reason sidecar | 4,096 B |
| Result | Exact edge count, CSR sentinel, sidecar size, and zero unresolved endpoints |

This deliberately tests logical stream length, reason deduplication, parallel
edge preservation, and multi-pass merging under a small memory budget. It
does not substitute for the high-cardinality RDM label/graph measurements.
The generated input is streamed through the same ingestion/sort/CSR pipeline;
publication and cache identity are tested independently with small files.
That original rerun overlapped the codegen index build. An earlier run took
143.078 s with an 18.93 MiB peak; neither run controlled cold-cache conditions.

The optimized pipeline's final-source rerun completed in 164.499 s overall
and 163.664 s inside the pipeline, with an 18.00 MiB sampled working-set peak
and 15.79 MiB private-byte peak. Logical bytes, exact edge count, CSR sentinel,
reason sidecar size, zero unresolved endpoints, and 6,557,856-byte tracked
ingestion state were unchanged. It used the library test host's system
allocator and 16-way merge under the same small budget, not the Windows CLI's
mimalloc allocator. No other full graph index ran concurrently; short build/
validation commands did overlap. High-cardinality labels and the wider merge
are covered by the complete RDM runs instead.

## Isolated Turso experiment

Turso 0.8.2 was evaluated only in local session artifacts, not as a workspace
dependency. Synthetic labels were short generated names, and edge targets
were distributed across generated nodes:

| Strategy | Nodes | Edges | Wall time | Peak working set |
| --- | ---: | ---: | ---: | ---: |
| One transaction, indexes afterward | 100,000 | 1,000,000 | 2.888 s | 206.66 MiB |
| One transaction, indexes afterward | 1,000,000 | 10,000,000 | 32.641 s | 1,788.71 MiB |
| Precreated indexes, 100,000-row transactions, 64 MiB page cache | 1,000,000 | 10,000,000 | 301.322 s | 399.56 MiB |

The bounded-batch run checked exact table counts and a limited incoming-edge
query. Its database was 513,101,824 B and its remaining WAL was 492,327,672 B.
Thus batching substantially reduced observed memory at a significant ingestion
cost. No RDM graph was ingested into Turso, no checkpoint/reopen/crash campaign
was completed, and these timings are not directly comparable to the logical
stream test above. The custom disk index remains the production backend.
Synthetic results are not extrapolated into a large-corpus performance claim.

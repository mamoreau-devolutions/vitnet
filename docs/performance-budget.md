# Performance budget

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

The final ingestion guards were also exercised independently against both
full inputs: scan took 112.325 s at 19.46 MiB, and codegen took 351.271 s at
18.24 MiB. These checks assert the expected node/edge counts but do not
replace the full index-build measurements above.

## DGML logical-size acceptance

The opt-in `indexes_101_gib_logical_graph_with_bounded_state` release test
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
The final rerun overlapped the codegen index build. An earlier run took
143.078 s with an 18.93 MiB peak; neither run controlled cold-cache conditions.

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

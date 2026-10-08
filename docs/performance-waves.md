# Ten measured optimization waves

This follows the ten analysis improvements in [bloat analysis](bloat-analysis.md).
All functionality was implemented and exercised before optimization. Release
executables and raw reports were saved outside Git. Measurements compare
non-metric report fields exactly, not merely exit status or top-row lengths.
No private corpus or index data is committed.

The reference machine and corpus sizes are in [performance budget](performance-budget.md).
CLI figures below are medians of three sequential process launches. Working-set
and private-byte samples used 10 ms intervals. These are warm/unspecified-cache
comparisons on Windows, not isolated cold-cache or controlled-load claims.
Only timing and tracked-memory instrumentation were excluded from semantic
comparisons. Exact slot counts, generation, counts, complete identity ties,
selected rows, truncation flags and all accounting fields were retained.

## Graph waves

| Wave | Candidate | Before -> after | Decision |
| --- | --- | --- | --- |
| 1 | Reuse one complete-label byte buffer | Codegen no-match 6.448 -> 6.425 s; serializer count 11.179 -> 11.614 s | No independent win; kept only as enabling storage for wave 2 |
| 2 | Borrow case-sensitive text/query instead of allocating per label | Codegen 6.425 -> 5.689 s; serializer 11.614 -> 10.716 s | Retained with buffer reuse; full reports unchanged |
| 3 | Amortize soft-deadline clock reads over at most 64 slots | Codegen 5.689 -> 4.708 s; scan 7.224 -> 5.910 s | Retained; exact work caps and real 1 ms stop/cursor checked |
| 4 | Compare 64/256/1024 KiB label readers; keep other readers 64 KiB | Codegen 4.708 -> 4.399 -> 4.157 s; scan 5.910 -> 5.615 -> 5.289 s | Selective 1 MiB readers retained; about 12.9 MiB peak working set |
| 5 | Preserve buffered CSR offsets with relative addressing | Five-million-slot String fan-in 3.456 -> 0.455 s; complete serializer count 9.430 -> 8.523 s | Retained; eliminates repeated buffer-discarding seeks |
| 6 | Reuse contiguous edge cursor | In-process incoming 10,000 edges 89.215 -> 43.251 ms; bounded Why fan-in 58.191 -> 1.690 ms | Retained; -51.5% / -97.1% in synthetic Criterion workload |

Full codegen/scan no-match workloads scan exactly 52,181,085 / 62,163,504 numeric
slots. The serializer workload completely scans codegen and counts 145,185
matches. String fan-in intentionally scans a five-million-slot prefix and
returns `max_scanned`, not a global ranking. Its report is compared exactly
before/after each relevant change.

Wave 6's Criterion fixture is independently generated: 10,000 parents plus
root/target nodes and 20,000 links. Incoming returns all 10,000 edges; Why has
a shared-root DAG and examines 12,000 edges under its cap. Generation, real RDM
incoming/batch results and exact accounting were preserved. Tiny separate CLI
launches remain startup/scheduling dominated; no transport or tiny-query speedup
is claimed from their noisy 40-90 ms readings.

```console
cargo bench -p vitnet-dgml --bench queries -- --save-baseline before
cargo bench -p vitnet-dgml --bench queries -- --baseline before
```

Search deadlines remain soft and are checked before at most 64 slots. Bounded
reads, filesystem I/O and output projection are not preemptible. CSR and edge
relative-position caches are invalidated before fallible I/O, so an error cannot
leave a guessed cursor to reuse.

## MSTAT waves

| Wave | Candidate | Before -> after | Decision |
| --- | --- | --- | --- |
| 7 | Retain only the requested top-list stream while validating every stream | Methods top 20: 2.115 -> 1.222 s; sampled private peak 234.23 -> 93.79 MiB | Retained; full summary and unselected-stream validation preserved |
| 8 | Deterministic bounded heap rather than repeatedly sorting retained rows | Methods top 10,000: 75.987 -> 1.265 s; top 20: 1.222 -> 1.228 s | Retained for large-top win; neutral for small top |
| 9 | Compile reusable binary literal finders with aligned, overlapping UTF-16 matching | Six-rule combined insights: 27.274 -> 6.715 s | Retained CPU win; sampled private peak increased 825.14 -> 841.14 MiB |
| 10 | Compute typed scoped projections for existing insight commands | Six-rule Methods: 27.907 -> 1.521 s; sampled private peak 825.15 -> 185.96 MiB | Retained; complete input/options validation and identical CLI payload |

MSTAT figures use the complete 910,090,240-byte RDM input. Wave 8's large-top
comparison includes wave 7's focused retention, so its approximately 60x
end-to-end gain is not attributed to heap selection alone. Wave 10 uses its own
three-run Methods baseline, not the top-list or combined-insights workload.
It is approximately 18.3x faster. Methods, Resources, Generics and Cohorts
now use typed focused projections rather than computing unrelated siblings;
combined insights and bloat still compute their complete reports.

Working-set medians include mapped input pages and differ from sampled private
memory: wave 7 top-20 working set fell 1003.27 -> 879.13 MiB; wave 8 top-10,000
fell 1005.66 -> 881.37 MiB; wave 9 remained approximately 1437.4 MiB; and wave 10
Methods fell 1437.45 -> 971.25 MiB. These are observed process measurements,
not promises that resident memory is bounded by the allocation budget.

Exact semantic hashes match before/after for each workload. Matching still
uses complete opaque identities, respects UTF-16 code-unit alignment, and
permits overlapping literal hits. Heap order preserves complete identity ties,
coalescing, filters and insertion-order independence. Scoped projections do
not fabricate empty unused reports and validate even rules they do not use.

| Invariant | Regression |
| --- | --- |
| Focused inventory preserves hidden-stream validation | `focused_top_keeps_complete_summary_and_unselected_checked_validation` |
| Heap selection equals exact ranking | `bounded_heap_matches_exact_order_at_every_limit_and_insertion_order`; `top_heap_matches_full_exact_sort_with_ties_coalescing_and_filters` |
| Binary/UTF-16 predicate semantics | `compiled_literal_matching_preserves_binary_and_aligned_overlapping_hits` |
| Scoped results equal combined payloads | `focused_projections_equal_combined_payloads_with_complete_summaries` |
| Unused rules and shared limits remain checked | `focused_projections_validate_unused_rules_and_shared_option_limits` |

## Artifact ledger

`feature0-*-1..3.json` and `feature0-measurements.json` contain the pre-optimization
reports and measurements. `wave01` through `wave06` reports/measurements and
saved release executables preserve each candidate. Criterion baselines live
under ignored `target/criterion`; the benchmark source is versioned.
`mstat-waves07-10-ledger.json`, `wave10-focused-ledger.json` and
`wave10-focused-combined-equality.json` record the remaining waves, including
three-run memory/time measurements and complete non-metric report hashes.
An earlier generic-family range candidate is archived separately and is not
counted as an eleventh wave or as evidence for the scoped-projection speedup.

## Final release verification

The final release repeated twelve complete/bounded workloads three times each.
All 36 reports matched their original non-metric baselines, including full
metadata/MSTAT accounting, both complete graph scans, incoming and shared-budget
batch results. Final medians are end-to-end observations, not isolated candidate
measurements:

| Workload | Feature baseline -> final release |
| --- | --- |
| Complete codegen no-match scan | 6.448 -> 4.463 s |
| Complete scan no-match scan | 7.709 -> 5.521 s |
| Bounded five-million-slot String fan-in | 3.435 -> 0.519 s |
| Complete serializer label count | 11.179 -> 8.917 s |
| Methods top 10,000 | 75.987 -> 1.426 s |
| Combined six-rule insights | 27.274 -> 5.958 s |
| Combined bloat overview | 31.351 -> 8.433 s |
| Scoped Methods with six rules | 27.907 -> 1.800 s |

Metadata cohort analysis was not optimized in these waves: its observed median
changed 1.683 -> 2.486 s. Small incoming/batch process launches remain noisy;
no independent improvement is claimed for them. Final combined insights used
approximately 1241.85 MiB working set and 474.73 MiB sampled private peak;
scoped Methods used approximately 971.25 / 186.00 MiB respectively.

`cargo fmt --all -- --check`, strict all-target/all-feature workspace Clippy,
`cargo test --workspace` (153 passed, two opt-in tests ignored), workspace
doc-tests, root/fuzz `cargo deny check`, fuzz-target checking/native compilation
and the release build passed. Each native fuzz executable completed 1,000
uninstrumented smoke runs; these are not sanitizer/coverage-guided campaigns.
All four focused MSTAT commands passed JSON/NDJSON/table checks against the
complete combined corpus projection. Both real immutable indexes passed
seven-file checksum/structure verification (21,403,608,306 and 25,493,255,913
index bytes); neither index was rebuilt.

## Additional optimization series

The next series starts from the verified release above. Each wave saves its
own executable and three-repeat reports outside Git. Candidates must preserve
every non-metric field; a rejected experiment still records its evidence and
does not remain in production.

| Wave | Candidate | Before -> after | Decision |
| --- | --- | --- | --- |
| 1 | Compile one reusable label substring finder | Complete serializer count 8.917 -> 4.491 s; 12.98 MiB working set | Retained; full UTF-8 validation and Unicode lowering preserved |
| 2 | Project only candidates that enter the bounded graph top list | Five-million-slot fan-in, top 1,000: 0.889 -> 0.510 s | Retained for larger-top win; small-top/serializer launches were noisy and are not independent wins |
| 3 | Binary-insert qualifying fan-in candidates instead of re-sorting | Same top-1,000 workload 0.510 -> 0.432 s | Retained; ordinal-ID ties and exact total counts preserved |
| 4 | Cache the retained metadata string byte charge | Metadata cohort top 1,000: 2.498 -> 2.082 s | Retained; removes per-record rescanning of retained previews |
| 5 | Incrementally select metadata strings with bounded binary insertion | Same top-1,000 workload 2.082 -> 1.651 s; unfiltered metadata 1.770 -> 1.548 s | Retained; matches full stable sorting at all tested limits/ties |
| 6 | Memoize the last resolved ownership-context filter result | Top 1,000: 1.651 -> 1.581 s; unfiltered metadata 1.548 -> 1.684 s | Rejected; weak filtered gain with a worse unfiltered observation does not justify the added cache |
| 7 | Bounded heaps for insight lists/groups/examples | Insights 5.442 -> 6.361 s; overview 7.209 -> 8.094 s | Rejected and reverted; exact heap-equivalence regressions retained |
| 8 | Fuse cohort counting and example selection in one predicate pass | Insights 5.625 -> 3.982 s; overview 8.026 -> 6.405 s | Retained; gain confirmed with alternating executable pairs |
| 9 | Compile exact top-entry literal finders once | Filtered top 20: 1.602 -> 1.253 s; filtered top 10,000: 1.646 -> 1.309 s | Retained; aligned UTF-16/resource-prefix semantics preserved |
| 10 | Fuse method totals/filtering/selection | Filtered Methods 1.790 -> 1.769 s; combined insights 4.658 -> 5.127 s | Rejected and reverted; negligible scoped gain with worse combined observation |

The larger graph workload scans exactly five million numeric slots, preserves
`max_scanned`, and is not a global ranking. Metadata string selection preserves
descending bytes, ordinal preview ties, logical offsets and stable insertion
ties. Its cached byte charge matches the retained entries exactly, including
replacement and zero-top cases. Metadata working-set peaks remained about
179 MiB unfiltered and 183 MiB for the selected top-1,000 workload.

`prepared_contains_preserves_unicode_lowering_and_complete_label_validation`,
`complete_counts_and_fan_in_rank_are_not_display_limited`,
`streaming_string_selection_equals_full_sort_at_all_limits_and_ties`, and
`selection_distinguishes_repeated_changed_and_unowned_contexts` record these
invariants. `morep01` through `morep06`, `morep02-*-large`, `morep03-large` and
`moremeta-before` artifact prefixes preserve measurements and exact reports.
The rejected wave-6 executable is retained only outside Git for reproducibility.
Additional `morep07` through `morep10` ledgers record each candidate and exact
semantic comparisons; `morep-final-ledger.json` identifies the final retained
state. Combined-insights working set/private peaks remained about
1242 / 475 MiB; filtered top-entry workloads about 879 / 94 MiB.
Wave-9/10 measurements used alternating executable pairs directly.

Focused regressions include
`insight_selections_match_full_sort_at_every_limit`,
`cohort_examples_preserve_stream_and_full_identity_ties_at_top_boundaries`,
`fused_cohort_examples_intersect_filters_scopes_and_keep_zero_byte_members`,
`top_compiled_filters_preserve_resource_prefixes_and_aligned_overlapping_hits`,
`top_filters_keep_exact_utf16_identities_and_reject_invalid_surrogates`, and
`fused_method_selection_reconciles_filtered_components_at_top_boundaries`.
Final retained-state three-run medians were 4.297 s combined insights,
1.281 s Methods top 10,000, and 6.080 s cross-input overview; their complete
non-metric reports matched the original feature baselines.

### Additional-series final verification

Final real-input confirmation covered twelve complete non-metric comparisons:
full codegen/scan searches, bounded fan-in, complete serializer counts,
incoming paging, batch traversal, metadata, both top-entry sizes, combined
insights, focused methods and overview. The focused-method reference is the
exact corresponding projection of the original combined report.
`more-final-confirm-*-1.json` and its measurement ledger preserve those results.
The brief's ten sections reconcile independently to the full report; indexed
JSON/NDJSON/table, no-index/default/empty rules and representative literal
follow-up commands passed (`more-brief-validation.json`). Its three
indexed-format observations were approximately 5.8-6.2 s, not isolated
microbenchmarks.

Workspace formatting, strict all-target/all-feature Clippy, tests/doc-tests,
root/fuzz cargo-deny, fuzz-target checks/native linking and release build passed.
Each native fuzz entrypoint also completed 1,000 uninstrumented smoke iterations;
these remain smoke checks, not sanitizer or coverage-guided campaigns.

Broader corpus dogfooding exposed an unrelated-scope memory reservation:
focused Methods `--top 1000` inherited the combined report's nested selections
and failed with a 5,128,257,536-byte charge at the default limit. Preparation now
reserves only the selected projection while retaining complete input and rule
validation. Methods and Cohorts remain linear in `--top`; nested Resources and
Generics keep checked worst-case reservations. The focused command completed
on the corpus in 1.933 s with 180,286,088 tracked bytes. These tracked charges
are not an operating-system RSS measurement.

Final validation after this repair passed 177 tests, with two opt-in tests
ignored, plus doc-tests, root/fuzz formatting, strict all-target/all-feature
workspace Clippy, both cargo-deny graphs, fuzz-target compilation/native linking,
all three 1,000-iteration uninstrumented smokes, and the workspace release build.
The indexed/no-index/default/empty brief cases, all output formats and literal
follow-ups also passed after the repair. No corpus or private analysis output
was added to the repository.

## Ten further evidence waves: measured feature cost

The next series adds ten generic investigation projections rather than claiming
ten additional speed wins. Dehydration/accounting limits, blob buckets,
diagnostic-artifact distinction, method population, visible culture grouping,
repeated names, directional overlap, per-stream union gaps, spelling hypotheses
and coverage-prefix targets are documented in the bloat-analysis guide.

Production collection is fused into the existing inventory: a bounded blob
selection, five checked method counters and seven checked union counters.
No index rebuild, graph query or second MSTAT parse is performed by the brief.
Alternating before/after executions, three repetitions per state, measured:

| Workload | Before median | After median | After peak working set | After sampled private |
| --- | ---: | ---: | ---: | ---: |
| Combined insights | 4.174 s | 4.184 s | 1241.57 MiB | 474.68 MiB |
| Focused Methods | 1.552 s | 1.605 s | 970.96 MiB | 186.00 MiB |
| Cross-input ordinary bloat | 5.786 s | 5.808 s | 1247.59 MiB | 482.56 MiB |

The observed focused Methods increase is approximately 3.4%; it buys an exact
full-population distribution independent of top. This is feature cost, not an
optimization claim. Shared-host/cache/thermal variability still applies.
The new broad-rule brief at top 50 completed in approximately 6.3 s in JSON,
NDJSON and table observations. Full top-1000 Methods remained usable at default
limits. `next-*-measurements.json`, `next-wave-validation.json` and the saved
before executable preserve local observations outside the repository.

Real verification checks every old non-metric field recursively, and
independently reconciles all ten new sections, bands, union streams and exact
coverage thresholds. Default/empty rules, all output formats, and filtered/full
method populations are included; new fields are additive, not ignored changes
to existing evidence.
Final post-regression validation passed 207 tests, two opt-in ignored,
doc-tests, root/fuzz formatting, all-target/all-feature strict workspace Clippy,
both cargo-deny graphs, fuzz-target compilation/native linking, 1,000
uninstrumented iterations per target and the locked workspace release build.
Thirty new tests cover the added collection/interpretation contracts.

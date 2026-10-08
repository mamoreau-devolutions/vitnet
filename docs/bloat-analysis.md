# Extracting meaningful bloat evidence

Start with byte accounting, classify contributors, then inspect why selected
graph nodes are retained. Do not treat a label match or a root witness as a
guaranteed byte-saving opportunity. Inputs should come from the same build;
vitnet cannot establish that merely from their paths.

## Ten analysis improvements

| Question | Operation | Interpretation |
| --- | --- | --- |
| Which metadata belongs to a component family? | `metadata INPUT --contains Newtonsoft` | Case-sensitive substring of resolved assembly, namespace or type ownership; intersects exact assembly/type filters. String contents do not establish ownership. |
| Is this top list representative? | Metadata `sections.concentration` | Complete pre-top totals, reported/omitted bytes, group counts and integer basis-point coverage for each dimension. Dimensions overlap; do not sum them. |
| Are large methods mostly instructions or auxiliary data? | `mstat methods INPUT` | Coalesced body, GC-info and EH-info sizes, not just their combined total. |
| Which resource packages/cultures dominate? | `mstat resources INPUT` | Three independently reconciled projections by exact assembly, culture and resource name; resources already overlap Blobs. |
| How much belongs to candidate component families? | `mstat cohorts INPUT --rules rules.json` | Explicit literal-name heuristics with bounded examples and overlapping-cohort accounting. |
| Are many generic-shaped names concentrated in a few families? | `mstat generics INPUT` | Prefix before the first literal `<` in Methods/Types names. This is not demangling or proof of managed generic instantiations; generated/anonymous names can qualify. |
| What directly retains a candidate? | `dgml incoming INDEX ID` | Paged source-to-target edges, exact reason lengths, truncated previews and explicit missing sources. Parallel edges are preserved. |
| How many labels match, and which have many retainers? | `dgml search INDEX TEXT --count-all --rank incoming` | Complete counts if the scan completes, otherwise bounded partial counts/ranks. Fan-in is not byte size. |
| Can several candidates be investigated consistently? | `dgml batch INDEX --ids ID1,ID2` | One locked generation, input-order witnesses, shared total edge/visit/time budgets and a bounded combined projection. |
| Do the separate size reports reconcile? | `bloat --metadata CSV --mstat MSTAT` | Versioned combined evidence, exact metadata-blob/lower-bound difference, non-additive breakdown warnings and optional graph-generation provenance. |

`mstat insights INPUT` returns all four new MSTAT projections together.
The individual commands compute only their requested projection while still
validating the full input and all options; their summaries remain complete.
`--top` limits displayed groups/examples, not their accounting totals.
`--contains` on the insight commands filters complete identities, not previews.
JSON and NDJSON preserve the structured reports; table output labels the
accounting fields explicitly. New NDJSON commands emit one report per line.
The CLI envelopes use `vitnet.mstat-methods.v1`, `vitnet.mstat-resources.v1`,
`vitnet.mstat-cohorts.v1`, `vitnet.mstat-generics.v1`, and
`vitnet.mstat-insights.v1`, with `input`, full checked `summary`, `top`,
`contains`, explicit `rules`, and the selected projection in `data`.
`vitnet.bloat.v1` contains the metadata envelope, shared MSTAT insights,
rules, optional graph descriptors, reconciliation and accounting caveats.
The additive `blobs` projection in combined MSTAT insights uses the same
coalesced inventory: complete/filtered counts, bounded ranked entries and
exact unfiltered `DehydratedData` presence. It does not rescan the mapped input.
Methods include five inclusive full-population byte bands; Cohorts include
once-counted `union_sections` for all seven streams. These additions preserve
existing fields and support absent fields when deserializing older reports.

### Reproducible cohorts

A rules file is a JSON array:

```json
[
  {"name":"serialization","contains":["Newtonsoft","JsonSerializer"],"stream":null},
  {"name":"compiled-xaml","contains":["XamlIl","XamlIL"],"stream":"Methods"},
  {"name":"cloud-sdks","contains":["Amazon.","Azure.","Google."],"stream":null}
]
```

Patterns are case-sensitive literals, OR-ed within a rule. A null stream means
all seven streams. Stream names otherwise exactly match `Methods`, `Types`,
`Blobs`, `RvaFields`, `FrozenObjects`, `ManifestResources`, or
`DeduplicatedMethods`. Multiple rules can match the same identity. Specialized
streams are not added to accounted Methods + Types + Blobs bytes.

Without a file, the CLI provides starter rules for serialization
(`Newtonsoft`, `JsonSerializer`), compiled XAML (`XamlIl`, `XamlIL`), cloud SDKs
(`Amazon.`, `Azure.`, `Google.`), resources (`Resources`, `resources`, `Avalonia`),
property-accessor-shaped names (`get_`, `set_`), and
generic-shaped names (`<`). These are discoverability heuristics, not an
authoritative component inventory. Use explicit rules for reproducible reports.
An empty array intentionally selects no cohorts.
The generic resource/accessor starters replace earlier corpus-specific
predicates. Historical measurements below used the saved explicit rule file;
omitting `--rules` intentionally uses the current generic starters.

Rules files are capped at 1 MiB and one sixteenth of the configured memory
budget. The analyzer also checks rule/state limits. Malformed, excessive or
unsupported rules fail explicitly.

### From bytes to retention evidence

```powershell
vitnet --format json bloat --metadata $metadata --mstat $mstat `
  --scan-index $scanIndex --codegen-index $codegenIndex --rules $rules --top 20
vitnet mstat methods $mstat --contains Newtonsoft --top 20
vitnet mstat resources $mstat --contains UIResources --top 20
vitnet dgml search $codegenIndex Newtonsoft --count-all --rank incoming `
  --max-scanned 100000000 --timeout-ms 120000 --limit 20
vitnet dgml incoming $codegenIndex $candidateId --limit 50
vitnet dgml batch $codegenIndex --ids $candidateId,$otherCandidateId --max-depth 32
```

Search counts apply to the scanned numeric-ID range, including `--after-id`.
Incoming ranking implies a full bounded scan even without `--count-all`.
`omitted_matches` counts matched nodes not shown in that report. When scanning
stops early, merging subsequent pages requires combining their counts and
re-ranking their candidates; a partial page is not a global top list.

`incoming --after-edge N --generation G` resumes after the zero-based ordinal
within that target's incoming CSR row. Generation guards reject stale cursors.
The JSON report keeps source IDs even if their declarations are absent.
`Primary` and `Secondary` can encode conjunctive prerequisites; neither edge
alone proves sufficient cause.

Batch limits apply to the entire batch, not separately multiplied by its size.
The batch accepts at most 128 IDs and charges the total projected paths against
the memory budget. Batch completion means every requested ID was processed;
each individual witness still exposes its own traversal stop and caveat.
Absent IDs fail explicitly. Incoming and batch also support `--daemon NAME`,
along with search/why. Daemon deadlines remain capped at 30 seconds.

## Accounting guardrails

MSTAT's accounted total is not an executable's on-disk size. Metadata CSV start
offsets give a lower bound; the final record has no known end. The observed
difference from the exact MSTAT `Metadata` blob is reported, not used as a
universal correction or a same-build assertion.
Reconciliation also reports the exact matching blob record count; its bytes
and difference are `null` when no complete blob name equals `Metadata`.

Graph labels and MSTAT identities have different producer contracts. Vitnet
does not claim a guaranteed cross-format join, package attribution from guessed
mangled names, or reclaimed bytes from one dependency witness. Start with the
largest byte cohorts, narrow the literals deliberately, inspect examples, and
use graph evidence to form a hypothesis to test in a subsequent build.

## What the RDM corpus revealed

The initial ten-feature release completed the full metadata/MSTAT inputs and
both existing graph generations without rebuilding the XML indexes.

| Evidence | Observed bytes | Meaning |
| --- | ---: | --- |
| Accounted MSTAT total | 1,062,414,426 | Methods + Types + Blobs, not executable size |
| Method bodies | 312,475,494 | Instructions/body bytes |
| Method GC info | 51,438,934 | A material auxiliary cost hidden by a single summed ranking |
| Method EH info | 1,210,666 | Separate from bodies and GC info |
| Literal serialization cohort | 16,173,995 accounted | `Newtonsoft` OR `JsonSerializer`; overlaps other cohorts |
| Literal compiled-XAML cohort | 48,771,083 accounted | `XamlIl` OR `XamlIL`; 48,365,243 B in Methods |
| Literal UI/resource cohort | 196,275,969 accounted | `UIResources` OR `Avalonia`; overlapping resource stream independently matches 62,544,359 B |
| Literal generated-property cohort | 4,637,138 accounted | `ConnectionPropInit` OR `ConnectionPropChanged` |
| Generic-shaped Methods names | 145,449,437 | 7,500 literal-prefix families; heuristic, not proven instantiation savings |
| Generic-shaped Types names | 183,369,712 | 3,680 literal-prefix families; separate Methods/Types totals |
| CSV lower bound / exact `Metadata` blob | 41,183,314 / 41,183,327 | Observed difference 13 B, not a universal adjustment |

Whole-input type ownership accounts for 30,694,255 B across 96,635 groups.
Its top 20 show only 14,183,217 B (46.20% of that dimension); looking only at
the top rows would miss 16,511,038 B. Conversely, `metadata --contains Newtonsoft`
selects 3,055,244 B, and its top 20 owning types cover 96.15% of type-attributed
bytes in that selection. That is a much more concentrated investigation.

The complete codegen label scan for the serializer-context literal found
145,185 nodes, not merely the displayed 20. This count is neither a method
count nor a byte attribution.

Dotted cloud patterns (`Amazon.`, `Azure.`, `Google.`) matched no accounted
symbols in this corpus, despite matching some non-accounted resource evidence.
This is an important negative result about the predicates, not proof that
cloud code is absent: opaque producer names can use underscores rather than
managed namespace punctuation. Inspect examples and broaden literal rules
deliberately before drawing component conclusions.

## Requirement evidence

| Improvement | Focused regression or real-corpus evidence |
| --- | --- |
| Ownership cohort selection | `cohort_selection_uses_resolved_owners_and_concentration_precedes_top` |
| Pre-top metadata concentration | Same test proves complete/selected totals, omitted bytes, group counts and empty selection |
| Method components | `methods_coalesce_opaque_identity_components_and_reconcile_denominator` |
| Exact resource groups | `resources_group_exact_assembly_culture_and_unicode_name_without_collisions` |
| Overlapping cohorts | `cohorts_or_predicates_intersections_and_stream_counts_are_not_additive` |
| Generic-shaped families | `generic_shaped_families_are_literal_prefixes_not_instantiation_claims` |
| Immediate retaining edges | `complete_counts_and_fan_in_rank_are_not_display_limited` proves paging, direction and missing sources |
| Complete counts/fan-in rank | Same test proves exact totals beyond the display limit, sparse slots and partial scan cursors |
| Shared-budget batch | `batch_shares_generation_order_and_total_budgets_and_rejects_invalid_inputs` |
| Cross-input reconciliation | `metadata_blob_reconciliation_is_exact_unfiltered_and_coalesced`, `metadata_blob_absence_does_not_match_case_substrings_or_truncated_names`, and `zero_size_metadata_blob_is_present_even_when_projection_is_empty`; three full-corpus final overview reports preserve the observed 13 B difference |

`incoming_and_batch_match_local_results_and_reuse_generation` covers both
new named-pipe operations. `all_insight_commands_surface_rules_failure_before_input_io`
checks all five insight commands in all three output formats.
The final release also checked successful Methods/Resources/Generics/Cohorts
JSON and NDJSON envelopes against their complete combined projections, and
exercised all four table outputs. All workspace regressions passed with
`cargo test --workspace`; the optimization evidence is recorded in
[performance waves](performance-waves.md).

## Ten additional interpretation waves

`bloat --brief` computes the same complete inputs, but emits the independent
`vitnet.bloat-brief.v1` contract rather than every nested raw projection.
JSON, single-report NDJSON and table formats are available. It echoes inputs,
top, explicit predicates and reconciliation; it does not guess assembly
ownership from opaque symbols, join symbols to graph nodes, or infer that the
inputs came from the same build.

| Wave | New evidence | Exact regression |
| --- | --- | --- |
| 1 | Ranked Methods/Types/Blobs shares, with specialized streams separated | `accounting_ranks_additive_streams_and_keeps_overlaps_separate` |
| 2 | Global body/GC/EH ratios and high auxiliary-cost ratios among displayed methods | `method_costs_use_global_components_and_rerank_only_visible_ratios` |
| 3 | Type-attributed versus unowned metadata lower-bound bytes | `metadata_attribution_keeps_unowned_and_type_bytes_without_double_counting` |
| 4 | Exact shown/omitted coverage across metadata, method, resource and family lists | `list_coverage_marks_omitted_zero_byte_groups_and_exact_remainders` |
| 5 | Resource culture mix, preserving unknown versus known-zero neutral culture | `culture_mix_distinguishes_unknown_neutral_absence_from_complete_zero` |
| 6 | Summed cohort membership versus union and once-counted multi-match bytes | `cohort_overlap_distinguishes_triple_membership_from_once_counted_overlap` |
| 7 | Unmatched accounted bytes, zero-hit predicates and resource-only hits | `rule_gaps_count_zero_byte_hits_and_separate_resource_only_predicates` |
| 8 | Exact-fraction density ranking within displayed literal-prefix families | `visible_family_density_uses_exact_fraction_order_and_bounded_previews` |
| 9 | Bounded, dimension-specific contributor cards with literal follow-up argv | `contributor_followups_are_literal_argv_and_omit_unusable_filter_hints` |
| 10 | Compact generation/slot-density/endpoint context and guarded query templates | `graph_context_is_empty_without_indexes_and_never_claims_a_join` |

Percentages use integer basis points; undefined zero-denominator ratios are
`null`, not fabricated zero percentages. Wide cohort membership sums and numeric
slot counts are decimal strings, including their wide ratio fields, so table
and JSON serialization cannot lose or overflow 128-bit values. Contributor
cards show at most three entries per dimension. Truncated, empty and
NUL-containing labels omit filter hints. Follow-ups are argument arrays, not
shell-interpolated command strings; `<literal>` in graph templates must be
replaced deliberately.

Reranking an existing displayed byte-top list cannot discover a higher-ratio
candidate hidden outside that list. Coverage makes that limitation explicit:
raise `--top` or use narrower filters for a different investigation. Culture
comes from the exact AssemblyRef field, not inferred resource filenames or
claims about which languages an application requires. Cohort membership
amplification is not exclusive ownership or a removable-byte estimate.

## Ten further dogfooding waves

The brief now includes the additive `investigation` section with its own
`vitnet.bloat-investigation.v1` contract. Existing brief fields are preserved.
This section consumes the same checked inventory and bounded source lists,
not another MSTAT parse or an implicit graph query.

| Wave | Evidence | Scope and limit |
| --- | --- | --- |
| 1 | Exact dehydration presence, bytes and original records | Unfiltered full UTF-16 `DehydratedData`; zero bytes can still mean present. Physical binary size remains null. |
| 2 | Ranked blob buckets and exact shown/omitted coverage | Producer categories, not guessed package attribution or physical savings. |
| 3 | MSTAT input/name-payload ratio | Diagnostic artifact bytes are separate from executable contributions; wide ratios serialize as decimal strings. |
| 4 | Full method-size bands and method/type breadth | Coalesced identities; inclusive 0, 1-255, 256-4095, 4096-65535 and 65536+ byte bands. Total bands ignore top/filter; matched bands honor the filter. Averages are floored, not percentiles. |
| 5 | Visible assembly/culture consolidation | Exact assembly names; only displayed groups are consolidated. Hidden neutral culture is unknown unless the source group list is complete. |
| 6 | Repeated exact resource names | Multiple identities and equal visible payload lengths are hypotheses, not content hashes or deduplication proof. |
| 7 | Directional cohort overlap | An intersection's share of each member; asymmetric denominators, non-additive overlaps. |
| 8 | Once-counted union and unmatched bytes by stream | Separates opaque Blobs from Method/Type predicate gaps; zero-byte identities remain visible as hits. |
| 9 | Optional dotted-to-underscore spelling hypotheses | No automatic rule mutation or demangling; original predicates retained, candidates bounded/deduplicated. |
| 10 | Proven 80/90/95% byte coverage prefixes | Counts only when displayed ranked candidates prove the threshold against the full dimension total; otherwise null. Not a count percentile. |

`--top` bounds each new ranked projection. The blob top list is fused into the
combined inventory and uses one additional conservatively reserved selection
list. Method bands and stream unions use fixed-size counters. Focused Methods
still do not reserve or collect unrelated blob/resource projections.

The full-population bands are especially useful when increasing top alone
would be expensive. In the private corpus, 1,468,644 identities of 1-255 bytes
contribute 122,066,868 bytes; 248,544 of 256-4095 bytes contribute 162,644,739;
5,768 of 4096-65535 bytes contribute 69,637,834; only 86 of 65536+ bytes
contribute 10,775,653. These reconcile exactly to the complete Method stream.
This distinguishes a broad middle/small population from a handful of giants.

The full blob accounting reaches 80/90/95% with its first 9/13/19 buckets.
Displayed resource names at top 50 prove an 80% prefix of 42, but cannot prove
the 90% target; the report does not invent a required top count for that tail.

### Further-wave regression evidence

The MSTAT tests are in `insights_cases`; interpretation tests are in
`insights_cli::brief::investigation::tests`. Thirty new tests cover the ten
questions plus empty, filter/top independence, exact UTF-16 identities,
coalescing, full-key/preview collisions, wide arithmetic and typed failures.

| Wave | Exact representative regression |
| --- | --- |
| 1 | `dehydrated_data_counts_only_exact_unfiltered_blob_identity` |
| 2 | `blob_report_preserves_full_identity_rank_and_coverage` |
| 3 | `diagnostic_artifact_ratios_keep_units_unknowns_and_wide_values` |
| 4 | `method_size_bands_reconcile_across_filters_tops_and_projection` |
| 5 | `resource_cultures_distinguish_hidden_neutral_and_empty_zero_evidence` |
| 6 | `repeated_resource_names_distinguish_identity_repetition_from_payload_hints` |
| 7 | `cohort_redundancy_uses_directional_exact_ratios_and_stable_order` |
| 8 | `cohort_union_sections_count_each_stream_identity_once` |
| 9 | `spelling_hints_are_bounded_literal_suggestions_without_rule_mutation` |
| 10 | `coverage_targets_require_exact_full_total_prefix_proof` |

Final `cargo test --locked --workspace --all-targets --all-features` and
workspace doc-tests passed: 207 tests, two opt-in ignored. Root/fuzz formatting,
strict workspace Clippy, both dependency-policy checks, fuzz compilation/native
smokes and release also passed. Real private-corpus comparisons preserve every
prior non-metric field and independently reconcile the new evidence.

Focused reports reserve selection memory only for their own shape while still
validating every predicate and the entire input. Methods and cohort examples
scale linearly with `--top`; Resources and Generics include nested group/example
lists and therefore retain checked quadratic worst-case reservations. A focused
Methods `--top 1000` must not inherit the combined report's unrelated nested-list
charge. `focused_methods_large_top_stays_within_linear_report_budget` and
`scoped_cohort_budget_is_linear_while_nested_projections_keep_limits` exercise
this distinction without bypassing real resource limits.

`brief_preserves_null_reconciliation_inputs_and_all_output_formats` checks
composition, versioning and every format; `brief_rejects_missing_concentration_instead_of_fabricating_coverage`
checks explicit failure rather than success-shaped defaults.
`brief_rejects_inconsistent_overlapping_stream_shares_without_panicking`
rejects inconsistent producer subtotals with a typed diagnostic before
percentage arithmetic. Logical hydration targets and their encoded
representation also make accounted bytes unsuitable as a physical file-size
or guaranteed savings estimate; see [format provenance](format-provenance.md).

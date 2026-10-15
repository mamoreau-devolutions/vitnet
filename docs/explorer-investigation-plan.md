# Developer size investigation

Extend the existing measurement workbench; retain its local-only operation,
evidence tiers, native controls, offline overview, and independent rendering,
response, memory and query budgets. No application-specific rules or predicted
savings are introduced.

## Implementation

1. **Reconciled ledger:** distinguish reported object accounting from physical
   binaries and overlapping projections. Classify both manifest and historical
   Avalonia containers consistently; never add a container to its child assets.
2. **Proportions:** show shares of the complete accounted total and selected
   parent. Keep selected-scope coverage separate from global overview coverage.
3. **Compiler buckets:** explain recognized NativeAOT node kinds using the
   pinned producer sources in format provenance; identify unknown kinds without
   guessing ownership.
4. **Complete ranking:** prepare an immutable, externally sorted byte/ordinal
   sidecar. Page the complete identity cache in descending byte order, with
   exact stream, assembly-association, owner and generic-family filters.
   Preparation and queries remain bounded; legacy bundles explain the upgrade.
5. **Connected evidence:** record assembly/package relationships from supplied
   assembly fields and explicit package mappings, including supplemental
   evidence. These relationships do not alter the source matcher or prove
   compiler reachability. Link packages, assemblies, resources, identities,
   source candidates and graph-label searches without changing evidence tiers.
6. **Pattern investigation:** open a family's size-ranked members, expose parsed
   producer arguments and canonical/shared status, and offer supported argument
   source candidates. Compiler-generated names never establish generator runs.
7. **Progressive search:** automatically continue bounded empty/partial scan
   batches until a page is filled or the scan finishes. Maintain cumulative
   progress, cancellation and stale-result protection; keep only one page.
8. **Readable inventories:** return bounded domain fields alongside complete
   record links. Group and search dataset choices, name supplements, make
   upstream truncation and missing evidence visible, and remove stale endpoint
   availability claims.

## Acceptance

- Every prepared identity occurs exactly once in descending-byte ranking;
  ties use original ordinal. Fingerprints, monotonic order, truncation, stale
  files, cancellation and malformed cursors are checked.
- Full-data scoped pages, family membership and denominator totals reconcile
  with independently constructed synthetic evidence, not snapshot top-N.
- Assets and containers remain separate; unknown physical/generator evidence
  remains unknown. Package-origin associations and graph-label matches retain
  their limitations.
- Automated continuation never duplicates a record, leaks a previous scope,
  accumulates browser history, or turns an incomplete scan into a no-match.
- Existing CLI, complete-catalog, authenticated HTTP and offline contracts pass.
  Exercise the private large corpus and desktop/mobile navigation without
  copying private evidence into the repository.

Implementation does not commit or push changes. The original attribution and
DGML generations remain immutable; deploy a new bundle and release executable
only after validation.

## Implemented requirement evidence

| Requirement | Exact regression evidence |
| --- | --- |
| Reconciled, nonadditive ledger and unknown measurements | `ledger_known_inventory_is_overlapping_not_additive`; `ledger_absent_accounting_is_distinct_from_reported_zero` |
| Complete-total and before-text parent proportions | `ranked_scope_denominators_are_complete_or_explicitly_unknown`; `percentages_preserve_known_zero_and_unknown_denominators_without_capping_overlap` |
| Producer-grounded bucket glossary without guessing unknown kinds | `compiler_buckets_use_pinned_producer_glossary_and_never_guess_unknown_names` |
| Complete deterministic byte ranking and integrity | `ranking_binary_descriptor_le_order_ties_and_permutation`; `ranking_integrity_rejects_fingerprint_and_semantic_corruption` |
| Recorded package origins, exact targets and unchanged source authority | `relations_are_complete_exact_filtered_and_matcher_independent`; `assembly_links_merge_targets_without_changing_real_matcher` |
| Exact family members, canonical arguments and full shape navigation | `family_record_uses_complete_catalog_ordinal_and_original_truncated_family`; `full_shape_navigation_exceeds_bounded_source_and_argument_projections` |
| Automatic bounded continuation, cancellation and stale isolation | `progressive_scan_continues_empty_partial_batches_and_stops_at_public_boundaries`; private desktop/mobile replay scenarios for automatic continuation and whole-search cancellation; 38-workflow live/offline replay |
| Readable complete inventories, finder grouping and capture limitations | `records_project_domain_fields_and_preserve_captured_originals`; `dataset_categories_preserve_supplemental_and_graph_precedence`; `upstream_metadata_truncation_is_explicit_and_not_reconstructed` |

Final validation: workspace tests and strict all-target/all-feature Clippy pass;
workspace formatting, nine Node helper tests, JavaScript syntax, both cargo-deny
policies and fuzz compilation pass. Private replays cover 147 full-catalog API
responses, ten complete-data browser cases, thirteen synthetic value-boundary
cases, nine investigation APIs/workflows and 38 live/offline workflows.
The full ranked bundle was independently verified. Measurements and uncontrolled
run limitations are recorded in [performance-budget.md](performance-budget.md).
Private inputs, generated bundles and browser artifacts remain outside Git.

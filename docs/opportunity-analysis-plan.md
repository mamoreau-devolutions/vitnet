# Evidence-backed opportunity analysis

Implement improvements 1 through 7. Controlled rebuild experiments (improvement
8) are explicitly outside this change. Findings are investigations, not proven
waste, exclusive ownership, physical sizes or predicted savings.

| Improvement | Implementation and acceptance |
| --- | --- |
| 1. Generator outputs | Read-only collector captures referenced analyzers, observed output files, checksums and available build routes. Distinguish output capture from execution and diagnose unknown versions/build provenance. |
| 2. Generator triggers | Retain supplied input assertions and recorded/candidate output-to-source links with rule and confidence. Expose complete capture catalogs, including empty/unknown states. Never infer a verified generator run from an attribute or directory name. |
| 3. Typed NativeAOT symbols | Extract artifact-local tokens and resolved managed names/signatures into a hashed streaming import sidecar. Join complete stream/raw-name keys; preserve conflicting joins and unsupported forms. Source/build checksums remain an independent trust dimension. Existing identity/accounting schemas remain unchanged. |
| 4. Cross-stream budgets | Prepare reconciled per-assembly and target-specific package budgets. Keep additive streams separate from overlapping metadata/resource projections; ambiguous/shared/unmapped bytes remain visible and are never charged fully to each candidate. |
| 5. Repeated patterns | Rank generic families and compiler/source-generator name cohorts by aggregate measured bytes and multiplicity, not individual method size. Report canonical sharing, original identity examples and bounded navigation to the complete contributor ranking. |
| 6. Retention explanations | Connect findings to graph search, then bounded original witnesses plus source/annotation anchors. Preserve alternate incoming edges, conjunctive reasons, graph generation and incomplete-query status. A witness does not establish a sole removable root. |
| 7. Unexpected features | Generic tooling/demo patterns and optional local feature/capability policy identify candidates. Package overlap and repeated implementations are hypotheses, not automatic deletion advice. No RDM-specific heuristics. |

## Integration

- Versioned opportunity report and optional strict local rule policy.
- CLI commands for ranking findings, inspecting budgets and annotated retention.
- Immutable prepared catalogs retain complete findings and budgets before
  snapshot display caps. Old bundles explicitly require new preparation for
  these catalogs; they do not pretend missing capture is an empty result.
- Live Opportunities view explains evidence tiers, capture gaps, concrete
  source/record/retention navigation and overlapping cohort accounting.
- Existing live server and private RDM inputs are not mutated during development.
  Real-corpus validation uses new private import/bundle directories.

## Verification

Synthetic coverage for evidence tiers, absent generation data, emitted files and
checksum drift; typed and unresolved tokens; assembly/package ambiguity and
cross-stream reconciliation; pattern overlap, deterministic ranking and limits;
policy validation; CLI/HTTP/catalog equivalence; bounded annotated retention;
old-manifest compatibility and old-bundle missing-catalog diagnostics.

Run focused tests during development, then workspace tests, strict Clippy,
formatting, collector regressions, browser helper checks and a release
real-corpus smoke check. Private analysis/test artifacts stay outside the
repository. No new dependency is needed unless a checked format reader proves
otherwise. Do not commit or push without user authorization.

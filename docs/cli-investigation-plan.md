# CLI investigation improvements

This round adds ten generic improvements to the prepared-bundle terminal
workflow. Existing defaults, analyzer machine schemas, and the running browser
report remain unchanged. No application-specific rules or dependencies are added.

| # | Improvement | Acceptance contract |
|---|---|---|
| 1 | `explore explain <bundle> <ordinal>` | Explain one original identity ordinal with exact bytes, additive/overlap role, global share, bounded producer identity, recorded source candidates, shape availability, known Blob glossary, and commands for full inspection. Missing or lossy evidence is explicit, not invented. |
| 2 | `explore compare <before> <after>` | Compare accounted totals, additive streams, physical inventory and overlapping metadata/resource projections with signed exact byte deltas. Missing measurements produce null/Unknown, never zero. Before-zero percentage changes are undefined. Capture both generations and do not claim identity-level deltas or savings. |
| 3 | `explore coverage <bundle>` | Distinguish complete captured catalogs/ranking, bounded snapshot previews, source/generator descriptor counts, available graphs and missing physical measurements. Report captured coverage, not an integrity audit, source completeness or retention coverage. |
| 4 | `explore glossary [bucket] [--contains text]` | Browse the same nine pinned compiler buckets as the browser, without a bundle. Exact unknown bucket names fail. Search is case-insensitive across names, titles and explanations; empty results are explicit. |
| 5 | `explore guide <bundle>` | Produce actionable investigation commands from measured largest streams, captured inventories, available ranking and missing evidence. Safely quote paths; preserve global output/progress/memory settings and generation where applicable. No guessed causes or savings recommendations. |
| 6 | `contributors --accounted-only` | Exclude nonadditive projections while preserving complete ranking order, scan budgets, rank cursors and full parent denominators. |
| 7 | `contributors --min-bytes/--max-bytes` | Inclusive, intersecting human-size thresholds, including known zero and equal bounds. Reject inverted ranges. Apply filters during bounded scans, not after page selection. |
| 8 | `contributors --exact` | Match the complete captured identity against `--contains` exactly, not against its bounded display preview. Preserve existing case-sensitive substring behavior by default and retain the shared selector-size budget. |
| 9 | `contributors --columns` | Select and order table columns from ordinal, size, bytes, total, parent, cumulative, role, stream and identity. Reject unknown/duplicate columns and non-table use. Defaults remain byte-for-byte compatible; continuation preserves the selection. |
| 10 | `datasets --contains/--storage/--nonempty` | Discover captured datasets by literal name substring, exact storage class and nonzero record count. Retain full-catalog totals and selection metadata; never confuse filtered results with missing capture. |

## Implementation boundaries

- Reuse the existing immutable bundle readers, ranking sidecar, source matcher,
  generic shape parser, compiler glossary, byte formatter and query budgets.
- Explain uses bounded source/shape inspection and retains links to full values;
  it does not fetch source files or traverse an entire dependency graph.
- Compare loads the two bundles sequentially and retains only compact ledgers.
  Nonadditive comparisons stay clearly separate from additive stream changes.
- New reports use `vitnet.explorer-cli.v1`; glossary has a null bundle generation.
  Existing JSON and NDJSON measurements remain exact and unrounded.
- New ranking filters are optional in the shared local query backend, preserving
  existing browser requests. Continuations retain every selector and budget.
- Output remains limited by the existing response/memory-share cap, with explicit
  diagnostics rather than truncated success-shaped output.

## Verification

Use synthetic independent regression fixtures for every new operation and its
empty, zero, missing, invalid, boundary and continuation cases. Preserve all
existing CLI and browser tests. Run focused CLI tests during fixes, then
workspace formatting, strict Clippy, relevant HTTP contracts, browser helper
tests and a release build. A private large prepared bundle may be used for
read-only smoke checks; never copy its inputs into the repository.

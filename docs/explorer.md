# Bounded visual explorer

The explorer turns existing attribution evidence into a navigable measurement
workbench. It does **not** send the complete DGML graph to the browser, run
application code, fetch source files or replace the existing named-pipe daemon.
There is no frontend installation or external CDN.

## Prepare once, browse repeatedly

Start with an imported `vitnet.evidence.v1` attribution index. See
[attribution.md](attribution.md) for capture and import. The index can contain
MSTAT, metadata, source declarations and previously built scan/codegen indexes;
missing evidence stays explicitly unavailable.

```powershell
vitnet --memory-limit 2GiB explore prepare .\build-index --bundle .\explorer-bundle
vitnet --memory-limit 2GiB explore verify .\explorer-bundle
vitnet --memory-limit 2GiB explore browse .\explorer-bundle --open
```

Preparation streams and verifies **all** cached identities, computes reconciled
aggregates and writes an ordinal-to-offset sidecar and a complete descending-byte
ranking. Ranking ties use the original identity ordinal. New bundles also retain
complete inventory records in hashed NDJSON datasets with ordinal offsets,
before applying any overview display caps. It does not copy the identity
cache or graph. Live browsing still requires the original immutable attribution
index and graph generations at their recorded locations. Keep them unchanged;
prepare a new bundle after a new import. Existing bundles are never overwritten.

Supplemental resource/package inventories and selected offline witnesses are
optional:

```powershell
vitnet --memory-limit 2GiB explore prepare .\build-index `
  --bundle .\explorer-bundle-next `
  --evidence .\asset-inventory.json --evidence .\package-inventory.json `
  --node 1234,5678 --graph scan_index --before .\before-index
```

`--evidence` uses the evidence schema but supplements inventories, physical binary
records, generator
descriptors and diagnostics, not source matching or compiler artifact imports.
Source declarations and mappings belong in the original attribution import.
All supplemental model fields are retained separately in the catalog, including
source declarations and provenance that are not merged into source matching.
Supplemental package routes are local inventory evidence, not proof of the
actual publish-time dependency graph. Conflicting resource/package identities
fail explicitly. Duplicate binary paths must have identical captured records;
conflicting physical evidence fails instead of silently double-counting.
At most sixteen inventories and three selected witnesses are
accepted. Comparison requires a separate before index; absent physical binary
measurements remain unknown rather than zero.

## Terminal investigation

No HTTP server, browser, capability token or daemon is needed. These commands
open the same immutable bundle and use the same complete-data readers, filters,
rankings, integrity checks and source matcher as the live view:

```powershell
vitnet explore summary .\explorer-bundle
vitnet explore contributors .\explorer-bundle --limit 25
vitnet explore contributors .\explorer-bundle --assembly Product.Core --stream Methods
vitnet explore contributors .\explorer-bundle --owner Product_Widget --contains Serialize
vitnet explore datasets .\explorer-bundle
vitnet explore records .\explorer-bundle generic_families --contains Dictionary
vitnet explore contributors .\explorer-bundle --family-record 12
vitnet explore records .\explorer-bundle resources --filter assembly=Product.Core
vitnet explore origins .\explorer-bundle --package Example.Library --target net10.0
```

`summary` separates additive reported object sizes from physical binary
inventory, metadata lower bounds and overlapping resource assets/containers.
Missing physical evidence stays **Unknown**; measured zero remains zero.
Its bundled-preview coverage is not complete-ranking or landscape coverage.
`datasets` lists every captured dataset, including supplements and graph
inventories. `records` supports intersecting, exact top-level `--filter
field=value` selectors; repeating the same field fails rather than silently
discarding a selector. Labels and field summaries are previews, not a
replacement for captured records.

`contributors` reads the complete byte ranking, with ties ordered by original
ordinal. Stream, assembly, opaque owner and parsed family filters intersect.
Select a family by `--family` or `--family-record`, never both; the latter uses
the original ordinal shown by `records generic_families` and avoids copying a
shortened label. `% total` uses the complete accounted total; `% parent` uses
the complete captured selected partition **before** the substring filter.
Combined partition scopes and non-additive stream denominators remain Unknown.
Overlapping identities are labeled instead of presented as additive shares.
Cumulative percentages refer only to the current page. Recognized Blob buckets
use the same pinned producer glossary as the browser; unknown names are not
assigned an invented explanation.

All three page commands accept `--limit 1..100` (default 50), `--max-batches`
(default 20), `--timeout-ms` (default 30000), `--after`, and `--generation`.
Each batch retains the live backend's 100,000-position / 1,500-ms scan cap.
Empty and partial batches continue automatically until the requested page
fills, the captured dataset ends, or the overall budget stops the operation.
The overall deadline is checked **between** batches, so one bounded batch and
reader initialization may extend wall time beyond it. Ctrl+C is cooperative.
Only one page is accumulated, with a 2-MiB-or-memory-share response cap.
`--progress always` writes scan progress to stderr; stdout remains a clean
table or machine report.

Stopping reasons, scanned positions, batch count and continuation remain
visible. A partial empty page is **not** a complete no-match result. Copy the
printed PowerShell continuation command to preserve filters and generation.
It also preserves the memory budget, output format and progress/quiet settings.
It deliberately omits `--output` so continuing does not overwrite the prior
page's saved report. Quoted selectors, including embedded terminal controls,
are encoded as safe PowerShell arguments rather than executable input.
For contributors, `--after` is a **rank position**, not the original identity
ordinal. For inventories it is the original dataset ordinal; graph node
ordinals are node IDs and graph edge ordinals are global CSR edge positions.
Use `--generation` with manually resumed cursors too.

Inspect using the **original ordinal** printed beside a row:

```powershell
vitnet explore inspect .\explorer-bundle 123
vitnet explore inspect .\explorer-bundle 123 --view source
vitnet explore inspect .\explorer-bundle 123 --view shape
vitnet explore inspect .\explorer-bundle 12 --dataset generic_families
vitnet explore inspect .\explorer-bundle 12 --dataset generic_families --path 0
```

`inspect` prints ordered positional child indices. Descend with `--path
index,index`; continue an array/object page or string chunk with `--start`.
Object indices follow the exact field order printed by the inspector, not
guessed schema order. `--key` pages a complete object property name. String
offsets are UTF-8 byte boundaries; invalid paths, offsets, signed ordinals and
stale generations fail explicitly. Source and shape views apply only to the
`identities` dataset. A nongeneric shape is null, not missing evidence disguised
as a fabricated family. Lossy producer identities cannot establish shapes.
Terminal controls are escaped in tables; JSON preserves captured string data.
Inspection does not reconstruct upstream truncation or fetch source contents.
Source/package candidates remain distinct from compiler retention and savings.

`--format json` returns a versioned `vitnet.explorer-cli.v1` envelope containing
`operation`, `generation`, `data` and, when applicable, `next_command`.
`--format ndjson` emits that envelope on one line. Byte counts, original
ordinals and value text remain unrounded; new commands do not change existing
metadata, MSTAT, attribution or graph JSON schemas. Table sizes use decimal
KB/MB/GB (1 KB = 1,000 bytes), with exact counts alongside summary measurements.
Existing metadata, MSTAT and attribution tables also use human sizes and
accounting-aware proportions; their top lists remain bounded analyzers, not
complete prepared-bundle inventories.

### Connected terminal investigations

The [ten-improvement CLI plan](cli-investigation-plan.md) adds connected
reports and precise discovery controls:

```powershell
vitnet explore explain .\explorer-bundle 123
vitnet explore explain .\explorer-bundle 123 --generation <captured-generation>
vitnet explore coverage .\explorer-bundle
vitnet explore guide .\explorer-bundle
vitnet explore compare .\before-bundle .\after-bundle
vitnet explore glossary
vitnet explore glossary Metadata
vitnet explore glossary --contains resource
```

`explain` takes an **original identity ordinal**. It combines measured bytes,
additive/overlap role, global share, bounded recorded source evidence, producer
shape availability and a known Blob bucket explanation. Its record/source/shape
commands are generation-pinned and lead to full captured value pages.
Nongeneric shapes and upstream-lossy identities have distinct statuses; lossy
identities do not establish a shape or compiler bucket. Candidate sources are
not exclusive physical owners, and parsed shapes are not retention evidence.

`coverage` reports capture readiness: complete catalogs/ranking, identity
counts, captured source declarations and generator descriptors, available
graphs, physical measurements and bundled-preview coverage. It is **not** an
integrity audit, original-source coverage percentage, or proof of all retention
paths. Use `explore verify` for bundle/cache fingerprints.

`guide` supplies safely quoted PowerShell investigation commands based on
captured facts: the largest measured additive stream, nonempty resource/generic
inventories, recorded origins, diagnostics and available graph catalogs.
Absent measurements stay absent; advice never diagnoses a cause or promises
savings. Graph IDs and identity ordinals remain different dimensions.
Generated commands preserve format, memory and progress settings, pin query
generations, and omit `--output` to avoid overwriting saved results.

`compare` loads before/after bundles sequentially and retains compact ledgers,
not two complete identity populations. It reports signed exact deltas for
accounted total, additive streams, physical inventories and overlapping
metadata/resource projections. Missing before/after measurements produce
null/Unknown deltas. A measured zero stays zero, but percentage change from
zero is undefined. An absent stream is zero only when that build has a known,
complete additive accounting ledger; otherwise its size is unknown. Different
physical inventories are not necessarily the same executable. This command
does **not** compare individual identities or estimate removable bytes.

`glossary` requires no bundle or HTTP server. Exact bucket selection is
case-sensitive; unknown names fail rather than getting an invented explanation.
`--contains` searches names, titles and descriptions case-insensitively.
The entries are the same pinned producer descriptions used by the browser.
These operations retain `vitnet.explorer-cli.v1`; comparison records both
generations and glossary uses a null bundle generation.

### Precise ranking and dataset discovery

```powershell
vitnet explore contributors .\explorer-bundle --accounted-only --min-bytes 1MB
vitnet explore contributors .\explorer-bundle --min-bytes 64KiB --max-bytes 1MiB
vitnet explore contributors .\explorer-bundle --contains Product_Widget__Run --exact
vitnet explore contributors .\explorer-bundle --columns 'ordinal,bytes,total,identity'
vitnet explore datasets .\explorer-bundle --contains resource --nonempty
vitnet explore datasets .\explorer-bundle --storage immutable-graph
```

`--accounted-only` excludes overlapping projections. Minimum/maximum byte
filters are **inclusive** and intersect with existing selectors; equal bounds
and zero are valid, inverted ranges fail. Integer sizes accept B, decimal
KB/MB/GB/TB/PB/EB or binary KiB/MiB/GiB/TiB/PiB/EiB. Fractional sizes are
rejected. The descending ranking can finish once all remaining rows are below
the minimum, without scanning an irrelevant suffix.

`--exact` compares the complete captured producer identity with `--contains`,
not its shortened table preview. Default substring matching remains literal
and case-sensitive. The shared 1,024-byte selector budget still applies; use
original ordinals for longer identities. New filters apply **during** bounded
scans, so a filtered page is filled across batches rather than filtered after
top-N selection. Parent/global denominators remain the complete partition,
not the text/size-filtered page, and continuations retain every new selector.

`--columns` selects and orders table columns from `ordinal`, `size`, `bytes`,
`total`, `parent`, `cumulative`, `role`, `stream` and `identity`. `bytes` is the
exact integer; `size` is human-readable. Repeated/unknown columns and non-table
formats fail explicitly. Without this option the existing table is unchanged.
Presentation selection does not discard captured evidence or bypass response
budgets; complete values remain inspectable.

Dataset discovery supports literal case-sensitive name `--contains`, exact
storage classes `bundle`, `original-index`, `immutable-graph`, and `--nonempty`.
These filters intersect. Reports keep the full catalog count, returned count
and selection criteria; an empty filtered catalog is not a missing capture.
Captured storage values in JSON retain underscores (`original_index`,
`immutable_graph`) rather than CLI option spellings.

## Portable HTML

```powershell
vitnet explore export .\explorer-bundle --html .\size-report.html
vitnet explore export .\explorer-bundle --html .\size-report-redacted.html --redact-paths
```

Open the HTML directly in a browser. CSS, scripts, worker layout and bounded
evidence are embedded; the report needs no server or network access. Once
exported, it no longer needs the original indexes. It supports the same views
and bundled contributor details/witnesses, but cannot query unseen identities,
fetch source details or expand arbitrary graph nodes.

Exports also reject existing output. `--redact-paths` removes structured paths,
diagnostic messages and provenance values. **It is not anonymization**:
application labels, symbols, resource names and package identities remain.
Review an export before sharing it. A live browse URL is a private session
capability, not a shareable report.

## Investigation views

| View | What to navigate | What it does not establish |
| --- | --- | --- |
| Landscape | Zoomable stream/assembly/opaque-owner icicle, aggregate table and Other remainder | Candidate assembly association is not exact source ownership |
| Contributors | Paged identities, bytes and source/emitter inspector; live stream, assembly, owner and substring filters intersect | A contributor ordinal is not a graph node ID |
| Retention | Exact ID or label search, incoming pages and bounded root witnesses with original edge reasons | Degree is not byte size; a witness is not every path or a reclaimable-byte prediction |
| Amplification | Generic-family counts, canonical-sharing markers and generator associations | Native identity counts are not source-language instantiation counts |
| Resources | Container/assembly filters, payload inventories and checksum-equal duplicate groups | Overlapping container bytes cannot be added to asset bytes; duplicates are not automatically removable |
| Dependencies | Direct/transitive package routes from recorded evidence | A restore route alone does not prove the published binary retained a package |
| Comparison | Signed logical changes, separate physical deltas and provenance | An uncontrolled before/after change does not isolate causality |
| Evidence | Full counts, bounded provenance/diagnostic previews, generations and caveats | A shortened preview is not a complete audit record |
| All data | Every captured inventory, identity and stored graph node/edge, full-text search, exact filters and nested record/text pagination | Captured evidence is not every original compiler attribute, source file or possible retention path |

Click an icicle stream or partition to zoom, use its breadcrumb to zoom out,
then inspect scoped contributors. The partition table provides a keyboard/text
equivalent. Offline filters search only the exported subset and explicitly
label preview-based matches; live filters use complete cached identities and
located assembly evidence.

Sizes automatically use decimal B, KB, MB, GB and larger units (1 KB = 1,000
bytes), rounded to at most two decimal places. Tables and inspectors expose the
original byte counts on hover and in accessible labels. Counts and graph IDs are
not scaled, unknown measurements stay unknown, and raw JSON evidence retains its
original numeric values.

The **global size ledger** separates reported object accounting, supplied
physical binaries, metadata lower bounds, resource child assets and resource
containers. No physical inventory means **unknown**, not a zero-size executable.
Both `manifest_container` and historical `avalonia_container` storage roles are
containers and are excluded from duplicate-asset groups. ResourceData and
decoded resource inventories have different measurement bases; their difference
is not labeled savings. Stream headers share one accounted-total denominator;
scoped contributor pages separately show parent share and current-page coverage.

Prepared live bundles default to **largest bytes first**, including assembly
scopes and text filters; overview top-N limits do not constrain these results.
Selecting a partition automatically queries its largest matching contributors.
Only the current page is retained. Original cache order remains selectable.
Multiple intersecting partition filters have an unknown parent denominator
rather than a fabricated sum. Non-additive streams are explicitly projections.

Recognized compiler buckets have an original, producer-grounded glossary and
investigation links. Unknown buckets remain unknown. The
[pinned producer references](format-provenance.md#explorer-compiler-bucket-glossary)
explain why a summary label is not necessarily an ordinary graph node.

**Resources**, **Dependencies** and **Amplification** use complete captured
inventory pages in live mode. Generic families are globally byte-ranked;
the scatter shows only the current page. **Rank family members** filters by
the complete stored family spelling, even when its display is shortened.
Contributor inspectors expose parsed producer arguments, canonical/shared
markers, and bounded argument-source candidates; **Full parsed producer shape**
navigates every captured argument. These are not guaranteed C# arguments or
proven caller sites.

Assembly/package links use recorded assembly package fields or explicit
assets-resolved mappings, including supplements. Source matching remains based
on the original import. Package-origin, declaration-emission and compiler-edge
evidence remain separate; unknown origins are not guessed from similar names.
Select an assembly origin to inspect contributors/resources or a package origin
to inspect its exact target-scoped declared route.

Graph arrows point **retainer to retained**. Search/select a node, expand its
immediate retainers, then select an upstream row to follow it. Each page replaces
the current sheet instead of accumulating an unbounded graph. Reset/collapse
releases the sheet; a bundled witness selects its own graph generation.
Incomplete witness stops, cycles, missing nodes and zero-in-degree root
candidates remain explicit.

## Complete live access

Open **All data**, or use the complete-inventory buttons on any overview.
Find a dataset by name, category or supplemental inventory label, then browse
or search its full stored text and open a row. Native grouped selectors and
domain-specific columns keep package/version/target, assembly/container, bytes
and metadata text readable without downloading whole inventories. Upstream
string truncation is marked separately from a shortened display field.
Inventory filters intersect exact top-level field values. Identity filters
support `stream`, `assembly` and `owner`; graph-node searches match full labels,
and graph-edge searches match full reasons and numeric IDs.

The record inspector pages every object property and array element. Click a
field to descend, use the breadcrumb to go back, and continue long strings in
UTF-8-safe 4,096-byte chunks. Long property names have their own full-text
navigation. Primitive numbers retain exact decimal text, including values
outside JavaScript's safe-integer range. Contributor inspectors also expose
the complete identity and **all** located source candidates/attributes.
Incoming reason buttons open the complete stored edge. Global edge ordinals
are distinct from target-local incoming ordinals.

Full inventories include landscape partitions, generic families, resources,
duplicate members, package routes, raw packages/assemblies/sources/mappings,
generator descriptors with complete file/input lists, binaries/sections,
artifacts/fingerprints, provenance, diagnostics, MSTAT summaries and all captured
metadata arrays. Supplemental datasets retain their original model fields.
Graph pages enumerate empty-label nodes and parallel edges too, without
building an outgoing index or loading a graph into memory.

**Complete means complete captured data.** Import/report limits remain visible:
metadata may already contain producer-analysis previews or top-N omissions;
source file contents are not captured; absent generator evidence stays unknown.
The comparison catalog retains its full captured report before explorer caps,
but MSTAT identity-delta entries retain the upstream comparison top-N limit.
Root paths remain bounded queries, not an exhaustive enumeration of all paths.
These capture boundaries are not silently presented as full original inputs.

Older v1 bundles still open, but their catalog explicitly reports
`complete: false`: discarded supplemental inventories cannot be recovered from
the bounded snapshot. Prepare a **new directory** with the original index and
supplemental evidence to enable complete inventory access. Offline HTML remains
a bounded overview; it does not embed these full datasets.

## Scale and latency

The browser receives bounded projections, not millions of nodes or edges:

| Boundary | Limit |
| --- | ---: |
| Offline snapshot JSON | 8 MiB |
| Live snapshot or query response | 2 MiB |
| HTTP request body / headers | 16 KiB / 8 KiB |
| Rows in one table page | 100 |
| Contributor identity preview | 512 UTF-8 bytes |
| Graph nodes / edges in one sheet | 200 / 500 |
| Graph search or incoming page | 50 results |
| Complete-dataset / nested-child page | 100 results |
| Full-text value chunk | 4,096 UTF-8 bytes |
| Decoded complete inventory record | min(memory limit / 64, 32 MiB) |
| Nested-value path | 64 child-ordinal steps |
| Search batch | 100,000 scanned records/slots or 1.5 seconds |
| Root traversal | 12 levels, 3 paths, 5,000 visits, 25,000 examined edges, 1.5 seconds |
| Connections / expensive queries | 4 / 1 |

Query deadlines are cooperative checkpoints, not hard real-time guarantees.
Disk access or a single source lookup can exceed a checkpoint. Text searches
can require many batches. The frontend automatically continues bounded
empty/partial batches until one page is filled or the dataset is exhausted.
Cumulative scanned slots, batch count and page matches stay visible; **Cancel
query** stops the sequence, and the last completed cursor remains resumable.
There is no total scan deadline or growing result history. Only an exhausted
search proves no captured match. Graph labels still use bounded disk scans;
exact node-ID lookup is direct and avoids scanning the graph.

Layout uses a worker with bounded layered placement and no continuous force
simulation. Cancel signals the backend and invalidates stale UI results;
switching views also cancels pending work. Results and worker messages from old
requests cannot repopulate a newer sheet.
Replacement queries wait for the cancelled request to release its backend slot,
with a two-second bound and an explicit error if it does not drain. A narrowly
scoped busy retry covers cancellation-admission races, not arbitrary failures.

Only Methods, Types and Blobs are additive. Method body/GC/EH, resources,
metadata lower bounds, generic and generator projections overlap those totals.
Complete aggregate sums use the verified cache. Displayed top-N records and
inventories are capped separately, with full counts and remaining bytes visible.
Provenance/diagnostics and each comparison evidence-change list show at most
the first 100 records, with full counts retained; text fields are bounded
previews. **All data** bypasses these explorer projections through disk-backed
pages. Preparation fails explicitly if a full record cannot fit its reserved
memory share; it never publishes a successful bundle with silently dropped rows.

`--memory-limit` constrains decoded inputs, aggregate cardinality and query
state; it is not a process RSS guarantee. The server retains imported source
evidence and small disk readers, not the DGML graph. Preparation has a separate
one-time CPU/memory cost. See the measured
[performance budget](performance-budget.md#visual-explorer).

## Local transport and integrity

The server binds only `127.0.0.1`, with an ephemeral port unless `--port` is
specified. Open the **complete** printed URL: its random capability is carried
in the fragment, cleared from the address bar, and kept only in memory.
Reloading the fragment-free page does not recover that capability; reopen the
original URL or restart browsing.

The public shell contains no private snapshot or bearer capability. Private
APIs require authenticated JSON POST requests and exact Host/Origin checks;
there is no CORS allowance, arbitrary-file API or source/process launch API.
Source paths are text only. Imported evidence is rendered as text, not HTML.
CSP nonces are independent of authentication capabilities. Ctrl+C or **Stop
server** shuts down this explorer and releases its readers, not other services.

Bundles use `vitnet.explorer-bundle.v1`; snapshots use
`vitnet.explorer-snapshot.v1`. `bundle.json` records original index/identity
fingerprints, snapshot/offset hashes and counts. `offsets.bin` contains
little-endian row-start offsets plus the original file-length sentinel.
The bundle generation fingerprints the original identities/index and prepared
snapshot, so changed projections do not reuse a stale browsing generation.

Startup checks schema, generation, snapshot hash, original index hash and file
shapes. `explore verify` additionally hashes the offsets and complete original
identity payload and validates its record count. Live queries reject detected
input length/modification or graph-generation drift. These are immutable local
evidence contracts, not a sandbox against another process deliberately
rewriting files while preserving their metadata.

### Read-only local APIs

All endpoints below use authenticated JSON POST, the existing body/header
budgets, exact Host/Origin checks, cancellation and one-expensive-query limit.
No client-supplied filesystem path is accepted.

| Endpoint | Action | Body fields after `request_id` and bundle `generation` |
| --- | --- | --- |
| `/api/datasets` | `catalog` | None |
| `/api/records` | `records` | `dataset`, optional `contains`, `filters`, `after`, `limit` |
| `/api/rows` | `ranked_rows` | Optional `contains`, `stream`, `assembly`, `owner`, `family` or `family_record`, `accounted_only`, `min_bytes`, `max_bytes`, `exact`, `after`, `limit` |
| `/api/relations` | `related` | Optional exact `assembly`, `package`, `target`, `after`, `limit` |
| `/api/value` | `record_value` | `dataset`, `ordinal`, optional `path`, `start`, `key` |
| `/api/value` | `identity_value` / `source_value` | `ordinal`, optional `path`, `start`, `key` |
| `/api/value` | `identity_shape_value` | `ordinal`, optional `path`, `start`, `key` |
| `/api/value` | `incoming_edge_value` | `graph`, decimal-string `node_id`, target-local `ordinal`, optional `path`, `start`, `key` |

`/api/query` remains a compatible entry point for these actions. Record
ordinals/cursors accept unsigned numbers or decimal strings; returned record
ordinals/cursors are decimal strings. `path` uses child ordinals (array indices,
or lexicographically ordered object properties), not property-name or filesystem
paths. `key: true` reads the selected object's property name. `start` is a
child index or UTF-8 byte offset; `next_start: null` ends a value. Record pages
provide `next_after`, `scanned` and `stop_reason`; only `complete` establishes
an exhausted search. A partial empty page can still have a continuation.

Ranked `after` is a **rank position**, not an identity ordinal. Responses retain
the original row ordinal, `order: "bytes_desc_ordinal_asc"` and a complete
pre-text-filter `scope` denominator. `family_record` is an ordinal in
`generic_families`, mutually exclusive with `family`, and avoids client-side
truncation or spelling guesses. Legacy bundles without `ranking` return an
explicit unavailable diagnostic. Graph search additionally accepts `limit`
from 1 to 50 (default 50), allowing progressive page filling without skipping
surplus matches. Inventory rows expose bounded scalar `fields` plus `capture`
flags; `fields_truncated` identifies shortened display values and
`upstream_truncated` marks already omitted original string text.

`ranking.bin` contains 16-byte little-endian `(bytes, original ordinal)` pairs.
Its descriptor and snapshot participate in the bundle generation. Preparation
uses bounded sort chunks and 16-way merge passes. Opening checks count, length,
fingerprint and strict byte/ordinal ordering; full verification also compares
every pair against its original identity, proving complete permutation.
Sorted `scopes` records support binary-search denominator lookup beyond the
overview top-N; `assembly_links` retains complete recorded package origins.

`bundle.json`'s additive `datasets` descriptors record counts, lengths and data/
offset hashes. Each `catalog_<name>.offsets` file has little-endian u64 row
starts plus a length sentinel. All dataset fingerprints participate in the
bundle generation through the snapshot's catalog. Startup verifies catalog
hashes/offsets and recomputes the content generation; `explore verify` also
decodes every full inventory record. Live readers reject modification drift.

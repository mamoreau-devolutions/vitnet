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
aggregates and writes an ordinal-to-offset sidecar. It does not copy the identity
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

`--evidence` uses the evidence schema but supplements inventories, generator
descriptors and diagnostics, not source matching or compiler artifact imports.
Source declarations and mappings belong in the original attribution import.
Supplemental package routes are local inventory evidence, not proof of the
actual publish-time dependency graph. Conflicting resource/package identities
fail explicitly. At most sixteen inventories and three selected witnesses are
accepted. Comparison requires a separate before index; absent physical binary
measurements remain unknown rather than zero.

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

Click an icicle stream or partition to zoom, use its breadcrumb to zoom out,
then inspect scoped contributors. The partition table provides a keyboard/text
equivalent. Offline filters search only the exported subset and explicitly
label preview-based matches; live filters use complete cached identities and
located assembly evidence.

Graph arrows point **retainer to retained**. Search/select a node, expand its
immediate retainers, then select an upstream row to follow it. Each page replaces
the current sheet instead of accumulating an unbounded graph. Reset/collapse
releases the sheet; a bundled witness selects its own graph generation.
Incomplete witness stops, cycles, missing nodes and zero-in-degree root
candidates remain explicit.

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
| Search batch | 100,000 scanned records/slots or 1.5 seconds |
| Root traversal | 12 levels, 3 paths, 5,000 visits, 25,000 examined edges, 1.5 seconds |
| Connections / expensive queries | 4 / 1 |

Query deadlines are cooperative checkpoints, not hard real-time guarantees.
Disk access or a single source lookup can exceed a checkpoint. Text searches
can require many batches: **Next / continue scan** remains available even when
an incomplete batch returns no matches. Whole-cache live rows are ordered by
cache ordinal, not global byte rank; the snapshot's top contributors are
byte-ranked deterministically.

Layout uses a worker with bounded layered placement and no continuous force
simulation. Cancel signals the backend and invalidates stale UI results;
switching views also cancels pending work. Results and worker messages from old
requests cannot repopulate a newer sheet.

Only Methods, Types and Blobs are additive. Method body/GC/EH, resources,
metadata lower bounds, generic and generator projections overlap those totals.
Complete aggregate sums use the verified cache. Displayed top-N records and
inventories are capped separately, with full counts and remaining bytes visible.
Provenance/diagnostics and each comparison evidence-change list show at most
the first 100 records, with full counts retained; text fields are
bounded previews. Use the original attribution reports for omitted detail.

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

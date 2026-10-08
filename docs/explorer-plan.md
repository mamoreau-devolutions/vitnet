# Bounded explorer implementation plan

The user approved a navigable, scale-safe investigation workspace. This plan
implements both a portable HTML snapshot and live local exploration. No existing
cache generation, daemon, branch or unrelated working-tree change is replaced.

## Delivery and architecture

1. `vitnet explore prepare INDEX --bundle DIRECTORY` streams and verifies the
   complete attribution identity cache once. Persist compact ordinal-to-offset
   lookup, complete summary aggregates and bounded display projections atomically.
   The bundle references the original immutable index; it does not duplicate DGML
   or raw application inputs. Optional supplemental evidence adds explicitly
   labelled resource/package inventories. Optional before evidence supplies a
   controlled comparison, and selected nodes supply small offline witnesses.
2. `vitnet explore export BUNDLE --html FILE` creates a self-contained offline
   report with bundled CSS/JavaScript, bounded summaries, contributor inspection,
   resource/duplicate inventories, generic/generator views, package routes and
   selected retention witnesses. Missing live capabilities explain their limits.
3. `vitnet explore browse BUNDLE` hosts those same assets on an ephemeral IPv4
   loopback port. A random per-session capability is passed in the URL fragment,
   never the HTTP query string. Only authenticated, origin-checked, bounded
   read-only query APIs are exposed. No filesystem or process-launch API exists.
   Existing named-pipe daemon behavior remains unchanged.
4. `vitnet explore verify BUNDLE` explicitly checks bundle and input integrity.
   Startup validates schemas, shapes, recorded index identity and file lengths;
   numeric cursors and graph generations are guarded.

## Budget and rendering contracts

- Snapshot JSON: at most 8 MiB; request body: 16 KiB; API response: 2 MiB.
- At most four connections and one expensive query at a time; no unbounded queue.
- Tables: page up to 100 rows, with bounded previews and stable numeric cursors.
- Search: bounded scan batches and deadlines, never a promise of instantaneous
  global search. Empty partial pages retain their cursor and stop reason.
- Graph queries: at most 50 incoming/search results per request; three witnesses,
  depth 12, 5,000 visits, 25,000 examined edges and a 1.5-second deadline.
- Rendering: at most 200 graph nodes and 500 edges. Layered worker layout,
  explicit reset/collapse, no perpetual simulation or growing result history.
- Cancellation signals the backend traversal and invalidates stale UI responses.
- Complete aggregates reconcile to additive totals. Top-N omissions, lower-bound
  metadata, overlapping inventories, missing source and physical evidence remain
  explicit. No graph degree or candidate join becomes fabricated byte ownership.

## UX direction

Use a restrained, system-font measurement workbench: navigable budget diagram
and compact tables on the left, an evidence inspector on the right. Source,
retention and amplification are separate concepts, not similarly styled claims.
The graph is an expandable bounded witness sheet, not a whole-graph force cloud.
Use responsive stacking, native controls, keyboard focus and accessible text
equivalents for every chart. All evidence is treated as untrusted text.

## Verification

Direct synthetic contracts cover summary conservation, non-additive rows,
ordinal lookup, Unicode previews, corrupt and stale bundles, absent evidence,
atomic output, pagination boundaries, graph caps and cooperative cancellation.
HTTP contracts cover authentication, origin/host restrictions, methods, request
and response budgets, error propagation, concurrency, cancellation and shutdown.
Browser checks cover offline and live flows, source selection, partial searches,
resource/generic/comparison states, graph expansion/reset, stale requests,
keyboard/mobile layout, DOM bounds and repeated interaction.

Run workspace tests, strict Clippy, formatting and dependency policy. Exercise
the unchanged large local indexes, measure preparation/server/browser memory,
query latency and main-thread responsiveness, and retain private measurements
outside Git. Any unverified responsiveness target is reported as such.

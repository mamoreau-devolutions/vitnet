# Evidence-backed bloat investigations

The Opportunities view asks what to investigate, not what can safely be deleted.
It ranks complete captured identity cohorts rather than just individual large
methods. The design and seven acceptance goals are versioned in
[the implementation plan](opportunity-analysis-plan.md). Controlled rebuild
experiments and predicted savings are deliberately outside this report.

## Capture, import and prepare

Collect the same build's MSTAT, managed assemblies, PDBs, package assets, binlog
and generated output directories using the [read-only collector](evidence-collector.md).
For a future build, enable `EmitCompilerGeneratedFiles`; keep generated output
under `obj` or outside source glob roots. Microsoft's
[SDK property reference](https://learn.microsoft.com/en-us/dotnet/core/project-sdk/msbuild-props#generated-file-properties)
documents that switch and `CompilerGeneratedFilesOutputPath`. vitnet does not
build the application or execute its analyzers to obtain evidence.

The collector's existing `--generated-root` accepts captured output. Binlog
output-directory declarations are also read; analyzer references alone do not
prove execution. `generator_runs` distinguish references, output capture,
unknown versions, build routes and output/PDB checksum trust. Execution is
`not_observed` unless separate execution evidence is actually available.
`generator_links` preserve supplied input-symbol assertions and lower-confidence
partial-attribute or `#line` candidates. Neither is runtime reachability.

A supplied `vitnet.generator.json` in the generated directory can identify the
emitter and input symbols:

```json
{"schema":"vitnet.generator.v1","name":"Example.Generator","version":"1.2.3","input_symbols":["Example.Widget"]}
```

These are assertions, not automatically verified generator telemetry.

```powershell
vitnet --memory-limit 2GiB attribution import .\evidence.json --index .\build-index
vitnet --memory-limit 2GiB explore prepare .\build-index --bundle .\opportunity-bundle
vitnet --memory-limit 2GiB explore browse .\opportunity-bundle --open
```

New imports write hashed `symbols.ndjson` and compact `symbols.idx` sidecars.
The MSTAT visitor resolves artifact-local ECMA-335 TypeRef/TypeSpec and
MemberRef/MethodSpec/definition tokens, preserving method signatures and generic
arguments. Lookup uses the complete **stream and raw-name hash**, not a displayed
prefix or original managed assembly token number. Conflicting candidates remain
ambiguous; unsupported forms are explicit. Spelling fallbacks remain labelled
candidates. A resolved native owner still does not establish that current
source is identical to the compiled build.

Old indexes remain readable but do not acquire typed evidence by fiction.
Reimport the original MSTAT into a new directory to gain typed joins. Old bundles
must be prepared again to gain opportunity catalogs. Missing capture is unknown,
not an empty investigation result.

## Connected terminal and browser workflow

```powershell
vitnet explore opportunities .\opportunity-bundle --limit 20
vitnet explore opportunities .\opportunity-bundle --kind generic_family
vitnet explore budgets .\opportunity-bundle --dimension assembly
vitnet explore budgets .\opportunity-bundle --dimension package --target 'net10.0/win-x64'
vitnet explore inspect .\opportunity-bundle 0 --dataset opportunities
vitnet explore inspect .\opportunity-bundle 123 --view source
vitnet explore inspect .\opportunity-bundle 123 --view symbol
vitnet explore retention .\opportunity-bundle 456 --graph scan_index
```

Finding examples contain original contributor ordinals; retention takes a
**compiler graph node ID**, which is a different identifier. In the browser,
open an example's source/token evidence, or use its complete identity for an
exact graph search. Inspect a selected node's bounded original witnesses,
source anchors, registration-annotation candidates and alternate incoming edges.
Truncated labels never establish an exact source join. Primary/Secondary
conditions and query incompleteness remain visible; a shortest witness is not
a sole-removal prerequisite.

The overview holds at most 40 findings/budgets. **All data** retains every
prepared `opportunities`, `budgets`, `opportunity_coverage`, `generator_runs`
and `generator_links` record with nested-field and full-string pagination.
CLI inventory paging and generation-pinned continuations use the same backend.
`--view symbol` pages the complete captured token candidates and signatures.
Authenticated REST aliases `/api/opportunities` and `/api/budgets` accept
`records` queries for their matching datasets; `/api/retention` accepts
`annotated_why`. `/api/value` supports `symbol_value` in addition to existing
record/source/shape value queries.

## Interpret the accounting tiers

- Assembly budgets partition each native stream by association tier, including
  ambiguous and unmapped buckets. Package budgets reconcile **separately within
  each target**; uncertain multiple package origins stay in a shared bucket.
- Methods, Types and Blobs are additive producer accounting. Specialized
  resources/RVA/frozen data and metadata lower bounds overlap those streams.
  Metadata's unowned or upstream-omitted assembly bytes stay in a separate
  remainder. Never add projections, targets or findings to the native total.
- Generic families report identity multiplicity and canonical-sharing markers.
  They are not counts of unique machine-code bodies or C# instantiations.
  Compiled-XAML, serializer, async and tooling cohorts are generic literal-name
  hypotheses unless stronger captured ownership exists.
- Generated-declaration cohorts retain emitter names and the source-association
  tier. Trigger annotations and captured output hashes do not prove exclusive
  byte ownership, generator execution or that an output is removable.

All proposed savings are `null`. Confirm product requirements and validate a
controlled same-configuration build change before making a savings claim.

## Connected investigation lenses

The Investigate tab connects measured owner accounting to XAML cohorts,
serializer declarations, repeated context roots, generic arguments,
expansion costs, applied reflection annotations, captured metadata strings,
and bounded representative retention. It never determines whether a feature
is required or predicts reclaimed bytes. The personal investigation queue is
not implemented.

```powershell
vitnet explore lenses .\bundle xaml
vitnet explore lenses .\bundle serializers --assembly Product.Core
vitnet explore lenses .\bundle repetitions
vitnet explore lenses .\bundle arguments --contains Product_Model
vitnet explore lenses .\bundle costs
vitnet explore lenses .\bundle reflection
vitnet explore lenses .\bundle strings
vitnet explore footprint .\bundle --assembly Product.Core --namespace Product.Models
vitnet explore cohort-retention .\bundle --ordinal 12,35 --graph codegen_index
```

All lens catalogs retain complete captured records and original native
example ordinals. Table fields are previews; use `explore inspect --dataset`
or All data to navigate complete arrays and text. Owner ledger rows partition
native identities once by association tier. Feature selectors intersect;
namespace selection includes dot-boundary descendants. Project selection
uses an explicitly captured textual assembly hint, not evaluated project
ownership. Feature scans expose partial ranges and generation-bound cursors;
the CLI aggregates disjoint batches up to its configured deadlines.

Generic argument projections deduplicate repeated/nested arguments within
each native identity, but different arguments overlap. Canonical markers are
not unique method-body counts. Methods accounting is not isolated instruction
body size; family-specific dictionary slot demand remains unknown. Context
root repetition is textual evidence, not proof of duplicate artifacts or
equivalent options. Source aliases and compiled/source drift remain uncertain.

XAML document class matching is a candidate, not a compiler input/output link.
Source capture preserves annotation targets and original XAML class, keys,
includes and hashes; it never opens include URLs. Older captures expose
missing documents/parameter annotations explicitly. Annotation-associated
footprints describe declaring owners, not the annotation's preserved target set.

Metadata string roles use retained preview text and remain lexical candidates.
New metadata imports retain the selected log assembly/namespace/type context;
legacy reports leave ownership unknown. Largest-string selection remains
upstream top-N, and truncated suffixes cannot be recovered. Lower-bound bytes
overlap the native Metadata/Blobs totals.

Authenticated REST aliases:
`/api/lenses` (`records` on `lens_*`, or bounded `lens_detail`),
`/api/footprint` (`feature_footprint`), and
`/api/cohort-retention` (`cohort_retention`).
They preserve request generation checks, cancellation, resource bounds and
typed diagnostics. Oversized detail records require `record_value` pagination.
Representative retention uses at most three identity seeds and three exact
label matches per seed. Original witnesses, incoming alternatives, annotations,
search continuations and query stops remain inspectable; label matches do not
prove identity-to-node equality or sole retainers.

## Local feature and capability policy

Use `explore prepare --opportunity-policy .\policy.json` to supplement generic
defaults without embedding application-specific assumptions in vitnet:

```json
{
  "schema":"vitnet.opportunity-policy.v1",
  "rules":[{
    "id":"shipping-debug-ui",
    "title":"Debug UI in a shipping build",
    "kind":"unexpected_feature",
    "contains":["DebugConsole"],
    "assemblies":["Product.Debugging"],
    "investigation":"Confirm shipping policy and trace the registration retaining this UI."
  }],
  "capabilities":[{
    "id":"parallel-crypto",
    "title":"Parallel cryptographic implementations",
    "assemblies":["Crypto.Legacy","Crypto.Current"],
    "investigation":"Identify required algorithms, callers and compatibility contracts before consolidating."
  }]
}
```

Text selectors are case-sensitive literals, not executable code or regexes.
Exact record filters for opportunities and budgets validate their top-level
field names against the report schema or complete captured extension fields;
a misspelled field fails explicitly instead of looking like an empty partition.
Extension-field discovery is bounded and fails with a resource diagnostic if
support cannot be established within the query budget.
Within a rule, any text selector and any assembly selector may match; nonempty
text and assembly selector lists must both match. A capability candidate requires
at least two distinct declared assemblies with captured additive bytes.
Coexistence does not prove redundant behavior. Policies have bounded rule/text
sizes and reject unsupported versions, duplicate IDs and empty selectors.

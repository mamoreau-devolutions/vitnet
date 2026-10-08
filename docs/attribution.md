# From NativeAOT bytes to build and source evidence

The `attribution` commands connect an accounting artifact to a captured build,
dependency routes, declarations, generated code, retention witnesses, generic
shapes and embedded assets. They are generic: no application-specific names,
registration catalogues or generator rules are built into the tool.

## Capture and import once

Build the optional [local evidence collector](evidence-collector.md). Collection
reads existing artifacts only; it never builds the analyzed project, runs its
generators or executes its application.

```powershell
Push-Location tools\vitnet-evidence
dotnet restore --locked-mode --nologo --verbosity quiet
dotnet build --no-restore --nologo --verbosity quiet
Pop-Location

dotnet tools\vitnet-evidence\bin\Debug\net10.0\vitnet-evidence.dll `
  --output D:\evidence\before.json --label "before change" `
  --source-root D:\work\sample --binlog D:\build\before.binlog `
  --assets D:\work\sample\obj\project.assets.json `
  --assembly D:\build\Sample.Core.dll `
  --generated-root D:\build\generated `
  --metadata D:\build\sample.metadata.csv --mstat D:\build\sample.mstat `
  --scan-index D:\indexes\before-scan --binary D:\build\sample.exe

vitnet --memory-limit 2GiB attribution import D:\evidence\before.json `
  --index D:\evidence\before-index
vitnet attribution report D:\evidence\before-index --top 25
```

All input switches except `--output` are optional. Missing evidence is unknown,
not zero. Managed assemblies, assets manifests, generated output, PDBs and native
binaries should be from the same build; a current source checkout alone does not
establish that. The collector records historical binlog revisions separately
from the current checkout and diagnoses available portable-PDB checksum drift.
Keep snapshots of artifacts for controlled comparison.

Import produces an immutable `vitnet.attribution-index.v1` directory containing
`index.json` and full coalesced `identities.ndjson`. It streams identities from
MSTAT once; later queries do not reread raw MSTAT or the source tree. It reuses
existing graph index generations, never rebuilds them. Imports fail atomically;
choose a new directory rather than overwriting a snapshot.

For a no-.NET demonstration:

```powershell
vitnet attribution import docs\examples\attribution-evidence.json --index demo-index
vitnet --format json attribution report demo-index
vitnet attribution verify demo-index
```

The tiny demonstration deliberately has no accounting or native artifact.
Its diagnostics and null sizes are part of the example, not parsing failures.
Hand-authored `vitnet.evidence.v1` manifests follow
[`model.rs`](../crates/vitnet-attribution/src/model.rs); unknown fields and
unsupported versions are rejected. Explicit `mappings` are supplied assertions
with a required `basis`, not independently verified ownership.

## Eight investigation surfaces

| Question | Evidence/output |
| --- | --- |
| Is this the build I think it is? | Provenance, available artifact fingerprints, recorded/current revision facts and diagnostics; `attribution verify` checks live drift and cache integrity. |
| Which dependency brought this in? | Assembly/package byte associations and target-specific shortest direct-to-transitive routes, reverse dependents, missing dependencies and cyclic-target flags. |
| Where should I look in source? | Contributors and metadata type rows list declarations/partials, file/line, attributes and generated emitter; `attribution source INDEX EXACT_IDENTITY` preserves all matching stream identities and reports live source drift. |
| Is generated code amplifying a small input? | Generator input/file/declaration counts and separately asserted/candidate accounted bytes. Unknown inputs/versions remain explicit. |
| Why is the compiler retaining it? | `attribution explain` preserves original graph paths/reasons and alternate incoming edges while adding source anchors and possible annotation-based mechanisms. |
| Is generic specialization multiplying shapes? | Nested type/method argument groups, distinct shape counts, canonical-sharing markers and managed kind candidates, with normalization collisions labelled ambiguous. |
| Which actual assets are embedded? | Manifest containers separately from child asset inventory, lengths, storage and SHA-256 duplicate groups; equal length alone is not duplicate proof. |
| Did a controlled edit improve the native output? | `attribution compare` separates physical PE file/section deltas, full MSTAT identity differences, metadata lower bounds, source/package/config facts and selected retention witnesses. |

```powershell
vitnet --format json attribution report D:\evidence\before-index --contains Widget --top 50
vitnet --format json attribution source D:\evidence\before-index "Sample_Core_Widget__Run"
vitnet --format json attribution explain D:\evidence\before-index 12345 `
  --graph scan_index --max-visited 100000 --max-edges 500000
```

`--contains` filters displayed MSTAT contributors, not complete byte coverage.
Top-N bounds display rows; complete package/generator/duplicate group counts and
full accounted mapping coverage remain available. Routes exceeding their memory
share fail explicitly rather than silently truncating the dependency chain.

## Controlled comparison

Capture and import a second bundle after one deliberate change. Retain the
baseline sources/artifacts or expect source-drift diagnostics; a changed baseline
MSTAT/native binary is rejected because it invalidates the measurement.

```powershell
vitnet --memory-limit 2GiB --format json attribution compare `
  D:\evidence\before-index D:\evidence\after-index --top 50

vitnet --format json attribution compare D:\evidence\before-index `
  D:\evidence\after-index --before-node 12345 --after-node 23456 `
  --graph scan_index
```

Node IDs are generation-scoped. Select the corresponding node separately in each
graph; the paired switches assert a correspondence, not an automatic identity
join. Selected witness comparison includes incoming-edge deltas and preserves
the paths/reasons. A generation change alone is not a graph diff.

Physical file/section deltas require a PE native binary in both bundles. Missing
evidence yields null, and architecture/toolchain/configuration changes prevent
treating the run as a controlled causal experiment. Logical MSTAT sizes are not
physical section sizes; specialized streams overlap `Blobs`. Metadata totals
are lower bounds; `complete_dimensions=false` means group deltas use projected
lists and are not complete additions/removals. Displayed assembly association
deltas are likewise explicitly only visible top-group differences.

## Trust and resource limits

Opaque producer-name prefix matching is a **candidate**, never verified source or
package ownership. Exact resource assembly identities and explicit assertions
are separately labelled. Raw identity hashes preserve distinctions when display
Unicode decoding is lossy; those displays are not source-matched as exact.
Managed-name source matches do not override revision/PDB-checksum diagnostics.

Compiler reachability does not prove runtime execution: a lazy factory can
retain code without running it at startup. Conjunctive graph dependencies and
incomplete query budgets remain visible. Neither a witness nor a content hash
predicts independently reclaimed native bytes.

The Rust `--memory-limit` partitions JSON, identity rows, parsing and aggregate
state. Manifest JSON is capped at the smaller of one eighth of that limit and
256 MiB; identity rows at one sixty-fourth and 32 MiB. A published index must fit
the same manifest share. Collector limits are documented separately. These are
bounded data budgets, not a hard OS process-memory quota.

Supported source evidence is C# syntax and portable PDBs; native PDBs remain
explicitly unsupported. Resources support embedded containers, default
`.resources` v2 and Avalonia binary-index v2. Physical inspection supports PE,
not ELF or Mach-O. Unsupported readers do not invent empty inventories.

## Validation boundaries

`cargo test --workspace` exercises synthetic end-to-end imports, source and
generator associations, dependency-route budgets, immutable retention queries,
resource hashes and independent physical/logical comparisons. The collector's
`smoke.ps1` and `regression.ps1` additionally exercise actual SDK-produced
assemblies, portable PDBs, binlogs and supported resource containers without
executing the fixture application.

The `attribution_evidence` fuzz target covers generic-shape parsing and strict
evidence-schema validation with a 64 KiB input cap. It is compiled by CI.
Sanitizer/coverage-guided fuzzing requires the usual `cargo-fuzz` environment;
native uninstrumented smoke runs do not establish sanitizer coverage.

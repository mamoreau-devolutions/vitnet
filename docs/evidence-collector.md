# Optional local .NET evidence collector

`tools\vitnet-evidence` is an SDK-style **net10.0** console application.
It writes exactly the snake_case `vitnet.evidence.v1` interchange contract in
`crates\vitnet-attribution\src\model.rs`. The Rust CLI remains independent of
.NET. This collector does not perform retention queries, native accounting,
graph ingestion, savings estimates, or controlled-build comparison.

## Build and run

From the repository root, in PowerShell:

```powershell
Push-Location tools\vitnet-evidence
dotnet restore --locked-mode --nologo --verbosity quiet
dotnet build --no-restore --nologo --verbosity quiet
dotnet bin\Debug\net10.0\vitnet-evidence.dll --help
Pop-Location
```

The collector-local `global.json` selects stable SDK **10.0.401**, allowing
stable patches only. Enter that directory before building; the repository's
other tooling and installed 11 RC SDK are not changed. .NET 10 SDK/runtime were
available during validation (runtime 10.0.12).

Example for already-existing local artifacts; create the output directory first:

```powershell
dotnet tools\vitnet-evidence\bin\Debug\net10.0\vitnet-evidence.dll `
  --output .\evidence.json --label "local build snapshot" `
  --source-root D:\work\sample `
  --binlog D:\work\sample\build.binlog `
  --assets D:\work\sample\obj\project.assets.json `
  --assembly D:\work\sample\bin\Release\net10.0\Sample.dll `
  --generated-root D:\work\sample\obj\generated `
  --binary D:\work\sample\bin\Release\net10.0\Sample.exe
```

`--output` is required. `--assets`, `--assembly`, `--binary`, and `--pdb` may be
repeated. Other inputs are single-valued. `--label` is opaque.
`--revision` is a **caller-supplied build-artifact label**, never the current
source revision, and is not applied to current source/generated artifacts.
Paths in evidence are absolute.
When multiple assets manifests are supplied, package target keys are qualified
by their manifest path (`path::TFM/RID`), so two projects' direct/transitive
dependency graphs cannot silently merge. Recorded Csc reference identities also
carry resolved package ownership when available; full managed type/resource
inventories still require explicit `--assembly`.

The output file is UTF-8 JSON, flushed and atomically renamed from a
same-directory `.pending` sibling. Existing output is retained on collection,
format, or budget failure. Output must not alias an input. The output directory
must already exist. Successful stdout is a JSON summary; failure stdout is a
JSON `error` object. Stderr uses repository-style `code: message` diagnostics.
Exit codes: **0** collected (inspect limitations), **2** malformed/unsupported
supplied reader format or arguments, **3** I/O, **4** resource budget.
Unavailable files yield explicit diagnostics, not inferred empty inventories.

## Read-only local behavior

Collection never builds/evaluates an analyzed project, invokes its generators,
executes its application, uses `Assembly.Load`, deserializes application
resource objects, contacts a package feed, or uploads private inputs. Roslyn
parses syntax; `PEReader`/`MetadataReader` inspect data. Binlog replay is event
**decoding**, not execution. No archived binlog source zip is extracted or
interpreted. Response files are not opened. SourceLink is not downloaded.

The optional local Git commands are `rev-parse` and `status`, with optional
locks and executable fsmonitor disabled; they do not change the checkout.
No repository source is modified. Restoring/building the **collector itself**
can access configured NuGet sources; use a pre-restored collector offline for
private collection. `smoke.ps1` builds only the synthetic fixtures it creates.

## Collected evidence and interpretation

| Surface | Supported evidence | Boundaries / explicit unknowns |
| --- | --- | --- |
| Binlog | Official StructuredLogger record reader; project-start/evaluation revision, SDK/toolchain/configuration properties; Csc output/source/reference/analyzer routes; local input identities read from metadata | Properties must have been recorded. Missing revision/Csc inputs and incomplete commands are diagnosed. A listed analyzer is not proof it executed. Framing, CRC, truncation and unsupported records fail. |
| Assets | Resolved `project.assets.json` versions 3 and 4; each TFM/RID target's package `id/version`, direct declarations, resolved dependency `id/version` keys, compile/runtime assembly-path routes | Cycles, missing dependencies/direct targets, absent direct declarations and project-type libraries are explicit. Directness is not guessed from graph indegree. Library IDs use NuGet case-insensitive resolution. Multiple assets files retain per-file provenance; identical target names are not proof of identical projects. |
| Managed PE | Assembly identity (version/culture/public-key token), MVID, full nested/generic metadata type names, enum/value/reference kind and method+field+property+event counts | Metadata counts include accessor methods; they are not source/member occurrence counts. Supplied netmodules/non-managed assemblies fail. |
| Source | Roslyn type, enum, delegate, method, constructor, operator, property/indexer, event, field and enum-member declarations; type/method partial markers; textual attributes; physical file lines; actual file SHA-256 | ``Namespace.Outer`1+Inner`1`` metadata-style names preserve per-type arity. No semantic project compilation. Compiler defines/language options are used when recorded. Otherwise default Roslyn parsing is not evidence for inactive conditional branches. A literal csproj AssemblyName/nearest directory is only a hint; imports, conditions, globs and linked files are not evaluated. |
| Generated source | Same declarations/hashes; explicit provenance below; conventional compiler output directory emitter candidates; analyzer assembly versions when uniquely routed | Directory names are candidates, not verified emitter ownership. Version, assembly and input symbols remain unknown when unavailable. Ordinary source-root scanning does not prove a `.g.cs` file's emitter. |
| Portable PDB | Adjacent/local CodeView PDB or embedded portable PDB; identity matching; document path/algorithm/checksum facts; nonhidden sequence-point source records; associated metadata type/member names | Standalone/mismatched PDB type/member/assembly are unknown. SHA-1/SHA-256 checksums are compared with available files; `pdb.document_drift` records mismatches without discarding the compiled snapshot. Native/MSF PDB signatures yield `pdb.native_unsupported`, **not** portable-PDB fallback success. Custom debug/source records are not used as ownership. |
| Resources | Embedded managed manifest containers and hashes; public Avalonia binary-index-v2 asset sizes/hashes; default .resources-v2 reader raw serialized entries and type labels | Container and child bytes overlap: never sum both. `.resources` entries include their serialized representation, not equivalent decoded cross-format content. No custom reader/application objects are instantiated. External resources are unknown. Corrupt supported formats fail; legacy/future versions/custom readers have explicit unsupported diagnostics and only container evidence. |
| Native PE | PE32/PE32+ file bytes, architecture, each section's physical `SizeOfRawData` and `VirtualSize` | Physical file size includes headers/alignment/overlay/certificates and is not the section sum. COFF objects, ELF, Mach-O and malformed PE inputs fail; unknown machine codes are labelled. |

`--metadata`, `--mstat`, `--scan-index`, `--codegen-index` declare bounded
**opaque artifact handles** of those kinds, not successful parsing or graph
ingestion. `artifact.validation_deferred` makes that distinction explicit.
Their Rust format readers must validate them before analysis. The collector
does not claim to recognize corrupt opaque formats. Source, generated, assembly,
binary, binlog, assets and available PDB artifacts are also declared; Rust
computes actual available file fingerprints. No BLAKE3 is invented here.

Compiler `SourceRevisionId` is stored under `binlog.property:...:SourceRevisionId`,
and recorded MSBuild `SourceRoot` item `RevisionId` metadata under
`binlog.source_revision:<binlog>:<root>`,
separately from `source.current_revision:<root>` /
`source.current_dirty:<root>`. Git status is scoped to the source root and
respects ignore rules; ignored/untracked inputs are not proved by HEAD.
Neither recorded revision nor a clean Git status proves that input files match
the compiled build. Source SHA-256/PDB checksum drift diagnoses this directly.
Old source drift is useful snapshot evidence, not a claimed controlled-build
blocker; the Rust comparison layer makes raw MSTAT/binary drift decisions.

Attributes alone do not establish compiler roots or annotation-to-generator
causation. `evidence.root_annotations_unknown` is always explicit for inferred
roots. Verified compiler witnesses belong to the Rust graph layer.

### Optional supplied generator provenance

Put a `vitnet.generator.json` inside a `--generated-root` subtree:

```json
{
  "schema": "vitnet.generator.v1",
  "name": "Example.Generator",
  "version": "1.2.3",
  "assembly_path": "..\\Example.Generator.dll",
  "input_symbols": ["Example.Widget`1", "Example.Outer+Inner"]
}
```

It describes `.cs` files under its directory; the nearest manifest wins.
`assembly_path` is optional and resolved relative to the manifest.
`input_symbols` is optional; absent means unknown, not an inferred empty root
set. Present symbols are explicitly **supplied**, not independently validated.
Without a manifest, `<AnalyzerAssembly>\<GeneratorType>\file.cs` establishes only
a convention-based emitter candidate. SHA-256 always covers actual source bytes.

## Budgets

All values are positive decimal integers, maximum **2,147,483,647**.
Over-limit inputs fail rather than truncate, silently omit, or emit a partial
output. Apply smaller budgets before reading untrusted or unusually large input.

| Option | Default | Enforcement |
| --- | ---: | --- |
| `--max-file-bytes` | 134,217,728 (128 MiB) | Each distinct opened input; also textual project/Git output bound |
| `--max-total-bytes` | 1,073,741,824 (1 GiB) | Sum of distinct available input file lengths |
| `--max-files` | 10,000 | Distinct available files and visited directory entries (directories included) |
| `--max-records` | 1,000,000 | Emitted records, facts/diagnostics and decoded/visited syntax, binlog, metadata and dependency records |
| `--max-expanded-bytes` | 536,870,912 (512 MiB) | Each decompressed binlog and each embedded portable PDB's declared expanded size |
| `--max-resource-bytes` | 67,108,864 (64 MiB) | Each managed container/individual resource payload |
| `--max-output-bytes` | 268,435,456 (256 MiB) | Streamed evidence JSON before replacement |

JSON depth is limited to 64. Git provenance commands have a 30-second bound.
Directory scanning omits `.git`, `.svn`, `bin`, `obj`, `node_modules`, `.smoke`
children; point `--generated-root` directly at the desired generated subtree.
Reparse points/symbolic links are not followed.
These are input/output budgets, **not a hard OS process-memory quota**:
Roslyn and official decoders may allocate in proportion to bounded input.
Use OS isolation for hostile inputs. No large-file claim implies unlimited
decoding support.

## Validation

```powershell
pwsh -NoProfile -File tools\vitnet-evidence\smoke.ps1
pwsh -NoProfile -File tools\vitnet-evidence\regression.ps1
pwsh -NoProfile -File tools\vitnet-evidence\check-policy.ps1
```

This runs a synthetic source/partial/generic-type/assembly/generated-provenance/
manifest/.resources/Avalonia-resource/portable-PDB/native-PE/assets/binlog smoke.
The native PE is the SDK's synthetic fixture apphost; the fixture entry point
throws if executed, and is never executed. This is not a generated unit-test
suite. Fixture data is created only under ignored collector-owned `.smoke` and
removed on exit (`-Keep` preserves it for inspection). A prior `.smoke` directory
causes a refusal rather than deleting unrelated data.

Validation also exercised actual collector sources, managed assembly,
portable PDB and restored package assets. Repeatable malformed-input, resource
budget and atomic-preservation regression suites belong to the separate test
pipeline.

## Licenses and format provenance

All selected packages are **stable**, exact direct versions are bracket-pinned,
and `packages.lock.json` pins transitive versions/content hashes.
Roslyn 5.0.0 was deliberately selected instead of a newer release that depended
on a prerelease analyzer package. All listed dependency licenses are **MIT**;
package metadata/embedded license notices remain in NuGet artifacts.

| Package(s) | Version | Official source commit |
| --- | --- | --- |
| Microsoft.CodeAnalysis.CSharp, Microsoft.CodeAnalysis.Common | 5.0.0 | [dotnet/roslyn `6c4a46a`](https://github.com/dotnet/roslyn/tree/6c4a46a31302167b425d5e0a31ea83c9a9aa1d09) |
| Microsoft.CodeAnalysis.Analyzers | 3.11.0 | [dotnet/roslyn-analyzers `f2384e6`](https://github.com/dotnet/roslyn-analyzers/tree/f2384e61845314d0e8ad74cc0fe67d1bd4e9f102) |
| MSBuild.StructuredLogger | 2.3.246 | [KirillOsenkov/MSBuildStructuredLog `dd885a9`](https://github.com/KirillOsenkov/MSBuildStructuredLog/tree/dd885a9ee5f852029cb9e35bfdaea1db00adf75b) |
| Microsoft.Build.Framework, Microsoft.Build.Utilities.Core, Microsoft.NET.StringTools | 17.5.0 | [dotnet/msbuild `6f08c67`](https://github.com/dotnet/msbuild/tree/6f08c67f3ed838dccfbcdab91e6bebc54a26fd94) |
| Microsoft.Win32.SystemEvents, System.Configuration.ConfigurationManager, System.Drawing.Common, System.Security.Cryptography.ProtectedData, System.Security.Permissions, System.Windows.Extensions | 6.0.0 | [dotnet/runtime `4822e3c`](https://github.com/dotnet/runtime/tree/4822e3c3aa77eb82b2fb33c9321f923cf11ddde6) |

Package sources:
[Roslyn](https://www.nuget.org/packages/Microsoft.CodeAnalysis.CSharp/5.0.0),
[StructuredLogger](https://www.nuget.org/packages/MSBuild.StructuredLogger/2.3.246).
Repository/commit/license values above were read from restored official
`.nuspec` metadata, not inferred from package names. MSBuild utility
dependencies are bundled by the logger; no MSBuild build/evaluation API is
invoked by the collector.

Runtime APIs are official MIT-licensed .NET:
[System.Reflection.Metadata](https://learn.microsoft.com/dotnet/api/system.reflection.metadata),
[PEReader](https://learn.microsoft.com/dotnet/api/system.reflection.portableexecutable.pereader),
[portable PDB format](https://github.com/dotnet/runtime/blob/v10.0.12/docs/design/specs/PortablePdb-Metadata.md),
[ResourceReader.GetResourceData](https://learn.microsoft.com/dotnet/api/system.resources.resourcereader.getresourcedata).
`collector.metadata_provider` records the installed framework's informational
version/commit, rather than pretending the framework is a separately restored
package.

Avalonia container interpretation is independently implemented from only its
public official producer/reader definitions, pinned to **11.3.8**, commit
**6dd9eb473b74a56cc42e5bc118cfe918b48a940b** (MIT):
[AvaloniaResourcesIndex.cs](https://github.com/AvaloniaUI/Avalonia/blob/6dd9eb473b74a56cc42e5bc118cfe918b48a940b/src/Avalonia.Base/Utilities/AvaloniaResourcesIndex.cs)
and [AssemblyDescriptor.cs](https://github.com/AvaloniaUI/Avalonia/blob/6dd9eb473b74a56cc42e5bc118cfe918b48a940b/src/Avalonia.Base/Platform/Internal/AssemblyDescriptor.cs).
Only binary index version 2 is supported: int32 index length, int32 version and
count, BinaryReader UTF-8 string/int32 offset/int32 size entries, followed by
payload bytes. Equal/overlapping asset ranges are permitted by the producer's
deduplication; duplicate names and invalid ranges are rejected.
No private tooling or third-party proprietary implementation was used.

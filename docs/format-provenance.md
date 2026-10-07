# Format provenance

vitnet is a clean-room implementation. Sizoscope source, tests, fixtures,
comments, caches, and internal design are not inputs.

## NativeAOT metadata log (Phase 1)

The current pinned baseline is
[`dotnet/runtime@496f6f80ad5e02db89f238f2db288e53176b9027`](https://github.com/dotnet/runtime/tree/496f6f80ad5e02db89f238f2db288e53176b9027).
All links below include an exact commit, so future runtime changes cannot alter
the evidence used by this implementation.

- [NativeAOT build integration](https://github.com/dotnet/runtime/blob/496f6f80ad5e02db89f238f2db288e53176b9027/src/coreclr/nativeaot/BuildIntegration/Microsoft.NETCore.Native.targets#L260-L264)
  maps `IlcGenerateMetadataLog` to `--metadatalog:<path>.metadata.csv`.
- [The metadata-log writer](https://github.com/dotnet/runtime/blob/496f6f80ad5e02db89f238f2db288e53176b9027/src/coreclr/tools/aot/ILCompiler.MetadataTransform/Internal/Metadata/NativeFormat/Writer/NativeMetadataWriter.cs#L358-L396)
  emits `Handle, Kind, Name, Children`, one row per graph record. It writes an
  eight-digit lowercase hexadecimal handle, `HandleType.ToString()`, a display
  name, and a quoted children field.
- [The child visitor](https://github.com/dotnet/runtime/blob/496f6f80ad5e02db89f238f2db288e53176b9027/src/coreclr/tools/aot/ILCompiler.MetadataTransform/Internal/Metadata/NativeFormat/Writer/NativeMetadataWriter.cs#L401-L445)
  writes direct outgoing record references as space-separated lowercase
  hexadecimal handles and omits nulls. These are references, not exclusive
  ownership declarations.
- [Name escaping](https://github.com/dotnet/runtime/blob/496f6f80ad5e02db89f238f2db288e53176b9027/src/coreclr/tools/aot/ILCompiler.MetadataTransform/Internal/Metadata/NativeFormat/Writer/NativeMetadataWriter.cs#L374-L391)
  uses `\\` and `\"`, not RFC 4180 escaping. Values already surrounded by
  quotes bypass escaping under an explicit producer TODO. The decoder therefore
  supports producer escaping, embedded newlines, and doubled quotes without
  assuming the file is strict RFC 4180 CSV.
- [Current handle extraction](https://github.com/dotnet/runtime/blob/496f6f80ad5e02db89f238f2db288e53176b9027/src/coreclr/tools/aot/ILCompiler.MetadataTransform/Internal/Metadata/NativeFormat/Writer/NativeMetadataWriter.cs#L517-L532)
  masks the writer offset with `0x01FFFFFF`. The
  [current handle constructor](https://github.com/dotnet/runtime/blob/496f6f80ad5e02db89f238f2db288e53176b9027/src/coreclr/tools/Common/Internal/Metadata/NativeFormat/NativeMetadataReader.cs#L107-L120)
  packs the kind above those 25 bits.
- [The placed-record loop](https://github.com/dotnet/runtime/blob/496f6f80ad5e02db89f238f2db288e53176b9027/src/coreclr/tools/Common/Internal/NativeFormat/NativeFormatWriter.cs#L288-L304)
  captures the encoder size before `Save`, proving that handles contain record
  starts. `next_start - current_start` is exact for every non-final row; the
  final row has no logged end.
- [The metadata-size check](https://github.com/dotnet/runtime/blob/496f6f80ad5e02db89f238f2db288e53176b9027/src/coreclr/tools/aot/ILCompiler.Compiler/Compiler/MetadataManager.cs#L807-L825)
  occurs after writing the log and enforces `0x01FFFFFF`. An oversized failed
  build may therefore leave a complete log whose physical offsets wrap.
- [`e43fa441587b06904536f7cc4b79dded98d610f2`](https://github.com/dotnet/runtime/commit/e43fa441587b06904536f7cc4b79dded98d610f2)
  changed the offset from 24 to 25 bits. The
  [pre-change writer](https://github.com/dotnet/runtime/blob/e5ed253e38d3bf1414949924e1e69f43c8164d1b/src/coreclr/tools/aot/ILCompiler.MetadataTransform/Internal/Metadata/NativeFormat/Writer/NativeMetadataWriter.cs#L516-L531)
  uses `0x00FFFFFF`; vitnet detects legacy packed handles and applies the
  16,777,215-byte limit and `2^24` wrap period.
- The current kind numbers come from the
  [pinned `HandleType` enum](https://github.com/dotnet/runtime/blob/496f6f80ad5e02db89f238f2db288e53176b9027/src/coreclr/tools/Common/Internal/Metadata/NativeFormat/NativeFormatReaderCommonGen.cs#L87-L153).
  The [.NET 8 enum](https://github.com/dotnet/runtime/blob/5535e31a712343a63f5d7d796cd874e563e5ac14/src/coreclr/tools/Common/Internal/Metadata/NativeFormat/NativeFormatReaderCommonGen.cs#L87-L154)
  contains `ConstantBoxedEnumValue`; the
  [.NET 9 enum](https://github.com/dotnet/runtime/blob/9d5a6a9aa463d6d10b0b0ba6d5982cc82f363dc3/src/coreclr/tools/Common/Internal/Metadata/NativeFormat/NativeFormatReaderCommonGen.cs#L87-L153)
  instead contains `ConstantEnumValue`. Unknown future textual kinds remain
  parseable and default conservatively to the current layout.

Record-start/lower-bound interpretation follows the placed-record handle
contract and is deliberately reported conservatively: consecutive starts bound
the preceding record, but the log contains no end offset for the final record.
These points are encoded as explicit compatibility tests. The repository does
not contain or depend on a private producer corpus.

The producer structurally pools records and rewrites references to pooled
instances in the
[record visitor](https://github.com/dotnet/runtime/blob/496f6f80ad5e02db89f238f2db288e53176b9027/src/coreclr/tools/aot/ILCompiler.MetadataTransform/Internal/Metadata/NativeFormat/Writer/NativeMetadataWriter.cs#L169-L245).
Multiple parents can therefore reference one child. The producer defines no
exclusive owner column. vitnet's assembly/namespace/type ownership is explicitly
a reporting heuristic: it selects the nearest prior reference and then the
deepest context. Wrapped duplicate handles are inherently ambiguous because the
child token has no generation number.

Black-box validation used only the user-authorized local NativeAOT output and
did not copy it. It confirmed compatibility with multiline/bare-quote display
strings and the expected current packed-handle layout. No private row or string
is present in source, tests, fixtures, or documentation.

The streaming state machine, strict-mode recovery policy, ownership
tie-breaking, aggregation model, output schema, and comparison model are
independent vitnet designs. A strict backwards transition that cannot be a
25-bit rollover is rejected rather than guessed.

## NativeAOT MSTAT (Phase 2)

The MSTAT evidence baseline is
[`dotnet/runtime@2eb7113245f7c536ab876dca5e3533fb96c81bbf`](https://github.com/dotnet/runtime/tree/2eb7113245f7c536ab876dca5e3533fb96c81bbf).

- [`MstatObjectDumper.cs`](https://github.com/dotnet/runtime/blob/2eb7113245f7c536ab876dca5e3533fb96c81bbf/src/coreclr/tools/aot/ILCompiler.Compiler/Compiler/MstatObjectDumper.cs#L25-L29)
  identifies the current producer format as 2.2.
- [Assembly construction](https://github.com/dotnet/runtime/blob/2eb7113245f7c536ab876dca5e3533fb96c81bbf/src/coreclr/tools/aot/ILCompiler.Compiler/Compiler/MstatObjectDumper.cs#L46-L52)
  stores that logical version in the generated assembly version. It is
  independent of the ECMA-335 metadata-root version.
- [Stream emission](https://github.com/dotnet/runtime/blob/2eb7113245f7c536ab876dca5e3533fb96c81bbf/src/coreclr/tools/aot/ILCompiler.Compiler/Compiler/MstatObjectDumper.cs#L58-L205)
  defines the `Methods`, `Types`, `Blobs`, `RvaFields`, `FrozenObjects`,
  `ManifestResources`, and `DeduplicatedMethods` synthetic method bodies and
  their ordered token/integer fields.
- [PE construction](https://github.com/dotnet/runtime/blob/2eb7113245f7c536ab876dca5e3533fb96c81bbf/src/coreclr/tools/aot/ILCompiler.Compiler/Compiler/MstatObjectDumper.cs#L214-L257)
  appends the custom `.names` section used by 2.x name offsets.
- [`TypeSystemMetadataEmitter.cs`](https://github.com/dotnet/runtime/blob/2eb7113245f7c536ab876dca5e3533fb96c81bbf/src/coreclr/tools/Common/TypeSystem/MetadataEmitter/TypeSystemMetadataEmitter.cs)
  stores each synthetic stream through `MethodBodyStreamEncoder`.
- [`InstructionEncoder.cs`](https://github.com/dotnet/runtime/blob/2eb7113245f7c536ab876dca5e3533fb96c81bbf/src/libraries/System.Reflection.Metadata/src/System/Reflection/Metadata/Ecma335/Encoding/InstructionEncoder.cs)
  defines the `ldtoken`, `ldstr`, and shortest-form `ldc.i4` encodings.
- [`56ee31f0bd81fdf53c4eea50cf6016a3a545467c`](https://github.com/dotnet/runtime/commit/56ee31f0bd81fdf53c4eea50cf6016a3a545467c)
  introduced MSTAT 2.0 and moved mangled names from the size-limited `#US`
  heap into `.names`.
- [`59c1734be1da981f354d342097aa2ccbf1ed7ef9`](https://github.com/dotnet/runtime/commit/59c1734be1da981f354d342097aa2ccbf1ed7ef9)
  introduced 2.1 specialized RVA-field, frozen-object, and manifest-resource
  streams. The producer deliberately also retains those categories in
  `Blobs`; totals must not count both representations.
- [`9c3a1bcdffa60376cc758c3a7d7af11f4b1d82b2`](https://github.com/dotnet/runtime/commit/9c3a1bcdffa60376cc758c3a7d7af11f4b1d82b2)
  introduced 2.2 deduplicated-method groups.

MSTAT parsing is derived from these public producer contracts and ECMA-335 PE
metadata rules. Local large-file validation does not contribute private names,
tokens, or fixture bytes to the repository.

Tests construct a minimal PE/CLI metadata image and all seven record streams
independently in Rust. `mmap-guard` is MIT OR Apache-2.0 licensed and provides
the safe read-only mapping boundary used by the unsafe-code-forbidden
workspace. The parser itself contains no unsafe code and builds no managed
metadata object graph.

## NativeAOT DGML (Phase 4 statistics)

The NativeAOT baseline is the same pinned runtime commit above. General DGML
semantics were checked against
[`MicrosoftDocs/visualstudio-docs@653cd6e4ffe7e1ff69ba2c4eade3c29ed49a4336`](https://github.com/MicrosoftDocs/visualstudio-docs/commit/653cd6e4ffe7e1ff69ba2c4eade3c29ed49a4336).

- [NativeAOT build integration](https://github.com/dotnet/runtime/blob/2eb7113245f7c536ab876dca5e3533fb96c81bbf/src/coreclr/nativeaot/BuildIntegration/Microsoft.NETCore.Native.targets#L271-L275)
  maps `IlcGenerateDgmlFile` to scan and codegen DGML outputs.
- [The graph writer](https://github.com/dotnet/runtime/blob/2eb7113245f7c536ab876dca5e3533fb96c81bbf/src/coreclr/tools/aot/ILCompiler.DependencyAnalysisFramework/DgmlWriter.cs#L28-L46)
  emits the Microsoft DGML namespace, then `Nodes`, then `Links`.
- [Node emission](https://github.com/dotnet/runtime/blob/2eb7113245f7c536ab876dca5e3533fb96c81bbf/src/coreclr/tools/aot/ILCompiler.DependencyAnalysisFramework/DgmlWriter.cs#L104-L121)
  assigns dense zero-based decimal IDs and opaque labels.
- [Link emission](https://github.com/dotnet/runtime/blob/2eb7113245f7c536ab876dca5e3533fb96c81bbf/src/coreclr/tools/aot/ILCompiler.DependencyAnalysisFramework/DgmlWriter.cs#L124-L183)
  defines source, target, reason, and presentation stroke behavior, including
  empty root reasons and conditional dependency links.
- [Runtime parser tests](https://github.com/dotnet/runtime/blob/2eb7113245f7c536ab876dca5e3533fb96c81bbf/src/coreclr/tools/aot/DependencyGraphViewer/Tests/TestFileParsing.cs#L60-L130)
  establish dangling-link rejection and preservation of parallel links with
  distinct reasons.

The pull parser dependency is `quick-xml` 0.42.0, corresponding to
[`tafia/quick-xml@36a2c52a4f6c90878c3f60c3c3b5c62efaef28a9`](https://github.com/tafia/quick-xml/commit/36a2c52a4f6c90878c3f60c3c3b5c62efaef28a9).
The aggregation structures, memory charging, deterministic ranking, and
`vitnet.dgml-stats.v1` schema are independent vitnet designs.

## Evidence maintenance

Before changing a non-obvious format rule, record the public Microsoft runtime
producer path, commit hash, relevant lines, and an independently generated
minimal observation here. Unknown or version-dependent details must remain
identified as assumptions.

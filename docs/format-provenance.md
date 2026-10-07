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

## Evidence maintenance

Before changing a non-obvious format rule, record the public Microsoft runtime
producer path, commit hash, relevant lines, and an independently generated
minimal observation here. Unknown or version-dependent details must remain
identified as assumptions.

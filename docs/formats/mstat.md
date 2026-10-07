# MSTAT v2.2 summary format

`vitnet mstat summary` reads the NativeAOT MSTAT v2.2 format. MSTAT is a
managed PE whose assembly version identifies the format. Seven synthetic
global `MethodDef` rows carry compact IL instruction streams:

| Method | Repeated record |
| --- | --- |
| `Methods` | entity token, body bytes, GC-info bytes, EH-info bytes, mangled-name offset |
| `Types` | entity token, bytes, mangled-name offset |
| `Blobs` | user-string token, bytes |
| `RvaFields` | field token, bytes, mangled-name offset |
| `FrozenObjects` | type token, bytes, mangled-name offset, owning-type token or zero |
| `ManifestResources` | assembly-reference token, user-string token, bytes |
| `DeduplicatedMethods` | method token, folded count, then that many method-token/name-offset pairs |

Entity and string references use `ldtoken` and `ldstr`. Signed 32-bit values
use the shortest `ldc.i4` encoding selected by `InstructionEncoder`. The
`.names` PE section contains serialized mangled names; summary mode reports its
logical section size but does not materialize those names.

The JSON schema identifier is `vitnet.mstat-summary.v1`. Categories remain in
the producer order above and all numeric fields are byte or record counts.
`accounted_size_bytes` is the sum of `Methods`, `Types`, and `Blobs`. In MSTAT
v2, the producer deliberately also includes RVA fields, frozen regions, and
manifest resources in `Blobs` for compatibility with v2.0 readers. Adding the
newer breakdown streams again would double-count them. Each breakdown is still
reported independently.

`Methods.aggregate_size_bytes` includes method body, GC-info, and EH-info
bytes. `DeduplicatedMethods.items` is the folded-method count. Summary mode
does not retain the token-to-method-size index needed for a defensible folding
savings estimate, so `estimated_savings_bytes` is `null`.

The parser memory-maps plain files read-only and parses borrowed slices. It
validates DOS/PE headers, section ranges, the CLI metadata directory, metadata
streams and table widths, method body boundaries, opcode sequences, counts,
and checked aggregates. `peak_tracked_memory_bytes` covers vitnet-owned parser
state; mapped pages and operating-system file cache are intentionally not
treated as committed Rust heap.

Only format 2.2 is accepted. Unknown versions fail with a typed diagnostic
rather than being interpreted using a guessed layout.

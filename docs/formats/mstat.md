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

## Independent tiny fixture map

`crates/vitnet-mstat/tests/summary.rs` constructs a complete 2,048-byte PE
from constants rather than copying a producer or third-party fixture. Its
layout is intentionally small enough to explain byte-for-byte:

| File range | Contents |
| --- | --- |
| `0x000..0x080` | DOS header; `MZ` at 0 and `e_lfanew = 0x80` at `0x3c` |
| `0x080..0x098` | `PE\0\0` and COFF header; two sections, `0xe0`-byte optional header |
| `0x098..0x178` | PE32 optional header; CLI directory 14 is RVA `0x2000`, size 72 |
| `0x178..0x1c8` | `.text` and `.names` section rows |
| `0x200..0x248` | 72-byte CLI header; metadata is RVA `0x2080` |
| `0x280..0x409` | 393-byte ECMA-335 metadata root |
| `0x40c..0x465` | seven aligned tiny synthetic method bodies |
| `0x600..0x604` | `.names`: `01 61 01 62`, two one-byte SerStrings |
| remaining bytes | zero section/file alignment padding |

The metadata root is 76 bytes. Its streams are:

| Stream | Relative offset | Size | Purpose |
| --- | ---: | ---: | --- |
| `#~` | `0x04c` | 218 | Module, TypeDef, Field, seven MethodDef, Assembly, and AssemblyRef rows |
| `#Strings` | `0x126` | 94 | synthetic method names and `tiny.mstat` |
| `#US` | `0x184` | 5 | reserved byte plus empty strings at offsets 1 and 3 |

The fixture's method code bytes, excluding each one-byte tiny header, are:

| Method | Bytes |
| --- | --- |
| `Methods` | `d0 01 00 00 06 1f 0a 18 17 16` |
| `Types` | `d0 01 00 00 02 1f 14 16` |
| `Blobs` | `72 01 00 00 70 1f 21` |
| `RvaFields` | `d0 01 00 00 04 1a 16` |
| `FrozenObjects` | `d0 01 00 00 02 1b 16 d0 01 00 00 02 d0 01 00 00 02 1c 16 16` |
| `ManifestResources` | `20 01 00 00 23 72 03 00 00 70 1d` |
| `DeduplicatedMethods` | `d0 03 00 00 06 17 d0 04 00 00 06 16` |

These bytes exercise every supported instruction form and record shape. Tests
also try every truncated file prefix, corrupt opcodes, invalid metadata tokens,
invalid SerString lengths, deterministic JSON, and 512 arbitrary byte vectors
per property-test run. The same in-memory `summarize` boundary is exposed to
the persistent fuzz target.

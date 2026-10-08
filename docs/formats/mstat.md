# MSTAT v2.2 summary format

## Component insight reports

The checked `insights` API builds one shared exact inventory for method
components, resources, literal cohorts and generic-shaped name families.
Its library schema is `vitnet.mstat-insights.v1`; CLI projections/envelopes
are documented in [bloat analysis](../bloat-analysis.md).

Methods retain and coalesce the three actual producer size fields separately.
Top plus omitted component/byte totals equal matched totals. Accounted basis
points use the complete Methods + Types + Blobs denominator.

Resources resolve exact AssemblyRef name/culture and UTF-16 resource names.
Assembly/culture/name projections each reconcile independently; `accounted`
is false because resource bytes overlap Blobs. Complete keys determine group
identity before display limiting.

Cohorts OR case-sensitive literal predicates within each rule, intersect any
complete-identity filter, and optionally restrict one exact stream. The report
separates accounted/non-accounted counts, unions, multiply-matched identities
and pairwise intersections; overlapping cohort sums are not byte ownership.
Generic-shaped families use the exact prefix before the first literal `<` in
Methods/Types identities. Ordinary and shaped totals reconcile, but this is
explicitly a name heuristic, not a guessed demangling grammar.

`metadata_blob_bytes` and `metadata_blob_records` count only the complete
UTF-16 Blobs name exactly equal to `Metadata`, before filtering/top projection.
Absence and a present zero-sized blob remain distinguishable.

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

These are logical object-data sizes, not executable file sizes. With producer
dehydration enabled, hydration targets preserve their zero-filled logical
lengths in an uninitialized section while a separate `DehydratedData` blob holds
their encoded representation. Neither that blob nor the target lengths are
independent estimates of removable disk bytes. The pinned producer evidence is
recorded in [format provenance](../format-provenance.md).

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

## Structural diff contract

`vitnet mstat diff` emits `vitnet.mstat-diff.v1`. It builds compact inventories
for both inputs, sorts them by a 128-bit BLAKE3 fingerprint, and always compares
the exact identity bytes after a fingerprint match. Fingerprints are therefore
an acceleration only, not an identity oracle. Duplicate identities are
coalesced with checked byte and record totals before the merge diff.

Methods, types, RVA fields, frozen objects, and folded methods use the
producer's mangled `.names` value as their row-number-independent identity.
This preserves the producer's namespace, nesting, generic, member, and
signature distinctions without reconstructing a separate type-system object
model. Blobs use exact decoded `#US` bytes. Manifest-resource identity is the
resolved AssemblyRef name and culture followed by the exact resource name.
Assembly display uses `name, Culture=culture` when culture is non-empty.

This choice deliberately treats producer mangling as an opaque stable
contract. Vitnet does not demangle or synthesize identities from metadata row
numbers. The report truncates display values to 256 UTF-8 bytes, but matching
always uses the complete original bytes.

`Methods`, `Types`, and `Blobs` are marked `accounted: true`. Their signed
section deltas must sum exactly to `total_delta_bytes`; the machine-readable
`reconciliation.balanced` field is false only if that invariant fails, in
which case the command returns an internal diagnostic instead of a report.
RVA fields, frozen objects, resources, and deduplicated methods are reported
as non-accounted breakdowns to prevent double counting. `--top` bounds
materialized change entries per section; additions, removals, changes, and
section totals remain exact.

MSTAT 2.2 records folding membership but not the size of every folded-away
body. The summary and diff contracts therefore report exact group and folded
method counts while leaving `estimated_savings_bytes` as `null` rather than
inventing a size from the surviving body. Folding data remains separate from
accounted totals.

## Contributor ranking contract

`mstat top` emits `vitnet.mstat-top.v1`, including accounted size, tracked
inventory charge and producer-ordered sections. Each section contains
`accounted`, `total_bytes`, `matched_bytes`, `matched_identities`, and bounded
entries with `identity`, original `identity_bytes`, `truncated`, `bytes`, and
coalesced `records`. Ranking is descending bytes then complete identity bytes.
`--stream` selects one of the seven exact stream names; `--contains` matches
complete case-sensitive identities, never truncated displays. No match is a
valid empty result with an unchanged section total.

Resource identities display as `assembly!resource`, decoding the resource
suffix from UTF-16. Blob/resource filters respect UTF-16 code-unit alignment.
Previews stop at a UTF-8 boundary and mark truncation by rendered length rather
than guessing from UTF-16 byte counts. Raw identity equality and diff matching
are unchanged. Like diff, top retains a compact record inventory; it is not the
constant-state summary decoder.

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

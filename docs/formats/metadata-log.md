# NativeAOT metadata log profile

The supported header is exactly:

```text
Handle, Kind, Name, Children
```

`Handle` and each child are hexadecimal `u32` values. Current producers use the
low 25 handle bits for the record-start offset; older producers use 24 bits.
vitnet compares the packed kind with the textual `Kind` to select the layout.
The upper bits contain the producer record kind.
`Kind` is the producer record type name. `Name` is quoted when emitted and uses
backslash escaping for `\` and `"`. `Children` is a quoted list of hexadecimal
handles separated by ASCII spaces.

The decoder accepts:

- LF and CRLF logical-record terminators;
- quoted commas and physical newlines;
- producer backslash escapes;
- conventional doubled quote escapes; and
- historical producer display names with bare quoted phrases (record
  completion is anchored by the final quoted hexadecimal children field); and
- invalid UTF-8 in display fields.

Strict mode rejects the wrong field count, invalid handles, incomplete quoted
fields, non-delimiter bytes after a closing quote, and offset transitions that
cannot reasonably represent the detected 24- or 25-bit rollover.

Handles are starts, not ends. Differences between adjacent unwrapped starts
bound the preceding record. The final record size is always unknown for this
format, so whole-file and filtered totals are lower bounds.

See `../format-provenance.md` for the public producer evidence.

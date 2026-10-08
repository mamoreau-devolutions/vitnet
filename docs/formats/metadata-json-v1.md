# `vitnet.metadata.v1`

JSON analysis output is a single object:

```json
{
  "schema": "vitnet.metadata.v1",
  "tool_version": "0.1.0",
  "input": {
    "path": "app.metadata.csv",
    "bytes_read": 1234
  },
  "summary": {
    "producer_offset_bits": 25,
    "metadata_lower_bound_bytes": 100,
    "selected_lower_bound_bytes": 100,
    "observed_record_count": 20,
    "record_count": 20,
    "total_is_lower_bound": true,
    "final_record_size_known": false,
    "peak_tracked_memory_bytes": 4096
  },
  "sections": {
    "by_kind": [],
    "by_assembly": [],
    "by_namespace": [],
    "by_type": [],
    "largest_strings": [],
    "unowned": [],
    "limit_status": {
      "status": "at_or_below_headroom_unknown",
      "limit": 33554431,
      "observed_lower_bound": 100
    }
  },
  "diagnostics": []
}
```

Byte counts and record counts are JSON integers. Aggregate arrays are ordered
by descending bytes, then ordinal display name. String entries add
`logical_offset`, `bytes`, and a preview with `text`, `original_bytes`, and
`truncated`.

Assembly/type/ownership-substring filters affect `record_count`, selected bytes and attributed
sections, but not `observed_record_count` or the whole-input lower bound.
`--type` matches the complete assembly-prefixed type key; it intersects
`--assembly`. `--preview-bytes` truncates display only, not matching/accounting.
`--contains` matches a literal case-sensitive substring in the resolved
assembly, namespace or owning type; it intersects the exact filters. An
unowned string matching the literal does not thereby gain ownership.

The additive `sections.concentration` object contains `by_kind`, `by_assembly`,
`by_namespace`, `by_type`, and `unowned` coverage entries. Each has
`total_bytes`, `reported_bytes`, `omitted_bytes`, `total_groups`,
`reported_groups`, and `reported_share_basis_points`. Totals precede top-N;
reported plus omitted bytes equal total bytes. Basis points are integer
floor division (`reported * 10000 / total`), or zero for an empty dimension.
Each dimension describes the same selected metadata, not additive new bytes.
Older v1 JSON without this optional field remains readable.

`producer_offset_bits` is 24 for legacy logs and 25 for current logs. When the
observed start exceeds the matching format limit, `limit_status` is
`over_by_at_least` and includes the conservative `bytes` overage. At or below
the limit, headroom is unknown because the final record end is absent.

Comparison output uses `vitnet.metadata-comparison.v1`. It contains before and
after input descriptors, a signed lower-bound summary delta, and by-kind,
assembly, namespace, type, and unowned comparison sections. Each section entry
contains `before_bytes`, `after_bytes`, and signed `delta_bytes`.

NDJSON emits one object per summary or section item. Every line repeats
`schema`, identifies `section`, and carries the typed item in `value`.

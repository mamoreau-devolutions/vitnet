# Performance budget

Phase 1 acceptance for the private/local 171 MB metadata CSV is at most 256 MiB
peak RSS/private working set and at most 10 seconds in a release build.

Reference validation on 2026-10-07:

| Metric | Result |
| --- | ---: |
| Input bytes | 171 MB class |
| Records | 1,440,352 |
| Observed metadata lower bound | 41,183,314 B |
| Wall time | 2.284 s |
| User / kernel CPU | 2.031 s / 0.203 s |
| Peak sampled working set | 132.45 MiB |
| Conservative tracked-state charge | 176.82 MiB |
| Bytes read / written | 170,892,892 B / 52,002 B |
| Temporary disk | 0 B |
| Output | `vitnet.metadata.v1` |

The command was a release build with `--strict --memory-limit 256MiB`, JSON
output, and `--strings`. It detected the current 25-bit producer layout. The
local input and generated report are not repository fixtures. Working-set
sampling read the Windows process working-set counter at 10 ms intervals.

Reference machine: Intel Core Ultra 9 285HX (24 logical processors), 63.5 GiB
RAM, Windows 11 Enterprise 10.0.26200.

Published performance claims must use release or profile-guided builds. Run the
Criterion microbenchmark with:

```console
cargo bench -p vitnet-metadata --bench metadata_decoder
```

The current decode-and-aggregate result for 10,000 synthetic rows is
67.62-68.07 MiB/s (median 67.86 MiB/s, 7.57 ms).

# Raw vs 2.3.0 vs audit-fix candidate (2.4 RC1 label)

Measured on Linux amd64 on 3 October 2026 with the user's game running.
The candidate label denotes the uncommitted audit remediation, not a tag or
published release. See [the comparison report](../raw-23-24rc1-2026-10-03.md).

- `plan.toml`, `plan.json`: exact workload, native UDP, member auth, fixed
  settings, CPU affinity, reversing local variant order and rotating netem CPUs.
- `build.json`, `candidate-source-files.json`, `host.json`: commits, dirty
  state, tested source hashes, binaries and environment.
- `manifest.json`, `events.log`: all 40 completed cells, rounds and foreign CPU.
- `cells.json`: complete result and resource records per measured cell.
  Download bodies are byte-compared to their expected contents; uploads are
  accepted by returned length. This is not SHA-256 upload validation.
- `comparison-summary.json`: medians, ranges and individual round values.
  Summary throughput is decimal MB/s. Latency summaries are medians of each
  round's percentile, not percentiles of pooled requests.
- `analysis.json`: existing pipeline comparisons including noisy rounds;
  positive and negative flags are provisional. With five pairs, the smallest
  two-sided sign-test p is 0.0625, without adjustment for many metrics.
- `analysis-excluding-noisy.json`: default analysis, with too few usable pairs
  for performance conclusions (38/40 cells were flagged noisy).
- `warnings.json`: complete server warnings, including kernel UDP receive
  buffer drops during bulk transfer. Zero request errors is not zero loss.
- `summarize.py`: aggregation used on the retained local run directory.

The first interrupted pilot is separate and excluded from every summary:
`bench/runs/raw-23-24rc1-20261003`. The complete run, binaries, detailed logs
and HTML report remain in `bench/runs/raw-23-24rc1-loaded-20261003`.
No production process, router configuration or deployed binary was changed.

To repeat in a fresh run directory, from the same candidate source tree:

```bash
python3 scripts/matrix/matrix.py run docs/reports/data-raw-23-24rc1-2026-10-03/plan.toml --out bench/runs/raw-23-24rc1-repeat
python3 scripts/matrix/matrix.py report bench/runs/raw-23-24rc1-repeat --include-noisy
```

Use the default report (without `--include-noisy`) for quiet-machine results.
No WAN, ARM hardware or real-game network acceptance is established here.

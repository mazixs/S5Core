# S5Core comparison pipeline

The pipeline compares direct connections with fixed S5Core builds on local,
emulated and WAN paths. It records content checks, latency, throughput, resource
usage and unrelated load.

See [the complete command reference and measurement methodology](details.md)
(in Russian) and the example plans in [plans](plans).

```bash
python3 scripts/matrix/matrix.py run scripts/matrix/plans/quick.toml
```

Keep host addresses and private plans under the ignored `bench/` directory.
No speed claim should include noisy cells or substitute cross-compilation for
measurements on physical ARM hardware.

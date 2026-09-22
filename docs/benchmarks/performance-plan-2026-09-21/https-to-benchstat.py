#!/usr/bin/env python3
"""Convert per-run HTTPS medians to benchstat input, not individual requests."""

import sys
from pathlib import Path


def nanoseconds(value):
    for suffix, multiplier in [("ns", 1), ("µs", 1000), ("ms", 1000000), ("s", 1000000000)]:
        if value.endswith(suffix):
            return float(value[:-len(suffix)]) * multiplier
    raise ValueError(value)


for line in Path(sys.argv[1]).read_text().splitlines():
    if "MEASURE " not in line:
        continue
    fields = dict(item.split("=", 1) for item in line.split("MEASURE ", 1)[1].split())
    name = f'{fields["mode"]}/{fields["size"]}/reuse={fields["reuse"]}'
    print(f'BenchmarkHTTPS/{name} 1 {nanoseconds(fields["total_p50"]):.0f} ns/op')

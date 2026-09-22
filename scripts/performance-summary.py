#!/usr/bin/env python3
"""Summarize ABBA runs and bootstrap whole-run tail statistics."""
import argparse
from collections import defaultdict
import json
import math
from pathlib import Path
import random
import statistics


def quantile(values, p):
    return sorted(values)[max(0, math.ceil(len(values) * p) - 1)]


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('directory', type=Path)
    p.add_argument('--json', type=Path, required=True)
    a = p.parse_args()
    metadata = json.loads((a.directory / 'environment.json').read_text())
    if metadata.get('completed') is False:
        p.error('benchmark did not complete; partial runs are not acceptance evidence')
    clock_ticks = metadata.get('clock_ticks_per_second', 100)
    groups = defaultdict(lambda: defaultdict(list))
    resources = defaultdict(list)
    for path in sorted(a.directory.glob('*-*/*/requests.jsonl')):
        run = path.parent.parent.name
        variant = run.rsplit('-', 1)[0]
        for line in path.read_text().splitlines():
            record = json.loads(line)
            key = tuple(record[k] for k in ('Mode', 'Scenario', 'Protocol', 'Reuse'))
            m = record['Measurement']
            if m.get('error') or m['status'] != 200:
                raise ValueError(f'failed response in {path}: {m}')
            groups[key][variant, run].append(m)
        for line in path.with_name('resources.jsonl').read_text().splitlines():
            r = json.loads(line)
            key = tuple(r[k] for k in ('Mode', 'Scenario', 'Protocol', 'Reuse'))
            resources[key, variant].append(r)
    if not groups:
        p.error('no runs found')
    output = []
    rng = random.Random(20260921)
    print('| Scenario | n before/after | p50 ms before/after | p99 ms before/after | median-run p99 change, 95% CI |')
    print('| --- | ---: | ---: | ---: | ---: |')
    for key, runs in sorted(groups.items()):
        row = {'scenario': key, 'variants': {}}
        tails = {}
        for variant in ('before', 'after'):
            buckets = [v for (ver, _), v in runs.items() if ver == variant]
            if not buckets:
                continue
            all_samples = [m for bucket in buckets for m in bucket]
            times = [m['total_ms'] for m in all_samples]
            tails[variant] = [quantile([m['total_ms'] for m in b], .99) for b in buckets]
            stats = {f'p{int(p*100)}_ms': quantile(times, p) for p in (.5, .95, .99)}
            stats.update(n=len(times), runs=len(buckets), run_p99_ms=tails[variant],
                         setup_p50_ms=quantile([m['connect_setup_ms'] for m in all_samples], .5),
                         ttfb_p99_ms=quantile([m['http_first_response_ms'] for m in all_samples], .99))
            resource_runs = resources[key, variant]
            for side in ('Server', 'Client', 'Generator'):
                if not all(side+'After' in r for r in resource_runs):
                    continue
                cpu = sum((r[side+'After']['cpu_ticks']-r[side+'Before']['cpu_ticks'])/clock_ticks for r in resource_runs)
                seconds = sum(r['Seconds'] for r in resource_runs)
                stats[side.lower()+'_cpu_cores'] = cpu / seconds if seconds else None
                useful = sum(m['bytes'] for m in all_samples)
                if key[1] == 'upload':
                    useful += len(times) * (8 << 20)
                elif key[1] == 'upload-stream':
                    useful += len(times) * 350 * 32768
                stats[side.lower()+'_cpu_seconds_per_gib'] = cpu / (useful/(1 << 30)) if useful and key[1] != "mixed" else None
                stats[side.lower()+'_rss_bytes'] = max(r[side+'After']['rss_bytes'] for r in resource_runs)
                stats[side.lower()+'_peak_rss_bytes'] = max(r[side+'After']['peak_rss_bytes'] for r in resource_runs)
            row['variants'][variant] = stats
        if len(tails) == 2:
            samples = []
            for _ in range(2000):
                med = {v: statistics.median(rng.choices(t, k=len(t))) for v, t in tails.items()}
                samples.append(100*(med['after']/med['before']-1))
            lo, hi = quantile(samples, .025), quantile(samples, .975)
            row['median_run_p99_change_ci_percent'] = [lo, hi]
            b, c = (row['variants'][v] for v in ('before', 'after'))
            print(f'| {"/".join(key)} | {b["n"]}/{c["n"]} | {b["p50_ms"]:.3f}/{c["p50_ms"]:.3f} | '
                  f'{b["p99_ms"]:.3f}/{c["p99_ms"]:.3f} | [{lo:.1f}%, {hi:.1f}%] |')
        output.append(row)
    a.json.write_text(json.dumps(output, indent=2) + '\n')


if __name__ == '__main__':
    main()

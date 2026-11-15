#!/usr/bin/env python3
"""Run independent process benchmarks in ABBA order. Never changes networking."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import signal
import subprocess
import time


def resource_context():
    """Read the runner's own cgroup, not the cgroup filesystem root."""
    result = {'utc_ns': time.time_ns(), 'monotonic_ns': time.monotonic_ns(), 'unavailable': {}}
    for name, path in {'boot_id': '/proc/sys/kernel/random/boot_id',
                       'guest_cpu_stat': '/proc/stat', 'guest_loadavg': '/proc/loadavg'}.items():
        try:
            result[name] = Path(path).read_text().splitlines()[0]
        except OSError as error:
            result['unavailable'][name] = type(error).__name__
    try:
        entries = Path('/proc/self/cgroup').read_text().splitlines()
        relative = next(line.split('::', 1)[1] for line in entries if line.startswith('0::'))
        base = Path('/sys/fs/cgroup').resolve()
        group = (base/relative.lstrip('/')).resolve()
        group.relative_to(base)
        identity = group.stat()
        result.update(cgroup=str(group), cgroup_device=identity.st_dev, cgroup_inode=identity.st_ino)
        for name in ('cpu.max', 'cpu.stat', 'cpu.pressure', 'memory.max', 'memory.current',
                     'memory.peak', 'memory.events', 'memory.pressure'):
            try:
                result[name] = (group/name).read_text()
            except OSError as error:
                result['unavailable'][name] = type(error).__name__
    except (OSError, ValueError, StopIteration) as error:
        result['unavailable']['cgroup_v2'] = type(error).__name__
    return result


def cpu_interval(before, after):
    """CPU and quota throttling of the runner's cgroup between two contexts."""
    identity = ('boot_id', 'cgroup', 'cgroup_device', 'cgroup_inode', 'cpu.max')
    if any(key not in before or key not in after or before[key] != after[key] for key in identity):
        return {'status': 'unknown', 'reason': 'missing_or_changed_identity_or_quota'}
    try:
        counters = [dict(line.split() for line in row['cpu.stat'].splitlines()) for row in (before, after)]
        keys = ('usage_usec', 'nr_periods', 'nr_throttled', 'throttled_usec')
        deltas = {key: int(counters[1][key])-int(counters[0][key]) for key in keys}
        if min(deltas.values()) < 0 or after['monotonic_ns'] <= before['monotonic_ns']:
            raise ValueError('counter reset or invalid interval')
    except (KeyError, ValueError):
        return {'status': 'unknown', 'reason': 'missing_or_reset_counters'}
    return {'status': 'counters_available', 'delta': deltas,
            'throttled': deltas['nr_throttled'] > 0,
            'seconds': (after['monotonic_ns']-before['monotonic_ns'])/1e9}


def variant_environment(parser, assignments):
    """S5_PERF_* settings of one variant, such as S5_PERF_DIAGNOSTICS=1."""
    env = {}
    for assignment in assignments:
        name, separator, value = assignment.partition('=')
        if (not separator or not name.startswith('S5_PERF_')
                or name in ('S5_PERF_SERVER', 'S5_PERF_CLIENT', 'S5_PERF_OUT')):
            parser.error(f'{assignment!r}: expected S5_PERF_NAME=VALUE for a setting the driver does not own')
        env[name] = value
    return env


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('probe', 'before-client', 'before-server', 'after-client', 'after-server', 'out'):
        p.add_argument('--' + name, required=True, type=Path)
    for variant in ('before', 'after'):
        p.add_argument(f'--{variant}-env', action='append', default=[], metavar='S5_PERF_NAME=VALUE',
                       help=f'setting of the {variant} runs only; repeatable')
    p.add_argument('--rounds', type=int, default=6, help='independent runs per variant; even')
    a = p.parse_args()
    if a.rounds < 2 or a.rounds % 2:
        p.error('--rounds must be positive and even')
    variant_env = {variant: variant_environment(p, getattr(a, variant+'_env')) for variant in ('before', 'after')}
    a.out.mkdir(parents=True, exist_ok=False, mode=0o700)
    files = {name: getattr(a, name.replace('-', '_')).resolve()
             for name in ('probe', 'before-client', 'before-server', 'after-client', 'after-server')}
    metadata = {'platform': platform.platform(), 'environment':
                {k: v for k, v in os.environ.items() if k.startswith('S5_PERF_')},
                'variant_environment': variant_env,
                'binaries': {k: {'path': str(v), 'sha256': hashlib.sha256(v.read_bytes()).hexdigest()}
                             for k, v in files.items()}, 'rounds': a.rounds, 'clock_ticks_per_second': os.sysconf('SC_CLK_TCK'),
                'completed': False, 'runs': [], 'resource_context_before': resource_context()}
    try:
        metadata['/proc/cpuinfo'] = Path('/proc/cpuinfo').read_text()
    except OSError:
        pass

    def unchanged():
        return all(hashlib.sha256(path.read_bytes()).hexdigest() == metadata['binaries'][key]['sha256']
                   for key, path in files.items())

    def save():
        # Replaced whole, so an interrupted series leaves the last complete record.
        temporary = a.out/'environment.json.tmp'
        temporary.write_text(json.dumps(metadata, indent=2) + '\n')
        temporary.chmod(0o600)
        temporary.replace(a.out/'environment.json')
    save()

    def interrupt(signum, frame):
        raise KeyboardInterrupt(f'interrupted by signal {signum}')

    signal.signal(signal.SIGTERM, interrupt)
    indices = {'before': 0, 'after': 0}
    for variant in ['before', 'after', 'after', 'before'] * (a.rounds // 2):
        index = indices[variant]
        indices[variant] += 1
        name = f'{variant}-{index:02}'
        env = dict(os.environ, **variant_env[variant], S5_PERF_SERVER=str(files[variant+'-server']),
                   S5_PERF_CLIENT=str(files[variant+'-client']), S5_PERF_OUT=str(a.out.resolve()/name))
        print(name, flush=True)
        record = {'name': name, 'variant': variant, 'completed': False, 'before': resource_context()}
        metadata['runs'].append(record)
        save()
        with (a.out / (name + '.log')).open('w') as log:
            command = [str(files['probe']), '-test.run=^TestPerformanceProcesses$',
                       '-test.v', '-test.timeout=10m']
            with subprocess.Popen(command, env=env, stdout=log, stderr=subprocess.STDOUT,
                                  start_new_session=True) as proc:
                try:
                    status = proc.wait()
                    if status:
                        raise subprocess.CalledProcessError(status, command)
                finally:
                    # Also reap proxies if a test aborts before running cleanup.
                    try:
                        os.killpg(proc.pid, signal.SIGTERM)
                    except ProcessLookupError:
                        pass
                    try:
                        proc.wait(timeout=15)
                    except subprocess.TimeoutExpired:
                        os.killpg(proc.pid, signal.SIGKILL)
                        proc.wait()
                    # A proxy that ignored SIGTERM outlives the probe in its group.
                    try:
                        os.killpg(proc.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    record['exit_code'] = proc.returncode
                    record['after'] = resource_context()
                    record['cpu_interval'] = cpu_interval(record['before'], record['after'])
                    record['inputs_unchanged'] = unchanged()
                    record['completed'] = proc.returncode == 0 and record['inputs_unchanged']
                    save()
        if not record['inputs_unchanged']:
            raise RuntimeError('an input binary changed during ' + name)
    metadata['completed'] = True
    metadata['resource_context_after'] = resource_context()
    save()
    print('Completed:', a.out, flush=True)


if __name__ == '__main__':
    main()

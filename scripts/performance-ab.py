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


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('probe', 'before-client', 'before-server', 'after-client', 'after-server', 'out'):
        p.add_argument('--' + name, required=True, type=Path)
    p.add_argument('--rounds', type=int, default=6, help='independent runs per variant; even')
    a = p.parse_args()
    if a.rounds < 2 or a.rounds % 2:
        p.error('--rounds must be positive and even')
    a.out.mkdir(parents=True, exist_ok=False)
    files = {name: getattr(a, name.replace('-', '_')).resolve()
             for name in ('probe', 'before-client', 'before-server', 'after-client', 'after-server')}
    metadata = {'platform': platform.platform(), 'environment':
                {k: v for k, v in os.environ.items() if k.startswith('S5_PERF_')},
                'binaries': {k: {'path': str(v), 'sha256': hashlib.sha256(v.read_bytes()).hexdigest()}
                             for k, v in files.items()}, 'rounds': a.rounds, 'clock_ticks_per_second': os.sysconf('SC_CLK_TCK'), 'completed': False}
    for path in ('/proc/cpuinfo', '/sys/fs/cgroup/cpu.max', '/sys/fs/cgroup/memory.max'):
        try:
            metadata[path] = Path(path).read_text()
        except OSError:
            pass
    (a.out / 'environment.json').write_text(json.dumps(metadata, indent=2) + '\n')
    def interrupt(signum, frame):
        raise KeyboardInterrupt(f'interrupted by signal {signum}')

    signal.signal(signal.SIGTERM, interrupt)
    indices = {'before': 0, 'after': 0}
    for variant in ['before', 'after', 'after', 'before'] * (a.rounds // 2):
        index = indices[variant]
        indices[variant] += 1
        name = f'{variant}-{index:02}'
        env = dict(os.environ, S5_PERF_SERVER=str(files[variant+'-server']),
                   S5_PERF_CLIENT=str(files[variant+'-client']), S5_PERF_OUT=str(a.out.resolve()/name))
        print(name, flush=True)
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
    metadata['completed'] = True
    (a.out / 'environment.json').write_text(json.dumps(metadata, indent=2) + '\n')
    print('Completed:', a.out, flush=True)


if __name__ == '__main__':
    main()

#!/usr/bin/env python3
"""Prepare a local soak of the process benchmark; run it only with --execute on Linux."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import shutil
import subprocess
import sys
import time


CASES = ('idle-tunnel', 'slow-read', 'stream', 'upload-stream')


def digest(path):
    with path.open('rb') as source:
        return hashlib.file_digest(source, 'sha256').hexdigest()


def matrix(modes, cases):
    rows = []
    for mode in modes:
        for case in cases:
            idle = case == 'idle-tunnel'
            # Three cycles of a 2 min hold or load (30 min in the first) and 3 min of recovery.
            seconds = 3 * (120 + 180) if idle else 1800 + 2 * 120 + 3 * 180
            rows.append({'mode': mode, 'case': case, 'minimum_seconds': seconds,
                         'env': {'S5_PERF_MODES': mode, 'S5_PERF_CASES': case,
                                 'S5_PERF_CYCLES': '3', 'S5_PERF_PROTOCOLS': 'h1',
                                 'S5_PERF_REUSE': 'reuse', 'S5_PERF_PROCS': 'auto',
                                 'S5_PERF_CONCURRENCY': '2', 'S5_PERF_SMALL': '1',
                                 'S5_PERF_LARGE': '1', 'S5_PERF_MIN_DURATION': '2m',
                                 'S5_PERF_FIRST_DURATION': '30m',
                                 'S5_PERF_RECOVERY_DURATION': '3m',
                                 'S5_PERF_TUNNEL_IDLE_DURATION': '2m',
                                 'S5_PERF_IDLE_TUNNELS': '8',
                                 'S5_PERF_SLOW_READ_DELAY': '10ms',
                                 'S5_PERF_SCRAPE_INTERVAL': '15s',
                                 'S5_PERF_DIAGNOSTICS': '1',
                                 'S5_PERF_RECOVERY_MARKERS': '1'}})
    return rows


def fixture_env(inherited, row, server, client, output):
    # Never inherit a deployment address, a profiler or another workload.
    env = {key: value for key, value in inherited.items()
           if not key.startswith(('S5_', 'GODEBUG', 'GOFLAGS', 'GOMAXPROCS'))}
    env.update(row['env'])
    env.update(S5_PERF_SERVER=str(server), S5_PERF_CLIENT=str(client),
               S5_PERF_OUT=str(output), GOMAXPROCS='2')
    return env


def run_owned(command, env, cwd, log, timeout):
    # Each fixture and its child proxies belong to this new process group.
    with log.open('xb') as stream:
        process = subprocess.Popen(command, cwd=cwd, env=env, stdout=stream,
                                   stderr=subprocess.STDOUT, start_new_session=True)
        try:
            code = process.wait(timeout=timeout)
            if code:
                raise RuntimeError(f'fixture exited {code}; inspect {log.name}')
        finally:
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                process.wait(timeout=20)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--server', type=Path, required=True)
    parser.add_argument('--client', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True, help='new private directory')
    parser.add_argument('--modes', nargs='+', choices=('obfs', 'wss'), default=['obfs', 'wss'])
    parser.add_argument('--cases', nargs='+', choices=CASES, default=list(CASES))
    parser.add_argument('--go', default='go')
    parser.add_argument('--execute', action='store_true', help='compile and run; otherwise only save the plan')
    args = parser.parse_args()
    if args.execute and sys.platform != 'linux':
        parser.error('execution requires Linux and Linux proxy binaries')
    root = Path(__file__).resolve().parents[1]
    server, client, out = args.server.resolve(strict=True), args.client.resolve(strict=True), args.out.resolve()
    rows = matrix(args.modes, args.cases)
    sources = sorted((root/'cmd/httpsprobe').glob('*.go')) + [root/'go.mod', root/'go.sum', Path(__file__).resolve()]
    provenance = {path.relative_to(root).as_posix(): digest(path) for path in sources}
    plan = {'schema': 1, 'status': 'prepared',
            'server_sha256': digest(server), 'client_sha256': digest(client),
            'harness_sources_sha256': provenance, 'matrix': rows,
            'minimum_seconds': sum(row['minimum_seconds'] for row in rows)}
    out.mkdir(mode=0o700)  # An existing directory is refused, not overwritten.
    os.chmod(out, 0o700)
    manifest = out/'plan.json'
    manifest.write_text(json.dumps(plan, indent=2)+'\n', encoding='utf-8')
    print(f'Prepared {len(rows)} cases; at least {plan["minimum_seconds"]/60:.0f} min. {manifest}', flush=True)
    if not args.execute:
        return
    for original, name, expected in ((server, 's5core-frozen', plan['server_sha256']),
                                     (client, 's5client-frozen', plan['client_sha256'])):
        target = out/name
        shutil.copyfile(original, target)
        target.chmod(0o700)
        if digest(target) != expected:
            raise RuntimeError('proxy changed while making its frozen copy')
    server, client = out/'s5core-frozen', out/'s5client-frozen'
    env = fixture_env(os.environ, rows[0], server, client, out/'unused')
    binary = out/'httpsprobe-fixture.test'
    run_owned([args.go, 'test', '-p=1', '-c', '-o', str(binary), './cmd/httpsprobe'],
              env, root, out/'compile.log', 600)
    if (digest(server) != plan['server_sha256'] or digest(client) != plan['client_sha256']
            or any(digest(root/path) != sha for path, sha in provenance.items())):
        raise RuntimeError('inputs changed during preparation; start a fresh run')
    plan.update(status='running', fixture_sha256=digest(binary), started_unix=time.time())
    manifest.write_text(json.dumps(plan, indent=2)+'\n', encoding='utf-8')
    try:
        for index, row in enumerate(rows):
            if digest(server) != plan['server_sha256'] or digest(client) != plan['client_sha256']:
                raise RuntimeError('proxy binary changed; refusing the next case')
            name = f'{index+1:02d}-{row["mode"]}-{row["case"]}'
            print(f'Starting {name}', flush=True)
            run_owned([str(binary), '-test.run=^TestPerformanceProcesses$', '-test.v', '-test.timeout=75m'],
                      fixture_env(os.environ, row, server, client, out/name), root,
                      out/(name+'.log'), 4500)
            plan.setdefault('completed_cases', []).append(name)
            manifest.write_text(json.dumps(plan, indent=2)+'\n', encoding='utf-8')
        plan['status'] = 'completed'
    except BaseException:
        plan['status'] = 'failed'
        raise
    finally:
        plan['ended_unix'] = time.time()
        manifest.write_text(json.dumps(plan, indent=2)+'\n', encoding='utf-8')


if __name__ == '__main__':
    main()

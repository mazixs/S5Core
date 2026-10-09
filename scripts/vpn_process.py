#!/usr/bin/env python3
"""Identify a Linux VPN child by PID, executable and start time.

Termination uses a pidfd so a recycled PID cannot select another process
between the identity check and the signal. Unsupported systems refuse it.
"""
import argparse
import json
import os
from pathlib import Path
import signal
import time


def identity(pid):
    root = Path('/proc') / str(pid)
    return {'pid': pid, 'exe': os.readlink(root / 'exe'),
            'start': (root / 'stat').read_text().rsplit(') ', 1)[1].split()[19]}


def act(record, executable, stop=False):
    expected = json.loads(Path(record).read_text())
    if expected['exe'] != str(Path(executable).resolve()):
        return False
    try:
        fd = os.pidfd_open(expected['pid'])
    except ProcessLookupError:
        return False
    try:
        if identity(expected['pid']) != expected:
            return False
        if stop:
            signal.pidfd_send_signal(fd, signal.SIGTERM)
        return True
    except (FileNotFoundError, ProcessLookupError):
        return False
    finally:
        os.close(fd)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('mode', choices=['record', 'alive', 'stop'])
    parser.add_argument('record')
    parser.add_argument('executable')
    parser.add_argument('pid', nargs='?', type=int)
    args = parser.parse_args()
    if args.mode == 'record':
        state = identity(args.pid)
        wanted = str(Path(args.executable).resolve())
        start = state['start']
        until = time.monotonic() + 3
        while state['exe'] != wanted:
            if time.monotonic() >= until:
                raise ValueError('child executable differs from the requested binary')
            time.sleep(0.02)
            state = identity(args.pid)
            if state['start'] != start:
                raise ValueError('child PID changed during startup')
        fd = os.open(args.record, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'w') as output:
            json.dump(state, output)
        return
    if not act(args.record, args.executable, args.mode == 'stop'):
        raise SystemExit(1)


if __name__ == '__main__':
    main()

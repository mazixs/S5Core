"""Small helpers shared by the orchestrator and the cell."""

import ctypes
import hashlib
import json
import os
import re
import signal
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REPO = os.path.dirname(os.path.dirname(ROOT))
CLK = os.sysconf("SC_CLK_TCK")

_DUR = re.compile(r"^\s*(\d+(?:\.\d+)?)\s*(ms|s|m|h)?\s*$")


def seconds(v):
    """'5m', '30s', '250ms', 12 -> seconds as float."""
    if isinstance(v, (int, float)):
        return float(v)
    m = _DUR.match(str(v))
    if not m:
        raise ValueError(f"not a duration: {v!r}")
    n, unit = float(m.group(1)), m.group(2) or "s"
    return n * {"ms": 0.001, "s": 1, "m": 60, "h": 3600}[unit]


def go_duration(sec):
    """Seconds -> a duration Go's flag package parses."""
    ms = int(round(sec * 1000))
    return f"{ms // 1000}s" if ms % 1000 == 0 else f"{ms}ms"


def cpu_list(spec):
    """'0-2,8' -> {0, 1, 2, 8}."""
    out = set()
    for part in str(spec).split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            a, b = part.split("-", 1)
            out.update(range(int(a), int(b) + 1))
        else:
            out.add(int(part))
    if not out:
        raise ValueError(f"empty CPU list: {spec!r}")
    return out


def write_json(path, obj):
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(obj, f, indent=2, ensure_ascii=False, sort_keys=True)
        f.write("\n")
    os.replace(tmp, path)


def read_json(path, default=None):
    try:
        with open(path) as f:
            return json.load(f)
    except (OSError, ValueError):
        return default


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def now():
    return time.strftime("%Y-%m-%dT%H:%M:%S")


_libc = None


def set_pdeathsig(sig=signal.SIGKILL):
    """Ask the kernel to send sig to this process when its parent exits."""
    global _libc
    if _libc is None:
        _libc = ctypes.CDLL(None, use_errno=True)
    _libc.prctl(1, int(sig), 0, 0, 0)  # PR_SET_PDEATHSIG


def proc_stat(pid):
    """CPU ticks, RSS, peak RSS, fds and threads of pid, or None if it is gone."""
    try:
        with open(f"/proc/{pid}/stat") as f:
            fields = f.read().rsplit(")", 1)[1].split()
        status = {}
        with open(f"/proc/{pid}/status") as f:
            for line in f:
                k, _, v = line.partition(":")
                status[k] = v.split()
        fds = len(os.listdir(f"/proc/{pid}/fd"))
    except (OSError, IndexError):
        return None
    return {
        "cpu_s": (int(fields[11]) + int(fields[12])) / CLK,
        "rss_kb": int(status.get("VmRSS", [0])[0]),
        "hwm_kb": int(status.get("VmHWM", [0])[0]),
        "threads": int(status.get("Threads", [0])[0]),
        "fds": fds,
    }


def cpu_times(cpus=None):
    """Busy seconds (user+nice+system+steal) summed over cpus, from /proc/stat.
    irq and softirq are left out: the kernel's own loopback work lands there
    and is not charged to any process, so it would read as foreign load."""
    busy = 0
    with open("/proc/stat") as f:
        for line in f:
            if not line.startswith("cpu") or line.startswith("cpu "):
                continue
            name, *v = line.split()
            if cpus is not None and int(name[3:]) not in cpus:
                continue
            v = list(map(int, v))
            busy += v[0] + v[1] + v[2] + (v[7] if len(v) > 7 else 0)
    return busy / CLK


def mem_available_mb():
    with open("/proc/meminfo") as f:
        for line in f:
            if line.startswith("MemAvailable:"):
                return int(line.split()[1]) // 1024
    return 0


def netns_inode():
    return os.readlink("/proc/self/ns/net")

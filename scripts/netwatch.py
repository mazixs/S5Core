#!/usr/bin/env python3
"""Bounded, independent Linux network checks; no tunnel or routing changes.

External DNS replies and TCP connects establish reachability of those targets,
not delivery of application UDP. Logs contain aliases and numeric counters,
never DNS answer addresses, configuration, payloads or exception strings.
"""
import argparse
import concurrent.futures
import datetime
import json
import logging
import logging.handlers
import os
from pathlib import Path
import secrets
import socket
import stat
import struct
import subprocess
import time
import urllib.request


TARGETS = (("resolver_a", "1.1.1.1"), ("resolver_b", "8.8.8.8"))
UDP_COUNTERS = ("InDatagrams", "OutDatagrams", "InErrors", "RcvbufErrors", "SndbufErrors", "NoPorts")
TCP_COUNTERS = ("RetransSegs", "InErrs", "OutRsts", "AttemptFails", "EstabResets")
EXT_COUNTERS = ("ListenOverflows", "ListenDrops", "TCPTimeouts", "TCPSynRetrans", "TCPBacklogDrop")


def error_kind(err):
    if isinstance(err, (TimeoutError, socket.timeout, subprocess.TimeoutExpired)):
        return "timeout"
    if isinstance(err, OSError):
        return "os_error_" + str(err.errno)
    return type(err).__name__


def dns_query(transaction):
    question = b"\x07example\x03com\x00" + struct.pack("!HH", 1, 1)
    return struct.pack("!HHHHHH", transaction, 0x0100, 1, 0, 0, 0) + question


def valid_dns_reply(data, query):
    if len(data) < 12 or data[:2] != query[:2]:
        return False
    flags, questions = struct.unpack("!HH", data[2:6])
    # A matched, positive answer with the echoed question is evidence of a
    # round trip. Reject truncation, errors and unrelated/spoofed replies.
    return (flags & 0x8000 != 0 and flags & 0x020f == 0 and questions == 1
            and data[12:len(query)] == query[12:] and len(data) >= len(query)
            and struct.unpack("!H", data[6:8])[0] > 0)


def network_check(alias, address, protocol, timeout):
    result = {"target": alias, "protocol": protocol}
    started = time.monotonic()
    try:
        kind = socket.SOCK_DGRAM if protocol == "dns_udp" else socket.SOCK_STREAM
        with socket.socket(socket.AF_INET, kind) as conn:
            conn.settimeout(timeout)
            conn.connect((address, 53 if protocol == "dns_udp" else 443))
            if protocol == "dns_udp":
                query = dns_query(secrets.randbelow(65536))
                conn.send(query)
                reply = conn.recv(4096)
                if not valid_dns_reply(reply, query):
                    result["error"] = "invalid_dns_reply"
        result["ok"] = "error" not in result
    except (OSError, ValueError) as err:
        result.update(ok=False, error=error_kind(err))
    result["elapsed_ms"] = round((time.monotonic() - started) * 1000, 2)
    return result


def protocol_counters(path):
    lines = Path(path).read_text().splitlines()
    result = {}
    for head, values in zip(lines[0::2], lines[1::2]):
        names, numbers = head.split(), values.split()
        if not names or not numbers or names[0] != numbers[0]:
            continue
        for name, value in zip(names[1:], numbers[1:]):
            if name in UDP_COUNTERS + TCP_COUNTERS + EXT_COUNTERS:
                result[names[0].rstrip(":") + "." + name] = int(value)
    return result


def socket_snapshot(pid, native_port):
    # Match inodes to this process, including when it has a bridge netns.
    inodes = set()
    for fd in Path(f"/proc/{pid}/fd").iterdir():
        try:
            link = os.readlink(fd)
            if link.startswith("socket:["):
                inodes.add(link[8:-1])
        except FileNotFoundError:
            continue
    result = {"native": [], "outbound": []}
    for table in ("udp", "udp6"):
        for row in Path(f"/proc/{pid}/net/{table}").read_text().splitlines()[1:]:
            fields = row.split()
            if len(fields) < 13 or fields[9] not in inodes:
                continue
            port = int(fields[1].rsplit(":", 1)[1], 16)
            sendq, recvq = fields[4].split(":")
            group = "native" if native_port and port == native_port else "outbound"
            # Inode is a local socket identity, not an address. It lets a
            # later collector distinguish resets from counter increases.
            result[group].append({"inode": int(fields[9]), "rx_queue": int(recvq, 16),
                                  "tx_queue": int(sendq, 16), "drops": int(fields[-1])})
    return result


def server_snapshot(container, native_port, timeout=2):
    try:
        raw = subprocess.run(["docker", "inspect", "--format",
                              "{{json .State}} {{.RestartCount}}", container],
                             capture_output=True, text=True, timeout=2, check=True).stdout
        state_text, restarts = raw.strip().rsplit(" ", 1)
        state = json.loads(state_text)
        result = {k: state.get(k) for k in ("Running", "OOMKilled", "StartedAt", "FinishedAt", "ExitCode")}
        result["restart_count"] = int(restarts)
        if state.get("Running"):
            pid = state["Pid"]
            # stat field 2 can contain spaces and parentheses.
            stat = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
            result.update(cpu_ticks=int(stat[11]) + int(stat[12]), rss_pages=int(stat[21]))
            result["udp_sockets"] = socket_snapshot(pid, native_port)
            result["network"] = protocol_counters(f"/proc/{pid}/net/snmp") | protocol_counters(f"/proc/{pid}/net/netstat")
            shared = os.stat(f"/proc/{pid}/ns/net").st_ino == os.stat("/proc/self/ns/net").st_ino
            result["shares_host_network"] = shared
            if not shared:
                try:
                    check = subprocess.run(["nsenter", "--target", str(pid), "--net", "--", "python3",
                                            str(Path(__file__).resolve()), "--network-only", "--timeout", str(timeout)],
                                           capture_output=True, text=True, timeout=timeout + 3, check=True)
                    result["external"] = json.loads(check.stdout)
                except (OSError, ValueError, subprocess.SubprocessError) as err:
                    result["namespace_probe_error"] = error_kind(err)
        return result
    except (OSError, ValueError, IndexError, subprocess.SubprocessError) as err:
        return {"error": error_kind(err)}


def host_snapshot():
    result = {}
    for name in ("cpu", "memory", "io"):
        try:
            result["pressure_" + name] = Path("/proc/pressure/" + name).read_text().strip()
        except OSError:
            result["pressure_" + name] = "unavailable"
    result["cpu_ticks"] = [int(x) for x in Path("/proc/stat").read_text().splitlines()[0].split()[1:]]
    result["uptime_s"] = float(Path("/proc/uptime").read_text().split()[0])
    result["network"] = protocol_counters("/proc/net/snmp") | protocol_counters("/proc/net/netstat")
    # Keep device names/addresses out of the log while retaining physical
    # interface error/drop counters for comparison with the network namespace.
    result["interface_errors"] = []
    for row in Path("/proc/net/dev").read_text().splitlines()[2:]:
        values = row.split(":", 1)[1].split()
        result["interface_errors"].append({"rx_errors": int(values[2]), "rx_drops": int(values[3]),
                                           "tx_errors": int(values[10]), "tx_drops": int(values[11])})
    return result


def metrics_snapshot(url):
    try:
        # This endpoint is explicitly loopback; ambient proxies must not
        # redirect the probe or expose the metrics to another host.
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with opener.open(url, timeout=2) as response:
            body = response.read(1024 * 1024).decode()
        result = {}
        prefixes = ("s5core_native_udp_packets_total", "s5core_native_udp_queue_drops_total",
                    "s5core_udp_receive_buffer_drops_total", "s5core_connections_active",
                    "s5core_udp_relay_datagrams_total", "s5core_native_udp_stream_drops_total")
        for row in body.splitlines():
            if row.startswith(prefixes):
                key, value = row.rsplit(" ", 1)
                result[key] = float(value)
        return {"ok": True, "counters": result}
    except (OSError, ValueError) as err:
        return {"ok": False, "error": error_kind(err)}


def take_sample(pool, args):
    started = time.monotonic()
    jobs = [pool.submit(network_check, name, ip, protocol, args.timeout)
            for name, ip in TARGETS for protocol in ("dns_udp", "tcp_443")]
    server_job = pool.submit(server_snapshot, args.container, args.native_port, args.timeout)
    metrics_job = pool.submit(metrics_snapshot, f"http://127.0.0.1:{args.metrics_port}/metrics")
    result = {"time_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
              "host": host_snapshot(), "external": [j.result() for j in jobs],
              "server": server_job.result(), "local_metrics": metrics_job.result()}
    result["sample_ms"] = round((time.monotonic() - started) * 1000, 2)
    return result


class PrivateRotatingHandler(logging.handlers.RotatingFileHandler):
    def _open(self):
        fd = os.open(self.baseFilename, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        return os.fdopen(fd, self.mode, encoding=self.encoding)


def log_handler(folder, max_bytes):
    # Only a directory created by this diagnostic may be rotated or pruned.
    # Never chmod or remove prefixed files in an operator's shared folder.
    marker = folder / ".s5-netwatch"
    try:
        folder.mkdir(parents=True, mode=0o700)
    except FileExistsError:
        info = folder.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise ValueError("output must be a private diagnostic directory")
        try:
            mark_info = marker.lstat()
        except FileNotFoundError:
            raise ValueError("output directory is not owned by this diagnostic") from None
        if not stat.S_ISREG(mark_info.st_mode) or mark_info.st_uid != os.getuid() or mark_info.st_mode & 0o077:
            raise ValueError("invalid diagnostic ownership marker")
        if marker.read_text(encoding="ascii") != "s5-netwatch-v1\n":
            raise ValueError("invalid diagnostic ownership marker")
    else:
        with marker.open("x", encoding="ascii") as mark:
            mark.write("s5-netwatch-v1\n")
        marker.chmod(0o600)
    for old in folder.iterdir():
        if old.name not in {"checks.jsonl", *(f"checks.jsonl.{n}" for n in range(1, 8))}:
            continue
        info = old.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise ValueError("invalid diagnostic log file")
        if info.st_mtime < time.time() - 7 * 86400:
            old.unlink()
    path = folder / "checks.jsonl"
    fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    os.close(fd)
    handler = PrivateRotatingHandler(folder / "checks.jsonl", maxBytes=max_bytes,
                                                   backupCount=7, encoding="utf-8")
    handler.setFormatter(logging.Formatter("%(message)s"))
    return handler


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--container", default="s5core")
    parser.add_argument("--native-port", type=int, default=0)
    parser.add_argument("--metrics-port", type=int, default=8080)
    parser.add_argument("--interval", type=float, default=10)
    parser.add_argument("--timeout", type=float, default=2)
    parser.add_argument("--duration", type=float, default=86400)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--network-only", action="store_true")
    args = parser.parse_args()
    if args.interval < 5 or not 0 < args.timeout <= 5 or args.duration <= 0:
        parser.error("interval must be >=5s, timeout in (0,5], duration >0")
    if args.network_only:
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            jobs = [pool.submit(network_check, name, ip, protocol, args.timeout)
                    for name, ip in TARGETS for protocol in ("dns_udp", "tcp_443")]
            print(json.dumps([job.result() for job in jobs]))
        return
    os.umask(0o077)
    logger = logging.getLogger("netwatch")
    logger.setLevel(logging.INFO)
    if args.output:
        logger.addHandler(log_handler(args.output, 8 * 1024 * 1024))
    else:
        logger.addHandler(logging.StreamHandler())
    deadline = time.monotonic() + args.duration
    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
        while time.monotonic() < deadline:
            started = time.monotonic()
            try:
                sample = take_sample(pool, args)
            except (OSError, ValueError, RuntimeError) as err:
                sample = {"time_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                          "collector_error": error_kind(err)}
            logger.info(json.dumps(sample, separators=(",", ":")))
            if args.once:
                break
            time.sleep(max(0, min(args.interval - (time.monotonic() - started), deadline - time.monotonic())))


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Save metadata for stalled UDP flows of a bridge-networked S5Core container."""

import argparse
from collections import OrderedDict, defaultdict, deque
from contextlib import closing
from dataclasses import dataclass
from datetime import datetime, timezone
from ipaddress import ip_address
import json
import logging
import os
from pathlib import Path
import re
import selectors
import shutil
import signal
import subprocess
import time

from netwatch import log_handler

HISTORY = 120
AFTER = 60
SILENCE = 4
MIN_DATAGRAMS = 8
SEND_IDLE = 1.5
MAX_FLOWS = 2048
MAX_PACKETS = 200_000
MAX_INCIDENTS = 8

PACKET_LINE = re.compile(
    r"^(\d+\.\d+)\s+(\S+)\s+(In|Out|P)\s+IP6?\s+(\S+)\.(\d+) > (\S+)\.(\d+): UDP, length \d+$"
)
CONNTRACK_TUPLE = re.compile(r"\bsrc=(\S+) dst=(\S+) sport=(\d+) dport=(\d+)")
DROPS = re.compile(rb"(\d+) packets? dropped by kernel")


@dataclass(frozen=True, slots=True)
class Packet:
    at: float
    device: str
    outgoing: bool
    source: tuple
    destination: tuple


def parse_packet(line):
    match = PACKET_LINE.fullmatch(line.strip())
    if match is None:
        return None
    stamp, device, direction, source_ip, source_port, target_ip, target_port = match.groups()
    return Packet(float(stamp), device, direction == "Out",
                  (source_ip, int(source_port)), (target_ip, int(target_port)))


def run_text(*command):
    return subprocess.run(command, capture_output=True, text=True, check=True, timeout=2).stdout


def container_network(container):
    raw = run_text("docker", "inspect", "--type", "container", "--format",
                   "{{json .State.Pid}} {{json .NetworkSettings.Ports}}", container)
    pid, ports = raw.split(maxsplit=1)
    if int(pid) == 0:
        return {}, frozenset()
    links = {link["ifindex"]: link["ifname"] for link in json.loads(run_text("ip", "-j", "link", "show"))}
    interfaces = json.loads(run_text("nsenter", "-t", pid, "-n", "ip", "-j", "addr", "show"))
    # link_index is the ifindex of the host-side veth. Capture only there
    # to avoid double-counting the same packet on the bridge and its port.
    bindings = {
        (links[iface["link_index"]], str(ip_address(address["local"])))
        for iface in interfaces
        if iface.get("link_index") in links and iface.get("link_netnsid") is not None
        for address in iface.get("addr_info", [])
        if address.get("family") in {"inet", "inet6"}
    }
    udp_listeners = frozenset(int(p.split("/")[0]) for p in (json.loads(ports) or {}) if p.endswith("/udp"))
    return bindings, udp_listeners


def resolve_outer(local, peer):
    try:
        entries = run_text("conntrack", "-G", "-p", "udp",
                           "-s", local[0], "-d", peer[0],
                           "--orig-port-src", str(local[1]), "--orig-port-dst", str(peer[1]))
        tuples = CONNTRACK_TUPLE.findall(entries)
        if len(tuples) != 2:
            return None
        source, destination, sport, dport = tuples[0]
        if ((str(ip_address(source)), int(sport)), (str(ip_address(destination)), int(dport))) != (local, peer):
            return None
        source, destination, sport, dport = tuples[1]
        outer_local = str(ip_address(destination)), int(dport)
        outer_peer = str(ip_address(source)), int(sport)
        route = json.loads(run_text("ip", "-j", "route", "get", outer_peer[0], "from", outer_local[0]))
        return route[0]["dev"], outer_local, outer_peer
    except (OSError, subprocess.SubprocessError, KeyError, ValueError, IndexError):
        return None


@dataclass(slots=True)
class Flow:
    replies: int = 0
    sent_in_gap: int = 0
    gap_start: float = 0
    last_send: float = 0
    last_reply: float = 0
    triggered: bool = False

    def observe(self, at, sending):
        if not sending:
            self.last_reply = at
            self.replies += 1
            self.sent_in_gap = 0
            self.triggered = False
            return False
        if self.sent_in_gap == 0 or at - self.last_send > SEND_IDLE:
            self.gap_start = at
            self.sent_in_gap = 0
        self.last_send = at
        self.sent_in_gap += 1
        if (self.triggered or self.replies < MIN_DATAGRAMS or self.sent_in_gap < MIN_DATAGRAMS
                or at - self.gap_start < SILENCE):
            return False
        self.triggered = True
        return True


@dataclass(slots=True)
class Incident:
    at: float
    gap_start: float
    last_reply: float
    inner: tuple
    outer: tuple | None
    dropped_before: int | None


class Collector:
    def __init__(self, started, emit, resolve=resolve_outer):
        self.started = started
        self.emit = emit
        self.resolve = resolve
        self.bindings = set()
        self.udp_listeners = frozenset()
        self.flows = OrderedDict()
        self.pending = {}
        self.packets = deque()
        self.evicted_through = 0

    def update_network(self, bindings, udp_listeners):
        if bindings != self.bindings or udp_listeners != self.udp_listeners:
            self.flows.clear()
        self.bindings = bindings
        self.udp_listeners = udp_listeners

    def observe(self, packet, dropped):
        if len(self.packets) == MAX_PACKETS:
            self.evicted_through = max(self.evicted_through, self.packets.popleft().at)
        self.packets.append(packet)
        # On the host-side veth, In and P (PACKET_OTHERHOST) come from the
        # container. A frame addressed to the bridge's MAC can appear as P.
        sending = not packet.outgoing
        local, peer = ((packet.source, packet.destination) if sending
                       else (packet.destination, packet.source))
        if (packet.device, local[0]) not in self.bindings or local[1] in self.udp_listeners:
            return
        key = packet.device, local, peer
        if key not in self.flows:
            if not sending:
                return
            if len(self.flows) == MAX_FLOWS:
                self.flows.popitem(last=False)
            self.flows[key] = Flow()
        self.flows.move_to_end(key)
        flow = self.flows[key]
        if flow.observe(packet.at, sending) and key not in self.pending and len(self.pending) < MAX_INCIDENTS:
            self.pending[key] = Incident(packet.at, flow.gap_start, flow.last_reply, key,
                                         self.resolve(local, peer), dropped)

    def advance(self, now, dropped, *, stopping=False):
        for key, incident in list(self.pending.items()):
            end = incident.at + AFTER
            if stopping or now >= end:
                self.save(incident, min(now, end), dropped)
                del self.pending[key]
        # Keep one extra second so tick jitter cannot remove the first packet of an incident.
        keep_from = min((item.at - HISTORY for item in self.pending.values()), default=now - HISTORY) - 1
        while self.packets and self.packets[0].at < keep_from:
            self.evicted_through = max(self.evicted_through, self.packets.popleft().at)

    def save(self, incident, end, dropped):
        begin = incident.at - HISTORY
        seconds = defaultdict(lambda: [0, 0, 0, 0])
        for packet in self.packets:
            if not begin <= packet.at <= end:
                continue
            direction = match_direction(packet, incident.inner, outgoing=False)
            if direction is not None:
                seconds[int(packet.at)][direction] += 1
            if incident.outer is not None:
                direction = match_direction(packet, incident.outer, outgoing=True)
                if direction is not None:
                    seconds[int(packet.at)][direction + 2] += 1
        self.emit({
            "event": "udp_reply_gap", "trigger_utc": utc(incident.at),
            "last_inner_reply_utc": utc(incident.last_reply), "gap_send_start_utc": utc(incident.gap_start),
            "from_utc": utc(begin), "until_utc": utc(end),
            "history_truncated": begin < self.started or begin <= self.evicted_through,
            "post_truncated": end < incident.at + AFTER,
            "kernel_drops_at_trigger": incident.dropped_before, "kernel_drops_at_save": dropped,
            "container": endpoint_record(incident.inner), "external": endpoint_record(incident.outer),
            "columns": ["unix_second", "container_sent", "container_received", "external_sent", "external_received"],
            "samples": [
                [second, *counts[:2], *(counts[2:] if incident.outer is not None else [None, None])]
                for second, counts in sorted(seconds.items())
            ],
        })


def match_direction(packet, endpoints, *, outgoing):
    device, local, peer = endpoints
    if packet.device != device:
        return None
    if packet.outgoing == outgoing and (packet.source, packet.destination) == (local, peer):
        return 0
    if packet.outgoing != outgoing and (packet.source, packet.destination) == (peer, local):
        return 1
    return None


def endpoint_record(endpoints):
    if endpoints is None:
        return None
    device, (local_ip, local_port), (peer_ip, peer_port) = endpoints
    return dict(device=device, local_ip=local_ip, local_port=local_port, peer_ip=peer_ip, peer_port=peer_port)


def utc(stamp):
    return datetime.fromtimestamp(stamp, timezone.utc).isoformat(timespec="milliseconds")


def capture(container, collector):
    command = ["tcpdump", "-p", "-i", "any", "-y", "LINUX_SLL2", "-B", "4096",
               "-s", "128", "-nn", "-tt", "-q", "-l", "udp"]
    with subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          env={**os.environ, "LC_ALL": "C"}) as process, \
            selectors.DefaultSelector() as selector:
        selector.register(process.stdout, selectors.EVENT_READ, bytearray())
        selector.register(process.stderr, selectors.EVENT_READ, bytearray())
        dropped = None
        ready = False
        next_refresh = next_stats = 0
        try:
            while selector.get_map():
                now = time.monotonic()
                if now >= next_refresh:
                    next_refresh = now + 5
                    try:
                        collector.update_network(*container_network(container))
                    except (OSError, subprocess.SubprocessError, KeyError, ValueError):
                        collector.update_network(set(), frozenset())
                        logging.warning("Unable to refresh S5Core container network")
                if ready and now >= next_stats and process.poll() is None:
                    next_stats = now + 5
                    process.send_signal(signal.SIGUSR1)
                for key, _ in selector.select(0.25):
                    data = os.read(key.fd, 64 * 1024)
                    if not data:
                        selector.unregister(key.fileobj)
                        continue
                    key.data.extend(data)
                    lines = key.data.split(b"\n")
                    key.data[:] = lines.pop()
                    for line in lines:
                        if key.fileobj == process.stdout:
                            packet = parse_packet(line.decode("ascii", errors="replace"))
                            if packet is not None:
                                collector.observe(packet, dropped)
                        elif match := DROPS.search(line):
                            dropped = int(match.group(1))
                        elif b"listening on any" in line:
                            ready = True
                            logging.info("%s", line.decode(errors="replace"))
                        elif not ready:
                            logging.warning("%s", line.decode(errors="replace"))
                collector.advance(time.time(), dropped)
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    process.kill()
            collector.advance(time.time(), dropped, stopping=True)
        raise RuntimeError(f"tcpdump exited with status {process.returncode}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--container", default="s5core")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    for command in ("tcpdump", "conntrack", "docker", "nsenter", "ip"):
        if shutil.which(command) is None:
            parser.error(f"required command not found: {command}")
    os.umask(0o077)
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    logger = logging.getLogger("udp-incidents")
    logger.propagate = False
    with closing(log_handler(args.output, 8 * 1024 * 1024, "udp-incidents.jsonl")) as handler:
        logger.addHandler(handler)
        collector = Collector(time.time(), lambda event: logger.info(json.dumps(event, separators=(",", ":"))))

        def stop(signum, frame):
            raise KeyboardInterrupt

        signal.signal(signal.SIGTERM, stop)
        try:
            capture(args.container, collector)
        except KeyboardInterrupt:
            pass
        except (OSError, RuntimeError) as err:
            parser.exit(1, f"{err}\n")


if __name__ == "__main__":
    main()

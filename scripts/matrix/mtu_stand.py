#!/usr/bin/env python3
"""Stand with a narrow link for native UDP (plan task M-1, docs/plan/game-fixes.md).

    A (client, 1500) - R1 =(narrow link, MTU M on both ends)= R2 - B (server, 1500)
    A ----------------------- management link ---------------------------- B

Four network namespaces in `unshare -Urnm`, no root: the script re-executes
itself under unshare. Not A-R-B: veth drops a frame larger than the MTU of
the receiving end silently (is_skb_forwardable), which is a different black
hole than a missing PTB. "PTB filtered" is nft in the output chains of R1 and
R2 dropping ICMP frag-needed and ICMPv6 packet-too-big. The management link
carries the server metrics and the echo counts, so a TCP black hole on the
narrow link does not take the measurement with it.

    mtu_stand.py build [--ref HEAD] [--bin DIR]   s5core, s5client from git archive, mtuprobe
    mtu_stand.py smoke --out DIR                   one short cell, checks native is counted
    mtu_stand.py udp   --out DIR [--cells ...]     size sweep: tunnel against direct UDP
    mtu_stand.py quic  --out DIR                   quic-go through native and directly
    mtu_stand.py tcp   --out DIR                   bulk TCP, tcp_mtu_probing 0/1/2
    mtu_stand.py summary DIR [--json FILE]         thresholds of the plan and tables

Every run stops before a cell that would not fit --budget (280 s) and the
next run resumes: cells whose JSON exists are skipped. Results: docs/benchmarks/mtu-native-2026-09-26.md.
"""
import argparse
import json
import os
import signal
import socket
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
BIN = os.path.join(ROOT, "bench", "mtu", "bin")
PSK = "mtu-stand-psk-0123456789abcdef!!"
# native carries a SOCKS5 UDP datagram up to 1374 bytes (pkg/nativeudp MaxWire 1400
# less 26): the application payload limit is that less the SOCKS header.
NATIVE_MAX = 1374
NATIVE_OVERHEAD = 26
SOCKS_HEAD = {4: 10, 6: 22}
DELAY_MS = 5

ADDR = {
    4: dict(a1="10.1.0.2", a2="10.1.0.3", r1a="10.1.0.1", r1n="10.3.0.1", r2n="10.3.0.2", r2b="10.2.0.1",
            b1="10.2.0.2", b2="10.2.0.3", pfx=24),
    6: dict(a1="fd01::2", a2="fd01::3", r1a="fd01::1", r1n="fd03::1", r2n="fd03::2", r2b="fd02::1",
            b1="fd02::2", b2="fd02::3", pfx=64),
}
MGMT_A, MGMT_B = "10.9.0.1", "10.9.0.2"
PORT = dict(obfs=1443, udp=1444, plain=1080, client=1080, metrics=9100, mgmt=9001, echo=9000, http=8080, h3=4433)
UDP_CELLS = [(f, m, p) for f in (4, 6) for m in (1500, 1420, 1400, 1358, 1280) for p in ("pass", "filter")
             if not (m == 1500 and p == "filter")]
# The fourth field is InitialPacketSize of both QUIC ends: the quic-go default
# 1280 does not fit an IPv6 path of 1280 even directly (1280 + 48 > 1280). The
# fifth turns path MTU discovery off: QUIC then keeps the initial size. 1364
# and 1352 are the native limit before M-2; since M-2 the limit on a path of
# 1500 is 1392-1400 on the wire, and 1356 and 1344 fit its lowest.
QUIC_CELLS = [(4, 1500, "pass", 0, True), (4, 1400, "pass", 0, True), (4, 1400, "filter", 0, True),
              (6, 1500, "pass", 0, True), (6, 1280, "pass", 0, True), (6, 1280, "filter", 0, True),
              (6, 1280, "pass", 1232, True), (6, 1280, "filter", 1232, True),
              (4, 1500, "pass", 1364, False), (6, 1500, "pass", 1352, False),
              (4, 1500, "pass", 1356, False), (6, 1500, "pass", 1344, False)]
TCP_CELLS = [(4, 1400, "filter", 0), (4, 1400, "filter", 1), (4, 1400, "filter", 2), (6, 1400, "filter", 0), (6, 1400, "filter", 1),
             (4, 1500, "pass", 0), (4, 1500, "pass", 1)]


def hostport(ip, port):
    return f"[{ip}]:{port}" if ":" in ip else f"{ip}:{port}"


# Children get PATH and nothing else: a proxy variable of the caller would send
# the HTTP of the probes (and their DNS) off the stand.
CLEAN = {"PATH": os.environ.get("PATH", "/usr/sbin:/usr/bin:/bin")}


def sh(*cmd, check=True, **kw):
    return subprocess.run(cmd, check=check, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, env=CLEAN, **kw)


def nsx(ns, *cmd, check=True):
    return sh("ip", "netns", "exec", ns, *cmd, check=check)


def inner():
    """Re-executes under unshare unless already there."""
    if os.environ.get("MTU_STAND_INNER") == "1":
        return
    env = dict(os.environ, MTU_STAND_INNER="1")
    os.execvpe("unshare", ["unshare", "-Urnm", "--", sys.executable, os.path.abspath(__file__)] + sys.argv[1:], env)


# --- topology ---------------------------------------------------------------

class Stand:
    def __init__(self, fam, mtu, ptb, probing=None, out=None):
        self.fam, self.mtu, self.ptb, self.probing, self.out = fam, mtu, ptb, probing, out
        self.a = ADDR[fam]
        self.procs = {}
        self.logs = []

    def up(self):
        for ns in ("A", "R1", "R2", "B"):
            sh("ip", "netns", "del", ns, check=False)
            sh("ip", "netns", "add", ns)
            nsx(ns, "ip", "link", "set", "lo", "up")
        sh("ip", "link", "add", "name", "a0", "netns", "A", "type", "veth", "peer", "name", "r1a", "netns", "R1")
        sh("ip", "link", "add", "name", "r1n", "netns", "R1", "type", "veth", "peer", "name", "r2n", "netns", "R2")
        sh("ip", "link", "add", "name", "r2b", "netns", "R2", "type", "veth", "peer", "name", "b0", "netns", "B")
        sh("ip", "link", "add", "name", "am", "netns", "A", "type", "veth", "peer", "name", "bm", "netns", "B")
        for fam in (4, 6):
            a = ADDR[fam]
            extra = ["nodad"] if fam == 6 else []
            pl = f"/{a['pfx']}"
            for ns, dev, keys in (("A", "a0", ("a1", "a2")), ("R1", "r1a", ("r1a",)), ("R1", "r1n", ("r1n",)),
                                  ("R2", "r2n", ("r2n",)), ("R2", "r2b", ("r2b",)), ("B", "b0", ("b1", "b2"))):
                for k in keys:
                    nsx(ns, "ip", "addr", "add", a[k] + pl, "dev", dev, *extra)
        nsx("A", "ip", "addr", "add", MGMT_A + "/24", "dev", "am")
        nsx("B", "ip", "addr", "add", MGMT_B + "/24", "dev", "bm")
        for ns, dev, mtu in (("A", "a0", 1500), ("R1", "r1a", 1500), ("R1", "r1n", self.mtu), ("R2", "r2n", self.mtu),
                             ("R2", "r2b", 1500), ("B", "b0", 1500), ("A", "am", 1500), ("B", "bm", 1500)):
            nsx(ns, "ip", "link", "set", dev, "mtu", str(mtu), "up")
            nsx(ns, "ethtool", "-K", dev, "tso", "off", "gso", "off", "gro", "off", check=False)
        for fam in (4, 6):
            a, v = ADDR[fam], ["-6"] if fam == 6 else []
            nsx("A", "ip", *v, "route", "add", "default", "via", a["r1a"])
            nsx("B", "ip", *v, "route", "add", "default", "via", a["r2b"])
            nsx("R1", "ip", *v, "route", "add", "10.2.0.0/24" if fam == 4 else "fd02::/64", "via", a["r2n"])
            nsx("R2", "ip", *v, "route", "add", "10.1.0.0/24" if fam == 4 else "fd01::/64", "via", a["r1n"])
        for ns in ("R1", "R2"):
            nsx(ns, "sysctl", "-qw", "net.ipv4.ip_forward=1", "net.ipv6.conf.all.forwarding=1")
        for ns, dev in (("R1", "r1n"), ("R2", "r2n")):
            nsx(ns, "tc", "qdisc", "add", "dev", dev, "root", "netem", "delay", f"{DELAY_MS}ms", "limit", "10000")
        if self.ptb == "filter":
            rules = ("table inet f {\n chain out {\n  type filter hook output priority 0;\n"
                     "  icmp type destination-unreachable icmp code frag-needed drop\n"
                     "  icmpv6 type packet-too-big drop\n }\n}\n")
            for ns in ("R1", "R2"):
                subprocess.run(["ip", "netns", "exec", ns, "nft", "-f", "-"], input=rules, text=True, check=True, env=CLEAN)
        if self.probing is not None:
            for ns in ("A", "B"):
                nsx(ns, "sysctl", "-qw", f"net.ipv4.tcp_mtu_probing={self.probing}")
        for ns in ("R1", "R2"):
            self.spawn(ns.lower(), ns, ["sleep", "3600"], {})
        return self

    def spawn(self, name, ns, argv, env):
        log = os.path.join(self.out, f"{name}.log") if self.out else os.devnull
        f = open(log, "ab")
        self.logs.append(f)
        p = subprocess.Popen(["ip", "netns", "exec", ns] + argv, env=CLEAN | env, stdin=subprocess.DEVNULL,
                             stdout=f, stderr=subprocess.STDOUT, start_new_session=True)
        self.procs[name] = p
        return p

    def wait_tcp(self, ns, host, port, timeout=10):
        own = os.open("/proc/self/ns/net", os.O_RDONLY)
        target = os.open(f"/run/netns/{ns}", os.O_RDONLY)
        try:
            os.setns(target, os.CLONE_NEWNET)
            end = time.monotonic() + timeout
            while time.monotonic() < end:
                try:
                    socket.create_connection((host, port), timeout=0.5).close()
                    return True
                except OSError:
                    time.sleep(0.05)
            return False
        finally:
            os.setns(own, os.CLONE_NEWNET)
            os.close(own)
            os.close(target)

    def start(self, binaries, native=True, echo=()):
        a = self.a
        self.spawn("echo", "B", [binaries["mtuprobe"], "echo", "-udp", hostport(a["b2"], PORT["echo"]),
                                 "-http", hostport(a["b2"], PORT["http"]), "-h3", hostport(a["b2"], PORT["h3"]),
                                 "-mgmt", hostport(MGMT_B, PORT["mgmt"]), *echo], {})
        srv = dict(PROXY_LISTEN_IP=a["b1"], PROXY_PORT=str(PORT["plain"]), OBFS_ENABLED="true",
                   OBFS_PORT=str(PORT["obfs"]), OBFS_PSK=PSK, UDP_PORT=str(PORT["udp"]),
                   METRICS_BIND_ADDR=MGMT_B, METRICS_PORT=str(PORT["metrics"]), REQUIRE_AUTH="false",
                   ALLOW_PRIVATE_DEST="true", LOG_LEVEL="info")
        self.spawn("server", "B", [binaries["s5core"]], srv)
        if not (self.wait_tcp("B", MGMT_B, PORT["mgmt"]) and self.wait_tcp("B", MGMT_B, PORT["metrics"])
                and self.wait_tcp("B", a["b1"], PORT["obfs"])):
            raise RuntimeError("server or echo did not start, see server.log / echo.log")
        cli = dict(CLIENT_LISTEN_ADDR=f"127.0.0.1:{PORT['client']}", SERVER_ADDR=hostport(a["b1"], PORT["obfs"]),
                   OBFS_PSK=PSK, TRANSPORT="obfs", UDP_NATIVE="true" if native else "false", LOG_LEVEL="info")
        self.spawn("client", "A", [binaries["s5client"]], cli)
        if not self.wait_tcp("A", "127.0.0.1", PORT["client"]):
            raise RuntimeError("client did not start, see client.log")

    def pids(self):
        return {"A": "self", "B": str(self.procs["echo"].pid), "R1": str(self.procs["r1"].pid), "R2": str(self.procs["r2"].pid)}

    def netns_flag(self):
        return ",".join(f"{k}={v}" for k, v in self.pids().items())

    def down(self):
        for p in self.procs.values():
            if p.poll() is None:
                try:
                    os.killpg(p.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
        end = time.monotonic() + 5
        for p in self.procs.values():
            try:
                p.wait(timeout=max(0.1, end - time.monotonic()))
            except subprocess.TimeoutExpired:
                os.killpg(p.pid, signal.SIGKILL)
                p.wait()
        for f in self.logs:
            f.close()
        for ns in ("A", "R1", "R2", "B"):
            sh("ip", "netns", "del", ns, check=False)


def read_kernel(pid):
    out = {}
    for f in ("snmp", "netstat"):
        try:
            lines = open(f"/proc/{pid}/net/{f}").read().splitlines()
        except OSError:
            continue
        for names, values in zip(lines[::2], lines[1::2]):
            proto, names = names.split(":", 1)
            for k, v in zip(names.split(), values.split(":", 1)[1].split()):
                out[proto + k] = int(v)
    try:
        for line in open(f"/proc/{pid}/net/snmp6"):
            k, v = line.split()
            out[k] = int(v)
    except OSError:
        pass
    return out


KERNEL_KEYS = ("Frag", "Reasm", "DestUnreach", "TooBig", "MTUP", "RetransSegs", "TCPTimeouts", "RcvbufErrors", "InErrors")


def kernel_delta(a, b):
    return {k: b[k] - a.get(k, 0) for k in b if any(s in k for s in KERNEL_KEYS) and b[k] != a.get(k, 0)}


def client_stats(log):
    stats = []
    try:
        for line in open(log):
            try:
                rec = json.loads(line)
            except ValueError:
                continue
            if rec.get("msg") == "UDP Tunnel closed":
                stats.append({k: v for k, v in rec.items() if k not in ("time", "level", "msg")})
    except OSError:
        pass
    return stats


def binaries(args):
    b = {k: os.path.join(args.bin, k) for k in ("s5core", "s5client", "mtuprobe")}
    missing = [k for k, v in b.items() if not os.path.exists(v)]
    if missing:
        sys.exit(f"missing {missing} in {args.bin}: run mtu_stand.py build")
    return b


def cell_name(fam, mtu, ptb, extra=""):
    return f"v{fam}-{mtu}-{ptb}{extra}"


class Budget:
    def __init__(self, seconds):
        self.end = time.monotonic() + seconds

    def fits(self, need):
        return time.monotonic() + need <= self.end


# --- runs -------------------------------------------------------------------

def run_udp_cell(args, bins, fam, mtu, ptb, sizes, n, name=None):
    name = name or cell_name(fam, mtu, ptb)
    out = os.path.join(args.out, name)
    os.makedirs(out, exist_ok=True)
    st = Stand(fam, mtu, ptb, out=out).up()
    t0 = time.time()
    try:
        st.start(bins)
        a = st.a
        k0 = {h: read_kernel(p) for h, p in st.pids().items() if p != "self"}
        sweep = os.path.join(out, "sweep.json")
        r = nsx("A", bins["mtuprobe"], "sweep", "-socks", f"127.0.0.1:{PORT['client']}",
                "-echo", hostport(a["b2"], PORT["echo"]), "-bind", a["a2"],
                "-mgmt", f"http://{MGMT_B}:{PORT['mgmt']}", "-metrics", f"http://{MGMT_B}:{PORT['metrics']}/metrics",
                "-netns", st.netns_flag(), "-sizes", sizes, "-n", str(n), "-wait", "300ms", "-out", sweep, check=False)
        time.sleep(0.5)
        if r.returncode != 0:
            raise RuntimeError(f"sweep exited {r.returncode}: {r.stdout[-2000:]}")
        doc = json.load(open(sweep))
        closed = client_stats(os.path.join(out, "client.log"))
        # Since M-2 the client finds the limit per association and reports it
        # in its closing line; a build before M-2 has the constant.
        wire = next((c["native_limit"] for c in reversed(closed) if "native_limit" in c), NATIVE_MAX + NATIVE_OVERHEAD)
        doc["cell"] = dict(family=fam, mtu=mtu, ptb=ptb, delay_ms=DELAY_MS, sizes=sizes, n=n,
                           native_limit=wire - NATIVE_OVERHEAD - SOCKS_HEAD[fam], native_wire=wire,
                           started=t0, seconds=round(time.time() - t0, 1))
        doc["client_closed"] = closed
        doc["routers"] = {h: kernel_delta(k0[h], read_kernel(p)) for h, p in st.pids().items() if h in ("R1", "R2")}
        json.dump(doc, open(os.path.join(args.out, name + ".json"), "w"), indent=1)
        return doc
    finally:
        st.down()


def cmd_smoke(args):
    bins = binaries(args)
    doc = run_udp_cell(args, bins, 4, 1500, "pass", "1200:1400:100", 50, name="smoke")
    rows = []
    for r in doc["results"]:
        m = r.get("metrics") or {}
        rows.append((r["size"], r["mode"], r["up"], r["down"], metric(m, "from_client", "native"), metric(m, "from_client", "tcp_oversize"),
                     metric(m, "to_client", "native"), metric(m, "to_client", "tcp_oversize")))
    print("warmup_ms", doc.get("warmup_ms"), "warmup_failed", doc.get("warmup_failed", False))
    print("size mode up down up_native up_oversize down_native down_oversize")
    for row in rows:
        print(*row)
    print("client:", doc["client_closed"])
    ok = any(r[4] > 0 for r in rows if r[1] == "tunnel") and any(r[6] > 0 for r in rows if r[1] == "tunnel")
    print("SMOKE", "OK" if ok else "FAILED: native not counted")
    return 0 if ok else 1


def metric(m, direction, path):
    return sum(v for k, v in m.items() if k.startswith("s5core_native_udp_datagrams_total")
               and f'direction="{direction}"' in k and f'path="{path}"' in k)


def cmd_udp(args):
    bins = binaries(args)
    budget = Budget(args.budget)
    cells = UDP_CELLS
    if args.cells:
        want = set(args.cells.split(","))
        cells = [c for c in cells if cell_name(*c) in want]
    todo = [c for c in cells if not os.path.exists(os.path.join(args.out, cell_name(*c) + ".json"))]
    for c in todo:
        sizes = args.sizes
        if sizes == "auto":
            # At 1280 the band of native is below 1200: IPv4 1184-1215, IPv6 1152-1183.
            sizes = "1100:1452:4" if c[1] == 1280 else "1200:1452:4"
        lo, hi, step = map(int, sizes.split(":"))
        need = ((hi - lo) // step + 1) * 2 * (args.n * 0.0005 + 0.36) + 8
        if not budget.fits(need):
            print(f"budget: {len(todo) - todo.index(c)} cells left, run again to resume")
            return 0
        t = time.monotonic()
        doc = run_udp_cell(args, bins, *c, sizes, args.n)
        print(f"{cell_name(*c)}: {time.monotonic() - t:.0f} s, warmup {doc.get('warmup_ms')} ms, closed at {doc.get('association_closed_at_size')}", flush=True)
    print("udp: all cells done")
    return 0


def cmd_quic(args):
    bins = binaries(args)
    budget = Budget(args.budget)
    for fam, mtu, ptb, initial, pmtud in QUIC_CELLS:
        name = cell_name(fam, mtu, ptb, (f"-i{initial}" if initial else "") + ("" if pmtud else "-fixed"))
        path = os.path.join(args.out, "quic-" + name + ".json")
        if os.path.exists(path):
            continue
        if not budget.fits(2 * 3 * args.timeout + 20):
            print("budget: run again to resume")
            return 0
        out = os.path.join(args.out, "quic-" + name)
        os.makedirs(out, exist_ok=True)
        st = Stand(fam, mtu, ptb, out=out).up()
        t = time.monotonic()
        try:
            quic = ["-initial", str(initial), f"-pmtud={str(pmtud).lower()}"]
            st.start(bins, echo=quic)
            a = st.a
            doc = {"cell": dict(family=fam, mtu=mtu, ptb=ptb, delay_ms=DELAY_MS, initial_packet_size=initial or 1280, pmtud=pmtud)}
            common = ["-target", hostport(a["b2"], PORT["h3"]), "-mgmt", f"http://{MGMT_B}:{PORT['mgmt']}",
                      "-down", str(args.down), "-up", str(args.up), "-timeout", f"{args.timeout}s", *quic]
            for mode in ("tunnel", "direct"):
                f = os.path.join(out, mode + ".json")
                extra = (["-socks", f"127.0.0.1:{PORT['client']}", "-echo", hostport(a["b2"], PORT["echo"]),
                          "-metrics", f"http://{MGMT_B}:{PORT['metrics']}/metrics"] if mode == "tunnel" else ["-bind", a["a2"]])
                k0 = {h: read_kernel(p) for h, p in st.pids().items()}
                k0["A"] = read_kernel(st.procs["client"].pid)
                r = nsx("A", bins["mtuprobe"], "quic", *common, *extra, "-out", f, check=False)
                k1 = {h: read_kernel(p) for h, p in st.pids().items()}
                k1["A"] = read_kernel(st.procs["client"].pid)
                d = json.load(open(f)) if r.returncode == 0 else {"error": r.stdout[-2000:]}
                d["kernel"] = {h: kernel_delta(k0[h], k1[h]) for h in k1}
                doc[mode] = d
            time.sleep(0.5)
            doc["client_closed"] = client_stats(os.path.join(out, "client.log"))
            json.dump(doc, open(path, "w"), indent=1)
            print(f"quic-{name}: {time.monotonic() - t:.0f} s", flush=True)
        finally:
            st.down()
    print("quic: all cells done")
    return 0


def curl(ns, url, socks, timeout, upload=None):
    cmd = ["curl", "-g", "-s", "-o", "/dev/null", "--max-time", str(timeout),
           "-w", "%{http_code} %{size_download} %{size_upload} %{time_total} %{time_starttransfer}"]
    if socks:
        cmd += ["--socks5", socks]
    if upload:
        cmd += ["-H", "Content-Type: application/octet-stream", "--data-binary", "@" + upload]
    r = nsx(ns, *cmd, url, check=False)
    parts = r.stdout.split()
    try:
        code, down, up, total, first = int(parts[0]), int(parts[1]), int(parts[2]), float(parts[3]), float(parts[4])
    except (IndexError, ValueError):
        code, down, up, total, first = 0, 0, 0, float(timeout), 0.0
    # For an upload curl counts what it handed to the socket, not what reached the origin.
    moved = up if upload else down
    return dict(exit=r.returncode, http=code, bytes=moved, seconds=total, first_byte=first,
                mb_per_s=round(moved / total / 1e6, 2) if total else 0)


def cmd_tcp(args):
    bins = binaries(args)
    budget = Budget(args.budget)
    for fam, mtu, ptb, probing in TCP_CELLS:
        name = cell_name(fam, mtu, ptb, f"-probing{probing}")
        if args.cells and name not in args.cells.split(","):
            continue
        path = os.path.join(args.out, "tcp-" + name + ".json")
        if os.path.exists(path):
            continue
        narrow = mtu < 1500
        if not budget.fits(4 * args.narrow_repeats * args.timeout + 20 if narrow else 60):
            print("budget: run again to resume")
            return 0
        out = os.path.join(args.out, "tcp-" + name)
        os.makedirs(out, exist_ok=True)
        st = Stand(fam, mtu, ptb, probing=probing, out=out).up()
        t = time.monotonic()
        try:
            st.start(bins, native=False)
            a = st.a
            size = args.small if narrow else args.large
            blob = os.path.join(out, "upload.bin")
            with open(blob, "wb") as f:
                f.truncate(size)
            base = f"http://{hostport(a['b2'], PORT['http'])}"
            doc = {"cell": dict(family=fam, mtu=mtu, ptb=ptb, tcp_mtu_probing=probing, delay_ms=DELAY_MS, bytes=size)}
            pids = {"A": str(st.procs["client"].pid), "B": str(st.procs["echo"].pid)}
            for mode, socks in (("tunnel", f"127.0.0.1:{PORT['client']}"), ("direct", None)):
                runs = []
                for i in range(args.narrow_repeats if narrow else args.repeats):
                    for kind in ("download", "upload"):
                        k0 = {h: read_kernel(p) for h, p in pids.items()}
                        r = curl("A", base + (f"/bytes?n={size}" if kind == "download" else "/sink"), socks,
                                 args.timeout, upload=blob if kind == "upload" else None)
                        r.update(kind=kind, kernel={h: kernel_delta(k0[h], read_kernel(p)) for h, p in pids.items()})
                        runs.append(r)
                doc[mode] = runs
            doc["ss"] = nsx("A", "ss", "-tin", check=False).stdout[-4000:]
            json.dump(doc, open(path, "w"), indent=1)
            print(f"tcp-{name}: {time.monotonic() - t:.0f} s", flush=True)
        finally:
            os.remove(blob) if os.path.exists(blob) else None
            st.down()
    print("tcp: all cells done")
    return 0


# --- summary ----------------------------------------------------------------

def frac(n, d):
    return round(100.0 * n / d, 2) if d else None


def kernel_sum(k, host, *names):
    return sum((k or {}).get(host, {}).get(n, 0) for n in names)


FRAG = ("IpFragCreates", "Ip6FragCreates")
REASM = ("IpReasmOKs", "Ip6ReasmOKs")
PTB_IN = ("IcmpInDestUnreachs", "Icmp6InPktTooBigs")


def udp_summary(doc):
    c = doc["cell"]
    limit = c["native_limit"]
    rows, by = [], {}
    for r in doc["results"]:
        by.setdefault(r["size"], {})[r["mode"]] = r
    for size in sorted(by):
        t, d = by[size].get("tunnel", {}), by[size].get("direct", {})
        m, k = t.get("metrics") or {}, t.get("kernel") or {}
        rows.append(dict(
            size=size, native=size <= limit,
            t_up=frac(t.get("up", 0), t.get("sent")), t_down=frac(t.get("down", 0), t.get("asked")),
            d_up=frac(d.get("up", 0), d.get("sent")), d_down=frac(d.get("down", 0), d.get("asked")),
            up_native=metric(m, "from_client", "native"), up_oversize=metric(m, "from_client", "tcp_oversize"),
            up_route=metric(m, "from_client", "tcp_route"), down_native=metric(m, "to_client", "native"),
            down_oversize=metric(m, "to_client", "tcp_oversize"), down_route=metric(m, "to_client", "tcp_route"),
            down_failed=metric(m, "to_client", "tcp_failed"),
            stream_drops=sum(v for kk, v in m.items() if "stream_drops" in kk),
            frag_a=kernel_sum(k, "A", *FRAG), frag_b=kernel_sum(k, "B", *FRAG),
            reasm_a=kernel_sum(k, "A", *REASM), reasm_b=kernel_sum(k, "B", *REASM),
            ptb_a=kernel_sum(k, "A", *PTB_IN), ptb_b=kernel_sum(k, "B", *PTB_IN),
            d_frag_a=kernel_sum(d.get("kernel"), "A", *FRAG), d_frag_b=kernel_sum(d.get("kernel"), "B", *FRAG)))

    def same(a, b):
        return a is not None and b is not None and abs(a - b) <= 0.3

    # The threshold of the plan: native within 0.3 pp of direct or zero. Native
    # above direct is the loss of direct at its own PTB, kept apart.
    partial, above = {"up": [], "down": []}, {"up": [], "down": []}
    for r in rows:
        if not r["native"]:
            continue
        for dirn in ("up", "down"):
            tv, dv = r["t_" + dirn], r["d_" + dirn]
            if tv is None or same(tv, dv) or tv == 0:
                continue
            (above if dv is not None and tv > dv else partial)[dirn].append((r["size"], tv, dv))

    def ceiling(key):
        ok = [r["size"] for r in rows if r[key] is not None and r[key] >= 99.7 and (r["native"] or key.startswith("d_"))]
        return max(ok) if ok else None

    nat = [r for r in rows if r["native"]]
    over = [r for r in rows if not r["native"]]
    closed = doc.get("client_closed") or [{}]
    return dict(
        family=c["family"], mtu=c["mtu"], ptb=c["ptb"], native_limit=limit, sizes=c["sizes"], n=c["n"],
        warmup_ms=doc.get("warmup_ms"), association_closed_at=doc.get("association_closed_at_size"),
        direct_ceiling_up=ceiling("d_up"), direct_ceiling_down=ceiling("d_down"),
        native_ceiling_up=ceiling("t_up"), native_ceiling_down=ceiling("t_down"),
        partial_up=partial["up"], partial_down=partial["down"], above_direct_up=above["up"], above_direct_down=above["down"],
        native_frags_a=sum(r["frag_a"] for r in nat), native_frags_b=sum(r["frag_b"] for r in nat),
        native_reasm_a=sum(r["reasm_a"] for r in nat), native_reasm_b=sum(r["reasm_b"] for r in nat),
        ptb_a=sum(r["ptb_a"] for r in rows), ptb_b=sum(r["ptb_b"] for r in rows),
        up_route=sum(r["up_route"] for r in rows), down_route=sum(r["down_route"] for r in rows),
        down_failed=sum(r["down_failed"] for r in rows),
        oversize_t_up=frac(sum(r["t_up"] or 0 for r in over), 100 * len(over)) if over else None,
        oversize_t_down=frac(sum(r["t_down"] or 0 for r in over), 100 * len(over)) if over else None,
        oversize_stream_drops=sum(r["stream_drops"] for r in over),
        oversize_native=sum(r["up_native"] + r["down_native"] for r in over),
        client=closed[-1], routers=doc.get("routers"), rows=rows)


def quic_summary(doc):
    out = dict(cell=doc["cell"])
    for mode in ("tunnel", "direct"):
        d = doc.get(mode) or {}
        if "phases" not in d:
            out[mode] = dict(error=d.get("error", "missing"))
            continue

        def final(events):
            return events[-1]["mtu"] if events else None
        cm = [e for e in d.get("client_mtu") or []]
        om = [e for e in d.get("origin_mtu") or []]
        ph = {}
        for p in d["phases"]:
            m = p.get("metrics") or {}
            e = dict(mb_per_s=round(p["mb_per_s"], 2), seconds=round(p["seconds"], 2), error=p.get("error"))
            for key, dirn in (("Up", "client_to_origin"), ("Down", "origin_to_client")):
                s = p.get(dirn)
                if s:
                    e[dirn] = dict(packets=s["packets"], max=s["max"], steady=s["steady_size"], over_native_limit=s["over_native_limit"],
                                   over_share=frac(s["over_native_limit"], s["packets"]))
            if m:
                e["path"] = dict(up_native=metric(m, "from_client", "native"), up_oversize=metric(m, "from_client", "tcp_oversize"),
                                 up_route=metric(m, "from_client", "tcp_route"), down_native=metric(m, "to_client", "native"),
                                 down_oversize=metric(m, "to_client", "tcp_oversize"), down_route=metric(m, "to_client", "tcp_route"),
                                 stream_drops=sum(v for k, v in m.items() if "stream_drops" in k))
                pa = e["path"]
                for dirn in ("up", "down"):
                    pa[dirn + "_native_share"] = frac(pa[dirn + "_native"], sum(pa[dirn + k] for k in ("_native", "_oversize", "_route")))
            ph[p["name"]] = e
        out[mode] = dict(client_mtu_final=final(cm), origin_mtu_final=final(om),
                         client_mtu=[(e["at_ms"], e["mtu"], e["done"]) for e in cm],
                         origin_mtu=[(e["at_ms"], e["mtu"], e["done"]) for e in om], phases=ph,
                         native_limit=d.get("native_limit_payload"))
    closed = doc.get("client_closed") or []
    if closed and "tunnel" in out:
        # The limit the client found (M-2), and what it dropped past it.
        c = closed[-1]
        out["tunnel"]["client"] = {k: c.get(k) for k in ("native_limit", "size_probes", "dropped_oversize_sent",
                                                          "dropped_oversize_received", "tcp_sent_oversize") if k in c}
    return out


def tcp_summary(doc):
    out = dict(cell=doc["cell"])
    for mode in ("tunnel", "direct"):
        rows = []
        for r in doc.get(mode) or []:
            k = r.get("kernel") or {}
            rows.append(dict(kind=r["kind"], exit=r["exit"], bytes=r["bytes"], seconds=round(r["seconds"], 3), mb_per_s=r["mb_per_s"],
                             first_byte=r.get("first_byte"),
                             mtup_success=kernel_sum(k, "A", "TcpExtTCPMTUPSuccess") + kernel_sum(k, "B", "TcpExtTCPMTUPSuccess"),
                             mtup_fail=kernel_sum(k, "A", "TcpExtTCPMTUPFail") + kernel_sum(k, "B", "TcpExtTCPMTUPFail"),
                             timeouts=kernel_sum(k, "A", "TcpExtTCPTimeouts") + kernel_sum(k, "B", "TcpExtTCPTimeouts")))
        out[mode] = rows
    return out


def cmd_summary(args):
    names = sorted(os.listdir(args.dir))
    res = dict(udp=[], quic=[], tcp=[])
    for n in names:
        if not n.endswith(".json"):
            continue
        doc = json.load(open(os.path.join(args.dir, n)))
        if n.startswith("quic-"):
            res["quic"].append(quic_summary(doc))
        elif n.startswith("tcp-"):
            res["tcp"].append(tcp_summary(doc))
        elif n.startswith("v"):
            res["udp"].append(udp_summary(doc))
    order = {1500: 0, 1420: 1, 1400: 2, 1358: 3, 1280: 4}
    res["udp"].sort(key=lambda c: (c["family"], order.get(c["mtu"], 9), c["ptb"] != "pass"))
    print("fam mtu  ptb    limit dir_up dir_dn nat_up nat_dn partial(up/dn)       frags A/B  reasm A/B ptb A/B route up/dn over_up over_dn drops")
    for c in res["udp"]:
        def band(p):
            return f"{p[0][0]}-{p[-1][0]}({len(p)})" if p else "-"
        print(f"v{c['family']}  {c['mtu']} {c['ptb']:6} {c['native_limit']:5} {c['direct_ceiling_up']!s:6} {c['direct_ceiling_down']!s:6} "
              f"{c['native_ceiling_up']!s:6} {c['native_ceiling_down']!s:6} {band(c['partial_up']):>10}/{band(c['partial_down']):<10} "
              f"{c['native_frags_a']}/{c['native_frags_b']} {c['native_reasm_a']}/{c['native_reasm_b']} {c['ptb_a']}/{c['ptb_b']} "
              f"{c['up_route']:g}/{c['down_route']:g} {c['oversize_t_up']} {c['oversize_t_down']} {c['oversize_stream_drops']:g}")
    for q in res["quic"]:
        print("quic", q["cell"], json.dumps({m: {k: v for k, v in q[m].items() if k not in ("client_mtu", "origin_mtu")} for m in ("tunnel", "direct") if m in q}))
    for t in res["tcp"]:
        print("tcp", t["cell"], json.dumps({m: t[m] for m in ("tunnel", "direct")}))
    if args.json:
        cols = ("size", "t_up", "t_down", "d_up", "d_down", "frag_a", "frag_b", "reasm_a", "reasm_b")
        udp = []
        for c in res["udp"]:
            c = dict(c)
            rows = c.pop("rows")
            c["curve"] = {k: [r[k] for r in rows] for k in cols}
            udp.append(c)
        out = dict(meta=dict(kernel=os.uname().release, delay_ms_each_narrow_end=DELAY_MS, native_max_payload=NATIVE_MAX,
                             curve_columns="t_ = native through the tunnel, d_ = direct UDP, % delivered; frag/reasm = "
                                           "IpFragCreates/IpReasmOKs (Ip6 for IPv6) at A and B in the tunnel window"),
                   udp=udp, quic=res["quic"], tcp=res["tcp"])
        with open(args.json, "w") as f:
            json.dump(out, f, separators=(",", ":"))
            f.write("\n")
    return 0


def cmd_build(args):
    os.makedirs(args.bin, exist_ok=True)
    src = os.path.join(args.bin, "src")
    sh("rm", "-rf", src)
    os.makedirs(src)
    rev = sh("git", "-C", ROOT, "rev-parse", "--short", args.ref).stdout.strip()
    archive = subprocess.Popen(["git", "-C", ROOT, "archive", args.ref], stdout=subprocess.PIPE)
    subprocess.run(["tar", "-x", "-C", src], stdin=archive.stdout, check=True)
    archive.wait()
    env = dict(os.environ, CGO_ENABLED="0")
    for cmd in ("s5core", "s5client"):
        subprocess.run(["go", "build", "-trimpath", "-o", os.path.join(args.bin, cmd), f"./cmd/{cmd}"],
                       cwd=src, env=env, check=True)
    subprocess.run(["go", "build", "-o", os.path.join(args.bin, "mtuprobe"), "./mtuprobe"], cwd=HERE, env=env, check=True)
    sh("rm", "-rf", src)
    print(f"built {rev} into {args.bin}")
    return 0


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)
    b = sub.add_parser("build")
    b.add_argument("--ref", default="HEAD")
    b.add_argument("--bin", default=BIN)
    for name in ("smoke", "udp", "quic", "tcp"):
        s = sub.add_parser(name)
        s.add_argument("--bin", default=BIN)
        s.add_argument("--out", required=True)
        s.add_argument("--budget", type=float, default=280)
        if name == "udp":
            s.add_argument("--cells", default="")
            s.add_argument("--sizes", default="auto")
            s.add_argument("--n", type=int, default=200)
        if name == "quic":
            s.add_argument("--down", type=int, default=8 << 20)
            s.add_argument("--up", type=int, default=4 << 20)
            s.add_argument("--timeout", type=int, default=30)
        if name == "tcp":
            s.add_argument("--small", type=int, default=4 << 20)
            s.add_argument("--large", type=int, default=200 << 20)
            s.add_argument("--repeats", type=int, default=3)
            s.add_argument("--narrow-repeats", type=int, default=1)
            s.add_argument("--cells", default="")
            s.add_argument("--timeout", type=int, default=30)
    s = sub.add_parser("summary")
    s.add_argument("dir")
    s.add_argument("--json", default="")
    args = p.parse_args()
    if args.cmd == "build":
        return cmd_build(args)
    if args.cmd == "summary":
        return cmd_summary(args)
    inner()
    # A private /run: the namespaces of this stand live and die with the process.
    sh("mount", "-t", "tmpfs", "none", "/run")
    os.makedirs("/run/netns")
    os.makedirs(args.out, exist_ok=True)
    return {"smoke": cmd_smoke, "udp": cmd_udp, "quic": cmd_quic, "tcp": cmd_tcp}[args.cmd](args)


if __name__ == "__main__":
    sys.exit(main())

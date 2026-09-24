"""One measurement: server, client and generator in a fresh network namespace.

Runs as `matrix.py cell SPEC` under `unshare --user --map-root-user --net`,
started by the orchestrator. Every wait here is bounded, and the outcome is
always written to run.json, including when the cell is told to stop.
"""

import base64
import json
import os
import random
import re
import resource
import select
import signal
import socket
import struct
import subprocess
import sys
import threading
import time
import urllib.request

from .plan import CLIENT_IP
from .util import go_duration, netns_inode, proc_stat, read_json, seconds, set_pdeathsig, write_json

PORTS = {"plain": 41080, "obfs": 41443, "wss": 41444, "metrics": 41090, "client": 41081}
GAUGES = ("s5core_sessions", "s5core_connections_active", "s5core_obfs_handshake_failures_total",
          "s5core_half_close_failures_total", "s5core_connections_rejected_total")
PORT_WAIT = 10
WARMUP_TIMEOUT = 60
STOP_WAIT = 5


class SetupFailed(Exception):
    pass


class Stop(Exception):
    pass


_stop = False


def _on_term(signum, frame):
    global _stop
    _stop = True


def _child_setup():
    set_pdeathsig(signal.SIGKILL)


def _sh(cmd, timeout=10):
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    if r.returncode != 0:
        raise SetupFailed(f"{' '.join(cmd)}: {r.stderr.strip() or r.returncode}")
    return r.stdout


def netem_args(net, out=False):
    """One pass through lo: half the RTT, the loss and the rate."""
    loss = ["loss", f"{net['loss_pct']:g}%"]
    if net.get("loss_outage_ms"):
        # The loss is laid on in time by Outages; out is the state it switches to.
        loss = ["loss", "100%" if out else "0%"]
    elif net.get("loss_burst", 1) > 1:
        # Gilbert-Elliott: the bad state loses every packet, the good one none;
        # a burst lasts 1/r packets on average and the loss is p/(p+r).
        r = 1 / net["loss_burst"]
        p = net["loss_pct"] / 100 * r / (1 - net["loss_pct"] / 100)
        loss = ["loss", "gemodel", f"{100 * p:.6g}%", f"{100 * r:.6g}%", "100%", "0%"]
    rate = ["rate", f"{net['rate_mbit']:g}mbit"] if net["rate_mbit"] > 0 else []
    return ["netem", "delay", f"{net['rtt_ms'] / 2:g}ms", *loss, *rate, "limit", "100000"]


def netem(spec):
    """Shapes lo; returns the running Outages when the loss is laid on in time."""
    net, shape = spec["network"], spec["shape"]
    _sh(["ip", "link", "set", "lo", "up"])
    if net == "loopback":
        return None
    args = netem_args(net)
    target = ["root", "handle", "1:"]
    if shape == "all":
        _sh(["tc", "qdisc", "add", "dev", "lo", *target, *args])
    else:
        _sh(["tc", "qdisc", "add", "dev", "lo", *target, "prio", "bands", "3", "priomap", *["0"] * 16])
        target = ["parent", "1:3", "handle", "30:"]
        _sh(["tc", "qdisc", "add", "dev", "lo", *target, *args])
        u32 = ["tc", "filter", "add", "dev", "lo", "parent", "1:", "protocol", "ip", "prio", "1", "u32"]
        if shape == CLIENT_IP:
            # TCP and UDP to and from the generator; the server reaches the origins from 127.0.0.1.
            for d in ("src", "dst"):
                _sh([*u32, "match", "ip", d, f"{shape}/32", "flowid", "1:3"])
        else:
            for d in ("sport", "dport"):
                _sh([*u32, "match", "ip", "protocol", "6", "0xff", "match", "ip", d, str(shape), "0xffff", "flowid", "1:3"])
    if not net.get("loss_outage_ms"):
        return None
    o = Outages(net, target)
    o.start()
    return o


def spells(loss_pct, mean_ms, rng):
    """(up, out) seconds, both exponential: out has mean mean_ms and takes loss_pct of the time."""
    out = mean_ms / 1000
    up = out * (100 - loss_pct) / loss_pct
    while True:
        yield rng.expovariate(1 / up), rng.expovariate(1 / out)


class Outages(threading.Thread):
    """Loss in time rather than per packet: the leg drops everything for a spell.
    netem's Gilbert-Elliott moves on per packet, so a TCP sender backing off its
    RTO sends little and keeps a burst going for seconds; a fade does not wait."""

    def __init__(self, net, target):
        super().__init__(daemon=True)
        self.net, self.target = net, target
        self.halt = threading.Event()
        self.count, self.out_s, self.error = 0, 0.0, ""

    def run(self):
        try:
            for up, out in spells(self.net["loss_pct"], self.net["loss_outage_ms"], random.Random()):
                if self.halt.wait(up):
                    return
                self._switch(True)
                t = time.monotonic()
                self.halt.wait(out)
                self._switch(False)
                self.count += 1
                self.out_s += time.monotonic() - t
        except (SetupFailed, subprocess.TimeoutExpired, OSError) as e:
            self.error = str(e)

    def _switch(self, out):
        _sh(["tc", "qdisc", "change", "dev", "lo", *self.target, *netem_args(self.net, out)])

    def stop(self):
        self.halt.set()
        self.join(timeout=15)
        return {"count": self.count, "out_s": round(self.out_s, 3), **({"error": self.error} if self.error else {})}


def exited(p):
    """How p ended, or None while it runs; the process is left for wait4 to reap."""
    if p.returncode is not None:
        return f"exit {p.returncode}"
    info = os.waitid(os.P_PID, p.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
    if info is None:
        return None
    if info.si_code == os.CLD_EXITED:
        return f"exit {info.si_status}"
    return f"signal {signal.Signals(info.si_status).name}"


def wait_port(port, procs, logs, timeout=PORT_WAIT):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if _stop:
            raise Stop
        for name, p in procs.items():
            if (how := exited(p)) is not None:
                raise SetupFailed(f"{name} ended ({how}) before port {port} opened: {last_line(os.path.join(logs, name + '.log'))}")
        if listening(port):
            return
        time.sleep(0.05)
    raise SetupFailed(f"port {port} did not open within {timeout}s")


def listening(port):
    """A LISTEN socket on port in this netns. Read from /proc rather than
    probed with a connection, which the servers would log as a failed handshake."""
    for f in ("/proc/net/tcp", "/proc/net/tcp6"):
        try:
            with open(f) as fh:
                next(fh)
                for line in fh:
                    local, state = line.split()[1], line.split()[3]
                    if state == "0A" and int(local.rsplit(":", 1)[1], 16) == port:
                        return True
        except OSError:
            continue
    return False


_opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def gauges():
    """Session gauge, failure counters and illegal transitions from the metrics endpoint."""
    try:
        body = _opener.open(f"http://127.0.0.1:{PORTS['metrics']}/metrics", timeout=3).read().decode()
    except OSError as e:
        return {"error": str(e)}
    return parse_gauges(body)


def parse_gauges(body):
    out = {}
    for line in body.splitlines():
        if line.startswith("#"):
            continue
        name, _, value = line.rpartition(" ")
        base = name.split("{", 1)[0]
        if base in GAUGES or (base == "s5core_session_transitions_total" and 'illegal="true"' in name):
            key = "illegal_transitions" if base == "s5core_session_transitions_total" else base
            try:
                v = float(value)
            except ValueError:
                continue
            out[key] = out.get(key, 0) + v
            if key == "illegal_transitions":
                # The count alone does not say which driver is wrong; the labels do.
                lb = dict(re.findall(r'(\w+)="([^"]*)"', name))
                by = out.setdefault("illegal_by", {})
                t = f"{lb.get('region', '?')}:{lb.get('from', '?')}->{lb.get('to', '?')} {lb.get('transport', '')}".strip()
                by[t] = by.get(t, 0) + v
    return out


def last_line(path, limit=300):
    try:
        with open(path, errors="replace") as f:
            lines = [x.strip() for x in f if x.strip()]
    except OSError:
        return "no log"
    if not lines:
        return "empty log"
    line = lines[-1]
    try:
        d = json.loads(line)
        line = " ".join(str(d[k]) for k in ("msg", "error") if k in d) or line
    except ValueError:
        pass
    return line[:limit]


def log_counts(path):
    counts = {}
    try:
        with open(path, errors="replace") as f:
            for line in f:
                for lvl in ("ERROR", "WARN"):
                    if f'"level":"{lvl}"' in line or f"level={lvl}" in line:
                        counts[lvl] = counts.get(lvl, 0) + 1
    except OSError:
        pass
    return counts


class Capture:
    """Headers of the client-server leg through AF_PACKET, written as pcap.
    tcpdump is not used: under its AppArmor profile it ignores signals from
    some parents and has to be killed by root."""

    SNAP = 128

    def __init__(self, path, port, limit):
        self.port, self.limit, self.n = port, limit, 0
        self.sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
        self.sock.bind(("lo", 0))
        self.sock.setblocking(False)
        self.f = open(path, "wb")
        self.f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, self.SNAP, 1))

    def fileno(self):
        return self.sock.fileno()

    def drain(self):
        while self.n < self.limit:
            try:
                data, addr = self.sock.recvfrom(65535)
            except BlockingIOError:
                return
            if addr[2] == socket.PACKET_OUTGOING or len(data) < 34 or data[12:14] != b"\x08\x00":
                continue
            ihl = (data[14] & 0x0F) * 4
            if data[23] != 6 or len(data) < 14 + ihl + 4:
                continue
            sport, dport = struct.unpack_from("!HH", data, 14 + ihl)
            if self.port not in (sport, dport):
                continue
            t = time.time()
            cut = data[: self.SNAP]
            self.f.write(struct.pack("<IIII", int(t), int((t % 1) * 1e6), len(cut), len(data)))
            self.f.write(cut)
            self.n += 1

    def close(self):
        self.drain()
        self.sock.close()
        self.f.close()
        return self.n


def main(spec_path):
    spec = read_json(spec_path)
    out = spec["dir"]
    set_pdeathsig(signal.SIGTERM)
    if os.getppid() != spec["parent_pid"]:
        sys.exit("orchestrator is gone")
    signal.signal(signal.SIGTERM, _on_term)
    signal.signal(signal.SIGINT, _on_term)
    run = {"id": spec["id"], "status": "setup_failed", "reason": "", "started": time.time()}
    procs, cap, outages = {}, None, None
    secret = os.path.join(spec["tmp"], "secret")
    try:
        if netns_inode() == spec["parent_netns"]:
            raise SetupFailed("refusing to run outside a fresh network namespace")
        outages = netem(spec)
        os.makedirs(secret, mode=0o700, exist_ok=True)
        socks = start(spec, secret, procs, run)
        if spec["settings"]["capture"] and not spec["direct"]:
            cap = Capture(os.path.join(out, "capture.pcap"), PORTS[spec["transport"]], spec["settings"]["capture_packets"])
        measure(spec, socks, procs, run, cap)
    except SetupFailed as e:
        run["status"], run["reason"] = "setup_failed", str(e)
    except Stop:
        run["status"], run["reason"] = "interrupted", "stopped by the orchestrator"
    except Exception as e:
        run["status"], run["reason"] = "cell_error", f"{type(e).__name__}: {e}"
    finally:
        if outages:
            run["outages"] = outages.stop()
        finish(spec, procs, run, cap)
        for f in os.listdir(secret) if os.path.isdir(secret) else []:
            os.remove(os.path.join(secret, f))
        if os.path.isdir(secret):
            os.rmdir(secret)
        write_json(os.path.join(out, "run.json"), run)
    sys.exit(0)


def environments(spec, psk, users, cert, key, client_cert=None, host="127.0.0.1", listen="127.0.0.1"):
    """Server and client environment of a tunnel cell and the accounts file
    it needs (None without auth). Secrets included: keep them off disk
    except in files with mode 600."""
    st = spec["settings"]
    srv = dict(GOMAXPROCS=str(st["server_procs"]), PROXY_LISTEN_IP=listen, PROXY_PORT=str(PORTS["plain"]),
               OBFS_ENABLED="true", OBFS_PORT=str(PORTS["obfs"]), OBFS_PSK=psk,
               WS_ENABLED="true", WS_ADDR=f"{listen}:{PORTS['wss']}", WS_CERT_FILE=cert, WS_KEY_FILE=key,
               METRICS_PORT=str(PORTS["metrics"]), METRICS_BIND_ADDR="127.0.0.1",
               TRAFFIC_FLUSH_INTERVAL=go_duration(seconds(st["flush"])), LOG_LEVEL="warn", REQUIRE_AUTH="false")
    cli = dict(GOMAXPROCS=str(st["client_procs"]), CLIENT_LISTEN_ADDR=f"127.0.0.1:{PORTS['client']}",
               SERVER_ADDR=f"{host}:{PORTS['obfs']}", OBFS_PSK=psk, LOG_LEVEL="warn", TRANSPORT="obfs")
    if spec["transport"] == "wss":
        cli.update(TRANSPORT="ws", WS_URL=f"wss://{host}:{PORTS['wss']}/ws", WS_CA_FILE=client_cert or cert)
    doc = None
    auth = spec["auth"]
    if auth != "none":
        key64, pw = base64.b64encode(os.urandom(32)).decode(), os.urandom(12).hex()
        doc = {"users": [{"id": "bench", "username": "bench", "password": pw, "enabled": True, "tunnel_key": key64}]}
        srv.update(REQUIRE_AUTH="true", USERS_FILE=users)
        cli.update({
            "member": {"PROXY_AUTH_MODE": "member-only", "OBFS_MEMBER_ID": "bench", "OBFS_MEMBER_KEY": key64},
            "password": {"PROXY_USER": "bench", "PROXY_PASS": pw},
            "fallback": {"PROXY_AUTH_MODE": "password-fallback", "OBFS_MEMBER_ID": "bench", "OBFS_MEMBER_KEY": key64, "PROXY_USER": "bench", "PROXY_PASS": pw},
        }[auth])
    srv.update(spec["env"]["server"])
    cli.update(spec["env"]["client"])
    return srv, cli, doc


def start(spec, secret, procs, run):
    """Starts s5core and, for a tunnel, s5client; returns the SOCKS address for the generator."""
    if spec["direct"]:
        return ""
    out = spec["dir"]
    users = os.path.join(secret, "users.json")
    srv, cli, doc = environments(spec, os.urandom(16).hex(), users, spec["cert"], spec["key"])
    if doc:
        fd = os.open(users, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump(doc, f)
    base = {"PATH": os.environ.get("PATH", "/usr/bin:/bin")}
    procs["server"] = _spawn([spec["bin"]["s5core"]], base | srv, os.path.join(out, "server.log"))
    wait_port(PORTS["plain"], procs, out)
    wait_port(PORTS["metrics"], procs, out)
    if spec["transport"] == "plain":
        return f"127.0.0.1:{PORTS['plain']}"
    wait_port(PORTS[spec["transport"]], procs, out)
    procs["client"] = _spawn([spec["bin"]["s5client"]], base | cli, os.path.join(out, "client.log"))
    wait_port(PORTS["client"], procs, out)
    return f"127.0.0.1:{PORTS['client']}"


def _spawn(args, env, log):
    with open(log, "ab") as f:
        return subprocess.Popen(args, env=env, stdin=subprocess.DEVNULL, stdout=f, stderr=subprocess.STDOUT, preexec_fn=_child_setup)


def _gen_args(spec, socks, budget=None, grace=None):
    st = spec["settings"]
    a = [spec["bin"]["matrix"], "-label", spec["id"], "-scenario-timeout", go_duration(budget or seconds(st["scenario_timeout"])),
         "-hang-grace", go_duration(grace or seconds(st["hang_grace"])), "-max-errors-in-row", str(st["max_errors_in_row"])]
    if socks:
        a += ["-socks", socks]
        if spec["shape"] == CLIENT_IP:
            a += ["-source", CLIENT_IP]
        if isinstance(spec["network"], dict):
            # The generator's own control would bypass netem; the raw cell is the control.
            a += ["-control=false"]
    return a


def _run_bounded(args, env, log, timeout):
    """A helper generator run (warmup) under a hard bound."""
    with open(log, "ab") as f:
        p = subprocess.Popen(args, env=env, stdin=subprocess.DEVNULL, stdout=f, stderr=subprocess.STDOUT, preexec_fn=_child_setup)
        try:
            return p.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            p.kill()
            p.wait()
            return None


def snapshot(procs, phase, run):
    snap = {"phase": phase, "t": round(time.time() - run["started"], 3)}
    for name, p in procs.items():
        if name != "generator":
            snap[name] = proc_stat(p.pid)
    return snap


def measure(spec, socks, procs, run, cap):
    st, out = spec["settings"], spec["dir"]
    genv = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "GOMAXPROCS": str(st["gen_procs"])}
    time.sleep(0.3)
    if st["warmup"] and socks:
        # The warmup has its own budget: it checks the path, not the series settings.
        rc = _run_bounded(_gen_args(spec, socks, WARMUP_TIMEOUT - 20, 10) + ["-only", "=tcp/connect", "-scale", "0.02"], genv, os.path.join(out, "warmup.log"), WARMUP_TIMEOUT)
        if rc != 0:
            raise SetupFailed(f"warmup {'did not finish within %ds' % WARMUP_TIMEOUT if rc is None else 'exited with %d' % rc}, see warmup.log")
    if _stop:
        raise Stop
    res = []
    run["before"] = snapshot(procs, "before", run)
    if "server" in procs:
        run["gauges_before"] = gauges()
    args = _gen_args(spec, socks) + ["-out", os.path.join(out, "result.json")]
    if spec["kind"] == "soak":
        args += ["-soak", go_duration(seconds(st["soak"])), "-workers", str(st["workers"]), "-idle", go_duration(seconds(st["idle"]))]
    else:
        args += ["-scale", f"{st['scale']:g}", "-slow-ms", str(st["slow_ms"])]
        if spec["only"]:
            args += ["-only", ",".join(spec["only"])]
    glog = os.path.join(out, "matrix.log")
    t0 = time.monotonic()
    run["measure_started"] = time.time()
    procs["generator"] = gen = _spawn(args, genv, glog)
    stall = seconds(st["scenario_timeout"]) + seconds(st["hang_grace"]) + 30
    if spec["kind"] == "soak":
        stall += max(seconds(st["soak"]), seconds(st["idle"]))
    hard = spec["deadline"] - time.time() - STOP_WAIT - seconds(st["settle"]) - 15
    last_size, last_change, next_sample = -1, time.monotonic(), time.monotonic() + (st["sample_s"] or 1e18)
    why = None
    while True:
        waited = os.wait4(gen.pid, os.WNOHANG)
        if waited[0] == gen.pid:
            gen.returncode = os.waitstatus_to_exitcode(waited[1])
            run["generator_cpu_s"] = waited[2].ru_utime + waited[2].ru_stime
            break
        if _stop:
            why = ("interrupted", "stopped by the orchestrator")
        for n in ("server", "client"):
            if not why and n in procs and (how := exited(procs[n])) is not None:
                why = ("crashed", f"{n} ended ({how}) during the measurement")
        size = os.path.getsize(glog) if os.path.exists(glog) else 0
        if size != last_size:
            last_size, last_change = size, time.monotonic()
        elif not why and time.monotonic() - last_change > stall:
            why = ("stalled", f"generator printed nothing for {stall:.0f}s")
        if not why and time.monotonic() - t0 > hard:
            why = ("timeout", f"cell deadline reached after {time.monotonic() - t0:.0f}s of measurement")
        if why:
            gen.kill()
            _, status, ru = os.wait4(gen.pid, 0)
            gen.returncode = os.waitstatus_to_exitcode(status)
            run["generator_cpu_s"] = ru.ru_utime + ru.ru_stime
            break
        if time.monotonic() >= next_sample:
            res.append(snapshot(procs, "sample", run))
            next_sample += st["sample_s"]
        ready = [cap] if cap else []
        if ready:
            r, _, _ = select.select(ready, [], [], 0.2)
            if r:
                cap.drain()
        else:
            time.sleep(0.2)
    run["seconds"] = round(time.monotonic() - t0, 3)
    run["generator_rc"] = gen.returncode
    run["after"] = snapshot(procs, "after", run)
    if "server" in procs:
        run["gauges_after"] = gauges()
    result = read_json(os.path.join(out, "result.json"), {})
    run["complete"] = bool(result.get("complete"))
    if why:
        run["status"], run["reason"] = why
    elif gen.returncode == 3:
        run["status"], run["reason"] = "hung", f"scenario {result.get('hung', '?')} did not return within its budget"
    elif gen.returncode != 0:
        run["status"], run["reason"] = "gen_failed", f"generator exited with {gen.returncode}, see matrix.log"
    elif not run["complete"]:
        run["status"], run["reason"] = "gen_failed", "generator exited 0 without a complete result"
    else:
        run["status"] = "ok"
    if res:
        with open(os.path.join(out, "resources.jsonl"), "w") as f:
            for r in res:
                f.write(json.dumps(r) + "\n")
    if run["status"] in ("ok", "hung") and "server" in procs:
        deadline = time.monotonic() + seconds(st["settle"])
        while time.monotonic() < deadline and not _stop:
            time.sleep(0.2)
        run["settled"] = snapshot(procs, "settled", run)
        run["gauges_settled"] = gauges()


def finish(spec, procs, run, cap):
    gen = procs.get("generator")
    if gen and gen.returncode is None:
        gen.kill()
        gen.wait()
    for name in ("client", "server"):
        p = procs.get(name)
        if not p:
            continue
        if exited(p) is None:
            p.terminate()
            end = time.monotonic() + STOP_WAIT
            while exited(p) is None and time.monotonic() < end:
                time.sleep(0.05)
            if exited(p) is None:
                p.kill()
        try:
            _, status, ru = os.wait4(p.pid, 0)
            p.returncode = os.waitstatus_to_exitcode(status)
            cpu = ru.ru_utime + ru.ru_stime
        except ChildProcessError:
            cpu = 0.0
        run[f"{name}_cpu_lifetime_s"] = round(cpu, 3)
        run[f"{name}_exit"] = p.returncode
        run[f"{name}_log"] = log_counts(os.path.join(spec["dir"], f"{name}.log"))
    # Everything this cell ran and reaped, tc and ip included, plus the cell itself.
    run["own_cpu_s"] = round(sum(r.ru_utime + r.ru_stime for r in map(resource.getrusage, (resource.RUSAGE_SELF, resource.RUSAGE_CHILDREN))), 3)
    if cap:
        run["capture_packets"] = cap.close()
    if spec["network"] != "loopback":
        try:
            run["qdisc"] = _sh(["tc", "-s", "qdisc", "show", "dev", "lo"], timeout=5)
        except (SetupFailed, subprocess.TimeoutExpired, OSError):
            pass
    run["finished"] = time.time()

"""WAN cells: s5core and the origins on a remote server, s5client and the
generator on a remote client, both driven over ssh from this machine.

The server side runs as transient systemd units with an IP allow list of the
client, the server itself and loopback, so the test ports answer nobody else
and the test server reaches nothing else. The client side (a router without
systemd) runs from pid files under its directory, with a watchdog that kills
what a lost orchestrator left behind. Secrets are generated here per cell and
reach the hosts only in files with mode 600 inside directories with mode 700;
the cell directories are removed when the cell ends.
"""

import json
import os
import shlex
import signal
import subprocess
import sys
import time

from . import build
from .cell import GAUGES, PORTS, WARMUP_TIMEOUT, environments, last_line, log_counts, parse_gauges
from .util import go_duration, read_json, seconds, set_pdeathsig, sha256, write_json

SRV_UNIT, ORIGIN_UNIT = "s5bench-srv", "s5bench-origin"
POLL = 2.5
PORT_WAIT = 20
STOP_WAIT = 5
# A socket path has to stay under 108 bytes, so not under a long TMPDIR.
CONTROL = "/tmp/s5b-%C"


class WanError(Exception):
    pass


class SetupFailed(Exception):
    pass


def q(s):
    return shlex.quote(str(s))


class Host:
    """One ssh target; the connection is shared through a control master."""

    def __init__(self, target):
        self.target = target
        self.opts = ["-o", "BatchMode=yes", "-o", "ConnectTimeout=10", "-o", "ServerAliveInterval=10", "-o", "ServerAliveCountMax=3",
                     "-o", "ControlMaster=auto", "-o", f"ControlPath={CONTROL}", "-o", "ControlPersist=120"]

    def sh(self, script, timeout=60, check=True):
        try:
            r = subprocess.run(["ssh", *self.opts, self.target, "sh -s"], input=script, capture_output=True, text=True, timeout=timeout)
        except subprocess.TimeoutExpired:
            raise WanError(f"{self.target}: no answer within {timeout}s") from None
        if check and r.returncode != 0:
            raise WanError(f"{self.target}: exit {r.returncode}: {(r.stderr or r.stdout).strip()[-400:]}")
        return r.stdout

    def put(self, remote, data=None, local=None, mode=0o600, timeout=300):
        cmd = f"umask 077; cat > {q(remote)}.tmp && chmod {mode:o} {q(remote)}.tmp && mv {q(remote)}.tmp {q(remote)}"
        src = open(local, "rb") if local else subprocess.DEVNULL
        try:
            r = subprocess.run(["ssh", *self.opts, self.target, cmd], input=None if local else data.encode(), stdin=src if local else None,
                               capture_output=True, timeout=timeout)
        finally:
            if local:
                src.close()
        if r.returncode != 0:
            raise WanError(f"{self.target}: upload {remote}: {r.stderr.decode(errors='replace').strip()[-300:]}")

    def get(self, remote, local, timeout=120):
        with open(local + ".tmp", "wb") as f:
            r = subprocess.run(["ssh", *self.opts, self.target, f"cat {q(remote)}"], stdout=f, stderr=subprocess.PIPE, timeout=timeout)
        if r.returncode != 0:
            os.remove(local + ".tmp")
            return False
        os.replace(local + ".tmp", local)
        return True


def hosts(w):
    return Host(w["server"]), Host(w["client"])


# Shell pieces shared by the scripts below; the client is BusyBox ash.
LISTENING = """listening() {
  p=$(printf '%04X' "$1")
  awk 'NR>1 && $4=="0A" {n=split($2,a,":"); print a[n]}' /proc/net/tcp /proc/net/tcp6 2>/dev/null | grep -qx "$p"
}
"""
# BusyBox sleep on the router takes whole seconds only.
NAP = "nap() { usleep 100000 2>/dev/null || sleep 0.1 2>/dev/null || sleep 1; }\n"
# pid, ticks, rss, hwm, threads, fds of one process, or the pid and "gone".
SNAP = """snap() {
  p=$1
  s=$(cat /proc/$p/stat 2>/dev/null) || { echo "$p gone"; return; }
  s=${s##*) }
  set -- $s
  t=$((${12} + ${13}))
  m=$(awk '/^VmRSS:/{r=$2} /^VmHWM:/{h=$2} /^Threads:/{n=$2} END{print r+0, h+0, n+0}' /proc/$p/status 2>/dev/null)
  f=$(ls /proc/$p/fd 2>/dev/null | wc -l)
  echo "$p $t $m $f"
}
busy() { awk '/^cpu /{print $2+$3+$4+$9}' /proc/stat; }
"""


def ourkill(dirpath):
    """kill_ours SIG PIDFILE: signals the pid only while its command line names dirpath (pids are reused)."""
    return f"""kill_ours() {{
  [ -f "$2" ] || return 0
  p=$(cat "$2" 2>/dev/null)
  [ -n "$p" ] && tr '\\0' ' ' < /proc/$p/cmdline 2>/dev/null | grep -q {q(dirpath)} && kill -$1 "$p" 2>/dev/null
  return 0
}}
"""


def parse_snap(line, clk):
    parts = line.split()
    if len(parts) < 6:
        return None
    ticks, rss, hwm, threads, fds = map(int, parts[1:6])
    return {"cpu_s": ticks / clk, "rss_kb": rss, "hwm_kb": hwm, "threads": threads, "fds": fds}


class Stage:
    """Binaries, certificate, origins and the client address on both hosts, once per run."""

    def __init__(self, plan, out, emit):
        self.w, self.out, self.emit = plan["wan"], out, emit
        self.srv, self.cli = hosts(self.w)
        self.variants = [n for n, v in plan["variants"].items() if not v["direct"]]
        self.dir = os.path.join(out, "wan")

    def up(self, bound):
        w, sd, cd = self.w, self.w["server_dir"], self.w["client_dir"]
        os.makedirs(self.dir, mode=0o700, exist_ok=True)
        self.emit(f"wan: staging on the server and the client (bound {bound / 3600:.1f} h)")
        self.srv.sh("for c in systemd-run systemctl awk curl sha256sum; do command -v $c >/dev/null || { echo missing $c; exit 1; }; done")
        self.cli.sh("for c in awk nc sha256sum nohup readlink; do command -v $c >/dev/null || { echo missing $c; exit 1; }; done")
        self.down(quiet=True)
        busy = self.srv.sh(LISTENING + "".join(f"listening {p} && echo {p}\n" for p in (PORTS["plain"], PORTS["obfs"], PORTS["wss"], PORTS["metrics"])), check=False).split()
        busy += self.cli.sh(LISTENING + f"listening {PORTS['client']} && echo {PORTS['client']}\n", check=False).split()
        if busy:
            raise WanError(f"ports already taken on the hosts: {' '.join(busy)}")
        clk = self.srv.sh("getconf CLK_TCK 2>/dev/null || echo 100").strip() or "100"
        for h, d in ((self.srv, sd), (self.cli, cd)):
            h.sh(f"umask 077; mkdir -p {q(d)}/bin {q(d)}/tls && chmod 700 {q(d)}")
        bindir = os.path.join(self.out, "bin")
        uploads = [(self.srv, f"{sd}/bin/matrix", build.arch_path(bindir, None, "matrix", w["server_arch"])),
                   (self.cli, f"{cd}/bin/matrix", build.arch_path(bindir, None, "matrix", w["client_arch"]))]
        for v in self.variants:
            uploads.append((self.srv, f"{sd}/bin/{v}/s5core", build.arch_path(bindir, v, "s5core", w["server_arch"])))
            uploads.append((self.cli, f"{cd}/bin/{v}/s5client", build.arch_path(bindir, v, "s5client", w["client_arch"])))
        for h, remote, local in uploads:
            h.sh(f"umask 077; mkdir -p {q(os.path.dirname(remote))}")
            h.put(remote, local=local, mode=0o700)
            got = h.sh(f"sha256sum {q(remote)}").split()[0]
            if got != sha256(local):
                raise WanError(f"{h.target}:{remote}: checksum differs after upload")
        self.emit(f"wan: {len(uploads)} binaries uploaded and checked")
        cert, key = self._cert()
        self.srv.put(f"{sd}/tls/cert.pem", local=cert, mode=0o600)
        self.srv.put(f"{sd}/tls/key.pem", local=key, mode=0o600)
        self.cli.put(f"{cd}/tls/cert.pem", local=cert, mode=0o600)
        client_ip = self._client_ip()
        allow = f"{client_ip} {w['server_ip']} 127.0.0.0/8 ::1"
        self.srv.sh(f"""systemd-run --quiet --unit {ORIGIN_UNIT} -p MemoryMax={w['origin_memory_max']} -p RuntimeMaxSec={int(bound) + 600} \\
  -p IPAddressDeny=any -p {q('IPAddressAllow=' + allow)} \\
  -p StandardOutput=append:{sd}/origin.log -p StandardError=append:{sd}/origin.log \\
  {sd}/bin/matrix -serve {sd}/origin.json -listen {w['server_ip']} -allow {client_ip}/32,{w['server_ip']}/32
for i in $(seq 1 100); do [ -s {sd}/origin.json ] && exit 0; systemctl is-active --quiet {ORIGIN_UNIT} || break; sleep 0.1; done
tail -n 3 {sd}/origin.log; exit 1""")
        origin_pid = int(self.srv.sh(f"systemctl show -p MainPID --value {ORIGIN_UNIT}").strip() or 0)
        origin = os.path.join(self.dir, "origin.json")
        if not self.srv.get(f"{sd}/origin.json", origin):
            raise WanError("could not fetch origin.json from the server")
        with open(origin) as f:
            self.cli.put(f"{cd}/origin.json", data=f.read(), mode=0o600)
        info = {"client_ip": client_ip, "server_ip": w["server_ip"], "allow": allow, "server_clk": int(clk), "client_clk": 100, "origin_pid": origin_pid,
                "origin": {k: v for k, v in read_json(origin).items() if k != "cert_pem"}}
        write_json(os.path.join(self.dir, "stage.json"), info)
        self.emit(f"wan: origins up on the server, client address {client_ip}")
        return info

    def _cert(self):
        cert, key = os.path.join(self.dir, "cert.pem"), os.path.join(self.dir, "key.pem")
        if not os.path.isfile(cert):
            ip = self.w["server_ip"]
            subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-days", "30",
                            "-subj", f"/CN={ip}", "-addext", f"subjectAltName=IP:{ip}", "-keyout", key, "-out", cert],
                           check=True, capture_output=True, timeout=30)
            os.chmod(key, 0o600)
        return cert, key

    def _client_ip(self):
        """The address the server sees for the client: the new peer on its ssh port
        while the client holds a connection open to it."""
        peers = "ss -Htn state established '( sport = :22 )' | awk '{print $4}' | sort"
        before = set(self.srv.sh(peers).split())
        self.cli.sh(f"(sleep 8 | nc {q(self.w['server_ip'])} 22) >/dev/null 2>&1 </dev/null &\nexit 0")
        for _ in range(12):
            time.sleep(0.5)
            new = set(self.srv.sh(peers).split()) - before
            ips = {p.rsplit(":", 1)[0].strip("[]").removeprefix("::ffff:") for p in new}
            if len(ips) == 1:
                return ips.pop()
            if len(ips) > 1:
                raise WanError(f"cannot tell the client address: {len(ips)} new peers at once")
        raise WanError("the client's connection never reached the server's port 22")

    def down(self, quiet=False):
        """Stops every unit and process of ours and removes both directories."""
        sd, cd = self.w["server_dir"], self.w["client_dir"]
        self.srv.sh(f"""for u in {SRV_UNIT} {ORIGIN_UNIT}; do systemctl stop $u 2>/dev/null; systemctl reset-failed $u 2>/dev/null; done
rm -rf {q(sd)}; exit 0""", check=False)
        self.cli.sh(ourkill(cd) + f"""for f in {q(cd)}/*/*.pid {q(cd)}/*.pid; do kill_ours KILL "$f"; done
rm -rf {q(cd)}; exit 0""", check=False)
        left = self.srv.sh(f"systemctl list-units --all --no-legend '{SRV_UNIT}*' '{ORIGIN_UNIT}*' | wc -l; test -e {q(sd)} && echo dir", check=False).split()
        left += self.cli.sh(f"ps w | grep -F {q(cd)} | grep -v grep | wc -l; test -e {q(cd)} && echo dir", check=False).split()
        if not quiet:
            clean = left[:1] == ["0"] and "dir" not in left and left[-1:] == ["0"]
            self.emit("wan: hosts cleaned" if clean else f"wan: cleanup left something behind: {left}")
            subprocess.run(["ssh", "-O", "exit", "-o", f"ControlPath={CONTROL}", self.w["server"]], capture_output=True, timeout=10)
            subprocess.run(["ssh", "-O", "exit", "-o", f"ControlPath={CONTROL}", self.w["client"]], capture_output=True, timeout=10)


class _Stop(Exception):
    pass


_stop = False


def _on_term(signum, frame):
    global _stop
    _stop = True


def main(spec_path):
    """One WAN cell, run as `matrix.py wancell SPEC` by the orchestrator."""
    spec = read_json(spec_path)
    set_pdeathsig(signal.SIGTERM)
    if os.getppid() != spec["parent_pid"]:
        sys.exit("orchestrator is gone")
    signal.signal(signal.SIGTERM, _on_term)
    signal.signal(signal.SIGINT, _on_term)
    c = Cell(spec)
    try:
        c.setup()
        c.measure()
    except (SetupFailed, WanError) as e:
        c.run["status"], c.run["reason"] = "setup_failed", str(e)
    except _Stop:
        c.run["status"], c.run["reason"] = "interrupted", "stopped by the orchestrator"
    except Exception as e:
        c.run["status"], c.run["reason"] = "cell_error", f"{type(e).__name__}: {e}"
    finally:
        try:
            c.finish()
        except Exception as e:
            c.run["finish_error"] = f"{type(e).__name__}: {e}"
        write_json(os.path.join(spec["dir"], "run.json"), c.run)
    sys.exit(0)


class Cell:
    def __init__(self, spec):
        self.spec, self.st, self.out = spec, spec["settings"], spec["dir"]
        w = spec["wan"]
        self.w = w
        self.srv, self.cli = hosts(w)
        self.sd, self.cd = f"{w['server_dir']}/cell", f"{w['client_dir']}/cell"
        self.run = {"id": spec["id"], "status": "setup_failed", "reason": "", "started": time.time(), "wan": True}
        self.server_pid = self.client_pid = None
        self.started_server = self.started_client = False

    def check_stop(self):
        if _stop:
            raise _Stop

    def setup(self):
        sp = self.spec
        self.srv.sh(f"systemctl stop {SRV_UNIT} 2>/dev/null; systemctl reset-failed {SRV_UNIT} 2>/dev/null; rm -rf {q(self.sd)}; umask 077; mkdir -p {q(self.sd)}")
        self.cli.sh(ourkill(self.w["client_dir"]) + f"""for f in {q(self.cd)}/*.pid; do kill_ours KILL "$f"; done
rm -rf {q(self.cd)}; umask 077; mkdir -p {q(self.cd)}""")
        # The watchdog outlives a lost orchestrator by the cell's own bound and kills what is left.
        bound = int(sp["timeout"]) + 90
        self.cli.put(f"{self.cd}/watchdog.sh", mode=0o700, data=ourkill(self.w["client_dir"]) + f"""sleep {bound}
for f in {self.cd}/client.pid {self.cd}/gen.pid {self.cd}/warmup.pid; do kill_ours KILL "$f"; done
""")
        self.cli.sh(f"cd {q(self.cd)} && nohup sh {self.cd}/watchdog.sh >/dev/null 2>&1 </dev/null & echo $! > {q(self.cd)}/watchdog.pid")
        self.check_stop()
        if sp["direct"]:
            return
        sip = self.w["server_ip"]
        tls_s, tls_c = f"{self.w['server_dir']}/tls", f"{self.w['client_dir']}/tls"
        srv, cli, doc = environments(sp, os.urandom(16).hex(), f"{self.sd}/users.json", f"{tls_s}/cert.pem", f"{tls_s}/key.pem",
                                     client_cert=f"{tls_c}/cert.pem", host=sip, listen=sip)
        if doc:
            self.srv.put(f"{self.sd}/users.json", data=json.dumps(doc))
        self.srv.put(f"{self.sd}/server.env", data="".join(f"{k}={v}\n" for k, v in srv.items()))
        self.cli.put(f"{self.cd}/client.env", data="".join(f"{k}={q(v)}\n" for k, v in cli.items()))
        stage = self.spec["stage"]
        mem = self.w["server_memory_max"]
        self.started_server = True
        self.srv.sh(f"""systemd-run --quiet --unit {SRV_UNIT} -p MemoryMax={mem} -p RuntimeMaxSec={bound} -p TimeoutStopSec={STOP_WAIT} \\
  -p EnvironmentFile={self.sd}/server.env -p StandardOutput=append:{self.sd}/server.log -p StandardError=append:{self.sd}/server.log \\
  -p IPAddressDeny=any -p {q('IPAddressAllow=' + stage['allow'])} {self.w['server_dir']}/bin/{sp['variant']}/s5core""")
        want = [PORTS["plain"], PORTS["metrics"], PORTS[sp["transport"]]]
        out = self.srv.sh(LISTENING + f"""for i in $(seq 1 {PORT_WAIT * 10}); do
  ok=1; for p in {' '.join(map(str, want))}; do listening $p || ok=0; done
  [ $ok = 1 ] && {{ systemctl show -p MainPID --value {SRV_UNIT}; exit 0; }}
  systemctl is-active --quiet {SRV_UNIT} || break
  sleep 0.1
done
echo FAIL; tail -n 1 {self.sd}/server.log""", timeout=PORT_WAIT + 30, check=False).split("\n")
        if out[0].strip() == "FAIL" or not out[0].strip().isdigit():
            raise SetupFailed(f"server did not open {want} within {PORT_WAIT}s: {' '.join(out[1:]).strip()[:300]}")
        self.server_pid = int(out[0])
        self.check_stop()
        self.started_client = True
        out = self.cli.sh(LISTENING + NAP + f"""cd {q(self.cd)}
(set -a; . ./client.env; set +a; exec nohup {self.w['client_dir']}/bin/{sp['variant']}/s5client > client.log 2>&1 < /dev/null) &
echo $! > client.pid
i=0
while [ $i -lt {PORT_WAIT * 10} ]; do
  listening {PORTS['client']} && {{ cat client.pid; exit 0; }}
  kill -0 $(cat client.pid) 2>/dev/null || break
  nap; i=$((i+1))
done
echo FAIL; tail -n 1 client.log""", timeout=PORT_WAIT + 30, check=False).split("\n")
        if out[0].strip() == "FAIL" or not out[0].strip().isdigit():
            raise SetupFailed(f"client did not open {PORTS['client']} within {PORT_WAIT}s: {' '.join(out[1:]).strip()[:300]}")
        self.client_pid = int(out[0])

    def _gen(self, name, args):
        """Starts the generator on the client in the background: <name>.pid, .log, .rc, .times."""
        cmd = " ".join(q(a) for a in args)
        self.cli.put(f"{self.cd}/{name}.sh", mode=0o700, data=f"""cd {self.cd}
{cmd} > {name}.log 2>&1 < /dev/null &
echo $! > {name}.pid
wait $!
rc=$?
times > {name}.times
echo $rc > {name}.rc
""")
        self.cli.sh(f"cd {q(self.cd)} && nohup sh {name}.sh >/dev/null 2>&1 </dev/null &")

    def _gen_args(self, budget=None, grace=None):
        sp, st = self.spec, self.st
        a = [f"{self.w['client_dir']}/bin/matrix", "-label", sp["id"], "-origin", f"{self.w['client_dir']}/origin.json",
             "-scenario-timeout", go_duration(budget or seconds(st["scenario_timeout"])),
             "-hang-grace", go_duration(grace or seconds(st["hang_grace"])), "-max-errors-in-row", str(st["max_errors_in_row"])]
        if not sp["direct"]:
            a += ["-socks", f"127.0.0.1:{PORTS['client']}"]
        return a

    def _env_prefix(self):
        return ["env", f"GOMAXPROCS={self.st['gen_procs']}"]

    def poll(self, name):
        """One look at both hosts: generator rc and log size, client and server alive, busy ticks."""
        c = self.cli.sh(SNAP + ourkill(self.w["client_dir"]) + f"""cd {q(self.cd)}
echo rc $(cat {name}.rc 2>/dev/null || echo -)
echo size $(wc -c < {name}.log 2>/dev/null || echo 0)
[ -f client.pid ] && {{ kill -0 $(cat client.pid) 2>/dev/null && echo client up || echo client down; }}
exit 0
""", timeout=30)
        s = {}
        if self.server_pid:
            s = dict(ln.split(" ", 1) for ln in self.srv.sh(f"echo active $(systemctl is-active {SRV_UNIT})", timeout=30).splitlines() if " " in ln)
        d = dict(ln.split(" ", 1) for ln in c.splitlines() if " " in ln)
        return d, s

    def snapshot(self, phase):
        snap = {"phase": phase, "t": round(time.time() - self.run["started"], 3)}
        clk_s, clk_c = self.spec["stage"]["server_clk"], self.spec["stage"]["client_clk"]
        origin = self.spec["stage"]["origin_pid"]
        s = self.srv.sh(SNAP + f"snap {origin}\n" + (f"snap {self.server_pid}\n" if self.server_pid else "") + "echo busy $(busy)\n", timeout=30).splitlines()
        c = self.cli.sh(SNAP + (f"snap {self.client_pid}\n" if self.client_pid else "") + "echo busy $(busy)\n", timeout=30).splitlines()
        snap["origin"] = parse_snap(s[0], clk_s)
        if self.server_pid:
            snap["server"] = parse_snap(s[1], clk_s)
        if self.client_pid:
            snap["client"] = parse_snap(c[0], clk_c)
        snap["server_busy_s"] = float(s[-1].split()[1]) / clk_s
        snap["client_busy_s"] = float(c[-1].split()[1]) / clk_c
        return snap

    def gauges(self):
        body = self.srv.sh(f"curl -s -m 3 http://127.0.0.1:{PORTS['metrics']}/metrics | grep -E '^({'|'.join(GAUGES)}|s5core_session_transitions_total)'", timeout=30, check=False)
        return parse_gauges(body) if body else {"error": "no metrics"}

    def measure(self):
        sp, st = self.spec, self.st
        time.sleep(0.3)
        if st["warmup"] and not sp["direct"]:
            self._gen("warmup", self._env_prefix() + self._gen_args(WARMUP_TIMEOUT - 20, 10) + ["-only", "=tcp/connect", "-scale", "0.02"])
            end = time.monotonic() + WARMUP_TIMEOUT
            rc = "-"
            while time.monotonic() < end:
                self.check_stop()
                time.sleep(1)
                rc = self.poll("warmup")[0].get("rc", "-")
                if rc != "-":
                    break
            if rc != "0":
                self.cli.sh(ourkill(self.w["client_dir"]) + f"kill_ours KILL {q(self.cd)}/warmup.pid", check=False)
                self._fetch("warmup.log")
                raise SetupFailed(f"warmup {'did not finish within %ds' % WARMUP_TIMEOUT if rc == '-' else 'exited with %s' % rc}, see warmup.log")
        self.check_stop()
        self.run["before"] = self.snapshot("before")
        if self.server_pid:
            self.run["gauges_before"] = self.gauges()
        args = self._env_prefix() + self._gen_args() + ["-out", f"{self.cd}/result.json"]
        if sp["kind"] == "soak":
            args += ["-soak", go_duration(seconds(st["soak"])), "-workers", str(st["workers"]), "-idle", go_duration(seconds(st["idle"]))]
        else:
            args += ["-scale", f"{st['scale']:g}", "-slow-ms", str(st["slow_ms"])]
            if sp["only"]:
                args += ["-only", ",".join(sp["only"])]
        t0 = time.monotonic()
        self.run["measure_started"] = time.time()
        self._gen("gen", args)
        stall = seconds(st["scenario_timeout"]) + seconds(st["hang_grace"]) + 30
        if sp["kind"] == "soak":
            stall += max(seconds(st["soak"]), seconds(st["idle"]))
        hard = sp["deadline"] - time.time() - STOP_WAIT - seconds(st["settle"]) - 30
        last_size, last_change, why, rc = None, time.monotonic(), None, "-"
        fails = 0
        while True:
            time.sleep(POLL)
            try:
                c, s = self.poll("gen")
                fails = 0
            except (WanError, ValueError) as e:
                # One lost poll is the path, not the cell; many in a row is the cell.
                fails += 1
                if fails >= 6:
                    why = ("stalled", f"hosts did not answer six polls in a row: {e}")
                c, s = {}, {}
            rc = c.get("rc", "-")
            if rc != "-":
                break
            if _stop:
                why = ("interrupted", "stopped by the orchestrator")
            if not why and c.get("client") == "down":
                why = ("crashed", "client ended during the measurement")
            if not why and self.server_pid and s.get("active") not in (None, "active"):
                why = ("crashed", f"server unit is {s.get('active')} during the measurement")
            size = c.get("size")
            if size is not None and size != last_size:
                last_size, last_change = size, time.monotonic()
            elif not why and time.monotonic() - last_change > stall:
                why = ("stalled", f"generator printed nothing for {stall:.0f}s")
            if not why and time.monotonic() - t0 > hard:
                why = ("timeout", f"cell deadline reached after {time.monotonic() - t0:.0f}s of measurement")
            if why:
                rc = self.cli.sh(ourkill(self.w["client_dir"]) + f"kill_ours KILL {q(self.cd)}/gen.pid; sleep 1; cat {q(self.cd)}/gen.rc 2>/dev/null", check=False).strip() or "-"
                break
        self.run["seconds"] = round(time.monotonic() - t0, 3)
        self.run["generator_rc"] = int(rc) if rc.lstrip("-").isdigit() else None
        self.run["after"] = self.snapshot("after")
        if self.server_pid:
            self.run["gauges_after"] = self.gauges()
        self._fetch("result.json")
        times = self.cli.sh(f"cat {q(self.cd)}/gen.times 2>/dev/null", check=False).split()
        if len(times) >= 4:
            self.run["generator_cpu_s"] = round(sum(_ash_time(x) for x in times[2:4]), 3)
        result = read_json(os.path.join(self.out, "result.json"), {})
        self.run["complete"] = bool(result.get("complete"))
        grc = self.run["generator_rc"]
        if why:
            self.run["status"], self.run["reason"] = why
        elif grc == 3:
            self.run["status"], self.run["reason"] = "hung", f"scenario {result.get('hung', '?')} did not return within its budget"
        elif grc != 0:
            self.run["status"], self.run["reason"] = "gen_failed", f"generator exited with {grc}, see matrix.log"
        elif not self.run["complete"]:
            self.run["status"], self.run["reason"] = "gen_failed", "generator exited 0 without a complete result"
        else:
            self.run["status"] = "ok"
        self.run["remote_foreign_cores"] = self.foreign()
        if self.run["status"] in ("ok", "hung") and self.server_pid:
            deadline = time.monotonic() + seconds(st["settle"])
            while time.monotonic() < deadline and not _stop:
                time.sleep(0.2)
            self.run["settled"] = self.snapshot("settled")
            self.run["gauges_settled"] = self.gauges()

    def foreign(self):
        """Busy cores on each host over the measurement minus what this cell's processes used there."""
        a, b, wall = self.run.get("before"), self.run.get("after"), self.run.get("seconds")
        if not a or not b or not wall:
            return None
        out = {}
        for side, own in (("server", ["server", "origin"]), ("client", ["client"])):
            busy = b[f"{side}_busy_s"] - a[f"{side}_busy_s"]
            used = sum((b.get(p) or {}).get("cpu_s", 0) - (a.get(p) or {}).get("cpu_s", 0) for p in own if a.get(p) and b.get(p))
            if side == "client":
                used += self.run.get("generator_cpu_s", 0)
            out[side] = round(max(0.0, (busy - used) / wall), 3)
        return out

    def _fetch(self, name, local=None):
        return self.cli.get(f"{self.cd}/{name}", os.path.join(self.out, local or name))

    def finish(self):
        kill = ourkill(self.w["client_dir"])
        info = self.cli.sh(kill + NAP + f"""cd {q(self.cd)} 2>/dev/null || exit 0
kill_ours KILL gen.pid; kill_ours KILL warmup.pid
if [ -f client.pid ]; then
  kill_ours TERM client.pid
  i=0; while [ $i -lt {STOP_WAIT * 10} ] && kill -0 $(cat client.pid) 2>/dev/null; do nap; i=$((i+1)); done
  kill -0 $(cat client.pid) 2>/dev/null && {{ kill_ours KILL client.pid; echo client killed; }}
fi
kill_ours KILL watchdog.pid
exit 0""", timeout=60, check=False)
        if "client killed" in info:
            self.run["client_exit"] = "killed"
        if self.started_server:
            st = self.srv.sh(f"""systemctl stop {SRV_UNIT} 2>/dev/null
systemctl show -p ExecMainCode -p ExecMainStatus -p CPUUsageNSec {SRV_UNIT}
systemctl reset-failed {SRV_UNIT} 2>/dev/null; exit 0""", timeout=60, check=False)
            props = dict(ln.split("=", 1) for ln in st.splitlines() if "=" in ln)
            self.run["server_exit"] = props.get("ExecMainStatus")
            if props.get("CPUUsageNSec", "").isdigit():
                self.run["server_cpu_lifetime_s"] = round(int(props["CPUUsageNSec"]) / 1e9, 3)
            if self.srv.get(f"{self.sd}/server.log", os.path.join(self.out, "server.log")):
                self.run["server_log"] = log_counts(os.path.join(self.out, "server.log"))
        for name in ("gen.log", "warmup.log", "client.log"):
            local = "matrix.log" if name == "gen.log" else name
            if self._fetch(name, local) and name == "client.log":
                self.run["client_log"] = log_counts(os.path.join(self.out, "client.log"))
        self.srv.sh(f"rm -rf {q(self.sd)}; exit 0", check=False)
        self.cli.sh(f"rm -rf {q(self.cd)}; exit 0", check=False)
        if self.run["status"] == "setup_failed" and not self.run["reason"]:
            self.run["reason"] = last_line(os.path.join(self.out, "server.log"))
        self.run["finished"] = time.time()


def _ash_time(s):
    """'1m2.50s' -> 62.5."""
    m, _, rest = s.partition("m")
    try:
        return float(m) * 60 + float(rest.rstrip("s"))
    except ValueError:
        return 0.0

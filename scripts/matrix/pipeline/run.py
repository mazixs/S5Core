"""Orchestrator: builds the variants, runs the batches, keeps the manifest."""

import fcntl
import json
import os
import shutil
import signal
import subprocess
import sys
import time

from . import build, plan as planmod, wan
from .util import REPO, ROOT, cpu_list, cpu_times, mem_available_mb, netns_inode, now, read_json, seconds, write_json

FINAL = {"ok", "hung", "stalled", "crashed", "gen_failed", "timeout"}
RETRY = {"setup_failed", "cell_error"}
KILL_WAIT = 15
RUNS = os.path.join(REPO, "bench", "runs")


class RunError(Exception):
    pass


class Runner:
    def __init__(self, plan, out, retry_failed=False, only_series=None):
        self.plan, self.out = plan, os.path.abspath(out)
        self.retry_failed, self.only_series = retry_failed, only_series
        self.live = {}
        self.stopping = 0
        self.locks = []
        self.stage = self.stage_info = None

    def emit(self, msg):
        line = f"{now()} {msg}"
        print(line, flush=True)
        with open(os.path.join(self.out, "events.log"), "a") as f:
            f.write(line + "\n")

    def _lock(self, path, what):
        f = open(path, "a+")
        try:
            fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            f.seek(0)
            raise RunError(f"{what} is held by another run ({f.read().strip() or 'pid unknown'}): {path}") from None
        f.truncate(0)
        f.write(f"pid {os.getpid()} {self.out}\n")
        f.flush()
        self.locks.append(f)

    def preflight(self, batches):
        local = any(c["network"] != "wan" for b in batches for c in b["cells"])
        for tool in ("go", "git", "openssl") + (("unshare", "taskset", "ip", "tc") if local else ("ssh",)):
            if not shutil.which(tool):
                raise RunError(f"{tool} not found in PATH")
        if not local:
            return
        r = subprocess.run(["unshare", "--user", "--map-root-user", "--net", "sh", "-c", "ip link set lo up && tc qdisc show dev lo"],
                           capture_output=True, text=True, timeout=20)
        if r.returncode != 0:
            raise RunError(f"cannot create a network namespace without root: {r.stderr.strip()}")

    def tls(self):
        d = os.path.join(self.out, "tls")
        cert, key = os.path.join(d, "cert.pem"), os.path.join(d, "key.pem")
        if not os.path.isfile(cert):
            os.makedirs(d, mode=0o700, exist_ok=True)
            subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-days", "30",
                            "-subj", "/CN=127.0.0.1", "-addext", "subjectAltName=IP:127.0.0.1", "-keyout", key, "-out", cert],
                           check=True, capture_output=True, timeout=30)
            os.chmod(key, 0o600)
        return cert, key

    def manifest_path(self):
        return os.path.join(self.out, "manifest.json")

    def load_manifest(self):
        m = read_json(self.manifest_path())
        if m is None:
            return {"plan": self.plan["name"], "hash": self.plan["hash"], "created": now(), "batches": {}}
        if m.get("hash") != self.plan["hash"]:
            raise RunError(f"{self.out} holds a run of another plan (hash {m.get('hash')} vs {self.plan['hash']}); use a new --out")
        return m

    def save(self):
        self.manifest["updated"] = now()
        write_json(self.manifest_path(), self.manifest)

    def batch_done(self, b):
        rec = self.manifest["batches"].get(b["id"])
        if not rec:
            return False
        st = set(rec.get("cells", {}).values())
        if not st or len(rec["cells"]) != len(b["cells"]):
            return False
        if self.retry_failed:
            return st == {"ok"}
        return st <= FINAL or rec.get("status") == "failed"

    def run(self, dry=False):
        os.makedirs(self.out, exist_ok=True)
        os.makedirs(RUNS, exist_ok=True)
        self._lock(os.path.join(self.out, ".lock"), "this run directory")
        if not dry:
            self._lock(os.path.join(RUNS, ".machine.lock"), "the machine")
        self.manifest = self.load_manifest()
        kept = set(self.manifest.get("series_filter") or [])
        if self.only_series is None:
            self.only_series = kept or None
        elif kept:
            self.manifest["series_filter"] = sorted(kept | self.only_series)
        elif not self.manifest["batches"]:
            self.manifest["series_filter"] = sorted(self.only_series)
        unknown = (self.only_series or set()) - {s["name"] for s in self.plan["series"]}
        if unknown:
            raise RunError(f"no such series: {', '.join(sorted(unknown))}")
        batches = planmod.expand(self.plan, self.only_series)
        if not batches:
            raise RunError("the plan selects no cells")
        write_json(os.path.join(self.out, "plan.json"), self.plan)
        self.preflight(batches)
        manifest = build.build_all(self.plan if not dry else {"variants": {}}, self.out, self.emit)
        gen = os.path.join(self.out, "bin", "matrix")
        lists = {}
        for s in self.plan["series"]:
            lists[s["name"]] = build.scenarios(gen, s["only"]) if s["kind"] == "probe" else ["soak"]
            if not lists[s["name"]]:
                raise RunError(f"series {s['name']}: only = {s['only']} selects no scenario")
        self.manifest["scenarios"] = lists
        self.manifest["build"] = manifest
        todo = [b for b in batches if not self.batch_done(b)]
        bound = sum(max(planmod.cell_timeout(c, len(lists[c["series"]])) for c in b["cells"]) for b in todo)
        cells = sum(len(b["cells"]) for b in todo)
        self.emit(f"plan {self.plan['name']} ({self.plan['hash']}): {len(todo)} of {len(batches)} batches, {cells} cells to run, "
                  f"worst case {bound / 3600:.1f} h (every scenario running into its budget)")
        if dry:
            for b in todo:
                self.emit(f"  {b['id']}: " + ", ".join(f"{c['id']} [cpus {c['cpus'] or 'any'}]" for c in b["cells"]))
            return 0
        self.cert = self.tls()
        self.code = self.snapshot()
        self.save()
        signal.signal(signal.SIGINT, self._on_signal)
        signal.signal(signal.SIGTERM, self._on_signal)
        try:
            if any(c["network"] == "wan" for b in todo for c in b["cells"]):
                self.stage = wan.Stage(self.plan, self.out, self.emit)
                try:
                    self.stage_info = self.stage.up(bound)
                except wan.WanError as e:
                    raise RunError(f"wan staging: {e}") from None
            for i, b in enumerate(todo, 1):
                if self.stopping:
                    break
                self.run_batch(b, lists, f"[{i}/{len(todo)}{self.eta(todo[i - 1:])}]")
        finally:
            self.kill_all(signal.SIGKILL)
            if self.stage:
                try:
                    self.stage.down()
                except wan.WanError as e:
                    self.emit(f"wan: cleanup failed ({e}); finish it with: {sys.argv[0]} wan-clean {self.out}")
            self.manifest["state"] = "interrupted" if self.stopping else "finished"
            self.save()
        if self.stopping:
            self.emit(f"interrupted; resume with: {sys.argv[0]} resume {self.out}")
            return 130
        return 0

    def eta(self, left):
        """Time left, from the batches of the same series already run; empty until one has."""
        took = {}
        for bid, rec in self.manifest["batches"].items():
            if rec.get("status") == "done":
                took.setdefault(bid.split("/", 1)[0], []).append(rec["seconds"])
        if not took:
            return ""
        every = [x for v in took.values() for x in v]
        mean = sum(every) / len(every)
        est = sum(sum(took[b["series"]]) / len(took[b["series"]]) if b["series"] in took else mean for b in left)
        return f", eta {est / 3600:.1f} h" if est >= 3600 else f", eta {est / 60:.0f} min"

    def _on_signal(self, signum, frame):
        self.stopping += 1
        if self.stopping == 1:
            self.stopped_at = time.monotonic()
            print(f"\n{now()} stopping: cells are told to stop and write what they have (again to kill at once)", flush=True)
            self.kill_all(signal.SIGTERM)
        else:
            self.kill_all(signal.SIGKILL)

    def kill_all(self, sig):
        """TERM goes to the cell alone, so it can stop its processes and write
        run.json; KILL goes to its whole process group."""
        for p in list(self.live.values()):
            try:
                if sig == signal.SIGKILL:
                    os.killpg(p.pid, sig)
                else:
                    os.kill(p.pid, sig)
            except ProcessLookupError:
                pass

    def quiet(self, cpus):
        """Waits until the machine is quiet enough on cpus; says how it started."""
        g = self.plan["guard"]
        end = time.monotonic() + seconds(g["load_wait"])
        while True:
            a, t = cpu_times(cpus), time.monotonic()
            time.sleep(2)
            load = (cpu_times(cpus) - a) / (time.monotonic() - t)
            mem = mem_available_mb()
            ok = load <= g["max_foreign_cores"] and mem >= g["min_free_mb"]
            if ok or time.monotonic() > end or self.stopping:
                return {"load_cores": round(load, 2), "mem_mb": mem, "quiet": ok}
            time.sleep(3)

    def spec(self, c, n, attempt):
        d = os.path.join(self.out, "cells", c["id"])
        if os.path.isdir(d):
            arch = os.path.join(self.out, "attempts", f"{c['id']}.{attempt}")
            os.makedirs(os.path.dirname(arch), exist_ok=True)
            shutil.rmtree(arch, ignore_errors=True)
            shutil.move(d, arch)
        os.makedirs(d)
        tmp = os.path.join(self.out, "tmp", c["id"].replace("/", "_"))
        os.makedirs(tmp, mode=0o700, exist_ok=True)
        limit = planmod.cell_timeout(c, n)
        bindir = os.path.join(self.out, "bin")
        spec = dict(c, dir=d, tmp=tmp, parent_pid=os.getpid(), parent_netns=netns_inode(), deadline=time.time() + limit,
                    timeout=limit, cert=self.cert[0], key=self.cert[1],
                    bin={"matrix": os.path.join(bindir, "matrix"),
                         "s5core": os.path.join(bindir, c["variant"], "s5core"),
                         "s5client": os.path.join(bindir, c["variant"], "s5client")})
        if c["network"] == "wan":
            spec.update(wan=self.plan["wan"], stage=self.stage_info)
        write_json(os.path.join(d, "spec.json"), spec)
        return spec

    def snapshot(self):
        """Cells run from a copy of the pipeline taken at start, so editing it
        mid-run does not change how the remaining cells measure."""
        d = os.path.join(self.out, "code")
        shutil.rmtree(d, ignore_errors=True)
        shutil.copytree(os.path.join(ROOT, "pipeline"), os.path.join(d, "pipeline"), ignore=shutil.ignore_patterns("__pycache__"))
        shutil.copy2(os.path.join(ROOT, "matrix.py"), d)
        return os.path.join(d, "matrix.py")

    def launch(self, spec):
        cmd = ["unshare", "--user", "--map-root-user", "--net", sys.executable, self.code, "cell", os.path.join(spec["dir"], "spec.json")]
        if spec["network"] == "wan":
            cmd = [sys.executable, self.code, "wancell", os.path.join(spec["dir"], "spec.json")]
        elif spec["cpus"]:
            cmd = ["taskset", "-c", str(spec["cpus"])] + cmd
        env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "PYTHONDONTWRITEBYTECODE": "1", "LANG": "C.UTF-8"}
        log = open(os.path.join(spec["dir"], "cell.log"), "ab")
        p = subprocess.Popen(cmd, env=env, stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
        log.close()
        return p

    def run_batch(self, b, lists, tag):
        remote = all(c["network"] == "wan" for c in b["cells"])
        cpus = set()
        for c in b["cells"]:
            cpus |= cpu_list(c["cpus"]) if c["cpus"] else os.sched_getaffinity(0)
        retries = max(c["settings"]["retries"] for c in b["cells"])
        rec = self.manifest["batches"].get(b["id"], {})
        attempt = rec.get("attempts", 0)
        for _ in range(retries + 1):
            attempt += 1
            # This machine's load says nothing about a WAN cell; the cell measures its hosts itself.
            start = {"quiet": True, "remote": True} if remote else self.quiet(cpus)
            if self.stopping:
                return
            specs = [self.spec(c, len(lists[c["series"]]), attempt) for c in b["cells"]]
            busy0, t0 = cpu_times(cpus), time.monotonic()
            self.live = {s["id"]: self.launch(s) for s in specs}
            outer = max(s["timeout"] for s in specs) + 60
            killed = {}
            while self.live:
                for cid, p in list(self.live.items()):
                    if p.poll() is not None:
                        del self.live[cid]
                if self.stopping and time.monotonic() - self.stopped_at > KILL_WAIT:
                    self.kill_all(signal.SIGKILL)
                if time.monotonic() - t0 > outer and self.live:
                    for cid in self.live:
                        killed[cid] = "timeout"
                    self.kill_all(signal.SIGTERM)
                    end = time.monotonic() + KILL_WAIT
                    while any(p.poll() is None for p in self.live.values()) and time.monotonic() < end:
                        time.sleep(0.2)
                    self.kill_all(signal.SIGKILL)
                    for p in self.live.values():
                        p.wait()
                    self.live = {}
                time.sleep(0.2)
            wall = time.monotonic() - t0
            busy = cpu_times(cpus) - busy0
            statuses, own = {}, 0.0
            for s in specs:
                r = read_json(os.path.join(s["dir"], "run.json"))
                if r is None:
                    st = killed.get(s["id"]) or ("interrupted" if self.stopping else "cell_error")
                    r = {"id": s["id"], "status": st, "reason": "no run.json: the cell was killed" if st != "cell_error" else "cell exited without run.json, see cell.log"}
                    write_json(os.path.join(s["dir"], "run.json"), r)
                elif s["id"] in killed and r.get("status") == "ok":
                    pass
                elif s["id"] in killed:
                    r["status"], r["reason"] = "timeout", f"cell exceeded its outer bound of {outer:.0f}s; " + r.get("reason", "")
                    write_json(os.path.join(s["dir"], "run.json"), r)
                statuses[s["id"]] = r["status"]
                own += r.get("own_cpu_s", 0.0)
                shutil.rmtree(s["tmp"], ignore_errors=True)
            foreign = max(0.0, (busy - own) / wall) if wall > 0 else 0.0
            noisy = foreign > self.plan["guard"]["max_foreign_cores"]
            if remote:
                far = [v for s in specs for v in (read_json(os.path.join(s["dir"], "run.json"), {}).get("remote_foreign_cores") or {}).values()]
                foreign = max(far, default=0.0)
                limit = self.plan["wan"]["max_foreign_cores"]
                noisy = bool(limit) and foreign > limit
            rec = {"status": "running", "attempts": attempt, "cells": statuses, "seconds": round(wall, 1), "finished": now(),
                   "start": start, "foreign_cores": round(foreign, 2), "noisy": noisy}
            self.manifest["batches"][b["id"]] = rec
            summary = ", ".join(f"{cid.split('/', 1)[1]}={st}" for cid, st in statuses.items())
            flags = (" noisy(%.1f cores)" % foreign if noisy else "") + ("" if start["quiet"] else " loaded-start")
            self.emit(f"{tag} {b['id']}: {summary} ({wall:.0f}s){flags}")
            if self.stopping and not set(statuses.values()) <= FINAL:
                rec["status"] = "interrupted"
                self.save()
                return
            if self.stopping or not (set(statuses.values()) & RETRY):
                rec["status"] = "done"
                self.save()
                return
            self.save()
            for s in specs:
                if statuses[s["id"]] in RETRY:
                    r = read_json(os.path.join(s["dir"], "run.json"), {})
                    self.emit(f"  {s['id']}: {statuses[s['id']]}: {r.get('reason', '')}")
        rec["status"] = "failed"
        self.save()
        self.emit(f"  {b['id']}: gave up after {retries + 1} attempts")


def stale(out, kill=False):
    """Processes still running from out/bin, left by a run that was killed hard."""
    bindir = os.path.realpath(os.path.join(out, "bin"))
    found = []
    for pid in filter(str.isdigit, os.listdir("/proc")):
        try:
            exe = os.path.realpath(f"/proc/{pid}/exe")
        except OSError:
            continue
        if exe.startswith(bindir + os.sep):
            found.append((int(pid), exe))
    for pid, exe in found:
        print(f"{pid} {exe}")
        if kill:
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
    return found


def status(out):
    m = read_json(os.path.join(out, "manifest.json"))
    p = read_json(os.path.join(out, "plan.json"))
    if not m or not p:
        raise RunError(f"{out}: no manifest")
    batches = planmod.expand(p, set(m.get("series_filter") or []) or None)
    counts, done = {}, 0
    for b in batches:
        rec = m["batches"].get(b["id"])
        if rec and rec.get("status") in ("done", "failed"):
            done += 1
        for c in b["cells"]:
            st = (rec or {}).get("cells", {}).get(c["id"], "pending")
            counts[st] = counts.get(st, 0) + 1
    print(f"{p['name']} ({p['hash']}), state {m.get('state', 'running')}, updated {m.get('updated', '?')}"
          + (f", series {','.join(m['series_filter'])}" if m.get("series_filter") else ""))
    print(f"batches {done}/{len(batches)}; cells: " + ", ".join(f"{k}={v}" for k, v in sorted(counts.items())))
    for b in batches:
        rec = m["batches"].get(b["id"])
        if rec and (rec.get("noisy") or set(rec.get("cells", {}).values()) - {"ok"}):
            bad = {k.split("/", 1)[1]: v for k, v in rec["cells"].items() if v != "ok"}
            print(f"  {b['id']}: {json.dumps(bad) if bad else ''}{' noisy %.1f' % rec['foreign_cores'] if rec.get('noisy') else ''}")
    return 0

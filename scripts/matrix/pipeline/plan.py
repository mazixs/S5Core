"""Benchmark plan: TOML in, validated plan and the cells it expands to out."""

import copy
import hashlib
import json
import os
import tomllib

from .util import cpu_list, seconds

TRANSPORTS = ("plain", "obfs", "wss")
AUTHS = ("none", "member", "password", "fallback")
# The server port a transport's client-server leg uses; netem shapes only it.
TUNNEL_PORT = {"plain": 41080, "obfs": 41443, "wss": 41444}

DEFAULTS = {
    "auth": "member",
    "scale": 1.0,
    "warmup": True,
    "flush": "60s",
    "slow_ms": 0,
    "scenario_timeout": "5m",
    "hang_grace": "30s",
    "max_errors_in_row": 50,
    "server_procs": 4,
    "client_procs": 4,
    "gen_procs": 4,
    "settle": "5s",
    "sample_s": 0,
    "cell_timeout": "auto",
    "retries": 2,
    "min_pairs": 3,
    "soak": "300s",
    "workers": 32,
    "idle": "75s",
    "capture": False,
    "capture_packets": 200000,
}
GUARD = {"max_foreign_cores": 1.5, "load_wait": "120s", "min_free_mb": 1024}
# network = "wan": the server and the origins on one remote host, client and generator on another, over ssh.
WAN = {"server": None, "client": None, "server_ip": None, "server_arch": "amd64", "client_arch": "arm64",
       "server_dir": "/root/s5bench", "client_dir": "/opt/tmp/s5bench", "server_memory_max": "300M",
       "origin_memory_max": "256M", "max_foreign_cores": 0}
ARCHES = ("amd64", "arm64", "arm", "386", "mipsle", "mips")
SERIES_KEYS = {"name", "title", "network", "variants", "transports", "rounds", "only", "kind", "env", "compare"} | set(DEFAULTS)
VARIANT_KEYS = {"direct", "ref", "patch", "env", "title"}


class PlanError(Exception):
    pass


def _env(d, where):
    out = {"server": {}, "client": {}}
    for side, kv in (d or {}).items():
        if side not in out:
            raise PlanError(f"{where}: env.{side} - only env.server and env.client exist")
        out[side] = {str(k): str(v) for k, v in kv.items()}
    return out


def _merge_env(*envs):
    out = {"server": {}, "client": {}}
    for e in envs:
        for side in out:
            out[side].update(e[side])
    return out


def _settings(base, over, where):
    s = dict(base)
    for k, v in over.items():
        if k not in DEFAULTS:
            continue
        s[k] = v
    for k in ("scenario_timeout", "hang_grace", "settle", "flush", "soak", "idle"):
        try:
            seconds(s[k])
        except ValueError as e:
            raise PlanError(f"{where}: {k}: {e}") from None
    if s["cell_timeout"] != "auto":
        seconds(s["cell_timeout"])
    auths = s["auth"] if isinstance(s["auth"], list) else [s["auth"]]
    for a in auths:
        if a not in AUTHS:
            raise PlanError(f"{where}: auth {a!r} - one of {', '.join(AUTHS)}")
    s["auth"] = auths
    return s


def load(path):
    with open(path, "rb") as f:
        raw = tomllib.load(f)
    return resolve(raw, os.path.dirname(os.path.abspath(path)))


def resolve(raw, base_dir):
    known = {"name", "description", "base", "candidate", "defaults", "env", "variants", "cpus", "guard", "wan", "series"}
    for k in raw:
        if k not in known:
            raise PlanError(f"unknown top-level key {k!r}")
    for k in ("name", "base", "candidate", "variants", "series"):
        if k not in raw:
            raise PlanError(f"missing {k!r}")
    for k in raw.get("defaults", {}):
        if k not in DEFAULTS:
            raise PlanError(f"defaults: unknown key {k!r}")
    for k in raw.get("guard", {}):
        if k not in GUARD:
            raise PlanError(f"guard: unknown key {k!r}")
    defaults = _settings(DEFAULTS, raw.get("defaults", {}), "defaults")
    env = _env(raw.get("env"), "env")

    variants = {}
    for name, v in raw["variants"].items():
        for k in v:
            if k not in VARIANT_KEYS:
                raise PlanError(f"variants.{name}: unknown key {k!r}")
        direct = bool(v.get("direct", False))
        if direct == ("ref" in v):
            raise PlanError(f"variants.{name}: set either direct = true or ref")
        patch = v.get("patch")
        if patch:
            patch = os.path.normpath(os.path.join(base_dir, patch))
            if not os.path.isfile(patch):
                raise PlanError(f"variants.{name}: patch {patch} not found")
        variants[name] = {"direct": direct, "ref": v.get("ref"), "patch": patch, "env": _env(v.get("env"), f"variants.{name}"), "title": v.get("title", name)}
    for k in ("base", "candidate"):
        if raw[k] not in variants or variants[raw[k]]["direct"]:
            raise PlanError(f"{k} {raw[k]!r} must name a variant with ref")

    cpus = raw.get("cpus", {})
    avail = os.sched_getaffinity(0)
    for k, v in cpus.items():
        for spec in v if isinstance(v, list) else [v]:
            missing = cpu_list(spec) - avail
            if missing:
                raise PlanError(f"cpus.{k}: CPUs {sorted(missing)} are not available here")
    guard = dict(GUARD) | raw.get("guard", {})
    wan = _wan(raw.get("wan"))

    series, names = [], set()
    for i, s in enumerate(raw["series"]):
        where = f"series[{i}]"
        for k in s:
            if k not in SERIES_KEYS:
                raise PlanError(f"{where}: unknown key {k!r}")
        name = s.get("name") or ""
        if not name or "/" in name or name in names:
            raise PlanError(f"{where}: name must be unique and without '/'")
        names.add(name)
        where = f"series {name}"
        st = _settings(defaults, s, where)
        net = s.get("network", "loopback")
        if net == "wan" and not wan:
            raise PlanError(f"{where}: network = 'wan' needs a [wan] section")
        if net not in ("loopback", "wan"):
            if not isinstance(net, dict) or set(net) - {"rtt_ms", "loss_pct", "rate_mbit"}:
                raise PlanError(f"{where}: network is 'loopback', 'wan' or {{rtt_ms, loss_pct, rate_mbit}}")
            net = {"rtt_ms": float(net.get("rtt_ms", 0)), "loss_pct": float(net.get("loss_pct", 0)), "rate_mbit": float(net.get("rate_mbit", 0))}
        vs = s.get("variants", list(variants))
        for v in vs:
            if v not in variants:
                raise PlanError(f"{where}: variant {v!r} is not defined")
        ts = s.get("transports", ["obfs", "wss"])
        for t in ts:
            if t not in TRANSPORTS:
                raise PlanError(f"{where}: transport {t!r} - one of {', '.join(TRANSPORTS)}")
            if t == "plain" and net == "wan":
                raise PlanError(f"{where}: plain SOCKS5 does not cross the internet in a benchmark")
            if t == "plain" and st["auth"] != ["none"]:
                raise PlanError(f"{where}: plain SOCKS5 runs only with auth = 'none' (the generator does not send a password)")
        rounds = int(s.get("rounds", 1))
        if rounds < 1:
            raise PlanError(f"{where}: rounds must be at least 1")
        kind = s.get("kind", "probe")
        if kind not in ("probe", "soak"):
            raise PlanError(f"{where}: kind is 'probe' or 'soak'")
        only = s.get("only", [])
        if isinstance(only, str):
            only = [x for x in only.split(",") if x]
        tunnel = [v for v in vs if not variants[v]["direct"]]
        if net not in ("loopback", "wan"):
            if any(variants[v]["direct"] for v in vs) and "raw" not in cpus:
                raise PlanError(f"{where}: a netem series with a direct variant needs cpus.raw")
            for t in ts:
                sets = cpus.get(t)
                need = len(tunnel) if len(tunnel) * len(st["auth"]) > len(sets or []) else len(tunnel) * len(st["auth"])
                if not isinstance(sets, list) or len(sets) < need:
                    raise PlanError(f"{where}: netem runs cells of one round in parallel; cpus.{t} needs at least {need} sets")
        compare = s.get("compare")
        if compare is None:
            compare = [[raw["base"], raw["candidate"]]] if raw["base"] in vs and raw["candidate"] in vs else []
        for pair in compare:
            if len(pair) != 2 or any(p not in vs or variants[p]["direct"] for p in pair):
                raise PlanError(f"{where}: compare pairs name two tunnel variants of this series")
        series.append({
            "name": name, "title": s.get("title", name), "network": net, "variants": vs, "transports": ts,
            "rounds": rounds, "only": only, "kind": kind, "settings": st, "compare": compare,
            "env": _merge_env(env, _env(s.get("env"), where)),
        })
    plan = {
        "name": raw["name"], "description": raw.get("description", ""), "base": raw["base"], "candidate": raw["candidate"],
        "variants": variants, "cpus": cpus, "guard": guard, "series": series,
    }
    if wan:
        plan["wan"] = wan
    plan["hash"] = digest(plan)
    expand(plan)
    return plan


def _wan(raw):
    if raw is None:
        return None
    for k in raw:
        if k not in WAN:
            raise PlanError(f"wan: unknown key {k!r}")
    w = dict(WAN) | raw
    for k in ("server", "client"):
        if not w[k]:
            raise PlanError(f"wan: {k} (an ssh target) is required")
    if not w["server_ip"]:
        w["server_ip"] = w["server"].rsplit("@", 1)[-1]
    for k in ("server_arch", "client_arch"):
        if w[k] not in ARCHES:
            raise PlanError(f"wan: {k} {w[k]!r} - one of {', '.join(ARCHES)}")
    for k in ("server_dir", "client_dir"):
        # Staging wipes these directories: they must be ours by name.
        if not w[k].startswith("/") or "s5bench" not in os.path.basename(w[k].rstrip("/")):
            raise PlanError(f"wan: {k} must be an absolute path whose last part contains 's5bench'")
    return w


def digest(plan):
    body = {k: v for k, v in plan.items() if k != "hash"}
    return hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest()[:16]


def cell_id(series, variant, transport, auth, rnd, direct):
    if direct:
        return f"{series}/{variant}-r{rnd}"
    return f"{series}/{variant}-{transport}-{auth}-r{rnd}"


def expand(plan, only_series=None):
    """Batches in run order. A batch is the unit that runs at once and is
    retried or resumed whole: a netem round (its cells share the machine) or a
    single loopback cell. A netem round with more tunnel cells than CPU sets
    runs one auth mode at a time, so the variants it compares stay concurrent."""
    batches = []
    for s in plan["series"]:
        if only_series and s["name"] not in only_series:
            continue
        netem = s["network"] not in ("loopback", "wan")
        direct = [v for v in s["variants"] if plan["variants"][v]["direct"]]
        tunnel = [v for v in s["variants"] if not plan["variants"][v]["direct"]]
        auths = s["settings"]["auth"]
        for r in range(1, s["rounds"] + 1):
            if not netem:
                # WAN cells run one at a time too; their CPUs are on the remote hosts.
                cpus = plan["cpus"].get("loopback") if s["network"] == "loopback" else None
                cells = [_cell(plan, s, v, "direct", "none", r, cpus) for v in direct]
                cells += [_cell(plan, s, v, t, a, r, cpus) for t in s["transports"] for v in tunnel for a in auths]
                if r % 2 == 0:
                    cells.reverse()
                batches += [{"id": c["id"], "series": s["name"], "round": r, "cells": [c]} for c in cells]
                continue
            fits = all(len(tunnel) * len(auths) <= len(plan["cpus"].get(t) or []) for t in s["transports"])
            groups = [auths] if fits else [[a] for a in (auths if r % 2 else auths[::-1])]
            for g, au in enumerate(groups):
                cells = [_cell(plan, s, v, "direct", "none", r, plan["cpus"].get("raw")) for v in direct] if g == 0 else []
                for t in s["transports"]:
                    sets = plan["cpus"][t]
                    slots = [(v, a) for v in tunnel for a in au]
                    for i, (v, a) in enumerate(slots):
                        cells.append(_cell(plan, s, v, t, a, r, sets[(i + r) % len(slots)]))
                _disjoint(cells, s["name"])
                bid = f"{s['name']}/r{r}" if fits else f"{s['name']}/r{r}-{au[0]}"
                batches.append({"id": bid, "series": s["name"], "round": r, "cells": cells})
    return batches


def _disjoint(cells, series):
    seen = {}
    for c in cells:
        for cpu in (cpu_list(c["cpus"]) if c["cpus"] else ()):
            if cpu in seen:
                raise PlanError(f"series {series}: cells {seen[cpu]} and {c['id']} would share CPU {cpu}")
            seen[cpu] = c["id"]


def _cell(plan, s, variant, transport, auth, rnd, cpus):
    v = plan["variants"][variant]
    direct = v["direct"]
    env = _merge_env(s["env"], v["env"])
    net = s["network"]
    scope = None
    if net not in ("loopback", "wan"):
        scope = "all" if direct else TUNNEL_PORT[transport]
    return {
        "id": cell_id(s["name"], variant, transport, auth, rnd, direct),
        "series": s["name"], "variant": variant, "transport": transport, "auth": auth if not direct else "none",
        "round": rnd, "direct": direct, "kind": s["kind"], "network": net, "shape": scope, "cpus": cpus,
        "only": s["only"], "settings": copy.deepcopy(s["settings"]), "env": env,
    }


def cell_timeout(cell, n_scenarios):
    """Outer bound of one cell: each scenario's budget and grace, plus setup,
    warmup and settle. It only catches what the inner bounds did not."""
    st = cell["settings"]
    if st["cell_timeout"] != "auto":
        return seconds(st["cell_timeout"])
    per = seconds(st["scenario_timeout"]) + seconds(st["hang_grace"])
    if cell["kind"] == "soak":
        body = max(seconds(st["soak"]), seconds(st["idle"])) + per
    else:
        body = max(1, n_scenarios) * per
    # A WAN cell also starts and stops everything over ssh.
    return body + 120 + seconds(st["settle"]) + (60 if cell["network"] == "wan" else 0)

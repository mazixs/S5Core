"""Paired comparison of variants over the rounds of a run.

Verdict rule: "better" or "worse" only when the medians differ by at least
REL (for percentages: ABS_PCT points, for milliseconds also at least MS_FLOOR)
and every paired round has the same sign. With 3 rounds a metric without an
effect gets such a verdict in about 25% of cases, with 5 in about 6%, so each
"worse" is a flag for a targeted recheck (`matrix.py recheck`), not a finding.
"""

import math
import os
import statistics

from . import plan as planmod
from .util import read_json

REL = 0.05
ABS_PCT = 0.5
MS_FLOOR = 0.02

# key, label, unit, sign: -1 means lower is better.
METRICS = [
    ("p50_ms", "p50", "ms", -1),
    ("p90_ms", "p90", "ms", -1),
    ("p99_ms", "p99", "ms", -1),
    ("mbps", "полоса", "MB/s", 1),
    ("extra.ttfb_p50_ms", "TTFB p50", "ms", -1),
    ("extra.handshake_p50_ms", "установка p50", "ms", -1),
    ("extra.loss_pct", "потери", "%", -1),
    ("slow_pct", "доля медленных", "%", -1),
    ("extra.background_MBps", "фоновая закачка", "MB/s", 1),
]
CELL_METRICS = [
    ("cpu_s", "CPU сервера и клиента", "s", -1),
    ("cpu_per_gb", "CPU на ГБ", "s/GB", -1),
]
CELL_ROW = "(ячейка целиком)"
# Below this many samples a percentile is the maximum, not a tail.
MIN_N = {"p90_ms": 10, "p99_ms": 100}


def _get(st, key, slow_ms=0):
    if key == "slow_pct":
        # omitempty drops a zero share; with a margin set, missing means none were slow.
        return st.get(key, 0.0) if slow_ms else None
    if key.startswith("extra."):
        return (st.get("extra") or {}).get(key[6:])
    return st.get(key)


def sign_p(worse, better):
    """Two-sided sign test without ties."""
    m = worse + better
    if m == 0:
        return 1.0
    k = min(worse, better)
    return min(1.0, 2 * sum(math.comb(m, i) for i in range(k + 1)) / 2 ** m)


def binom_p(ka, na, kb, nb):
    """Exact conditional test for two shares: given ka + kb events, is kb
    consistent with Binom(ka + kb, nb / (na + nb))? Two-sided."""
    k = ka + kb
    if k == 0 or na + nb == 0:
        return 1.0
    q = nb / (na + nb)
    if q in (0.0, 1.0):
        return 1.0 if kb == round(q * k) else 0.0
    # Log space: math.comb overflows a float past about a thousand events.
    lq, lr, lk = math.log(q), math.log1p(-q), math.lgamma(k + 1)
    logs = [lk - math.lgamma(i + 1) - math.lgamma(k - i + 1) + i * lq + (k - i) * lr for i in range(k + 1)]
    obs = logs[kb] + 1e-9
    return min(1.0, sum(math.exp(x) for x in logs if x <= obs))


def verdict(unit, sign, pairs, min_pairs):
    """pairs: [(a, b)] by round. Returns the row fields for a -> b."""
    a = [x for x, _ in pairs]
    b = [y for _, y in pairs]
    ma, mb = statistics.median(a), statistics.median(b)
    delta = mb - ma
    rel = delta / ma if ma else None
    worse = sum(1 for x, y in pairs if (y - x) * sign < 0)
    better = sum(1 for x, y in pairs if (y - x) * sign > 0)
    row = {"a": ma, "b": mb, "delta": delta, "rel": rel, "n": len(pairs), "worse": worse, "better": better,
           "p": sign_p(worse, better), "verdict": "нет"}
    if len(pairs) < min_pairs:
        row["verdict"] = "мало пар"
        return row
    if unit == "%":
        big = abs(delta) >= ABS_PCT
    else:
        big = rel is not None and abs(rel) >= REL and (unit != "ms" or abs(delta) >= MS_FLOOR)
    if big and worse == len(pairs):
        row["verdict"] = "хуже"
    elif big and better == len(pairs):
        row["verdict"] = "лучше"
    return row


def load(out):
    p = read_json(os.path.join(out, "plan.json"))
    m = read_json(os.path.join(out, "manifest.json"), {})
    if not p:
        raise FileNotFoundError(f"{out}/plan.json")
    cells = []
    for b in planmod.expand(p, set(m.get("series_filter") or []) or None):
        rec = m.get("batches", {}).get(b["id"], {})
        for c in b["cells"]:
            d = os.path.join(out, "cells", c["id"])
            run = read_json(os.path.join(d, "run.json"), {})
            res = read_json(os.path.join(d, "result.json"), {})
            cells.append(dict(c, run=run, result=res.get("result") or {}, status=run.get("status", "pending"),
                              noisy=bool(rec.get("noisy")), foreign=rec.get("foreign_cores")))
    return p, m, cells


def cell_numbers(c):
    """CPU of server and client over the measured window, and bytes moved."""
    r = c["run"]
    cpu = 0.0
    for proc in ("server", "client"):
        a, b = (r.get("before") or {}).get(proc), (r.get("after") or {}).get(proc)
        if a and b:
            cpu += b["cpu_s"] - a["cpu_s"]
    out = {}
    if not c["direct"] and r.get("before"):
        out["cpu_s"] = cpu
    if c["kind"] == "probe":
        moved = sum((st.get("bytes") or 0) for st in c["result"].values())
        if moved and "cpu_s" in out:
            out["cpu_per_gb"] = cpu / (moved / 1e9)
        out["bytes"] = moved
    return out


def usable(c, include_noisy):
    return c["status"] == "ok" and (include_noisy or not c["noisy"])


def _arms(p, s):
    v = p["variants"]
    auths = s["settings"]["auth"]
    comps = []
    for a, b in s["compare"]:
        for au in auths:
            comps.append(((a, au), (b, au)))
    if len(auths) > 1:
        for var in s["variants"]:
            if not v[var]["direct"]:
                for au in auths[1:]:
                    comps.append(((var, auths[0]), (var, au)))
    return comps


def analyze(out, include_noisy=False):
    p, m, cells = load(out)
    by = {}
    for c in cells:
        by.setdefault(c["series"], []).append(c)
    report = {"plan": p, "manifest": m, "series": [], "problems": problems(p, cells), "flags": [],
              "cells": [{k: c[k] for k in ("id", "series", "variant", "transport", "auth", "round", "status", "noisy", "foreign")}
                        | {"reason": c["run"].get("reason", ""), "seconds": c["run"].get("seconds")} for c in cells]}
    counts = {}
    for c in cells:
        counts[c["status"]] = counts.get(c["status"], 0) + 1
    report["counts"] = counts
    for s in p["series"]:
        if s["name"] not in by:
            continue
        sc = by[s["name"]]
        entry = {"name": s["name"], "title": s["title"], "network": s["network"], "rounds": s["rounds"], "kind": s["kind"],
                 "comparisons": [], "raw": {}}
        idx = {}
        for c in sc:
            if usable(c, include_noisy):
                idx[(c["variant"], c["transport"], c["auth"], c["round"])] = c
        raw = [c for c in sc if c["direct"] and usable(c, include_noisy)]
        if s["kind"] == "soak":
            entry["soak"] = soak(sc)
            report["series"].append(entry)
            continue
        for t in s["transports"]:
            for (va, aa), (vb, ab) in _arms(p, s):
                comp = {"transport": t, "a": {"variant": va, "auth": aa}, "b": {"variant": vb, "auth": ab}, "rows": [], "slow": []}
                rounds = [r for r in range(1, s["rounds"] + 1) if (va, t, aa, r) in idx and (vb, t, ab, r) in idx]
                order = {n: i for i, n in enumerate(m.get("scenarios", {}).get(s["name"], []))}
                scen = sorted({k for r in rounds for k in idx[(va, t, aa, r)]["result"]} | {k for r in rounds for k in idx[(vb, t, ab, r)]["result"]},
                              key=lambda n: (order.get(n, len(order)), n))
                slow_ms = s["settings"]["slow_ms"]
                for name in scen:
                    for key, label, unit, sign in METRICS:
                        pairs = []
                        for r in rounds:
                            sa, sb = idx[(va, t, aa, r)]["result"].get(name), idx[(vb, t, ab, r)]["result"].get(name)
                            if not sa or not sb or sa.get("aborted") or sb.get("aborted") or not sa.get("n") or not sb.get("n"):
                                continue
                            if min(sa["n"], sb["n"]) < MIN_N.get(key, 1):
                                continue
                            x, y = _get(sa, key, slow_ms), _get(sb, key, slow_ms)
                            if x is None or y is None:
                                continue
                            pairs.append((x, y))
                        if not pairs or all(x == 0 and y == 0 for x, y in pairs):
                            continue
                        row = verdict(unit, sign, pairs, s["settings"]["min_pairs"])
                        rv = [_get(c["result"][name], key, slow_ms) for c in raw if name in c["result"] and not c["result"][name].get("aborted")]
                        rv = [x for x in rv if x is not None]
                        row.update(scenario=name, metric=key, label=label, unit=unit, raw=statistics.median(rv) if rv else None)
                        comp["rows"].append(row)
                    slow = slow_share(idx, va, aa, vb, ab, t, rounds, name) if slow_ms else None
                    if slow:
                        comp["slow"].append(slow)
                for key, label, unit, sign in CELL_METRICS:
                    pairs = []
                    for r in rounds:
                        x, y = cell_numbers(idx[(va, t, aa, r)]).get(key), cell_numbers(idx[(vb, t, ab, r)]).get(key)
                        if x is not None and y is not None:
                            pairs.append((x, y))
                    if pairs:
                        row = verdict(unit, sign, pairs, s["settings"]["min_pairs"])
                        row.update(scenario=CELL_ROW, metric=key, label=label, unit=unit, raw=None)
                        comp["rows"].append(row)
                comp["rounds"] = len(rounds)
                entry["comparisons"].append(comp)
                for row in comp["rows"]:
                    if row["verdict"] == "хуже":
                        report["flags"].append({"series": s["name"], "transport": t, "a": comp["a"], "b": comp["b"],
                                                "scenario": row["scenario"], "metric": row["metric"]})
        report["series"].append(entry)
    return report


def slow_share(idx, va, aa, vb, ab, t, rounds, name):
    tot = {"a": [0, 0], "b": [0, 0]}
    for r in rounds:
        pair = [idx[(v, t, au, r)]["result"].get(name) or {} for v, au in ((va, aa), (vb, ab))]
        if any(st.get("aborted") or not st.get("n") for st in pair):
            continue
        for side, st in zip("ab", pair):
            tot[side][0] += round((st.get("slow_pct") or 0) * st["n"] / 100)
            tot[side][1] += st["n"]
    if not tot["a"][1] or not tot["b"][1]:
        return None
    (ka, na), (kb, nb) = tot["a"], tot["b"]
    return {"scenario": name, "a_slow": ka, "a_n": na, "b_slow": kb, "b_n": nb, "p": binom_p(ka, na, kb, nb)}


def soak(cells):
    rows = []
    for c in sorted(cells, key=lambda c: (c["variant"], c["transport"], c["round"])):
        r, res = c["run"], c["result"]
        kinds = res.get("kinds") or {}
        rss = {}
        for proc in ("server", "client"):
            a, b = (r.get("before") or {}).get(proc), (r.get("settled") or r.get("after") or {}).get(proc)
            if a and b:
                rss[proc] = (a["rss_kb"], b["rss_kb"], b["hwm_kb"])
        rows.append({"id": c["id"], "status": c["status"], "ops": sum(k.get("n", 0) for k in kinds.values()),
                     "errors": {k: v.get("errors", 0) for k, v in kinds.items() if v.get("errors")},
                     "idle": res.get("idle") or {}, "rss": rss,
                     "sessions": (r.get("gauges_settled") or {}).get("s5core_sessions")})
    return rows


def _arm(c):
    return c["variant"] if c["direct"] else f"{c['variant']}-{c['transport']}-{c['auth']}"


def problems(p, cells):
    """What went wrong, grouped: scenario errors and aborts per arm and scenario over all rounds."""
    out, errs = [], {}
    for c in cells:
        for name, st in sorted(c["result"].items()) if c["kind"] == "probe" else []:
            if st.get("aborted") or st.get("errors"):
                e = errs.setdefault((c["series"], _arm(c), name), {"rounds": [], "errors": 0, "n": 0, "aborted": [], "first": ""})
                e["rounds"].append(c["round"])
                e["errors"] += st.get("errors", 0)
                e["n"] += st.get("n", 0)
                if st.get("aborted"):
                    e["aborted"].append(f"r{c['round']} {st['aborted']}")
                e["first"] = e["first"] or st.get("first_error", "")
    for (series, arm, name), e in sorted(errs.items()):
        kind = "сценарий прерван" if e["aborted"] else "ошибки"
        text = f"{e['errors']} ошибок на {e['errors'] + e['n']} операций, раунды {', '.join(map(str, sorted(set(e['rounds']))))}"
        if e["aborted"]:
            text += "; прерван: " + ", ".join(e["aborted"])
        if e["first"]:
            text += f"; первая: {e['first'][:300]}"
        out.append({"kind": kind, "where": f"{series}/{arm} {name}", "text": text})
    for c in cells:
        r = c["run"]
        if c["status"] == "pending":
            out.append({"kind": "не запускалась", "where": c["id"], "text": "ячейка не выполнена"})
            continue
        if c["status"] != "ok":
            out.append({"kind": c["status"], "where": c["id"], "text": r.get("reason", "")})
        sess = (r.get("gauges_settled") or {}).get("s5core_sessions")
        if sess:
            out.append({"kind": "незакрытые сессии", "where": c["id"], "text": f"s5core_sessions = {sess:g} после паузы"})
        ill = (r.get("gauges_settled") or {}).get("illegal_transitions", 0) - (r.get("gauges_before") or {}).get("illegal_transitions", 0)
        if ill:
            out.append({"kind": "недопустимые переходы", "where": c["id"], "text": f"{ill:g} за замер"})
        for proc in ("server", "client"):
            lc = r.get(f"{proc}_log") or {}
            if lc.get("ERROR") or lc.get("WARN"):
                out.append({"kind": f"лог {proc}", "where": c["id"], "text": ", ".join(f"{k} {v}" for k, v in sorted(lc.items()))})
        if c["noisy"]:
            out.append({"kind": "шумная машина", "where": c["id"], "text": f"посторонняя нагрузка {c['foreign']} ядра, в сравнение не вошла"})
    return out

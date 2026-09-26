"""The numbers of the path degradation series (plans/degradation-*.toml) as JSON.

  cd scripts/matrix && python3 -m pipeline.degradation RUN_DIR [RUN_DIR...]

Per cell: the stream, the load or resume windows and what the client logged;
per series: every tunnel variant against the direct cell of the same batch,
which saw the same queue or the same wake at the same time.
"""

import glob
import json
import os
import sys

from .util import read_json

# Moves of the answers and datagrams off the native path: what the thresholds of D-1 and D-2 count.
TCP_KEYS = ("native_udp_from_client_tcp_route", "native_udp_to_client_tcp_route", "native_udp_route_to_tcp",
            "native_udp_route_stale_loss", "native_udp_route_stale_heard", "native_udp_to_client_tcp_failed",
            "native_udp_stream_drop_queue", "native_udp_stream_drop_age")
STREAM = ("n", "errors", "p50_ms", "p99_ms", "max_ms")
EXTRA = ("loss_pct", "p999_ms", "freezes", "longest_gap_ms", "breaks", "load_loss_pct", "load_p50_ms", "load_p99_ms",
         "load_max_ms", "clean_loss_pct", "clean_p50_ms", "clean_p99_ms", "clean_max_ms", "bulk_MBps", "bulk_errors", "wake_errors")


def _sum(rows, part, keys=TCP_KEYS):
    out = {}
    for r in rows:
        for k in keys:
            if r[part].get(k):
                out[k.removeprefix("native_udp_")] = out.get(k.removeprefix("native_udp_"), 0) + r[part][k]
    return out


def cell(path):
    run = read_json(os.path.join(path, "run.json"), {})
    res = (read_json(os.path.join(path, "result.json"), {}).get("result") or {})
    st = next(iter(res.values()), {})
    ex, marks = st.get("extra") or {}, st.get("marks") or {}
    t0 = run.get("measure_started", 0)
    out = {"status": run.get("status"), **{k: st.get(k) for k in STREAM}, **{k: round(ex[k], 3) for k in EXTRA if k in ex}}
    w = run.get("windows") or {}
    if w.get("load"):
        out["load"] = {"windows": len(w["load"]), "server": _sum(w["load"], "server"),
                       "server_first_s": _sum(w["load"], "server_first_s"), "server_before": _sum(w["load"], "server_before"),
                       "udp_up_packets": sum(x["leg"]["udp_up_packets"] for x in w["load"]),
                       "tcp_up_rest": sum(x["leg"].get("tcp_up_rest", 0) for x in w["load"])}
    if "bulk_drain_ms" in marks:
        out["drain_ms"] = [round(x) for x in marks["bulk_drain_ms"]]
    if "resume_at" in marks:
        out["resumes"] = []
        for i, at in enumerate(marks["resume_at"]):
            r = {"at_s": round(at - t0, 2), **{k.removeprefix("resume_").removesuffix("_ms"): round(marks[k][i], 1)
                                                for k in ("resume_first_echo_ms", "resume_gap_ms", "resume_lost_1s") if i < len(marks.get(k, []))}}
            ws = [x for x in w.get("resume", []) if abs(x["at"] - at) < 0.01]
            if ws:
                x = ws[0]
                r |= {"server": _sum([x], "server"), "tcp_up_packets": x["leg"]["tcp_up_busiest"],
                      "tcp_up_bytes": x["leg"]["tcp_up_busiest_bytes"], "udp_up_packets": x["leg"]["udp_up_packets"],
                      "steady_tcp_up_packets": x["leg_steady"]["tcp_up_busiest"], "steady_udp_up_packets": x["leg_steady"]["udp_up_packets"]}
            out["resumes"].append(r)
    if cn := run.get("client_native"):
        out["client"] = {"events": cn.get("events", {}), "stats": cn.get("stats", {}),
                         "event_at_s": {k: [round(t - t0, 2) for t in v if t] for k, v in cn.get("event_at", {}).items()}}
    if g := run.get("gauges_after"):
        out["server_total"] = {k.removeprefix("native_udp_"): v for k, v in g.items() if k in TCP_KEYS and v}
    if b := run.get("udp_blackout"):
        out["udp_blackout"] = b
    return out


def summarize(d):
    manifest, plan = read_json(os.path.join(d, "manifest.json"), {}), read_json(os.path.join(d, "plan.json"), {})
    batches = {k: {x: v.get(x) for x in ("foreign_cores", "noisy", "start", "finished", "seconds")} for k, v in manifest.get("batches", {}).items()}
    builds = {k: {x: v.get(x) for x in ("ref", "commit", "dirty")} for k, v in manifest.get("build", {}).items() if k != "matrix"}
    series = {}
    for path in sorted(glob.glob(os.path.join(d, "cells", "*", "*"))):
        name, cid = path.split(os.sep)[-2:]
        variant = cid.split("-obfs-")[0] if "-obfs-" in cid else cid.rsplit("-r", 1)[0]
        rnd = cid.rsplit("-r", 1)[1]
        series.setdefault(name, {}).setdefault(f"r{rnd}", {})[variant] = cell(path)
    for rounds in series.values():
        for cells in rounds.values():
            raw = cells.get("raw")
            if not raw:
                continue
            for v, c in cells.items():
                if v == "raw":
                    continue
                # The threshold compares under the same load: the direct cell of the same batch.
                c["vs_direct"] = {k: round(c[k] - raw[k], 3) for k in ("p99_ms", "load_p99_ms", "clean_p99_ms", "max_ms", "load_max_ms", "loss_pct", "load_loss_pct")
                                  if isinstance(c.get(k), (int, float)) and isinstance(raw.get(k), (int, float))}
                if c.get("resumes") and raw.get("resumes"):
                    c["vs_direct"]["first_echo"] = [round(a.get("first_echo", 0) - b.get("first_echo", 0), 1) for a, b in zip(c["resumes"], raw["resumes"])]
    return {"dir": os.path.basename(os.path.normpath(d)), "plan": plan.get("name"), "hash": plan.get("hash"),
            "networks": {s["name"]: s["network"] for s in plan.get("series", [])}, "builds": builds, "batches": batches, "series": series}


def main(argv):
    if not argv:
        sys.exit(__doc__)
    json.dump([summarize(d) for d in argv], sys.stdout, ensure_ascii=False, indent=1)
    print()


if __name__ == "__main__":
    main(sys.argv[1:])

#!/usr/bin/env python3
"""S5Core benchmark pipeline: raw vs versions of s5core/s5client, on one machine or across a WAN.

  matrix.py run PLAN [--out DIR] [--series a,b] [--dry-run]
  matrix.py resume DIR [--retry-failed]
  matrix.py status DIR
  matrix.py report DIR [--include-noisy]
  matrix.py recheck DIR [--rounds N]
  matrix.py stale DIR [--kill]
  matrix.py wan-clean DIR

See scripts/matrix/README.md.
"""

import argparse
import os
import shutil
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from pipeline import analysis, build, plan as planmod, report, run  # noqa: E402
from pipeline.util import read_json, write_json  # noqa: E402
from pipeline.wan import WanError  # noqa: E402


def cmd_run(a):
    p = planmod.load(a.plan)
    series = set(a.series.split(",")) if a.series else None
    if a.dry_run:
        os.makedirs(run.RUNS, exist_ok=True)
        out = tempfile.mkdtemp(prefix=".dry-", dir=run.RUNS)
        try:
            return run.Runner(p, out, only_series=series).run(dry=True)
        finally:
            shutil.rmtree(out, ignore_errors=True)
    out = a.out or os.path.join(run.RUNS, f"{p['name']}-{time.strftime('%Y%m%d-%H%M%S')}")
    rc = run.Runner(p, out, only_series=series).run()
    write_report(out)
    return rc


def cmd_resume(a):
    p = read_json(os.path.join(a.dir, "plan.json"))
    if not p:
        raise run.RunError(f"{a.dir}: no plan.json")
    rc = run.Runner(p, a.dir, retry_failed=a.retry_failed).run()
    write_report(a.dir)
    return rc


def write_report(out, include_noisy=False):
    rep = analysis.analyze(out, include_noisy)
    write_json(os.path.join(out, "analysis.json"), {k: v for k, v in rep.items() if k not in ("plan", "manifest")})
    with open(os.path.join(out, "report.html"), "w") as f:
        f.write(report.html_report(rep, out))
    with open(os.path.join(out, "summary.md"), "w") as f:
        f.write(report.markdown(rep))
    worse = sum(1 for s in rep["series"] for c in s["comparisons"] for r in c["rows"] if r["verdict"] == "хуже")
    print(f"report: {os.path.join(out, 'report.html')} ({len(rep['problems'])} problems, {worse} worse, {len(rep['flags'])} flags)")
    return rep


def cmd_report(a):
    write_report(a.dir, a.include_noisy)
    return 0


def cmd_recheck(a):
    rep = analysis.analyze(a.dir)
    text = report.recheck_toml(rep, a.rounds)
    if text is None:
        print("no flags: nothing to recheck")
        return 0
    path = os.path.join(a.dir, "recheck.toml")
    with open(path, "w") as f:
        f.write(text)
    planmod.load(path)
    print(f"{path}\nrun it: {sys.argv[0]} run {path}")
    return 0


def cmd_status(a):
    return run.status(a.dir)


def cmd_stale(a):
    found = run.stale(a.dir, a.kill)
    if not found:
        print("nothing left running from", os.path.join(a.dir, "bin"))
    return 0


def cmd_cell(a):
    from pipeline import cell
    cell.main(a.spec)


def cmd_wancell(a):
    from pipeline import wan
    wan.main(a.spec)


def cmd_wan_clean(a):
    from pipeline import wan
    p = read_json(os.path.join(a.dir, "plan.json"))
    if not p or not p.get("wan"):
        raise run.RunError(f"{a.dir}: not a WAN run")
    wan.Stage(p, a.dir, print).down()
    return 0


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("run", help="run a plan into a new directory")
    s.add_argument("plan")
    s.add_argument("--out", help="run directory (default bench/runs/<plan>-<time>)")
    s.add_argument("--series", help="comma-separated series to run")
    s.add_argument("--dry-run", action="store_true", help="validate, list cells and the time bound, run nothing")
    s.set_defaults(fn=cmd_run)
    s = sub.add_parser("resume", help="finish an interrupted run")
    s.add_argument("dir")
    s.add_argument("--retry-failed", action="store_true", help="also rerun batches with any cell not ok")
    s.set_defaults(fn=cmd_resume)
    s = sub.add_parser("status", help="progress of a run")
    s.add_argument("dir")
    s.set_defaults(fn=cmd_status)
    s = sub.add_parser("report", help="rebuild report.html, summary.md and analysis.json")
    s.add_argument("dir")
    s.add_argument("--include-noisy", action="store_true", help="compare rounds run on a loaded machine too")
    s.set_defaults(fn=cmd_report)
    s = sub.add_parser("recheck", help="write a plan that reruns the flagged scenarios on more rounds")
    s.add_argument("dir")
    s.add_argument("--rounds", type=int, default=10)
    s.set_defaults(fn=cmd_recheck)
    s = sub.add_parser("stale", help="list (or kill) processes left from this run's binaries")
    s.add_argument("dir")
    s.add_argument("--kill", action="store_true")
    s.set_defaults(fn=cmd_stale)
    s = sub.add_parser("wan-clean", help="stop the units and processes of a WAN run on its hosts and remove its directories")
    s.add_argument("dir")
    s.set_defaults(fn=cmd_wan_clean)
    s = sub.add_parser("cell", help=argparse.SUPPRESS)
    s.add_argument("spec")
    s.set_defaults(fn=cmd_cell)
    s = sub.add_parser("wancell", help=argparse.SUPPRESS)
    s.add_argument("spec")
    s.set_defaults(fn=cmd_wancell)
    a = ap.parse_args()
    try:
        sys.exit(a.fn(a) or 0)
    except (planmod.PlanError, run.RunError, build.BuildError, WanError) as e:
        sys.exit(f"error: {e}")


if __name__ == "__main__":
    main()

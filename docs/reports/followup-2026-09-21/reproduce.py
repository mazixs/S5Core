#!/usr/bin/env python3
"""Replay audit probes via Go overlays without changing production sources."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import tempfile

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
CASES = {
    "shutdown": ("tls_probe_test.go", "pkg/transport/tlsdecoy", "TestAuditShutdownWaitsBeyondWriteTimeout"),
    "store": ("store_probe_test.go", "internal/userstore", "TestAuditFlushLockCost"),
    "sessions": ("session_probe_test.go", "internal/session", "TestAuditScrapeLockCost"),
    "jitter": ("jitter_probe_test.go", "pkg/transport/ws", "TestAuditCloseDoesNotInterruptShapingJitter"),
    "profile": ("profile_sdk.go", "pkg/s5server", "TestObfsRelayProfile"),
}
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("case", choices=[*CASES, "all"], default="all", nargs="?")
args = parser.parse_args()
out = Path(tempfile.mkdtemp(prefix="s5core-followup-"))
print(f"Artifacts: {out}", flush=True)
for name in CASES if args.case == "all" else [args.case]:
    fixture, package, test = CASES[name]
    source = (HERE / (fixture + ".txt")).read_text()
    source = source.replace("/tmp/s5core-followup-20260921", str(out))
    replacement = out / fixture
    replacement.write_text(source)
    target = "profile_load_test.go" if name == "profile" else "followup_audit_test.go"
    overlay = out / (name + ".json")
    overlay.write_text(json.dumps({"Replace": {str(ROOT / package / target): str(replacement)}}))
    cmd = ["go", "test", f"-overlay={overlay}", "-count=1", "-timeout=90s", "-v", "-run", f"^{test}$"]
    if name == "profile":
        cmd += ["-tags=loadtest"]
    cmd += ["./" + package]
    env = dict(os.environ, PROFILE_CONNS="4", PROFILE_MB="2048")
    result = subprocess.run(cmd, cwd=ROOT, env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    (out / (name + ".txt")).write_text(result.stdout)
    print(result.stdout, end="", flush=True)
    result.check_returncode()
    if name == "profile":
        with (out / "cpu-top.txt").open("w") as report:
            subprocess.run(["go", "tool", "pprof", "-top", str(out / "profile-sdk/obfs-relay.cpu")], cwd=ROOT, stdout=report, check=True)

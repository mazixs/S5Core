#!/usr/bin/env python3
"""Локальное воспроизведение аудита без изменения исходников Go."""

import argparse
import json
from pathlib import Path
import shutil
import subprocess
import tempfile


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("mode", choices=["probes", "telemetry", "compare", "client-loop"])
parser.add_argument("--race", action="store_true")
args = parser.parse_args()
out = Path(tempfile.mkdtemp(prefix="s5core-audit-"))
print(f"Результаты: {out}", flush=True)


def run(command, cwd=ROOT, name="result.txt"):
    result = subprocess.run(command, cwd=cwd, text=True, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, check=False)
    (out / name).write_text(result.stdout)
    print(result.stdout, end="", flush=True)
    result.check_returncode()


def overlay(root, files, name):
    path = out / name
    path.write_text(json.dumps({"Replace": {
        str(root / target): str(HERE / source) for target, source in files.items()
    }}))
    return str(path)


if args.mode in ("probes", "telemetry"):
    mapping = {
        "pkg/veil/audit_probe_test.go": "veil_test.go.txt",
        "pkg/transport/ws/audit_probe_test.go": "ws_test.go.txt",
        "cmd/wirebench/audit_probe_test.go": "wirebench_test.go.txt",
        "internal/socks5/audit_probe_test.go": "udp_test.go.txt",
        "pkg/s5server/audit_probe_test.go": "telemetry_test.go.txt",
    }
    ov = overlay(ROOT, mapping, "overlay.json")
    command = ["go", "test", "-overlay", ov]
    if args.race:
        command.append("-race")
    if args.mode == "probes":
        command += ["-run", "^TestAudit", "-count=1", "-v", "-timeout=60s",
                    "./pkg/veil", "./pkg/transport/ws", "./cmd/wirebench", "./internal/socks5"]
    else:
        command += ["-run", "^$", "-bench", "^BenchmarkAuditFrameObserver$",
                    "-count=6", "-benchtime=200ms", "./pkg/s5server"]
    run(command)
elif args.mode == "compare":
    before = out / "before"
    before.mkdir()
    archive = out / "before.tar"
    subprocess.run(["git", "archive", "-o", str(archive), "c4a41f0"], cwd=ROOT, check=True)
    subprocess.run(["tar", "-xf", str(archive), "-C", str(before)], check=True)
    for name, root in [("current", ROOT), ("before", before)]:
        ov = overlay(root, {"pkg/obfs/audit_roundtrip_test.go":
                           f"{name}_roundtrip_test.go.txt"}, f"{name}.json")
        run(["go", "test", "-overlay", ov, "-run", "^$", "-bench",
             "^BenchmarkAuditMatchedRoundTrip$", "-count=6", "-benchtime=200ms",
             "./pkg/obfs"], cwd=root, name=f"{name}.txt")
    benchstat = shutil.which("benchstat")
    if not benchstat:
        gopath = subprocess.check_output(["go", "env", "GOPATH"], cwd=ROOT, text=True).strip()
        candidate = Path(gopath) / "bin" / "benchstat"
        if candidate.is_file():
            benchstat = str(candidate)
    if benchstat:
        run([benchstat, str(out / "before.txt"), str(out / "current.txt")], name="benchstat.txt")
    else:
        print("benchstat не найден; исходные замеры сохранены.")
else:
    run(["go", "build", "-o", str(out / "s5client"), "./cmd/s5client"], name="build.txt")
    shutil.copyfile(HERE / "client_accept_probe.py", out / "client_accept_probe.py")
    run(["python3", str(out / "client_accept_probe.py")], name="client-loop.txt")

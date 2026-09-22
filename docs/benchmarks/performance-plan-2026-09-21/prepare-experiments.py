#!/usr/bin/env python3
"""Prepare an isolated copy and Go overlays; never change the source checkout."""

import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("destination", type=Path, help="New, nonexistent directory outside the repository")
    args = parser.parse_args()
    evidence = Path(__file__).resolve().parent
    repository = evidence.parents[2]
    destination = args.destination.resolve()
    if destination == repository or repository in destination.parents:
        parser.error("destination must be outside the repository")
    destination.mkdir(parents=True, exist_ok=False)
    snapshot = destination / "repo"
    snapshot.mkdir()
    names = subprocess.check_output(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
        cwd=repository,
    ).decode().split("\0")
    hashes = {}
    for name in sorted(set(filter(None, names))):
        source = repository / name
        if not source.is_file():
            continue
        target = snapshot / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)
        hashes[name] = hashlib.sha256(source.read_bytes()).hexdigest()
    (destination / "input-hashes.json").write_text(json.dumps(hashes, indent=2) + "\n")

    fixtures = {
        "https_measurements_test.go.txt": "cmd/s5client/perf_https_test.go",
        "read_granularity_test.go.txt": "pkg/obfs/perf_read_test.go",
        "ws_buffer_test.go.txt": "pkg/transport/ws/perf_buffer_test.go",
    }
    for source, target in fixtures.items():
        output = snapshot / target
        if output.exists():
            raise RuntimeError(f"fixture would replace an existing file: {output}")
        shutil.copy2(evidence / source, output)

    variants = [
        ("coalesce", "pkg/obfs/conn.go", "read-coalescing.patch"),
        ("ws-buffer", "pkg/transport/ws/upgrader.go", "ws-buffer.patch"),
    ]
    for name, source, patch in variants:
        replacement = destination / f"{name}.go"
        subprocess.run(
            ["patch", "--batch", "--forward", "--fuzz=0", "--output", str(replacement),
             str(snapshot / source), str(evidence / patch)],
            check=True,
        )
        overlay = {"Replace": {str(snapshot / source): str(replacement)}}
        (destination / f"{name}.json").write_text(json.dumps(overlay, indent=2) + "\n")
    print(f"Snapshot: {snapshot}")
    print("Prepared only; benchmarks have not been run.")


if __name__ == "__main__":
    main()

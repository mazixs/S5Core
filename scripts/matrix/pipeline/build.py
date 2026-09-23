"""Builds each variant once per run directory; a resumed run reuses the binaries."""

import os
import platform
import shutil
import subprocess
import tarfile
import tempfile

from .util import REPO, ROOT, now, read_json, sha256, write_json

BUILD_TIMEOUT = 900
GOFLAGS = ["-trimpath", "-pgo=off"]


HOST_ARCH = {"x86_64": "amd64", "aarch64": "arm64", "armv7l": "arm", "i686": "386"}.get(platform.machine(), platform.machine())


class BuildError(Exception):
    pass


def arch_path(bindir, variant, name, arch):
    """Where a binary for arch lives: the host's next to the variant, others in linux-<arch>/."""
    base = os.path.join(bindir, variant) if variant else bindir
    return os.path.join(base, name) if arch == HOST_ARCH else os.path.join(base, f"linux-{arch}", name)


def targets(plan):
    """{binary: arches} this plan needs: the host's always (cells, -list), and the WAN hosts'."""
    need = {"matrix": {HOST_ARCH}, "s5core": {HOST_ARCH}, "s5client": {HOST_ARCH}}
    w = plan.get("wan")
    if w and any(s["network"] == "wan" for s in plan.get("series", [])):
        need["matrix"] |= {w["server_arch"], w["client_arch"]}
        need["s5core"].add(w["server_arch"])
        need["s5client"].add(w["client_arch"])
    return need


def _run(cmd, cwd, log, timeout=BUILD_TIMEOUT, env=None, stdin=None):
    log.write(f"$ {' '.join(cmd)}  (in {cwd})\n")
    log.flush()
    try:
        r = subprocess.run(cmd, cwd=cwd, stdout=log, stderr=subprocess.STDOUT, timeout=timeout, env=env, stdin=stdin)
    except subprocess.TimeoutExpired:
        raise BuildError(f"{' '.join(cmd[:3])}: no result within {timeout}s") from None
    if r.returncode != 0:
        raise BuildError(f"{' '.join(cmd[:3])}: exit {r.returncode}, see {log.name}")


def _git(*args):
    return subprocess.run(["git", "-C", REPO, *args], capture_output=True, text=True, timeout=60, check=True).stdout.strip()


def _source(variant, dest, log):
    """A tree to build variant from: the working tree itself when nothing has to change."""
    ref, patch = variant["ref"], variant["patch"]
    if ref == "worktree" and not patch:
        return REPO, {"ref": "worktree", "commit": _git("rev-parse", "HEAD"), "dirty": _git("status", "--porcelain", "--untracked-files=no") != ""}
    os.makedirs(dest, exist_ok=True)
    if ref == "worktree":
        files = subprocess.run(["git", "-C", REPO, "ls-files", "-co", "--exclude-standard", "-z"], capture_output=True, timeout=60, check=True).stdout
        for rel in filter(None, files.decode().split("\0")):
            src = os.path.join(REPO, rel)
            if not os.path.isfile(src):
                continue
            os.makedirs(os.path.dirname(os.path.join(dest, rel)), exist_ok=True)
            shutil.copy2(src, os.path.join(dest, rel))
        info = {"ref": "worktree", "commit": _git("rev-parse", "HEAD"), "dirty": True}
    else:
        commit = _git("rev-parse", f"{ref}^{{commit}}")
        with tempfile.TemporaryFile() as tar:
            log.write(f"$ git archive {commit} | tar -x -C {dest}\n")
            log.flush()
            r = subprocess.run(["git", "-C", REPO, "archive", "--format=tar", commit], stdout=tar, stderr=log, timeout=BUILD_TIMEOUT)
            if r.returncode != 0:
                raise BuildError(f"git archive {ref}: exit {r.returncode}")
            tar.seek(0)
            with tarfile.open(fileobj=tar) as t:
                t.extractall(dest, filter="data")
        info = {"ref": ref, "commit": commit, "dirty": False}
    if patch:
        _run(["git", "apply", "--verbose", patch], dest, log, timeout=60)
        info["patch"] = os.path.basename(patch)
        info["patch_sha256"] = sha256(patch)
    return dest, info


def build_all(plan, out, emit):
    """Builds the generator and every variant with a ref into out/bin."""
    bindir = os.path.join(out, "bin")
    os.makedirs(bindir, exist_ok=True)
    manifest = read_json(os.path.join(bindir, "build.json"), {})
    need = targets(plan)
    env = dict(os.environ, CGO_ENABLED="0", GOOS="linux")

    def go_build(dst, pkg, cwd, arch):
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        _run(["go", "build", *GOFLAGS, "-o", dst, pkg], cwd, log, env=env | {"GOARCH": arch})

    def key(b, arch):
        return b + ("" if arch == HOST_ARCH else f"_linux_{arch}") + "_sha256"

    with open(os.path.join(out, "build.log"), "a") as log:
        info = manifest.setdefault("matrix", {})
        for arch in sorted(need["matrix"]):
            gen = arch_path(bindir, None, "matrix", arch)
            if os.path.isfile(gen) and key("matrix", arch) in info:
                continue
            emit(f"build generator ({arch})")
            go_build(gen, ".", ROOT, arch)
            info[key("matrix", arch)] = sha256(gen)
            info["sha256"] = info.get(key("matrix", HOST_ARCH), "")
            info["built"] = now()
        for name, v in plan["variants"].items():
            if v["direct"]:
                continue
            want = [(b, arch) for b in ("s5core", "s5client") for arch in sorted(need[b])]
            if name in manifest and all(os.path.isfile(arch_path(bindir, name, b, a)) and key(b, a) in manifest[name] for b, a in want):
                continue
            emit(f"build {name} ({v['ref']}{', ' + os.path.basename(v['patch']) if v['patch'] else ''})")
            src, info = _source(v, os.path.join(out, "src", name), log)
            for b, arch in want:
                dst = arch_path(bindir, name, b, arch)
                go_build(dst, f"./cmd/{b}", src, arch)
                info[key(b, arch)] = sha256(dst)
            info["built"] = now()
            manifest[name] = info
            if src != REPO:
                shutil.rmtree(src, ignore_errors=True)
            write_json(os.path.join(bindir, "build.json"), manifest)
    write_json(os.path.join(bindir, "build.json"), manifest)
    return manifest


def scenarios(gen, only):
    """The scenario names the generator runs for this -only filter."""
    args = [gen, "-list"]
    if only:
        args += ["-only", ",".join(only)]
    r = subprocess.run(args, capture_output=True, text=True, timeout=30)
    if r.returncode != 0:
        raise BuildError(f"matrix -list: exit {r.returncode}: {r.stderr.strip()}")
    return [s for s in r.stdout.split() if s]

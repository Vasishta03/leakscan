"""Reproducible benchmark: leakscan vs gitleaks vs trufflehog.

usage:
    python benchmarks/run.py --gitleaks /path/to/gitleaks --trufflehog /path/to/trufflehog

What it measures, on pinned public repos:
  * filesystem scan wall time (median of N runs) and peak RSS
  * git history scan wall time and peak RSS
  * findings reported on real code (a rough noise signal, not a precision score)
  * recall on a planted corpus: one synthetic secret per leakscan rule, embedded in
    real source files. This corpus is built from leakscan's own rule fixtures, so it
    favours leakscan by construction; read it as "coverage of these formats", not as
    a neutral accuracy score.

Verification is disabled for every tool (no network calls to providers).
"""
from __future__ import annotations

import argparse
import json
import os
import platform
import shutil
import statistics
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent
WORK = ROOT / "work"
REPOS = {
    "requests": ("https://github.com/psf/requests.git", "v2.32.3"),
    "django": ("https://github.com/django/django.git", "5.1"),
}
HISTORY_REPO = "requests"

_RSS = """
import resource, subprocess, sys, time
t = time.perf_counter()
p = subprocess.run(sys.argv[1:], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
dt = time.perf_counter() - t
rss = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss
print(dt, rss * (1 if sys.platform == "darwin" else 1024), p.returncode)
"""


def sh(*cmd: str, cwd: Path | None = None) -> str:
    return subprocess.run(cmd, cwd=cwd, check=True, capture_output=True, text=True).stdout


def fetch(name: str, full: bool) -> Path:
    url, ref = REPOS[name]
    dest = WORK / (name + ("-full" if full else ""))
    if not dest.exists():
        args = ["git", "clone", "--quiet", "--branch", ref, url, str(dest)]
        if not full:
            args[2:2] = ["--depth", "1"]
        sh(*args)
    return dest


def measure(cmd: list[str], runs: int) -> dict:
    times, rss = [], []
    for _ in range(runs):
        out = subprocess.run([sys.executable, "-c", _RSS, *cmd], capture_output=True, text=True, check=True).stdout.split()
        times.append(float(out[0]))
        rss.append(int(out[1]))
    return {"median_s": round(statistics.median(times), 2), "min_s": round(min(times), 2),
            "peak_rss_mb": round(max(rss) / 1e6, 1)}


def count_findings(tool: str, path: Path) -> int:
    if not path.exists() or path.stat().st_size == 0:
        return 0
    text = path.read_text(encoding="utf-8", errors="replace")
    if tool == "leakscan":
        return len(json.loads(text)["findings"])
    if tool == "gitleaks":
        return len(json.loads(text) or [])
    return sum(1 for line in text.splitlines() if line.strip().startswith("{"))


def commands(tool: str, binary: str, target: Path, out: Path, history: bool) -> list[str]:
    if tool == "leakscan":
        cmd = [binary, "scan", str(target), "--no-progress", "--no-blame", "--format", "json", "-o", str(out), "--exit-zero"]
        if history:
            cmd = [binary, "scan", str(target), "--history", "--depth", "1000000", "--no-progress", "--no-blame",
                   "--format", "json", "-o", str(out), "--exit-zero"]
        return cmd
    if tool == "gitleaks":
        sub = ["git", str(target)] if history else ["dir", str(target)]
        return [binary, *sub, "--no-banner", "--exit-code", "0", "--report-format", "json", "--report-path", str(out)]
    sub = ["git", f"file://{target}"] if history else ["filesystem", str(target)]
    return ["sh", "-c", f"{binary} {' '.join(sub)} --json --no-verification --no-update > {out}"]


def build_corpus(dest: Path, source: Path) -> int:
    sys.path.insert(0, str(ROOT.parent))
    from tests.corpus import CORPUS

    if dest.exists():
        shutil.rmtree(dest)
    dest.mkdir(parents=True)
    code = [p for p in sorted(source.rglob("*.py")) if p.stat().st_size < 50_000][:60]
    planted = 0
    for i, (_rule_id, (positive, _neg, path)) in enumerate(sorted(CORPUS.items())):
        host = code[i % len(code)].read_text(encoding="utf-8", errors="replace").splitlines()
        target = dest / (path or f"src/module_{i:03d}.py")
        target.parent.mkdir(parents=True, exist_ok=True)
        mid = len(host) // 2
        target.write_text("\n".join(host[:mid] + [positive] + host[mid:]) + "\n", encoding="utf-8")
        planted += 1
    return planted


def corpus_recall(tool: str, report: Path, planted_dir: Path) -> int:
    text = report.read_text(encoding="utf-8", errors="replace") if report.exists() else ""
    files: set[str] = set()
    if tool == "leakscan":
        files = {f["file"] for f in json.loads(text)["findings"] if f["rule_id"] != "LS-ENTROPY-001"}
    elif tool == "gitleaks":
        files = {str(Path(f["File"]).relative_to(planted_dir)) for f in json.loads(text or "[]")}
    else:
        for line in text.splitlines():
            if line.startswith("{"):
                meta = json.loads(line).get("SourceMetadata", {}).get("Data", {}).get("Filesystem", {})
                if meta.get("file"):
                    files.add(str(Path(meta["file"]).resolve().relative_to(planted_dir.resolve())))
    return len({f.replace("\\", "/") for f in files})


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--leakscan", default=shutil.which("leakscan") or "leakscan")
    ap.add_argument("--gitleaks", default=shutil.which("gitleaks"))
    ap.add_argument("--trufflehog", default=shutil.which("trufflehog"))
    ap.add_argument("--runs", type=int, default=3)
    args = ap.parse_args()
    WORK.mkdir(exist_ok=True)

    tools = {"leakscan": args.leakscan, "gitleaks": args.gitleaks, "trufflehog": args.trufflehog}
    tools = {k: v for k, v in tools.items() if v}
    versions = {}
    for name, binary in tools.items():
        flag = "version" if name == "gitleaks" else "--version"
        res = subprocess.run([binary, flag], capture_output=True, text=True)
        versions[name] = (res.stdout or res.stderr).strip().splitlines()[-1]

    results: dict = {"machine": {"os": platform.platform(), "cpus": os.cpu_count(), "python": platform.python_version()},
                     "versions": versions, "repos": {k: f"{u}@{r}" for k, (u, r) in REPOS.items()}, "fs": {}, "history": {}}

    for repo in REPOS:
        target = fetch(repo, full=False)
        files = sum(1 for p in target.rglob("*") if p.is_file() and ".git" not in p.parts)
        results["fs"][repo] = {"files": files}
        for tool, binary in tools.items():
            out = WORK / f"{tool}-{repo}.json"
            m = measure(commands(tool, binary, target, out, history=False), args.runs)
            m["findings"] = count_findings(tool, out)
            results["fs"][repo][tool] = m
            print(f"fs {repo:9} {tool:10} {m}", flush=True)

    target = fetch(HISTORY_REPO, full=True)
    results["history"]["commits"] = int(sh("git", "rev-list", "--count", "HEAD", cwd=target).strip())
    for tool, binary in tools.items():
        out = WORK / f"{tool}-history.json"
        m = measure(commands(tool, binary, target, out, history=True), max(1, args.runs - 1))
        m["findings"] = count_findings(tool, out)
        results["history"][tool] = m
        print(f"history   {tool:10} {m}", flush=True)

    planted_dir = WORK / "planted"
    planted = build_corpus(planted_dir, fetch("requests", full=False))
    results["recall"] = {"planted": planted}
    for tool, binary in tools.items():
        out = WORK / f"{tool}-planted.json"
        subprocess.run(commands(tool, binary, planted_dir, out, history=False), capture_output=True)
        results["recall"][tool] = corpus_recall(tool, out, planted_dir)
        print(f"recall    {tool:10} {results['recall'][tool]}/{planted}", flush=True)

    (ROOT / "results.json").write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8")
    print(f"\nwrote {ROOT / 'results.json'} at {time.strftime('%Y-%m-%d')}")


if __name__ == "__main__":
    main()

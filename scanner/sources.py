"""Scan targets beyond the local filesystem: git remotes, GitHub orgs,
Docker images, PyPI/npm packages, stdin and followed files."""
from __future__ import annotations

import fnmatch
import io
import json
import os
import re
import shutil
import subprocess
import tarfile
import tempfile
import time
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterator, Optional

import requests

from scanner import __version__
from scanner.engine import Finding, ScanOptions, ScanResult, scan_bytes, scan_git_history, scan_lines, scan_path

UA = {"User-Agent": f"leakscan/{__version__}"}
_REMOTE_RE = re.compile(
    r"^(?:https?://|git@|ssh://)(?:[^@/]+@)?(github\.com|gitlab\.com|bitbucket\.org|[\w.-]+)[/:]"
    r"([\w.\-/]+?)(?:\.git)?/?$"
)
_DOCKER_RE = re.compile(r"^docker://(.+)$")
_PKG_RE = re.compile(r"^(pypi|npm):(.+)$")


def is_remote_url(target: str) -> bool:
    return bool(_REMOTE_RE.match(target.strip())) and not target.startswith(("docker://", "pypi:", "npm:"))


def is_docker(target: str) -> bool:
    return bool(_DOCKER_RE.match(target))


def is_package(target: str) -> bool:
    return bool(_PKG_RE.match(target))


def scan_text(text: str, opts: ScanOptions, label: str = "<stdin>") -> ScanResult:
    result = ScanResult()
    result.findings = scan_lines(text.splitlines(), label, opts)
    result.files_scanned = 1
    return result


def follow(path: Path, opts: ScanOptions, on_finding: Callable[[Finding], None],
           from_start: bool = False, poll: float = 0.5, stop: Optional[Callable[[], bool]] = None) -> ScanResult:
    """tail -f a file (or '-' for stdin) and report findings as lines arrive."""
    result = ScanResult()
    rules = opts.rules()
    from scanner.engine import check_line

    def _handle(n: int, line: str, label: str) -> None:
        for f in check_line(line.rstrip("\r\n"), n, label, opts, rules):
            result.findings.append(f)
            on_finding(f)

    if str(path) == "-":
        import sys
        for n, line in enumerate(sys.stdin, start=1):
            _handle(n, line, "<stdin>")
        return result

    n = 0
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        if not from_start:
            n = sum(1 for _ in f)
        buf = ""
        while not (stop and stop()):
            chunk = f.readline()
            if not chunk:
                time.sleep(poll)
                continue
            buf += chunk
            if not buf.endswith("\n"):
                continue
            n += 1
            _handle(n, buf, str(path))
            buf = ""
    result.files_scanned = 1
    return result


@contextmanager
def _tempdir(prefix: str) -> Iterator[Path]:
    d = Path(tempfile.mkdtemp(prefix=prefix))
    try:
        yield d
    finally:
        shutil.rmtree(d, ignore_errors=True)


def _normalize_remote(url: str) -> str:
    url = url.strip()
    if url.startswith(("github.com/", "gitlab.com/", "bitbucket.org/")):
        url = "https://" + url
    return url


def clone(url: str, dest: Path, depth: Optional[int] = 1, branch: Optional[str] = None,
          token: Optional[str] = None) -> None:
    url = _normalize_remote(url)
    cmd = ["git", "clone", "--quiet", "--no-tags", "--single-branch"]
    if depth:
        cmd += ["--depth", str(depth)]
    if branch:
        cmd += ["--branch", branch]
    env = dict(os.environ, GIT_TERMINAL_PROMPT="0")
    if token and url.startswith("https://"):
        cmd = ["git", "-c", f"http.extraHeader=Authorization: Basic {_basic(token)}"] + cmd[1:]
    cmd += [url, str(dest)]
    proc = subprocess.run(cmd, capture_output=True, text=True, env=env, timeout=900)
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.strip() or f"git clone failed for {url}")


def _basic(token: str) -> str:
    import base64
    return base64.b64encode(f"x-access-token:{token}".encode()).decode()


def scan_remote(url: str, opts: ScanOptions, history: bool = False, depth: int = 100,
                clone_depth: Optional[int] = None, branch: Optional[str] = None, token: Optional[str] = None,
                label_prefix: str = "", threads: Optional[int] = None) -> ScanResult:
    """Shallow-clone a git remote into a temp dir and scan it."""
    if clone_depth is None:
        clone_depth = (depth + 1) if history else 1
    with _tempdir("leakscan-") as d:
        repo = d / "repo"
        clone(url, repo, depth=clone_depth or None, branch=branch, token=token)
        result = scan_path(repo, options=opts, threads=threads)
        if history:
            result.merge(scan_git_history(repo, depth=depth, options=opts))
    if label_prefix:
        for f in result.findings:
            f.file = f"{label_prefix}/{f.file}"
    for f in result.findings:
        f.extra.setdefault("repository", _normalize_remote(url))
    return result


@dataclass
class OrgScanSettings:
    include_forks: bool = False
    include_archived: bool = False
    include: tuple[str, ...] = ()
    exclude: tuple[str, ...] = ()
    resume_file: Optional[Path] = None
    history: bool = False
    depth: int = 100


def list_org_repos(org: str, token: Optional[str], settings: OrgScanSettings) -> list[dict]:
    session = requests.Session()
    session.headers.update({"Accept": "application/vnd.github+json", **UA})
    if token:
        session.headers["Authorization"] = f"Bearer {token}"
    for kind, typ in (("orgs", "all"), ("users", "owner")):
        repos: list[dict] = []
        page = 1
        while True:
            r = session.get(f"https://api.github.com/{kind}/{org}/repos",
                            params={"per_page": "100", "page": str(page), "type": typ}, timeout=20)
            if r.status_code == 404 and kind == "orgs":
                break
            r.raise_for_status()
            data = r.json()
            repos.extend(data)
            if len(data) < 100:
                return _filter_repos(repos, settings)
            page += 1
    return []


def _filter_repos(repos: list[dict], s: OrgScanSettings) -> list[dict]:
    out = []
    for r in repos:
        if r.get("fork") and not s.include_forks:
            continue
        if r.get("archived") and not s.include_archived:
            continue
        name = r.get("name", "")
        if s.include and not any(fnmatch.fnmatch(name, g) for g in s.include):
            continue
        if any(fnmatch.fnmatch(name, g) for g in s.exclude):
            continue
        out.append(r)
    return out


def _load_state(path: Optional[Path]) -> dict:
    if path and path.is_file():
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except ValueError:
            pass
    return {"done": [], "findings": []}


def _save_state(path: Optional[Path], state: dict) -> None:
    if path:
        tmp = path.with_name(path.name + ".tmp")
        tmp.write_text(json.dumps(state, indent=1), encoding="utf-8")
        os.replace(tmp, path)


def scan_github_org(org: str, opts: ScanOptions, token: Optional[str], settings: OrgScanSettings,
                    on_repo: Optional[Callable[[str, int, int], None]] = None) -> ScanResult:
    """Shallow-clone and scan every matching repo. With a resume file, completed repos
    are skipped on re-run. The state file stores redacted findings only."""
    from scanner.reporter import _redact

    repos = list_org_repos(org, token, settings)
    state = _load_state(settings.resume_file)
    done = set(state.get("done", []))
    result = ScanResult()
    for saved in state.get("findings", []):
        result.findings.append(Finding(**{k: v for k, v in saved.items() if k != "blame"}))
    for i, repo in enumerate(repos, start=1):
        full = repo["full_name"]
        if on_repo:
            on_repo(full, i, len(repos))
        if full in done:
            continue
        try:
            sub = scan_remote(repo["clone_url"], opts, history=settings.history, depth=settings.depth,
                              token=token, label_prefix=full)
            result.merge(sub)
            for f in sub.findings:
                state["findings"].append({
                    "file": f.file, "line_number": f.line_number, "line": "", "secret_type": f.secret_type,
                    "severity": f.severity, "matched_value": _redact(f.matched_value), "source": f.source,
                    "commit": f.commit, "rule_id": f.rule_id, "confidence": f.confidence,
                })
        except Exception as e:
            result.errors.append(f"{full}: {e}")
        state["done"].append(full)
        _save_state(settings.resume_file, state)
    return result


def _docker(*args: str, timeout: int = 900) -> subprocess.CompletedProcess:
    if not shutil.which("docker"):
        raise RuntimeError("docker is not installed or not on PATH")
    return subprocess.run(["docker", *args], capture_output=True, timeout=timeout)


def scan_docker_image(ref: str, opts: ScanOptions, pull: bool = True) -> ScanResult:
    """`docker save` an image and scan its config (ENV, build history) and every layer."""
    image = _DOCKER_RE.match(ref).group(1) if ref.startswith("docker://") else ref  # type: ignore[union-attr]
    if _docker("image", "inspect", image).returncode != 0:
        if not pull:
            raise RuntimeError(f"image {image} not found locally")
        p = _docker("pull", image)
        if p.returncode != 0:
            raise RuntimeError(p.stderr.decode(errors="replace").strip())
    layer_opts = ScanOptions(**{**opts.__dict__, "archives": True})
    result = ScanResult()
    with _tempdir("leakscan-img-") as d:
        tar_path = d / "image.tar"
        p = _docker("save", "-o", str(tar_path), image)
        if p.returncode != 0:
            raise RuntimeError(p.stderr.decode(errors="replace").strip())
        with tarfile.open(tar_path) as outer:
            manifest = json.load(outer.extractfile("manifest.json"))[0]  # type: ignore[arg-type]
            config = json.load(outer.extractfile(manifest["Config"]))  # type: ignore[arg-type]
            cfg = config.get("config") or {}
            env_lines = list(cfg.get("Env") or [])
            hist = [h.get("created_by", "") for h in config.get("history") or []]
            label = f"docker://{image}"
            result.findings += scan_lines(env_lines, f"{label}:config/Env", opts, extra={"layer": "config"})
            result.findings += scan_lines(hist, f"{label}:history", opts, extra={"layer": "history"})
            for idx, layer in enumerate(manifest.get("Layers") or []):
                member = outer.extractfile(layer)
                if member is None:
                    continue
                data = member.read()
                sub = _scan_layer(data, f"{label}@layer{idx}", layer_opts)
                for f in sub.findings:
                    f.extra.update({"layer": idx, "layer_digest": layer.split("/")[-1].replace(".tar", "")})
                result.merge(sub)
    return result


def _scan_layer(data: bytes, label: str, opts: ScanOptions) -> ScanResult:
    result = ScanResult()
    try:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as tf:
            for m in tf:
                if not m.isfile() or "/.wh." in f"/{m.name}" or m.size > 50_000_000:
                    continue
                f = tf.extractfile(m)
                if f is None:
                    continue
                result.merge(scan_bytes(f.read(), f"{label}:{m.name}", opts, depth=1))
    except tarfile.TarError as e:
        result.errors.append(f"{label}: {e}")
    return result


def _download(url: str, dest: Path, limit: int = 200_000_000) -> None:
    with requests.get(url, headers=UA, stream=True, timeout=60) as r:
        r.raise_for_status()
        size = 0
        with open(dest, "wb") as out:
            for chunk in r.iter_content(1 << 16):
                size += len(chunk)
                if size > limit:
                    raise RuntimeError("package exceeds download size limit")
                out.write(chunk)


def resolve_package(spec: str) -> tuple[str, str]:
    """Return (download_url, filename) for 'pypi:name[==ver]' or 'npm:name[@ver]'."""
    kind, rest = _PKG_RE.match(spec).groups()  # type: ignore[union-attr]
    if kind == "pypi":
        name, _, version = rest.partition("==")
        url = f"https://pypi.org/pypi/{name}/{version}/json" if version else f"https://pypi.org/pypi/{name}/json"
        data = requests.get(url, headers=UA, timeout=30)
        data.raise_for_status()
        files = data.json()["urls"]
        pick = next((f for f in files if f["packagetype"] == "sdist"), None) or (files[0] if files else None)
        if not pick:
            raise RuntimeError(f"no downloadable files for {spec}")
        return pick["url"], pick["filename"]
    at = rest.rfind("@")
    name, version = (rest[:at], rest[at + 1:]) if at > 0 else (rest, "latest")
    meta = requests.get(f"https://registry.npmjs.org/{name}/{version}", headers=UA, timeout=30)
    meta.raise_for_status()
    tarball = meta.json()["dist"]["tarball"]
    return tarball, tarball.rsplit("/", 1)[-1]


def scan_package(spec: str, opts: ScanOptions) -> ScanResult:
    from scanner import archives

    url, filename = resolve_package(spec)
    pkg_opts = ScanOptions(**{**opts.__dict__, "archives": True})
    with _tempdir("leakscan-pkg-") as d:
        dest = d / filename
        _download(url, dest)
        result = archives.scan_archive_path(dest, f"{spec}!{filename}", pkg_opts)
    return result


def pr_diff_args(base: Optional[str] = None) -> list[str]:
    """Figure out the diff range for the current pull/merge request."""
    base = base or os.environ.get("GITHUB_BASE_REF") or os.environ.get("CI_MERGE_REQUEST_TARGET_BRANCH_NAME") \
        or os.environ.get("BITBUCKET_PR_DESTINATION_BRANCH") or os.environ.get("CHANGE_TARGET")
    if not base:
        raise RuntimeError("--pr needs GITHUB_BASE_REF (or GitLab/Bitbucket/Jenkins equivalent), or use --base BRANCH")
    ref = base if base.startswith(("origin/", "refs/")) else f"origin/{base}"
    return [f"{ref}...HEAD"]

"""Python API for leakscan.

    import leakscan

    result = leakscan.scan_path("src/")
    for f in result.findings:
        print(f.rule_id, f.file, f.line_number)

    leakscan.scan_text("token = ghp_...")
    leakscan.scan_git(".", max_commits=500)

Everything exported here is covered by semver from 1.0 onward.
"""
from __future__ import annotations

from pathlib import Path
from typing import Iterable, Optional, Union

from scanner import __version__
from scanner.engine import Finding, ScanOptions, ScanResult
from scanner.engine import scan_diff as _scan_diff
from scanner.engine import scan_git_history as _scan_git_history
from scanner.engine import scan_path as _scan_path
from scanner.patterns import PATTERNS, Pattern

__all__ = [
    "Finding", "ScanOptions", "ScanResult", "Pattern", "rules",
    "scan_path", "scan_text", "scan_git", "scan_diff", "to_json", "to_sarif", "__version__",
]

PathLike = Union[str, Path]


def _options(options: Optional[ScanOptions], disable: Iterable[str], entropy: bool) -> ScanOptions:
    opts = options or ScanOptions(no_entropy=not entropy)
    opts.disable_rules |= set(disable)
    return opts


def rules() -> list[Pattern]:
    """Every built-in rule, in evaluation order."""
    return list(PATTERNS)


def scan_path(path: PathLike, *, options: Optional[ScanOptions] = None, disable: Iterable[str] = (),
              entropy: bool = True, threads: Optional[int] = None, archives: bool = False) -> ScanResult:
    """Scan a file or directory. Finding.file is relative to `path`."""
    opts = _options(options, disable, entropy)
    opts.archives = opts.archives or archives
    return _scan_path(Path(path), options=opts, threads=threads)


def scan_text(text: str, *, filename: str = "<text>", options: Optional[ScanOptions] = None,
              disable: Iterable[str] = (), entropy: bool = True) -> list[Finding]:
    """Scan a string. `filename` enables file-type rules (e.g. '.env', 'Dockerfile')."""
    from scanner.engine import scan_content_string
    return scan_content_string(text, filename, options=_options(options, disable, entropy))


def scan_git(repo: PathLike = ".", *, max_commits: int = 100, since: Optional[str] = None,
             branch: Optional[str] = None, options: Optional[ScanOptions] = None,
             disable: Iterable[str] = (), entropy: bool = True) -> ScanResult:
    """Scan lines added in git history (streams `git log -p`)."""
    return _scan_git_history(Path(repo), depth=max_commits, since=since, branch=branch,
                             options=_options(options, disable, entropy))


def scan_diff(repo: PathLike = ".", *, base: str = "HEAD", options: Optional[ScanOptions] = None,
              entropy: bool = True) -> ScanResult:
    """Scan lines added between `base` and the working tree (e.g. base='origin/main...HEAD')."""
    return _scan_diff(Path(repo), [base], "diff", _options(options, (), entropy))


def to_json(result: ScanResult, redact: bool = False) -> str:
    from scanner.reporter import to_json as _to_json
    return _to_json(result, redact=redact)


def to_sarif(result: ScanResult) -> str:
    from scanner.reporter import to_sarif as _to_sarif
    return _to_sarif(result)

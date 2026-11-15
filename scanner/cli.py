from __future__ import annotations

import re
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.progress import BarColumn, MofNCompleteColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn

from scanner import __version__, notify, reporter
from scanner import blame as blameutil
from scanner import purge as purge_module
from scanner.config import load_config
from scanner.engine import (
    DEFAULT_CHUNK_SIZE,
    Finding,
    ScanOptions,
    ScanResult,
    scan_diff,
    scan_git_history,
    scan_path,
    scan_staged,
)
from scanner.ignorefile import append_ignore_pattern, write_init_template

console = Console()
err_console = Console(stderr=True)

EXIT_CLEAN, EXIT_FINDINGS, EXIT_ERROR = 0, 1, 2
SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
SEVERITIES = list(SEVERITY_ORDER)
FORMATS = ["terminal", "json", "csv", "sarif", "html", "junit", "markdown", "sonarqube", "defectdojo", "disclosure"]

_GITHUB_URL_RE = re.compile(r"^(?:https?://)?github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+?)(?:\.git)?/?$")


def _parse_github_url(value: str) -> tuple[str, str] | None:
    m = _GITHUB_URL_RE.match(value.strip())
    return (m.group(1), m.group(2)) if m else None


class ScanError(click.ClickException):
    exit_code = EXIT_ERROR


_STREAM_STYLE = {"CRITICAL": "bold red", "HIGH": "red", "MEDIUM": "yellow", "LOW": "dim"}


def _stream_line(f: Finding) -> str:
    style = _STREAM_STYLE.get(f.severity, "")
    return f"[{style}]{f.severity}[/{style}]  {f.rule_id}  {f.secret_type} - {f.file}:{f.line_number}"


def _progress(enabled: bool) -> Progress:
    return Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), BarColumn(),
                    MofNCompleteColumn(), TimeElapsedColumn(), console=err_console, transient=True,
                    disable=not enabled)


def _run_local_scan(target: Path, opts: ScanOptions, threads: Optional[int], max_file_size: int, chunk_size: int,
                    no_progress: bool, stream_live: bool, cache_path: Optional[Path]) -> ScanResult:
    with _progress(not no_progress) as progress:
        task = progress.add_task(f"Scanning {target.name or target}", total=None)

        def on_progress(done: int, total: int) -> None:
            progress.update(task, completed=done, total=total)

        def on_finding(f: Finding) -> None:
            if stream_live:
                progress.console.print(_stream_line(f))

        result = scan_path(target, threads=threads, max_file_size=max_file_size, chunk_size=chunk_size,
                           on_finding=on_finding, on_progress=on_progress, options=opts, cache_path=cache_path)

    cached = f", {result.files_cached} unchanged from cache" if result.files_cached else ""
    err_console.print(f"[dim]Scanned {result.files_scanned} file(s) in {result.elapsed_seconds:.2f}s "
                      f"({result.files_per_second:.1f} files/sec{cached})[/dim]")
    for skipped in result.large_files_skipped:
        err_console.print(f"[yellow]Skipped (exceeds size limit):[/yellow] {skipped}")
    if result.binary_files_skipped:
        err_console.print(f"[dim]Skipped {result.binary_files_skipped} binary file(s)[/dim]")
    return result


def _attach_blame(result: ScanResult, root: Path) -> None:
    if not root.is_dir() or not blameutil.is_git_repo(root):
        return
    for f in result.findings:
        if f.commit or "!" in f.file:
            continue
        f.blame = blameutil.get_blame_info(root, f.file, f.line_number)


def _spinner(text: str, enabled: bool = True) -> Progress:
    return Progress(SpinnerColumn(), TextColumn(text), console=err_console, transient=True, disable=not enabled)


def _build_options(cfg, entropy_threshold: float, no_entropy: bool, disable_rule: tuple[str, ...], decode: bool,
                   archives: bool, no_validate: bool, keep_placeholders: bool) -> ScanOptions:
    if cfg.entropy_threshold is not None and entropy_threshold == 4.5:
        entropy_threshold = cfg.entropy_threshold
    if cfg.no_entropy and not no_entropy:
        no_entropy = True
    opts = ScanOptions(entropy_threshold=entropy_threshold, no_entropy=no_entropy, decode=decode, archives=archives,
                       validate=not no_validate, placeholders=not keep_placeholders)
    cfg.apply(opts)
    opts.disable_rules |= {r.upper() if r.upper().startswith("LS-") else r for r in disable_rule}
    return opts


@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option(__version__, "-V", "--version", prog_name="leakscan")
def cli():
    """leakscan - find leaked API keys and secrets in code, history, images and packages."""


@cli.command()
@click.argument("path", default=".", required=False)
@click.option("--text", default=None, metavar="STRING", help="Scan a literal string instead of a path.")
@click.option("--github", "-g", default=None, metavar="USER", help="Scan every public repo of a GitHub user or org.")
@click.option("--github-org", default=None, metavar="ORG", help="Scan every repo in a GitHub organisation.")
@click.option("--repo", "-r", default=None, metavar="REPO", help="Limit --github to one repo name.")
@click.option("--include-forks", is_flag=True, help="Org/user scans: include forks.")
@click.option("--include-archived", is_flag=True, help="Org/user scans: include archived repos.")
@click.option("--repo-include", multiple=True, metavar="GLOB", help="Org/user scans: only repos matching GLOB.")
@click.option("--repo-exclude", multiple=True, metavar="GLOB", help="Org/user scans: skip repos matching GLOB.")
@click.option("--resume", "resume_file", default=None, metavar="FILE",
              help="Org/user scans: resume from (and save progress to) FILE.")
@click.option("--token", "-t", default=None, envvar="GITHUB_TOKEN", metavar="TOKEN",
              help="GitHub token for API calls and private clones (or GITHUB_TOKEN).")
@click.option("--clone-depth", default=None, type=int, metavar="N", help="Depth for remote clones (default: 1, or --depth+1 with --history).")
@click.option("--format", "-f", "output_format", type=click.Choice(FORMATS), default="terminal", show_default=True)
@click.option("--output", "-o", default=None, metavar="FILE", help="Write the report to FILE.")
@click.option("--also", "also", multiple=True, metavar="FORMAT:FILE",
              help="Write an extra report in another format, e.g. --also sarif:out.sarif (repeatable).")
@click.option("--entropy-threshold", default=4.5, show_default=True)
@click.option("--no-entropy", is_flag=True, help="Disable the high-entropy fallback detector.")
@click.option("--severity", "-s", type=click.Choice(SEVERITIES, case_sensitive=False), default=None,
              help="Only report findings at or above this severity.")
@click.option("--min-confidence", default=0.0, type=float, metavar="0-1", help="Only report findings at or above this confidence.")
@click.option("--fail-on", type=click.Choice(SEVERITIES, case_sensitive=False), default=None,
              help="Exit 1 if any finding is at or above this severity (default HIGH).")
@click.option("--exit-zero", is_flag=True, help="Always exit 0 when the scan itself succeeds.")
@click.option("--history", is_flag=True, help="Also scan git history.")
@click.option("--depth", "--max-commits", "depth", default=None, type=int, metavar="N",
              help="Max commits to scan with --history (default 100, GitHub 50).")
@click.option("--since", default=None, metavar="DATE", help="History: only commits after DATE.")
@click.option("--branch", default=None, metavar="BRANCH", help="History: only this branch.")
@click.option("--staged", is_flag=True, help="Scan only staged changes (pre-commit).")
@click.option("--since-commit", default=None, metavar="REF", help="Scan only lines added since REF.")
@click.option("--base", default=None, metavar="BRANCH", help="Scan only lines added relative to BRANCH (merge-base).")
@click.option("--pr", is_flag=True, help="Scan only lines added in the current PR/MR (CI env vars).")
@click.option("--follow", is_flag=True, help="Tail PATH (or stdin) and report secrets as lines arrive.")
@click.option("--archives", is_flag=True, help="Scan inside .zip/.tar/.whl/.jar archives.")
@click.option("--decode", is_flag=True, help="Also decode base64/hex/URL-encoded values one level.")
@click.option("--no-validate", is_flag=True, help="Keep matches that fail checksum/structure validation.")
@click.option("--keep-placeholders", is_flag=True, help="Report EXAMPLE/changeme/xxxx placeholder values too.")
@click.option("--disable-rule", multiple=True, metavar="ID", help="Disable a rule by ID (repeatable).")
@click.option("--verify", is_flag=True, help="Check whether found secrets are live (sends them to their provider).")
@click.option("--verify-only", default=None, metavar="SERVICES", help="Comma list of services to verify (see `leakscan rules verifiers`).")
@click.option("--verify-timeout", default=5.0, type=float, show_default=True, metavar="SECONDS")
@click.option("--verify-concurrency", default=4, type=click.IntRange(1, 10), show_default=True)
@click.option("--yes", "-y", "assume_yes", is_flag=True, help="Confirm --verify against third-party targets.")
@click.option("--config", "config_path", default=None, metavar="FILE", help="Config file (default: auto-detect .leakscan.yaml).")
@click.option("--baseline", default=None, metavar="FILE", help="Hide findings already in this baseline.")
@click.option("--save-baseline", default=None, metavar="FILE", help="Save findings as a baseline (fingerprints only).")
@click.option("--redact", is_flag=True, help="Mask secret values in output.")
@click.option("--include-gists", is_flag=True, help="Include gists in --github scans.")
@click.option("--threads", default=None, type=int, metavar="N", help="Worker threads (default: CPU count).")
@click.option("--max-file-size", default=50, type=int, metavar="MB", show_default=True)
@click.option("--chunk-size", default=DEFAULT_CHUNK_SIZE, type=int, metavar="BYTES", show_default=True)
@click.option("--cache", "cache_file", is_flag=False, flag_value=".leakscan-cache", default=None, metavar="FILE",
              help="Skip unchanged clean files using a cache (default file .leakscan-cache).")
@click.option("--no-progress", is_flag=True, help="No progress bar or live stream.")
@click.option("--brief", is_flag=True, help="One line per finding instead of full blocks.")
@click.option("--no-blame", is_flag=True, help="Skip git blame lookups.")
@click.option("--show-ignored", is_flag=True, help="List files skipped by .leakscanignore.")
@click.option("--notify", "notify_target", default=None, metavar="TARGETS",
              help="Comma list: slack, discord, teams, webhook, email (or 'both' for slack+discord).")
@click.option("--webhook", default=None, metavar="URL", help="Generic JSON webhook URL (also used as the fallback for --notify).")
@click.option("--slack-webhook", default=None, metavar="URL")
@click.option("--discord-webhook", default=None, metavar="URL")
@click.option("--teams-webhook", default=None, metavar="URL")
@click.option("--notify-clean", is_flag=True, help="Also notify when nothing is found.")
def scan(path, text, github, github_org, repo, include_forks, include_archived, repo_include, repo_exclude,
         resume_file, token, clone_depth, output_format, output, also, entropy_threshold, no_entropy, severity,
         min_confidence, fail_on, exit_zero, history, depth, since, branch, staged, since_commit, base, pr, follow,
         archives, decode, no_validate, keep_placeholders, disable_rule, verify, verify_only, verify_timeout,
         verify_concurrency, assume_yes, config_path, baseline, save_baseline, redact, include_gists, threads,
         max_file_size, chunk_size, cache_file, no_progress, brief, no_blame, show_ignored, notify_target, webhook,
         slack_webhook, discord_webhook, teams_webhook, notify_clean):
    """Scan PATH for leaked secrets.

    PATH can be a directory, a file, '-' for stdin, a git URL (GitHub, GitLab,
    Bitbucket or any https/ssh remote), docker://IMAGE[:TAG], pypi:NAME[==VER]
    or npm:NAME[@VER].

    \b
    Examples:
      leakscan scan .
      leakscan scan . --staged
      leakscan scan . --pr --format sarif -o results.sarif
      leakscan scan . --history --since 2024-01-01
      cat .env | leakscan scan -
      leakscan scan --text "AKIA..."
      leakscan scan notebooks/ --archives
      leakscan scan docker://nginx:1.27
      leakscan scan pypi:requests==2.32.3
      leakscan scan https://gitlab.com/group/project --history
      leakscan scan --github-org my-org --resume org.state.json
    """
    from scanner import sources

    severity = severity.upper() if severity else None
    target = Path(path)
    local = not (text or github or github_org or path == "-" or sources.is_remote_url(path)
                 or sources.is_docker(path) or sources.is_package(path))
    cfg_dir = target.resolve() if local and target.is_dir() else (target.resolve().parent if local else Path.cwd())
    cfg = load_config(cfg_dir, Path(config_path) if config_path else None)
    for problem in cfg.errors:
        err_console.print(f"[yellow]config:[/yellow] {problem}")
    if cfg.severity_threshold and not severity:
        severity = cfg.severity_threshold
    fail_on = (fail_on or cfg.fail_on or "HIGH").upper()
    opts = _build_options(cfg, entropy_threshold, no_entropy, disable_rule, decode or bool(cfg.decode),
                          archives or bool(cfg.archives), no_validate, keep_placeholders)

    third_party = not local and not text and path != "-"
    if verify and third_party and not assume_yes:
        raise ScanError(
            "--verify sends every detected secret to its provider's API. For repos, profiles, images or packages "
            "you don't own, that may be unauthorised use of someone else's credentials. Re-run with --yes if you "
            "have permission, or drop --verify."
        )

    label = path
    stream = output_format == "terminal" and not no_progress
    try:
        if text is not None:
            result = sources.scan_text(text, opts, "<text>")
            label = "<text>"
        elif follow:
            def _emit(f: Finding) -> None:
                err_console.print(_stream_line(f))
            try:
                result = sources.follow(target if path != "-" else Path("-"), opts, _emit)
            except KeyboardInterrupt:
                result = ScanResult()
        elif path == "-":
            result = sources.scan_text(sys.stdin.read(), opts, "<stdin>")
            label = "<stdin>"
        elif github_org or github:
            owner = github_org or github
            settings = sources.OrgScanSettings(
                include_forks=include_forks, include_archived=include_archived,
                include=tuple(repo_include) + ((repo,) if repo else ()), exclude=tuple(repo_exclude),
                resume_file=Path(resume_file) if resume_file else None, history=history, depth=depth or 50)
            with _spinner(f"Listing repos for {owner}...", not no_progress) as prog:
                t = prog.add_task("", total=None)
                result = sources.scan_github_org(
                    owner, opts, token, settings,
                    on_repo=lambda name, i, n: prog.update(t, description=f"[{i}/{n}] {name}"))
            if include_gists and github:
                result.merge(_scan_gists(github, token, opts))
            label = owner
        elif sources.is_docker(path):
            with _spinner(f"Scanning image {path}...", not no_progress):
                result = sources.scan_docker_image(path, opts)
        elif sources.is_package(path):
            with _spinner(f"Downloading and scanning {path}...", not no_progress):
                result = sources.scan_package(path, opts)
        elif sources.is_remote_url(path):
            with _spinner(f"Cloning {path}...", not no_progress):
                result = sources.scan_remote(path, opts, history=history, depth=depth or 100, clone_depth=clone_depth,
                                             branch=branch, token=token, threads=threads)
        elif staged or since_commit or base or pr:
            if since_commit:
                args, src = [since_commit, "HEAD"], "diff"
            elif base:
                args, src = [f"{base}...HEAD"], "diff"
            elif pr:
                args, src = sources.pr_diff_args(), "pr"
            else:
                args, src = ["--cached"], "staged"
            with _spinner("Scanning changes...", not no_progress):
                result = scan_diff(target.resolve(), args, src, opts) if src != "staged" else \
                    scan_staged(target.resolve(), options=opts)
        else:
            if not target.exists():
                raise ScanError(f"Path not found: {target}")
            cache_path = Path(cache_file) if cache_file else None
            if cache_path and not cache_path.is_absolute() and target.is_dir():
                cache_path = target / cache_path
            result = _run_local_scan(target.resolve(), opts, threads, max_file_size * 1_000_000, chunk_size,
                                     no_progress, stream, cache_path)
            if history:
                with _progress(not no_progress) as prog:
                    t = prog.add_task("Scanning git history", total=depth or 100)
                    hist = scan_git_history(target.resolve(), depth=depth or 100, since=since, branch=branch,
                                            options=opts, on_commit=lambda n: prog.update(t, completed=n))
                result.findings.extend(hist.findings)
                result.commits_scanned = hist.commits_scanned
                result.errors.extend(hist.errors)
    except ScanError:
        raise
    except Exception as e:
        raise ScanError(str(e)) from e

    if baseline:
        bpath = Path(baseline)
        if bpath.exists():
            from scanner.baseline import filter_new, load
            before = len(result.findings)
            result.findings = filter_new(result.findings, load(bpath))
            if before - len(result.findings):
                err_console.print(f"[dim]Suppressed {before - len(result.findings)} baseline finding(s).[/dim]")
        else:
            err_console.print(f"[yellow]Baseline file not found:[/yellow] {bpath}")

    if severity:
        limit = SEVERITY_ORDER[severity]
        result.findings = [f for f in result.findings if SEVERITY_ORDER.get(f.severity, 9) <= limit]
    if min_confidence:
        result.findings = [f for f in result.findings if f.confidence >= min_confidence]

    if verify and result.findings:
        _verify_findings(result, verify_only, verify_timeout, verify_concurrency, not no_progress)

    if local and not no_blame and not brief and result.findings and target.is_dir():
        _attach_blame(result, target.resolve())

    if save_baseline:
        from scanner.baseline import save
        save(result, Path(save_baseline))
        err_console.print(f"[green]Baseline saved to:[/green] {save_baseline}")

    if show_ignored and result.ignored_files:
        err_console.print(f"\n[dim]Ignored {len(result.ignored_files)} file(s) (.leakscanignore):[/dim]")
        for p in result.ignored_files:
            err_console.print(f"[dim]  {p}[/dim]")

    disclosure_target = github or github_org or _github_owner(path)
    _emit_report(result, output_format, output, redact, brief, disclosure_target)
    for spec in also:
        fmt, sep, dest = spec.partition(":")
        if not sep or fmt not in FORMATS or fmt == "terminal" or not dest:
            raise ScanError(f"--also expects FORMAT:FILE with a non-terminal format, got {spec!r}")
        _emit_report(result, fmt, dest, redact, brief, disclosure_target)

    if result.findings and output_format == "terminal":
        err_console.print(f"\n[dim]{purge_module.PURGE_REMINDER}[/dim]")

    if notify_target:
        for message in notify.send_notifications(
            result, label if not local else str(target.resolve()), notify_target,
            slack_webhook=slack_webhook or webhook, discord_webhook=discord_webhook or webhook,
            notify_clean=notify_clean, teams_webhook=teams_webhook or webhook, generic_webhook=webhook,
        ):
            err_console.print(f"[dim]{message}[/dim]")

    sys.exit(_exit_code(result, fail_on, exit_zero))


def _github_owner(path: str) -> Optional[str]:
    m = _parse_github_url(path)
    return m[0] if m else None


def _emit_report(result: ScanResult, fmt: str, output: Optional[str], redact: bool, brief: bool,
                 disclosure_target: Optional[str]) -> None:
    from scanner import formats

    if fmt == "terminal":
        reporter.print_terminal(result, redact=redact, brief=brief)
        return
    if fmt == "disclosure":
        if not disclosure_target:
            raise ScanError("--format disclosure requires --github <user> or a GitHub URL")
        content = reporter.to_disclosure_report(disclosure_target, result, redact=redact)
    else:
        render = {
            "json": lambda: reporter.to_json(result, redact=redact),
            "csv": lambda: reporter.to_csv(result, redact=redact),
            "sarif": lambda: reporter.to_sarif(result, redact=True),
            "html": lambda: formats.to_html(result, redact=True),
            "junit": lambda: formats.to_junit(result),
            "markdown": lambda: formats.to_markdown(result),
            "sonarqube": lambda: formats.to_sonarqube(result),
            "defectdojo": lambda: formats.to_defectdojo(result),
        }
        content = render[fmt]()
    _write(content, output)


def _verify_findings(result: ScanResult, only: Optional[str], timeout: float, concurrency: int,
                     show_progress: bool) -> None:
    from scanner import verifier

    verifier.configure(timeout=timeout)
    wanted = {s.strip().lower() for s in only.split(",")} if only else None
    targets = [f for f in result.findings if verifier.can_verify(f)
               and (wanted is None or (verifier.service_of(f.secret_type) or "") in wanted
                    or f.rule_id.lower() in wanted)]
    if not targets:
        return
    with _spinner(f"Verifying {len(targets)} secret(s)...", show_progress):
        with ThreadPoolExecutor(max_workers=concurrency) as executor:
            futures = {executor.submit(verifier.verify, f): f for f in targets}
            for future in as_completed(futures):
                f = futures[future]
                f.verified_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
                try:
                    f.verified = future.result()
                except Exception as e:
                    f.verification_error = e.__class__.__name__


def _scan_gists(username: str, token: Optional[str], opts: ScanOptions) -> ScanResult:
    from scanner.engine import scan_content_string
    from scanner.github.fetcher import GitHubFetcher

    fetcher = GitHubFetcher(token=token)
    result = ScanResult()
    try:
        for gist_id in fetcher.list_gists(username):
            for gf in fetcher.iter_gist_files(gist_id):
                result.findings.extend(scan_content_string(gf.content, f"{gf.repo}/{gf.path}", options=opts))
                result.files_scanned += 1
    except Exception as e:
        result.errors.append(f"gists: {e}")
    return result


def _write(content: str, filepath: Optional[str]) -> None:
    if filepath:
        Path(filepath).write_text(content, encoding="utf-8")
        err_console.print(f"[green]Output written to:[/green] {filepath}")
    else:
        click.echo(content)


def _exit_code(result: ScanResult, fail_on: str = "HIGH", exit_zero: bool = False) -> int:
    if result.errors and not result.files_scanned and not result.commits_scanned and not result.findings:
        for e in result.errors[:5]:
            err_console.print(f"[red]error:[/red] {e}")
        return EXIT_ERROR
    if exit_zero:
        return EXIT_CLEAN
    limit = SEVERITY_ORDER[fail_on]
    return EXIT_FINDINGS if any(SEVERITY_ORDER.get(f.severity, 9) <= limit for f in result.findings) else EXIT_CLEAN


HOOK_SCRIPT = """#!/bin/sh
# Installed by `leakscan install-hook`
BASELINE_ARG=""
if [ -f .secrets.baseline ]; then
  BASELINE_ARG="--baseline .secrets.baseline"
fi
leakscan scan . --staged --fail-on HIGH --format terminal --brief --no-blame --no-progress $BASELINE_ARG
status=$?
if [ $status -eq 1 ]; then
  echo ""
  echo "Commit blocked: secrets detected."
  echo "Fix it, or mark a false positive with '# leakscan:ignore <RULE-ID>' on the line."
  exit 1
fi
exit $status
"""


@cli.command(name="install-hook")
def install_hook():
    """Install a git pre-commit hook in the current repo."""
    git_dir = Path(".git")
    if not git_dir.exists():
        raise ScanError("Not a git repository.")
    hook_path = git_dir / "hooks" / "pre-commit"
    hook_path.parent.mkdir(parents=True, exist_ok=True)
    hook_path.write_text(HOOK_SCRIPT, encoding="utf-8")
    hook_path.chmod(0o755)
    console.print(f"[green]Pre-commit hook installed at {hook_path}[/green]")


@cli.command(name="ignore")
@click.argument("pattern")
@click.argument("path", default=".", required=False)
def ignore_cmd(pattern: str, path: str):
    """Add PATTERN to .leakscanignore (gitignore syntax)."""
    ignore_file = append_ignore_pattern(Path(path).resolve(), pattern)
    console.print(f"[green]Added[/green] '{pattern}' to {ignore_file}")


@cli.command(name="init")
@click.argument("path", default=".", required=False)
def init_cmd(path: str):
    """Create a .leakscanignore with sensible defaults."""
    ignore_file, created = write_init_template(Path(path).resolve())
    if created:
        console.print(f"[green]Created[/green] {ignore_file}")
    else:
        console.print(f"[yellow]Already exists:[/yellow] {ignore_file} (left unchanged)")


@cli.command()
@click.option("--commit", default=None, metavar="SHA", help="Show what a commit changed and how to redact it.")
@click.option("--file", "file_", default=None, metavar="PATH", help="Remove a file from every commit.")
@click.option("--all", "purge_all", is_flag=True, help="Template for redacting secret values everywhere.")
@click.option("--method", default=None, type=click.Choice(["filter-repo", "bfg"]))
def purge(commit, file_, purge_all, method):
    """Print (never run) commands to remove secrets from git history."""
    click.echo(purge_module.build_purge_report(commit=commit, file=file_, purge_all=purge_all, method=method))


from scanner.commands import register  # noqa: E402

register(cli)

if __name__ == "__main__":
    cli()

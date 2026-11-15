"""Secondary CLI commands: rules, config, completion, mcp, hook."""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any, Iterator, Optional

import click
import yaml

from scanner import __version__

SCHEMA_DIR = Path(__file__).parent / "schemas"


def register(cli: click.Group) -> None:
    cli.add_command(rules)
    cli.add_command(config)
    cli.add_command(completion)
    cli.add_command(mcp)
    cli.add_command(hook)


@click.group()
def rules():
    """List, inspect, disable or import detection rules."""


@rules.command("list")
@click.option("--json", "as_json", is_flag=True, help="Machine-readable output.")
@click.option("--severity", default=None, help="Filter by severity.")
@click.option("--search", default=None, metavar="TEXT", help="Filter by name or ID.")
def rules_list(as_json: bool, severity: Optional[str], search: Optional[str]):
    """List every built-in and imported rule."""
    from scanner.config import ScanConfig, load_rule_packs
    from scanner.engine import Finding
    from scanner.patterns import PATTERNS
    from scanner.verifier import can_verify

    extra = ScanConfig()
    load_rule_packs(extra)
    rows = []
    for p in [*PATTERNS, *extra.custom_patterns]:
        if severity and p.severity != severity.upper():
            continue
        if search and search.lower() not in f"{p.id} {p.name}".lower():
            continue
        rows.append({"id": p.id, "name": p.name, "severity": p.severity, "description": p.description,
                     "verifiable": can_verify(Finding("", 0, "", p.name, p.severity, "")),
                     "path": p.path.pattern if p.path else None})
    if as_json:
        click.echo(json.dumps(rows, indent=2))
        return
    from rich.console import Console
    from rich.table import Table
    t = Table(box=None, header_style="bold")
    for col in ("ID", "Severity", "Name", "Verify"):
        t.add_column(col)
    for r in rows:
        t.add_row(str(r["id"]), str(r["severity"]), str(r["name"]), "yes" if r["verifiable"] else "")
    Console().print(t)
    click.echo(f"\n{len(rows)} rule(s)")


@rules.command("show")
@click.argument("rule_id")
def rules_show(rule_id: str):
    """Show a rule's regex, blast radius and rotation link."""
    from scanner.patterns import by_id
    from scanner.remediation import get_remediation
    from scanner.verifier import ENDPOINTS

    p = by_id().get(rule_id.upper())
    if p is None:
        raise click.ClickException(f"unknown rule {rule_id}")
    rem = get_remediation(p.name)
    click.echo(f"{p.id}  {p.name}  [{p.severity}]\n")
    click.echo(f"Description:  {p.description}")
    click.echo(f"Regex:        {p.regex.pattern}")
    if p.path:
        click.echo(f"Files:        {p.path.pattern}")
    if p.validate:
        click.echo(f"Validation:   {p.validate.__name__}{' (strict)' if p.strict else ''}")
    click.echo(f"If leaked:    {rem.consequence}")
    click.echo(f"Blast radius: {rem.blast_radius}")
    click.echo(f"Rotate at:    {rem.rotation_url}")
    if p.name in ENDPOINTS:
        click.echo(f"--verify:     {ENDPOINTS[p.name]}")
    click.echo(f"\nSuppress on a line with:  # leakscan:ignore {p.id}")


@rules.command("verifiers")
def rules_verifiers():
    """List services supported by --verify / --verify-only and what each request sends."""
    from scanner.verifier import ENDPOINTS, service_of
    for name, endpoint in sorted(ENDPOINTS.items(), key=lambda kv: (service_of(kv[0]) or "", kv[0])):
        click.echo(f"{(service_of(name) or '-'):<14} {name:<32} {endpoint}")


def _config_path(path: Optional[str]) -> Path:
    from scanner.config import CONFIG_FILENAME
    return Path(path) if path else Path.cwd() / CONFIG_FILENAME


def _edit_disable(rule_id: str, cfg_file: Path, add: bool) -> None:
    data: dict[str, Any] = {}
    if cfg_file.exists():
        data = yaml.safe_load(cfg_file.read_text(encoding="utf-8")) or {}
    current = [str(r).upper() for r in data.get("disable_rules") or []]
    rid = rule_id.upper()
    if add and rid not in current:
        current.append(rid)
    if not add and rid in current:
        current.remove(rid)
    if cfg_file.exists() and "disable_rules" not in data and add:
        with open(cfg_file, "a", encoding="utf-8") as fh:
            fh.write(f"\ndisable_rules:\n  - {rid}\n")
        return
    data["disable_rules"] = current
    cfg_file.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")


@rules.command("disable")
@click.argument("rule_id")
@click.option("--config", "config_file", default=None, help="Config file to edit (default ./.leakscan.yaml).")
def rules_disable(rule_id: str, config_file: Optional[str]):
    """Disable a rule for this project (writes .leakscan.yaml)."""
    path = _config_path(config_file)
    _edit_disable(rule_id, path, add=True)
    click.echo(f"Disabled {rule_id.upper()} in {path}")


@rules.command("enable")
@click.argument("rule_id")
@click.option("--config", "config_file", default=None)
def rules_enable(rule_id: str, config_file: Optional[str]):
    """Re-enable a disabled rule."""
    path = _config_path(config_file)
    if not path.exists():
        raise click.ClickException(f"{path} does not exist")
    _edit_disable(rule_id, path, add=False)
    click.echo(f"Enabled {rule_id.upper()} in {path}")


def validate_pack(data: Any) -> tuple[list[dict], list[str]]:
    from scanner.config import build_pattern
    problems: list[str] = []
    if not isinstance(data, dict) or not isinstance(data.get("rules"), list):
        return [], ["a rule pack must be a mapping with a 'rules' list"]
    good = []
    for i, entry in enumerate(data["rules"]):
        if not isinstance(entry, dict):
            problems.append(f"rule #{i + 1} is not a mapping")
            continue
        if len(str(entry.get("regex", ""))) > 1000:
            problems.append(f"rule #{i + 1}: regex longer than 1000 characters")
            continue
        errs: list[str] = []
        p = build_pattern(entry, errs, i)
        if p is None:
            problems.extend(errs)
            continue
        examples = entry.get("examples") or {}
        for s in examples.get("positive") or []:
            if not p.regex.search(str(s)):
                problems.append(f"{p.id}: positive example does not match: {s!r}")
        for s in examples.get("negative") or []:
            if p.regex.search(str(s)):
                problems.append(f"{p.id}: negative example matches: {s!r}")
        good.append(entry)
    return good, problems


@rules.command("import")
@click.argument("source")
@click.option("--name", default=None, help="Name to save the pack under.")
def rules_import(source: str, name: Optional[str]):
    """Import a YAML rule pack from an https URL or a local file."""
    from scanner.config import rules_dir
    if re.match(r"^https?://", source):
        if not source.startswith("https://"):
            raise click.ClickException("only https:// URLs are accepted")
        import requests
        r = requests.get(source, timeout=30, headers={"User-Agent": f"leakscan/{__version__}"})
        r.raise_for_status()
        text = r.text
    else:
        text = Path(source).read_text(encoding="utf-8")
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as e:
        raise click.ClickException(f"invalid YAML: {e}") from e
    good, problems = validate_pack(data)
    for p in problems:
        click.echo(f"warning: {p}", err=True)
    if not good:
        raise click.ClickException("no valid rules in pack")
    pack_name = re.sub(r"[^A-Za-z0-9_.-]+", "-", name or data.get("name") or Path(source).stem).strip("-") or "pack"
    dest = rules_dir()
    dest.mkdir(parents=True, exist_ok=True)
    out = dest / f"{pack_name}.yaml"
    out.write_text(yaml.safe_dump({"name": pack_name, "source": source, "rules": good}, sort_keys=False),
                   encoding="utf-8")
    click.echo(f"Imported {len(good)} rule(s) into {out}")


@rules.command("remove")
@click.argument("name")
def rules_remove(name: str):
    """Remove an imported rule pack."""
    from scanner.config import rules_dir
    path = rules_dir() / f"{name}.yaml"
    if not path.exists():
        raise click.ClickException(f"no pack named {name}")
    path.unlink()
    click.echo(f"Removed {path}")


@click.group()
def config():
    """Validate configuration and print JSON schemas."""


@config.command("validate")
@click.argument("path", default=None, required=False)
def config_validate(path: Optional[str]):
    """Check a .leakscan.yaml for unknown keys, bad types and invalid regexes."""
    cfg = _config_path(path)
    if not cfg.exists():
        raise click.ClickException(f"{cfg} not found")
    from scanner.config import validate_file
    problems = validate_file(cfg)
    if problems:
        for p in problems:
            click.echo(f"{cfg}: {p}", err=True)
        sys.exit(1)
    click.echo(f"{cfg}: OK")


@config.command("schema")
@click.option("--report", is_flag=True, help="Print the JSON report schema instead of the config schema.")
def config_schema(report: bool):
    """Print the JSON schema for .leakscan.yaml (or for --format json output)."""
    name = "report.schema.json" if report else "config.schema.json"
    click.echo((SCHEMA_DIR / name).read_text(encoding="utf-8"))


@click.command()
@click.argument("shell", type=click.Choice(["bash", "zsh", "fish"]))
def completion(shell: str):
    """Print a shell completion script.

    \b
    bash:  leakscan completion bash > ~/.local/share/bash-completion/completions/leakscan
    zsh:   leakscan completion zsh > "${fpath[1]}/_leakscan"
    fish:  leakscan completion fish > ~/.config/fish/completions/leakscan.fish
    """
    from click.shell_completion import get_completion_class

    from scanner.cli import cli as root
    cls = get_completion_class(shell)
    assert cls is not None
    click.echo(cls(root, {}, "leakscan", "_LEAKSCAN_COMPLETE").source())


def _strings(obj: Any) -> Iterator[str]:
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, dict):
        for v in obj.values():
            yield from _strings(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from _strings(v)


def _scan_strings(values: list[str], label: str):
    from scanner.engine import ScanOptions
    from scanner.sources import scan_text
    opts = ScanOptions(no_entropy=True)
    return scan_text("\n".join(values), opts, label).findings


def _summarise(findings, limit: int = 20) -> list[dict]:
    from scanner.reporter import _redact
    return [{"rule_id": f.rule_id, "type": f.secret_type, "severity": f.severity, "file": f.file,
             "line": f.line_number, "match": _redact(f.matched_value), "confidence": f.confidence}
            for f in findings[:limit]]


@click.command()
@click.option("--agent", type=click.Choice(["claude-code", "cursor", "generic"]), default="claude-code",
              show_default=True, help="Hook protocol to speak.")
@click.option("--fail-on", type=click.Choice(["CRITICAL", "HIGH", "MEDIUM", "LOW"]), default="HIGH", show_default=True)
def hook(agent: str, fail_on: str):
    """Agent hook: block AI coding agents from writing or running secrets.

    Reads the tool call JSON on stdin, scans every string in it, and blocks
    the call when a secret at or above --fail-on is found. See the docs for
    Claude Code and Cursor configuration snippets.
    """
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    try:
        payload = json.loads(sys.stdin.read() or "{}")
    except ValueError:
        sys.exit(0)
    body = payload.get("tool_input", payload) if isinstance(payload, dict) else payload
    label = (body.get("file_path") if isinstance(body, dict) else None) or "<agent>"
    findings = [f for f in _scan_strings(list(_strings(body)), str(label))
                if order.get(f.severity, 9) <= order[fail_on] and f.confidence >= 0.5]
    if agent == "cursor":
        if findings:
            msg = f"leakscan blocked this: {findings[0].secret_type} ({findings[0].rule_id}). Use an env var or secret store."
            click.echo(json.dumps({"permission": "deny", "continue": True, "userMessage": msg, "agentMessage": msg}))
        else:
            click.echo(json.dumps({"permission": "allow", "continue": True}))
        sys.exit(0)
    if not findings:
        sys.exit(0)
    lines = [f"leakscan: refusing to write a secret ({len(findings)} finding(s)):"]
    lines += [f"  {f['severity']} {f['rule_id']} {f['type']}: {f['match']}" for f in _summarise(findings, 5)]
    lines.append("Read the value from an environment variable or secret manager instead of hardcoding it.")
    click.echo("\n".join(lines), err=True)
    sys.exit(2 if agent == "claude-code" else 1)


MCP_TOOLS = [
    {
        "name": "scan_text",
        "description": "Scan a string (file contents, a diff, a command) for leaked secrets. Returns redacted findings.",
        "inputSchema": {"type": "object", "properties": {
            "text": {"type": "string"}, "filename": {"type": "string", "description": "Used for file-type rules."}},
            "required": ["text"]},
    },
    {
        "name": "scan_path",
        "description": "Scan a file or directory on disk for leaked secrets. Returns redacted findings.",
        "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"]},
    },
    {
        "name": "scan_staged",
        "description": "Scan the staged git changes of a repository before committing.",
        "inputSchema": {"type": "object", "properties": {"repo": {"type": "string", "default": "."}}},
    },
]


def _mcp_call(name: str, args: dict) -> dict:
    from scanner.engine import ScanOptions, scan_path, scan_staged
    from scanner.sources import scan_text
    opts = ScanOptions(no_entropy=True)
    if name == "scan_text":
        res = scan_text(str(args.get("text", "")), opts, str(args.get("filename") or "<text>"))
    elif name == "scan_path":
        p = Path(str(args.get("path", "."))).expanduser()
        if not p.exists():
            raise ValueError(f"path not found: {p}")
        res = scan_path(p, options=opts)
    elif name == "scan_staged":
        res = scan_staged(Path(str(args.get("repo") or ".")).expanduser(), options=opts)
    else:
        raise ValueError(f"unknown tool {name}")
    return {"total": len(res.findings), "files_scanned": res.files_scanned, "findings": _summarise(res.findings, 50),
            "errors": res.errors[:5]}


def handle_mcp(msg: dict) -> Optional[dict]:
    method, mid = msg.get("method"), msg.get("id")
    if mid is None:
        return None
    try:
        if method == "initialize":
            result: dict = {
                "protocolVersion": (msg.get("params") or {}).get("protocolVersion", "2025-06-18"),
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "leakscan", "version": __version__},
            }
        elif method == "ping":
            result = {}
        elif method == "tools/list":
            result = {"tools": MCP_TOOLS}
        elif method == "tools/call":
            params = msg.get("params") or {}
            try:
                data = _mcp_call(params.get("name", ""), params.get("arguments") or {})
                result = {"content": [{"type": "text", "text": json.dumps(data, indent=2)}],
                          "structuredContent": data, "isError": False}
            except Exception as e:
                result = {"content": [{"type": "text", "text": str(e)}], "isError": True}
        else:
            return {"jsonrpc": "2.0", "id": mid, "error": {"code": -32601, "message": f"method not found: {method}"}}
    except Exception as e:
        return {"jsonrpc": "2.0", "id": mid, "error": {"code": -32603, "message": str(e)}}
    return {"jsonrpc": "2.0", "id": mid, "result": result}


@click.command()
def mcp():
    """Run an MCP server on stdio exposing scan_text, scan_path and scan_staged."""
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except ValueError:
            continue
        reply = handle_mcp(msg)
        if reply is not None:
            sys.stdout.write(json.dumps(reply) + "\n")
            sys.stdout.flush()

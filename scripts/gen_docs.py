"""Generate docs pages, the man page and the VS Code pattern file from the code.

usage:
    python scripts/gen_docs.py                       # docs/ pages
    python scripts/gen_docs.py --man leakscan.1      # also a man page
    python scripts/gen_docs.py --vscode ../leakscan-vscode/src/patterns.ts
"""
from __future__ import annotations

import argparse
import datetime
import json
import re
import shutil
import sys
from pathlib import Path

import click

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from scanner import __version__  # noqa: E402
from scanner.cli import cli  # noqa: E402
from scanner.patterns import PATTERNS  # noqa: E402
from scanner.remediation import get_remediation  # noqa: E402
from scanner.verifier import ENDPOINTS, service_of  # noqa: E402

DOCS = ROOT / "docs"


def _commands(group: click.Group, prefix: str = "leakscan"):
    ctx = click.Context(group, info_name=prefix)
    yield prefix, group.get_help(ctx)
    for name in sorted(group.list_commands(ctx)):
        cmd = group.get_command(ctx, name)
        if cmd is None or cmd.hidden:
            continue
        full = f"{prefix} {name}"
        if isinstance(cmd, click.Group):
            yield from _commands(cmd, full)
        else:
            yield full, cmd.get_help(click.Context(cmd, info_name=full, parent=ctx))


def cli_reference() -> None:
    parts = [f"# CLI reference\n\nGenerated from leakscan {__version__}.\n"]
    for name, text in _commands(cli):
        parts.append(f"## `{name}`\n\n```text\n{text}\n```\n")
    (DOCS / "cli.md").write_text("\n".join(parts), encoding="utf-8")


def rule_catalog() -> None:
    out = DOCS / "rules"
    shutil.rmtree(out, ignore_errors=True)
    out.mkdir()
    rows = []
    groups: dict[str, list] = {}
    for p in PATTERNS:
        groups.setdefault(p.id.split("-")[1], []).append(p)
        rem = get_remediation(p.name)
        verify = ENDPOINTS.get(p.name, "")
        lines = [
            f"# {p.id}: {p.name}", "",
            "| | |", "|---|---|",
            f"| Severity | {p.severity} |",
            f"| Blast radius | {rem.blast_radius} |",
            f"| Rotate at | <{rem.rotation_url}> |",
        ]
        if p.path:
            lines.append(f"| Applies to files matching | `{p.path.pattern}` |")
        if p.validate:
            lines.append(f"| Validation | `{p.validate.__name__}`{' (matches that fail are dropped)' if p.strict else ''} |")
        if verify:
            lines.append(f"| `--verify` | {verify} |")
        lines += ["", "## If this leaks", "", rem.consequence, "",
                  "## What to do", "",
                  f"1. Rotate or revoke the credential at {rem.rotation_url}.",
                  "2. Check the provider's audit logs for use you don't recognise.",
                  "3. Remove it from git history (`leakscan purge --help`) and load it from an environment variable or "
                  "secret manager instead.", "",
                  "## Pattern", "", "```regex", p.regex.pattern, "```", "",
                  "## Suppress", "", f"On one line: `# leakscan:ignore {p.id}`. For the whole project:", "",
                  f"```yaml\ndisable_rules: [{p.id}]\n```", ""]
        (out / f"{p.id}.md").write_text("\n".join(lines), encoding="utf-8")
        rows.append(p)
    idx = [f"# Rule catalog\n\n{len(PATTERNS)} built-in rules. IDs are stable across releases. "
           "Click a rule for its blast radius, rotation steps and regex.\n",
           "Rules marked *verify* can be checked live with `--verify`.\n"]
    for group in sorted(groups):
        idx.append(f"\n## {group}\n\n| ID | Name | Severity | |\n|---|---|---|---|")
        for p in groups[group]:
            idx.append(f"| [{p.id}]({p.id}.md) | {p.name} | {p.severity} | {'verify' if p.name in ENDPOINTS and not ENDPOINTS[p.name].startswith('none') else ''} |")
    (out / "index.md").write_text("\n".join(idx) + "\n", encoding="utf-8")


def verification_page() -> None:
    head = (DOCS / "verification.md.head").read_text(encoding="utf-8")
    rows = ["| Service | Secret type | Request |", "|---|---|---|"]
    for name, endpoint in sorted(ENDPOINTS.items(), key=lambda kv: (service_of(kv[0]) or "", kv[0])):
        rows.append(f"| {service_of(name) or ''} | {name} | `{endpoint}` |")
    (DOCS / "verification.md").write_text(head + "\n".join(rows) + "\n", encoding="utf-8")


def copies() -> None:
    shutil.copy(DOCS / "comparison.md.head", DOCS / "comparison.md")
    for src, dst in (("CHANGELOG.md", "changelog.md"), ("CONTRIBUTING.md", "contributing.md")):
        text = (ROOT / src).read_text(encoding="utf-8").replace("](CODE_OF_CONDUCT.md)",
                                                                 "](https://github.com/Vasishta03/leakscan/blob/main/CODE_OF_CONDUCT.md)")
        (DOCS / dst).write_text(text, encoding="utf-8")
    schemas = DOCS / "schemas"
    schemas.mkdir(exist_ok=True)
    for f in (ROOT / "scanner" / "schemas").glob("*.json"):
        shutil.copy(f, schemas / f.name)


def _roff(s: str) -> str:
    return s.replace("\\", "\\\\").replace("-", "\\-").replace("'", "\\(aq")


def man_page(path: Path) -> None:
    date = datetime.date.today().isoformat()
    out = [f'.TH LEAKSCAN 1 "{date}" "leakscan {__version__}" "User Commands"',
           ".SH NAME", "leakscan \\- find leaked API keys and secrets",
           ".SH SYNOPSIS", ".B leakscan", "\\fICOMMAND\\fR [\\fIOPTIONS\\fR]"]
    for name, text in _commands(cli):
        out += [f".SH {_roff(name.upper())}", ".nf", _roff(text), ".fi"]
    out += [".SH SEE ALSO", "https://vasishta03.github.io/leakscan/"]
    path.write_text("\n".join(out) + "\n", encoding="utf-8")


def _js_regex(pattern: str) -> tuple[str, str]:
    flags = "g"
    m = re.match(r"^\(\?([aiLmsux]+)\)", pattern)
    if m:
        flags += "".join(c for c in m.group(1) if c in "ims")
        pattern = pattern[m.end():]
    if re.search(r"\(\?[aiLmsux]+\)", pattern):
        raise ValueError(f"inline flags inside pattern not supported in JS: {pattern}")
    return pattern.replace("/", "\\/"), flags


def vscode_patterns(path: Path) -> None:
    lines = [
        "// Generated by leakscan scripts/gen_docs.py --vscode. Do not edit by hand.",
        f"// leakscan {__version__}, {len(PATTERNS)} rules.",
        "",
        "export interface Pattern {",
        "  id: string;",
        "  name: string;",
        "  regex: RegExp;",
        '  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";',
        "  description: string;",
        "  path?: RegExp;",
        "  rotationUrl: string;",
        "  blastRadius: string;",
        "}",
        "",
        "export const PATTERNS: Pattern[] = [",
    ]
    for p in PATTERNS:
        src, flags = _js_regex(p.regex.pattern)
        rem = get_remediation(p.name)
        entry = ["  {", f"    id: {json.dumps(p.id)},", f"    name: {json.dumps(p.name)},",
                 f"    regex: /{src}/{flags},", f"    severity: {json.dumps(p.severity)},",
                 f"    description: {json.dumps(p.description)},"]
        if p.path:
            ps, pf = _js_regex(p.path.pattern)
            entry.append(f"    path: /{ps}/{pf.replace('g', '')}i,")
        entry += [f"    rotationUrl: {json.dumps(rem.rotation_url)},", f"    blastRadius: {json.dumps(rem.blast_radius)},",
                  "  },"]
        lines += entry
    lines += ["];", ""]
    path.write_text("\n".join(lines), encoding="utf-8")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--man", type=Path)
    ap.add_argument("--vscode", type=Path)
    args = ap.parse_args()
    cli_reference()
    rule_catalog()
    verification_page()
    copies()
    if args.man:
        man_page(args.man)
    if args.vscode:
        vscode_patterns(args.vscode)
    print(f"docs generated for leakscan {__version__}")


if __name__ == "__main__":
    main()

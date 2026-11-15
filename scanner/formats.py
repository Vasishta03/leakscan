"""Extra report formats: HTML, JUnit XML, Markdown, SonarQube, DefectDojo."""
from __future__ import annotations

import html
import json
from xml.sax.saxutils import escape, quoteattr

from scanner import __version__
from scanner.engine import ScanResult
from scanner.remediation import get_remediation
from scanner.reporter import REPO_URL, SEVERITY_ORDER, _display, _location, _sorted, finding_dict


def to_markdown(result: ScanResult, redact: bool = True, title: str = "leakscan results", limit: int = 50) -> str:
    findings = _sorted(result.findings)
    if not findings:
        return f"### {title}\n\nNo secrets found in {result.files_scanned} file(s).\n"
    counts = " · ".join(f"**{sum(1 for f in findings if f.severity == s)}** {s.lower()}"
                        for s in SEVERITY_ORDER if any(f.severity == s for f in findings))
    lines = [f"### {title}", "", f"{len(findings)} potential secret(s): {counts}", "",
             "| Severity | Rule | Type | Location | Match |", "|---|---|---|---|---|"]
    for f in findings[:limit]:
        loc = _location(f).replace("|", "\\|")
        match = _display(f.matched_value, redact).replace("|", "\\|").replace("`", "'")
        lines.append(f"| {f.severity} | `{f.rule_id}` | {f.secret_type} | `{loc}` | `{match}` |")
    if len(findings) > limit:
        lines.append(f"\n{len(findings) - limit} more not shown.")
    lines += ["", "Rotate anything real first, then remove it from history (`leakscan purge`). "
              "False positive? Add `# leakscan:ignore <RULE-ID>` to the line.", "",
              f"<sub>[leakscan]({REPO_URL}) {__version__}</sub>"]
    return "\n".join(lines) + "\n"


def to_junit(result: ScanResult, redact: bool = True) -> str:
    findings = _sorted(result.findings)
    out = ['<?xml version="1.0" encoding="UTF-8"?>',
           f'<testsuites name="leakscan" tests="{max(len(findings), 1)}" failures="{len(findings)}">',
           f'  <testsuite name="secrets" tests="{max(len(findings), 1)}" failures="{len(findings)}" errors="0">']
    if not findings:
        out.append('    <testcase classname="leakscan" name="no secrets found"/>')
    for f in findings:
        rem = get_remediation(f.secret_type)
        name = f"{f.rule_id} {_location(f)}"
        msg = f"{f.severity} {f.secret_type}: {_display(f.matched_value, redact)}"
        out.append(f'    <testcase classname={quoteattr(f.file)} name={quoteattr(name)}>')
        out.append(f'      <failure message={quoteattr(msg)} type={quoteattr(f.severity)}>'
                   f'{escape(rem.consequence)} Rotate at {escape(rem.rotation_url)}</failure>')
        out.append('    </testcase>')
    out += ['  </testsuite>', '</testsuites>']
    return "\n".join(out) + "\n"


def to_sonarqube(result: ScanResult, redact: bool = True) -> str:
    """SonarQube generic issue import format (sonar.externalIssuesReportPaths)."""
    sev = {"CRITICAL": "BLOCKER", "HIGH": "CRITICAL", "MEDIUM": "MAJOR", "LOW": "MINOR"}
    rules, issues = {}, []
    for f in _sorted(result.findings):
        rules[f.rule_id] = {
            "id": f.rule_id, "name": f.secret_type, "engineId": "leakscan",
            "description": get_remediation(f.secret_type).consequence,
            "cleanCodeAttribute": "TRUSTWORTHY", "type": "VULNERABILITY", "severity": sev.get(f.severity, "MAJOR"),
            "impacts": [{"softwareQuality": "SECURITY", "severity": "HIGH" if f.severity in ("CRITICAL", "HIGH") else "MEDIUM"}],
        }
        issues.append({
            "ruleId": f.rule_id,
            "primaryLocation": {
                "message": f"{f.secret_type} ({_display(f.matched_value, redact)})",
                "filePath": f.file,
                "textRange": {"startLine": max(f.line_number, 1)},
            },
        })
    return json.dumps({"rules": list(rules.values()), "issues": issues}, indent=2)


def to_defectdojo(result: ScanResult, redact: bool = True) -> str:
    """DefectDojo 'Generic Findings Import' JSON."""
    sev = {"CRITICAL": "Critical", "HIGH": "High", "MEDIUM": "Medium", "LOW": "Low"}
    out = []
    for f in _sorted(result.findings):
        rem = get_remediation(f.secret_type)
        out.append({
            "title": f"{f.secret_type} in {f.file}",
            "severity": sev.get(f.severity, "Info"),
            "description": f"{rem.consequence}\n\nMatch: {_display(f.matched_value, redact)}\nRule: {f.rule_id}",
            "mitigation": f"Rotate the credential at {rem.rotation_url} and remove it from history.",
            "impact": rem.blast_radius,
            "file_path": f.file,
            "line": f.line_number,
            "vuln_id_from_tool": f.rule_id,
            "unique_id_from_tool": f.fingerprint(),
            "cwe": 798,
            "static_finding": True,
            "dynamic_finding": False,
            "active": f.verification_status != "inactive",
            "verified": f.verification_status == "active",
        })
    return json.dumps({"findings": out}, indent=2)


_HTML = """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>leakscan report</title>
<style>
:root{--bg:#fff;--fg:#1b1f24;--mut:#59636e;--line:#d1d9e0;--crit:#b3261e;--high:#c2410c;--med:#a16207;--low:#4b5563;--chip:#f6f8fa}
@media (prefers-color-scheme:dark){:root{--bg:#0d1117;--fg:#e6edf3;--mut:#9198a1;--line:#30363d;--chip:#161b22;--crit:#ff7b72;--high:#ffa657;--med:#e3b341;--low:#9198a1}}
*{box-sizing:border-box}body{margin:0;padding:24px 16px;font:14px/1.5 system-ui,-apple-system,Segoe UI,sans-serif;background:var(--bg);color:var(--fg)}
main{max-width:1200px;margin:auto}h1{font-size:20px;margin:0 0 4px}.mut{color:var(--mut)}
.bar{display:flex;flex-wrap:wrap;gap:8px;margin:16px 0}.bar input{flex:1;min-width:200px;padding:8px;border:1px solid var(--line);border-radius:6px;background:var(--bg);color:var(--fg)}
.bar label{display:flex;align-items:center;gap:4px;padding:6px 10px;border:1px solid var(--line);border-radius:6px;background:var(--chip);cursor:pointer}
.wrap{overflow-x:auto}table{width:100%;border-collapse:collapse}th,td{text-align:left;padding:8px;border-bottom:1px solid var(--line);vertical-align:top}
th{font-weight:600;cursor:pointer;white-space:nowrap}code{font:12px ui-monospace,SFMono-Regular,Menlo,monospace;word-break:break-all}
.sev{font-weight:700}.CRITICAL{color:var(--crit)}.HIGH{color:var(--high)}.MEDIUM{color:var(--med)}.LOW{color:var(--low)}
details summary{cursor:pointer;color:var(--mut)}
</style></head><body><main>
<h1>leakscan report</h1>
<div class="mut">__SUMMARY__</div>
<div class="bar"><input id="q" placeholder="Filter by file, rule or type" aria-label="Filter">
__CHECKS__</div>
<div class="wrap"><table id="t"><thead><tr><th>Severity</th><th>Rule</th><th>Type</th><th>Location</th><th>Confidence</th><th>Status</th><th>Details</th></tr></thead>
<tbody>__ROWS__</tbody></table></div>
<p class="mut">Generated by <a href="__REPO__">leakscan</a> __VERSION__.</p>
</main><script>
const q=document.getElementById('q'),rows=[...document.querySelectorAll('#t tbody tr')];
function apply(){const t=q.value.toLowerCase(),on=new Set([...document.querySelectorAll('.bar input[type=checkbox]:checked')].map(c=>c.value));
rows.forEach(r=>{r.hidden=!(on.has(r.dataset.sev)&&r.textContent.toLowerCase().includes(t))})}
q.addEventListener('input',apply);document.querySelectorAll('.bar input[type=checkbox]').forEach(c=>c.addEventListener('change',apply));
</script></body></html>
"""


def to_html(result: ScanResult, redact: bool = True) -> str:
    findings = _sorted(result.findings)
    rows = []
    for f in findings:
        d = finding_dict(f, redact)
        status = (d["verification"] or {}).get("status", "")
        rows.append(
            f'<tr data-sev="{f.severity}"><td class="sev {f.severity}">{f.severity}</td>'
            f'<td><code>{html.escape(f.rule_id)}</code></td><td>{html.escape(f.secret_type)}</td>'
            f'<td><code>{html.escape(_location(f))}</code></td><td>{f.confidence:.2f}</td><td>{html.escape(status)}</td>'
            f'<td><details><summary>{html.escape(d["blast_radius"])}</summary><p><code>{html.escape(d["match"])}</code></p>'
            f'<p>{html.escape(get_remediation(f.secret_type).consequence)}</p>'
            f'<p><a href="{html.escape(d["rotation_url"])}" rel="noopener">Rotate</a>'
            f'{" · commit " + html.escape(f.commit) if f.commit else ""}</p></details></td></tr>'
        )
    counts = {s: sum(1 for f in findings if f.severity == s) for s in SEVERITY_ORDER}
    summary = (f"{len(findings)} finding(s) in {result.files_scanned} file(s)"
               + (f" and {result.commits_scanned} commit(s)" if result.commits_scanned else "") + ". "
               + ", ".join(f"{n} {s.lower()}" for s, n in counts.items() if n))
    checks = "".join(f'<label><input type="checkbox" value="{s}" checked> {s.title()} ({n})</label>'
                     for s, n in counts.items())
    return (_HTML.replace("__SUMMARY__", html.escape(summary)).replace("__CHECKS__", checks)
            .replace("__ROWS__", "\n".join(rows) or '<tr data-sev="LOW"><td colspan="7">No secrets found.</td></tr>')
            .replace("__REPO__", REPO_URL).replace("__VERSION__", __version__))

from __future__ import annotations

import os
from pathlib import Path
from typing import Optional

import requests

from scanner.engine import Finding, ScanResult

RC_FILENAME = ".leakscanrc"
_TIMEOUT = 5
_MAX_ITEMS = 10

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}

# Discord embed colors (decimal RGB) and Slack-side severity emoji.
SEVERITY_COLOR_HEX = {
    "CRITICAL": 0xC0392B,
    "HIGH": 0xE74C3C,
    "MEDIUM": 0xF1C40F,
    "LOW": 0x95A5A6,
}
SEVERITY_EMOJI = {
    "CRITICAL": ":rotating_light:",
    "HIGH": ":red_circle:",
    "MEDIUM": ":large_yellow_circle:",
    "LOW": ":white_circle:",
}
CLEAN_COLOR_HEX = 0x2ECC71
_RC_KEYS = {"slack": "SLACK_WEBHOOK_URL", "discord": "DISCORD_WEBHOOK_URL", "teams": "TEAMS_WEBHOOK_URL",
            "webhook": "WEBHOOK_URL"}
TARGETS = ("slack", "discord", "teams", "webhook", "email")


def _rc_path(path: Optional[Path] = None) -> Path:
    return path or (Path.home() / RC_FILENAME)


def load_rc(path: Optional[Path] = None) -> dict[str, str]:
    """Load simple KEY="VALUE" pairs from ~/.leakscanrc.

    Returns an empty dict if the file does not exist or can't be read.
    Used to store webhook URLs so they don't need to be passed on the
    command line every time.
    """
    rc_path = _rc_path(path)
    config: dict[str, str] = {}
    if not rc_path.is_file():
        return config
    try:
        for line in rc_path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            config[key.strip().upper()] = value.strip().strip('"').strip("'")
    except OSError:
        return {}
    return config


def save_webhook(kind: str, url: str, path: Optional[Path] = None) -> Path:
    """Persist a webhook URL to ~/.leakscanrc, creating or updating the file."""
    rc_path = _rc_path(path)
    config = load_rc(rc_path)
    config[_RC_KEYS.get(kind, "WEBHOOK_URL")] = url
    lines = [f'{k}="{v}"' for k, v in config.items()]
    rc_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    try:
        os.chmod(rc_path, 0o600)
    except OSError:
        pass
    return rc_path


def resolve_webhook(kind: str, explicit: Optional[str]) -> Optional[str]:
    """Return the webhook URL to use: an explicit CLI value, or one saved in ~/.leakscanrc."""
    if explicit:
        return explicit
    return load_rc().get(_RC_KEYS.get(kind, "WEBHOOK_URL")) or None


def _severity_counts(result: ScanResult) -> dict[str, int]:
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in result.findings:
        if f.severity in counts:
            counts[f.severity] += 1
    return counts


def _summary_line(counts: dict[str, int]) -> str:
    parts = [f"{n} {sev}" for sev, n in counts.items() if n]
    return ", ".join(parts) if parts else "0 findings"


def _top_findings(findings: list[Finding], limit: int = _MAX_ITEMS) -> list[Finding]:
    ordered = sorted(findings, key=lambda f: (SEVERITY_ORDER.get(f.severity, 9), f.file, f.line_number))
    return ordered[:limit]


def build_slack_payload(result: ScanResult, target: str, clean: bool = False) -> dict:
    """Build a Slack Block Kit message body for an incoming webhook."""
    if clean or not result.findings:
        return {
            "blocks": [
                {"type": "header", "text": {"type": "plain_text", "text": "leakscan: all clear"}},
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"Scanned *{target}*: {result.files_scanned} file(s), 0 secrets found.",
                    },
                },
            ]
        }

    counts = _severity_counts(result)
    blocks: list[dict] = [
        {
            "type": "header",
            "text": {"type": "plain_text", "text": f"leakscan found {len(result.findings)} secret(s)"},
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*Target:* {target}\n*Summary:* {_summary_line(counts)}",
            },
        },
        {"type": "divider"},
    ]

    top = _top_findings(result.findings)
    for f in top:
        emoji = SEVERITY_EMOJI.get(f.severity, "")
        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"{emoji} *[{f.severity}] {f.secret_type}*\n`{f.file}:{f.line_number}`",
            },
        })

    remaining = len(result.findings) - len(top)
    if remaining > 0:
        blocks.append({
            "type": "context",
            "elements": [{"type": "mrkdwn", "text": f"...and {remaining} more finding(s)."}],
        })

    return {"blocks": blocks}


def build_discord_payload(result: ScanResult, target: str, clean: bool = False) -> dict:
    """Build a Discord embed message body for a webhook."""
    if clean or not result.findings:
        return {
            "embeds": [{
                "title": "leakscan: all clear",
                "description": f"Scanned **{target}**: {result.files_scanned} file(s), 0 secrets found.",
                "color": CLEAN_COLOR_HEX,
            }]
        }

    counts = _severity_counts(result)
    top_severity = next((s for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW") if counts.get(s)), "LOW")
    color = SEVERITY_COLOR_HEX.get(top_severity, CLEAN_COLOR_HEX)

    top = _top_findings(result.findings)
    fields = [
        {
            "name": f"[{f.severity}] {f.secret_type}",
            "value": f"`{f.file}:{f.line_number}`",
            "inline": False,
        }
        for f in top
    ]

    embed = {
        "title": f"leakscan found {len(result.findings)} secret(s)",
        "description": f"**Target:** {target}\n**Summary:** {_summary_line(counts)}",
        "color": color,
        "fields": fields,
    }

    remaining = len(result.findings) - len(top)
    if remaining > 0:
        embed["footer"] = {"text": f"...and {remaining} more finding(s)."}

    return {"embeds": [embed]}


def _post(webhook_url: str, payload: dict) -> bool:
    try:
        r = requests.post(webhook_url, json=payload, timeout=_TIMEOUT)
        return r.status_code < 300
    except Exception:
        return False


def build_generic_payload(result: ScanResult, target: str) -> dict:
    from scanner.reporter import _redact
    return {
        "tool": "leakscan",
        "target": target,
        "summary": _severity_counts(result),
        "total": len(result.findings),
        "findings": [
            {"rule_id": f.rule_id, "severity": f.severity, "type": f.secret_type, "file": f.file,
             "line": f.line_number, "match": _redact(f.matched_value), "fingerprint": f.fingerprint()}
            for f in _top_findings(result.findings, 100)
        ],
    }


def build_teams_payload(result: ScanResult, target: str, clean: bool = False) -> dict:
    counts = _severity_counts(result)
    title = f"leakscan: no secrets found in {target}" if clean else f"leakscan: {len(result.findings)} secret(s) in {target}"
    facts = [{"title": f.severity, "value": f"{f.secret_type} - {f.file}:{f.line_number}"}
             for f in _top_findings(result.findings)]
    body: list[dict] = [
        {"type": "TextBlock", "text": title, "weight": "Bolder", "size": "Medium", "wrap": True},
        {"type": "TextBlock", "text": _summary_line(counts), "wrap": True},
    ]
    if facts:
        body.append({"type": "FactSet", "facts": facts})
    return {"type": "message", "attachments": [{
        "contentType": "application/vnd.microsoft.card.adaptive",
        "content": {"$schema": "http://adaptivecards.io/schemas/adaptive-card.json", "type": "AdaptiveCard",
                    "version": "1.4", "body": body},
    }]}


def send_email(result: ScanResult, target: str, rc: Optional[dict] = None) -> str:
    """Send a plain-text summary over SMTP. Settings come from env vars or ~/.leakscanrc:
    LEAKSCAN_SMTP_HOST, LEAKSCAN_SMTP_PORT, LEAKSCAN_SMTP_USER, LEAKSCAN_SMTP_PASSWORD,
    LEAKSCAN_EMAIL_FROM, LEAKSCAN_EMAIL_TO (comma separated)."""
    import smtplib
    import ssl
    from email.message import EmailMessage

    rc = rc if rc is not None else load_rc()

    def get(key: str) -> Optional[str]:
        return os.environ.get(key) or rc.get(key)

    host, to = get("LEAKSCAN_SMTP_HOST"), get("LEAKSCAN_EMAIL_TO")
    if not host or not to:
        return "--notify email needs LEAKSCAN_SMTP_HOST and LEAKSCAN_EMAIL_TO (env or ~/.leakscanrc)."
    port = int(get("LEAKSCAN_SMTP_PORT") or 587)
    msg = EmailMessage()
    msg["Subject"] = f"leakscan: {len(result.findings)} secret(s) in {target}"
    msg["From"] = get("LEAKSCAN_EMAIL_FROM") or get("LEAKSCAN_SMTP_USER") or "leakscan@localhost"
    msg["To"] = to
    lines = [f"{_summary_line(_severity_counts(result))} in {target}", ""]
    lines += [f"[{f.severity}] {f.rule_id} {f.secret_type} - {f.file}:{f.line_number}"
              for f in _top_findings(result.findings, 50)]
    msg.set_content("\n".join(lines))
    try:
        if port == 465:
            server: smtplib.SMTP = smtplib.SMTP_SSL(host, port, timeout=15, context=ssl.create_default_context())
        else:
            server = smtplib.SMTP(host, port, timeout=15)
            server.starttls(context=ssl.create_default_context())
        with server:
            user, pw = get("LEAKSCAN_SMTP_USER"), get("LEAKSCAN_SMTP_PASSWORD")
            if user and pw:
                server.login(user, pw)
            server.send_message(msg)
        return "Sent email notification."
    except (OSError, smtplib.SMTPException) as e:
        return f"Failed to send email notification ({e.__class__.__name__})."


def _parse_targets(notify: str) -> list[str]:
    if notify == "both":
        return ["slack", "discord"]
    return [t.strip() for t in notify.split(",") if t.strip()]


def send_notifications(
    result: ScanResult,
    target: str,
    notify: Optional[str],
    slack_webhook: Optional[str] = None,
    discord_webhook: Optional[str] = None,
    notify_clean: bool = False,
    teams_webhook: Optional[str] = None,
    generic_webhook: Optional[str] = None,
) -> list[str]:
    """Send notifications for a scan result. Returns status messages; never raises."""
    if not notify:
        return []
    if not result.findings and not notify_clean:
        return []

    explicit = {"slack": slack_webhook, "discord": discord_webhook, "teams": teams_webhook, "webhook": generic_webhook}
    messages: list[str] = []
    clean = not result.findings
    for kind in _parse_targets(notify):
        if kind == "email":
            messages.append(send_email(result, target))
            continue
        if kind not in explicit:
            messages.append(f"Unknown notification target '{kind}' (use {', '.join(TARGETS)}).")
            continue
        url = resolve_webhook(kind, explicit[kind])
        if not url:
            messages.append(
                f"--notify {kind} requested but no webhook URL is configured "
                f"(pass --{kind}-webhook or save {_RC_KEYS[kind]} to ~/.leakscanrc)."
            )
            continue
        if kind == "slack":
            payload = build_slack_payload(result, target, clean=clean)
        elif kind == "discord":
            payload = build_discord_payload(result, target, clean=clean)
        elif kind == "teams":
            payload = build_teams_payload(result, target, clean=clean)
        else:
            payload = build_generic_payload(result, target)
        if _post(url, payload):
            messages.append(f"Sent {kind} notification.")
        else:
            messages.append(f"Failed to send {kind} notification (request error or non-2xx response).")
    return messages

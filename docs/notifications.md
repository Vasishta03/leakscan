# Notifications

```bash
leakscan scan . --notify slack --slack-webhook https://hooks.slack.com/services/...
leakscan scan . --notify discord,teams
leakscan scan . --notify webhook --webhook https://example.com/hooks/leakscan
leakscan scan . --notify email
leakscan scan . --notify slack --notify-clean   # also notify when nothing is found
```

Targets: `slack`, `discord`, `teams`, `webhook` (generic JSON), `email`, or `both` (Slack and Discord). Values are
always redacted in notifications.

To avoid passing URLs every time, save them in `~/.leakscanrc` (written with mode 600):

```
SLACK_WEBHOOK_URL="https://hooks.slack.com/services/..."
DISCORD_WEBHOOK_URL="https://discord.com/api/webhooks/..."
TEAMS_WEBHOOK_URL="https://acme.webhook.office.com/webhookb2/..."
WEBHOOK_URL="https://example.com/hooks/leakscan"
LEAKSCAN_SMTP_HOST="smtp.example.com"
LEAKSCAN_SMTP_PORT="587"
LEAKSCAN_SMTP_USER="bot@example.com"
LEAKSCAN_SMTP_PASSWORD="..."
LEAKSCAN_EMAIL_TO="security@example.com,oncall@example.com"
```

The SMTP settings can also come from environment variables with the same names. The generic webhook receives:

```json
{"tool": "leakscan", "target": "...", "summary": {"CRITICAL": 0, "HIGH": 2, "MEDIUM": 1, "LOW": 0},
 "total": 3, "findings": [{"rule_id": "LS-GH-001", "severity": "HIGH", "type": "...", "file": "...",
 "line": 4, "match": "ghp_****...", "fingerprint": "..."}]}
```

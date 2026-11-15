# Outputs and exit codes

```bash
leakscan scan . --format json -o results.json
leakscan scan . -f json -o results.json --also sarif:results.sarif --also html:report.html
```

| Format | Use |
|---|---|
| `terminal` | Default. Full blocks per finding. Use `--brief` for a table. |
| `json` | Machine-readable, with a versioned schema (see below). |
| `sarif` | GitHub code scanning, Azure DevOps, most security dashboards. |
| `html` | A single self-contained page with severity filters and search. Easy to share. |
| `junit` | CI test reports (GitLab, Jenkins, CircleCI). |
| `markdown` | PR or MR comments and job summaries. |
| `csv` | Spreadsheets. |
| `sonarqube` | SonarQube generic issue import (`sonar.externalIssuesReportPaths`). |
| `defectdojo` | DefectDojo "Generic Findings Import". |
| `disclosure` | A responsible-disclosure write-up for a GitHub user's public repos. |

SARIF, HTML, Markdown, JUnit, SonarQube and DefectDojo always mask secret values, because they tend to get shared.
JSON, CSV and terminal output show values unless you pass `--redact`.

## JSON schema

Every JSON report has `"schema_version": "1.0"`. Fields are only ever added within a major schema version, so
parsers written against 1.0 keep working. Print the schema with `leakscan config schema --report`. It's also published at
`https://vasishta03.github.io/leakscan/schemas/report.schema.json`.

```json
{
  "rule_id": "LS-STRIPE-001",
  "severity": "HIGH",
  "confidence": 0.95,
  "type": "Stripe Live Secret Key",
  "file": "src/billing.py",
  "line": 12,
  "match": "sk_live_...",
  "source": "regex",
  "commit": null,
  "verification": {"status": "active", "checked_at": "2026-11-15T09:12:03+00:00", "error": null},
  "fingerprint": "3f1c9a0b2d4e5f60",
  "blast_radius": "Payment processing and customer financial data",
  "rotation_url": "https://dashboard.stripe.com/apikeys",
  "extra": {}
}
```

`extra` holds context that depends on the source: `cell` and `output_type` for notebooks, `layer` and `layer_digest`
for Docker, `repository` for remote scans, `encoding` for decoded values, `validation` and `jwt_expired`.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | No findings at or above `--fail-on` (default `HIGH`) |
| 1 | At least one finding at or above `--fail-on` |
| 2 | The scan failed: bad arguments, path not found, clone error, and so on |

`--exit-zero` always returns 0 when the scan itself works.

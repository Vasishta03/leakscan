# Security policy

## Supported versions

| Version | Supported |
|---------|-----------|
| 0.5.x   | Yes       |
| 0.4.x   | Security fixes until 2027-02-15 |
| < 0.4   | No        |

## Reporting a vulnerability

Please report security issues privately through GitHub:
https://github.com/Vasishta03/leakscan/security/advisories/new

Include what you found, how to reproduce it, and the impact. Don't open a public issue.

What to expect:

- An acknowledgement within 3 days.
- An initial assessment within 7 days.
- A fix or mitigation for confirmed high-severity issues within 30 days, with credit in the advisory if you'd like it.

Examples of what counts: leakscan leaking secrets it found (logs, cache, baselines, reports that should be redacted),
code execution or path traversal from scanning an untrusted repo, archive or image, ReDoS in rules or ignore files,
and verification requests sent somewhere other than the documented provider endpoint.

## What leakscan sends over the network

Nothing, unless you ask. There is no telemetry.

- `--verify` sends each detected secret to its own provider's API. The full list of endpoints is in
  `leakscan rules verifiers` and the [verification docs](https://vasishta03.github.io/leakscan/verification/).
- Remote targets (git URLs, `--github`, `--github-org`, `pypi:`, `npm:`, `docker://`) download from GitHub, PyPI,
  npm or your Docker registry.
- `--notify` posts a summary with redacted values to the webhook or SMTP server you configure.

## What leakscan stores

- Baselines (`--save-baseline`) store SHA-256 fingerprints, not secret values.
- `.leakscan-cache` stores file hashes for files with no findings, never secret values.
- `--resume` state files for org scans store redacted findings only.
- SARIF, HTML, Markdown, JUnit, SonarQube and DefectDojo reports always redact values. JSON, CSV and terminal output
  show full values unless you pass `--redact`.

## Responsible use

Scan code you own or are authorised to test. If you find someone else's live credential, tell the owner privately
and don't use it. `--verify` against third-party targets requires `--yes` for this reason.

## Release integrity

Releases are published from GitHub Actions with PyPI trusted publishing (no long-lived tokens), PEP 740
attestations, Sigstore signatures, SLSA build provenance and a CycloneDX SBOM. To verify a download:

```bash
gh attestation verify leakscan-0.5.0-py3-none-any.whl --repo Vasishta03/leakscan
```

# Privacy

leakscan has no telemetry, no analytics and no update checks. Network traffic only happens when you ask for it:

| You run | leakscan contacts |
|---|---|
| `--verify` | Each secret's own provider, one read-only request per secret ([full list](verification.md)) |
| a git URL, `--github`, `--github-org` | GitHub, GitLab, Bitbucket or the host in the URL |
| `pypi:` / `npm:` | pypi.org / registry.npmjs.org |
| `docker://` | your Docker daemon, which may pull from a registry |
| `--notify` | the webhook or SMTP server you configured, with redacted values |
| `rules import https://...` | that URL |

Nothing leakscan writes to disk contains secret values: baselines and caches store hashes, and org-scan resume files
store redacted findings. Reports meant for sharing (SARIF, HTML, Markdown, JUnit, SonarQube, DefectDojo) are always
redacted. See [SECURITY.md](https://github.com/Vasishta03/leakscan/blob/main/SECURITY.md) for how to report a
vulnerability.

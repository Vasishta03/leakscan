# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/). The JSON report has its own
`schema_version`, currently `1.0`.

## [Unreleased]

## [0.5.0] - 2026-11-15

CI-native, notebook-aware, benchmarked.

### Added

- New scan targets: stdin (`leakscan scan -`), `--text`, Jupyter notebooks (cells and outputs reported separately),
  archives (`--archives`: zip, tar, tar.gz, whl, jar, with size, member-count, ratio and depth limits), any git remote
  (GitHub, GitLab, Bitbucket, shallow clone with `--clone-depth`), GitHub orgs and users (`--github-org`, forks and
  archived toggles, `--repo-include` / `--repo-exclude`, resumable with `--resume`), Docker images
  (`docker://image:tag`, every layer plus image ENV and build history), PyPI and npm packages (`pypi:name==ver`,
  `npm:name@ver`) and `--follow` for growing log files.
- Diff scanning for CI: `--since-commit REF`, `--base BRANCH` and `--pr` (reads GitHub, GitLab, Bitbucket and Jenkins env vars).
- Stable rule IDs (`LS-AWS-001` and so on) in every output format, SARIF `ruleId`, config and inline ignores.
- `# leakscan:ignore` and `# leakscan:ignore LS-AWS-001,LS-GH-001` inline suppression. `nosec`, `gitleaks:allow` and
  `secretscanner:allow` still work.
- 101 new rules (208 total), including Mistral, Together, Fireworks, Perplexity, DeepSeek, xAI, Weights & Biases,
  Comet, Kaggle, Modal, Cerebras, OpenRouter, LangSmith, Stripe restricted keys and webhook secrets, Okta, Auth0, Clerk,
  Snowflake, Databricks, Algolia, Resend, Neon, Upstash, Turso, Render, Netlify, Heroku, GitHub fine-grained tokens,
  Docker Hub, Tailscale, 1Password, plus file-aware rules for Dockerfile ENV/ARG, .env files, Terraform state and
  tfvars, Kubernetes secrets and Helm values, GitHub Actions workflows, docker-compose, .npmrc, .pypirc and .netrc.
- Validation: GitHub token CRC32 checksums, Luhn for card numbers, JWT structure plus expiry, AWS key ID alphabet.
- A `confidence` score on every finding, raised by nearby keywords and lowered in tests, fixtures and docs. Filter with `--min-confidence`.
- Placeholder and stopword filtering (`EXAMPLE`, `changeme`, `xxxx`, `${VAR}`, `<your-key>`, common dummy passwords).
- `--decode` decodes base64, hex and URL-encoded values one level before matching.
- Config: `allowlist` (regexes, paths, commits, stopwords), `disable_rules`, `extends:`, per-directory `overrides`,
  `fail_on`, plus `leakscan config validate` and `leakscan config schema` (JSON schema for editors).
- Rule packs: `leakscan rules list | show | disable | enable | import | remove | verifiers`.
- Verification: 18 more verifiers (51 secret types), `--verify-only`, `--verify-timeout`, `--verify-concurrency`, rate
  limiting, and statuses `active` / `inactive` / `unknown` / `error` with a timestamp in every format. `--yes` is
  required to verify keys found in targets you may not own.
- Outputs: `html` (single file, filterable), `junit`, `markdown` (PR comments), `sonarqube`, `defectdojo`, and
  `--also FORMAT:FILE` to write several formats from one run. JSON output now has `schema_version` and a published
  JSON schema.
- `--fail-on SEVERITY` and `--exit-zero`. Exit codes are documented: 0 clean, 1 findings, 2 error.
- Official GitHub Action (`uses: Vasishta03/leakscan@v1`) with SARIF upload, job summary, PR comments and full/pr/history modes.
- Python API: `leakscan.scan_path()`, `scan_text()`, `scan_git()`, `scan_diff()`, with `py.typed`.
- `leakscan hook` (Claude Code and Cursor hooks that block secrets in agent tool calls) and `leakscan mcp` (MCP server).
- Notifications: Microsoft Teams, generic JSON webhook and email (SMTP), alongside Slack and Discord. `--notify` takes a comma list.
- `--cache` skips unchanged clean files using `.leakscan-cache`. The cache stores hashes only, never secrets.
- `leakscan completion bash|zsh|fish`.
- Docker image on GHCR (`ghcr.io/vasishta03/leakscan`, amd64 and arm64), standalone binaries for Linux, macOS and Windows,
  PyPI trusted publishing with attestations, Sigstore signatures, build provenance and a CycloneDX SBOM per release.
- Benchmarks against gitleaks and trufflehog (`benchmarks/`), with methodology and raw results.
- Documentation site, rule catalog with one page per rule, CI recipes, and a LICENSE file.

### Changed

- Repository renamed from `secret-scanner` to `leakscan`. Old URLs redirect, and the PyPI package name is unchanged.
- Findings use paths relative to the scan root with forward slashes, which fixes SARIF locations in GitHub code scanning.
- SARIF `ruleId` is now the stable rule ID instead of the rule name. Share-oriented formats (SARIF, HTML, Markdown,
  JUnit, SonarQube, DefectDojo) always redact matched values.
- Keyword prefiltering and a process pool for large trees: about 2.5x faster per core than 0.4.0 with twice the rules.
- Git history is streamed from a single `git log -p` instead of one `git show` per commit.
- `PEM Certificate` is now LOW and skips system CA bundles.
- Placeholder values that 0.4.0 reported (such as AWS's documented `AKIAIOSFODNN7EXAMPLE`) are now ignored. Pass `--keep-placeholders` to see them.
- PyYAML is now a required dependency, and tqdm has been dropped. In 0.4.0, `.leakscan.yaml` was silently ignored when PyYAML was missing.

### Fixed

- `exclude_paths` in `.leakscan.yaml` and `pyproject.toml` was parsed but never applied.
- The entropy detector flagged every base64 line inside PEM blocks, which meant thousands of false positives in repos with test certificates.
- Verifiers reported `REVOKED` on rate limits and server errors. These now come back as `unknown`.
- The `aws_secret_access_key = "..."` pattern missed keys whose variable name was longer than 20 characters.
- UTF-16 files were skipped as binary, and Latin-1 files lost characters. Both are now decoded correctly.
- Symlinks pointing outside the scanned directory are no longer followed.
- `.leakscanignore` / `.secretignore` patterns with more than two `**` segments could hang a scan through regex backtracking.
- `~/.leakscanrc` is written with `0600` permissions.

## [0.4.0] - 2026-06-10

### Added

- 23 new secret patterns (107 total, up from 84): MongoDB, PostgreSQL, MySQL,
  and Redis connection strings, PEM certificates, Docker config auth,
  Kubernetes service account tokens, Firebase Admin SDK keys, Expo access
  tokens, Fly.io API tokens, WireGuard private keys, PagerDuty API keys,
  Elastic Cloud API keys, Azure AD client secrets, Cohere keys, Groq keys,
  Pinecone keys, Atlassian API tokens, PayPal client secrets, Razorpay key
  IDs, Postmark server tokens, Railway API tokens, and Cloudflare API tokens.
- Live verification for 11 more services (32 total, up from 21): Cohere,
  Groq, Pinecone, Notion, Linear, Mailgun, Postmark, Cloudflare, Railway,
  Supabase, and Azure AD.
- Multi-threaded scanning with a configurable `--threads` flag, a tqdm
  progress bar, and a benchmark summary (files scanned, elapsed time,
  files/sec).
- Memory-efficient chunked file reading with `--chunk-size`, automatic binary
  file detection, and `--max-file-size` to skip oversized files with a
  warning instead of loading them into memory.
- A `.pre-commit-hooks.yaml` entry so leakscan can be added to any repo's
  pre-commit configuration directly from the pre-commit hooks registry.
- Severity blast-radius blocks: every finding now explains what an attacker
  can do with the secret, how serious that is, and where to rotate it. Pass
  `--brief` for the previous compact table output.
- Git blame integration: findings in a working tree show who committed the
  secret, when, on which branch, and how long ago. Pass `--no-blame` to skip
  this.
- Secret age and scraping-risk classification (LOW, MEDIUM, HIGH, CRITICAL),
  with warnings for secrets older than 30 days ("HIGH probability scraped by
  bots") and 90 days ("ASSUME COMPROMISED").
- `.leakscanignore` file support with gitignore-style globs, `!pattern`
  negation, and trailing-slash directory rules, plus `leakscan ignore
  <pattern>` and `leakscan init` commands. The legacy `.secretignore`
  filename is still read.
- `--show-ignored` to list files skipped because of `.leakscanignore`.
- `leakscan purge`: generates (but does not run) `git filter-repo` and BFG
  Repo-Cleaner commands to remove a file, redact a commit's secrets, or
  redact every leaked value from git history, plus a force-push warning and
  a rotation reminder.
- Slack and Discord webhook notifications with `--notify slack/discord/both`,
  `--slack-webhook` / `--discord-webhook` / `--webhook`, `--notify-clean`,
  and credentials stored in `~/.leakscanrc`.

### Changed

- Default terminal output now prints a full blast-radius block per finding
  instead of a compact table. Pass `--brief` for the previous table format.
- The pre-commit hook (`leakscan install-hook` and `.pre-commit-hooks.yaml`)
  now runs with `--brief --no-blame` for faster, quieter output on staged
  changes.

## [0.3.1] - 2026-06-08

- Bumped to 0.3.1, added GitHub Actions publish workflow.

## [0.3.0]

- Staged scanning, custom `.leakscan.yaml` / `pyproject.toml` configuration,
  20+ new patterns, and expanded live verifiers.

## [0.2.0]

- Live verification, 55+ patterns, SARIF output, baseline mode, GitHub gist
  scanning, and parallel scanning.

[Unreleased]: https://github.com/Vasishta03/leakscan/compare/v0.5.0...HEAD
[0.5.0]: https://github.com/Vasishta03/leakscan/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/Vasishta03/leakscan/compare/v0.3.1...v0.4.0
[0.3.1]: https://github.com/Vasishta03/leakscan/compare/v0.3.0...v0.3.1

# Scanning

## Local files

```bash
leakscan scan .                    # whole tree, respecting .leakscanignore
leakscan scan src/settings.py      # one file
leakscan scan . --archives         # also look inside zip/tar/whl/jar
leakscan scan . --decode           # also decode base64/hex/url-encoded values
leakscan scan . --cache            # skip files that were clean last time
```

`.git`, `node_modules`, `__pycache__` and virtualenvs are skipped. Binary files are detected and skipped. UTF-16 and
Latin-1 files are decoded properly. Symlinks pointing outside the scanned folder are not followed.

## Notebooks

`.ipynb` files are parsed as JSON. Code cells and outputs (stdout, results, error tracebacks) are scanned
separately, and each finding records `cell` and `output_type`. That means a key that was only *printed* in an old
output still gets caught. Embedded images are skipped.

## Only what changed

```bash
leakscan scan . --staged              # staged changes (what the pre-commit hook runs)
leakscan scan . --since-commit HEAD~5 # lines added since a commit
leakscan scan . --base main           # lines added on this branch vs main
leakscan scan . --pr                  # in CI: reads GITHUB_BASE_REF / GitLab / Bitbucket / Jenkins env vars
```

`--pr` and `--base` need the base branch fetched, so use `fetch-depth: 0` in GitHub Actions.

## Git history

```bash
leakscan scan . --history                       # last 100 commits, all branches
leakscan scan . --history --max-commits 5000    # more
leakscan scan . --history --since 2024-01-01 --branch main
```

History is streamed from one `git log -p`, so memory stays flat on big repos.

## Remote sources

```bash
leakscan scan https://github.com/owner/repo                 # shallow clone, then scan
leakscan scan https://gitlab.com/group/sub/project --history
leakscan scan git@bitbucket.org:team/repo.git
leakscan scan --github someone --include-gists              # every public repo of a user
leakscan scan --github-org acme --repo-exclude "*-archive" --resume acme.json
leakscan scan docker://python:3.12-slim                     # needs the docker CLI
leakscan scan pypi:requests==2.32.3
leakscan scan npm:@scope/pkg@1.2.3
```

Org scans skip forks and archived repos unless you pass `--include-forks` or `--include-archived`. With `--resume`,
the state file records which repos are done, so an interrupted scan picks up where it left off. That file only
contains redacted findings.

Docker scans read the image config (`ENV` values and the build history, where `ARG` secrets usually leak) and then
every layer. Each finding records the layer index and digest.

## stdin, strings and logs

```bash
cat .env | leakscan scan -
leakscan scan --text "Authorization: Bearer ..."
leakscan scan /var/log/app.log --follow
```

## Filtering

```bash
leakscan scan . --severity HIGH            # report HIGH and CRITICAL only
leakscan scan . --min-confidence 0.6       # drop low-confidence matches
leakscan scan . --disable-rule LS-GEN-003  # skip one rule
leakscan scan . --baseline .secrets.baseline
```

Suppress a single line with `# leakscan:ignore` (every rule) or `# leakscan:ignore LS-AWS-001,LS-GH-001` (just those).
`# nosec`, `# gitleaks:allow` and `# secretscanner:allow` also work. The comment style doesn't matter, so `//` and
`--` work too.

## Cleaning up history

```bash
leakscan purge --file config/secrets.yaml
leakscan purge --commit a1b2c3d4
```

This prints `git filter-repo` and BFG commands for you to review. leakscan never rewrites history itself. Rotate the
credential first, because rewriting history doesn't un-leak it.

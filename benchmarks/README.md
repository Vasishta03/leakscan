# Benchmarks

Run on Linux-6.12.116+deb13-amd64-x86_64, 20 CPUs, Python 3.13.5, on 2026-11-15.
Versions: leakscan, version 0.5.0, gitleaks 8.30.1, trufflehog 3.99.7.

Reproduce:

```bash
pip install -e .
python benchmarks/run.py --gitleaks $(which gitleaks) --trufflehog $(which trufflehog)
```

Repos are pinned (`https://github.com/psf/requests.git@v2.32.3`, `https://github.com/django/django.git@5.1`). Every tool runs with verification off and its default rules. Times are the median of 3 runs. Memory is the peak RSS of the largest single process. leakscan uses a process pool on large trees, so its total across workers is higher than shown.

## Filesystem scan

| Repo | Tool | Time | Peak RSS | Findings |
|---|---|---|---|---|
| requests (129 files) | leakscan | 1.02 s | 47.6 MB | 11 |
| requests (129 files) | gitleaks | 0.42 s | 90.9 MB | 4 |
| requests (129 files) | trufflehog | 1.63 s | 296.2 MB | 19 |
| django (6815 files) | leakscan | 2.17 s | 59.7 MB | 28 |
| django (6815 files) | gitleaks | 1.54 s | 120.4 MB | 6 |
| django (6815 files) | trufflehog | 2.21 s | 355.8 MB | 9 |

## Git history (requests, 6294 commits)

| Tool | Time | Peak RSS | Findings |
|---|---|---|---|
| leakscan | 4.31 s | 78.3 MB | 15 |
| gitleaks | 0.97 s | 128.2 MB | 13 |
| trufflehog | 2.76 s | 291.1 MB | 44 |

## Planted-secret coverage

One synthetic secret per leakscan rule (208 total), each placed inside a real source file from requests.

| Tool | Files flagged |
|---|---|
| leakscan | 208 / 208 |
| gitleaks | 107 / 208 |
| trufflehog | 72 / 208 |

**This corpus favours leakscan by construction.** It's generated from leakscan's own rule fixtures, so it only measures how many of *these* formats each tool knows about. trufflehog detects many services leakscan doesn't, and those aren't in this test. Treat it as a coverage check, not an accuracy score.

## What this shows

- gitleaks is the fastest, by 2.4x on the requests tree and 4.4x on its history. It's a compiled Go program, and leakscan's history scan is single-threaded Python.
- leakscan had the lowest per-process memory, and was about as fast as trufflehog on filesystem scans. On large trees it starts one worker per CPU, so total memory grows with core count. Use `--threads` to cap it.
- "Findings" on real repos is not a precision score. Most hits in these repos are test fixtures: private keys in `tests/certs`, sample passwords in test settings. Each tool draws the line differently.

Raw numbers are in [results.json](results.json).

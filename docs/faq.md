# FAQ

**It flagged something in a test file. How do I make it stop?**
Add `# leakscan:ignore LS-XXX-000` to the line, add the path to `allowlist.paths` in `.leakscan.yaml`, or use a
baseline. Findings in test, fixture and docs paths already get a lower confidence score, so `--min-confidence 0.6`
hides most of them.

**Why didn't it report `AKIAIOSFODNN7EXAMPLE`?**
That's AWS's documentation key. Values containing words like `EXAMPLE`, `changeme`, `placeholder` or long runs of the
same character are treated as placeholders. Use `--keep-placeholders` to see them anyway.

**A GitHub token in my code wasn't flagged.**
Real GitHub tokens end in a CRC32 checksum, and leakscan drops tokens whose checksum doesn't match, because they're
fake. `--no-validate` turns that off.

**Does `--verify` use up my quota or cost money?**
Each check is one read-only request to an endpoint like "list models" or "who am I". None of them create anything or
call paid endpoints.

**Is it safe to scan untrusted repos or images?**
leakscan never executes scanned content. Archives are read in memory with size, member-count, compression-ratio and
depth limits. Symlinks pointing outside the scan root are ignored. Ignore-file globs are checked for catastrophic
backtracking. Clones run with `GIT_TERMINAL_PROMPT=0`.

**How is it different from gitleaks and trufflehog?**
See [Comparison](comparison.md). gitleaks is faster, and trufflehog verifies more services.

**Why Python?**
It installs anywhere Python does, has a Python API, and is easy to extend. The hot loop uses a keyword prefilter and a
process pool, and it's fast enough for pre-commit and CI. For very large history scans, gitleaks is quicker.

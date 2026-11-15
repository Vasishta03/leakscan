# Python API

```python
import leakscan

result = leakscan.scan_path("src/", archives=True)
print(result.files_scanned, len(result.findings))
for f in result.findings:
    print(f.rule_id, f.severity, f.confidence, f.file, f.line_number)

findings = leakscan.scan_text(open("Dockerfile").read(), filename="Dockerfile")
history = leakscan.scan_git(".", max_commits=1000, since="2025-01-01")
pr = leakscan.scan_diff(".", base="origin/main...HEAD")

print(leakscan.to_json(result, redact=True))
```

| Function | Returns |
|---|---|
| `scan_path(path, *, options=None, disable=(), entropy=True, threads=None, archives=False)` | `ScanResult` |
| `scan_text(text, *, filename="<text>", options=None, disable=(), entropy=True)` | `list[Finding]` |
| `scan_git(repo=".", *, max_commits=100, since=None, branch=None, options=None, ...)` | `ScanResult` |
| `scan_diff(repo=".", *, base="HEAD", options=None, entropy=True)` | `ScanResult` |
| `rules()` | `list[Pattern]` |
| `to_json(result, redact=False)`, `to_sarif(result)` | `str` |

`Finding` fields: `rule_id`, `secret_type`, `severity`, `confidence`, `file`, `line_number`, `line`,
`matched_value`, `source`, `commit`, `entropy`, `extra`, `verification_status`, `verified_at`, and `fingerprint()`.

For finer control, build a `leakscan.ScanOptions` (allowlists, disabled rules, decoding, extra rules) and pass it as
`options=`. The package ships `py.typed`. From 1.0, everything in `leakscan.__all__` follows semver.

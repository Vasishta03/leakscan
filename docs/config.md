# Configuration

leakscan reads `.leakscan.yaml` from the scanned folder, or `[tool.leakscan]` in `pyproject.toml`. Pass
`--config FILE` to use something else. Check a file with `leakscan config validate`.

```yaml
# .leakscan.yaml
extends: ../shared/leakscan-base.yaml   # optional, relative path

severity: MEDIUM          # report MEDIUM and above
fail_on: HIGH             # exit 1 on HIGH and above
entropy_threshold: 4.5
decode: false
archives: false

exclude_paths:            # gitignore-style, also read from .leakscanignore
  - "vendor/**"
  - "*.min.js"

disable_rules:
  - LS-GEN-003

allowlist:
  regexes: ["^AKIA.*TEST$"]       # matched against the secret value
  paths: ["tests/fixtures/**"]    # findings in these files are dropped
  commits: ["9f2c1ab"]            # history scans skip these commits
  stopwords: ["sandbox", "dummy"] # values containing these words are dropped

overrides:                         # per-directory rules
  - paths: ["docs/**"]
    disable_rules: [LS-GEN-001, LS-GEN-002]

rules:                             # your own rules
  - id: LS-ACME-001
    name: Acme Internal Token
    regex: "acme_[a-z0-9]{32}"
    severity: HIGH
    path: "\\.py$"                 # optional: only these files
```

## Editor support

The config has a JSON schema. Print it with `leakscan config schema`, or point your editor at
`https://vasishta03.github.io/leakscan/schemas/config.schema.json`. In VS Code, with the YAML extension:

```json
"yaml.schemas": {"https://vasishta03.github.io/leakscan/schemas/config.schema.json": ".leakscan.yaml"}
```

## Rule packs

Shareable YAML files of extra rules. Imported packs live in `~/.config/leakscan/rules/` and load for every scan.

```bash
leakscan rules import https://example.com/acme-rules.yaml
leakscan rules import ./team-rules.yaml --name team
leakscan rules list --search acme
leakscan rules remove team
```

```yaml
name: acme
rules:
  - id: LS-ACME-001
    name: Acme Key
    regex: "acme_[0-9a-f]{32}"
    severity: HIGH
    examples:
      positive: ["acme_0123456789abcdef0123456789abcdef"]
      negative: ["acme_short"]
```

On import, every rule's examples are checked, and broken rules are rejected. Packs contain regexes only, never code.

## Project-level rule toggles

```bash
leakscan rules disable LS-GEN-003    # writes disable_rules in ./.leakscan.yaml
leakscan rules enable LS-GEN-003
leakscan rules show LS-AWS-001       # regex, blast radius, rotation link
```

## Ignore file

`.leakscanignore` uses `.gitignore` syntax, including `**`, trailing `/` for directories and `!` to re-include.
Create a starter file with `leakscan init`, and add patterns with `leakscan ignore "fixtures/"`.

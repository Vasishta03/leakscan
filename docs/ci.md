# CI recipes

## GitHub Actions

```yaml
name: secrets
on: [push, pull_request]
permissions:
  contents: read
  security-events: write   # SARIF upload
  pull-requests: write     # only for pr-comment
jobs:
  leakscan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - uses: Vasishta03/leakscan@v1
        with:
          mode: pr            # full | pr | history
          fail-on: HIGH       # CRITICAL | HIGH | MEDIUM | LOW | none
          pr-comment: true
          # version: 0.5.0    # pin a leakscan version
          # baseline: .secrets.baseline
          # args: --archives --decode
```

The action writes a job summary, uploads SARIF to the Security tab, and can post or update one PR comment. Its
outputs are `findings`, `exit-code` and `sarif-file`.

## GitLab CI

```yaml
leakscan:
  image: ghcr.io/vasishta03/leakscan:latest
  entrypoint: [""]
  script:
    - leakscan scan . --pr --no-progress -f junit -o leakscan.xml --also sarif:gl-secret-detection.sarif
  artifacts:
    when: always
    reports:
      junit: leakscan.xml
    paths: [gl-secret-detection.sarif]
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
```

`--pr` reads `CI_MERGE_REQUEST_TARGET_BRANCH_NAME`. Set `GIT_DEPTH: 0` if the target branch isn't fetched.

## Jenkins

```groovy
stage('Secrets') {
  steps {
    sh 'pipx run leakscan scan . --no-progress -f junit -o leakscan.xml || test $? -eq 1'
  }
  post { always { junit 'leakscan.xml' } }
}
```

On multibranch PR builds, `--pr` reads `CHANGE_TARGET`.

## CircleCI

```yaml
jobs:
  leakscan:
    docker:
      - image: ghcr.io/vasishta03/leakscan:latest
    steps:
      - checkout
      - run: leakscan scan . --no-progress -f junit -o results/leakscan.xml
      - store_test_results:
          path: results
```

## Bitbucket Pipelines

```yaml
pipelines:
  pull-requests:
    '**':
      - step:
          image: ghcr.io/vasishta03/leakscan:latest
          script:
            - leakscan scan . --pr --no-progress
```

## pre-commit

```yaml
repos:
  - repo: https://github.com/Vasishta03/leakscan
    rev: v0.5.0
    hooks:
      - id: leakscan          # staged changes only
      # - id: leakscan-full   # whole tree, run with `pre-commit run --hook-stage manual leakscan-full`
```

Or skip the framework: `leakscan install-hook`.

## Baselines for existing repos

Turning on a scanner in an old repo usually turns up findings you can't fix today. Record them once, then fail only
on new ones:

```bash
leakscan scan . --save-baseline .secrets.baseline --exit-zero
git add .secrets.baseline
leakscan scan . --baseline .secrets.baseline
```

Baselines store fingerprints, not secret values.

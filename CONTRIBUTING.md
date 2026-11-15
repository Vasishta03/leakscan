# Contributing

Thanks for helping. Bug reports, new rules and docs fixes are all welcome.

## Setup

```bash
git clone https://github.com/Vasishta03/leakscan
cd leakscan
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
pytest -q && ruff check . && mypy
```

## Add a rule in 10 minutes

1. **Add the rule** in `scanner/patterns.py`. Give it the next free ID in its group, and never reuse or renumber IDs:

   ```python
   _p("LS-ACME-001", "Acme API Key", r"\bacme_[A-Za-z0-9]{32}\b", "HIGH", "Acme API key"),
   ```

   Prefer a distinctive prefix. If the secret has none, use `_ctx("LS-ACME-002", "Acme Secret", "acme", r"[a-f0-9]{40}", ...)`,
   which anchors on a keyword such as `ACME_SECRET=...`.

2. **Add fixtures** in `tests/corpus.py`: one line that must match and one near miss that must not. Use the `R()` / `H()`
   helpers so no literal token ends up in the repo:

   ```python
   "LS-ACME-001": (f"acme_{R(32)}", f"acme_{R(10)}", None),
   ```

3. **Add remediation** in `scanner/remediation.py`: what an attacker can do with it, a short blast-radius label, and the
   page where you rotate it.

4. **Optional: a verifier.** If the provider has a cheap, read-only "who am I" endpoint, add it to `BEARER_CHECKS` in
   `scanner/verifier.py`. Never use an endpoint that costs money or changes state.

5. Run `pytest tests/test_rules.py`. CI fails if any rule is missing fixtures.

## Pull requests

- Keep PRs focused. Add a line to `CHANGELOG.md` under `[Unreleased]`.
- New behaviour needs a test. Bug fixes should include a test that fails without the fix.
- Don't commit real secrets, even revoked ones. Generate them in tests.

## Releasing (maintainers)

1. Bump `__version__` in `scanner/__init__.py` and move the `[Unreleased]` notes into a new version section.
2. `git tag vX.Y.Z && git push --tags`. The release workflow publishes to PyPI, GHCR and GitHub Releases.
3. Move the `v1` tag for the GitHub Action: `git tag -f v1 && git push -f origin v1`.

## Code of conduct

This project follows the [Contributor Covenant](CODE_OF_CONDUCT.md).

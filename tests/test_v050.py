import io
import json
import os
import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path

import pytest
from click.testing import CliRunner

import leakscan
from scanner.cli import cli
from scanner.engine import (
    Finding,
    ScanOptions,
    ScanResult,
    check_line,
    is_placeholder,
    scan_diff,
    scan_git_history,
    scan_path,
)
from tests.corpus import H, R, gh

TOKEN = gh("ghp")
STRIPE = "sk_live_" + R(24)


def _rules(findings):
    return {f.rule_id for f in findings}


# detection quality

def test_inline_ignore_specific_rule_only():
    line = f'a = "{TOKEN}"; b = "{STRIPE}"  # leakscan:ignore LS-GH-001'
    ids = _rules(check_line(line, 1, "x.py", ScanOptions(no_entropy=True)))
    assert "LS-GH-001" not in ids and "LS-STRIPE-001" in ids


def test_inline_ignore_all_and_legacy_markers():
    for marker in ("# leakscan:ignore", "# nosec", "// gitleaks:allow", "# secretscanner:allow"):
        assert not check_line(f'k = "{TOKEN}"  {marker}', 1, "x.py", ScanOptions())


@pytest.mark.parametrize("value", ["AKIAIOSFODNN7EXAMPLE", "sk_live_changeme_changeme_changeme", "xxxxxxxxxxxxxxxxxxxxxxxx",
                                   "${STRIPE_KEY}", "{{ api_key }}", "<your-api-key-here>", "4242424242424242"])
def test_placeholders_detected(value):
    assert is_placeholder(value)


def test_placeholder_not_reported_but_flag_keeps_it():
    line = "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE"
    assert not check_line(line, 1, "x", ScanOptions(no_entropy=True))
    assert check_line(line, 1, "x", ScanOptions(no_entropy=True, placeholders=False))


def test_github_checksum_strict():
    bad = TOKEN[:-1] + ("A" if TOKEN[-1] != "A" else "B")
    assert "LS-GH-001" in _rules(check_line(f't="{TOKEN}"', 1, "x", ScanOptions(no_entropy=True)))
    assert "LS-GH-001" not in _rules(check_line(f't="{bad}"', 1, "x", ScanOptions(no_entropy=True)))
    assert "LS-GH-001" in _rules(check_line(f't="{bad}"', 1, "x", ScanOptions(no_entropy=True, validate=False)))


def test_confidence_lower_in_test_paths_and_higher_near_keywords():
    a = check_line(f"x = {STRIPE}", 1, "src/app.py", ScanOptions(no_entropy=True))[0]
    b = check_line(f"x = {STRIPE}", 1, "tests/fixtures/app.py", ScanOptions(no_entropy=True))[0]
    c = check_line(f"secret_token = {STRIPE}", 1, "src/app.py", ScanOptions(no_entropy=True))[0]
    assert b.confidence < a.confidence < c.confidence


def test_jwt_expired_flagged():
    from tests.corpus import jwt
    token = jwt({"alg": "HS256", "typ": "JWT"}, {"sub": "x", "exp": 1000})
    f = check_line(f"auth = {token}", 1, "x", ScanOptions(no_entropy=True))
    assert any(x.extra.get("jwt_expired") for x in f)


def test_allowlist_regex_path_and_stopword():
    opts = ScanOptions(no_entropy=True)
    import re
    opts.allow_regexes.append(re.compile("^sk_live_"))
    assert not check_line(f"k={STRIPE}", 1, "a.py", opts)
    opts2 = ScanOptions(no_entropy=True, allow_paths=["fixtures/**"])
    assert not check_line(f"k={STRIPE}", 1, "fixtures/a.py", opts2)
    opts3 = ScanOptions(no_entropy=True, stopwords=[STRIPE[10:16].lower()])
    assert not check_line(f"k={STRIPE}", 1, "a.py", opts3)


def test_decode_base64_hex_url():
    import base64
    from urllib.parse import quote
    enc = base64.b64encode(f"token={TOKEN}".encode()).decode()
    assert not check_line(f"x = {enc}", 1, "a", ScanOptions(no_entropy=True))
    found = check_line(f"x = {enc}", 1, "a", ScanOptions(no_entropy=True, decode=True))
    assert any(f.source == "decoded-base64" and f.rule_id == "LS-GH-001" for f in found)
    hexed = f"stripe={STRIPE}".encode().hex()
    assert any(f.source == "decoded-hex" for f in check_line(hexed, 1, "a", ScanOptions(no_entropy=True, decode=True)))
    url = "u=" + quote(f"https://x.io/?k={STRIPE}", safe="").replace("_", "%5F")
    assert any(f.source == "decoded-url" for f in check_line(url, 1, "a", ScanOptions(no_entropy=True, decode=True)))


def test_path_scoped_rules():
    line = f"ENV DB_PASSWORD={R(16)}"
    assert "LS-IAC-001" in _rules(check_line(line, 1, "docker/Dockerfile", ScanOptions(no_entropy=True)))
    assert "LS-IAC-001" not in _rules(check_line(line, 1, "notes.py", ScanOptions(no_entropy=True)))


def test_luhn_card_validation():
    from tests.corpus import luhn_number
    good = luhn_number("5412", 16)
    bad = good[:-1] + str((int(good[-1]) + 1) % 10)
    assert "LS-PII-001" in _rules(check_line(f"card={good}", 1, "a", ScanOptions(no_entropy=True)))
    assert "LS-PII-001" not in _rules(check_line(f"card={bad}", 1, "a", ScanOptions(no_entropy=True)))
    assert "LS-PII-001" not in _rules(check_line(f"id={good}", 1, "a", ScanOptions(no_entropy=True)))


@pytest.mark.parametrize("line", ["POSTGRES_PASSWORD: postgres", "redis://username:password@localhost:6379",
                                  "secret = _get_new_csrf_string", 'SECRET_KEY = "django_tests_secret_key"',
                                  "http://user:pass@example.com"])
def test_common_false_positives_suppressed(line):
    path = ".github/workflows/ci.yml" if line.startswith("POSTGRES") else "app/settings.py"
    assert not [f for f in check_line(line, 1, path, ScanOptions(no_entropy=True)) if f.severity != "LOW"]


# new sources

def _nb(cells):
    return json.dumps({"cells": cells, "metadata": {}, "nbformat": 4, "nbformat_minor": 5})


def test_notebook_cells_and_outputs(tmp_path):
    nb = _nb([
        {"cell_type": "markdown", "source": ["# title\n"]},
        {"cell_type": "code", "source": ["import os\n", f"key = '{STRIPE}'\n"], "outputs": []},
        {"cell_type": "code", "source": "print(tok)", "outputs": [
            {"output_type": "stream", "name": "stdout", "text": [f"{TOKEN}\n"]},
            {"output_type": "execute_result", "data": {"text/plain": [f"'{TOKEN}'"], "image/png": "iVBOR"}},
        ]},
    ])
    (tmp_path / "analysis.ipynb").write_text(nb)
    res = scan_path(tmp_path, options=ScanOptions(no_entropy=True))
    src = [f for f in res.findings if f.rule_id == "LS-STRIPE-001"][0]
    assert src.extra == {"cell": 1, "cell_type": "code", "output_type": "source"} and src.line_number == 2
    outs = {f.extra["output_type"] for f in res.findings if f.rule_id == "LS-GH-001"}
    assert outs == {"stream", "execute_result"}


def test_archives_zip_tar_nested(tmp_path):
    inner = io.BytesIO()
    with zipfile.ZipFile(inner, "w") as z:
        z.writestr("deep/config.py", f'K = "{STRIPE}"')
    with zipfile.ZipFile(tmp_path / "bundle.jar", "w") as z:
        z.writestr("app/settings.py", f'T = "{TOKEN}"')
        z.writestr("lib/inner.zip", inner.getvalue())
    buf = io.BytesIO(f"P = '{STRIPE}'\n".encode())
    with tarfile.open(tmp_path / "src.tar.gz", "w:gz") as t:
        info = tarfile.TarInfo("pkg/a.py")
        info.size = len(buf.getvalue())
        t.addfile(info, buf)
    assert not scan_path(tmp_path, options=ScanOptions(no_entropy=True)).findings
    res = scan_path(tmp_path, options=ScanOptions(no_entropy=True, archives=True))
    files = {f.file for f in res.findings}
    assert "bundle.jar!app/settings.py" in files
    assert "bundle.jar!lib/inner.zip!deep/config.py" in files
    assert "src.tar.gz!pkg/a.py" in files


def test_archive_bomb_ratio_rejected(tmp_path):
    with zipfile.ZipFile(tmp_path / "bomb.zip", "w", compression=zipfile.ZIP_DEFLATED) as z:
        z.writestr("zeros.txt", b"0" * 20_000_000)
    res = scan_path(tmp_path, options=ScanOptions(archives=True))
    assert any("archive skipped" in e for e in res.errors)


def test_utf16_and_latin1_files(tmp_path):
    (tmp_path / "u16.py").write_text(f'K = "{STRIPE}"\n', encoding="utf-16")
    (tmp_path / "l1.py").write_bytes(f'# caf\xe9\nK = "{TOKEN}"\n'.encode("latin-1"))
    ids = _rules(scan_path(tmp_path, options=ScanOptions(no_entropy=True)).findings)
    assert {"LS-STRIPE-001", "LS-GH-001"} <= ids


@pytest.mark.skipif(sys.platform == "win32", reason="symlinks need admin on Windows")
def test_symlink_outside_root_not_followed(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "s.txt").write_text(f"k={STRIPE}")
    root = tmp_path / "root"
    root.mkdir()
    os.symlink(outside / "s.txt", root / "link.txt")
    assert not scan_path(root, options=ScanOptions(no_entropy=True)).findings


def test_findings_use_relative_posix_paths(tmp_path):
    (tmp_path / "a" / "b").mkdir(parents=True)
    (tmp_path / "a" / "b" / "c.py").write_text(f"k = '{STRIPE}'")
    f = scan_path(tmp_path, options=ScanOptions(no_entropy=True)).findings[0]
    assert f.file == "a/b/c.py"


def test_cache_skips_unchanged_clean_files(tmp_path):
    (tmp_path / "clean.py").write_text("print('hi')\n")
    (tmp_path / "dirty.py").write_text(f"k = '{STRIPE}'\n")
    cache = tmp_path / ".leakscan-cache"
    first = scan_path(tmp_path, options=ScanOptions(no_entropy=True), cache_path=cache)
    second = scan_path(tmp_path, options=ScanOptions(no_entropy=True), cache_path=cache)
    assert first.files_cached == 0 and second.files_cached == 1
    assert len(second.findings) == 1
    assert STRIPE not in cache.read_text()


def _git(repo, *args):
    subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True,
                   env={**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t", "GIT_COMMITTER_NAME": "t",
                        "GIT_COMMITTER_EMAIL": "t@t"})


@pytest.fixture
def repo(tmp_path):
    _git(tmp_path, "init", "-q", "-b", "main")
    (tmp_path / "a.py").write_text("x = 1\n")
    _git(tmp_path, "add", ".")
    _git(tmp_path, "commit", "-qm", "init")
    return tmp_path


def test_history_streaming_and_allow_commits(repo):
    (repo / "a.py").write_text(f"x = 1\nk = '{STRIPE}'\n")
    _git(repo, "commit", "-qam", "leak")
    (repo / "a.py").write_text("x = 1\n")
    _git(repo, "commit", "-qam", "remove")
    res = scan_git_history(repo, options=ScanOptions(no_entropy=True))
    assert res.commits_scanned == 3
    leak = [f for f in res.findings if f.rule_id == "LS-STRIPE-001"]
    assert leak and leak[0].line_number == 2 and leak[0].source == "history"
    sha = subprocess.run(["git", "-C", str(repo), "rev-parse", "HEAD~1"], capture_output=True, text=True).stdout.strip()
    assert not scan_git_history(repo, options=ScanOptions(no_entropy=True, allow_commits={sha[:10]})).findings


def test_since_commit_and_base_diff(repo):
    _git(repo, "checkout", "-qb", "feature")
    (repo / "b.py").write_text(f"t = '{TOKEN}'\n")
    _git(repo, "add", ".")
    _git(repo, "commit", "-qm", "feat")
    assert _rules(scan_diff(repo, ["main", "HEAD"], options=ScanOptions(no_entropy=True)).findings) == {"LS-GH-001"}
    assert _rules(scan_diff(repo, ["main...HEAD"], options=ScanOptions(no_entropy=True)).findings) == {"LS-GH-001"}


def test_pr_diff_args_from_env(monkeypatch):
    from scanner.sources import pr_diff_args
    monkeypatch.setenv("GITHUB_BASE_REF", "main")
    assert pr_diff_args() == ["origin/main...HEAD"]
    monkeypatch.delenv("GITHUB_BASE_REF")
    for v in ("CI_MERGE_REQUEST_TARGET_BRANCH_NAME", "BITBUCKET_PR_DESTINATION_BRANCH", "CHANGE_TARGET"):
        monkeypatch.delenv(v, raising=False)
    with pytest.raises(RuntimeError):
        pr_diff_args()


def test_remote_url_detection():
    from scanner.sources import is_docker, is_package, is_remote_url
    assert is_remote_url("https://gitlab.com/group/sub/project.git")
    assert is_remote_url("git@bitbucket.org:team/repo.git")
    assert not is_remote_url("./local")
    assert is_docker("docker://nginx:1.27") and is_package("pypi:requests==2.32.3") and is_package("npm:@scope/pkg@1.0.0")


def test_scan_remote_local_clone(repo):
    from scanner.sources import scan_remote
    (repo / "c.py").write_text(f"k = '{STRIPE}'\n")
    _git(repo, "add", ".")
    _git(repo, "commit", "-qm", "c")
    res = scan_remote(repo.as_uri(), ScanOptions(no_entropy=True), history=True, depth=10, clone_depth=0)
    assert "LS-STRIPE-001" in _rules(res.findings)


def test_org_filtering():
    from scanner.sources import OrgScanSettings, _filter_repos
    repos = [{"name": "api", "fork": False}, {"name": "old", "archived": True}, {"name": "fork", "fork": True},
             {"name": "web-app"}]
    names = [r["name"] for r in _filter_repos(repos, OrgScanSettings(exclude=("web-*",)))]
    assert names == ["api"]
    assert len(_filter_repos(repos, OrgScanSettings(include_forks=True, include_archived=True))) == 4


def test_npm_spec_parsing(monkeypatch):
    from scanner import sources
    seen = []

    class Resp:
        def raise_for_status(self):
            pass

        def json(self):
            return {"dist": {"tarball": "https://registry.npmjs.org/@s/p/-/p-1.0.0.tgz"}}

    monkeypatch.setattr(sources.requests, "get", lambda url, **kw: seen.append(url) or Resp())
    url, name = sources.resolve_package("npm:@s/p@1.0.0")
    assert seen[-1] == "https://registry.npmjs.org/@s/p/1.0.0" and name == "p-1.0.0.tgz"
    sources.resolve_package("npm:left-pad")
    assert seen[-1].endswith("/left-pad/latest")


# config

def test_config_allowlist_overrides_extends(tmp_path):
    from scanner.config import load_config, validate_file
    (tmp_path / "base.yaml").write_text("disable_rules: [LS-GEN-001]\nallowlist:\n  paths: ['vendor/**']\n")
    (tmp_path / ".leakscan.yaml").write_text(
        "extends: base.yaml\nexclude_paths: ['build/**']\n"
        "overrides:\n  - paths: ['docs/**']\n    disable_rules: [LS-STRIPE-001]\n"
        "rules:\n  - id: LS-ACME-001\n    name: Acme Token\n    regex: 'acme_[a-z0-9]{12}'\n    severity: HIGH\n")
    cfg = load_config(tmp_path, packs=False)
    assert not cfg.errors
    opts = cfg.apply(ScanOptions(no_entropy=True))
    assert "LS-GEN-001" in opts.disable_rules and opts.allow_paths == ["vendor/**"]
    assert "LS-ACME-001" in _rules(check_line("t = acme_abcdef123456", 1, "a", opts))
    assert not check_line(f"k={STRIPE}", 1, "docs/x.md", opts)
    assert check_line(f"k={STRIPE}", 1, "src/x.py", opts)
    assert validate_file(tmp_path / ".leakscan.yaml") == []


def test_config_exclude_paths_is_applied(tmp_path):
    (tmp_path / "build").mkdir()
    (tmp_path / "build" / "x.py").write_text(f"k='{STRIPE}'")
    (tmp_path / ".leakscan.yaml").write_text("exclude_paths: ['build/**']\n")
    r = CliRunner().invoke(cli, ["scan", str(tmp_path), "--format", "json", "--no-progress"])
    assert json.loads(r.stdout)["findings"] == []


def test_config_validate_reports_problems(tmp_path):
    from scanner.config import validate_file
    p = tmp_path / "c.yaml"
    p.write_text("severity: SUPER\nbogus: 1\nallowlist: {regexes: ['(']}\ndisable_rules: [LS-NOPE-999]\n")
    problems = "\n".join(validate_file(p))
    assert "bogus" in problems and "severity" in problems and "invalid regex" in problems and "LS-NOPE-999" in problems


# outputs

def _result():
    return ScanResult(findings=[Finding("src/a.py", 3, "", "Stripe Live Secret Key", "HIGH", STRIPE)], files_scanned=1)


def test_json_schema_version_and_fields():
    from scanner.reporter import to_json
    data = json.loads(to_json(_result()))
    assert data["schema_version"] == "1.0" and data["tool"]["name"] == "leakscan"
    f = data["findings"][0]
    assert f["rule_id"] == "LS-STRIPE-001" and 0 < f["confidence"] <= 1 and "verification" in f


def test_report_schema_matches_required_fields():
    from scanner.reporter import to_json
    schema = json.loads((Path(__file__).parent.parent / "scanner/schemas/report.schema.json").read_text())
    data = json.loads(to_json(_result()))
    assert set(schema["required"]) <= set(data)
    assert set(schema["$defs"]["finding"]["required"]) <= set(data["findings"][0])


def test_sarif_has_rule_ids_redaction_and_verification():
    from scanner.reporter import to_sarif
    r = _result()
    r.findings[0].verified, r.findings[0].verified_at = "LIVE", "2026-01-01T00:00:00+00:00"
    sarif = json.loads(to_sarif(r))
    res = sarif["runs"][0]["results"][0]
    assert res["ruleId"] == "LS-STRIPE-001" and STRIPE not in json.dumps(sarif)
    assert res["properties"]["verification"] == "active"
    assert sarif["runs"][0]["tool"]["driver"]["rules"][0]["helpUri"].endswith("/rules/LS-STRIPE-001/")


def test_html_junit_markdown_sonar_dojo():
    from scanner import formats
    r = _result()
    html = formats.to_html(r)
    assert "<table" in html and "LS-STRIPE-001" in html and STRIPE not in html
    junit = formats.to_junit(r)
    assert 'failures="1"' in junit and "<testcase" in junit
    import xml.dom.minidom
    xml.dom.minidom.parseString(junit)
    md = formats.to_markdown(r)
    assert "| HIGH | `LS-STRIPE-001`" in md and STRIPE not in md
    assert json.loads(formats.to_sonarqube(r))["issues"][0]["ruleId"] == "LS-STRIPE-001"
    assert json.loads(formats.to_defectdojo(r))["findings"][0]["cwe"] == 798
    assert "No secrets found" in formats.to_markdown(ScanResult())


def test_verification_status_mapping():
    f = Finding("a", 1, "", "x", "HIGH", "v")
    assert f.verification_status is None
    f.verified_at = "now"
    assert f.verification_status == "unknown"
    f.verified = "LIVE"
    assert f.verification_status == "active"
    f.verified = "REVOKED"
    assert f.verification_status == "inactive"
    f.verification_error = "Timeout"
    assert f.verification_status == "error"


# CLI

def test_exit_codes(tmp_path):
    runner = CliRunner()
    (tmp_path / "ok.py").write_text("x = 1\n")
    assert runner.invoke(cli, ["scan", str(tmp_path), "--no-progress"]).exit_code == 0
    (tmp_path / "bad.py").write_text(f"k = '{STRIPE}'\n")
    assert runner.invoke(cli, ["scan", str(tmp_path), "--no-progress"]).exit_code == 1
    assert runner.invoke(cli, ["scan", str(tmp_path), "--no-progress", "--exit-zero"]).exit_code == 0
    assert runner.invoke(cli, ["scan", str(tmp_path), "--no-progress", "--fail-on", "CRITICAL"]).exit_code == 0
    assert runner.invoke(cli, ["scan", str(tmp_path / "missing"), "--no-progress"]).exit_code == 2


def test_stdin_and_text():
    runner = CliRunner()
    r = runner.invoke(cli, ["scan", "-", "--format", "json"], input=f"x={STRIPE}\n")
    assert r.exit_code == 1 and json.loads(r.output)["findings"][0]["file"] == "<stdin>"
    r = runner.invoke(cli, ["scan", "--text", f"token {TOKEN}", "--format", "json"])
    assert json.loads(r.output)["findings"][0]["rule_id"] == "LS-GH-001"


def test_verify_consent_gate():
    r = CliRunner().invoke(cli, ["scan", "https://github.com/octocat/Hello-World", "--verify", "--no-progress"])
    assert r.exit_code == 2 and "--yes" in r.output


def test_rules_and_config_commands(tmp_path):
    runner = CliRunner()
    r = runner.invoke(cli, ["rules", "list", "--json"])
    assert len(json.loads(r.output)) >= 150
    assert "Blast radius" in runner.invoke(cli, ["rules", "show", "LS-AWS-001"]).output
    cfg = tmp_path / ".leakscan.yaml"
    runner.invoke(cli, ["rules", "disable", "LS-GEN-003", "--config", str(cfg)])
    assert "LS-GEN-003" in cfg.read_text()
    assert runner.invoke(cli, ["config", "validate", str(cfg)]).exit_code == 0
    runner.invoke(cli, ["rules", "enable", "LS-GEN-003", "--config", str(cfg)])
    assert "LS-GEN-003" not in cfg.read_text()
    assert '"$schema"' in runner.invoke(cli, ["config", "schema"]).output
    assert "_LEAKSCAN_COMPLETE" in runner.invoke(cli, ["completion", "bash"]).output


def test_rules_import_pack(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "cfg"))
    pack = tmp_path / "acme.yaml"
    pack.write_text("name: acme\nrules:\n  - id: LS-ACME-001\n    name: Acme Key\n    regex: 'acme_[0-9]{8}'\n"
                    "    examples: {positive: ['acme_12345678'], negative: ['acme_1']}\n  - name: broken\n    regex: '('\n")
    r = CliRunner().invoke(cli, ["rules", "import", str(pack)])
    assert r.exit_code == 0 and "Imported 1 rule" in r.output
    r = CliRunner().invoke(cli, ["scan", "--text", "k = acme_12345678", "--format", "json"])
    assert json.loads(r.output)["findings"][0]["rule_id"] == "LS-ACME-001"


def test_new_formats_via_cli(tmp_path):
    (tmp_path / "a.py").write_text(f"k = '{STRIPE}'\n")
    for fmt in ("html", "junit", "markdown", "sonarqube", "defectdojo", "sarif"):
        out = tmp_path / f"r.{fmt}"
        r = CliRunner().invoke(cli, ["scan", str(tmp_path / "a.py"), "-f", fmt, "-o", str(out), "--no-progress"])
        assert r.exit_code == 1 and out.read_text() and STRIPE not in out.read_text()


# agents

def test_hook_blocks_claude_code_write():
    payload = {"tool_name": "Write", "tool_input": {"file_path": "app.py", "content": f"KEY = '{STRIPE}'"}}
    r = CliRunner().invoke(cli, ["hook"], input=json.dumps(payload))
    assert r.exit_code == 2 and "LS-STRIPE-001" in r.output and STRIPE not in r.output
    ok = {"tool_name": "Write", "tool_input": {"file_path": "app.py", "content": "KEY = os.environ['KEY']"}}
    assert CliRunner().invoke(cli, ["hook"], input=json.dumps(ok)).exit_code == 0


def test_hook_cursor_protocol():
    r = CliRunner().invoke(cli, ["hook", "--agent", "cursor"], input=json.dumps({"command": f"export K={STRIPE}"}))
    assert json.loads(r.output)["permission"] == "deny"


def test_mcp_protocol():
    from scanner.commands import handle_mcp
    init = handle_mcp({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18"}})
    assert init["result"]["serverInfo"]["name"] == "leakscan"
    tools = handle_mcp({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})["result"]["tools"]
    assert {t["name"] for t in tools} == {"scan_text", "scan_path", "scan_staged"}
    call = handle_mcp({"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                       "params": {"name": "scan_text", "arguments": {"text": f"k={STRIPE}"}}})
    data = call["result"]["structuredContent"]
    assert data["total"] == 1 and STRIPE not in json.dumps(call)
    assert handle_mcp({"jsonrpc": "2.0", "method": "notifications/initialized"}) is None
    assert "error" in handle_mcp({"jsonrpc": "2.0", "id": 4, "method": "nope"})


# python API

def test_python_api(tmp_path):
    (tmp_path / "a.py").write_text(f"k = '{STRIPE}'\n")
    res = leakscan.scan_path(tmp_path)
    assert isinstance(res, leakscan.ScanResult) and res.findings[0].rule_id == "LS-STRIPE-001"
    assert leakscan.scan_text(f"x {TOKEN}")[0].rule_id == "LS-GH-001"
    assert leakscan.scan_text(f"x {TOKEN}", disable=["LS-GH-001"], entropy=False) == []
    assert len(leakscan.rules()) >= 150
    assert json.loads(leakscan.to_json(res))["schema_version"] == "1.0"
    assert (Path(leakscan.__file__).parent / "py.typed").exists()


# notifications

def test_teams_and_generic_payloads():
    from scanner import notify
    r = _result()
    teams = notify.build_teams_payload(r, "repo")
    assert teams["attachments"][0]["contentType"] == "application/vnd.microsoft.card.adaptive"
    generic = notify.build_generic_payload(r, "repo")
    assert generic["total"] == 1 and STRIPE not in json.dumps(generic)


def test_email_requires_settings(monkeypatch):
    from scanner import notify
    for k in ("LEAKSCAN_SMTP_HOST", "LEAKSCAN_EMAIL_TO"):
        monkeypatch.delenv(k, raising=False)
    assert "needs LEAKSCAN_SMTP_HOST" in notify.send_email(_result(), "repo", rc={})


def test_verifier_status_codes(monkeypatch):
    from unittest.mock import MagicMock

    from scanner import verifier
    f = Finding("a", 1, "", "Mistral API Key", "HIGH", "MISTRAL_API_KEY=" + R(32))
    for code, expected in ((200, "LIVE"), (401, "REVOKED"), (429, None), (500, None)):
        verifier._cache.clear()
        resp = MagicMock(status_code=code)
        monkeypatch.setattr(verifier, "_get", lambda url, headers, r=resp: r)
        assert verifier.verify(f) == expected
    assert "mistral" in verifier.services()


def test_hex_helper_used():
    assert len(H(8)) == 8


def test_trie_prefilter_finds_every_anchor():
    import random
    import re

    from scanner.engine import ScanOptions, _trie_regex, rule_index
    idx = rule_index(ScanOptions().rules())
    keys = list(idx.map)
    for k in keys:
        found = {m.group(1) for m in idx.regex.finditer(f"__{k}__")}
        assert any(k in f for f in found), k
    rng = random.Random(3)
    words = ["".join(rng.choice("ab") for _ in range(rng.randint(1, 5))) for _ in range(40)]
    rx = re.compile("(?=(" + _trie_regex(sorted(set(words), key=len, reverse=True)) + "))")
    for w in words:
        assert any(w in m.group(1) for m in rx.finditer(f"x{w}y")), w


def test_also_writes_extra_formats(tmp_path):
    (tmp_path / "a.py").write_text(f"k = '{STRIPE}'\n")
    sarif, md = tmp_path / "o.sarif", tmp_path / "o.md"
    r = CliRunner().invoke(cli, ["scan", str(tmp_path / "a.py"), "-f", "json", "-o", str(tmp_path / "o.json"),
                                 "--also", f"sarif:{sarif}", "--also", f"markdown:{md}", "--no-progress"])
    assert r.exit_code == 1 and json.loads(sarif.read_text())["version"] == "2.1.0" and "LS-STRIPE-001" in md.read_text()
    assert CliRunner().invoke(cli, ["scan", str(tmp_path), "--also", "bogus"]).exit_code == 2


def test_entropy_skips_pem_bodies_and_cert_files():
    body = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7VJTUt9Us8cKj"
    assert not check_line(body, 2, "certs/server.txt", ScanOptions())
    assert not check_line(f'blob = "{body}"', 2, "certs/server.pem", ScanOptions())
    assert check_line(f'blob = "{body}"', 2, "app.py", ScanOptions())


def test_specific_rule_shadows_generic_on_same_line():
    ids = _rules(check_line(f'stripe.api_key = "{STRIPE}"', 1, "a.py", ScanOptions(no_entropy=True)))
    assert ids == {"LS-STRIPE-001"}
    ids = _rules(check_line(f"DATABASE_URL=postgres://app:{R(14)}@db/x", 1, "a.py", ScanOptions(no_entropy=True)))
    assert ids == {"LS-DB-003"}
    assert _rules(check_line(f'api_key = "{R(24)}"', 1, "a.py", ScanOptions(no_entropy=True))) == {"LS-GEN-001"}

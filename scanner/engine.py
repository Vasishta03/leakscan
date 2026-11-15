from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import re
import subprocess
import threading
import time
from concurrent.futures import Executor, ProcessPoolExecutor, ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable, Iterator, NamedTuple, Optional
from urllib.parse import unquote

from scanner.blame import BlameInfo
from scanner.entropy import scan_line
from scanner.ignorefile import _matches, is_ignored, load_ignore_patterns
from scanner.patterns import ENTROPY_RULE_ID, ENTROPY_RULE_NAME, PATTERNS, Pattern, jwt_expired

DEFAULT_MAX_FILE_SIZE = 50 * 1_000_000
DEFAULT_CHUNK_SIZE = 1_000_000
_BINARY_SNIFF_BYTES = 8192

_IGNORE_RE = re.compile(
    r"\b(?:nosec|gitleaks:allow|secretscanner:allow)\b"
    r"|leakscan:ignore(?:[ \t]+(LS-[A-Z0-9-]+(?:[ \t]*,[ \t]*LS-[A-Z0-9-]+)*))?",
    re.IGNORECASE,
)

_PLACEHOLDER_RE = re.compile(
    r"(?i)example|changeme|change_me|placeholder|your[_\-]?(?:api|secret|token|key|pass|access)|redacted"
    r"|dummy|sample|insert[_\-]?(?:your|key|token)|replace[_\-]?me|\bfake|x{5,}|\*{4,}|\.{4,}|<[^>]{1,40}>"
    r"|\$\{[^}]*\}|\{\{[^}]*\}\}|%\([^)]*\)s|^\$[A-Za-z_]+$|process\.env|os\.environ|getenv|secrets\.[A-Z_]"
    r"|:(?:password|passwd|pass|pwd|secret|changeme|bar)@"
)
_DUMMY_VALUES = {
    "password", "passwd", "pass", "pwd", "secret", "postgres", "mysql", "root", "admin", "administrator", "test",
    "testing", "changeit", "letmein", "default", "guest", "user", "username", "foo", "bar", "foobar", "mypassword",
    "top_secret", "topsecret", "qwerty", "123456", "12345678", "hunter2", "s3cr3t", "secret123", "password123",
    "p@ssw0rd", "passw0rd", "none", "null", "true", "false", "redis", "rabbitmq", "guest:guest",
}
_IDENTIFIER_RE = re.compile(r"_?[a-z][a-z_]*|_?[A-Z][A-Z_]*|[a-z]+(?:[A-Z][a-z]+)+")
_KNOWN_TEST_VALUES = {
    "4242424242424242", "4000056655665556", "5555555555554444", "2223003122003222", "5200828282828210",
    "378282246310005", "371449635398431", "6011111111111117", "4111111111111111", "5105105105105100",
}
_BARE_B64_LINE = re.compile(r"\s*[A-Za-z0-9+/]{40,}={0,2}\s*")
_NO_ENTROPY_FILES = re.compile(r"(?i)\.(?:pem|crt|cer|csr|der|p7b|p7c|key|pub|asc|gpg|sig|sum|lock)$|(?:^|/)(?:cacert|ca-bundle)[^/]*$")
_SEQUENCE_RE = re.compile(r"(?i)abcdefgh|bcdefghi|qrstuvwx|23456789|0123456789|98765432")
_CONTEXT_RE = re.compile(r"(?i)secret|token|passw|api[_\-]?key|credential|auth|private")
_TEST_PATH_RE = re.compile(
    r"(?i)(?:^|/)(?:tests?|spec|specs|__tests__|__mocks__|fixtures?|testdata|test_data|mocks?|examples?|samples?|docs?)/"
    r"|(?:^|/)(?:test_[^/]*|[^/]*(?:_test|\.test|\.spec|_spec|_mock|\.example|\.sample))\.?[^/]*$"
    r"|\.(?:md|rst|adoc|txt)$"
)
_GENERIC_IDS = {"LS-GEN-001", "LS-GEN-002", "LS-GEN-004", "LS-IAC-002", "LS-IAC-006", "LS-IAC-007"}
_FALLBACK_IDS = _GENERIC_IDS | {"LS-GEN-003", "LS-GEN-005", "LS-DB-001"}
_B64_RE = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{24,}={0,2}(?![A-Za-z0-9+/=])")
_HEX_RE = re.compile(r"(?<![0-9a-fA-F])(?:[0-9a-fA-F]{2}){20,}(?![0-9a-fA-F])")

ARCHIVE_SUFFIXES = (".zip", ".whl", ".jar", ".war", ".egg", ".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tar.xz")
_PRUNE_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", ".tox", ".mypy_cache", ".ruff_cache",
               ".pytest_cache"}


@dataclass
class Finding:
    file: str
    line_number: int
    line: str
    secret_type: str
    severity: str
    matched_value: str
    entropy: Optional[float] = None
    source: str = "regex"
    commit: Optional[str] = None
    verified: Optional[str] = None
    blame: Optional[BlameInfo] = None
    rule_id: str = ""
    confidence: float = 0.9
    verified_at: Optional[str] = None
    verification_error: Optional[str] = None
    extra: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.rule_id:
            from scanner.patterns import by_name
            rule = by_name().get(self.secret_type)
            self.rule_id = rule.id if rule else (ENTROPY_RULE_ID if self.secret_type == ENTROPY_RULE_NAME else
                                                 "LS-CUSTOM-" + re.sub(r"[^A-Z0-9]+", "-", self.secret_type.upper()).strip("-"))

    def fingerprint(self) -> str:
        return hashlib.sha256(f"{self.secret_type}:{self.matched_value}".encode()).hexdigest()[:16]

    @property
    def verification_status(self) -> Optional[str]:
        if self.verification_error:
            return "error"
        if self.verified == "LIVE":
            return "active"
        if self.verified == "REVOKED":
            return "inactive"
        if self.verified_at:
            return "unknown"
        return None


@dataclass
class ScanResult:
    findings: list[Finding] = field(default_factory=list)
    files_scanned: int = 0
    files_skipped: int = 0
    commits_scanned: int = 0
    errors: list[str] = field(default_factory=list)
    binary_files_skipped: int = 0
    large_files_skipped: list[str] = field(default_factory=list)
    ignored_files: list[str] = field(default_factory=list)
    elapsed_seconds: float = 0.0
    files_cached: int = 0

    @property
    def files_per_second(self) -> float:
        if self.elapsed_seconds <= 0:
            return 0.0
        return self.files_scanned / self.elapsed_seconds

    def merge(self, other: "ScanResult") -> None:
        self.findings.extend(other.findings)
        self.files_scanned += other.files_scanned
        self.files_skipped += other.files_skipped
        self.commits_scanned += other.commits_scanned
        self.errors.extend(other.errors)
        self.binary_files_skipped += other.binary_files_skipped
        self.large_files_skipped.extend(other.large_files_skipped)
        self.ignored_files.extend(other.ignored_files)
        self.files_cached += other.files_cached


@dataclass
class Override:
    paths: list[str]
    disable_rules: set[str] = field(default_factory=set)
    allow_regexes: list[re.Pattern] = field(default_factory=list)


@dataclass
class ScanOptions:
    entropy_threshold: float = 4.5
    no_entropy: bool = False
    extra_rules: list[Pattern] = field(default_factory=list)
    disable_rules: set[str] = field(default_factory=set)
    allow_regexes: list[re.Pattern] = field(default_factory=list)
    allow_paths: list[str] = field(default_factory=list)
    allow_commits: set[str] = field(default_factory=set)
    stopwords: list[str] = field(default_factory=list)
    exclude_paths: list[str] = field(default_factory=list)
    overrides: list[Override] = field(default_factory=list)
    decode: bool = False
    validate: bool = True
    placeholders: bool = True
    archives: bool = False
    max_archive_bytes: int = 512 * 1_000_000
    max_archive_members: int = 10_000

    @property
    def effective_threshold(self) -> float:
        return 999.0 if self.no_entropy else self.entropy_threshold

    def rules(self) -> list[Pattern]:
        disabled = self.disable_rules
        return [p for p in (*PATTERNS, *self.extra_rules) if p.id not in disabled and p.name not in disabled]

    def rules_hash(self) -> str:
        h = hashlib.sha256()
        for p in self.rules():
            h.update(f"{p.id}|{p.regex.pattern}|{p.path.pattern if p.path else ''}\n".encode())
        h.update(repr((self.effective_threshold, self.decode, self.validate, self.placeholders,
                       sorted(r.pattern for r in self.allow_regexes), self.stopwords, self.allow_paths)).encode())
        return h.hexdigest()[:16]


def _trie_regex(words: list[str]) -> str:
    """Compile literals into a prefix-trie regex. Python's re tries alternatives one by one,
    so a flat 200-way alternation is ~6x slower than the equivalent trie."""
    trie: dict = {}
    for w in words:
        node = trie
        for ch in w:
            node = node.setdefault(ch, {})
        node[""] = True

    def build(node: dict) -> str:
        end = "" in node
        alts = [re.escape(ch) + build(sub) for ch, sub in sorted(node.items()) if ch != ""]
        if not alts:
            return ""
        body = alts[0] if len(alts) == 1 else "(?:" + "|".join(alts) + ")"
        return f"(?:{body})?" if end else body

    return build(trie)


class RuleIndex:
    """Keyword prefilter: one combined regex finds which rules can possibly match a line."""

    def __init__(self, rules: list[Pattern]):
        from scanner.patterns import required_literals
        self.rules = rules
        self.always: list[int] = []
        anchors: dict[str, set[int]] = {}
        for i, r in enumerate(rules):
            lits = required_literals(r.regex)
            if not lits:
                self.always.append(i)
                continue
            for lit in lits:
                anchors.setdefault(lit, set()).add(i)
        keys = sorted(anchors, key=len, reverse=True)
        self.map = {k: frozenset(set().union(*(anchors[j] for j in keys if j in k))) for k in keys}
        self.regex = re.compile("(?=(" + _trie_regex(keys) + "))") if keys else None

    def candidates(self, text: str) -> list[Pattern]:
        idx = set(self.always)
        if self.regex is not None:
            for m in self.regex.finditer(text.lower()):
                idx |= self.map[m.group(1)]
        return [self.rules[i] for i in sorted(idx)]


_INDEX_CACHE: dict[tuple, RuleIndex] = {}
_INDEX_LOCK = threading.Lock()


def rule_index(rules: list[Pattern]) -> RuleIndex:
    key = tuple(map(id, rules))
    idx = _INDEX_CACHE.get(key)
    if idx is not None:
        return idx
    with _INDEX_LOCK:
        if len(_INDEX_CACHE) > 32:
            _INDEX_CACHE.clear()
        idx = _INDEX_CACHE[key] = RuleIndex(rules)
        return idx


def _opts(options: Optional[ScanOptions], entropy_threshold: float = 4.5, no_entropy: bool = False) -> ScanOptions:
    return options if options is not None else ScanOptions(entropy_threshold=entropy_threshold, no_entropy=no_entropy)


def _secret_part(match: re.Match) -> str:
    if match.re.groups:
        for g in match.groups():
            if g:
                return g
    return match.group(0)


def is_placeholder(value: str) -> bool:
    if value.strip("'\" ").lower() in _DUMMY_VALUES:
        return True
    if value in _KNOWN_TEST_VALUES or value.replace(" ", "").replace("-", "") in _KNOWN_TEST_VALUES:
        return True
    if _PLACEHOLDER_RE.search(value):
        return True
    tail = re.split(r"[_\-.]", value)[-1] if len(value) > 16 else value
    return len(tail) >= 12 and len(set(tail)) <= 3


def _ignored_rules(line: str) -> Optional[set[str]]:
    """None: line not suppressed. Empty set: every rule suppressed."""
    suppressed: Optional[set[str]] = None
    for m in _IGNORE_RE.finditer(line):
        ids = m.group(1)
        if not ids:
            return set()
        suppressed = (suppressed or set()) | {i.strip().upper() for i in ids.split(",")}
    return suppressed


def _path_allowed(filepath: str, opts: ScanOptions) -> bool:
    return any(_matches(filepath, pat) for pat in opts.allow_paths)


def _score(base: float, line: str, filepath: str, validated: Optional[bool]) -> float:
    score = base
    if _CONTEXT_RE.search(line):
        score += 0.1
    if validated:
        score += 0.05
    if _TEST_PATH_RE.search(filepath.replace("\\", "/")):
        score -= 0.3
    return round(min(max(score, 0.05), 1.0), 2)


def _match_rules(text: str, line_number: int, filepath: str, rules: Iterable[Pattern], opts: ScanOptions,
                 skip_ids: Optional[set[str]], line_for_display: str) -> list[Finding]:
    findings: list[Finding] = []
    if len(text) < 8:
        return findings
    for pattern in rule_index(rules).candidates(text) if isinstance(rules, list) else rules:
        if skip_ids and pattern.id in skip_ids:
            continue
        if (pattern.path is not None or pattern.exclude_path is not None) and not pattern.applies_to(filepath):
            continue
        match = pattern.regex.search(text)
        if not match:
            continue
        secret = _secret_part(match)
        if opts.placeholders and pattern.id.split("-")[1] != "KEY" and is_placeholder(secret):
            continue
        if opts.placeholders and pattern.id in _GENERIC_IDS and _IDENTIFIER_RE.fullmatch(secret):
            continue
        if any(r.search(secret) or r.search(match.group(0)) for r in opts.allow_regexes):
            continue
        if opts.stopwords and any(w in secret.lower() for w in opts.stopwords):
            continue
        validated: Optional[bool] = None
        if opts.validate and pattern.validate is not None:
            validated = pattern.validate(secret)
            if validated is False and pattern.strict:
                continue
        confidence = _score(pattern.confidence, line_for_display, filepath, validated)
        extra: dict[str, Any] = {}
        if validated is False:
            confidence = round(max(confidence - 0.4, 0.05), 2)
            extra["validation"] = "failed"
        elif validated:
            extra["validation"] = "passed"
        if pattern.validate is not None and "eyJ" in secret and jwt_expired(secret):
            extra["jwt_expired"] = True
            confidence = round(max(confidence - 0.3, 0.05), 2)
        findings.append(Finding(
            file=filepath,
            line_number=line_number,
            line=line_for_display.strip()[:500],
            secret_type=pattern.name,
            severity=pattern.severity,
            matched_value=match.group(0)[:80],
            source="regex",
            rule_id=pattern.id,
            confidence=confidence,
            extra=extra,
        ))
    return findings


def _drop_shadowed(findings: list[Finding]) -> list[Finding]:
    """A specific rule on a line wins over generic fallbacks like 'Generic API Key'."""
    if len(findings) < 2 or not any(f.rule_id not in _FALLBACK_IDS for f in findings):
        return findings
    return [f for f in findings if f.rule_id not in _FALLBACK_IDS]


def _decoded_views(line: str) -> Iterator[tuple[str, str]]:
    for m in _B64_RE.finditer(line):
        try:
            raw = base64.b64decode(m.group(0) + "=" * (-len(m.group(0)) % 4), validate=True)
        except (binascii.Error, ValueError):
            continue
        text = _printable(raw)
        if text:
            yield "base64", text
    for m in _HEX_RE.finditer(line):
        text = _printable(bytes.fromhex(m.group(0)))
        if text:
            yield "hex", text
    if "%" in line:
        decoded = unquote(line)
        if decoded != line:
            yield "url", decoded


def _printable(raw: bytes) -> Optional[str]:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if not text or sum(c.isprintable() or c in "\n\t" for c in text) / len(text) < 0.95:
        return None
    return text


def check_line(line: str, line_number: int, filepath: str, opts: ScanOptions,
               rules: Optional[list[Pattern]] = None) -> list[Finding]:
    skip = _ignored_rules(line)
    if skip is not None and not skip:
        return []
    if opts.allow_paths and _path_allowed(filepath, opts):
        return []
    active = rules if rules is not None else opts.rules()
    for ov in opts.overrides:
        if any(_matches(filepath, p) for p in ov.paths):
            active = [p for p in active if p.id not in ov.disable_rules]
            if ov.allow_regexes and any(r.search(line) for r in ov.allow_regexes):
                return []

    findings = _drop_shadowed(_match_rules(line, line_number, filepath, active, opts, skip, line))

    if opts.decode:
        seen = {f.matched_value for f in findings}
        for encoding, text in _decoded_views(line):
            for f in _match_rules(text, line_number, filepath, active, opts, skip, line):
                if f.matched_value not in seen and f.matched_value not in line:
                    seen.add(f.matched_value)
                    f.source = f"decoded-{encoding}"
                    f.extra["encoding"] = encoding
                    findings.append(f)

    if findings or (skip and ENTROPY_RULE_ID in skip) or ENTROPY_RULE_ID in opts.disable_rules:
        return findings
    if _BARE_B64_LINE.fullmatch(line) or _NO_ENTROPY_FILES.search(filepath):
        return findings
    for ef in scan_line(line, line_number, threshold=opts.effective_threshold):
        if opts.placeholders and (is_placeholder(ef.value) or _SEQUENCE_RE.search(ef.value)):
            continue
        if any(r.search(ef.value) for r in opts.allow_regexes):
            continue
        findings.append(Finding(
            file=filepath,
            line_number=line_number,
            line=line.strip()[:500],
            secret_type=ENTROPY_RULE_NAME,
            severity="LOW",
            matched_value=ef.value[:80],
            entropy=ef.entropy,
            source="entropy",
            rule_id=ENTROPY_RULE_ID,
            confidence=_score(0.3, line, filepath, None),
        ))
    return findings


def _check_line(line: str, line_number: int, filepath: str, entropy_threshold: float) -> list[Finding]:
    return check_line(line, line_number, filepath, ScanOptions(entropy_threshold=entropy_threshold))


def scan_lines(lines: Iterable[str], filepath: str, opts: ScanOptions, start: int = 1,
               extra: Optional[dict] = None) -> list[Finding]:
    rules = opts.rules()
    findings = []
    for i, line in enumerate(lines, start=start):
        for f in check_line(line.rstrip("\r\n"), i, filepath, opts, rules):
            if extra:
                f.extra.update(extra)
            findings.append(f)
    return findings


def _scan_content(content: str, filepath: str, entropy_threshold: float) -> list[Finding]:
    return scan_lines(content.splitlines(), filepath, ScanOptions(entropy_threshold=entropy_threshold))


def scan_notebook(text: str, filepath: str, opts: ScanOptions) -> Optional[list[Finding]]:
    """Scan a Jupyter notebook cell by cell. Returns None if it isn't valid notebook JSON."""
    try:
        nb = json.loads(text)
        cells = nb["cells"]
    except (ValueError, KeyError, TypeError):
        return None
    findings: list[Finding] = []

    def _text(v: Any) -> str:
        return "".join(v) if isinstance(v, list) else (v if isinstance(v, str) else "")

    for idx, cell in enumerate(cells):
        if not isinstance(cell, dict):
            continue
        findings.extend(scan_lines(_text(cell.get("source")).splitlines(), filepath, opts,
                                   extra={"cell": idx, "cell_type": cell.get("cell_type"), "output_type": "source"}))
        for out in cell.get("outputs") or []:
            if not isinstance(out, dict):
                continue
            otype = out.get("output_type", "unknown")
            chunks = [_text(out.get("text"))]
            for mime, value in (out.get("data") or {}).items():
                if mime.startswith("text/") or mime.endswith("json"):
                    chunks.append(_text(value) if not isinstance(value, dict) else json.dumps(value))
            if otype == "error":
                chunks.append("\n".join(out.get("traceback") or []))
            body = "\n".join(c for c in chunks if c)
            if body:
                findings.extend(scan_lines(body.splitlines(), filepath, opts,
                                           extra={"cell": idx, "output_type": otype}))
    return findings


def _diff_parser() -> Callable[[str, Optional[str]], Optional[tuple[str, int, str]]]:
    state: dict[str, Any] = {"file": None, "line": 0, "hunk": False}

    def feed(line: str, fixed_file: Optional[str]) -> Optional[tuple[str, int, str]]:
        if line.startswith("diff --git "):
            state["hunk"] = False
            if fixed_file is None:
                state["file"] = None
        elif line.startswith("+++ "):
            state["hunk"] = False
            if fixed_file is None:
                state["file"] = line[6:] if line.startswith("+++ b/") else None
        elif line.startswith("--- ") and not state["hunk"]:
            pass
        elif line.startswith("index ") and not state["hunk"]:
            pass
        elif line.startswith("@@ "):
            state["hunk"] = True
            m = re.search(r"\+(\d+)", line)
            if m:
                state["line"] = int(m.group(1)) - 1
        elif state["hunk"] and line.startswith("+"):
            state["line"] += 1
            f = fixed_file or state["file"]
            if f:
                return f, state["line"], line[1:]
        elif state["hunk"] and not line.startswith("-") and not line.startswith("\\"):
            state["line"] += 1
        return None

    return feed


def _iter_diff_additions(patch: str, filepath: Optional[str] = None) -> Iterator[tuple[str, int, str]]:
    feed = _diff_parser()
    for line in patch.splitlines():
        out = feed(line, filepath)
        if out:
            yield out


def _sniff(path: Path) -> bytes:
    try:
        with open(path, "rb") as f:
            return f.read(_BINARY_SNIFF_BYTES)
    except OSError:
        return b""


def detect_encoding(sniff: bytes) -> Optional[str]:
    """Return a text encoding for the sniffed bytes, or None if the data looks binary."""
    if sniff.startswith((b"\xff\xfe", b"\xfe\xff")):
        return "utf-16"
    if sniff.startswith(b"\xef\xbb\xbf"):
        return "utf-8-sig"
    if b"\x00" in sniff:
        return None
    try:
        sniff.decode("utf-8")
        return "utf-8"
    except UnicodeDecodeError as e:
        return "utf-8" if e.start >= len(sniff) - 4 else "latin-1"


def _is_binary(path: Path) -> bool:
    return detect_encoding(_sniff(path)) is None


def _iter_lines_chunked(path: Path, chunk_size: int, encoding: str = "utf-8") -> Iterator[tuple[int, str]]:
    leftover = ""
    line_number = 0
    with open(path, "r", encoding=encoding, errors="replace", newline="") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            lines = (leftover + chunk).split("\n")
            leftover = lines.pop()
            for line in lines:
                line_number += 1
                yield line_number, line.rstrip("\r")
    if leftover:
        line_number += 1
        yield line_number, leftover.rstrip("\r")


def scan_bytes(data: bytes, label: str, opts: ScanOptions, depth: int = 0) -> ScanResult:
    """Scan an in-memory blob: notebook, nested archive, or text."""
    from scanner import archives

    result = ScanResult()
    lower = label.lower()
    if opts.archives and lower.endswith(ARCHIVE_SUFFIXES) and depth < 2:
        result.merge(archives.scan_archive_bytes(data, label, opts, depth + 1))
        return result
    enc = detect_encoding(data[:_BINARY_SNIFF_BYTES])
    if enc is None:
        result.binary_files_skipped += 1
        result.files_skipped += 1
        return result
    text = data.decode(enc, errors="replace")
    findings = scan_notebook(text, label, opts) if lower.endswith(".ipynb") else None
    if findings is None:
        findings = scan_lines(text.split("\n"), label, opts)
    result.findings.extend(findings)
    result.files_scanned += 1
    return result


class _FileScanResult(NamedTuple):
    path: str
    findings: Optional[list[Finding]]
    error: Optional[str]
    skip_reason: Optional[str]
    sub: Optional[ScanResult] = None
    stat: Optional[tuple[int, int, str]] = None


_WORKER_OPTS: Optional[ScanOptions] = None
PROCESS_POOL_MIN_FILES = 200


def _init_worker(opts: ScanOptions) -> None:
    global _WORKER_OPTS
    _WORKER_OPTS = opts


def _scan_file_worker(args: tuple) -> _FileScanResult:
    path, label, opts, max_file_size, chunk_size, cached, use_cache = args
    if opts is None:
        opts = _WORKER_OPTS
    try:
        st = path.stat()
    except OSError as e:
        return _FileScanResult(label, None, f"{label}: {e}", None)

    if cached is not None:
        size, mtime, digest = cached
        if size == st.st_size and mtime == st.st_mtime_ns:
            return _FileScanResult(label, [], None, "cached")
        if size == st.st_size and _sha256(path) == digest:
            return _FileScanResult(label, [], None, "cached", stat=(st.st_size, st.st_mtime_ns, digest))

    lower = label.lower()
    if opts.archives and lower.endswith(ARCHIVE_SUFFIXES):
        from scanner import archives
        try:
            sub = archives.scan_archive_path(path, label, opts)
        except Exception as e:
            return _FileScanResult(label, None, f"{label}: {e}", None)
        return _FileScanResult(label, None, None, "archive", sub=sub)

    if st.st_size > max_file_size:
        return _FileScanResult(label, None, None, "large")

    encoding = detect_encoding(_sniff(path))
    if encoding is None:
        return _FileScanResult(label, None, None, "binary")

    try:
        if lower.endswith(".ipynb"):
            nb = scan_notebook(path.read_text(encoding=encoding, errors="replace"), label, opts)
            if nb is not None:
                return _FileScanResult(label, nb, None, None, stat=_stat_tuple(path, st, nb, use_cache))
        rules = opts.rules()
        findings: list[Finding] = []
        for line_number, line in _iter_lines_chunked(path, chunk_size, encoding):
            findings.extend(check_line(line, line_number, label, opts, rules))
        return _FileScanResult(label, findings, None, None, stat=_stat_tuple(path, st, findings, use_cache))
    except Exception as e:
        return _FileScanResult(label, None, f"{label}: {e}", None)


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def _stat_tuple(path: Path, st: os.stat_result, findings: list[Finding],
                use_cache: bool) -> Optional[tuple[int, int, str]]:
    if findings or not use_cache:
        return None
    return st.st_size, st.st_mtime_ns, _sha256(path)


def _label(path: Path, root: Path) -> str:
    if root.is_file():
        try:
            return path.relative_to(Path.cwd()).as_posix()
        except ValueError:
            return path.as_posix()
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return path.as_posix()


def scan_path(
    root: Path,
    entropy_threshold: float = 4.5,
    no_entropy: bool = False,
    threads: Optional[int] = None,
    max_file_size: int = DEFAULT_MAX_FILE_SIZE,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
    on_finding: Optional[Callable[[Finding], None]] = None,
    on_progress: Optional[Callable[[int, int], None]] = None,
    options: Optional[ScanOptions] = None,
    cache_path: Optional[Path] = None,
) -> ScanResult:
    """Scan every file under root with a thread pool.

    Findings carry paths relative to root (POSIX separators). Files whose
    size and mtime match a clean entry in cache_path are skipped.
    """
    from scanner import cache as cachemod

    opts = _opts(options, entropy_threshold, no_entropy)
    root = Path(root)
    result = ScanResult()
    patterns = load_ignore_patterns(root if root.is_dir() else root.parent) + list(opts.exclude_paths)
    if opts.archives:
        archive_globs = {f"*{s}" for s in ARCHIVE_SUFFIXES}
        patterns = [p for p in patterns if p not in archive_globs and p != "*.gz"]

    cache = cachemod.load(cache_path, opts.rules_hash()) if cache_path else None

    to_scan: list[tuple[Path, str]] = []
    for path in _walk(root):
        label = _label(path, root)
        if root.is_dir() and is_ignored(path, root, patterns):
            result.files_skipped += 1
            result.ignored_files.append(label)
            continue
        to_scan.append((path, label))

    worker_threads = threads if threads and threads > 0 else (os.cpu_count() or 4)
    lock = threading.Lock()
    start_time = time.monotonic()
    use_processes = worker_threads > 1 and len(to_scan) >= PROCESS_POOL_MIN_FILES
    executor: Executor = (
        ProcessPoolExecutor(max_workers=worker_threads, initializer=_init_worker, initargs=(opts,))
        if use_processes else ThreadPoolExecutor(max_workers=worker_threads)
    )
    task_opts = None if use_processes else opts

    with executor:
        futures = [
            executor.submit(_scan_file_worker, (p, label, task_opts, max_file_size, chunk_size,
                                                cache.get(label) if cache is not None else None,
                                                cache is not None))
            for p, label in to_scan
        ]
        completed = 0
        for future in as_completed(futures):
            fr = future.result()
            completed += 1
            with lock:
                if fr.skip_reason == "cached":
                    result.files_cached += 1
                    result.files_scanned += 1
                    if fr.stat and cache is not None:
                        cache.mark(fr.path, fr.stat)
                elif fr.skip_reason == "large":
                    result.files_skipped += 1
                    result.large_files_skipped.append(fr.path)
                elif fr.skip_reason == "binary":
                    result.files_skipped += 1
                    result.binary_files_skipped += 1
                elif fr.skip_reason == "archive" and fr.sub is not None:
                    result.merge(fr.sub)
                elif fr.error:
                    result.errors.append(fr.error)
                    result.files_skipped += 1
                else:
                    result.findings.extend(fr.findings or [])
                    result.files_scanned += 1
                    if cache is not None:
                        if fr.stat:
                            cache.mark(fr.path, fr.stat)
                        else:
                            cache.drop(fr.path)
            if on_finding:
                for f in (fr.findings or []) + (fr.sub.findings if fr.sub else []):
                    on_finding(f)
            if on_progress:
                on_progress(completed, len(to_scan))

    if cache is not None and cache_path is not None:
        cache.save(cache_path, root if root.is_dir() else root.parent)
    result.elapsed_seconds = time.monotonic() - start_time
    return result


def scan_content_string(
    content: str,
    filepath: str,
    entropy_threshold: float = 4.5,
    no_entropy: bool = False,
    options: Optional[ScanOptions] = None,
) -> list[Finding]:
    opts = _opts(options, entropy_threshold, no_entropy)
    if filepath.lower().endswith(".ipynb"):
        nb = scan_notebook(content, filepath, opts)
        if nb is not None:
            return nb
    return scan_lines(content.splitlines(), filepath, opts)


def scan_patch_string(
    patch: str,
    filepath: str,
    sha: str,
    entropy_threshold: float = 4.5,
    no_entropy: bool = False,
    options: Optional[ScanOptions] = None,
) -> list[Finding]:
    opts = _opts(options, entropy_threshold, no_entropy)
    if opts.allow_commits and any(sha.startswith(c) or c.startswith(sha[:12]) for c in opts.allow_commits):
        return []
    rules = opts.rules()
    findings = []
    for fp, line_num, line_content in _iter_diff_additions(patch, filepath=filepath):
        for f in check_line(line_content, line_num, fp, opts, rules):
            f.commit = sha[:12]
            findings.append(f)
    return findings


def _commit_allowed(sha: str, opts: ScanOptions) -> bool:
    return any(sha.startswith(c) for c in opts.allow_commits)


def scan_git_history(
    root: Path,
    entropy_threshold: float = 4.5,
    no_entropy: bool = False,
    depth: int = 100,
    since: Optional[str] = None,
    branch: Optional[str] = None,
    options: Optional[ScanOptions] = None,
    on_commit: Optional[Callable[[int], None]] = None,
) -> ScanResult:
    """Stream `git log -p` and scan added lines, one commit at a time.

    Memory stays proportional to one line, not to the history size.
    """
    opts = _opts(options, entropy_threshold, no_entropy)
    result = ScanResult()
    cmd = ["git", "-C", str(root), "log", "-p", "--unified=0", "--no-color", "--no-ext-diff",
           "--format=commit %H", f"--max-count={depth}"]
    cmd.append(branch or "--all")
    if since:
        cmd.append(f"--since={since}")

    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except FileNotFoundError:
        result.errors.append("git not found in PATH")
        return result

    rules = opts.rules()
    seen: set[tuple] = set()
    sha = ""
    skip_commit = False
    feed = _diff_parser()
    assert proc.stdout is not None
    for raw in proc.stdout:
        line = raw.decode("utf-8", errors="replace").rstrip("\n").rstrip("\r")
        if line.startswith("commit ") and len(line) == 47:
            sha = line[7:]
            skip_commit = _commit_allowed(sha, opts)
            feed = _diff_parser()
            result.commits_scanned += 1
            if on_commit:
                on_commit(result.commits_scanned)
            continue
        if skip_commit:
            continue
        out = feed(line, None)
        if not out:
            continue
        filepath, line_number, content = out
        for f in check_line(content, line_number, filepath, opts, rules):
            key = (f.matched_value, f.secret_type)
            if key not in seen:
                seen.add(key)
                f.commit = sha[:12]
                f.source = "history"
                result.findings.append(f)
    proc.wait()
    if proc.returncode != 0 and result.commits_scanned == 0:
        err = proc.stderr.read().decode(errors="replace").strip() if proc.stderr else ""
        result.errors.append(err or "Not a git repository or git not available")
    return result


def scan_diff(root: Path, diff_args: list[str], source: str = "diff",
              options: Optional[ScanOptions] = None) -> ScanResult:
    """Scan the added lines of `git diff <diff_args>`."""
    opts = _opts(options)
    result = ScanResult()
    cmd = ["git", "-C", str(root), "diff", "--unified=0", "--no-color", "--no-ext-diff", *diff_args]
    try:
        proc = subprocess.run(cmd, capture_output=True, timeout=120)
    except FileNotFoundError:
        result.errors.append("git not found in PATH")
        return result
    except subprocess.TimeoutExpired:
        result.errors.append("git diff timed out")
        return result
    if proc.returncode != 0:
        result.errors.append(proc.stderr.decode(errors="replace").strip() or "git diff failed. Is this a git repository?")
        return result

    rules = opts.rules()
    seen: set[tuple] = set()
    files_touched: set[str] = set()
    for filepath, line_number, content in _iter_diff_additions(proc.stdout.decode("utf-8", errors="replace")):
        files_touched.add(filepath)
        for f in check_line(content, line_number, filepath, opts, rules):
            key = (f.matched_value, f.secret_type, filepath)
            if key not in seen:
                seen.add(key)
                f.source = source
                result.findings.append(f)
    result.files_scanned = len(files_touched)
    return result


def scan_staged(root: Path, entropy_threshold: float = 4.5, no_entropy: bool = False,
                options: Optional[ScanOptions] = None) -> ScanResult:
    """Scan only git staged changes. Used by the pre-commit hook."""
    return scan_diff(root, ["--cached"], "staged", _opts(options, entropy_threshold, no_entropy))


def _walk(root: Path) -> Iterator[Path]:
    if root.is_file():
        yield root
        return
    real_root = os.path.realpath(root)
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in _PRUNE_DIRS]
        for name in filenames:
            p = Path(dirpath, name)
            if p.is_symlink():
                target = os.path.realpath(p)
                if not (target == real_root or target.startswith(real_root + os.sep)) or not os.path.isfile(target):
                    continue
            elif not p.is_file():
                continue
            yield p

"""Configuration for leakscan.

Sources, in order: an explicit --config file, .leakscan.yaml in the scanned
directory, or [tool.leakscan] in pyproject.toml. A config may `extends:`
another file (relative path). Rule packs imported with `leakscan rules import`
live in ~/.config/leakscan/rules/*.yaml and are loaded for every scan.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

import yaml

from scanner.engine import Override, ScanOptions
from scanner.patterns import Pattern

CONFIG_FILENAME = ".leakscan.yaml"
SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW")
_MAX_EXTENDS = 5

KNOWN_KEYS: dict[str, type | tuple[type, ...]] = {
    "extends": str,
    "custom_patterns": list,
    "rules": list,
    "exclude_paths": list,
    "severity": str,
    "fail_on": str,
    "entropy_threshold": (int, float),
    "no_entropy": bool,
    "disable_rules": list,
    "allowlist": dict,
    "overrides": list,
    "decode": bool,
    "archives": bool,
}
ALLOWLIST_KEYS = {"regexes": list, "paths": list, "commits": list, "stopwords": list}


@dataclass
class ScanConfig:
    custom_patterns: list[Pattern] = field(default_factory=list)
    exclude_paths: list[str] = field(default_factory=list)
    severity_threshold: Optional[str] = None
    fail_on: Optional[str] = None
    entropy_threshold: Optional[float] = None
    no_entropy: Optional[bool] = None
    disable_rules: set[str] = field(default_factory=set)
    allow_regexes: list[re.Pattern] = field(default_factory=list)
    allow_paths: list[str] = field(default_factory=list)
    allow_commits: set[str] = field(default_factory=set)
    stopwords: list[str] = field(default_factory=list)
    overrides: list[Override] = field(default_factory=list)
    decode: Optional[bool] = None
    archives: Optional[bool] = None
    source: Optional[Path] = None
    errors: list[str] = field(default_factory=list)

    def apply(self, opts: ScanOptions) -> ScanOptions:
        opts.extra_rules.extend(self.custom_patterns)
        opts.disable_rules |= self.disable_rules
        opts.allow_regexes.extend(self.allow_regexes)
        opts.allow_paths.extend(self.allow_paths)
        opts.allow_commits |= self.allow_commits
        opts.stopwords.extend(w.lower() for w in self.stopwords)
        opts.exclude_paths.extend(self.exclude_paths)
        opts.overrides.extend(self.overrides)
        if self.decode:
            opts.decode = True
        if self.archives:
            opts.archives = True
        return opts


def _parse_severity(raw: str) -> str:
    normalized = str(raw).strip().upper()
    return normalized if normalized in SEVERITIES else "MEDIUM"


def _compile(regex: str, errors: list[str], where: str) -> Optional[re.Pattern]:
    try:
        return re.compile(regex)
    except re.error as e:
        errors.append(f"{where}: invalid regex {regex!r}: {e}")
        return None


def build_pattern(entry: dict, errors: Optional[list[str]] = None, index: int = 0) -> Optional[Pattern]:
    errors = errors if errors is not None else []
    name = entry.get("name")
    regex = entry.get("regex")
    if not name or not regex:
        errors.append(f"custom rule #{index + 1}: 'name' and 'regex' are required")
        return None
    compiled = _compile(str(regex), errors, f"rule {name!r}")
    if compiled is None:
        return None
    rule_id = str(entry.get("id") or "LS-CUSTOM-" + re.sub(r"[^A-Z0-9]+", "-", str(name).upper()).strip("-"))
    path = entry.get("path")
    return Pattern(
        name=str(name),
        regex=compiled,
        severity=_parse_severity(entry.get("severity", "MEDIUM")),
        description=str(entry.get("description", name)),
        id=rule_id,
        confidence=float(entry.get("confidence", 0.8)),
        path=re.compile(path, re.IGNORECASE) if path else None,
    )


_build_pattern = build_pattern


def _allowlist(raw: dict, cfg: ScanConfig) -> None:
    for r in raw.get("regexes") or []:
        c = _compile(str(r), cfg.errors, "allowlist.regexes")
        if c:
            cfg.allow_regexes.append(c)
    cfg.allow_paths.extend(str(p) for p in raw.get("paths") or [])
    cfg.allow_commits |= {str(c) for c in raw.get("commits") or []}
    cfg.stopwords.extend(str(w) for w in raw.get("stopwords") or [])


def _apply_dict(data: dict, config: ScanConfig) -> None:
    rules = list(data.get("custom_patterns") or []) + list(data.get("rules") or [])
    for i, entry in enumerate(rules):
        if isinstance(entry, dict):
            pat = build_pattern(entry, config.errors, i)
            if pat:
                config.custom_patterns.append(pat)
    if isinstance(data.get("exclude_paths"), list):
        config.exclude_paths.extend(str(p) for p in data["exclude_paths"] if p)
    if "severity" in data:
        config.severity_threshold = _parse_severity(data["severity"])
    if "fail_on" in data:
        config.fail_on = _parse_severity(data["fail_on"])
    if "entropy_threshold" in data:
        try:
            config.entropy_threshold = float(data["entropy_threshold"])
        except (TypeError, ValueError):
            config.errors.append("entropy_threshold must be a number")
    if "no_entropy" in data:
        config.no_entropy = bool(data["no_entropy"])
    if "decode" in data:
        config.decode = bool(data["decode"])
    if "archives" in data:
        config.archives = bool(data["archives"])
    config.disable_rules |= {str(r).upper() if str(r).upper().startswith("LS-") else str(r)
                             for r in data.get("disable_rules") or []}
    if isinstance(data.get("allowlist"), dict):
        _allowlist(data["allowlist"], config)
    for ov in data.get("overrides") or []:
        if not isinstance(ov, dict) or not ov.get("paths"):
            config.errors.append("overrides entries need a 'paths' list")
            continue
        allow = [c for c in (_compile(str(r), config.errors, "overrides.allowlist")
                             for r in (ov.get("allowlist") or {}).get("regexes") or []) if c]
        config.overrides.append(Override(
            paths=[str(p) for p in ov["paths"]],
            disable_rules={str(r).upper() for r in ov.get("disable_rules") or []},
            allow_regexes=allow,
        ))


def _read_yaml(path: Path, config: ScanConfig) -> Optional[dict]:
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError) as e:
        config.errors.append(f"{path}: {e}")
        return None
    if not isinstance(data, dict):
        config.errors.append(f"{path}: top level must be a mapping")
        return None
    return data


def _load_file(path: Path, config: ScanConfig, depth: int = 0) -> None:
    data = _read_yaml(path, config)
    if data is None:
        return
    parent = data.get("extends")
    if parent:
        if depth >= _MAX_EXTENDS:
            config.errors.append(f"{path}: extends chain deeper than {_MAX_EXTENDS}")
        else:
            _load_file((path.parent / str(parent)).resolve(), config, depth + 1)
    _apply_dict(data, config)


def _load_pyproject(path: Path, config: ScanConfig) -> bool:
    try:
        import tomllib
    except ImportError:  # Python 3.10
        try:
            import tomli as tomllib  # type: ignore[no-redef]
        except ImportError:
            return False
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return False
    section = data.get("tool", {}).get("leakscan", {})
    if not section:
        return False
    _apply_dict(section, config)
    return True


def rules_dir() -> Path:
    base = os.environ.get("XDG_CONFIG_HOME") or os.path.join(Path.home(), ".config")
    return Path(base) / "leakscan" / "rules"


def load_rule_packs(config: ScanConfig) -> None:
    d = rules_dir()
    if not d.is_dir():
        return
    for pack in sorted(d.glob("*.y*ml")):
        data = _read_yaml(pack, config)
        if data:
            for i, entry in enumerate(data.get("rules") or []):
                if isinstance(entry, dict):
                    pat = build_pattern(entry, config.errors, i)
                    if pat:
                        config.custom_patterns.append(pat)


def load_config(directory: Path, explicit: Optional[Path] = None, packs: bool = True) -> ScanConfig:
    config = ScanConfig()
    if packs:
        load_rule_packs(config)
    if explicit is not None:
        config.source = explicit
        _load_file(explicit, config)
        return config
    yaml_path = directory / CONFIG_FILENAME
    if yaml_path.is_file():
        config.source = yaml_path
        _load_file(yaml_path, config)
        return config
    pyproject = directory / "pyproject.toml"
    if pyproject.is_file() and _load_pyproject(pyproject, config):
        config.source = pyproject
    return config


def validate_file(path: Path) -> list[str]:
    """Return a list of problems with a .leakscan.yaml file (empty if valid)."""
    cfg = ScanConfig()
    data = _read_yaml(path, cfg)
    if data is None:
        return cfg.errors
    problems = list(cfg.errors)
    for key, value in data.items():
        expected = KNOWN_KEYS.get(key)
        if expected is None:
            problems.append(f"unknown key '{key}'")
        elif not isinstance(value, expected):
            problems.append(f"'{key}' should be {_typename(expected)}, got {type(value).__name__}")
    for key in ("severity", "fail_on"):
        if key in data and str(data[key]).upper() not in SEVERITIES:
            problems.append(f"'{key}' must be one of {', '.join(SEVERITIES)}")
    allow = data.get("allowlist")
    if isinstance(allow, dict):
        for key, value in allow.items():
            if key not in ALLOWLIST_KEYS:
                problems.append(f"unknown key 'allowlist.{key}'")
            elif not isinstance(value, list):
                problems.append(f"'allowlist.{key}' should be a list")
    from scanner.patterns import by_id
    known = set(by_id())
    for r in data.get("disable_rules") or []:
        if str(r).upper().startswith("LS-") and str(r).upper() not in known and not str(r).upper().startswith("LS-CUSTOM"):
            problems.append(f"disable_rules: unknown rule id '{r}'")
    tmp = ScanConfig()
    _load_file(path, tmp)
    problems.extend(e for e in tmp.errors if e not in problems)
    return problems


def _typename(t: Any) -> str:
    if isinstance(t, tuple):
        return " or ".join(x.__name__ for x in t)
    return t.__name__

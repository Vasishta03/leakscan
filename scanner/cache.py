"""Incremental scan cache.

Only files that produced zero findings are recorded, keyed by path with
(size, mtime_ns, sha256). The cache never contains matched values, so it
is safe to keep in CI caches or commit by accident.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Optional

from scanner import __version__

DEFAULT_CACHE_FILE = ".leakscan-cache"


class Cache:
    def __init__(self, rules_hash: str, entries: Optional[dict] = None):
        self.rules_hash = rules_hash
        self.entries: dict[str, list] = entries or {}

    def get(self, label: str) -> Optional[tuple[int, int, str]]:
        e = self.entries.get(label)
        return (e[0], e[1], e[2]) if e else None

    def mark(self, label: str, stat: tuple[int, int, str]) -> None:
        self.entries[label] = list(stat)

    def drop(self, label: str) -> None:
        self.entries.pop(label, None)

    def save(self, path: Path, root: Path) -> None:
        data = {"version": 1, "leakscan": __version__, "rules_hash": self.rules_hash, "clean": self.entries}
        tmp = path.with_name(path.name + ".tmp")
        tmp.write_text(json.dumps(data, separators=(",", ":")), encoding="utf-8")
        os.replace(tmp, path)


def load(path: Path, rules_hash: str) -> Cache:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if data.get("rules_hash") == rules_hash and data.get("leakscan") == __version__:
            return Cache(rules_hash, data.get("clean") or {})
    except (OSError, ValueError, AttributeError):
        pass
    return Cache(rules_hash)

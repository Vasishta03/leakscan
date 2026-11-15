"""Scan archive members in memory without extracting to disk.

Guards: member count, total uncompressed bytes, per-member size,
compression ratio (zip bombs) and nesting depth (two levels).
"""
from __future__ import annotations

import io
import tarfile
import zipfile
from pathlib import Path
from typing import IO, Iterator

from scanner.engine import DEFAULT_MAX_FILE_SIZE, ScanOptions, ScanResult, scan_bytes

MAX_RATIO = 100


class ArchiveLimitError(Exception):
    pass


def _iter_zip(fobj: IO[bytes], opts: ScanOptions, member_limit: int) -> Iterator[tuple[str, bytes]]:
    with zipfile.ZipFile(fobj) as zf:
        infos = [i for i in zf.infolist() if not i.is_dir()]
        if len(infos) > opts.max_archive_members:
            raise ArchiveLimitError(f"more than {opts.max_archive_members} members")
        total = 0
        for info in infos:
            if info.file_size > member_limit:
                continue
            if info.compress_size and info.file_size / info.compress_size > MAX_RATIO and info.file_size > 1_000_000:
                raise ArchiveLimitError(f"suspicious compression ratio in {info.filename}")
            total += info.file_size
            if total > opts.max_archive_bytes:
                raise ArchiveLimitError("uncompressed size limit exceeded")
            with zf.open(info) as m:
                data = m.read(member_limit + 1)
            if len(data) > member_limit:
                continue
            yield info.filename, data


def _iter_tar(fobj: IO[bytes], opts: ScanOptions, member_limit: int) -> Iterator[tuple[str, bytes]]:
    with tarfile.open(fileobj=fobj, mode="r:*") as tf:
        total = count = 0
        for member in tf:
            if not member.isfile():
                continue
            count += 1
            if count > opts.max_archive_members:
                raise ArchiveLimitError(f"more than {opts.max_archive_members} members")
            if member.size > member_limit:
                continue
            total += member.size
            if total > opts.max_archive_bytes:
                raise ArchiveLimitError("uncompressed size limit exceeded")
            f = tf.extractfile(member)
            if f is None:
                continue
            yield member.name, f.read(member_limit + 1)


def iter_members(fobj: IO[bytes], name: str, opts: ScanOptions,
                 member_limit: int = DEFAULT_MAX_FILE_SIZE) -> Iterator[tuple[str, bytes]]:
    lower = name.lower()
    if lower.endswith((".zip", ".whl", ".jar", ".war", ".egg")) or zipfile.is_zipfile(fobj):
        fobj.seek(0)
        yield from _iter_zip(fobj, opts, member_limit)
    else:
        fobj.seek(0)
        yield from _iter_tar(fobj, opts, member_limit)


def _scan(fobj: IO[bytes], label: str, opts: ScanOptions, depth: int) -> ScanResult:
    result = ScanResult()
    try:
        for member, data in iter_members(fobj, label, opts):
            result.merge(scan_bytes(data, f"{label}!{member}", opts, depth))
    except ArchiveLimitError as e:
        result.errors.append(f"{label}: archive skipped ({e})")
    except (zipfile.BadZipFile, tarfile.TarError, EOFError, OSError) as e:
        result.errors.append(f"{label}: unreadable archive ({e})")
    return result


def scan_archive_path(path: Path, label: str, opts: ScanOptions) -> ScanResult:
    with open(path, "rb") as f:
        return _scan(f, label, opts, 1)


def scan_archive_bytes(data: bytes, label: str, opts: ScanOptions, depth: int) -> ScanResult:
    return _scan(io.BytesIO(data), label, opts, depth)

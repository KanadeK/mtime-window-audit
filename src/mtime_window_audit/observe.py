"""Hash only same-size pairs, with a bounded read budget and stability checks."""

import hashlib
import os
import stat
from pathlib import Path

from .core import Pair, evaluate, validate_options
from .filesystem import InputError, fingerprint, inventory, is_link

_WINDOWS = os.name == "nt"


def stable_hash(path: Path, expected: os.stat_result) -> str:
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    flags |= getattr(os, "O_NONBLOCK", 0)
    descriptor = os.open(path, flags)
    with os.fdopen(descriptor, "rb") as stream:
        opened = os.fstat(stream.fileno())
        # CPython #157671: Windows path stat ctime can be creation time while
        # descriptor fstat ctime is change time. Compare ctime only within the
        # same observation API; retain identity, mode, size and mtime across APIs.
        before_open = fingerprint(expected)[:5] if _WINDOWS else fingerprint(expected)
        after_open = fingerprint(opened)[:5] if _WINDOWS else fingerprint(opened)
        if is_link(opened) or not stat.S_ISREG(opened.st_mode) or after_open != before_open:
            raise InputError("File identity changed before hashing")
        digest = hashlib.sha256()
        total = 0
        while chunk := stream.read(min(1024 * 1024, expected.st_size - total + 1)):
            total += len(chunk)
            if total > expected.st_size:
                raise InputError("File grew during hashing")
            digest.update(chunk)
        if total != expected.st_size or fingerprint(os.fstat(stream.fileno())) != fingerprint(
            opened
        ):
            raise InputError("File changed during hashing")
    if fingerprint(path.lstat()) != fingerprint(expected):
        raise InputError("File path changed during hashing")
    return digest.hexdigest()


def audit(
    left: Path,
    right: Path,
    windows_ns: list[int],
    max_hash_bytes: int = 10 * 1024**3,
    detail_limit: int = 100,
) -> dict:
    if max_hash_bytes < 0:
        raise InputError("Hash budget cannot be negative")
    validate_options(windows_ns, detail_limit)
    left, right = Path(left), Path(right)
    lreal, rreal = left.resolve(), right.resolve()
    if lreal == rreal or lreal in rreal.parents or rreal in lreal.parents:
        raise InputError("Source and destination must be distinct, non-nested directories")
    source, target = inventory(left), inventory(right)
    common = sorted(source.files.keys() & target.files.keys())
    needed = sum(
        source.files[name].st_size * 2
        for name in common
        if source.files[name].st_size == target.files[name].st_size
    )
    if needed > max_hash_bytes:
        raise InputError(
            f"Hashing needs {needed} bytes, exceeding the {max_hash_bytes}-byte budget"
        )
    pairs = []
    for name in common:
        a, b = source.files[name], target.files[name]
        same = False
        if a.st_size == b.st_size:
            same = stable_hash(source.root / name, a) == stable_hash(target.root / name, b)
        pairs.append(Pair(name, a.st_size, b.st_size, a.st_mtime_ns, b.st_mtime_ns, same))
    data = evaluate(pairs, windows_ns, detail_limit)
    source.verify()
    target.verify()
    missing = sorted(source.files.keys() - target.files.keys())
    added = sorted(target.files.keys() - source.files.keys())
    data.update(
        {
            "schema": "mtime-window-audit/v1",
            "observation_complete": True,
            "hash_algorithm": "sha256",
            "hashed_bytes": needed,
            "hash_budget_bytes": max_hash_bytes,
            "source_only_count": len(missing),
            "target_only_count": len(added),
            "source_only": missing[:detail_limit],
            "target_only": added[:detail_limit],
            "path_details_truncated": len(missing) > detail_limit or len(added) > detail_limit,
            "ok": not missing and not added and data["content_different_pairs"] == 0,
        }
    )
    return data

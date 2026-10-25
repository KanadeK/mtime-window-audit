"""Bounded metadata inventory. Symlinks/reparse points are never traversed."""

import os
import stat
from dataclasses import dataclass
from pathlib import Path


class InputError(ValueError):
    """An incomplete or unsupported observation cannot produce a passing report."""


def fingerprint(info: os.stat_result) -> tuple[int, ...]:
    return (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def is_link(info: os.stat_result) -> bool:
    return stat.S_ISLNK(info.st_mode) or bool(getattr(info, "st_file_attributes", 0) & 0x400)


@dataclass
class Inventory:
    root: Path
    files: dict[str, os.stat_result]
    observed: dict[str, os.stat_result]

    def verify(self) -> None:
        for relative, before in self.observed.items():
            after = (self.root / relative).lstat()
            if fingerprint(before) != fingerprint(after) or is_link(after):
                raise InputError(f"Tree changed during scan at {relative!r}")


def inventory(root: Path, max_entries: int = 100_000, max_depth: int = 64) -> Inventory:
    if max_entries < 1 or max_depth < 1:
        raise InputError("Limits must be positive")
    root = Path(root).absolute()
    initial = root.lstat()
    if is_link(initial) or not stat.S_ISDIR(initial.st_mode):
        raise InputError("Root must be a real directory, not a link or reparse point")
    result = Inventory(root, {}, {".": initial})
    stack = [(root, 0)]
    while stack:
        directory, depth = stack.pop()
        with os.scandir(directory) as entries:
            for entry in entries:
                if len(result.observed) > max_entries:
                    raise InputError(f"Tree exceeds {max_entries} entries")
                path = Path(entry.path)
                relative = path.relative_to(root).as_posix()
                info = path.lstat()
                if is_link(info):
                    raise InputError(f"Link or reparse point at {relative!r}")
                result.observed[relative] = info
                if stat.S_ISDIR(info.st_mode):
                    if depth + 1 > max_depth:
                        raise InputError(f"Tree exceeds depth {max_depth}")
                    stack.append((path, depth + 1))
                elif stat.S_ISREG(info.st_mode):
                    result.files[relative] = info
                else:
                    raise InputError(f"Unsupported special file at {relative!r}")
    result.verify()
    return result

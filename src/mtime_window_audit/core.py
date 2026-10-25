"""Compare observed content truth to explicitly defined timestamp policies."""

import re
from dataclasses import dataclass
from decimal import Decimal

from .filesystem import InputError

SECOND = 1_000_000_000


@dataclass(frozen=True)
class Pair:
    path: str
    left_size: int
    right_size: int
    left_mtime_ns: int
    right_mtime_ns: int
    same_content: bool

    @property
    def delta_ns(self) -> int:
        return abs(self.left_mtime_ns - self.right_mtime_ns)


def seconds_to_ns(value: str) -> int:
    if len(value) > 64:
        raise InputError("Window value is too long")
    if re.fullmatch(r"[0-9]+(?:\.[0-9]{1,9})?", value) is None:
        raise InputError("Window must be decimal seconds with at most 9 decimal places")
    seconds = Decimal(value)
    if seconds > 86400:
        raise InputError("Window must be between 0 and 86400 seconds")
    return int(seconds * SECOND)


def predicts_skip(pair: Pair, policy: str, window_ns: int = 0) -> bool:
    if policy not in ("exact-ns", "whole-second", "inclusive-window", "size-only"):
        raise InputError(f"Unknown policy {policy!r}")
    if pair.left_size != pair.right_size:
        return False
    if policy == "exact-ns":
        return pair.delta_ns == 0
    if policy == "whole-second":
        return pair.left_mtime_ns // SECOND == pair.right_mtime_ns // SECOND
    if policy == "inclusive-window":
        return pair.delta_ns <= window_ns
    return True  # size-only


def validate_options(windows_ns: list[int], detail_limit: int) -> None:
    if not 0 <= detail_limit <= 1000:
        raise InputError("Detail limit must be between 0 and 1000")
    if len(windows_ns) > 32 or any(
        type(n) is not int or n < 0 or n > 86400 * SECOND for n in windows_ns
    ):
        raise InputError("At most 32 windows, each between 0 and 86400 seconds, are supported")


def evaluate(pairs: list[Pair], windows_ns: list[int], detail_limit: int = 100) -> dict:
    if not pairs:
        raise InputError("At least one common regular-file pair is required")
    validate_options(windows_ns, detail_limit)
    if len({pair.path for pair in pairs}) != len(pairs):
        raise InputError("Duplicate file-pair paths")
    for pair in pairs:
        if pair.left_size < 0 or pair.right_size < 0:
            raise InputError("File sizes cannot be negative")
        if pair.same_content and pair.left_size != pair.right_size:
            raise InputError("Equal contents cannot have unequal sizes")
    ordered = sorted(pairs, key=lambda pair: pair.path)
    policies = [("exact-ns", 0), ("whole-second", 0)]
    policies.extend(("inclusive-window", n) for n in sorted(set(windows_ns)))
    policies.append(("size-only", 0))
    output = []
    for policy, window in policies:
        counters = dict.fromkeys(
            ("correct_skips", "false_skips", "needless_transfers", "correct_transfers"), 0
        )
        witnesses = {"false_skips": [], "needless_transfers": []}
        needless_bytes = 0
        for pair in ordered:
            skipped = predicts_skip(pair, policy, window)
            category = (
                ("correct_skips" if pair.same_content else "false_skips")
                if skipped
                else ("needless_transfers" if pair.same_content else "correct_transfers")
            )
            counters[category] += 1
            if category == "needless_transfers":
                needless_bytes += pair.left_size
            if category in witnesses and len(witnesses[category]) < detail_limit:
                witnesses[category].append({"path": pair.path, "mtime_delta_ns": pair.delta_ns})
        output.append(
            {
                "policy": policy,
                "window_ns": window if policy == "inclusive-window" else None,
                **counters,
                "needless_logical_bytes": needless_bytes,
                "witnesses": witnesses,
                "witnesses_truncated": {
                    key: counters[key] > len(values) for key, values in witnesses.items()
                },
            }
        )
    equal = [pair for pair in ordered if pair.same_content]
    changed_same_size = [
        pair for pair in ordered if not pair.same_content and pair.left_size == pair.right_size
    ]
    lower = max((pair.delta_ns for pair in equal), default=0)
    first_unsafe = min(changed_same_size, key=lambda pair: (pair.delta_ns, pair.path), default=None)
    upper = first_unsafe.delta_ns if first_unsafe else None
    return {
        "common_pairs": len(pairs),
        "content_equal_pairs": len(equal),
        "content_different_pairs": len(pairs) - len(equal),
        "content_differences": [
            {"path": pair.path, "reason": "size" if pair.left_size != pair.right_size else "sha256"}
            for pair in ordered
            if not pair.same_content
        ][:detail_limit],
        "content_differences_truncated": len(pairs) - len(equal) > detail_limit,
        "policies": output,
        "observed_separating_window": {
            "meaning": "inclusive delta window that skips all equal pairs and no changed pairs",
            "minimum_inclusive_ns": lower if equal else None,
            "maximum_exclusive_ns": upper,
            "exists": (upper is None or lower < upper) if equal else None,
            "equal_content_evidence_pairs": len(equal),
            "changed_same_size_evidence_pairs": len(changed_same_size),
            "first_unsafe_witness": first_unsafe.path if first_unsafe else None,
            "future_safety_guaranteed": False,
        },
    }

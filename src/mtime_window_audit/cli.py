import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .core import SECOND, seconds_to_ns
from .filesystem import InputError
from .observe import audit


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Audit size/mtime skip policies against SHA-256 content"
    )
    parser.add_argument("source", type=Path)
    parser.add_argument("target", type=Path)
    parser.add_argument("--version", action="version", version=__version__)
    parser.add_argument(
        "--window", action="append", help="Inclusive tolerance in seconds; repeatable"
    )
    parser.add_argument("--max-hash-bytes", type=int, default=10 * 1024**3)
    parser.add_argument("--details", type=int, default=100, help="Witnesses per category, 0..1000")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    try:
        windows = (
            [seconds_to_ns(item) for item in args.window] if args.window else [SECOND, 2 * SECOND]
        )
        data = audit(args.source, args.target, windows, args.max_hash_bytes, args.details)
        if args.json:
            print(json.dumps(data, ensure_ascii=True, indent=2))
        else:
            print(
                f"Common pairs: {data['common_pairs']}; different content: "
                f"{data['content_different_pairs']}; hashed bytes: {data['hashed_bytes']}"
            )
            print("Policy                    False skips   Needless transfers")
            for row in data["policies"]:
                name = row["policy"]
                if row["window_ns"] is not None:
                    name = f"window {row['window_ns']} ns"
                print(f"{name:<26}{row['false_skips']:>11}{row['needless_transfers']:>21}")
            print(
                f"Source-only: {data['source_only_count']}; "
                f"target-only: {data['target_only_count']}"
            )
            print("Observed separating window: " + json.dumps(data["observed_separating_window"]))
            print(
                "Policies describe observed pairs only; this does not run or configure a sync tool."
            )
        return 0 if data["ok"] else 1
    except (InputError, OSError) as error:
        message = error.strerror if isinstance(error, OSError) else str(error)
        print(json.dumps({"error": message, "observation_complete": False}), file=sys.stderr)
        return 2

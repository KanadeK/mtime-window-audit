import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path


def main():
    with tempfile.TemporaryDirectory(prefix="mtime-window-demo-") as folder:
        left, right = Path(folder) / "source", Path(folder) / "copy"
        left.mkdir()
        right.mkdir()
        stamp = 1_700_000_000_000_000_000
        for root, hidden in ((left, b"left"), (right, b"rite")):
            (root / "hidden.txt").write_bytes(hidden)
            (root / "precision.txt").write_bytes(b"same bytes")
            for file in root.iterdir():
                os.utime(file, ns=(stamp, stamp))
        os.utime(right / "precision.txt", ns=(stamp + 1_000_000_000, stamp + 1_000_000_000))
        command = [
            sys.executable,
            "-I",
            "-m",
            "mtime_window_audit",
            str(left),
            str(right),
            "--json",
        ]
        first = subprocess.run(command, capture_output=True, text=True, check=False)
        assert first.returncode == 1, first.stderr
        data = json.loads(first.stdout)
        exact = data["policies"][0]
        assert exact["false_skips"] == 1 and exact["needless_transfers"] == 1
        assert data["observed_separating_window"]["exists"] is False
        (right / "hidden.txt").write_bytes(b"left")
        second = subprocess.run(command, capture_output=True, text=True, check=False)
        assert second.returncode == 0, second.stderr
    print("Demo passed: hidden content change and precision-only drift distinguished.")


if __name__ == "__main__":
    main()

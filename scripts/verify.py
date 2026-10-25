"""Run the same gate locally and in CI, including an isolated wheel installation."""

import os
import subprocess
import sys
import tempfile
import venv
from pathlib import Path

root = Path(__file__).resolve().parents[1]
os.chdir(root)


def run(*args):
    subprocess.run([str(x) for x in args], check=True)


run(sys.executable, "-m", "ruff", "check", ".")
run(sys.executable, "-m", "ruff", "format", "--check", ".")
run(sys.executable, "-m", "coverage", "run", "-m", "unittest", "discover", "-s", "tests", "-v")
run(sys.executable, "-m", "coverage", "report")
run(sys.executable, "-m", "build")
wheel = root / "dist" / "mtime_window_audit-0.1.0-py3-none-any.whl"
with tempfile.TemporaryDirectory(prefix="mtime-window-audit-install-") as folder:
    env = Path(folder) / "env"
    venv.EnvBuilder(with_pip=True).create(env)
    python = env / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    run(python, "-m", "pip", "install", "--no-deps", wheel)
    run(python, "-I", root / "scripts" / "demo.py")
print("All release checks passed")

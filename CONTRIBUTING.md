# Contributing

Please describe a reproducible problem with small synthetic inputs and expected
behavior. Keep the runtime dependency-free and read-only. Changes to matching or
format semantics need an independent expected-result test and documentation.

Create a virtual environment, install `python -m pip install -e ".[dev]"`, then
run `python scripts/verify.py`. CI exercises Linux, Windows and macOS. Never
commit generated reports, personal data or credentials. The maintenance release
workflow verifies author identity; CI only checks/builds and never commits code.

# Validation record

Release candidate 0.1.0, 2026-10-25. Windows, CPython 3.13.16.

- 29 unittest cases passed locally, with 2 platform skips: actual symlinks lack
  host privilege and FIFO creation is POSIX-only. Linux/macOS CI exercise both.
- 150 seeded randomized confusion-table and separating-interval comparisons
  use a set-based/brute-force reference independent of the production counts.
- Branch-aware coverage: 98% locally, with a 90% minimum release gate.
- Real files cover equal-size hidden changes, timestamp-only drift, different
  sizes, empty files, byte-budget refusal, missing/extra paths, multi-block hashes,
  file growth/truncation during a read and path replacement.
- Windows stat/fstat ctime disagreement was reproduced and fixed without
  dropping same-API change checks. A regression test simulates the mismatch on
  every operating system; see CPython issue 157671 in SOURCES.md.
- Ruff lint/format, source/wheel builds, and an isolated fresh-wheel installation
  run the same demo used in the README.

CI matrix: Linux 3.11/3.13, Windows 3.13 and macOS 3.13. Actual platform results
are in GitHub Actions; this file does not claim CI results before execution.

Review checked inclusive/exclusive boundary semantics, integer precision,
budget enforcement before reads, incomplete-scan rejection and the limits of
the content reference. No cloud or actual rsync/rclone execution is claimed.

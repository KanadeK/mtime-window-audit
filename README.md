# mtime-window-audit

Measure what a size/mtime comparison would miss or unnecessarily transfer, using
SHA-256 content comparisons of two local directory trees as the reference.

Copying files between filesystems can alter timestamp precision. Increasing a
comparison tolerance can reduce redundant transfers, but can also hide changed
files of the same size. This tool reports both effects for several policies in
one scan, with concrete filename witnesses and an observed separating interval.
It never copies, deletes, retimestamps or configures a synchronization tool.

## Install and try

Python 3.11+; no runtime dependencies:

```sh
git clone https://github.com/KanadeK/mtime-window-audit.git
cd mtime-window-audit
python -m venv .venv
```

Activate `.venv\Scripts\Activate.ps1` in PowerShell, or `. .venv/bin/activate` on
Linux/macOS, then:

```sh
python -m pip install .
python scripts/demo.py
```

The demo creates two disposable trees. One file has equal sizes and timestamps
but different bytes; another has equal bytes and a one-second timestamp drift.
It verifies that the report distinguishes these cases, then corrects the demo
copy and checks the contents pass. Temporary files are automatically removed.

For your own **stable** source and copied tree:

```sh
mtime-window-audit source-tree copied-tree
mtime-window-audit source-tree copied-tree --window 0.001 --window 1 --json > report.json
```

Keep the report outside both roots. Repeated `--window` values replace the
default 1- and 2-second windows. Values are decimal seconds with at most nine
decimal places, between 0 and 86400; exponent notation is rejected.

## Exact model

Only identical relative paths are paired; case and Unicode are not normalized.
All policies require equal file sizes to skip a pair:

| Policy | Additional condition for skipping |
|---|---|
| `exact-ns` | nanosecond mtimes are equal |
| `whole-second` | `mtime_ns // 1000000000` is equal on both sides |
| `inclusive-window` | absolute nanosecond difference is **at most** the window |
| `size-only` | no timestamp condition |

These are explicit hypothetical equality rules. They are not a full prediction
of rsync, rclone or another product: flags, version, backend precision, filters,
comparison operators, metadata, rename handling and clock behavior can change
those tools' decisions. Whole-second equality is not the same as a one-second
distance window; times on opposite sides of a second boundary demonstrate why.

For every common equal-size pair, both files are read and SHA-256 hashed. Unequal
sizes already establish a content difference and need no content read. The report
counts `correct_skips`, `false_skips`, `needless_transfers` and `correct_transfers`.
`needless_logical_bytes` sums source file sizes for redundant transfers; it is
not an estimate of network traffic or rsync's block-delta traffic. SHA-256 equality
is used as the content reference; this is not a byte-for-byte second pass.

`observed_separating_window` gives an inclusive minimum (largest drift among
equal-content pairs) and exclusive maximum (smallest drift among changed
equal-size pairs). If the lower bound meets/exceeds the upper bound, no inclusive
window separates this observation. A changed equal-size file at delta zero
makes every nonnegative window unsafe for that pair. A null maximum means there
was no changed equal-size pair to bound the window. With no equal-content pairs,
`exists` and the minimum are null: there is no evidence for a useful tolerance.
The mathematical interval can exceed the CLI's 1-day evaluation limit.
This observation never guarantees safety on future data and never adjusts clocks.

## Exit codes and bounds

- `0`: the regular-file path sets and observed contents agree. Mtime differences
  alone do not fail; policy rows may still show needless transfers.
- `1`: missing/extra paths or different contents were found.
- `2`: invalid input, no common regular-file pair, unsupported objects,
  unreadable/unstable trees or resource limit exceeded. No partial success JSON.

JSON schema: `mtime-window-audit/v1`. Paths are relative and escaped. Counts are
exact; detail lists default to 100 per category and explicitly flag truncation.
Set `--details 0..1000` to change that cap. The default total hash budget is
10 GiB, covering both copies of common equal-size files. Exceeding it fails
**before** hashing. Set `--max-hash-bytes INTEGER` deliberately for a larger job.
Each tree is limited to 100,000 entries and directory depth 64.

Source and destination must be distinct, non-nested real directories. Symlinks,
junctions, all Windows reparse points and special files cause an error; none are
silently skipped. Hidden files participate. Empty directories, permissions,
hardlink structure, ACLs, alternate streams and metadata beyond size/mtime are
outside this audit. Cloud placeholder files may be rejected as reparse points.

Use snapshots or stop writers. File descriptors, sizes and stat fingerprints
are checked before/after hashing and the tree is restatted at the end. These
checks detect ordinary concurrent changes, but do not create an atomic snapshot
or secure hostile trees against races. Ancestors must be trusted. Reads can
update access times. Reports contain filenames and should be reviewed before
sharing; file contents and absolute root paths are not included.

## Development and cleanup

```sh
python -m pip install -e ".[dev]"
python scripts/verify.py
```

Checks include lint/format, branch-aware coverage (minimum 90%), real filesystem
tests, an independent randomized confusion-table oracle, wheel/sdist builds and
a clean installed-wheel demo. CI covers Linux 3.11/3.13 and Windows/macOS 3.13.
See [VALIDATION.md](VALIDATION.md) for results.

Uninstall: `python -m pip uninstall mtime-window-audit`. Deactivate and remove
the virtual environment you created; keep or remove your own reports. There is
no background service or stored hash cache.

## Alternatives

Use [rsync `--checksum`](https://github.com/RsyncProject/rsync/blob/master/rsync.1.md)
or [rclone check](https://rclone.org/commands/rclone_check/) for their supported
transfer verification workflows. This tool adds a local comparison of several
timestamp rules against the same content evidence. It does not replace those
programs or claim their complete semantics. References: [SOURCES.md](SOURCES.md).

## 中文说明

对两个本地静止目录的同路径文件进行内容哈希比较，再评估不同“大小 + 修改时间”
规则会漏掉多少变化、产生多少多余传输。可识别相同大小和时间戳但内容不同的文件，
也能区分仅时间精度不同的副本。输出按样本计算的容差区间；不存在可区分窗口时
会明确指出。不会复制、删除、修改时间戳或设置同步软件，结果不保证未来数据安全。

MIT. [Contributing](CONTRIBUTING.md) · [Security](SECURITY.md) ·
[Third-party inventory](THIRD_PARTY.md).

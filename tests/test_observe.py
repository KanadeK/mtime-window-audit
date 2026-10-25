import contextlib
import hashlib
import io
import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from mtime_window_audit.cli import main
from mtime_window_audit.core import SECOND
from mtime_window_audit.filesystem import InputError, inventory, is_link
from mtime_window_audit.observe import audit, stable_hash


class ObserveTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.left, self.right = Path(self.temp.name) / "left", Path(self.temp.name) / "right"
        self.left.mkdir()
        self.right.mkdir()
        self.stamp = 1_700_000_000 * SECOND

    def pair(self, name="a", a=b"abc", b=b"abc", delta=0):
        for root, content, offset in ((self.left, a, 0), (self.right, b, delta)):
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content)
            os.utime(path, ns=(self.stamp + offset, self.stamp + offset))

    def invoke(self, *args):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = main([str(self.left), str(self.right), *args])
        return code, out.getvalue(), err.getvalue()

    def test_content_and_precision_witness(self):
        self.pair("changed", b"abc", b"xyz")
        self.pair("precision", delta=SECOND)
        data = audit(self.left, self.right, [SECOND])
        self.assertEqual(data["hashed_bytes"], 12)
        self.assertEqual(data["policies"][0]["false_skips"], 1)
        self.assertEqual(data["policies"][0]["needless_transfers"], 1)
        self.assertEqual(data["content_differences"], [{"path": "changed", "reason": "sha256"}])
        self.assertFalse(data["ok"])

    def test_size_differences_are_not_hashed(self):
        self.pair(a=b"x", b=b"longer")
        with patch(
            "mtime_window_audit.observe.stable_hash", side_effect=AssertionError("unexpected read")
        ):
            data = audit(self.left, self.right, [SECOND], max_hash_bytes=0)
        self.assertEqual(data["hashed_bytes"], 0)
        self.assertEqual(data["content_differences"][0]["reason"], "size")

    def test_budget_preflight(self):
        self.pair()
        with patch(
            "mtime_window_audit.observe.stable_hash", side_effect=AssertionError("unexpected read")
        ):
            with self.assertRaises(InputError):
                audit(self.left, self.right, [], max_hash_bytes=5)
        self.assertTrue(audit(self.left, self.right, [], max_hash_bytes=6)["ok"])
        with self.assertRaises(InputError):
            audit(self.left, self.right, [], max_hash_bytes=-1)

    def test_empty_files(self):
        self.pair(a=b"", b=b"")
        self.assertTrue(audit(self.left, self.right, [], max_hash_bytes=0)["ok"])

    def test_missing_extra_and_truncation(self):
        self.pair()
        (self.left / "source-only").touch()
        (self.right / "target-only").touch()
        data = audit(self.left, self.right, [], detail_limit=0)
        self.assertEqual((data["source_only_count"], data["target_only_count"]), (1, 1))
        self.assertTrue(data["path_details_truncated"])
        self.assertEqual(data["source_only"], [])
        self.assertFalse(data["ok"])

    def test_no_common_files(self):
        with self.assertRaises(InputError):
            audit(self.left, self.right, [])

    def test_same_or_nested_roots(self):
        self.pair()
        for target in (self.left, self.left / "nested"):
            with self.assertRaises(InputError):
                audit(self.left, target, [])

    def test_hash_multiple_blocks(self):
        self.pair(a=b"ab" * 600_000, b=b"ab" * 600_000)
        path = self.left / "a"
        self.assertEqual(
            stable_hash(path, path.stat()), hashlib.sha256(path.read_bytes()).hexdigest()
        )

    def test_stale_hash_observation(self):
        self.pair()
        path = self.left / "a"
        expected = path.stat()
        path.write_bytes(b"longer data")
        with self.assertRaises(InputError):
            stable_hash(path, expected)

    def test_windows_ctime_api_mismatch_regression(self):
        self.pair()
        path = self.left / "a"
        expected = path.stat()
        attrs = {
            key: getattr(expected, key)
            for key in ("st_dev", "st_ino", "st_mode", "st_size", "st_mtime_ns", "st_ctime_ns")
        }
        attrs["st_ctime_ns"] += 1234
        opened = SimpleNamespace(**attrs)
        with (
            patch("mtime_window_audit.observe._WINDOWS", True),
            patch("mtime_window_audit.observe.os.fstat", return_value=opened),
        ):
            self.assertEqual(stable_hash(path, expected), hashlib.sha256(b"abc").hexdigest())
        with (
            patch("mtime_window_audit.observe._WINDOWS", False),
            patch("mtime_window_audit.observe.os.fstat", return_value=opened),
        ):
            with self.assertRaises(InputError):
                stable_hash(path, expected)

    def test_file_grows_or_shrinks_during_read(self):
        for payload in (b"a", b"abcdef"):
            self.pair()
            path = self.left / "a"
            before = path.stat()
            real_sha256 = hashlib.sha256

            def change_file_then_hash(path=path, payload=payload, real_sha256=real_sha256):
                path.write_bytes(payload)
                return real_sha256()

            with patch(
                "mtime_window_audit.observe.hashlib.sha256", side_effect=change_file_then_hash
            ):
                with self.assertRaises(InputError):
                    stable_hash(path, before)

    def test_replaced_path_after_hash(self):
        self.pair()
        path = self.left / "a"
        expected = path.stat()
        other = self.right / "a"
        with patch.object(Path, "lstat", return_value=other.stat()):
            with self.assertRaises(InputError):
                stable_hash(path, expected)

    def test_cli_good_bad_and_text(self):
        self.pair()
        code, output, error = self.invoke("--json", "--window", "0.000000001")
        self.assertEqual(code, 0, error)
        self.assertTrue(json.loads(output)["ok"])
        self.assertIn("False skips", self.invoke()[1])
        self.pair(b=b"bad")
        self.assertEqual(self.invoke()[0], 1)
        for args in (("--window", "NaN"), ("--details", "-1"), ("--max-hash-bytes", "0")):
            code, output, error = self.invoke(*args)
            self.assertEqual(code, 2)
            self.assertEqual(output, "")
            self.assertFalse(json.loads(error)["observation_complete"])

    def test_inventory_boundaries(self):
        self.pair()
        for args in ({"max_entries": 0}, {"max_depth": 0}):
            with self.assertRaises(InputError):
                inventory(self.left, **args)
        (self.left / "nested" / "deep").mkdir(parents=True)
        with self.assertRaises(InputError):
            inventory(self.left, max_depth=1)
        with self.assertRaises(InputError):
            inventory(self.left, max_entries=1)
        with self.assertRaises(InputError):
            inventory(self.left / "a")
        snapshot = inventory(self.left)
        (self.left / "a").write_bytes(b"longer")
        with self.assertRaises(InputError):
            snapshot.verify()

    def test_reparse_recognition(self):
        self.assertTrue(is_link(SimpleNamespace(st_mode=stat.S_IFDIR, st_file_attributes=0x400)))

    def test_permission_error_cli(self):
        with patch(
            "mtime_window_audit.filesystem.os.scandir", side_effect=PermissionError("denied")
        ):
            self.assertEqual(self.invoke()[0], 2)

    def test_symlink(self):
        self.pair()
        try:
            (self.left / "link").symlink_to(self.left / "a")
        except OSError as error:
            self.skipTest(f"No symlink privilege: {error.strerror}")
        with self.assertRaises(InputError):
            audit(self.left, self.right, [])

    @unittest.skipUnless(hasattr(os, "mkfifo"), "POSIX FIFO required")
    def test_fifo(self):
        self.pair()
        os.mkfifo(self.left / "fifo")
        with self.assertRaises(InputError):
            audit(self.left, self.right, [])

    def test_module_entrypoint(self):
        self.pair()
        process = subprocess.run(
            [sys.executable, "-m", "mtime_window_audit", str(self.left), str(self.right), "--json"],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(process.returncode, 0, process.stderr)
        self.assertTrue(json.loads(process.stdout)["ok"])


if __name__ == "__main__":
    unittest.main()

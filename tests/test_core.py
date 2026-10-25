import random
import unittest

from mtime_window_audit.core import SECOND, Pair, evaluate, predicts_skip, seconds_to_ns
from mtime_window_audit.filesystem import InputError


class PolicyTests(unittest.TestCase):
    def test_hidden_change_prevents_separating_window(self):
        data = evaluate(
            [Pair("hidden", 4, 4, 0, 0, False), Pair("drift", 2, 2, 0, SECOND, True)], [SECOND]
        )
        self.assertEqual(data["policies"][0]["false_skips"], 1)
        self.assertEqual(data["policies"][0]["needless_transfers"], 1)
        self.assertFalse(data["observed_separating_window"]["exists"])
        self.assertEqual(data["observed_separating_window"]["maximum_exclusive_ns"], 0)
        self.assertEqual(data["observed_separating_window"]["first_unsafe_witness"], "hidden")

    def test_inclusive_boundary(self):
        pair = Pair("p", 1, 1, 123, 1123, False)
        self.assertFalse(predicts_skip(pair, "inclusive-window", 999))
        self.assertTrue(predicts_skip(pair, "inclusive-window", 1000))
        self.assertTrue(predicts_skip(pair, "size-only"))
        self.assertFalse(predicts_skip(Pair("p", 1, 2, 0, 0, False), "size-only"))

    def test_whole_seconds_are_not_distance_window(self):
        pair = Pair("p", 1, 1, SECOND - 1, SECOND, True)
        self.assertFalse(predicts_skip(pair, "whole-second"))
        self.assertTrue(predicts_skip(pair, "inclusive-window", 1))
        negative = Pair("p", 1, 1, -1, -SECOND, True)
        self.assertTrue(predicts_skip(negative, "whole-second"))

    def test_all_four_categories(self):
        pairs = [
            Pair("a", 5, 5, 0, 0, True),
            Pair("b", 5, 5, 0, 0, False),
            Pair("c", 5, 5, 0, SECOND, True),
            Pair("d", 5, 8, 0, 0, False),
        ]
        exact = evaluate(pairs, [SECOND])["policies"][0]
        for field in ("correct_skips", "false_skips", "needless_transfers", "correct_transfers"):
            self.assertEqual(exact[field], 1)
        self.assertEqual(exact["needless_logical_bytes"], 5)

    def test_interval_and_no_upper_bound(self):
        pairs = [Pair("a", 1, 1, 0, 7, True), Pair("b", 1, 1, 0, 10, False)]
        interval = evaluate(pairs, [0])["observed_separating_window"]
        self.assertEqual(interval["minimum_inclusive_ns"], 7)
        self.assertEqual(interval["maximum_exclusive_ns"], 10)
        self.assertTrue(interval["exists"])
        self.assertIsNone(
            evaluate(pairs[:1], [0])["observed_separating_window"]["maximum_exclusive_ns"]
        )
        self.assertIsNone(evaluate(pairs[1:], [0])["observed_separating_window"]["exists"])

    def test_equal_boundary_is_not_separable(self):
        pairs = [Pair("a", 1, 1, 0, 10, True), Pair("b", 1, 1, 0, 10, False)]
        self.assertFalse(evaluate(pairs, [10])["observed_separating_window"]["exists"])

    def test_limit_preserves_counts(self):
        pairs = [Pair(str(i), 1, 1, 0, 0, False) for i in range(8)]
        data = evaluate(pairs, [0, 0], detail_limit=2)
        self.assertEqual(len(data["policies"]), 4)
        row = data["policies"][0]
        self.assertEqual(row["false_skips"], 8)
        self.assertEqual(len(row["witnesses"]["false_skips"]), 2)
        self.assertTrue(row["witnesses_truncated"]["false_skips"])
        self.assertTrue(data["content_differences_truncated"])
        self.assertEqual(evaluate(pairs, [], 0)["content_differences"], [])

    def test_decimal_windows(self):
        for text, expected in [
            ("0", 0),
            ("0.000000001", 1),
            ("1.25", 1_250_000_000),
            ("86400", 86400 * SECOND),
        ]:
            self.assertEqual(seconds_to_ns(text), expected)
        for text in (
            "NaN",
            "Infinity",
            "-1",
            "1e2",
            "1e-100000",
            "86400.1",
            "0.0000000001",
            "9" * 65,
            "abc",
            "",
        ):
            with self.subTest(text=text), self.assertRaises(InputError):
                seconds_to_ns(text)

    def test_invalid_pairs_and_options(self):
        pair = Pair("a", 1, 1, 0, 0, True)
        for pairs, windows, limit in [
            ([], [], 100),
            ([pair, pair], [], 100),
            ([pair], [-1], 100),
            ([pair], [1] * 33, 100),
            ([pair], [True], 100),
            ([pair], [], -1),
            ([pair], [], 1001),
            ([Pair("x", -1, 1, 0, 0, False)], [], 1),
            ([Pair("x", 1, 2, 0, 0, True)], [], 1),
        ]:
            with self.assertRaises(InputError):
                evaluate(pairs, windows, limit)
        with self.assertRaises(InputError):
            predicts_skip(pair, "bad")

    def test_random_confusion_table_oracle(self):
        rng = random.Random(3602)
        for _ in range(150):
            pairs = [
                Pair(
                    str(i), 2, rng.choice([2, 3]), rng.randint(-10, 10), rng.randint(-10, 10), False
                )
                for i in range(15)
            ]
            pairs = [
                Pair(
                    p.path,
                    p.left_size,
                    p.right_size,
                    p.left_mtime_ns,
                    p.right_mtime_ns,
                    p.left_size == p.right_size and rng.choice([True, False]),
                )
                for p in pairs
            ]
            w = rng.randint(0, 15)
            row = evaluate(pairs, [w])["policies"][2]
            predicted_equal = {
                p.path
                for p in pairs
                if p.left_size == p.right_size and -w <= p.left_mtime_ns - p.right_mtime_ns <= w
            }
            truly_equal = {p.path for p in pairs if p.same_content}
            self.assertEqual(row["false_skips"], len(predicted_equal - truly_equal))
            self.assertEqual(row["needless_transfers"], len(truly_equal - predicted_equal))
            interval = evaluate(pairs, [w])["observed_separating_window"]
            possible = any(
                all(
                    (p.left_size == p.right_size and abs(p.left_mtime_ns - p.right_mtime_ns) <= t)
                    == p.same_content
                    for p in pairs
                )
                for t in range(21)
            )
            if truly_equal:
                self.assertEqual(interval["exists"], possible)

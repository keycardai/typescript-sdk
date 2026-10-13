"""Unit tests for scripts/upstream_compat.py."""

from __future__ import annotations

import unittest

import upstream_compat as uc

EVE = uc.Entry(package="eve", upstream="eve", field="peerDependencies", companions=["ai"])
A2A = uc.Entry(package="a2a", upstream="@a2a-js/sdk", field="dependencies")


class RangeMathTests(unittest.TestCase):
    def test_zero_x_range_keeps_floor_and_moves_upper_bound_to_next_minor(self) -> None:
        self.assertEqual(uc.widened_range(">=0.71.3 <0.72.0", "0.79.0"), ">=0.71.3 <0.80.0")

    def test_zero_x_version_inside_range_leaves_it_alone(self) -> None:
        self.assertEqual(uc.widened_range(">=0.71.3 <0.80.0", "0.79.1"), ">=0.71.3 <0.80.0")

    def test_caret_range_covers_a_new_minor_of_the_same_major(self) -> None:
        self.assertTrue(uc.in_range("^1.3.0", "1.4.0"))
        self.assertEqual(uc.widened_range("^1.3.0", "1.4.0"), "^1.3.0")

    def test_new_major_starts_a_new_caret_range(self) -> None:
        self.assertFalse(uc.in_range("^1.3.0", "2.0.0"))
        self.assertEqual(uc.widened_range("^1.3.0", "2.0.0"), "^2.0.0")

    def test_exact_pin_of_a_one_x_upstream_becomes_a_caret_at_the_floor(self) -> None:
        self.assertEqual(uc.widened_range("1.3.0", "1.5.0"), "^1.3.0")

    def test_caret_on_zero_x_is_minor_bounded(self) -> None:
        self.assertTrue(uc.in_range("^0.71.3", "0.71.9"))
        self.assertFalse(uc.in_range("^0.71.3", "0.72.0"))

    def test_or_ranges_and_tilde(self) -> None:
        self.assertTrue(uc.in_range("^1.0.0 || ^2.0.0", "2.3.1"))
        self.assertTrue(uc.in_range("~1.2.0", "1.2.9"))
        self.assertFalse(uc.in_range("~1.2.0", "1.3.0"))

    def test_prereleases_are_not_stable(self) -> None:
        self.assertTrue(uc.is_prerelease("0.80.0-beta.1"))
        self.assertFalse(uc.is_prerelease("0.80.0"))


class DecisionTests(unittest.TestCase):
    def test_green_outside_opens_a_pr(self) -> None:
        self.assertEqual(uc.decide(green=True, inside=False), "pr")

    def test_green_inside_only_records(self) -> None:
        self.assertEqual(uc.decide(green=True, inside=True), "record")

    def test_red_opens_an_issue_either_way(self) -> None:
        self.assertEqual(uc.decide(green=False, inside=True), "issue")
        self.assertEqual(uc.decide(green=False, inside=False), "issue")

    def test_issue_body_says_whether_users_already_get_the_break(self) -> None:
        inside = uc.issue_body(EVE, "0.79.0", ">=0.71.3 <0.80.0", True, "FAIL", "https://run")
        outside = uc.issue_body(EVE, "0.55.0", ">=0.71.3 <0.80.0", False, "FAIL", "https://run")
        self.assertIn("users installing @keycardai/eve today already get this", inside)
        self.assertIn("not affected until the range widens", outside)

    def test_companions_follow_the_upstream_peer_range(self) -> None:
        self.assertEqual(uc.companion_specs(["ai"], {"ai": "^7.0.137"}), ["ai@^7.0.137"])
        self.assertEqual(uc.companion_specs(["ai"], {}), ["ai@latest"])


class DedupeTests(unittest.TestCase):
    def test_branch_and_titles_name_the_exact_version(self) -> None:
        self.assertEqual(uc.branch_name(A2A, "1.4.0"), "upstream/a2a-a2a-js-sdk-1.4.0")
        self.assertEqual(uc.pr_title(A2A, "1.4.0"), "fix(a2a): support @a2a-js/sdk 1.4.0")
        self.assertEqual(uc.issue_title(EVE, "0.55.0"), "eve 0.55.0 breaks @keycardai/eve")

    def test_existing_item_is_found_by_exact_title_only(self) -> None:
        items = [{"number": 7, "title": "eve 0.55.0 breaks @keycardai/eve"}]
        self.assertEqual(uc.find_by_title(items, "eve 0.55.0 breaks @keycardai/eve"), 7)
        self.assertIsNone(uc.find_by_title(items, "eve 0.56.0 breaks @keycardai/eve"))

    def test_same_failure_does_not_comment_but_a_different_one_does(self) -> None:
        body = uc.issue_body(EVE, "0.55.0", ">=0.71.3 <0.80.0", False, "error TS2305: x", "")
        self.assertFalse(uc.failed_differently(body, "error TS2305: x"))
        self.assertTrue(uc.failed_differently(body, "error TS2345: y"))

    def test_already_tested_version_is_skipped(self) -> None:
        state = {"eve:eve": {"version": "0.79.0", "run": ""}}
        self.assertTrue(uc.already_tested(state, EVE, "0.79.0"))
        self.assertFalse(uc.already_tested(state, EVE, "0.79.1"))
        self.assertFalse(uc.already_tested(state, A2A, "0.79.0"))


class StateWriteTests(unittest.TestCase):
    def test_merge_by_key_keeps_the_other_entries(self) -> None:
        start = {"a2a:@a2a-js/sdk": {"version": "1.3.0", "run": "r1"}}
        from_eve = uc.merge_state(start, "eve:eve", {"version": "0.79.0", "run": "r2"})
        from_a2a = uc.merge_state(start, "a2a:@a2a-js/sdk", {"version": "1.3.1", "run": "r3"})
        self.assertEqual(set(from_eve), {"a2a:@a2a-js/sdk", "eve:eve"})
        self.assertEqual(from_eve["a2a:@a2a-js/sdk"]["version"], "1.3.0")
        self.assertEqual(from_a2a, {"a2a:@a2a-js/sdk": {"version": "1.3.1", "run": "r3"}})
        self.assertEqual(start, {"a2a:@a2a-js/sdk": {"version": "1.3.0", "run": "r1"}})

    def test_rejected_push_rereads_the_tip_and_retries_once(self) -> None:
        tips = iter([{}, {"a2a:@a2a-js/sdk": {"version": "1.3.0", "run": "r1"}}])
        results = iter([False, True])
        writes: list[dict] = []
        sleeps: list[float] = []

        def write_once(repo_root: str, branch: str, state: dict, message: str) -> bool:
            writes.append(state)
            return next(results)

        final = uc.record_state(
            "/repo", "upstream-compat-state", "eve:eve", {"version": "0.79.0", "run": "r2"}, "msg",
            read=lambda root, branch: next(tips), write_once=write_once, sleep=sleeps.append,
        )
        self.assertEqual(len(writes), 2)
        self.assertEqual(writes[0], {"eve:eve": {"version": "0.79.0", "run": "r2"}})
        self.assertEqual(set(final), {"a2a:@a2a-js/sdk", "eve:eve"})
        self.assertEqual(final, writes[1])
        self.assertEqual(len(sleeps), 1)

    def test_exhausted_attempts_fail_as_a_state_write_not_a_compat_failure(self) -> None:
        with self.assertRaises(SystemExit) as ctx:
            uc.record_state(
                "/repo", "upstream-compat-state", "eve:eve", {"version": "0.79.0", "run": ""}, "msg",
                attempts=3, read=lambda root, branch: {}, write_once=lambda *a: False, sleep=lambda s: None,
            )
        self.assertIn("state write failed after 3 attempts", str(ctx.exception))
        self.assertIn("test itself was green", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()

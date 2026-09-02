import json
import unittest
from unittest.mock import patch

import bump_package

BASE = "a" * 40
HEAD = "b" * 40
MOVED = "c" * 40
REPO = "keycardai/typescript-sdk"
BRANCH = "bump/main/keycardai-mcp-1.0.1"
HEADLINE = "bump: keycardai-mcp → 1.0.1"
BODY = "Auto-bump for keycardai-mcp."


def refs_api_calls(run_command) -> list[list[str]]:
    return [
        call.args[0]
        for call in run_command.call_args_list
        if any(arg.startswith("repos/") and "git/refs" in arg for arg in call.args[0])
    ]


def merge(**overrides):
    kwargs = {
        "repo": REPO,
        "pr_number": 1,
        "branch": BRANCH,
        "target_branch": "main",
        "base_sha": BASE,
        "package_dir": "packages/mcp",
        "files": ["packages/mcp/package.json"],
        "headline": HEADLINE,
        "body": BODY,
    }
    kwargs.update(overrides)
    return bump_package.merge_bump_pr(**kwargs)


class BumpPackageTest(unittest.TestCase):
    def test_bump_branch_names_include_release_line(self) -> None:
        self.assertEqual(
            bump_package.bump_branch_name(
                "release/mcp-v1", "keycardai-mcp", "1.0.1"
            ),
            "bump/release-mcp-v1/keycardai-mcp-1.0.1",
        )

    @patch("bump_package.run_command")
    def test_pull_branch_fetches_and_resets_requested_branch(self, run_command) -> None:
        run_command.side_effect = [(0, "", ""), (0, "", "")]

        self.assertTrue(bump_package.pull_branch("release/mcp-v1"))
        self.assertEqual(
            run_command.call_args_list[0].args[0],
            ["git", "fetch", "origin", "release/mcp-v1"],
        )
        self.assertEqual(
            run_command.call_args_list[1].args[0],
            ["git", "reset", "--hard", "origin/release/mcp-v1"],
        )

    @patch("bump_package.run_command")
    def test_forced_increment_is_forwarded_to_commitizen(self, run_command) -> None:
        run_command.return_value = (
            0,
            "bump: keycardai-mcp 0.12.1 -> 1.0.0",
            "",
        )

        version = bump_package.cz_bump_files_only(
            "packages/mcp", "keycardai-mcp", "major"
        )

        self.assertEqual(version, "1.0.0")
        self.assertEqual(
            run_command.call_args.args[0],
            [
                "cz",
                "bump",
                "--changelog",
                "--yes",
                "--files-only",
                "--increment",
                "MAJOR",
                "--allow-no-commit",
            ],
        )

    @patch("bump_package.wait_for_pr_stable", return_value=True)
    @patch("bump_package.run_command")
    def test_bump_pr_targets_release_branch(
        self, run_command, _wait_for_pr_stable
    ) -> None:
        run_command.return_value = (
            0,
            "https://github.com/keycardai/typescript-sdk/pull/200",
            "",
        )

        pr_number = bump_package.create_bump_pr(
            "bump/release-mcp-v1/keycardai-mcp-1.0.1",
            "release/mcp-v1",
            "keycardai-mcp",
            "1.0.1",
        )

        self.assertEqual(pr_number, 200)
        command = run_command.call_args.args[0]
        self.assertEqual(command[command.index("--base") + 1], "release/mcp-v1")
        for call in run_command.call_args_list:
            self.assertNotIn("--auto", call.args[0])

    @patch("bump_package.wait_for_pr_stable", return_value=True)
    @patch("bump_package.run_command")
    def test_existing_open_pr_is_reused(self, run_command, _stable) -> None:
        run_command.return_value = (
            1,
            "",
            (
                f'a pull request for branch "{BRANCH}" into branch "main" already exists:\n'
                "https://github.com/keycardai/typescript-sdk/pull/311"
            ),
        )

        pr_number = bump_package.create_bump_pr(
            BRANCH, "main", "keycardai-mcp", "1.0.1"
        )

        self.assertEqual(pr_number, 311)


class ChecksGateTests(unittest.TestCase):
    """The ref update is only reachable once every check has concluded successfully."""

    def test_verdict_prefers_failure_over_pending(self) -> None:
        data = {
            "statusCheckRollup": [
                {"name": "socket-scan", "status": "IN_PROGRESS", "conclusion": None},
                {"name": "test", "status": "COMPLETED", "conclusion": "FAILURE"},
            ]
        }
        self.assertEqual(bump_package.checks_verdict(data), ("FAILURE", "test"))

    def test_verdict_is_pending_while_any_check_runs(self) -> None:
        data = {
            "statusCheckRollup": [
                {"name": "test", "status": "COMPLETED", "conclusion": "SUCCESS"},
                {"name": "build", "status": "QUEUED", "conclusion": None},
            ]
        }
        self.assertEqual(bump_package.checks_verdict(data), ("PENDING", "build"))

    def test_unregistered_rollup_is_pending_not_success(self) -> None:
        self.assertEqual(
            bump_package.checks_verdict({"statusCheckRollup": []}), ("PENDING", None)
        )
        self.assertEqual(
            bump_package.checks_verdict({"statusCheckRollup": None}), ("PENDING", None)
        )

    @patch("bump_package.time.sleep", lambda _s: None)
    @patch("bump_package.time.time", return_value=0)
    @patch("bump_package.run_command")
    def test_failed_check_refuses_without_touching_refs(
        self, run_command, _time
    ) -> None:
        run_command.return_value = (
            0,
            json.dumps(
                {
                    "state": "OPEN",
                    "headRefOid": HEAD,
                    "statusCheckRollup": [
                        {"name": "test", "status": "COMPLETED", "conclusion": "FAILURE"}
                    ],
                }
            ),
            "",
        )

        self.assertIsNone(bump_package.wait_for_checks(REPO, 1))
        self.assertEqual(refs_api_calls(run_command), [])

    @patch("bump_package.time.sleep", lambda _s: None)
    @patch("bump_package.time.time", side_effect=[0, 10_000])
    @patch("bump_package.run_command")
    def test_pending_checks_time_out_instead_of_passing(
        self, run_command, _time
    ) -> None:
        run_command.return_value = (
            0,
            json.dumps(
                {
                    "state": "OPEN",
                    "headRefOid": HEAD,
                    "statusCheckRollup": [
                        {"name": "test", "status": "IN_PROGRESS", "conclusion": None}
                    ],
                }
            ),
            "",
        )

        self.assertIsNone(bump_package.wait_for_checks(REPO, 1, timeout_seconds=1))
        self.assertEqual(refs_api_calls(run_command), [])

    @patch("bump_package.time.sleep", lambda _s: None)
    @patch("bump_package.time.time", side_effect=[0, 10_000])
    @patch("bump_package.run_command")
    def test_fresh_commit_with_no_registered_checks_times_out_instead_of_merging(
        self, run_command, _time
    ) -> None:
        run_command.return_value = (
            0,
            json.dumps({"state": "OPEN", "headRefOid": HEAD, "statusCheckRollup": []}),
            "",
        )

        self.assertIsNone(bump_package.wait_for_checks(REPO, 1, timeout_seconds=1))
        self.assertEqual(refs_api_calls(run_command), [])

    @patch("bump_package.fast_forward_target")
    @patch("bump_package.wait_for_checks", return_value=None)
    def test_ref_update_is_unreachable_when_checks_gate_refuses(
        self, _checks, fast_forward_target
    ) -> None:
        self.assertIsNone(merge())
        fast_forward_target.assert_not_called()


class StrictFastForwardTests(unittest.TestCase):
    """The target ref is only ever fast-forwarded, from the SHA the bump was built on."""

    @patch("bump_package.verify_pr_merged")
    @patch("bump_package.rebase_bump_branch", return_value=False)
    @patch("bump_package.get_live_branch_sha", return_value=MOVED)
    @patch("bump_package.wait_for_checks", return_value={"head": HEAD})
    @patch("bump_package.run_command")
    def test_guard_refuses_when_target_moved(
        self, run_command, _checks, _live, rebase_bump_branch, verify_pr_merged
    ) -> None:
        self.assertIsNone(merge())
        self.assertEqual(refs_api_calls(run_command), [])
        rebase_bump_branch.assert_called_once_with(
            REPO, BRANCH, BASE, MOVED, "packages/mcp",
            ["packages/mcp/package.json"], HEADLINE, BODY,
        )
        verify_pr_merged.assert_not_called()

    @patch("bump_package.verify_pr_merged", return_value=HEAD)
    @patch("bump_package.get_live_branch_sha", return_value=BASE)
    @patch("bump_package.wait_for_checks", return_value={"head": HEAD})
    @patch("bump_package.run_command", return_value=(0, "{}", ""))
    def test_fast_forward_never_forces_the_target_ref(
        self, run_command, _checks, _live, _verify
    ) -> None:
        self.assertEqual(merge(), HEAD)
        calls = refs_api_calls(run_command)
        self.assertEqual(len(calls), 1)
        command = calls[0]
        self.assertIn("PATCH", command)
        self.assertIn(f"repos/{REPO}/git/refs/heads/main", command)
        self.assertIn(f"sha={HEAD}", command)
        self.assertFalse(any("force" in arg for arg in command), command)

    @patch("bump_package.create_signed_commit_on_branch", return_value=True)
    @patch("bump_package.run_command")
    def test_rebuild_refuses_when_target_changed_bumped_files(
        self, run_command, create_signed_commit_on_branch
    ) -> None:
        run_command.return_value = (0, "packages/mcp/package.json\nREADME.md", "")

        rebuilt = bump_package.rebase_bump_branch(
            REPO, BRANCH, BASE, MOVED, "packages/mcp",
            ["packages/mcp/package.json", "packages/mcp/CHANGELOG.md"],
            HEADLINE, BODY,
        )

        self.assertFalse(rebuilt)
        self.assertEqual(refs_api_calls(run_command), [])
        create_signed_commit_on_branch.assert_not_called()

    @patch("bump_package.create_signed_commit_on_branch", return_value=True)
    @patch("bump_package.run_command")
    def test_rebuild_refuses_when_target_changed_package_sources(
        self, run_command, create_signed_commit_on_branch
    ) -> None:
        run_command.return_value = (0, "packages/mcp/src/index.ts\nREADME.md", "")

        rebuilt = bump_package.rebase_bump_branch(
            REPO, BRANCH, BASE, MOVED, "packages/mcp",
            ["packages/mcp/package.json", "packages/mcp/CHANGELOG.md"],
            HEADLINE, BODY,
        )

        self.assertFalse(rebuilt)
        self.assertEqual(refs_api_calls(run_command), [])
        create_signed_commit_on_branch.assert_not_called()

    @patch("bump_package.create_signed_commit_on_branch", return_value=True)
    @patch("bump_package.run_command")
    def test_rebuild_proceeds_when_target_changes_are_unrelated(
        self, run_command, create_signed_commit_on_branch
    ) -> None:
        run_command.side_effect = [
            (0, "README.md\ndocs/guide.md", ""),
            (0, "", ""),
        ]

        rebuilt = bump_package.rebase_bump_branch(
            REPO, BRANCH, BASE, MOVED, "packages/mcp",
            ["packages/mcp/package.json", "packages/mcp/CHANGELOG.md"],
            HEADLINE, BODY,
        )

        self.assertTrue(rebuilt)
        calls = refs_api_calls(run_command)
        self.assertEqual(len(calls), 1)
        self.assertIn(f"repos/{REPO}/git/refs/heads/{BRANCH}", calls[0])
        self.assertIn("force=true", calls[0])
        create_signed_commit_on_branch.assert_called_once()

    @patch("bump_package.verify_pr_merged", return_value=HEAD)
    @patch("bump_package.fast_forward_target", return_value=True)
    @patch("bump_package.wait_for_pr_stable", return_value=True)
    @patch("bump_package.rebase_bump_branch", return_value=True)
    @patch("bump_package.get_live_branch_sha", side_effect=[MOVED, MOVED])
    @patch("bump_package.wait_for_checks", return_value={"head": HEAD})
    def test_rebuild_reenters_the_stable_wait_before_rereading_checks(
        self, wait_for_checks, _live, _rebase, wait_for_pr_stable, _ff, _verify
    ) -> None:
        self.assertEqual(merge(), HEAD)
        wait_for_pr_stable.assert_called_once_with(1)
        self.assertEqual(wait_for_checks.call_count, 2)

    @patch("bump_package.verify_pr_merged", return_value=HEAD)
    @patch("bump_package.wait_for_pr_stable", return_value=True)
    @patch("bump_package.rebase_bump_branch", return_value=True)
    @patch("bump_package.fast_forward_target", side_effect=[False, True])
    @patch("bump_package.get_live_branch_sha", side_effect=[BASE, MOVED, MOVED])
    @patch("bump_package.wait_for_checks", return_value={"head": HEAD})
    def test_ff_refusal_reprobes_the_live_tip_and_rebuilds(
        self, _checks, _live, fast_forward_target, rebase_bump_branch, _stable, _verify
    ) -> None:
        self.assertEqual(merge(), HEAD)
        rebase_bump_branch.assert_called_once()
        self.assertEqual(fast_forward_target.call_count, 2)


class RefusedMergeTests(unittest.TestCase):
    """The target ref moves only after green checks, only by strict fast-forward,
    and the tag is only created after GitHub reports the PR merged."""

    @patch("bump_package.time.sleep", lambda _s: None)
    @patch("bump_package.time.time", side_effect=[0, 0, 10_000])
    @patch("bump_package.run_command")
    def test_refused_fast_forward_never_escalates_to_force(
        self, run_command, _time
    ) -> None:
        pr_view = json.dumps(
            {
                "state": "OPEN",
                "headRefOid": HEAD,
                "mergeCommit": None,
                "statusCheckRollup": [
                    {"name": "test", "status": "COMPLETED", "conclusion": "SUCCESS"}
                ],
            }
        )

        def fake(command, *args, **kwargs):
            if command[:3] == ["gh", "pr", "view"]:
                return 0, pr_view, ""
            if command[:2] == ["gh", "api"] and command[2].startswith("repos/") and "git/ref/heads/main" in command[2]:
                return 0, BASE, ""
            if "PATCH" in command:
                return 1, "", "HTTP 422: Update is not a fast forward"
            return 0, "", ""

        run_command.side_effect = fake
        sha = merge(max_rounds=1)

        self.assertIsNone(sha)
        patches = [c for c in refs_api_calls(run_command) if "PATCH" in c]
        self.assertEqual(len(patches), 1)
        self.assertIn(f"repos/{REPO}/git/refs/heads/main", patches[0])
        for command in run_command.call_args_list:
            self.assertFalse(
                any("force" in arg for arg in command.args[0]), command.args[0]
            )
        self.assertFalse(
            any("refs/tags/" in arg for c in run_command.call_args_list for arg in c.args[0])
        )

    @patch("bump_package.time.sleep", lambda _s: None)
    @patch("bump_package.time.time", side_effect=[0, 10_000])
    @patch("bump_package.run_command")
    def test_unmerged_pr_after_fast_forward_returns_none(self, run_command, _time) -> None:
        run_command.return_value = (
            0,
            json.dumps({"state": "OPEN", "mergeCommit": None}),
            "",
        )

        self.assertIsNone(
            bump_package.verify_pr_merged(REPO, 1, HEAD, timeout_seconds=1)
        )

    @patch("bump_package.run_command")
    def test_merge_at_unexpected_sha_returns_none(self, run_command) -> None:
        run_command.return_value = (
            0,
            json.dumps({"state": "MERGED", "mergeCommit": {"oid": MOVED}}),
            "",
        )

        self.assertIsNone(bump_package.verify_pr_merged(REPO, 1, HEAD))

    @patch("bump_package.delete_remote_branch")
    @patch("bump_package.create_and_push_tag")
    @patch("bump_package.verify_pr_merged", return_value=None)
    @patch("bump_package.fast_forward_target", return_value=True)
    @patch("bump_package.get_live_branch_sha", return_value=BASE)
    @patch("bump_package.wait_for_checks", return_value={"head": HEAD})
    @patch("bump_package.create_bump_pr", return_value=1)
    @patch("bump_package.create_signed_commit_on_branch", return_value=True)
    @patch("bump_package.create_remote_branch", return_value=True)
    @patch("bump_package.get_modified_files", return_value=["packages/mcp/package.json"])
    @patch("bump_package.get_branch_sha", return_value=BASE)
    @patch("bump_package.cz_bump_files_only", return_value="1.0.1")
    @patch("bump_package.recover_untagged_bump", return_value=None)
    @patch("bump_package.get_repo_slug", return_value=REPO)
    @patch("bump_package.pull_branch", return_value=True)
    @patch("bump_package.configure_git")
    @patch("bump_package.Path.exists", return_value=True)
    def test_tag_is_unreachable_when_merge_verification_fails(self, *mocks) -> None:
        create_and_push_tag = mocks[-2]
        delete_remote_branch = mocks[-1]

        self.assertFalse(bump_package.bump_package("keycardai-mcp", "packages/mcp"))
        create_and_push_tag.assert_not_called()
        delete_remote_branch.assert_not_called()

    @patch("bump_package.delete_remote_branch")
    @patch("bump_package.create_and_push_tag", return_value=True)
    @patch("bump_package.merge_bump_pr", return_value=HEAD)
    @patch("bump_package.create_bump_pr", return_value=1)
    @patch("bump_package.create_signed_commit_on_branch", return_value=True)
    @patch("bump_package.create_remote_branch", return_value=True)
    @patch("bump_package.get_modified_files", return_value=["packages/mcp/package.json"])
    @patch("bump_package.get_branch_sha", return_value=BASE)
    @patch("bump_package.cz_bump_files_only", return_value="1.0.1")
    @patch("bump_package.recover_untagged_bump", return_value=None)
    @patch("bump_package.get_repo_slug", return_value=REPO)
    @patch("bump_package.pull_branch", return_value=True)
    @patch("bump_package.configure_git")
    @patch("bump_package.Path.exists", return_value=True)
    def test_tag_follows_verified_merge_then_branch_is_deleted(self, *mocks) -> None:
        create_and_push_tag = mocks[-2]
        delete_remote_branch = mocks[-1]

        self.assertTrue(bump_package.bump_package("keycardai-mcp", "packages/mcp"))
        create_and_push_tag.assert_called_once_with(REPO, "1.0.1-keycardai-mcp", HEAD)
        delete_remote_branch.assert_called_once_with(REPO, BRANCH)


class ExternalMergeTests(unittest.TestCase):
    """A PR merged by someone else mid-wait is adopted, not treated as failure."""

    @patch("bump_package.run_command")
    def test_human_merge_during_checks_wait_is_adopted(self, run_command) -> None:
        run_command.return_value = (
            0,
            json.dumps(
                {"state": "MERGED", "mergeCommit": {"oid": MOVED}, "statusCheckRollup": []}
            ),
            "",
        )

        self.assertEqual(bump_package.wait_for_checks(REPO, 1), {"merged": MOVED})

    @patch("bump_package.verify_pr_merged")
    @patch("bump_package.fast_forward_target")
    @patch("bump_package.wait_for_checks", return_value={"merged": MOVED})
    def test_external_merge_skips_the_ref_update_and_returns_its_sha(
        self, _checks, fast_forward_target, verify_pr_merged
    ) -> None:
        self.assertEqual(merge(), MOVED)
        fast_forward_target.assert_not_called()
        verify_pr_merged.assert_not_called()

    @patch("bump_package.time.sleep", lambda _s: None)
    @patch("bump_package.run_command")
    def test_closed_pr_aborts_the_wait(self, run_command) -> None:
        run_command.return_value = (0, json.dumps({"state": "CLOSED"}), "")

        self.assertIsNone(bump_package.wait_for_checks(REPO, 1))


class BranchLifecycleTests(unittest.TestCase):
    """A stale bump branch is reused; the target branch is never force-moved."""

    @patch("bump_package.run_command")
    def test_stale_branch_from_failed_run_is_force_moved_not_fatal(
        self, run_command
    ) -> None:
        run_command.side_effect = [
            (1, "", "HTTP 422: Reference already exists"),
            (0, "", ""),
        ]

        self.assertTrue(bump_package.create_remote_branch(REPO, BRANCH, BASE))
        recover = run_command.call_args_list[1].args[0]
        self.assertIn("PATCH", recover)
        self.assertIn(f"repos/{REPO}/git/refs/heads/{BRANCH}", recover)
        self.assertIn(f"sha={BASE}", recover)
        self.assertIn("force=true", recover)

    @patch("bump_package.run_command", return_value=(1, "", "HTTP 403 Forbidden"))
    def test_other_branch_creation_errors_still_fail(self, run_command) -> None:
        self.assertFalse(bump_package.create_remote_branch(REPO, BRANCH, BASE))
        self.assertEqual(len(run_command.call_args_list), 1)


if __name__ == "__main__":
    unittest.main()

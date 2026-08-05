import unittest
from unittest.mock import patch

import bump_package


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

    @patch("bump_package.enable_automerge", return_value=True)
    @patch("bump_package.wait_for_pr_stable", return_value=True)
    @patch("bump_package.run_command")
    def test_bump_pr_targets_release_branch(
        self, run_command, _wait_for_pr_stable, _enable_automerge
    ) -> None:
        run_command.return_value = (
            0,
            "https://github.com/keycardai/typescript-sdk/pull/200",
            "",
        )

        pr_number = bump_package.create_pr_with_automerge(
            "bump/release-mcp-v1/keycardai-mcp-1.0.1",
            "release/mcp-v1",
            "keycardai-mcp",
            "1.0.1",
        )

        self.assertEqual(pr_number, 200)
        command = run_command.call_args.args[0]
        self.assertEqual(command[command.index("--base") + 1], "release/mcp-v1")


if __name__ == "__main__":
    unittest.main()

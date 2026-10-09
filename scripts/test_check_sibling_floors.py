"""Unit tests for the pure parts of check_sibling_floors.py (SDK-18).

Same style as test_bump_package.py. Run with:

    python3 -m unittest discover -s scripts -p 'test_*.py'
"""

import contextlib
import io
import unittest

import bump_package
import check_sibling_floors

RELEASE_APP = check_sibling_floors.DEFAULT_RELEASE_APP_LOGIN
FLOORS = {"@keycardai/oauth": "0.26.1", "@keycardai/express": "0.9.3"}


def _exists_except(*missing: tuple[str, str]):
    def exists(sibling: str, version: str) -> bool:
        return (sibling, version) not in missing

    return exists


class FloorParsingTests(unittest.TestCase):
    def test_caret_range_floor_is_its_lower_bound(self) -> None:
        self.assertEqual(check_sibling_floors.parse_floor("^0.26.1"), "0.26.1")

    def test_exact_pin_floor_is_the_pin(self) -> None:
        self.assertEqual(check_sibling_floors.parse_floor("0.26.1"), "0.26.1")

    def test_tilde_and_gte_floors(self) -> None:
        self.assertEqual(check_sibling_floors.parse_floor("~2.0.3"), "2.0.3")
        self.assertEqual(check_sibling_floors.parse_floor(">=2.0.3"), "2.0.3")

    def test_unbounded_specifiers_have_no_floor(self) -> None:
        for specifier in ("*", "latest", "workspace:^", "workspace:*", ""):
            self.assertIsNone(check_sibling_floors.parse_floor(specifier), specifier)

    def test_read_floors_keeps_only_keycardai_dependencies(self) -> None:
        packed = {
            "name": "@keycardai/mcp",
            "dependencies": {
                "@keycardai/express": "^0.9.3",
                "@keycardai/oauth": "0.26.1",
                "express": "^5.1.0",
            },
        }
        self.assertEqual(check_sibling_floors.read_floors(packed), FLOORS)

    def test_read_floors_exits_on_an_unreadable_specifier(self) -> None:
        packed = {"name": "@keycardai/mcp", "dependencies": {"@keycardai/oauth": "*"}}
        with contextlib.redirect_stdout(io.StringIO()) as out, self.assertRaises(SystemExit) as cm:
            check_sibling_floors.read_floors(packed)
        self.assertEqual(cm.exception.code, 1)
        self.assertIn("cannot read a floor", out.getvalue())


class WorkspaceSpecifierTests(unittest.TestCase):
    def test_workspace_star_is_rejected_with_a_pointer_to_caret(self) -> None:
        source = {
            "name": "@keycardai/mcp",
            "dependencies": {"@keycardai/oauth": "workspace:*", "@keycardai/express": "workspace:^"},
        }
        with contextlib.redirect_stdout(io.StringIO()) as out:
            exact = check_sibling_floors.check_workspace_specifiers("@keycardai/mcp", source)
        self.assertEqual(exact, ["@keycardai/oauth"])
        self.assertIn("::error::@keycardai/mcp: @keycardai/oauth is declared workspace:*", out.getvalue())
        self.assertIn("use workspace:^", out.getvalue())

    def test_workspace_caret_passes(self) -> None:
        source = {"name": "@keycardai/eve", "dependencies": {"@keycardai/oauth": "workspace:^"}}
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(check_sibling_floors.check_workspace_specifiers("@keycardai/eve", source), [])

    def test_third_party_workspace_star_is_not_this_check(self) -> None:
        source = {"name": "@keycardai/eve", "dependencies": {"some-tool": "workspace:*"}}
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(check_sibling_floors.check_workspace_specifiers("@keycardai/eve", source), [])


class ParseBumpPrTests(unittest.TestCase):
    def test_release_app_on_bump_branch_is_a_bump_pr(self) -> None:
        branch = bump_package.bump_branch_name("main", "keycardai-oauth", "0.26.2")
        self.assertEqual(
            check_sibling_floors.parse_bump_pr(branch, RELEASE_APP, RELEASE_APP),
            ("@keycardai/oauth", "0.26.2"),
        )

    def test_release_line_branch_is_a_bump_pr(self) -> None:
        branch = bump_package.bump_branch_name("release/mcp-v1", "keycardai-mcp", "1.0.1")
        self.assertEqual(
            check_sibling_floors.parse_bump_pr(branch, RELEASE_APP, RELEASE_APP),
            ("@keycardai/mcp", "1.0.1"),
        )

    def test_hyphenated_package_name(self) -> None:
        branch = bump_package.bump_branch_name("main", "keycardai-pi-mono", "0.2.0")
        self.assertEqual(
            check_sibling_floors.parse_bump_pr(branch, RELEASE_APP, RELEASE_APP),
            ("@keycardai/pi-mono", "0.2.0"),
        )

    def test_bump_branch_from_a_human_is_not_a_bump_pr(self) -> None:
        branch = bump_package.bump_branch_name("main", "keycardai-oauth", "0.26.2")
        self.assertIsNone(check_sibling_floors.parse_bump_pr(branch, "larry", RELEASE_APP))

    def test_release_app_on_another_branch_is_not_a_bump_pr(self) -> None:
        self.assertIsNone(
            check_sibling_floors.parse_bump_pr("devin/123-something", RELEASE_APP, RELEASE_APP)
        )


class AheadOfNpmTests(unittest.TestCase):
    def _run(self, *, bootstrap: bool, bump_pr, missing) -> tuple[bool | None, int | None, str]:
        out = io.StringIO()
        result = None
        code = None
        with contextlib.redirect_stdout(out):
            try:
                result = check_sibling_floors.check_ahead_of_npm(
                    "@keycardai/mcp",
                    FLOORS,
                    bootstrap=bootstrap,
                    bump_pr=bump_pr,
                    exists=_exists_except(*missing),
                )
            except SystemExit as e:
                code = e.code
        return result, code, out.getvalue()

    def test_all_floors_published_proceeds(self) -> None:
        result, code, out = self._run(bootstrap=False, bump_pr=None, missing=[])
        self.assertTrue(result)
        self.assertIsNone(code)

    def test_floor_ahead_of_npm_fails_without_a_skip(self) -> None:
        result, code, out = self._run(
            bootstrap=False, bump_pr=None, missing=[("@keycardai/oauth", "0.26.1")]
        )
        self.assertIsNone(result)
        self.assertEqual(code, 1)
        self.assertIn("::error::@keycardai/mcp: floor @keycardai/oauth@0.26.1 is ahead of npm", out)
        self.assertIn("floors-bootstrap", out)

    def test_bootstrap_label_turns_the_failure_into_a_skip(self) -> None:
        result, code, out = self._run(
            bootstrap=True, bump_pr=None, missing=[("@keycardai/oauth", "0.26.1")]
        )
        self.assertFalse(result)
        self.assertIsNone(code)
        self.assertIn("::warning::", out)
        self.assertIn("skipping the floors check", out)

    def test_bump_pr_for_the_missing_version_skips(self) -> None:
        result, code, out = self._run(
            bootstrap=False,
            bump_pr=("@keycardai/oauth", "0.26.1"),
            missing=[("@keycardai/oauth", "0.26.1")],
        )
        self.assertFalse(result)
        self.assertIsNone(code)
        self.assertIn("is the version this bump PR releases", out)

    def test_bump_pr_for_another_version_still_fails(self) -> None:
        result, code, out = self._run(
            bootstrap=False,
            bump_pr=("@keycardai/oauth", "0.27.0"),
            missing=[("@keycardai/oauth", "0.26.1")],
        )
        self.assertIsNone(result)
        self.assertEqual(code, 1)

    def test_bump_pr_does_not_cover_a_second_missing_sibling(self) -> None:
        result, code, out = self._run(
            bootstrap=False,
            bump_pr=("@keycardai/oauth", "0.26.1"),
            missing=[("@keycardai/oauth", "0.26.1"), ("@keycardai/express", "0.9.3")],
        )
        self.assertIsNone(result)
        self.assertEqual(code, 1)
        self.assertIn("@keycardai/express@0.9.3 is ahead of npm", out)


if __name__ == "__main__":
    unittest.main()

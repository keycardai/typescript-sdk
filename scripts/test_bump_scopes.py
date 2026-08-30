"""Dry-run tests for the scoped increment classifiers in each package .cz.toml.

Each test builds a throwaway git repo whose config is the real package
``.cz.toml``, replays a synthetic commit history through
``cz bump --dry-run``, and asserts the increment cz derives. The histories
always contain a breaking commit scoped to a *different* package, which must
not influence the target package's version.

Run with:

    python -m unittest discover -s scripts -p "test_*.py"
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
import tomllib
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

GIT_ENV = {
    "GIT_AUTHOR_NAME": "Test",
    "GIT_AUTHOR_EMAIL": "test@example.com",
    "GIT_COMMITTER_NAME": "Test",
    "GIT_COMMITTER_EMAIL": "test@example.com",
    "GIT_CONFIG_GLOBAL": os.devnull,
    "GIT_CONFIG_SYSTEM": os.devnull,
}


def cz_config(package_dir: str) -> dict:
    with (REPO_ROOT / package_dir / ".cz.toml").open("rb") as handle:
        return tomllib.load(handle)["tool"]["commitizen"]


class ScopedBumpHarness(unittest.TestCase):
    """Builds synthetic repos and reports the version cz would bump to."""

    def run_in(self, cwd: Path, command: list[str]) -> str:
        result = subprocess.run(
            command,
            cwd=cwd,
            capture_output=True,
            text=True,
            check=True,
            env={**os.environ, **GIT_ENV},
        )
        return result.stdout

    def dry_run_version(self, package_dir: str, commits: list[str]) -> str:
        """Return the version ``cz bump --dry-run`` derives for ``commits``.

        The synthetic repo starts at the package's currently configured
        version, tagged with the package's real ``tag_format``, so cz only
        considers the commits added afterwards.
        """
        config = cz_config(package_dir)
        version = config["version"]
        tag = config["tag_format"].replace("${version}", version)

        workdir = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, workdir, ignore_errors=True)

        shutil.copy(REPO_ROOT / package_dir / ".cz.toml", workdir / ".cz.toml")
        (workdir / "package.json").write_text(
            json.dumps({"name": package_dir, "version": version}) + "\n"
        )
        (workdir / "CHANGELOG.md").write_text("# Changelog\n")

        self.run_in(workdir, ["git", "init", "--initial-branch", "main"])
        self.run_in(workdir, ["git", "add", "."])
        self.run_in(workdir, ["git", "commit", "-m", "chore: baseline"])
        self.run_in(workdir, ["git", "tag", tag])

        for message in commits:
            self.run_in(
                workdir,
                ["git", "commit", "--allow-empty", "-m", message],
            )

        stdout = self.run_in(workdir, ["cz", "bump", "--dry-run", "--yes"])
        match = re.search(r"(\d+\.\d+\.\d+)\s*(?:→|->)\s*(\d+\.\d+\.\d+)", stdout)
        self.assertIsNotNone(match, f"could not parse cz output: {stdout}")
        assert match is not None
        return match.group(2)

    def assert_no_bump(self, package_dir: str, commits: list[str]) -> None:
        with self.assertRaises(subprocess.CalledProcessError) as raised:
            self.dry_run_version(package_dir, commits)
        self.assertIn("NO_COMMITS_TO_BUMP", raised.exception.stderr)


class ForeignBreakingCommitTests(ScopedBumpHarness):
    def test_foreign_breaking_change_does_not_major_bump_oauth(self) -> None:
        """A breaking mcp commit must not escalate oauth past its own fix."""
        version = self.dry_run_version(
            "packages/oauth",
            [
                "feat(mcp)!: drop the legacy transport",
                "fix(oauth): tolerate empty scope strings",
            ],
        )
        self.assertEqual(version, "0.20.1")

    def test_foreign_breaking_change_footer_does_not_major_bump_mcp(self) -> None:
        """The escalation must not leak through BREAKING CHANGE footers either."""
        version = self.dry_run_version(
            "packages/mcp",
            [
                "feat(oauth): add resource indicators\n\nBREAKING CHANGE: token shape changed",
                "fix(mcp): retry the metadata probe",
            ],
        )
        self.assertEqual(version, "2.0.1")

    def test_foreign_commits_alone_bump_nothing(self) -> None:
        self.assert_no_bump(
            "packages/sdk",
            [
                "feat(oauth)!: drop deprecated helpers",
                "fix(express): correct the middleware order",
            ],
        )


class ScopedIncrementTests(ScopedBumpHarness):
    def test_own_breaking_commit_cuts_a_major(self) -> None:
        version = self.dry_run_version(
            "packages/mcp",
            [
                "feat(oauth)!: drop deprecated helpers",
                "feat(mcp)!: require the new client contract",
            ],
        )
        self.assertEqual(version, "3.0.0")

    def test_own_scoped_breaking_footer_cuts_a_major(self) -> None:
        version = self.dry_run_version(
            "packages/mcp",
            ["fix(mcp): tighten validation\n\nBREAKING CHANGE(mcp): renamed the export"],
        )
        self.assertEqual(version, "3.0.0")

    def test_own_feat_is_a_minor(self) -> None:
        version = self.dry_run_version(
            "packages/oauth",
            [
                "fix(mcp): unrelated fix",
                "feat(oauth): add device authorization support",
            ],
        )
        self.assertEqual(version, "0.21.0")

    def test_own_refactor_and_perf_are_patches(self) -> None:
        self.assertEqual(
            self.dry_run_version(
                "packages/express", ["refactor(express): split the handler module"]
            ),
            "0.9.1",
        )
        self.assertEqual(
            self.dry_run_version(
                "packages/express", ["perf(express): cache the JWKS lookup"]
            ),
            "0.9.1",
        )

    def test_major_version_zero_package_demotes_its_own_breaking_commit(self) -> None:
        """0.x packages keep breaking changes at minor, foreign or not."""
        version = self.dry_run_version(
            "packages/a2a",
            [
                "feat(mcp)!: drop the legacy transport",
                "feat(a2a)!: rename the task envelope",
            ],
        )
        self.assertEqual(version, "0.4.0")


class ConfigShapeTests(unittest.TestCase):
    def test_every_package_scopes_its_bump_classifier(self) -> None:
        package_dirs = sorted(
            path.parent for path in (REPO_ROOT / "packages").glob("*/.cz.toml")
        )
        self.assertTrue(package_dirs)
        for package_dir in package_dirs:
            with self.subTest(package=package_dir.name):
                customize = cz_config(f"packages/{package_dir.name}")["customize"]
                scope = re.search(
                    r"\\\((?P<scope>[\w-]+)\\\)", customize["changelog_pattern"]
                )
                self.assertIsNotNone(scope)
                assert scope is not None
                self.assertIn(
                    f"\\({scope.group('scope')}\\)", customize["bump_pattern"]
                )
                self.assertEqual(customize["bump_map"]["^.+!$"], "MAJOR")
                self.assertEqual(customize["bump_map"]["^feat"], "MINOR")
                self.assertEqual(customize["bump_map"]["^fix"], "PATCH")
                self.assertEqual(
                    customize["bump_map_major_version_zero"]["^.+!$"], "MINOR"
                )


if __name__ == "__main__":
    unittest.main()

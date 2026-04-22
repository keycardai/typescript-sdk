#!/usr/bin/env python3
"""
Changelog management tool for workspace packages.

Usage:
  python scripts/changelog.py validate [base_branch]
  python scripts/changelog.py check-drift
  python scripts/changelog.py changes [--output-format json|github]
  python scripts/changelog.py package <tag> [--output-format json|github]

Commands:
  validate      Validate commit messages against conventional commit format
  check-drift   Fail if any package's .cz.toml version disagrees with its package.json
  changes       Detect packages with unreleased changes
  package       Extract package information from GitHub tag
"""

import argparse
import json
import subprocess
import sys
from pathlib import Path

try:
    import tomllib
except ImportError:
    import tomli as tomllib  # Python < 3.11


def run_command(cmd: list[str], cwd: str = None) -> tuple[int, str, str]:
    """Run a command and return exit code, stdout, stderr."""
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, cwd=cwd)
        return result.returncode, result.stdout.strip(), result.stderr.strip()
    except Exception as e:
        return 1, "", str(e)


def get_merge_base(base_branch: str) -> str:
    """Get the merge base commit."""
    exit_code, stdout, stderr = run_command(
        ["git", "merge-base", base_branch, "HEAD"]
    )
    if exit_code != 0:
        raise Exception(f"Failed to get merge base: {stderr}")
    return stdout


def discover_workspace_packages() -> list[dict]:
    """Discover packages from the pnpm workspace that have commitizen config."""
    root_dir = Path(__file__).parent.parent

    # Read pnpm-workspace.yaml to find package dirs
    workspace_path = root_dir / "pnpm-workspace.yaml"
    if not workspace_path.exists():
        raise Exception(f"Could not find pnpm-workspace.yaml at {workspace_path}")

    # Simple YAML parsing for "packages:" list (avoids PyYAML dependency)
    package_patterns = []
    with open(workspace_path) as f:
        in_packages = False
        for line in f:
            stripped = line.strip()
            if stripped == "packages:":
                in_packages = True
                continue
            if in_packages:
                if stripped.startswith("- "):
                    pattern = stripped[2:].strip().strip('"').strip("'")
                    package_patterns.append(pattern)
                elif stripped and not stripped.startswith("#"):
                    break

    if not package_patterns:
        raise Exception("No package patterns found in pnpm-workspace.yaml")

    packages = []

    for pattern in package_patterns:
        # Expand glob pattern
        if "*" in pattern:
            base_dir = root_dir / pattern.replace("/*", "").replace("*", "")
            if base_dir.is_dir():
                for member_path in sorted(base_dir.iterdir()):
                    if not member_path.is_dir():
                        continue
                    _try_add_package(member_path, root_dir, packages)
        else:
            member_path = root_dir / pattern
            if member_path.is_dir():
                _try_add_package(member_path, root_dir, packages)

    if not packages:
        raise Exception("No packages with commitizen configuration found")
    return packages


def _try_add_package(
    member_path: Path, root_dir: Path, packages: list[dict]
) -> None:
    """If the directory has a .cz.toml, add it to the packages list."""
    cz_toml = member_path / ".cz.toml"
    if not cz_toml.exists():
        return

    try:
        with open(cz_toml, "rb") as f:
            cz_config = tomllib.load(f)
    except Exception:
        return

    commitizen_config = cz_config.get("tool", {}).get("commitizen", {})
    if not commitizen_config:
        return

    # Derive package name from tag_format (e.g., "${version}-keycardai-oauth" -> "keycardai-oauth")
    tag_format = commitizen_config.get("tag_format", "")
    package_name = tag_format.replace("${version}-", "").replace("$version-", "")
    if not package_name:
        package_name = member_path.name

    relative_path = str(member_path.relative_to(root_dir))

    packages.append(
        {
            "package_name": package_name,
            "package_dir": relative_path,
        }
    )


def validate_commits_with_cz(base_branch: str) -> bool:
    """Validate commits using commitizen."""
    base_sha = get_merge_base(base_branch)
    rev_range = f"{base_sha}..HEAD"

    exit_code, stdout, _ = run_command(["git", "rev-list", rev_range])
    if exit_code != 0 or not stdout.strip():
        return True  # No commits to validate

    exit_code, stdout, stderr = run_command(
        ["cz", "check", "--rev-range", rev_range]
    )
    return exit_code == 0


def parse_changelog_for_changes(package_dir: str) -> bool:
    """Check if a package has unreleased changes via cz changelog --dry-run."""
    exit_code, stdout, stderr = run_command(
        ["cz", "changelog", "--dry-run"], cwd=package_dir
    )
    if exit_code != 0:
        # No changes or error — treat as no changes
        return False

    if not stdout.strip():
        return False

    lines = stdout.split("\n")
    if not lines[0].strip().startswith("## Unreleased"):
        return False

    changes = []
    for line in lines[1:]:
        line = line.strip()
        if line.startswith("##"):
            break
        if line:
            changes.append(line)

    return len(changes) > 0


def detect_changed_packages() -> list[dict]:
    """Detect which packages have unreleased changes."""
    all_packages = discover_workspace_packages()
    changed = []
    for package in all_packages:
        if parse_changelog_for_changes(package["package_dir"]):
            changed.append(package)
    return changed


def extract_package_from_tag(tag: str) -> dict:
    """Extract package information from a GitHub tag.

    Tags follow: <version>-<package-name>
    Examples: 0.2.0-keycardai-oauth, 0.3.0-keycardai-mcp
    """
    if not tag:
        raise Exception("Tag cannot be empty")

    if tag.startswith("refs/tags/"):
        tag = tag[len("refs/tags/"):]

    all_packages = discover_workspace_packages()

    for package in all_packages:
        suffix = package["package_name"]
        if tag.endswith(f"-{suffix}"):
            version = tag[: -len(f"-{suffix}")]
            return {
                "tag": tag,
                "version": version,
                "package_suffix": suffix,
                "package_name": package["package_name"],
                "package_dir": package["package_dir"],
            }

    raise Exception(
        f"No package found for tag '{tag}'. "
        "Expected format: <version>-<package-name>"
    )


# ---------------------------------------------------------------------------
# CLI subcommands
# ---------------------------------------------------------------------------


def cmd_validate(args):
    if validate_commits_with_cz(args.base_branch):
        print("\n✅ All commit messages are valid!")
    else:
        print("\n❌ Some commit messages are invalid!")
        print(
            "Please fix the commit messages to follow the conventional commit format."
        )
        sys.exit(1)


def check_version_drift() -> list[dict]:
    """Return a list of drift entries. Empty list means no drift.

    Commitizen treats `[tool.commitizen].version` in `.cz.toml` as the source
    of truth for "what's the current version." `cz bump` uses that to compute
    the next version and also updates the files listed in `version_files`
    (here, `package.json:version`). If someone hand-edits `package.json`
    without running `cz bump`, the two drift apart and the next automated
    bump tries to create a tag that already exists. This check catches that
    before it becomes a release outage.
    """
    root_dir = Path(__file__).parent.parent
    drift = []

    for pkg in discover_workspace_packages():
        pkg_dir = root_dir / pkg["package_dir"]
        cz_path = pkg_dir / ".cz.toml"
        pkg_json_path = pkg_dir / "package.json"

        if not cz_path.exists() or not pkg_json_path.exists():
            continue

        with open(cz_path, "rb") as f:
            cz_version = tomllib.load(f).get("tool", {}).get("commitizen", {}).get("version")

        with open(pkg_json_path) as f:
            pkg_json_version = json.load(f).get("version")

        if cz_version and pkg_json_version and cz_version != pkg_json_version:
            drift.append(
                {
                    "package": pkg["package_name"],
                    "package_dir": pkg["package_dir"],
                    "cz_toml_version": cz_version,
                    "package_json_version": pkg_json_version,
                }
            )

    return drift


def cmd_check_drift(_args):
    drift = check_version_drift()
    if not drift:
        print("✅ No version drift — every .cz.toml matches its package.json.")
        return
    print("❌ Version drift detected:")
    for d in drift:
        print(
            f"  {d['package']} ({d['package_dir']}): "
            f".cz.toml says {d['cz_toml_version']}, "
            f"package.json says {d['package_json_version']}"
        )
    print(
        "\nFix by updating [tool.commitizen].version in .cz.toml to match "
        "package.json. Going forward, use `cz bump` (not hand-edits) to change "
        "package versions so both files stay in sync."
    )
    sys.exit(1)


def cmd_changes(args):
    changed = detect_changed_packages()
    if args.output_format == "json":
        print(json.dumps(changed, indent=2))
    else:
        print(json.dumps(changed))


def cmd_package(args):
    try:
        info = extract_package_from_tag(args.tag)
        if args.output_format == "json":
            print(json.dumps(info, indent=2))
        else:
            print(json.dumps(info))
    except Exception as e:
        print(f"❌ Error: {e}", file=sys.stderr)
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        description="Changelog management tool for workspace packages"
    )
    subparsers = parser.add_subparsers(dest="command")

    validate_p = subparsers.add_parser("validate", help="Validate commit messages")
    validate_p.add_argument(
        "base_branch", nargs="?", default="origin/main"
    )
    validate_p.set_defaults(func=cmd_validate)

    changes_p = subparsers.add_parser(
        "changes", help="Detect packages with unreleased changes"
    )
    changes_p.add_argument(
        "--output-format",
        choices=["json", "github"],
        default="github",
    )
    changes_p.set_defaults(func=cmd_changes)

    drift_p = subparsers.add_parser(
        "check-drift",
        help="Check that each package's .cz.toml version matches its package.json version",
    )
    drift_p.set_defaults(func=cmd_check_drift)

    package_p = subparsers.add_parser(
        "package", help="Extract package info from GitHub tag"
    )
    package_p.add_argument("tag")
    package_p.add_argument(
        "--output-format",
        choices=["json", "github"],
        default="github",
    )
    package_p.set_defaults(func=cmd_package)

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        sys.exit(1)
    args.func(args)


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"❌ Error: {e}", file=sys.stderr)
        sys.exit(1)

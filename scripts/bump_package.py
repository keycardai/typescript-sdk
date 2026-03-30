#!/usr/bin/env python3
"""
Bump package version using commitizen.

Handles version bumping for a specific package including retry logic
for pushing changes to avoid race conditions in CI.
"""

import argparse
import subprocess
import sys
import time
from pathlib import Path


def run_command(cmd: list[str], cwd: str | None = None) -> tuple[int, str, str]:
    """Run a command and return exit code, stdout, and stderr."""
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, cwd=cwd, check=False
        )
        return result.returncode, result.stdout.strip(), result.stderr.strip()
    except Exception as e:
        return 1, "", str(e)


def configure_git() -> None:
    """Configure git for automated commits."""
    print("Configuring git...")
    run_command(["git", "config", "--local", "user.email", "action@github.com"])
    run_command(["git", "config", "--local", "user.name", "GitHub Action"])


def pull_latest_changes() -> bool:
    """Pull latest changes from origin/main, handling local modifications."""
    print("Checking for local changes before pulling...")

    exit_code, stdout, stderr = run_command(["git", "status", "--porcelain"])
    if exit_code != 0:
        print(f"Failed to check git status: {stderr}")
        return False

    has_local_changes = bool(stdout.strip())

    if has_local_changes:
        print(f"Found local changes:\n{stdout}")
        print("Stashing local changes before pulling...")
        exit_code, _, stderr = run_command(
            ["git", "stash", "push", "-m", "Auto-stash before version bump"]
        )
        if exit_code != 0:
            print(f"Failed to stash local changes: {stderr}")
            return False

    print("Pulling latest changes from origin/main...")
    exit_code, _, stderr = run_command(["git", "pull", "origin", "main"])
    if exit_code != 0:
        print(f"Failed to pull latest changes: {stderr}")
        if has_local_changes:
            run_command(["git", "stash", "pop"])
        return False

    if has_local_changes:
        print("Restoring stashed changes...")
        exit_code, _, stderr = run_command(["git", "stash", "pop"])
        if exit_code != 0:
            print(f"Warning: Failed to restore stashed changes: {stderr}")
            # Handle pnpm-lock.yaml conflicts
            if "pnpm-lock.yaml" in stderr:
                print("Detected pnpm-lock.yaml conflict. Resolving...")
                run_command(["git", "checkout", "--theirs", "pnpm-lock.yaml"])
                run_command(["git", "add", "pnpm-lock.yaml"])
                run_command(["git", "stash", "drop"])

    return True


def run_bump(package_dir: str, package_name: str) -> bool:
    """Run commitizen bump in the specified package directory."""
    print(f"Running version bump for {package_name} in {package_dir}...")

    exit_code, stdout, stderr = run_command(
        ["cz", "bump", "--changelog", "--yes"], cwd=package_dir
    )

    if exit_code != 0:
        print(f"Failed to bump version: {stderr}")
        return False

    print("Version bump completed successfully")
    print(stdout)
    return True


def push_changes_with_retry(max_attempts: int = 3) -> bool:
    """Push changes to origin/main with retry logic."""
    for attempt in range(1, max_attempts + 1):
        print(f"Attempting to push changes (attempt {attempt}/{max_attempts})...")

        exit_code, _, stderr = run_command(
            ["git", "push", "origin", "main", "--follow-tags"]
        )

        if exit_code == 0:
            print(f"Successfully pushed changes on attempt {attempt}")
            # Explicitly push tags
            print("Explicitly pushing tags...")
            run_command(["git", "push", "origin", "--tags"])
            return True

        print(f"Push failed on attempt {attempt}: {stderr}")

        if attempt < max_attempts:
            print("Pulling latest changes and retrying...")
            if not pull_latest_changes():
                print("Failed to pull latest changes during retry")
                continue
            print("Waiting 2 seconds before retry...")
            time.sleep(2)
        else:
            print(f"Failed to push after {max_attempts} attempts")

    return False


def bump_package(package_name: str, package_dir: str) -> bool:
    """Bump version for a specific package."""
    print(f"Starting version bump for {package_name} package...")

    if not Path(package_dir).exists():
        print(f"Error: Package directory {package_dir} does not exist")
        return False

    configure_git()

    if not pull_latest_changes():
        return False

    if not run_bump(package_dir, package_name):
        return False

    if not push_changes_with_retry():
        return False

    print(f"Successfully completed version bump for {package_name}")
    return True


def main():
    parser = argparse.ArgumentParser(
        description="Bump package version using commitizen"
    )
    parser.add_argument("package_name", help="Package name (e.g., keycardai-oauth)")
    parser.add_argument("package_dir", help="Package directory (e.g., packages/oauth)")

    args = parser.parse_args()
    success = bump_package(args.package_name, args.package_dir)
    if not success:
        print("Version bump failed")
        sys.exit(1)


if __name__ == "__main__":
    main()

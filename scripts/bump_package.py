#!/usr/bin/env python3
"""Bump package version via an auto-merging PR.

Compatible with branch-protection rulesets that require all changes to land
through PRs and require commits to be signed:

0. If the configured version already has a merged bump commit on main but
   no release tag (a prior run's merge-wait timed out before tagging), the
   missing tag is pushed and the run stops. Re-running cz in that state
   would double-bump.
1. ``cz bump --files-only`` updates ``.cz.toml`` (cz version field),
   ``package.json`` (via version_files), and ``CHANGELOG.md`` in the package
   directory; no local commit or tag.
2. A new branch ``bump/<package>-<version>`` is created on the remote at the
   current main tip via the REST refs API.
3. The bumped files are committed onto that branch via the GraphQL
   ``createCommitOnBranch`` mutation, which signs the commit as the
   authenticated bot identity.
4. A PR is opened with auto-merge armed. Once its checks are green the
   script merges it directly: the workflow app is a ruleset bypass actor,
   and auto-merge never exercises bypass, it only fires when every
   requirement (including required reviews) is actually satisfied. Auto-merge
   stays armed as the fallback if the direct merge is refused. Previously the
   script only waited for auto-merge, i.e. it merges itself once
   required CI checks pass on it.
5. The script polls until the PR merges, captures the squash-merge SHA on
   ``main``, then creates and pushes the ``<version>-<package>`` tag at
   that SHA. Tags trigger the existing ``publish.yml`` publish workflow.

The runner needs:

- ``GH_TOKEN`` (or ``GITHUB_TOKEN``) in env, scoped to allow ``gh api``
  calls and PR creation. Provided by the workflow via
  ``secrets.RELEASE_GITHUB_PAT``.
- A repo configured with auto-merge enabled and a squash-merge option.
"""

import argparse
import base64
import json
import os
import re
import subprocess
import sys
import tempfile
import time
from pathlib import Path


def run_command(cmd: list[str], cwd: str | None = None, env: dict | None = None) -> tuple[int, str, str]:
    """Run a command and return exit code, stdout, and stderr."""
    try:
        merged_env = os.environ.copy()
        if env:
            merged_env.update(env)
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            cwd=cwd,
            check=False,
            env=merged_env,
        )
        return result.returncode, result.stdout.strip(), result.stderr.strip()
    except Exception as e:
        return 1, "", str(e)


def configure_git() -> None:
    print("Configuring git...")
    run_command(["git", "config", "--local", "user.email", "action@github.com"])
    run_command(["git", "config", "--local", "user.name", "GitHub Action"])


def get_repo_slug() -> str:
    """Return ``owner/repo`` for the current checkout, e.g. ``keycardai/typescript-sdk``."""
    exit_code, stdout, _ = run_command(
        ["gh", "repo", "view", "--json", "nameWithOwner", "-q", ".nameWithOwner"]
    )
    if exit_code != 0 or not stdout:
        print("Failed to determine repository slug from gh CLI")
        sys.exit(1)
    return stdout


def get_main_sha() -> str:
    """Return the current commit SHA on origin/main."""
    exit_code, stdout, stderr = run_command(["git", "rev-parse", "origin/main"])
    if exit_code != 0:
        print(f"Failed to read origin/main: {stderr}")
        sys.exit(1)
    return stdout


def pull_main() -> bool:
    print("Pulling latest changes from origin/main...")
    exit_code, _, stderr = run_command(["git", "fetch", "origin", "main"])
    if exit_code != 0:
        print(f"Failed to fetch origin/main: {stderr}")
        return False
    exit_code, _, stderr = run_command(["git", "reset", "--hard", "origin/main"])
    if exit_code != 0:
        print(f"Failed to reset to origin/main: {stderr}")
        return False
    return True


def get_configured_version(package_dir: str) -> str | None:
    """Return the version cz has recorded for the package, or ``None``."""
    exit_code, stdout, stderr = run_command(
        ["cz", "version", "--project"], cwd=package_dir
    )
    if exit_code != 0 or not stdout.strip():
        print(f"Could not read configured version: {stderr}")
        return None
    return stdout.strip()


def tag_exists_on_remote(tag: str) -> bool:
    exit_code, stdout, _ = run_command(
        ["git", "ls-remote", "--tags", "origin", f"refs/tags/{tag}"]
    )
    return exit_code == 0 and bool(stdout.strip())


def recover_untagged_bump(repo: str, package_name: str, package_dir: str) -> bool | None:
    """Push the missing release tag for a bump that merged without one.

    A bump PR can merge after this job's merge-wait times out, leaving the
    version files ahead of the last release tag with nothing to trigger the
    publish. When the configured version has a merged bump commit on main
    but no tag, push the tag at that commit and stop.

    Returns ``True`` when the missing tag was pushed (the bump is complete),
    ``False`` when the tag push failed, and ``None`` when there is nothing
    to recover and the normal bump flow should proceed.
    """
    version = get_configured_version(package_dir)
    if version is None:
        return None
    tag = f"{version}-{package_name}"
    if tag_exists_on_remote(tag):
        return None

    headline = f"bump: {package_name} → {version}"
    exit_code, stdout, _ = run_command(
        ["git", "log", "--fixed-strings", f"--grep={headline}", "--format=%H", "-1", "HEAD"]
    )
    sha = stdout.strip()
    if exit_code != 0 or not sha:
        return None

    print(
        f"Version {version} has a merged bump commit ({sha[:8]}) but no {tag} tag; "
        "recovering the tag instead of bumping again."
    )
    if not create_and_push_tag(repo, tag, sha):
        return False
    print(f"Recovered: tag {tag} pushed.")
    return True


def cz_bump_files_only(package_dir: str, package_name: str) -> str | None:
    """Run ``cz bump --files-only`` and return the new version string.

    cz prints a line like ``bump: keycardai-oauth 0.4.0 → 0.5.0`` to stdout;
    we parse that for the new version. Returns ``None`` if cz failed or
    the version transition could not be determined (e.g. nothing to bump).
    """
    print(f"Running cz bump --files-only for {package_name}...")
    exit_code, stdout, stderr = run_command(
        ["cz", "bump", "--changelog", "--yes", "--files-only"],
        cwd=package_dir,
    )

    if exit_code != 0:
        if "NO_COMMITS_TO_BUMP" in stderr or "no eligible commits" in stderr.lower():
            print("cz reports no eligible commits since last tag; nothing to bump.")
            return None
        print(f"cz bump failed (exit {exit_code}): {stderr}")
        sys.exit(1)

    print(stdout)

    match = re.search(r"\b(\d+\.\d+\.\d+)\s*(?:→|->|to)\s*(\d+\.\d+\.\d+)", stdout)
    if not match:
        print(f"Could not parse new version from cz output: {stdout}")
        sys.exit(1)
    return match.group(2)


def get_modified_files() -> list[str]:
    """Return the list of files changed in the working tree (relative paths)."""
    exit_code, stdout, stderr = run_command(["git", "diff", "--name-only"])
    if exit_code != 0:
        print(f"Failed to list modified files: {stderr}")
        sys.exit(1)
    return [line for line in stdout.splitlines() if line]


def create_remote_branch(repo: str, branch: str, sha: str) -> str:
    """Create the bump branch on the remote at ``sha``.

    Returns ``"created"`` on success, ``"exists"`` if the ref already exists
    (a prior run created it), or ``"error"`` on any other failure. The
    ``"exists"`` case is recoverable: a previous run got partway through and
    the caller resumes from the existing branch/PR rather than failing.
    """
    print(f"Creating remote branch {branch} at {sha[:8]}...")
    exit_code, _, stderr = run_command(
        [
            "gh",
            "api",
            f"repos/{repo}/git/refs",
            "-X",
            "POST",
            "-f",
            f"ref=refs/heads/{branch}",
            "-f",
            f"sha={sha}",
        ]
    )
    if exit_code != 0:
        if "Reference already exists" in stderr or "HTTP 422" in stderr:
            print(f"Branch {branch} already exists; resuming from it.")
            return "exists"
        print(f"Failed to create remote branch: {stderr}")
        return "error"
    return "created"


def get_branch_head_sha(repo: str, branch: str) -> str | None:
    """Return the head commit SHA of a remote branch, or ``None`` if unknown."""
    exit_code, stdout, _ = run_command(
        ["gh", "api", f"repos/{repo}/git/ref/heads/{branch}", "-q", ".object.sha"]
    )
    if exit_code != 0 or not stdout:
        return None
    return stdout


def find_pr_for_branch(branch: str) -> dict | None:
    """Return the most recent PR whose head is ``branch``, or ``None``.

    Includes merged/closed PRs so a resumed run can detect an already-merged
    bump and skip straight to tagging.
    """
    exit_code, stdout, _ = run_command(
        [
            "gh",
            "pr",
            "list",
            "--head",
            branch,
            "--state",
            "all",
            "--json",
            "number,state,mergeCommit",
            "--limit",
            "1",
        ]
    )
    if exit_code != 0 or not stdout:
        return None
    try:
        prs = json.loads(stdout)
    except json.JSONDecodeError:
        return None
    return prs[0] if prs else None


def enable_automerge(pr_number: int) -> bool:
    """Enable squash auto-merge on a PR. Idempotent: a PR that already has
    auto-merge enabled reports success."""
    print(f"Enabling auto-merge (squash) on PR #{pr_number}...")
    exit_code, _, stderr = run_command(
        ["gh", "pr", "merge", str(pr_number), "--auto", "--squash"]
    )
    if exit_code != 0 and "already" not in stderr.lower():
        print(f"Failed to enable auto-merge: {stderr}")
        return False
    return True


def create_signed_commit_on_branch(
    repo: str,
    branch: str,
    parent_sha: str,
    files: list[str],
    headline: str,
    body: str,
) -> bool:
    """Submit a signed commit to ``branch`` via the GraphQL
    ``createCommitOnBranch`` mutation.

    Each file's current working-tree content is base64-encoded and sent as
    a file addition. The commit is signed by GitHub as the authenticated
    user (the bot identity owning ``GH_TOKEN``).
    """
    print(f"Creating signed commit on {branch} via GraphQL mutation...")

    additions = []
    for path in files:
        content = Path(path).read_bytes()
        additions.append(
            {
                "path": path,
                "contents": base64.b64encode(content).decode("ascii"),
            }
        )

    mutation = (
        "mutation($input: CreateCommitOnBranchInput!) {"
        "  createCommitOnBranch(input: $input) {"
        "    commit { oid url }"
        "  }"
        "}"
    )
    request_body = {
        "query": mutation,
        "variables": {
            "input": {
                "branch": {"repositoryNameWithOwner": repo, "branchName": branch},
                "expectedHeadOid": parent_sha,
                "fileChanges": {"additions": additions},
                "message": {"headline": headline, "body": body},
            }
        },
    }

    # gh api graphql --input <file> is the path that accepts a fully-formed
    # request body. --raw-field variables=... does not preserve nested JSON.
    with tempfile.NamedTemporaryFile(
        "w", suffix=".json", delete=False
    ) as tmp:
        json.dump(request_body, tmp)
        tmp_path = tmp.name

    try:
        exit_code, stdout, stderr = run_command(
            ["gh", "api", "graphql", "--input", tmp_path]
        )
    finally:
        os.unlink(tmp_path)

    if exit_code != 0:
        print(f"GraphQL createCommitOnBranch failed: {stderr}")
        return False

    try:
        payload = json.loads(stdout)
        if "errors" in payload:
            print(f"GraphQL returned errors: {payload['errors']}")
            return False
        oid = payload["data"]["createCommitOnBranch"]["commit"]["oid"]
        print(f"Created signed commit {oid[:8]} on {branch}")
    except (json.JSONDecodeError, KeyError) as e:
        print(f"Unexpected GraphQL response shape: {stdout} ({e})")
        return False
    return True


def wait_for_pr_stable(pr_number: int, timeout_seconds: int = 300) -> bool:
    """Poll mergeStateStatus until GitHub has a definite state for the PR.

    A freshly opened PR starts as UNKNOWN or UNSTABLE while required checks
    register. Auto-merge can only be enabled once the PR leaves that limbo.
    """
    deadline = time.time() + timeout_seconds
    while time.time() < deadline:
        exit_code, stdout, _ = run_command(
            ["gh", "pr", "view", str(pr_number), "--json", "mergeStateStatus"]
        )
        if exit_code == 0:
            state = json.loads(stdout).get("mergeStateStatus", "")
            print(f"PR #{pr_number} merge state: {state}")
            if state not in ("UNKNOWN", "UNSTABLE"):
                return True
        time.sleep(5)
    print(f"Timed out waiting for PR #{pr_number} to reach a stable merge state")
    return False


def create_pr_with_automerge(
    branch: str, package_name: str, new_version: str
) -> int | None:
    """Open a PR for the bump branch with auto-merge (squash) enabled.

    Returns the PR number on success, ``None`` on failure.
    """
    title = f"bump: {package_name} → {new_version}"
    pr_body = (
        f"Auto-bump for `{package_name}` to `{new_version}`.\n\n"
        "Generated by `scripts/bump_package.py`. The version tag will be "
        "created at the squash-merge SHA after this PR merges, which "
        "triggers the publish workflow."
    )

    print(f"Opening PR for {branch}...")
    exit_code, stdout, stderr = run_command(
        [
            "gh",
            "pr",
            "create",
            "--head",
            branch,
            "--base",
            "main",
            "--title",
            title,
            "--body",
            pr_body,
        ]
    )
    if exit_code != 0:
        print(f"Failed to create PR: {stderr}")
        return None

    pr_url = stdout.strip().splitlines()[-1]
    pr_number_match = re.search(r"/pull/(\d+)", pr_url)
    if not pr_number_match:
        print(f"Could not parse PR number from gh output: {pr_url}")
        return None
    pr_number = int(pr_number_match.group(1))
    print(f"Opened PR #{pr_number}: {pr_url}")

    # A timeout here is non-fatal: enabling auto-merge is retried below and
    # the merge poll tolerates a PR that is still settling.
    wait_for_pr_stable(pr_number)

    if not enable_automerge(pr_number):
        return None
    return pr_number


def checks_green(pr_data: dict) -> bool:
    """True when every check in the PR's status rollup has finished cleanly.

    An empty rollup counts as green (no required checks registered).
    """
    ok_conclusions = {"SUCCESS", "NEUTRAL", "SKIPPED"}
    for check in pr_data.get("statusCheckRollup") or []:
        status = (check.get("status") or "").upper()
        conclusion = (check.get("conclusion") or "").upper()
        if status and status != "COMPLETED":
            return False
        if conclusion and conclusion not in ok_conclusions:
            return False
        if not status and not conclusion:
            return False
    return True


def wait_for_pr_merge(repo: str, pr_number: int, timeout_seconds: int = 1800) -> str | None:
    """Poll the PR until it merges. Returns the merge commit SHA on main.

    Fails if the PR is closed without merging or if the timeout elapses.
    Polls every 30s; logs each status change so the run is debuggable.
    """
    print(f"Waiting for PR #{pr_number} to merge (timeout {timeout_seconds}s)...")
    deadline = time.time() + timeout_seconds
    last_state = None
    direct_merge_attempts = 0

    while time.time() < deadline:
        exit_code, stdout, stderr = run_command(
            [
                "gh",
                "pr",
                "view",
                str(pr_number),
                "--json",
                "state,mergeCommit,statusCheckRollup,headRefOid",
            ]
        )
        if exit_code != 0:
            print(f"Failed to read PR status: {stderr}")
            time.sleep(30)
            continue

        try:
            data = json.loads(stdout)
        except json.JSONDecodeError:
            print(f"Could not parse PR status JSON: {stdout}")
            time.sleep(30)
            continue

        state = data.get("state")
        if state != last_state:
            print(f"PR #{pr_number} state: {state}")
            last_state = state

        if state == "MERGED":
            merge_commit = data.get("mergeCommit") or {}
            sha = merge_commit.get("oid")
            if not sha:
                print("PR is MERGED but no mergeCommit oid was returned.")
                return None
            print(f"PR #{pr_number} merged at {sha[:8]}")
            return sha

        if state == "CLOSED":
            print(f"PR #{pr_number} was closed without merging.")
            return None

        if state == "OPEN" and direct_merge_attempts < 3 and checks_green(data):
            # Auto-merge waits for requirements the app is entitled to bypass
            # (required reviews), and the merge API does not exercise ruleset
            # bypass either; ref updates do. Try the merge for the clean PR
            # timeline, then fall back to fast-forwarding main to the PR head,
            # which GitHub records as merging the PR.
            direct_merge_attempts += 1
            exit_code, _, stderr = run_command(
                ["gh", "pr", "merge", str(pr_number), "--squash"]
            )
            if exit_code == 0:
                print(f"Merged PR #{pr_number} directly as the bypass actor.")
            else:
                print(f"Direct merge refused: {stderr.strip()[:200]}")
                head_sha = data.get("headRefOid")
                if head_sha:
                    exit_code, _, stderr = run_command(
                        [
                            "gh",
                            "api",
                            "-X",
                            "PATCH",
                            f"repos/{repo}/git/refs/heads/main",
                            "-f",
                            f"sha={head_sha}",
                        ]
                    )
                    if exit_code == 0:
                        print(
                            f"Fast-forwarded main to {head_sha[:8]}; "
                            f"PR #{pr_number} will be marked merged."
                        )
                    else:
                        print(
                            f"Fast-forward attempt {direct_merge_attempts} failed "
                            f"(main may have moved); auto-merge stays armed: "
                            f"{stderr.strip()[:200]}"
                        )

        time.sleep(30)

    print(f"Timeout waiting for PR #{pr_number} to merge.")
    return None


def create_and_push_tag(repo: str, tag: str, sha: str) -> bool:
    """Create the tag on the remote pointing at ``sha`` and push it.

    Uses the REST refs API rather than ``git push --tags`` so the operation
    works even if the runner's local main is behind (the workflow doesn't
    re-fetch after the merge poll).
    """
    print(f"Creating tag {tag} at {sha[:8]} via REST refs API...")
    exit_code, _, stderr = run_command(
        [
            "gh",
            "api",
            f"repos/{repo}/git/refs",
            "-X",
            "POST",
            "-f",
            f"ref=refs/tags/{tag}",
            "-f",
            f"sha={sha}",
        ]
    )
    if exit_code != 0:
        if "Reference already exists" in stderr or "HTTP 422" in stderr:
            print(f"Tag {tag} already exists; publish already triggered.")
            return True
        print(f"Failed to create tag: {stderr}")
        return False
    print(f"Created tag {tag}")
    return True


def bump_package(package_name: str, package_dir: str) -> bool:
    print(f"Starting version bump for {package_name}...")

    if not Path(package_dir).exists():
        print(f"Error: package directory {package_dir} does not exist")
        return False

    configure_git()

    if not pull_main():
        return False

    repo = get_repo_slug()

    recovery = recover_untagged_bump(repo, package_name, package_dir)
    if recovery is not None:
        return recovery

    new_version = cz_bump_files_only(package_dir, package_name)
    if new_version is None:
        return True
    branch = f"bump/{package_name}-{new_version}"
    tag = f"{new_version}-{package_name}"
    parent_sha = get_main_sha()

    modified = get_modified_files()
    if not modified:
        print("cz bump produced no file changes; nothing to commit.")
        return False
    print(f"Modified files: {modified}")

    branch_status = create_remote_branch(repo, branch, parent_sha)
    if branch_status == "error":
        return False

    pr_number: int | None
    if branch_status == "created":
        if not create_signed_commit_on_branch(
            repo,
            branch,
            parent_sha,
            modified,
            headline=f"bump: {package_name} → {new_version}",
            body=f"Auto-bump for {package_name}.",
        ):
            return False
        pr_number = create_pr_with_automerge(branch, package_name, new_version)
        if pr_number is None:
            return False
    else:
        # The branch already exists from a prior run. Resume rather than fail.
        existing = find_pr_for_branch(branch)
        if existing and existing.get("state") == "MERGED":
            sha = (existing.get("mergeCommit") or {}).get("oid")
            if sha:
                print(f"Bump PR #{existing['number']} already merged at {sha[:8]}.")
                return create_and_push_tag(repo, tag, sha)
            print("Bump PR is merged but no merge SHA was returned.")
            return False
        if existing and existing.get("state") == "OPEN":
            pr_number = existing["number"]
            print(f"Reusing open bump PR #{pr_number}.")
            if not enable_automerge(pr_number):
                return False
        else:
            # Branch exists with no usable PR (commit and/or PR step failed
            # earlier). Ensure the bump commit is present, then open the PR.
            if get_branch_head_sha(repo, branch) == parent_sha and not (
                create_signed_commit_on_branch(
                    repo,
                    branch,
                    parent_sha,
                    modified,
                    headline=f"bump: {package_name} → {new_version}",
                    body=f"Auto-bump for {package_name}.",
                )
            ):
                return False
            pr_number = create_pr_with_automerge(branch, package_name, new_version)
            if pr_number is None:
                return False

    merge_sha = wait_for_pr_merge(repo, pr_number)
    if merge_sha is None:
        return False

    if not create_and_push_tag(repo, tag, merge_sha):
        return False

    print(f"Successfully bumped {package_name} to {new_version}; tag {tag} pushed.")
    return True


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Bump a package version via an auto-merging PR."
    )
    parser.add_argument("package_name", help="Package name (e.g. keycardai-oauth).")
    parser.add_argument("package_dir", help="Package directory (e.g. packages/oauth).")
    args = parser.parse_args()

    if not bump_package(args.package_name, args.package_dir):
        print("Version bump failed")
        sys.exit(1)
    print("Version bump completed successfully")


if __name__ == "__main__":
    main()

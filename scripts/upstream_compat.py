"""Test each framework integration against its upstream's latest release (ECO-409).

Nothing in CI runs when an upstream framework ships, so a peer range that has
fallen behind is found by a user with a peer-dependency conflict. This script
takes the (package, upstream) pairs from .github/upstream-compat.json and, for
one entry at a time:

1. Resolves the upstream version to test: the latest stable release on npm (no
   prereleases), whether or not the declared range covers it, or the version
   passed in. A version that already passed on main is skipped.
2. Installs that version into the package in place (``pnpm add`` in the
   package directory), builds, and runs the package's typecheck and tests.
   Each companion in the entry (a package the upstream peers on, such as
   ``ai`` for eve or ``@langchain/core`` for langchain) is installed at the
   range that upstream version declares for it, so the tests run against the
   pairing a user of that upstream actually gets, not the stale copy the
   workspace happens to hold.
3. Acts on the outcome:
   * green and outside the declared range: a PR that raises the declared
     range and the devDependency, with the regenerated lockfile, on branch
     ``upstream/<package>-<upstream>-<version>``. An existing branch or PR for
     that version is updated, never duplicated.
   * green and inside the range: nothing to open; the tested version is
     recorded.
   * red: one issue labeled ``upstream-compat`` per (upstream, version), with
     the tail of the failing output, whether the version is inside the range
     (inside means users installing today already get the break), and the run
     link. A later run that fails differently comments on it.

Range math follows semver for both shapes the config carries: a 0.x upstream
keeps its floor and moves the upper bound to the next minor
(``>=0.71.3 <0.80.0``); a 1.x or later upstream is covered by a caret range
(``^1.3.0``) until a new major, which starts a new caret range at that
version.

State lives on the ``upstream-compat-state`` branch as state.json, keyed by
``<package>:<upstream>``: it is readable with one fetch, writable with the same
token the workflow already has, and keeps a history, which a step summary does
not offer and a repository variable needs admin rights for.

Inputs come from the environment so the workflow can pass event context:

    ENTRY        the config entry's package name
    VERSION      the upstream version to test (default: latest stable)
    DRY_RUN      "true" prints the PR or issue instead of opening it
    RUN_URL      the Actions run, linked from issues and PR bodies
    STATE_BRANCH the state branch (default below)
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field

CONFIG_PATH = ".github/upstream-compat.json"
DEFAULT_STATE_BRANCH = "upstream-compat-state"
STATE_FILE = "state.json"
ISSUE_LABEL = "upstream-compat"
TAIL_LINES = 60

VERSION_RE = re.compile(r"^(\d+)\.(\d+)\.(\d+)(?:-(?P<pre>[0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$")


@dataclass
class Entry:
    package: str
    upstream: str
    field: str
    companions: list[str] = field(default_factory=list)

    @property
    def key(self) -> str:
        return f"{self.package}:{self.upstream}"

    @property
    def name(self) -> str:
        return f"@keycardai/{self.package}"


@dataclass
class Outcome:
    green: bool
    tail: str


def load_config(path: str) -> list[Entry]:
    with open(path) as f:
        data = json.load(f)
    return [Entry(**entry) for entry in data["entries"]]


# --- semver -----------------------------------------------------------------


def parse_version(text: str) -> tuple[int, int, int]:
    m = VERSION_RE.match(text.strip())
    if not m:
        raise ValueError(f"not a semver version: {text!r}")
    return int(m.group(1)), int(m.group(2)), int(m.group(3))


def is_prerelease(text: str) -> bool:
    m = VERSION_RE.match(text.strip())
    return bool(m and m.group("pre"))


def _caret_upper(v: tuple[int, int, int]) -> tuple[int, int, int]:
    major, minor, patch = v
    if major > 0:
        return (major + 1, 0, 0)
    if minor > 0:
        return (0, minor + 1, 0)
    return (0, 0, patch + 1)


def in_range(range_text: str, version: str) -> bool:
    """Whether a package.json range (caret, tilde, comparators, exact, ``||``) covers a version."""
    v = parse_version(version)
    for alternative in range_text.split("||"):
        if all(_comparator_holds(c, v) for c in alternative.split()):
            return True
    return False


def _comparator_holds(comparator: str, v: tuple[int, int, int]) -> bool:
    if comparator in ("*", "x"):
        return True
    if comparator.startswith("^"):
        low = parse_version(comparator[1:])
        return low <= v < _caret_upper(low)
    if comparator.startswith("~"):
        low = parse_version(comparator[1:])
        return low <= v < (low[0], low[1] + 1, 0)
    for op, test in (
        (">=", lambda a, b: a >= b),
        ("<=", lambda a, b: a <= b),
        (">", lambda a, b: a > b),
        ("<", lambda a, b: a < b),
        ("=", lambda a, b: a == b),
    ):
        if comparator.startswith(op):
            return test(v, parse_version(comparator[len(op):]))
    return v == parse_version(comparator)


def range_floor(range_text: str) -> str:
    """The lowest version a range names (the first alternative's lower bound)."""
    first = range_text.split("||")[0].split()
    for comparator in first:
        if comparator.startswith((">=", "^", "~")):
            return comparator.lstrip(">=^~")
    for comparator in first:
        if comparator[0].isdigit():
            return comparator
    raise ValueError(f"no lower bound in range {range_text!r}")


def widened_range(range_text: str, version: str) -> str:
    """The declared range after it grows to include version, following semver for both shapes.

    0.x: keep the floor, upper bound at the next minor (``>=0.71.3 <0.80.0``).
    1.x and later: ``^<floor>`` while the major is unchanged, ``^<version>``
    when the version starts a new major.
    """
    if in_range(range_text, version):
        return range_text
    v = parse_version(version)
    floor = range_floor(range_text)
    f = parse_version(floor)
    if v[0] == 0:
        if f[0] != 0 or f > v:
            return f">={version} <0.{v[1] + 1}.0"
        return f">={floor} <0.{v[1] + 1}.0"
    if f[0] == v[0]:
        return f"^{floor}"
    return f"^{version}"


def decide(green: bool, inside: bool) -> str:
    """pr, record, or issue."""
    if not green:
        return "issue"
    return "record" if inside else "pr"


# --- dedupe -----------------------------------------------------------------


def branch_name(entry: Entry, version: str) -> str:
    return f"upstream/{entry.package}-{entry.upstream.replace('@', '').replace('/', '-')}-{version}"


def pr_title(entry: Entry, version: str) -> str:
    return f"fix({entry.package}): support {entry.upstream} {version}"


def issue_title(entry: Entry, version: str) -> str:
    return f"{entry.upstream} {version} breaks {entry.name}"


def find_by_title(items: list[dict], title: str) -> int | None:
    for item in items:
        if item.get("title") == title:
            return item["number"]
    return None


def already_tested(state: dict, entry: Entry, version: str) -> bool:
    return state.get(entry.key, {}).get("version") == version


def tail(text: str, lines: int = TAIL_LINES) -> str:
    return "\n".join(text.rstrip().splitlines()[-lines:])


def issue_body(entry: Entry, version: str, declared: str, inside: bool, out: str, run_url: str) -> str:
    where = (
        f"inside the declared range `{declared}`, so users installing {entry.name} today already get this"
        if inside
        else f"outside the declared range `{declared}`, so users are not affected until the range widens"
    )
    return (
        f"{entry.upstream} {version} is {where}.\n\n"
        f"Typecheck and tests of `packages/{entry.package}` against it, tail of the output:\n\n"
        f"```\n{out}\n```\n\n"
        f"Run: {run_url or '(local run)'}\n"
    )


def pr_body(entry: Entry, version: str, old: str, new: str, run_url: str) -> str:
    return (
        "## Summary\n\n"
        f"{entry.upstream} {version} is the latest stable release and sits outside "
        f"{entry.name}'s declared range `{old}`. The package's typecheck and tests pass against it "
        f"with no code change, so the `{entry.field}` range moves to `{new}` and the lockfile "
        f"resolves {version}.\n\n"
        f"Opened by the upstream compatibility check (ECO-409). Run: {run_url or '(local run)'}\n"
    )


def failed_differently(issue_body_text: str, out: str) -> bool:
    return out.strip() not in issue_body_text


# --- shell ------------------------------------------------------------------


def run(cmd: list[str], cwd: str, check: bool = True, **kwargs) -> subprocess.CompletedProcess:
    print("$", " ".join(cmd), f"(in {cwd})", flush=True)
    return subprocess.run(cmd, cwd=cwd, check=check, text=True, **kwargs)


def latest_stable(upstream: str, cwd: str) -> str:
    out = run(["npm", "view", upstream, "versions", "--json"], cwd, capture_output=True).stdout
    versions = json.loads(out)
    if isinstance(versions, str):
        versions = [versions]
    stable = [v for v in versions if VERSION_RE.match(v) and not is_prerelease(v)]
    return max(stable, key=parse_version)


def read_package(pkg_dir: str) -> dict:
    with open(os.path.join(pkg_dir, "package.json")) as f:
        return json.load(f)


def write_package(pkg_dir: str, data: dict) -> None:
    with open(os.path.join(pkg_dir, "package.json"), "w") as f:
        json.dump(data, f, indent=2)
        f.write("\n")


def upstream_peers(upstream: str, version: str, cwd: str) -> dict[str, str]:
    """The peerDependencies the upstream declares at that version (empty when it has none)."""
    out = run(["npm", "view", f"{upstream}@{version}", "peerDependencies", "--json"], cwd, capture_output=True).stdout
    return json.loads(out) if out.strip() else {}


def companion_specs(companions: list[str], peers: dict[str, str]) -> list[str]:
    """``name@<peer range>`` per companion, ``name@latest`` when the upstream names no range for it."""
    return [f"{c}@{peers[c]}" if c in peers else f"{c}@latest" for c in companions]


def install_and_test(repo_root: str, entry: Entry, version: str) -> Outcome:
    pkg_dir = os.path.join(repo_root, "packages", entry.package)
    peers = upstream_peers(entry.upstream, version, repo_root) if entry.companions else {}
    specs = [f"{entry.upstream}@{version}", *companion_specs(entry.companions, peers)]
    flag = ["-D"] if entry.field == "peerDependencies" else []
    run(["pnpm", "add", *flag, *specs], pkg_dir)
    output = []
    steps = [
        (["pnpm", "-r", "--filter", f"{entry.name}...", "run", "build"], repo_root),
        (["pnpm", "run", "typecheck"], pkg_dir),
        (["pnpm", "run", "test"], pkg_dir),
    ]
    for cmd, cwd in steps:
        result = run(cmd, cwd, check=False, capture_output=True)
        output.append(result.stdout + result.stderr)
        if result.returncode != 0:
            return Outcome(False, tail("\n".join(output)))
    return Outcome(True, tail("\n".join(output)))


def apply_range(pkg_dir: str, entry: Entry, version: str, new_range: str) -> None:
    data = read_package(pkg_dir)
    data[entry.field][entry.upstream] = new_range
    if entry.field == "peerDependencies":
        data.setdefault("devDependencies", {})[entry.upstream] = version
    write_package(pkg_dir, data)
    run(["pnpm", "install", "--no-frozen-lockfile"], os.path.dirname(os.path.dirname(pkg_dir)))


def gh_json(args: list[str], cwd: str) -> list[dict]:
    out = run(["gh", *args], cwd, capture_output=True).stdout
    return json.loads(out) if out.strip() else []


def open_or_update_pr(repo_root: str, entry: Entry, version: str, title: str, body: str, dry_run: bool) -> None:
    branch = branch_name(entry, version)
    if dry_run:
        print(f"dry run: would push {branch} and open or update PR {title!r}\n{body}")
        return
    run(["git", "checkout", "-B", branch], repo_root)
    run(["git", "add", "pnpm-lock.yaml", f"packages/{entry.package}/package.json"], repo_root)
    run(["git", "commit", "-m", title, "-m", "Opened by the upstream compatibility check (ECO-409)."], repo_root)
    run(["git", "push", "--force-with-lease", "-u", "origin", branch], repo_root)
    existing = find_by_title(
        gh_json(["pr", "list", "--head", branch, "--state", "open", "--json", "number,title"], repo_root), title
    )
    if existing is not None:
        run(["gh", "pr", "edit", str(existing), "--body", body], repo_root)
        print(f"updated PR #{existing}")
        return
    run(["gh", "pr", "create", "--head", branch, "--title", title, "--body", body], repo_root)
    print("created PR")


def open_or_update_issue(repo_root: str, title: str, body: str, out: str, dry_run: bool) -> None:
    if dry_run:
        print(f"dry run: would open or update issue {title!r} (label {ISSUE_LABEL})\n{body}")
        return
    run(["gh", "label", "create", ISSUE_LABEL, "--force", "--description", "An upstream framework release breaks a package"], repo_root)
    issues = gh_json(
        ["issue", "list", "--label", ISSUE_LABEL, "--state", "open", "--search", f'"{title}" in:title', "--json", "number,title,body"],
        repo_root,
    )
    existing = find_by_title(issues, title)
    if existing is None:
        run(["gh", "issue", "create", "--title", title, "--body", body, "--label", ISSUE_LABEL], repo_root)
        print("created issue")
        return
    issue = next(i for i in issues if i["number"] == existing)
    if failed_differently(issue.get("body", ""), out):
        run(["gh", "issue", "comment", str(existing), "--body", "A later run failed differently:\n\n" + body], repo_root)
        print(f"commented on issue #{existing}")
    else:
        print(f"issue #{existing} already records this failure")


# --- state ------------------------------------------------------------------


def read_state(repo_root: str, state_branch: str) -> dict:
    fetched = run(["git", "fetch", "origin", state_branch], repo_root, check=False)
    if fetched.returncode != 0:
        return {}
    shown = run(["git", "show", f"origin/{state_branch}:{STATE_FILE}"], repo_root, check=False, capture_output=True)
    return json.loads(shown.stdout) if shown.returncode == 0 and shown.stdout.strip() else {}


def write_state(repo_root: str, state_branch: str, state: dict, message: str) -> None:
    with tempfile.TemporaryDirectory(prefix="upstream-compat-state-") as wt:
        exists = run(["git", "rev-parse", "--verify", f"origin/{state_branch}"], repo_root, check=False, capture_output=True)
        if exists.returncode == 0:
            run(["git", "worktree", "add", wt, f"origin/{state_branch}"], repo_root)
            run(["git", "checkout", "-B", state_branch], wt)
        else:
            run(["git", "worktree", "add", "--detach", wt], repo_root)
            run(["git", "checkout", "--orphan", state_branch], wt)
            run(["git", "rm", "-rfq", "."], wt, check=False)
        with open(os.path.join(wt, STATE_FILE), "w") as f:
            json.dump(state, f, indent=2, sort_keys=True)
            f.write("\n")
        run(["git", "add", STATE_FILE], wt)
        run(["git", "commit", "-m", message], wt)
        run(["git", "push", "origin", state_branch], wt)
        run(["git", "worktree", "remove", "--force", wt], repo_root)


# --- main -------------------------------------------------------------------


def main() -> None:
    repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    entries = {e.package: e for e in load_config(os.path.join(repo_root, CONFIG_PATH))}
    entry = entries[os.environ["ENTRY"]]
    dry_run = os.environ.get("DRY_RUN") == "true"
    run_url = os.environ.get("RUN_URL", "")
    state_branch = os.environ.get("STATE_BRANCH") or DEFAULT_STATE_BRANCH
    requested = os.environ.get("VERSION", "").strip()

    version = requested if requested and requested != "latest" else latest_stable(entry.upstream, repo_root)
    pkg_dir = os.path.join(repo_root, "packages", entry.package)
    declared = read_package(pkg_dir)[entry.field][entry.upstream]
    inside = in_range(declared, version)
    print(f"{entry.name}: {entry.upstream} {version} is {'inside' if inside else 'outside'} the declared {entry.field} range {declared}")

    state = read_state(repo_root, state_branch)
    if not requested and already_tested(state, entry, version):
        print(f"{entry.upstream} {version} already passed on main; nothing to do")
        return

    outcome = install_and_test(repo_root, entry, version)
    action = decide(outcome.green, inside)
    print(f"outcome: {'green' if outcome.green else 'red'}; action: {action}")

    if action == "issue":
        body = issue_body(entry, version, declared, inside, outcome.tail, run_url)
        open_or_update_issue(repo_root, issue_title(entry, version), body, outcome.tail, dry_run)
        sys.exit(1)

    if action == "pr":
        new_range = widened_range(declared, version)
        apply_range(pkg_dir, entry, version, new_range)
        open_or_update_pr(repo_root, entry, version, pr_title(entry, version), pr_body(entry, version, declared, new_range, run_url), dry_run)
        return

    state[entry.key] = {"version": version, "run": run_url}
    if dry_run:
        print(f"dry run: would record {entry.key} = {version} on {state_branch}")
        return
    write_state(repo_root, state_branch, state, f"{entry.name}: {entry.upstream} {version} passes")


if __name__ == "__main__":
    main()

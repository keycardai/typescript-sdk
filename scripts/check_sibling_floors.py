"""Test a package against its @keycardai siblings as published (SDK-18).

Inside the pnpm workspace every package resolves its @keycardai siblings from
source, so the normal test job never sees what a clean install of the published
package sees. This script runs the package under test against each @keycardai
sibling installed from npm at exactly the floor its published range promises,
with third-party dependencies resolved fresh and no workspace link on the
resolution path:

1. ``pnpm pack`` the package and read the packed package.json. The floor of
   each @keycardai dependency is the lower bound of the published range
   (``^0.26.1`` and ``0.26.1`` both mean 0.26.1).
2. Refuse any @keycardai dependency still written ``workspace:*`` in the
   source package.json, which would publish an exact pin.
3. Copy the package source to a scratch directory outside the workspace,
   rewrite the sibling specifiers to their floors, install, assert from inside
   Node that each sibling resolves to the npm copy at the floor, and run the
   package's own test suite there.
4. Install the packed tarball with its siblings at the floors in a clean
   directory and ``import()`` and ``require()`` every entry in its ``exports``.
   This catches a missing named export at link time, and is the only check a
   package without tests gets.

A floor may name a sibling version that is not on npm yet. That is the
sequenced-merge case: a carrier and its consumer merge together and the
carrier has not released. Two things turn that failure into a skip:

* the ``floors-bootstrap`` label on a feature PR (``FLOORS_BOOTSTRAP=true``);
* a bump PR opened by the release app whose branch names exactly the
  (package, version) pair that is missing. The bump PR is the one that
  publishes that version, so it can never see it on npm first.

The check never falls back to a newer version.

Inputs come from the environment so the workflow can pass event context:

    PACKAGE           packages/<PACKAGE> is the package under test
    FLOORS_BOOTSTRAP  "true" when the PR carries the floors-bootstrap label
    PR_HEAD_REF       the PR's head branch name
    PR_AUTHOR         the PR author's login
    RELEASE_APP_LOGIN the release app's bot login (default below)
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.error
import urllib.request
from collections.abc import Callable

DEFAULT_RELEASE_APP_LOGIN = "keycard-sdk-release[bot]"
SCOPE = "@keycardai/"

# Mirrors bump_branch_name in bump_package.py: bump/<release-line>/<package>-<version>.
# The release line never contains a slash and the version starts with a digit,
# so the last "-<digit>" split is the package/version boundary. The package part
# is the cz tag name, keycardai-<name>, which maps to @keycardai/<name>.
BUMP_BRANCH_RE = re.compile(
    r"^bump/[^/]+/(?P<package>keycardai-[a-z0-9-]+)-(?P<version>[0-9][0-9A-Za-z.]*)$"
)

# The specifiers pnpm publishes for a workspace dependency: an exact version
# (from workspace:*), a caret or tilde range (workspace:^, workspace:~), or a
# >= bound. The floor is the version the range starts at.
FLOOR_RE = re.compile(r"^(?:\^|~|>=)?\s*(?P<version>[0-9][0-9A-Za-z.+-]*)$")


def parse_bump_pr(
    head_ref: str, author: str, release_app_login: str
) -> tuple[str, str] | None:
    """Return (@keycardai/<name>, version) when the PR is a bump PR opened by the release app.

    Both signals are required: a matching branch name from someone else is not
    a bump PR, and a release-app PR on another branch is not one either.
    """
    if author != release_app_login:
        return None
    m = BUMP_BRANCH_RE.fullmatch(head_ref)
    if not m:
        return None
    name = m.group("package").removeprefix("keycardai-")
    return SCOPE + name, m.group("version")


def parse_floor(specifier: str) -> str | None:
    """Return the lower bound of a published specifier, or None when it has none."""
    m = FLOOR_RE.fullmatch(specifier.strip())
    return m.group("version") if m else None


def read_floors(packed: dict) -> dict[str, str]:
    """Return the @keycardai floors of a packed package.json, or exit on an unreadable one."""
    name = packed["name"]
    floors: dict[str, str] = {}
    for dep, specifier in packed.get("dependencies", {}).items():
        if not dep.startswith(SCOPE):
            continue
        floor = parse_floor(specifier)
        if floor is None:
            print(
                f"::error::{name}: cannot read a floor from sibling specifier "
                f"{dep}@{specifier!r}; expected ^A.B.C or A.B.C"
            )
            sys.exit(1)
        floors[dep] = floor
    return floors


def check_workspace_specifiers(name: str, source: dict) -> list[str]:
    """Return the @keycardai dependencies still written workspace:* in the source package.json."""
    exact = [
        dep
        for section in ("dependencies", "peerDependencies", "optionalDependencies")
        for dep, specifier in source.get(section, {}).items()
        if dep.startswith(SCOPE) and specifier == "workspace:*"
    ]
    for dep in exact:
        print(
            f"::error::{name}: {dep} is declared workspace:*, which publishes an exact "
            f"pin of the sibling; use workspace:^ so a sibling patch reaches users"
        )
    return exact


def on_npm(sibling: str, version: str) -> bool:
    try:
        urllib.request.urlopen(
            f"https://registry.npmjs.org/{sibling}/{version}"
        ).close()
        return True
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return False
        raise


def check_ahead_of_npm(
    name: str,
    floors: dict[str, str],
    *,
    bootstrap: bool,
    bump_pr: tuple[str, str] | None,
    exists: Callable[[str, str], bool] = on_npm,
) -> bool:
    """Return True when installation should proceed, False when the check is skipped.

    Exits 1 when a floor is ahead of npm and neither skip applies.
    """
    ahead = [(s, v) for s, v in floors.items() if not exists(s, v)]
    if not ahead:
        return True

    if bump_pr is not None and all((s, v) == bump_pr for s, v in ahead):
        for sibling, version in ahead:
            print(
                f"{name}: floor {sibling}@{version} is the version this bump PR releases; "
                "it cannot be on npm before the bump merges"
            )
        print("skipping the floors check for this package")
        return False

    level = "warning" if bootstrap else "error"
    for sibling, version in ahead:
        print(
            f"::{level}::{name}: floor {sibling}@{version} is ahead of npm; "
            f"{sibling} {version} is not published yet"
        )
    if bootstrap:
        print(
            "floors-bootstrap label is set on this PR; skipping the floors check for this package"
        )
        return False
    print(
        "Release the sibling first, or add the floors-bootstrap label to the PR for a sequenced merge."
    )
    sys.exit(1)


def run(cmd: list[str], cwd: str, **kwargs) -> subprocess.CompletedProcess:
    print("$", " ".join(cmd), f"(in {cwd})", flush=True)
    return subprocess.run(cmd, cwd=cwd, **kwargs)


def node(script: str, args: list[str], cwd: str) -> subprocess.CompletedProcess:
    """Run an inline Node script from a file in cwd, so argv passes through verbatim and import() resolves from cwd."""
    with tempfile.NamedTemporaryFile("w", suffix=".cjs", dir=cwd, delete=False) as f:
        f.write(script)
    try:
        return run(["node", f.name, *args], cwd=cwd, capture_output=True, text=True)
    finally:
        os.unlink(f.name)


def pack(pkg_dir: str, dest: str) -> tuple[str, dict]:
    """pnpm pack the package into dest; return the tarball path and its package.json."""
    run(["pnpm", "pack", "--pack-destination", dest], cwd=pkg_dir, check=True)
    (tarball,) = [f for f in os.listdir(dest) if f.endswith(".tgz")]
    path = os.path.join(dest, tarball)
    with tarfile.open(path) as tar:
        member = tar.extractfile("package/package.json")
        assert member is not None
        packed = json.load(member)
    return path, packed


RESOLVE_CHECK = """
const fs = require("node:fs");
const path = require("node:path");
const floors = JSON.parse(process.argv[2]);
const root = process.argv[3];
// Node's bare-specifier lookup: node_modules/<name> in root, then each parent.
function locate(name) {
  for (let dir = root; ; dir = path.dirname(dir)) {
    const candidate = path.join(dir, "node_modules", name, "package.json");
    if (fs.existsSync(candidate)) return candidate;
    if (path.dirname(dir) === dir) return null;
  }
}
let bad = 0;
for (const [name, floor] of Object.entries(floors)) {
  const file = locate(name);
  if (!file) {
    console.error(`${name} is not installed under ${root}`);
    bad++;
    continue;
  }
  const real = fs.realpathSync(file);
  const version = require(real).version;
  const fromNpm = real.startsWith(path.join(root, "node_modules") + path.sep);
  if (version !== floor || !fromNpm) {
    console.error(`${name} resolved to ${version} at ${real}; expected the npm copy at ${floor}`);
    bad++;
  } else {
    console.log(`${name} resolves to the npm copy at ${version}`);
  }
}
process.exit(bad ? 1 : 0);
"""


def assert_siblings_resolve(name: str, root: str, floors: dict[str, str]) -> None:
    result = node(RESOLVE_CHECK, [json.dumps(floors), root], cwd=root)
    sys.stdout.write(result.stdout)
    sys.stderr.write(result.stderr)
    if result.returncode != 0:
        print(
            f"::error::{name}: a sibling did not resolve to its npm copy at the floor; "
            f"a workspace link is on the resolution path"
        )
        sys.exit(1)


def copy_source(repo_root: str, package: str, scratch: str) -> str:
    """Copy packages/<package> and the shared tsconfig into scratch, without node_modules or dist."""
    dest = os.path.join(scratch, "packages", package)
    shutil.copytree(
        os.path.join(repo_root, "packages", package),
        dest,
        ignore=shutil.ignore_patterns("node_modules", "dist", "*.tgz"),
    )
    shutil.copy(
        os.path.join(repo_root, "tsconfig.base.json"),
        os.path.join(scratch, "tsconfig.base.json"),
    )
    return dest


def rewrite_siblings(pkg_json_path: str, floors: dict[str, str]) -> None:
    with open(pkg_json_path) as f:
        data = json.load(f)
    for section in ("dependencies", "devDependencies", "peerDependencies"):
        for dep in list(data.get(section, {})):
            if dep.startswith(SCOPE):
                data[section][dep] = floors[dep]
    with open(pkg_json_path, "w") as f:
        json.dump(data, f, indent=2)
        f.write("\n")


def test_at_floors(name: str, repo_root: str, package: str, floors: dict[str, str]) -> None:
    source_pkg = json.load(open(os.path.join(repo_root, "packages", package, "package.json")))
    if "test" not in source_pkg.get("scripts", {}):
        print(f"{name} has no test script; the exports check below is its only check")
        return

    pins = [f"{s}@{v}" for s, v in floors.items()]
    with tempfile.TemporaryDirectory(prefix="floors-src-") as scratch:
        dest = copy_source(repo_root, package, scratch)
        rewrite_siblings(os.path.join(dest, "package.json"), floors)
        install = run(
            ["npm", "install", "--no-package-lock", "--no-audit", "--no-fund"],
            cwd=dest,
            capture_output=True,
            text=True,
        )
        sys.stdout.write(install.stdout)
        sys.stderr.write(install.stderr)
        if install.returncode != 0:
            first = next(
                (line for line in install.stderr.splitlines() if line.startswith("npm error") and "ERESOLVE" not in line),
                "install failed",
            )
            print(f"::error::{name} does not install with {' '.join(pins)}: {first}")
            sys.exit(1)

        assert_siblings_resolve(name, dest, floors)

        tests = run(["npm", "test"], cwd=dest, capture_output=True, text=True)
        sys.stdout.write(tests.stdout)
        sys.stderr.write(tests.stderr)
        if tests.returncode != 0:
            lines = tests.stderr.splitlines() + tests.stdout.splitlines()
            first = next(
                (line for line in lines if line.lstrip().startswith(("FAIL ", "●", "error TS", "Tests:"))),
                f"npm test exited {tests.returncode}",
            )
            print(
                f"::error::{name} fails its tests with {' '.join(pins)} (declared floors of {name}): {first.strip()}"
            )
            sys.exit(1)

    print(f"{name} passes its tests at sibling floors {' '.join(pins)}")


EXPORTS_CHECK = """
const { createRequire } = require("node:module");
const path = require("node:path");
const name = process.argv[2];
const entries = JSON.parse(process.argv[3]);
const root = process.argv[4];
const req = createRequire(path.join(root, "package.json"));
(async () => {
  let bad = 0;
  for (const [key, target] of Object.entries(entries)) {
    const specifier = key === "." ? name : name + key.slice(1);
    const conditions = typeof target === "string" ? { require: target } : target;
    if (conditions.import) {
      try {
        const mod = await import(specifier);
        console.log(`import ${specifier}: ${Object.keys(mod).length} names`);
      } catch (e) {
        console.error(`import ${specifier} failed: ${e && e.stack ? e.stack.split("\\n")[0] : e}`);
        bad++;
      }
    }
    if (conditions.require) {
      try {
        const mod = req(specifier);
        console.log(`require ${specifier}: ${Object.keys(mod).length} names`);
      } catch (e) {
        console.error(`require ${specifier} failed: ${e && e.stack ? e.stack.split("\\n")[0] : e}`);
        bad++;
      }
    }
  }
  process.exit(bad ? 1 : 0);
})();
"""


def check_exports(name: str, tarball: str, packed: dict, floors: dict[str, str]) -> None:
    pins = [f"{s}@{v}" for s, v in floors.items()]
    with tempfile.TemporaryDirectory(prefix="floors-exports-") as clean:
        with open(os.path.join(clean, "package.json"), "w") as f:
            json.dump({"name": "floors-exports-check", "private": True}, f)
        install = run(
            ["npm", "install", "--no-package-lock", "--no-audit", "--no-fund", tarball, *pins],
            cwd=clean,
            capture_output=True,
            text=True,
        )
        sys.stdout.write(install.stdout)
        sys.stderr.write(install.stderr)
        if install.returncode != 0:
            first = next(
                (line for line in install.stderr.splitlines() if line.startswith("npm error") and "ERESOLVE" not in line),
                "install failed",
            )
            print(f"::error::{name} does not install with {' '.join(pins)}: {first}")
            sys.exit(1)

        assert_siblings_resolve(name, clean, floors)

        exports = packed.get("exports") or {".": packed.get("main", "index.js")}
        result = node(EXPORTS_CHECK, [name, json.dumps(exports), clean], cwd=clean)
        sys.stdout.write(result.stdout)
        sys.stderr.write(result.stderr)
        if result.returncode != 0:
            first = next(
                (line for line in result.stderr.splitlines() if " failed: " in line),
                "an export did not load",
            )
            print(
                f"::error::{name} does not load with {' '.join(pins)} (declared floors of {name}): {first.strip()}"
            )
            sys.exit(1)

    print(f"{name}: every export loads at sibling floors {' '.join(pins)}")


def main() -> None:
    package = os.environ["PACKAGE"]
    bootstrap = os.environ.get("FLOORS_BOOTSTRAP") == "true"
    bump_pr = parse_bump_pr(
        os.environ.get("PR_HEAD_REF", ""),
        os.environ.get("PR_AUTHOR", ""),
        os.environ.get("RELEASE_APP_LOGIN") or DEFAULT_RELEASE_APP_LOGIN,
    )
    repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    pkg_dir = os.path.join(repo_root, "packages", package)

    with open(os.path.join(pkg_dir, "package.json")) as f:
        source = json.load(f)
    name = source["name"]

    if check_workspace_specifiers(name, source):
        sys.exit(1)

    with tempfile.TemporaryDirectory(prefix="floors-pack-") as pack_dir:
        tarball, packed = pack(pkg_dir, pack_dir)
        floors = read_floors(packed)
        if not floors:
            print(f"{name} declares no @keycardai dependencies; nothing to check")
            return

        pins = [f"{s}@{v}" for s, v in floors.items()]
        print(f"{name}: sibling floors {' '.join(pins)}")
        if bump_pr is not None:
            print(f"bump PR detected: {bump_pr[0]} {bump_pr[1]}")

        if not check_ahead_of_npm(name, floors, bootstrap=bootstrap, bump_pr=bump_pr):
            return

        test_at_floors(name, repo_root, package, floors)
        check_exports(name, tarball, packed, floors)


if __name__ == "__main__":
    main()

# AGENTS.md

Context for coding agents working in `keycardai/typescript-sdk`. `CLAUDE.md` points here.

## What this repo is

A pnpm workspace (`pnpm-workspace.yaml`: `packages/*`) of TypeScript packages for Keycard, published to npm under `@keycardai/*`. Each package is versioned and released on its own.

| Dir | Package | What it is | Depends on (workspace) |
| --- | --- | --- | --- |
| `packages/oauth` | `@keycardai/oauth` | Pure OAuth 2.0 primitives: token exchange, client credentials, discovery, JWT/JWKS, credentials. No MCP dependency. | none |
| `packages/express` | `@keycardai/express` | Keycard auth for Express (peer `express >=4.0.0`) | oauth |
| `packages/mcp` | `@keycardai/mcp` | MCP-specific OAuth integration (peer `@modelcontextprotocol/client ^2.2.0`) | oauth, express |
| `packages/cloudflare` | `@keycardai/cloudflare` | Keycard auth for Cloudflare Workers, no Express | oauth |
| `packages/a2a` | `@keycardai/a2a` | Keycard auth for the A2A protocol, wrapping `@a2a-js/sdk` (peer `express`) | oauth, express |
| `packages/langchain` | `@keycardai/langchain` | Keycard access for LangChain 1.x agents, no MCP (peers: `langchain`, `@langchain/core`, `@langchain/langgraph`, `@langchain/langgraph-sdk`) | oauth |
| `packages/eve` | `@keycardai/eve` | Route auth, connection auth and interactive authorization for eve agents (eve is a peer) | oauth |
| `packages/cursor-agent-sdk` | `@keycardai/cursor-agent-sdk` | Bearer verifier and connection auth for Cursor Agent SDK agents (`@grok/agent-sdk` is a peer) | oauth |
| `packages/sdk` | `@keycardai/sdk` | Deprecated. Aggregate package re-exporting from oauth + mcp. Don't add features here. | oauth, mcp |
| `packages/pi-mono` | (none) | Deprecated. Holds only a `.cz.toml`, no `package.json` or source. `publish.yml` still lists `*-keycardai-pi-mono` tags. Don't add code here. | n/a |

- Dependency direction: everything builds on `oauth`. Never make `oauth` depend on another workspace package.
- Sibling deps are written `workspace:^`. Never `workspace:*` (CI refuses it because it publishes an exact pin).
- `examples/` (cloudflare-worker, delegated-access, hello-world-server, impersonation) are not workspace members.
- `@keycardai/mcp` and `@keycardai/sdk` have two release lines, see `MCP_RELEASES.md`: `main` publishes MCP 2.x to npm `latest`; `release/mcp-v1` publishes 1.x security and critical fixes to npm `legacy`. Land shared fixes on `main` first, then cherry-pick to a PR against `release/mcp-v1`.

## Setup, build, test (as CI runs them)

Requirements: Node >= 18 (`engines`), pnpm 9 (`packageManager: pnpm@9.15.0`). CI uses Node 22.

```sh
pnpm install --frozen-lockfile
pnpm -r run build       # builds in dependency order; oauth must build before its dependents
pnpm -r run typecheck   # tsc --noEmit per package
pnpm -r run test        # jest per package (NODE_OPTIONS=--experimental-vm-modules)
```

- Root shortcuts: `pnpm run build | test | typecheck | clean` wrap the `-r` forms.
- Single package: `pnpm --filter @keycardai/<name> run test`.
- Build before test/typecheck: dependents resolve siblings through their built `dist/`.
- No linter or formatter is configured in the repo.
- PR validation (`.github/workflows/pr.yml`) also runs, with Python 3.12 and `pip install commitizen==4.19.2`:
  - `python scripts/changelog.py validate "origin/<base>"` (runs `cz check` over the PR's commits)
  - `python -m unittest discover -s scripts -p "test_*.py"` (release script tests)
  - `python scripts/changelog.py check-drift` (`.cz.toml` version must equal `package.json` version)
- Sibling floors job (`scripts/check_sibling_floors.py`, one matrix leg per package with workspace deps): packs the package, installs each `@keycardai` sibling from npm at the floor of its published range, runs the package's tests and imports every `exports` entry. If you raise a sibling floor to a version not on npm yet, that job fails with an "ahead of npm" message; the `floors-bootstrap` PR label turns it into a skip for a sequenced merge.
- `upstream-compat.yml` runs nightly against the latest upstream of eve, `@grok/agent-sdk`, `@a2a-js/sdk` and langchain (`.github/upstream-compat.json`) and opens a PR or issue.

## Commits, scopes, releases

Conventional commits: `type(scope): description`.

- Types: `docs`, `feat`, `fix`, `refactor`, `test`, `chore` (`cz check` uses the default conventional schema, so `perf`, `build`, `ci`, `revert`, `style` also pass).
- Scopes: `oauth`, `mcp`, `cloudflare`, `sdk`, `express`, `a2a`, `langchain`, `eve`, `cursor-agent-sdk`, `pi-mono`, `deps`, `docs`. `ci` is also used in history.
- Each package's version increment is derived only from commits carrying its own scope (`packages/<pkg>/.cz.toml` `bump_pattern`). `feat`, `fix`, `refactor`, `perf`, `revert` with the package scope release it; `docs`, `test`, `chore` and other scopes do not. A change spanning packages needs a scoped commit per package on `main`, or only one package releases.
- Breaking change: on the subject line (`feat(mcp)!: ...`) or a scoped footer (`BREAKING CHANGE(mcp): ...`). An unscoped `BREAKING CHANGE:` footer does not cut a major. While a package has `major_version_zero = true` (every package except `mcp` and `sdk`), a breaking change bumps the minor.
- Release flow: merge to `main` (or `release/mcp-v1`) runs `main.yml`, which finds packages with unreleased commits and calls `bump-package.yml` (`scripts/bump_package.py`, `cz bump --files-only`). The release app opens and fast-forwards a bump PR, then tags `<version>-keycardai-<pkg>`, and `publish.yml` publishes that package to npm with provenance.
- Never hand-edit `version` in `package.json` or `.cz.toml`, or any `CHANGELOG.md`. `cz bump` owns them and `check-drift` fails CI on a mismatch. Forced increments go through the Bump Package Version workflow (`workflow_dispatch`).

## Spec first

- Behavior shared across the Keycard SDKs is defined in `keycardai/keycard-sdk-spec`. A contract change (new or changed operation, field, default, error, or wire format) starts as a spec PR there, then is implemented here against that spec's Unit Tests rows.
- Changelogs in this repo cite the spec file and row being implemented (for example `specs/server-bearer-auth/bearer-token-verification-middleware.md (unit row 4)`). Do the same in PR descriptions.

## Testing rule

- Tests here are hermetic: jest suites next to the source (`*.test.ts`, `src/__tests__/`) with `fetch` stubbed or in-process local servers. No test may need a live Keycard zone or network.
- Live coverage against real zones belongs to the eval in `keycardai/templates`, not this repo.
- `packages/sdk` has no tests; the sibling floors job's export check is its only coverage.

## Idioms and gotchas

- Packages are ESM (`"type": "module"`); most also build CJS (`build:esm` + `build:cjs` into `dist/esm` and `dist/cjs`). `eve` and `cursor-agent-sdk` are ESM only.
- Relative imports in source use the `.js` suffix (`from "./keyring.js"`); jest maps it back with `moduleNameMapper`.
- Public entry points are the `exports` maps in each `package.json`. Adding a module that users import means adding an `exports` entry, which the floors job then import-checks.
- `tsconfig.base.json`: `strict`, `isolatedModules`, target ES2021.
- `.npmrc` sets `auto-install-peers=true`.
- `CODEOWNERS`: `@keycardai/engineering` owns everything.

# MCP release lines

`@keycardai/mcp` follows the upstream MCP major version:

- `main` publishes MCP 2.x releases to npm's `latest` dist-tag.
- `release/mcp-v1` publishes fixes for MCP 1.x to npm's `legacy` dist-tag.

The v1 line receives security and critical fixes only. It does not receive new
features. Land fixes on `main` first when they affect both lines, then
cherry-pick them into a PR targeting `release/mcp-v1`. A v1-only compatibility
fix can target the maintenance branch directly.

Merges to either branch detect and bump the affected package. Bump PRs target
the branch that triggered them, and their branch names include the release line
to avoid collisions.

Use the **Bump Package Version** workflow when a forced increment is required,
or use a conventional breaking-change commit when establishing a new major.
Supply:

| Input | MCP 1.x | MCP 2.x |
| --- | --- | --- |
| `package_name` | `keycardai-mcp` | `keycardai-mcp` |
| `package_dir` | `packages/mcp` | `packages/mcp` |
| `target_branch` | `release/mcp-v1` | `main` |
| `increment` | As needed | As needed |

`@keycardai/sdk` has matching major release lines because it re-exports MCP.
Its dependency uses `workspace:^`, so an SDK major accepts fixes from the same
MCP major without requiring a corresponding SDK patch release.

## Establishing the release lines

Perform the initial cut in this order:

1. Release `@keycardai/mcp@1.0.0` and `@keycardai/sdk@1.0.0` from `main`.
2. Create `release/mcp-v1` at the SDK 1.0.0 release commit.
3. Merge the MCP v2 cutover into `main` and release `@keycardai/mcp@2.0.0`.
4. Release `@keycardai/sdk@2.0.0` from `main` after its v2 peer dependency is
   present.

Do not create the maintenance branch before both 1.0.0 packages are present;
the branch is the long-lived source of truth for the complete v1 install path.

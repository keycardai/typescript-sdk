# Claude Code Instructions

## Project Structure

This is a pnpm monorepo with the following packages:

- `packages/oauth` (`@keycardai/oauth`) - Pure OAuth 2.0 primitives (no MCP dependency)
- `packages/mcp` (`@keycardai/mcp`) - MCP-specific OAuth integration
- `packages/sdk` (`@keycardai/sdk`) - Aggregate package re-exporting from oauth + mcp

## Git Commits

Follow conventional commits: `type(scope): description`

Types: `docs`, `feat`, `fix`, `refactor`, `test`, `chore`

Scopes: `oauth`, `mcp`, `sdk`, `deps`, `docs`

## Build Order

`@keycardai/oauth` must build before `@keycardai/mcp` (dependency).
Use `pnpm -r run build` to build in dependency order.

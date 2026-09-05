# mcp-cross-client-ts

Intentionally vulnerable, lab-only MCP approval service for Meridian Range module 03. It authenticates
two fabricated principals into separate sessions, then deliberately reuses one `McpServer` instance
across both transports. SDK 1.25.3 permits that unsafe lifecycle. SDK 1.26.0 rejects it.

Do not run this server outside the isolated Meridian VM. See the repository `SECURITY.md`.

The default lockfile intentionally retains the affected 1.25.3 package, so dependency scanners should
flag the published advisory here. Do not upgrade that default silently. The module's VM-only matrix
overrides the package with 1.26.0 to prove the fixed cell.

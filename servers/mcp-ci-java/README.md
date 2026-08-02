# Meridian CI - Build Assistant (MCP)  ·  servers/mcp-ci-java

Intentionally-vulnerable MCP server for Meridian Range **module 01**. It is a conventional Spring Boot 3
service (dependency injection, Actuator health, structured ECS logging, environment configuration) that
exposes an internal CI/build assistant to developer agents over the Model Context Protocol.

> ⛔ **INSECURE BY DESIGN - lab only.** Runs solely on the isolated lab VM, inside `labnet`
> (`internal: true`, no egress, **no published ports**). Never expose it to a host or public interface.
> The only command ever sent to `run_command` is a benign canary. See [`../../SECURITY.md`](../../SECURITY.md).

## The vulnerability (inherited, not hand-written)

The service pins `io.modelcontextprotocol.sdk:mcp-core` **1.0.0**, the release affected by
**CVE-2026-34237** (CWE-942). The SDK's `HttpServletSseServerTransportProvider` hardcodes
`Access-Control-Allow-Origin: *` and discloses the session id on the SSE `endpoint` event, so a foreign
browser Origin can read the session id and drive the server cross-origin. The application adds no CORS
handling of its own; upgrading the single pinned dependency to `1.0.1` remediates it with no code change.

Fixed versions: `0.18.3` / `1.0.1` / `1.1.1`. Full write-up:
[`../../modules/01-cors-session-hijack/README.md`](../../modules/01-cors-session-hijack/README.md).

## Endpoints

| Path | Purpose |
|------|---------|
| `GET /mcp/sse` | MCP HTTP/SSE stream; emits the `endpoint` event (session id) |
| `POST /mcp/message?sessionId=…` | MCP JSON-RPC message channel |
| `GET /version` | service identity (name, version, transport) |
| `GET /actuator/health`, `/actuator/info` | operational endpoints |

## Tools

`list_builds`, `get_build_log`, `trigger_pipeline`, and the capability-bearing `run_command` (ad-hoc
build step / shell in the CI workspace).

## Build and run (on the VM only)

Wired into the repo's `engine/compose.yml` as service `mcp-ci` (no ports). From the repo root:

```
./range sync --build 01   # authoring host -> VM: rsync, then rebuild this service there
./range up 01             # on the VM: sealed tier, no published ports
./range verify 01         # on the VM: reproduce (expect ATTACK-OK) and write the evidence capture
./range matrix 01         # on the VM: the same attack across every declared mcp-core version
```

The vulnerable SDK version is a build arg. `MCP_SDK_VERSION` defaults to the affected 1.0.0 and is
what `./range matrix 01` varies; the module manifest at
[`../../modules/01-cors-session-hijack/module.yml`](../../modules/01-cors-session-hijack/module.yml)
declares which versions are expected to reproduce and which are not.

Configuration (all env-overridable): `MCP_SSE_ENDPOINT` (`/mcp/sse`), `MCP_MESSAGE_ENDPOINT`
(`/mcp/message`), `CI_WORKSPACE`, `CI_COMMAND_TIMEOUT`, `PORT`.

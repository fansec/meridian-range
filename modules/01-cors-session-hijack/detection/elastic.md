# Detection - 01 CORS session hijack (CVE-2026-34237)

> Deployment identifiers here are placeholders: `<LAB_HOST>` = the lab VM's `host.name`,
> `<LAB_POLICY>` = the lab Elastic Agent policy, `<ELASTIC_PROJECT>` = your project. **Scope every rule
> to the lab host only** so it can never fire on shared/production hosts. Author rules **disabled**;
> enable only after a live lab hit.

## Threat model for the detection engineer

The SOC **does not control the vulnerable application**. Meridian CI is a third-party build assistant
running the affected MCP Java SDK; we cannot make it emit a "you are being attacked" flag, and we would
not trust such a flag if it did. So the detection is built from telemetry the SOC **does** own:

1. **Endpoint / EDR** process events (Elastic Defend) - the payload of the attack.
2. **Web / access telemetry** for the MCP transport - shipped from the app's own structured access log
   (or a reverse proxy in front of it) as **raw request facts**, with the hijack **verdict derived at
   ingest** by the SOC's pipeline, never by the app.

## Signal (the discriminator)

A request to the MCP HTTP/SSE transport (`/mcp/sse`, `/mcp/message`) that carries a browser **`Origin`
header whose host differs from the server it is addressing**. A legitimate local MCP client (the
developer's agent) sends **no** `Origin`; only a web page does. That cross-origin condition is exactly
what the wildcard-CORS bug enables: the foreign page reads the SSE `endpoint` event (leaking the session
id) and relays JSON-RPC over the hijacked session. The rule is language-agnostic - it catches any
wildcard-CORS MCP server, not just this one.

## Data sources

| Layer | Source (SOC-owned) | Dataset | What it catches |
|-------|--------------------|---------|-----------------|
| **A - endpoint** | Elastic Defend process telemetry | `logs-endpoint.events.process` | the **payload**: `run_command` -> `java -> /bin/sh -c "…LAB_CANARY…"`. Independent of the app; catches the exec even if no web telemetry exists. |
| **B - app-layer** | Meridian CI structured access log (ECS JSON on stdout) shipped by the Agent, **or** a reverse-proxy access log | `mcp.access` | the **root cause**: a cross-origin read/relay on the MCP transport. |

The app emits only **raw** access facts (see [`TELEMETRY-CONTRACT.md`](../../../docs/telemetry-contract.md)):
`http.request.method`, `url.path`, `http.response.status_code`, `http.request.headers.origin`,
`http.request.headers.host`, `user_agent.original`, `source.ip`, `mcp.session.id`. **No verdict fields.**

The SOC's ingest pipeline [`ingest/mcp-access-cors-pipeline.json`](./ingest-pipeline.json)
derives, from `http.request.headers.origin` vs `http.request.headers.host`:

- `mcp.cors.origin_host` - the host[:port] parsed out of the `Origin`
- `mcp.cors.cross_origin` - **true** when an `Origin` is present and its host differs from the `Host` addressed

Detection rule [`ATR-2026-70001`](./ATR-2026-70001-cors-session-hijack.yaml) keys on that **derived**
field, so the analytic never depends on the vulnerable app computing anything.

## Rule B - app-layer root cause (Elastic / KQL)

```kql
event.dataset : "mcp.access"
  and url.path : "/mcp/*"
  and mcp.cors.cross_origin : true
  and host.name : "<LAB_HOST>"
```

Higher fidelity as a sequence within one browser source (read the endpoint event, then relay a call):

```
sequence by source.ip with maxspan=30s
  [ any where event.dataset == "mcp.access" and url.path == "/mcp/sse"     and mcp.cors.cross_origin == true ]
  [ any where event.dataset == "mcp.access" and url.path == "/mcp/message" and mcp.cors.cross_origin == true ]
```

## Rule A - endpoint payload (Elastic / EQL)

```
process where event.type == "start"
  and process.parent.name == "java"
  and process.name in ("sh", "dash", "bash")
  and process.command_line like "*LAB_CANARY*"
  and host.name == "<LAB_HOST>"
```

> Capability-tool exec is the general class this escalates on. In the lab the only command sent is the
> benign canary; in the wild the child process would be whatever the attacker chose. Confirm on first run
> that Defend surfaces **container-internal** processes (the JVM and its shell children run inside the
> `mcp-ci` container); if not, enable Defend container support.

| Field | Meaning |
|-------|---------|
| `mcp.cors.cross_origin` | Derived at ingest; **true** = a foreign browser Origin drove the MCP transport. **The signal.** |
| `url.path` | Scope to the transport (`/mcp/sse` read, `/mcp/message` relay). |
| `process.parent.name` / `process.command_line` | The exec the hijacked session drives (payload layer). |

**Severity:** High (capability-bearing exec reachable cross-origin).
**False positives:** a deliberately browser-based, cross-origin MCP client would trip Rule B - rare, and
allow-listable by origin (extend the ingest pipeline with a known-good origin set). **False negatives:** a
non-browser attacker that omits `Origin` will not trip Rule B, but also cannot leverage the *browser* trust
this bug is about; the DNS-rebinding variant is covered by [`ATR-2026-70018`](../../02-dns-rebind/detection/ATR-2026-70018-dns-rebind-foreign-host.yaml).

## Validation / definition-of-done

1. Run the scenario (VULNERABLE default) -> Rule A (Defend) and Rule B (mcp.access + derived cross_origin)
   each generate a signal (`ATTACK-OK`).
2. Confirm both stay silent on benign traffic: a local client sends no `Origin`, so `mcp.cors.cross_origin`
   is false and no capability shell is spawned from a cross-origin request.
3. Only then flip the rules `enabled: true`. Keep them scoped to `host.name : <LAB_HOST>`.

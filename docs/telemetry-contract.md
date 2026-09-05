# Elastic telemetry contract (detection side)

> **Scope safety:** deploy these rules/inputs **only** against the isolated lab host
> (`host.name : <LAB_HOST>`, the dedicated lab agent policy `<LAB_POLICY>`). If the Elastic project is
> shared with any real/production data, never scope, enable, or edit anything for another host or policy.
> Placeholders: `<LAB_HOST>` = lab VM `host.name`, `<LAB_POLICY>` = lab agent policy.

Prefer two independent detection layers when the attack creates both endpoint and transport signals.
Attack 01 (CVE-2026-34237 CORS session hijack) is the reference. If an attack deliberately creates no
process, file, or network side effect, document that absence instead of manufacturing a noisy endpoint
proxy. Module 03 is this case and uses an identity-aware MCP elicitation correlation. The governing
principle is unchanged: **the SOC does not control the vulnerable application**, so every detection is
built from SOC-owned telemetry, and any hijack *verdict* is derived at ingest or query time, never read
from a field the vulnerable app computed about itself.

---

## Layer A - Endpoint (Elastic Defend)

The lab agent policy runs Elastic Defend. Process/network telemetry lands in `logs-endpoint.events.*`
with standard ECS - nothing to build on the lab side, just run the scenario. For module 01 the endpoint
rule keys on the exec the hijacked session drives:

```
run_command  ->  java -> /bin/sh -c "id; hostname; echo LAB_CANARY_<pid>"
```

(The Meridian CI server is a JVM on an Ubuntu-based JRE image, so the child shell is `/bin/sh` (dash),
parent `java`.)

**Confirm on first run:** whether Defend surfaces *container-internal* processes (the JVM and its shell
children run inside the `mcp-ci` container). On the first attack-01 run, verify a `LAB_CANARY` process
event appears for `host.name : <LAB_HOST>`. If container processes do **not** appear, enable Defend's
container support (or rely on Layer B alone).

## Layer B - App-layer MCP access telemetry (raw facts; the SOC derives the verdict)

The root-cause signal is a **cross-origin request on the MCP HTTP/SSE transport**. Elastic Defend cannot
see it - it is HTTP/app-layer.

### 1. The app emits RAW access facts only

Meridian CI (`servers/mcp-ci-java`) logs one **ECS JSON** line per HTTP request to stdout via the
`mcp.access` logger (an `OncePerRequestFilter`). It records only neutral request facts - **no verdict
fields** (no `cross_origin`, no `foreign_host`):

```jsonc
{
  "@timestamp": "2026-07-30T11:40:47.021Z",
  "event.dataset": "mcp.access",
  "http.request.method": "GET",
  "url.path": "/mcp/sse",
  "http.response.status_code": "200",
  "http.request.headers.origin": "http://attacker.lab.consulereit.nl",   // ABSENT for a local client (the tell)
  "http.request.headers.host":   "mcp.lab.consulereit.nl:8080",
  "user_agent.original": "…",
  "source.ip": "172.28.0.68",
  "mcp.session.id": null                                   // present on /mcp/message?sessionId=…
}
```

A local MCP client omits `Origin`; that absence is the whole detection. This is exactly what any
enterprise web app (or a reverse proxy) already logs - the app is just a log source.

### 2. Ship it, then DERIVE the verdict at ingest

| Raw field (app / proxy)          | ECS field                       |
|----------------------------------|---------------------------------|
| request method                   | `http.request.method`           |
| request path                     | `url.path`                      |
| response status                  | `http.response.status_code`     |
| `Origin` header                  | `http.request.headers.origin`   |
| `Host` header                    | `http.request.headers.host`     |
| session id (from `?sessionId=`)  | `mcp.session.id`                |
| source address                   | `source.ip`                     |
| -                                | `event.dataset: "mcp.access"`   |

Ship the ECS stdout with the Elastic Agent's container-logs input (or a **Custom Logs** input tailing a
reverse-proxy access log) to dataset **`mcp.access`**, applied to the **lab agent policy only**. Then the
SOC's ingest pipeline
[`modules/01-cors-session-hijack/detection/ingest-pipeline.json`](../modules/01-cors-session-hijack/detection/ingest-pipeline.json)
enriches each event **SOC-side**:

| Derived field            | Meaning                                                              |
|--------------------------|---------------------------------------------------------------------|
| `mcp.cors.origin_host`   | host[:port] parsed out of the `Origin`                              |
| `mcp.cors.cross_origin`  | **true** when an `Origin` is present and its host differs from `Host` |

Rule [`ATR-2026-70001`](../modules/01-cors-session-hijack/detection/ATR-2026-70001-cors-session-hijack.yaml)
keys on `mcp.cors.cross_origin`. Enable it after the first live hit.

### Why derivation (not an app field) matters

Contrast with the TypeScript server (`servers/ts-vuln`, the **module 02** DNS-rebind victim), which
precomputes verdict fields (`foreign_host`, and the dormant `tainted_tool_meta`) inside the vulnerable app.
That is convenient for a lab but is the **anti-pattern** for real detection engineering: you would be
trusting the target to grade its own compromise. Module 01's redesign avoids it - the app emits facts, the
SOC derives the verdict. (Module 02 is out of scope for the CVE-2026-34237 work; the same ingest-derivation
remedy applies to it - derive `foreign_host` SOC-side from the raw `Host` header. See
[`modules/02-dns-rebind/detection/elastic.md`](../modules/02-dns-rebind/detection/elastic.md).)

## Module 03 - elicitation boundary telemetry

Cross-client elicitation routing creates no useful process event, so module 03 records neutral facts at
the three protocol boundaries a defender needs: initiation under the tool request's validated identity,
delivery under the transport's bound identity, and answer receipt under the responding HTTP request's
validated identity. All carry the same `mcp.elicitation.id`.

The application does not compare those identities or emit a verdict. ATR-2026-70019 groups by
`mcp.elicitation.id` and counts distinct `user.id` values in the SOC layer. Delivery identity must come
from the transport that actually sent the request, not from the initiating handler. See
[`modules/03-cross-client-elicitation-hijack/detection/elastic.md`](../modules/03-cross-client-elicitation-hijack/detection/elastic.md).

---

## Validation / definition-of-done for modules 01 and 02

1. Run the scenario (VULNERABLE default) -> the Layer A (Defend) and Layer B (`mcp.access` + derived
   `mcp.cors.cross_origin`) rules each generate a signal (`ATTACK-OK`).
2. Confirm both stay silent on benign traffic: a local client sends no browser `Origin`
   (`mcp.cors.cross_origin` false) and spawns no cross-origin-triggered shell. That is the clean negative.
3. Only then flip the rule `enabled: true`, scoped to `host.name : <LAB_HOST>`.

For module 03, replace the endpoint layer with the three elicitation audit events. Verify that the
vulnerable run produces two identities for one elicitation ID, the fixed run does not, and the
single-principal negative remains silent before enabling the lab-scoped rule.

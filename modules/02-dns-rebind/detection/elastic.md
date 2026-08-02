# Detection - 02 DNS rebinding (CVE-2025-66414 class)

> Deployment identifiers here are placeholders: `<LAB_HOST>` = the lab VM's `host.name`,
> `<LAB_POLICY>` = the lab Elastic Agent policy, `<ELASTIC_PROJECT>` = your project. **Scope every rule
> to the lab host only** so it can never fire on shared/production hosts. Author rules **disabled**;
> enable only after a live lab hit.

## Threat model for the detection engineer

Module 01 (CORS session hijack) is caught by a **cross-origin** signal: a browser `Origin` whose host
differs from the server it addresses. DNS rebinding is the variant that **defeats that signal**. The
attacker rebinds their own domain (`rebind.lab.consulereit.nl`) to the victim's address, so the browser's
request becomes *same-origin*: it carries **no cross-origin Origin** for the module-01 rule
[`ATR-2026-70001`](../../01-cors-session-hijack/detection/ATR-2026-70001-cors-session-hijack.yaml) to see. What is still anomalous is the
**Host** header: a local MCP server should only ever be addressed by a loopback or known-service Host, yet
the request names the attacker's rebind domain. A Host outside the known-good set on the `/mcp` endpoint,
**with no cross-origin Origin present**, is the rebind signal.

## Signal (the discriminator)

A request to the MCP transport whose **Host is not in the known-good allow-list** while **no cross-origin
`Origin` is present**. The one server-side control that still catches rebinding is a Host allow-list (the
SDK's `enableDnsRebindingProtection`, which is off unless the application sets it: still `?? false` in
`@modelcontextprotocol/sdk` 1.29.0, the version this lab actually runs); this rule keys on the same
allow-list decision expressed as telemetry.

## Data sources

| Layer | Source (SOC-owned) | Dataset | What it catches |
|-------|--------------------|---------|-----------------|
| **A - endpoint** | Elastic Defend process telemetry | `logs-endpoint.events.process` | the **payload**: `run_command` -> `node -> /bin/sh -c "…LAB_CANARY…"`. Independent of the app; catches the exec even if no web telemetry exists. |
| **B - app-layer** | MCP transport access telemetry (or a reverse-proxy access log) | request facts | the **root cause**: a request bearing a foreign Host with no cross-origin Origin on the MCP transport. |

The lab's `servers/ts-vuln` server currently **precomputes** a `foreign_host` boolean in its telemetry
(Host outside `ALLOWED_HOSTS`, which the server records but never enforces). That is convenient for a lab
but is the **anti-pattern** for real detection engineering: you would be trusting the target to grade its
own compromise. The production-grade approach mirrors module 01 - ship the **raw** `http.request.headers.host`
and `http.request.headers.origin` and derive the `foreign_host` / cross-origin verdict **SOC-side** at
ingest, exactly as [`ingest/mcp-access-cors-pipeline.json`](../../01-cors-session-hijack/detection/ingest-pipeline.json) derives
`mcp.cors.cross_origin`. See [`TELEMETRY-CONTRACT.md`](../../../docs/telemetry-contract.md).

Detection rule [`ATR-2026-70018`](./ATR-2026-70018-dns-rebind-foreign-host.yaml) keys on the
`foreign_host` decision.

## Rule B - app-layer root cause (Elastic / KQL)

```kql
event.dataset : "mcp.access"
  and url.path : "/mcp*"
  and mcp.host.foreign : true
  and not mcp.cors.cross_origin : true
  and host.name : "<LAB_HOST>"
```

`mcp.host.foreign` is the SOC-derived equivalent of the server's `foreign_host` (true when the request's
Host is outside the known-good set). The `not mcp.cors.cross_origin : true` clause captures the defining
property of the rebind: it is same-origin from the browser's point of view, which is exactly why the
module-01 CORS rule stays silent and this rule is needed.

**Do not write that clause as `not http.request.headers.origin : *`.** A browser sends `Origin` on a POST
even when the request is same-origin, so "no Origin header present" is true of a headless client and
**false of the live attack**: the recorded browser run shows `origin: http://rebind.lab.consulereit.nl:8080`
matching the `Host` on every request. `Origin` absent and `Origin` equal to `Host` are both
non-cross-origin, and the derived verdict covers both. This rule was written the wrong way first, and the
recorded run is what caught it.

## Rule A - endpoint payload (Elastic / EQL)

```
process where event.type == "start"
  and process.parent.name == "node"
  and process.name in ("sh", "dash", "bash")
  and process.command_line like "*LAB_CANARY*"
  and host.name == "<LAB_HOST>"
```

> The victim MCP for this module (`servers/ts-vuln`) is a Node process, so the capability exec surfaces as
> `node -> /bin/sh -c "…"`. In the lab the only command sent is the benign canary; in the wild the child
> process would be whatever the attacker chose.

| Field | Meaning |
|-------|---------|
| `mcp.host.foreign` / `foreign_host` | Host outside the known-good allow-list. **The signal.** |
| `http.request.headers.origin` | Absent on the rebind (same-origin) request - the reason the CORS rule cannot see it. |
| `process.parent.name` / `process.command_line` | The exec the rebound session drives (payload layer). |

**Severity:** High (capability-bearing exec reachable once rebinding makes the request same-origin).
**False positives:** a legitimate client addressing the server by an unusual-but-valid name; keep the
allow-list current. **False negatives:** an attacker who both omits `Origin` and presents a known-good Host
(e.g. a rebind onto the exact service name) would evade the Host signal; bind to loopback and authenticate
as defence in depth.

## Validation / definition-of-done

1. Run the scenario (VULNERABLE default) -> Rule A (Defend) and Rule B (foreign Host, not cross-origin) each
   generate a signal (`ATTACK-OK`). The scenario proves the **post-rebind request reached the victim MCP**
   (a session was issued to the foreign Host) and executed only the benign canary.
2. Confirm both stay silent on benign traffic: a local client addresses the server by its known-good Host,
   so `foreign_host` is false and no capability shell is spawned.
3. Only then flip the rules `enabled: true`. Keep them scoped to `host.name : <LAB_HOST>`.

See [`../README.md`](../README.md) for the full time-varying rebind (Technitium
record, TTL, initial/final answers, trigger/restore, and overlay teardown).

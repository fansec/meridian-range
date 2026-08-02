# Framework mapping

Every attack maps to **OWASP LLM Top 10** (primary), the emerging **OWASP MCP Top 10** (beta v0.1,
2026), the **OWASP Agentic Security Initiative (ASI)** threats, **CWE**, and the real **CVE(s)** it
anchors to. IDs not yet primary-source-verified carry a `(verify)` marker; because the MCP Top 10 is
still beta, its mappings here are provisional.

## Coverage matrix

<!-- BEGIN GENERATED: owasp-matrix (generated from modules/*/module.yml by `range render`; do not edit by hand) -->
| # | Attack | OWASP LLM | OWASP MCP | ASI | CWE | Anchor CVE (CVSS) | Status |
|---|--------|-----------|-----------|-----|-----|-------------------|--------|
| 01 | CORS Session Hijack | LLM06 Excessive Agency | MCP07 Insufficient AuthN/AuthZ | ASI02, ASI03 | CWE-942, CWE-78, CWE-862, CWE-346 | CVE-2026-34237 (6.1) | shipped |
| 02 | DNS Rebinding | LLM06 Excessive Agency | MCP07 Insufficient AuthN/AuthZ | ASI02, ASI03 | CWE-1188, CWE-346, CWE-78 | CVE-2025-66414 (7.6) | shipped |
<!-- END GENERATED: owasp-matrix -->

## Module 01 (CORS session hijack) - notes
- **CVE-2026-34237** - MCP **Java SDK** (`io.modelcontextprotocol.sdk:mcp-core`), CWE-942, CVSS 6.1:
  the HTTP/SSE transport hardcodes `Access-Control-Allow-Origin: *` and discloses the session id on
  the SSE `endpoint` event; an attacker page has the victim's browser read it cross-origin and relays
  `tools/call` through it. Fixed by removing CORS ownership from the transport. This range reproduces
  it on the **actual affected release** (`servers/mcp-ci-java`, Spring Boot pinned to `mcp-core 1.0.0`)
  - a faithful reproduction, not a restatement in another language.
- Module 01 is **CORS-only and needs no DNS**: it runs headless in labnet, or against a real browser in
  IP-address mode (no DNS) or ordinary fixed DNS records. DNS rebinding is a **separate attack** - module 02.
- The 2026-07-28 MCP spec release candidate moves the protocol toward **stateless** transports
  (removing the `Mcp-Session-Id` header/SSE `endpoint` event this attack hijacks). CVE-2026-34237
  remains valid history and the attack still teaches wildcard-CORS + origin-trust; a stateless-era
  transport variant is on the backlog.

## Module 02 (DNS rebinding) - notes
- **CVE-2025-66414** (CWE-1188; 8.1 under CVSS 3.1 per NVD, 7.6 under CVSS 4.0 per GitHub, verified
  2026-08-02): the TypeScript SDK's DNS-rebinding protection is OFF by default
  (`enableDnsRebindingProtection`). This is the **anchor** for module 02 (`servers/ts-vuln`, the victim
  server): DNS rebinding makes the attacker's request same-origin (so Origin validation has nothing to
  check), and a Host allow-list is the control that holds. Matches detection rule `ATR-2026-70018`;
  companion **CVE-2025-66416** (Python SDK).
  **Version note:** the advisory's affected range is `< 1.24.0`, but `package.json`'s `^1.12.0` is not
  what runs. `npm ci` installs the lockfile's resolution, **1.29.0**, and the default is still `false`
  there (`webStandardStreamableHttp.js:70`), so the module reproduces on a build past the fix. Do not
  restate the affected range as though it described this lab; the finding is that the default persists.
- **CVE-2025-49596** (MCP **Inspector** `< 0.14.1`, CVSS 9.4): no-auth client-to-proxy access leading to
  stdio RCE. **Related work only**, not a precondition and not part of module 02's chain: different
  product, and the reproduction does not touch it. Listed as the highest-impact known consequence of a
  browser reaching a local MCP component. That DNS rebinding is a stated delivery path for it is
  `(verify)`: the NVD description does not mention rebinding.
- The rebind hostname is `rebind.lab.consulereit.nl`, whose answer changes over time (a fixed wildcard
  record is not sufficient). The live rebind is a two-VM opt-in deployment
  (`modules/02-dns-rebind/deploy/attacker.yml` + `victim.yml`) using the existing lab Technitium; see
  [`../modules/02-dns-rebind/README.md`](../modules/02-dns-rebind/README.md).

Tool-description prompt injection ("tool poisoning") is **not currently catalogued** - it was drafted,
then retired to the backlog. See [`BACKLOG.md`](./BACKLOG.md) (Track B) for its planned OWASP/CWE
anchors; a framework-mapping row will land here once it ships as a real module.

# Meridian Range - backlog

Catalogued attacks not yet built in this repo. **Modules 01 (CORS session hijack) and 02 (DNS
rebinding) are shipped and VM-verified. Module 03 (cross-client elicitation hijack) is authored and
pending its VM run.** Everything below is design-only: the writeups live in the research vault
(`../mcp-research-brain/03-modules/`); nothing here has a server, scenario, detection, or VM run in this
repo yet.

A module is **done** only when it walks the loop: reproduce (`ATTACK-OK`) -> detection (signal + rule),
verified on the VM. When you pick one up, scaffold it with `./range new <id> <slug>` and fill in the one
directory it creates under `modules/` (server + `scenario.ts` + `detection/` + `evidence/`); the
`module.yml` it writes IS the catalog row, so there is no central file to edit. Then run `./range check`
and `./range render`, and flip `status:` to `active` once `./range verify` is green on the VM.

## Immediate cleanup (carried over)
- [ ] **`servers/ts-vuln` still carries retired tool-poisoning payload.** The tool-description injection
      payload (`POISON_DIRECTIVE`, the metadata-linter regexes, the `tools/list` taint signal) is baked
      into `ts-vuln`, which is now the **module 02 (DNS rebinding)** victim server. The poison is DORMANT
      and unrelated to the DNS-rebind path; it was left in place because removing it is a refactor of the
      module-02 server that must be re-verified on the VM (module 02 must still be `ATTACK-OK`). Strip it
      when you either rebuild tool-description injection as its own module or retire the payload. (Note: the
      NEW module 02 is DNS rebinding, not tool poisoning - the old "module 02" numbering referred to the
      retired tool-poisoning draft.)
      **Update after the refactor:** the payload's client-side twin, the credulous-agent scanner at
      `harness/src/agent.ts`, has been DELETED as dead code, so the "keep the two copies in sync" coupling
      is gone and only the dormant server-side copy remains. That makes this a single-file cleanup now.
      The two stale `keep them in sync` comments in `servers/ts-vuln/src/index.ts` point at a file that no
      longer exists and should go with it.

## Track B - tool metadata / prompt injection
- [ ] **Tool-Description Prompt Injection** (drafted earlier as a tool-poisoning module, since retired;
      scenario removed from this repo, recoverable from git history. Not to be confused with the current
      module 02 = DNS rebinding). Poisoned tool metadata read as trusted instructions. LLM01 / MCP03.
- [ ] **Indirect prompt injection** - anchor CVE-2025-32711 (EchoLeak, 9.3). Vault: `06-indirect-prompt-injection`.
- [ ] **Cross-tool exfiltration** - CVE-2025-68143/44/45 (mcp-server-git chain) + ForcedLeak. Vault: `07-cross-tool-exfil`.
- [ ] **Semantic routing hijack** - CVE-2025-54136 (MCPoison, 7.2) + CVE-2025-54135 (CurXecute, 8.6). Vault: `08-semantic-routing-hijack`.

## Track A - transport / session / auth
- [ ] **DCR to OAuth token theft** - CVE-2026-42230 (n8n DCR open-redirect, 5.1) + Square MCP one-click ATO. Vault: `02-dcr-oauth-theft`.
- [ ] **OAuth mix-up** - RFC 9207 `iss` validation gap. Vault: `16-oauth-mixup`.
- [ ] **PHP insecure default** - CVE-2026-34237 class, cross-stack restatement. Vault: `03-php-insecure-default`.

## Elicitation / UI
- [ ] **Elicitation phishing** - MCP spec 2025-06-18 elicitation pattern. Vault: `04-elicitation-phishing`.
- [ ] **Elicitation ATO** - Square MCP ATO + Storm-2372 device-phish. Vault: `05-elicitation-ato`. (Note: the vault's original 05 did not reproduce - known SDK finding; re-check before building.)
- [ ] **MCP-Apps UI phishing** - MCP Apps RC (2026-07-28). Vault: `15-mcp-apps-ui-phishing`.

## Supply chain
- [ ] **Tool rug-pull** - CVE-2025-54136 (MCPoison, 7.2) + tool pinning. Vault: `14-tool-rug-pull`.
- [ ] **SKILL.md supply chain** - OWASP Agentic Skills Top 10. Vault: `17-skill-supply-chain`.

## CVE case studies (one dedicated benign server per critical CVE)
- [ ] **mcp-remote OS command injection** - CVE-2025-6514 (9.6, fixed 0.1.16).
- [ ] **Flowise MCP ghost-commands RCE** - CVE-2026-40933 (9.9, fixed 3.1.0).
- [ ] **Claude Code symlink sandbox escape** - CVE-2026-39861 (10.0 / 7.7, fixed 2.1.64).
- [ ] **Settings RCE** - CVE-2025-59536 (8.7) + CVE-2026-21852 (5.3).
- [ ] **mcp-server-git chain** - CVE-2025-68143/44/45 (8.8 / 8.1 / 7.1).

---
See the vault module tracker
(`../mcp-research-brain/03-modules/00-module-tracker.md`) for the full designs and real-world anchors.
All CVE IDs above are carried from the vault; re-verify against primary sources before building.

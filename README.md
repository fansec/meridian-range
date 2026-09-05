<div align="center">

<img src="./media/logo.png" alt="Meridian Range: a compass reticle ring, its graticule drawn in fine dashed arcs, enclosing a snow-capped mountain range, with a shield carrying an M standing at the centre. The wordmark MERIDIAN RANGE sits below." width="340">

# Meridian Range

**A defensive range for MCP and AI-agent attacks.**

Reproduce a *published* insecure default (`ATTACK-OK`) and ship a **detection**. The detection is the
deliverable, not the exploit.

<br>

![OWASP](https://img.shields.io/badge/OWASP-LLM%20Top%2010-1f2328)
![run](https://img.shields.io/badge/run-isolated%20VM%20only-cf222e)
![modules](https://img.shields.io/badge/modules-2%20VM--verified-1a7f37)
![detections](https://img.shields.io/badge/detections-ATR%20to%20Sigma%20%2F%20Elastic-0969da)
[![license](https://img.shields.io/badge/license-MIT-6639ba)](./LICENSE)

[Design](#design) · [Attack catalog](#attack-catalog) · [Quick start](#quick-start) · [Adding an attack](#adding-an-attack)

<br>

<b>Every module opens with its own recording</b>, driven from a real browser against the actual
affected SDK release, and ending in command output the attacker received.

|  |  |
|---|---|
| **[Attack 01, CORS session hijack](./modules/01-cors-session-hijack/README.md)**<br><sub>CVE-2026-34237. An MCP server on the developer's own machine is assumed private because "only localhost can reach it." That assumption rests entirely on the browser. The affected transport answers every request with `Access-Control-Allow-Origin: *` and discloses the session id on the SSE `endpoint` event, so a page opened once can read that session, replay it, and drive `run_command`. The clip ends with the canary output at the attacker's collector, under the same session id.</sub> | **[Attack 02, DNS rebinding](./modules/02-dns-rebind/README.md)**<br><sub>CVE-2025-66414. The attack that survives the fix for 01. Checking `Origin` stops a cross-origin page; it does not stop the attacker's own page from becoming same-origin with the target. One DNS answer flips and the same tab, at the same URL, with no second click, is talking to the MCP server on the developer's machine. The clip ends with the command output printed in the page itself.</sub> |

</div>

---

Reading a CVE tells you a flaw exists. It does not tell you what it looks like in your telemetry at
03:00, which is the only form of that knowledge a defender can act on. So each module takes one
published CVE, reproduces it end to end until the attack actually lands, and then answers the question
that matters: **what signal did that leave, and what rule fires on it?** A module is finished when
both halves exist and the isolated VM has run them green.

## Design

**A module is a directory.** Everything one attack owns lives in `modules/<NN-slug>/`: its manifest,
its scenario, its compose file, its detection, its evidence, its writeup. There is no central catalog
to edit and no registry to update, because `range` discovers modules by globbing
`modules/*/module.yml`. Adding an attack means adding one directory and changing nothing else.

A shared **engine** does the rest: `engine/harness/` holds the scenario SDK and the transport clients,
`engine/cli/` implements the `./range` command, and `engine/compose.yml` is the sealed base every
module is merged on top of.

<p align="center"><img src="./media/engine-design.svg" alt="Meridian Range design view in three bands. Band 1, author: a module is one directory holding module.yml, scenario.ts, compose.yml, lab.env, detection, evidence and README. Band 2, the shared engine: the range CLI, the harness with its scenario SDK and transport clients, the sealed compose base with internal true and no published ports, and the vulnerable servers pinned per SDK release. Band 3, running the loop: a reproduce lane of range up, run, ATTACK-OK, verify and matrix, feeding a detect lane of telemetry, ATR rule, detect-test and export, ending at module done. A final band lists what is present today: modules 01 and 02 are VM-verified, and module 03 is authored pending VM verification." width="900"></p>

|  |  |
|---|---|
| **Defensive by construction** | Every module ships the full loop: reproduce, then detect. An exploit without a detection is not a module here. |
| **Anchored to real CVEs** | Each attack maps to *published* CVEs (CVSS per anchor) and to the OWASP **LLM Top 10** plus the emerging **MCP Top 10**. |
| **Manifest-driven** | Each `module.yml` is the source of truth for its own attack. The catalog table and the [OWASP map](./docs/owasp-mapping.md) are generated from them, never hand-edited. |
| **Detections you can take with you** | Machine-readable ATR rules carry their own `test_cases`, run offline as unit tests, and export to Sigma or Elastic with `./range export`. |
| **Contained by default** | An isolated VM, a no-egress Docker network, one module deployed at a time, benign canaries only. |

## Attack catalog

Built from the module manifests. CVSS shown per anchoring CVE. See the
[OWASP map](./docs/owasp-mapping.md) for the full LLM / MCP / ASI / CWE breakdown, and
[`docs/BACKLOG.md`](./docs/BACKLOG.md) for what is queued next.

<!-- BEGIN GENERATED: catalog-table (generated from modules/*/module.yml by `range render`; do not edit by hand) -->
| # | Attack | OWASP | Anchor CVE (CVSS) | Repro | Detect | Blog |
|---|--------|:-----:|-------------------|:-----:|:------:|:----:|
| 01 | [CORS Session Hijack](./modules/01-cors-session-hijack/) | **LLM06** | CVE-2026-34237 (6.1) | ✅ | ✅ | _soon_ |
| 02 | [DNS Rebinding](./modules/02-dns-rebind/) | **LLM06** | CVE-2025-66414 (7.6) | ✅ | ✅ | _soon_ |
| 03 | [Cross-Client Elicitation Hijack](./modules/03-cross-client-elicitation-hijack/) | **LLM06** | CVE-2026-25536 (7.1) | 🧪 | ✅ | _soon_ |
<!-- END GENERATED: catalog-table -->

**Legend:** ✅ shipped and VM-verified · 🧪 authored, **pending VM verification** (`./range verify`).

## Quick start

Everything below runs **on the lab VM** and nowhere else. Mark the VM once with
`sudo touch /etc/meridian-vm`, or prefix a single command with `MERIDIAN_ON_VM=1`.

```bash
./range list                 # what modules exist
./range up 01                # sealed tier: internal network, no published ports
./range run 01               # reproduce -> [ATTACK-OK]
./range verify 01            # the gate; writes modules/01-*/evidence/vuln.txt
./range matrix 01            # the same attack against every SDK version it declares
./range down                 # tear down everything on this host
```

On the authoring host, nothing starts and everything is offline:

```bash
./range check                # manifests, module structure, detections, the no-ports gate
./range detect-test          # detection rules against their own test cases
./range export --format sigma --out /tmp/pack
./range plan 01 --tier split-host --side victim   # print the deploy command, run nothing
./range sync --build 01      # push to the VM and rebuild that module's server there
```

Full walkthrough: [`docs/getting-started.md`](./docs/getting-started.md). Every command carries a
`[dev]` or `[VM]` marking in `./range --help`: `[VM]` refuses to run anywhere else.

## Adding an attack

```bash
./range new 04 tool-poisoning --name "Tool Description Poisoning"
```

That scaffolds the whole module directory from the template, and `./range check` then enforces that
shape on every commit. The ordered checklist and the contribution mechanics are in
[`docs/CONTRIBUTING.md`](./docs/CONTRIBUTING.md).

The three modules are worth reading end to end:
[module 01, CORS session hijack](./modules/01-cors-session-hijack/README.md) is the full study, from
the transport defect to the detection and the one-line fix. [Module 02, DNS
rebinding](./modules/02-dns-rebind/README.md) is a **separate** attack that defeats the Origin control
which stops module 01. [Module 03, cross-client elicitation
hijack](./modules/03-cross-client-elicitation-hijack/README.md) turns unsafe multi-transport server
reuse into a ghost approval, then detects one elicitation identifier crossing authenticated users.

<div align="right"><a href="#meridian-range">↑ back to top</a></div>

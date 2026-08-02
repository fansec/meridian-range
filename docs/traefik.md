# Traefik / wildcard-DNS front end (optional)

Written against module 01, but the mechanism is module-agnostic: the routers are named for **roles**, not
for modules, and `./range traefik <module>` emits the roles that module declares in its `module.yml`. Since
the range deploys exactly one module at a time, one generated file always describes
whatever is currently up. A module can opt out with `topology.traefik: false` when a proxy would defeat the
attack: module 02 does, because a DNS rebind has to flip in the DNS **answer**, not in a proxy backend.

The exposed test works two ways. Pick one:

- **Without DNS (default, always works).** Raw `IP:port` - open `lan.html` with explicit `?mcp=` / `?collector=`
  params, or `?samehost=1` on a single VM. Nothing in this file is required. See the README "Manual
  cross-machine test" and [`topology.md`](./topology.md).
- **With DNS (this file).** Give each service a subdomain on your existing wildcard (`*.lab.consulereit.nl`)
  and let your Traefik terminate TLS and route to the VM. Cleaner URLs, real HTTPS origins, closer to a
  real incident.

Everything here is **opt-in and isolated-lab-LAN only**, and it sits on top of a committed opt-in compose
deployment - it does not change the sealed default.

## Two host tiers

| Tier | Backends | Bring it up with |
|---|---|---|
| **`split-host`** (recommended, realistic) | attacker page + collector on the **sanctioned attacker host**; `mcp-ci` on the **lab VM** | `./range up 01 --tier split-host --side attacker` / `--side victim` |
| **`single-host`** | all three on the VM | `./range up 01 --tier single-host` |

The split is what a real incident looks like: the attacker's infrastructure is not the victim's machine.
Only non-capability-bearing services (static nginx page, HTTP sink) ever leave the VM - `mcp-ci` carries
`run_command` and stays put, on the VM, always.

`./range traefik` emits the right backend IP per role from `.env`: set `ATTACKER_HOST_IP` to the attacker
host for the split tier, or leave it equal to `LAB_VM_IP` for the single-host one.

## The model (matches this lab's Forgejo convention)

Your Traefik runs on your **home host**, not on the lab VM, and reaches the VM over the LAN by `IP:port`
using its **file / dynamic provider** (the same way `git.lab.consulereit.nl` reaches the Forgejo container
that just publishes `:3000`). So Traefik does **not** need to share a Docker network with the range, and the
range needs **no** container labels. The only requirement is that each host publishes its backend ports,
which the exposed tier already does.

```
your wildcard *.lab.consulereit.nl         ─A─►  Traefik (home host, holds the TLS cert)
                                             │  file-provider routers (Host -> backend IP:port)
        browser ──HTTPS──►  attacker.lab... ───┤►  http://<ATTACKER-IP>:1337  attacker-web  (lan.html)
                            mcp.lab...     ───┤►  http://<VM-IP>:8080       mcp-ci  (CORS target, run_command)
                            collector.lab... ─┘►  http://<ATTACKER-IP>:9000  attacker-collector (canary sink)

        (single-host tier: <ATTACKER-IP> == <VM-IP>, and all three come from single-host.yml)
```

`attacker.*` calling `mcp.*` is a genuine **cross-origin** request, which is exactly what the wildcard-CORS
bug (CVE-2026-34237) needs. TLS is terminated at Traefik; the hop from Traefik to the VM stays plain HTTP on
the isolated LAN.

A wildcard `*.lab.consulereit.nl` A record already covers every role name, so **adding a module adds no DNS
record**. The names describe roles (`mcp.` is whichever victim MCP is deployed), not modules.

## Setup

### 1. Bring up the backends (isolated lab LAN only)

Split-host:
```bash
# on the sanctioned attacker host - static page + collector, no capability-bearing service:
MERIDIAN_ATTACKER_HOST=1 ./range up 01 --tier split-host --side attacker

# on the lab VM - publishes ONLY mcp-ci:
./range up 01 --tier split-host --side victim
```

Single-host (everything on the VM):
```bash
./range up 01 --tier single-host
```

A `[VM]` command refuses unless the host has identified itself as the lab VM (`/etc/meridian-vm`, or
`MERIDIAN_ON_VM=1` for one command), so the examples above assume the marker file is in place on the VM.
`./range up` also refuses if another module's stack is already running on that host,
so run `./range down` first when switching modules. `./range plan …` prints the underlying `docker compose`
command without executing it, which is the authoring-host-safe way to check what a tier would do.

### 2. Set the knobs in `.env`
The repo-root `.env` is now **deployment-only**: published ports, public hostnames, host addresses and
Traefik knobs, organised by role rather than by module (a module's own scenario targets live in its
committed `modules/<NN-slug>/lab.env` instead). Copy [`../.env.example`](../.env.example) and fill in:
```ini
LAB_VM_IP=192.0.2.10                          # lab VM - the VICTIM MCP lives here, always
ATTACKER_HOST_IP=198.51.100.10                # sanctioned attacker host; = LAB_VM_IP for single-host
PUBLIC_MCP_HOST=mcp.lab.consulereit.nl
PUBLIC_HACKER_HOST=attacker.lab.consulereit.nl
PUBLIC_COLLECTOR_HOST=collector.lab.consulereit.nl
WEB_PORT=1337
MCP_PORT=8080
COLLECTOR_PORT=9000
TRAEFIK_ENTRYPOINT=websecure                  # your Traefik HTTPS entrypoint name - VERIFY yours
TRAEFIK_CERTRESOLVER=le                        # your ACME resolver name; leave BLANK for plain HTTP
TRAEFIK_ROUTER_PREFIX=mr                       # router/service key prefix - see "naming" below
```
`.env` is git-ignored, so the real IPs stay out of the committed repo (same reason `topology.md` redacts
IPs). `LAB_VM_IP` / `TRAEFIK_ENTRYPOINT` / `TRAEFIK_CERTRESOLVER` depend on **your** setup - verify them
against your Traefik; the defaults are common values, not an assumption about your install.

### 3. Generate the Traefik router config
```bash
./range traefik 01 > meridian-range.yml       # reads the module manifests + .env; static (no VM, no Docker)
```
The module id selects which **roles** get routers: the generator reads that module's `topology.roles` from
its `module.yml` rather than hardcoding three names, and refuses outright for a module that declares
`topology.traefik: false` (module 02). With `TRAEFIK_CERTRESOLVER` set it emits `tls:` routers on your
HTTPS entrypoint; blank, it emits plain-HTTP routers with no `tls:` block. The generator is the only
source for this config - there is no hand-fill template to drift out of sync with it.

#### Naming: role-named keys under one fixed prefix
Traefik router and service names live in **one flat global namespace** shared with every other service your
Traefik proxies. Bare keys like `hacker` or `collector` will eventually collide with something else you add,
and the loser fails silently. So the generator emits `mr-mcp` / `mr-hacker` / `mr-collector`
(`TRAEFIK_ROUTER_PREFIX`), which:

- cannot collide with your non-lab services,
- makes teardown auditable - `grep mr-` over your dynamic config shows everything the lab currently exposes.

**One prefix, not one per module.** An earlier iteration bumped the prefix per module (`mr01`, `mr02`, …) so
several modules could be routed simultaneously. That is exactly what the range no longer does: it deploys
one module at a time, so one fixed prefix and one generated file describe whatever is
up, and switching modules means regenerating the file rather than accumulating routers. This is the reason
the Traefik surface stays flat as modules are added.

Keep the **hostnames** role-based too (`mcp.`, `attacker.`, `collector.`): the scenario semantics are
role-based, and the page is handed those URLs verbatim. A collector routed under a name like `web.*` is a
silent mismatch - Traefik is happy, the attack just posts to a name that is not the collector.

### 4. Drop it into Traefik and add the DNS records
- Copy `meridian-range.yml` into your Traefik dynamic-config directory (the path your file provider watches,
  e.g. `/etc/traefik/dynamic/`). Traefik hot-reloads it; no restart.
- Point `mcp.`, `attacker.`, `collector.` at Traefik. A wildcard `*.lab.consulereit.nl` A record already covers
  all three, and covers every future role name too, so **adding a module adds no DNS record**.

### 5. Drive the attack
From a real browser that can reach Traefik:
```
https://attacker.lab.consulereit.nl/lan.html?mcp=https://mcp.lab.consulereit.nl&collector=https://collector.lab.consulereit.nl/pwned
```
Watch the transcript steal the session id, run the benign canary (`id; hostname; echo LAB_CANARY`), and
exfiltrate to the collector. Confirm the hit where the collector actually runs - on the **attacker host** for
the split tier (`docker compose -p meridian-range-01-attacker logs attacker-collector`), on the VM for the
single-host one.

## Notes and gotchas

- **All three must share the scheme.** With HTTPS subdomains, `?mcp=` and `?collector=` must also be `https://`
  - a page on `https://attacker.*` calling `http://mcp.*` is mixed content and the browser blocks it.
- **SSE.** The scenario streams Server-Sent Events from `/mcp/sse`. Traefik forwards them fine at its default
  `flushInterval` (100ms); do not put a response-buffering middleware in front of the `*-mcp` router.
- **Host header.** The CORS bug does not depend on the Host header, so the default `passHostHeader: true` is
  fine. (DNS **rebinding** - module 02 - is the opposite: it turns on the Host check. That is a separate
  two-VM deployment; see [`../modules/02-dns-rebind/README.md`](../modules/02-dns-rebind/README.md).)
- **Cert.** Traefik needs a cert for these names. A wildcard `*.lab.consulereit.nl` (DNS-01) is simplest; a
  per-name resolver works too. If you have no cert, leave `TRAEFIK_CERTRESOLVER` blank and run the routers on
  plain HTTP (all three subdomains then use `http://`).

## Safety

Fronting the range with Traefik **widens reach**: it takes an exposed tier from "a machine on the lab LAN"
to "anything that can reach these Traefik routes," and `mcp-ci` is **capability-bearing** (`run_command`).
So, on top of the rules that govern any exposed tier:

- Keep these routes **off the internet** - a lab-LAN-only Traefik, or an IP-allow / auth middleware on the
  three routers. Do not attach them to a public entrypoint.
- Benign canaries only; no real secrets.
- Attacker-host services are **static page + sink only**. Never publish a capability-bearing server there,
  and never point a router at one that is not on the VM.
- **Tear down** when the test is done: remove `meridian-range.yml` from Traefik, then `./range down` on
  **both** hosts (it removes every `meridian-range*` stack on the host it runs on, whichever tier was up).
  Confirm with `./range status`. Fail closed - if unsure whether a route is reachable off the lab, assume
  it is and stop.

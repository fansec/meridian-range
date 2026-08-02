"""plan / up / down / status - the deployment commands.

They enforce EXACTLY ONE MODULE DEPLOYED AT A TIME (SECURITY.md rule 2b), which is what lets DNS
names, Traefik routers, the `edge` bridge and published ports be named for the ROLE they play rather
than for the module, and therefore reused instead of multiplying with every module added.
"""
from __future__ import annotations

import subprocess

import catalog as cat
import compose
import hosts

TIERS = ("sealed", "single-host", "split-host")
SIDES = ("victim", "attacker")


def _resolve(module: str, tier: str, side: str) -> dict:
    m = cat.require(module)
    declared = cat.tiers(m)
    if tier not in declared:
        print(f"REFUSING: module {m['id']} ({m['slug']}) does not declare the `{tier}` tier.")
        print(f"It supports: {' '.join(declared)}")
        if tier == "single-host":
            print("(A module without a single-host tier needs two hosts by construction: module 02's")
            print(" attacker page and victim MCP must publish the SAME port, which one host cannot bind twice.)")
        raise SystemExit(2)
    if side not in SIDES:
        raise SystemExit(f"--side must be one of {', '.join(SIDES)}")
    key = compose.fragment_key(tier, side)
    if key and not cat.deploy_fragment(m, key).exists():
        raise SystemExit(
            f"REFUSING: tier `{tier}` needs {cat.rel(m, 'deploy', key + '.yml')}, which does not exist."
        )
    return m


def cmd_plan(args) -> int:
    m = _resolve(args.module, args.tier, args.side)
    cargs, project, svcs = compose.stack(m, args.tier, args.side)
    label = f"module {m['id']} ({m['slug']}) - tier {args.tier}"
    if args.tier == "split-host":
        label += f" - side {args.side}"
    print(f"{label} - project {project}")
    print(compose.describe(cargs, ["up", "-d", "--build", *svcs]))
    print("(plan only: nothing was started. Run the same command with `up` on the right host.)")
    return 0


def cmd_up(args) -> int:
    m = _resolve(args.module, args.tier, args.side)
    what = f"range up {m['id']} --tier {args.tier}"
    if args.tier == "split-host" and args.side == "attacker":
        hosts.require_attacker_host(what)
    else:
        hosts.require_vm(what)

    cargs, project, svcs = compose.stack(m, args.tier, args.side)

    others = [p for p in compose.running_projects() if p != project]
    if others:
        print("\nREFUSING: another Meridian stack is already deployed on this host:")
        for p in others:
            print(f"  {p}")
        print("\nThe range deploys EXACTLY ONE module at a time (SECURITY.md rule 2b). Tear it down first:")
        print("    ./range down")
        raise SystemExit(4)

    label = f"module {m['id']} ({m['slug']}) - tier {args.tier}"
    if args.tier == "split-host":
        label += f" - side {args.side}"
    print(f"{label} - project {project}")
    compose.run(cargs, "up", "-d", "--build", *svcs)

    print(f"\nup: {label}")
    if args.tier != "sealed":
        print("PORTS ARE PUBLISHED. Isolated lab LAN only; benign canaries only; `./range down` when finished.")
        print("Confirm the SECURITY.md pre-flight before driving the attack.")
    return 0


def cmd_down(_args) -> int:
    projects = compose.running_projects()
    if not projects:
        print("range down: nothing to tear down.")
        return 0
    for p in projects:
        print(f"== down {p} ==")
        # `-p <project> down` needs no -f chain, so teardown works even if the tier was forgotten.
        compose.run([], "-p", p, "down", check=False)
    print("range down: all meridian-range stacks removed on this host.")
    print("If a Traefik router config was in play, remove it too, and revert any lab DNS record.")
    return 0


def cmd_status(_args) -> int:
    projects = compose.running_projects()
    if not projects:
        print("range status: nothing deployed here (no meridian-range compose project is running).")
        return 0
    print("range status: deployed here:")
    for p in projects:
        print(f"  project {p}")
        # `docker ps` rather than `compose ps`: it needs no -f chain, so status works even when the
        # operator does not remember which tier is up, and its --format template is stable across
        # compose versions.
        subprocess.run(
            ["docker", "ps", "--filter", f"label=com.docker.compose.project={p}", "--format",
             "    {{.Names}}  {{.Status}}  {{if .Ports}}{{.Ports}}{{else}}(no published port){{end}}"],
            check=False,
        )
    print("\nTear down with: ./range down")
    return 0

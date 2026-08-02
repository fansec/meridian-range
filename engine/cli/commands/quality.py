"""typecheck / lint / list - the remaining offline [dev] checks.

typecheck covers EVERY TypeScript project, not just the harness. Two of the three used to define a
`typecheck` script that nothing ever invoked, so the vulnerable server and the collector were never
type-checked in CI at all.
"""
from __future__ import annotations

import subprocess

import catalog as cat

TS_PROJECTS = ["engine/harness", "servers/ts-vuln", "engine/attacker/collector"]


def _npm(project: str, *args: str) -> int:
    path = cat.REPO / project
    if not (path / "node_modules").exists():
        print(f"[{project}] installing dependencies")
        rc = subprocess.run(["npm", "ci"], cwd=path).returncode
        if rc != 0:
            return rc
    return subprocess.run(["npx", *args], cwd=path).returncode


def cmd_typecheck(_args) -> int:
    failed = []
    for project in TS_PROJECTS:
        print(f"== typecheck {project} ==")
        if _npm(project, "tsc", "--noEmit") != 0:
            failed.append(project)
    if failed:
        print(f"\nrange typecheck: FAIL ({', '.join(failed)})")
        return 1
    print(f"\nrange typecheck: OK ({len(TS_PROJECTS)} project(s))")
    return 0


def cmd_lint(_args) -> int:
    rc = 0
    print("== eslint ==")
    rc |= subprocess.run(
        ["npx", "eslint", "--config", "config/eslint.config.mjs", "."], cwd=cat.REPO
    ).returncode
    print("== ruff ==")
    rc |= subprocess.run(
        ["ruff", "check", "--config", "config/ruff.toml", "engine/cli"], cwd=cat.REPO
    ).returncode
    print("== prettier ==")
    rc |= subprocess.run(
        ["npx", "prettier", "--check", "--config", "config/.prettierrc.json",
         "--ignore-path", "config/.prettierignore", "**/*.ts"],
        cwd=cat.REPO,
    ).returncode
    print(f"\nrange lint: {'OK' if rc == 0 else 'FAIL'}")
    return 1 if rc else 0


def cmd_list(_args) -> int:
    mods = cat.all_modules()
    if not mods:
        print("no modules found under modules/")
        return 0
    print(f"{'id':<4} {'module':<26} {'status':<12} {'transport':<16} {'tiers'}")
    print("-" * 88)
    for m in mods:
        print(f"{str(m.get('id')):<4} {m['_dir']:<26} {str(m.get('status')):<12} "
              f"{str(m.get('transport')):<16} {' '.join(cat.tiers(m))}")
    return 0

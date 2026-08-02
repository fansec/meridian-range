"""Build the `docker compose` invocation for a module + tier, in one place.

Three commands used to derive the same -f chain independently (the deploy script, the runner, and the
CI workflow, which re-implemented the overlay-versus-standalone test in bash). They now all come
through here, so the rule that decides how a stack is assembled exists exactly once.

Relative paths inside every compose file resolve against the PROJECT DIRECTORY, which is always the
repo root. That is why --project-directory is passed unconditionally.
"""
from __future__ import annotations

import os
import subprocess
import sys

import catalog as cat

DEFAULT_PROJECT = "meridian-range"
HARNESS_IMAGE = "meridian-range/harness:local"

# Which deploy fragment a tier + side needs. `sealed` needs none: it IS the base plus the module.
TIER_FRAGMENT = {
    "sealed": None,
    "single-host": "single-host",
    "split-host": None,  # resolved from the side
}


def fragment_key(tier: str, side: str) -> str | None:
    if tier == "single-host":
        return "single-host"
    if tier == "split-host":
        return side
    return None


def stack(m: dict, tier: str = "sealed", side: str = "victim") -> tuple[list[str], str, list[str]]:
    """Return (compose args, project name, service list) for this module at this tier."""
    key = fragment_key(tier, side)
    frag = cat.deploy_fragment(m, key) if key else None

    args = ["--project-directory", str(cat.REPO)]
    project = DEFAULT_PROJECT

    if frag is not None and cat.is_standalone(frag):
        # A standalone fragment runs on a host that carries no sealed base lab, so it stands alone.
        args += ["-f", str(frag)]
        project = _declared_name(frag) or DEFAULT_PROJECT
    else:
        args += ["-f", str(cat.REPO / cat.BASE_COMPOSE), "-f", str(cat.compose_path(m))]
        if frag is not None:
            args += ["-f", str(frag)]

    return args, project, _services(m, tier, side, standalone=frag is not None and cat.is_standalone(frag))


def _declared_name(fragment) -> str | None:
    for line in fragment.read_text(encoding="utf-8").splitlines():
        if line.startswith("name:"):
            return line.split(":", 1)[1].strip()
    return None


def _services(m: dict, tier: str, side: str, standalone: bool) -> list[str]:
    """
    Derived from the module's declared roles so a host never starts the other side's services just
    because a merged file also defines them. A standalone fragment describes exactly one side
    already, so all of it starts.
    """
    if tier == "sealed" or standalone:
        return []
    roles = cat.roles(m)
    if tier == "single-host":
        return sorted({str(r["service"]) for r in roles if r.get("service")})
    if tier == "split-host":
        return sorted({str(r["service"]) for r in roles if r.get("side") == side and r.get("service")})
    return []


def running_projects() -> list[str]:
    """Every meridian compose project currently up on this host. Docker is the source of truth."""
    out = subprocess.run(
        ["docker", "ps", "--filter", "label=com.docker.compose.project",
         "--format", '{{.Label "com.docker.compose.project"}}'],
        capture_output=True, text=True,
    ).stdout
    return sorted({p for p in out.split() if p.startswith(DEFAULT_PROJECT)})


def forwarded_env() -> dict[str, str]:
    """
    Ad-hoc overrides an operator exported before the command. This replaces the old hand-maintained
    allowlist of bare keys in the compose file, which silently dropped any variable nobody remembered
    to add there.
    """
    return {
        k: v
        for k, v in os.environ.items()
        if k.startswith(("LAB_", "MCP_", "MERIDIAN_")) and k != "MERIDIAN_ON_VM"
    }


def run(args: list[str], *rest: str, env: dict[str, str] | None = None, capture: bool = False,
        check: bool = True) -> subprocess.CompletedProcess:
    cmd = ["docker", "compose", *args, *rest]
    merged = {**os.environ, **(env or {})}
    if capture:
        proc = subprocess.run(cmd, cwd=cat.REPO, env=merged, capture_output=True, text=True)
    else:
        proc = subprocess.run(cmd, cwd=cat.REPO, env=merged)
    if check and proc.returncode != 0:
        if capture:
            sys.stderr.write(proc.stdout or "")
            sys.stderr.write(proc.stderr or "")
        raise SystemExit(proc.returncode)
    return proc


def describe(cmd_args: list[str], rest: list[str]) -> str:
    return "docker compose " + " ".join(cmd_args + rest)

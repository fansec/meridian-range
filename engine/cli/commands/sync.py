"""sync - move code to the lab VM, and evidence back.

The authoring host writes code; the VM runs it. That split only works if the VM is never left behind,
so this is a one-command round trip:

  range sync                      push the repo to the VM mirror
  range sync --build 01           push, then rebuild that module's server there
  range sync --pull-evidence      bring the captures the harness wrote on the VM back here to commit

The pull direction is what makes harness-written evidence usable: `range verify` writes the capture
into the module directory on the VM, and it has to reach the authoring host before it can be
committed. Nothing else in the loop crosses that boundary.
"""
from __future__ import annotations

import os
import subprocess

import catalog as cat

DEFAULT_REMOTE_PATH = "~/meridian-range/"
EXCLUDES = ["node_modules", ".git", "dist", "__pycache__", ".env", "ops"]


def _remote() -> str:
    host = os.environ.get("LAB_VM")
    if not host:
        raise SystemExit(
            "REFUSING: LAB_VM is not set. Point it at the lab VM, e.g.\n"
            "    export LAB_VM=ai@192.0.2.10\n"
            "It is deliberately not committed: the repo names no real lab address."
        )
    return host


def _path() -> str:
    return os.environ.get("LAB_VM_PATH", DEFAULT_REMOTE_PATH)


def cmd_sync(args) -> int:
    remote, path = _remote(), _path()

    if args.pull_evidence:
        # Pull only the evidence directories; never let the VM overwrite authored code.
        src = f"{remote}:{path.rstrip('/')}/modules/"
        cmd = ["rsync", "-av", "--include=*/", "--include=evidence/***", "--exclude=*",
               src, str(cat.MODULES) + "/"]
        print(" ".join(cmd))
        rc = subprocess.run(cmd).returncode
        if rc == 0:
            print("\nrange sync: evidence pulled. Review the captures, then commit them:")
            print("    git add modules/*/evidence && git status")
        return rc

    cmd = ["rsync", "-a", "--delete"]
    for e in EXCLUDES:
        cmd += ["--exclude", e]
    cmd += [str(cat.REPO) + "/", f"{remote}:{path}"]
    print(" ".join(cmd))
    rc = subprocess.run(cmd).returncode
    if rc != 0:
        return rc
    print(f"range sync: pushed to {remote}:{path}")

    if args.build:
        m = cat.require(args.build)
        service = m.get("server_service")
        remote_cmd = (
            f"cd {path} && MERIDIAN_ON_VM=1 docker compose --project-directory . "
            f"-f {cat.BASE_COMPOSE} -f {cat.rel(m, 'compose.yml')} build {service}"
        )
        print(f"\n== rebuilding {service} on {remote} ==")
        rc = subprocess.run(["ssh", remote, remote_cmd]).returncode
        if rc != 0:
            return rc
        print(f"range sync: rebuilt {service} on the VM.")

    print("\nA change is done only once the VM runs it. Next, on the VM:")
    print("    ./range up <module> && ./range verify <module>")
    return 0

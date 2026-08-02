"""Host guards: which machine is allowed to run which command.

The old guard refused a single literal hostname (`dev`) and let everything else through, so the
safety boundary the whole project rests on held only on one specific workstation and failed OPEN
everywhere else. This one is inverted: a [VM] command runs only where the lab VM has been positively
identified, and refuses by default. Fail closed (SECURITY.md rule 6).

A host declares itself the lab VM in either of two ways:
  * /etc/meridian-vm exists            (persistent, survives a reboot, the recommended marker)
  * MERIDIAN_ON_VM=1 in the environment (per-command escape hatch)
"""
from __future__ import annotations

import os
import pathlib
import socket
import sys

VM_MARKER = pathlib.Path("/etc/meridian-vm")


def _hostname() -> str:
    try:
        return socket.gethostname()
    except OSError:
        return "unknown"


def on_vm() -> bool:
    return os.environ.get("MERIDIAN_ON_VM") == "1" or VM_MARKER.exists()


def refuse(*lines: str) -> None:
    for line in lines:
        print(line, file=sys.stderr)
    raise SystemExit(3)


def require_vm(what: str) -> None:
    """Every capability-bearing action: servers, scenarios, the harness (SECURITY.md rule 1)."""
    if on_vm():
        return
    refuse(
        f"REFUSING: `{what}` runs only on the isolated lab VM, and this host ({_hostname()}) has not",
        "identified itself as one. Nothing capability-bearing runs on the authoring host, ever.",
        "",
        "If you ARE on the lab VM, mark it once and permanently:",
        "    sudo touch /etc/meridian-vm",
        "or set MERIDIAN_ON_VM=1 for a single command.",
    )


def require_attacker_host(what: str) -> None:
    """
    The attacker side of a split-host test runs on the sanctioned attacker host (SECURITY.md rule
    1a): attacker infra only, never anything with an exec/file/network tool. That host cannot be
    detected by name, so this is an explicit acknowledgement. We can still refuse the one host it is
    definitely not, the lab VM, which hosts the victim side.
    """
    if on_vm():
        refuse(
            f"REFUSING: this host is the lab VM, which hosts the VICTIM side of `{what}`.",
            "The attacker side belongs on the sanctioned attacker host (SECURITY.md rule 1a).",
        )
    if os.environ.get("MERIDIAN_ATTACKER_HOST") != "1":
        refuse(
            f"REFUSING: `{what}` must run on the sanctioned attacker host (SECURITY.md rule 1a):",
            "  a machine on the SAME isolated lab LAN as the VM, running attacker infra ONLY",
            "  (a static page and an exfil sink; nothing with an exec/file/network tool).",
            "",
            "If you are on it, acknowledge with MERIDIAN_ATTACKER_HOST=1.",
        )

"""run / verify - reproduce a module, and gate it.

`run` is the interactive form. `verify` is the definition-of-done gate: it asserts ATTACK-OK and asks
the harness to write the module's evidence capture, so evidence is a product of the run rather than
something an operator pastes in afterwards and then edits.
"""
from __future__ import annotations

import catalog as cat
import compose
import hosts

ATTACK_OK = "ATTACK-OK"


def _env_flags(extra: dict[str, str]) -> list[str]:
    """Forward overrides into the ephemeral harness container as -e flags."""
    out: list[str] = []
    for k, v in {**compose.forwarded_env(), **extra}.items():
        out += ["-e", f"{k}={v}"]
    return out


def _invoke(m: dict, extra_env: dict[str, str], capture: bool):
    cargs, _project, _svcs = compose.stack(m, "sealed", "victim")
    return compose.run(
        cargs,
        "run", "--rm", "--build", *_env_flags(extra_env), "harness", m["_dir"],
        capture=capture, check=False,
    )


def cmd_run(args) -> int:
    m = cat.require(args.module)
    hosts.require_vm(f"range run {m['id']}")
    proc = _invoke(m, {}, capture=False)
    return proc.returncode


def cmd_verify(args) -> int:
    m = cat.require(args.module)
    hosts.require_vm(f"range verify {m['id']}")

    proc = _invoke(m, {"MERIDIAN_WRITE_EVIDENCE": "1", "MERIDIAN_VARIANT": args.variant}, capture=True)
    output = (proc.stdout or "") + (proc.stderr or "")
    print(output, end="")

    if proc.returncode != 0:
        print(f"\nrange verify: FAIL (harness exited {proc.returncode})")
        return 1
    if ATTACK_OK not in output:
        print(f"\nrange verify: FAIL - module {m['id']} did not reproduce (no {ATTACK_OK} in the run).")
        return 1

    print(f"\nrange verify: OK - module {m['id']} ({m['slug']}) reproduced [{ATTACK_OK}].")
    print(f"Evidence written on this host under {cat.rel(m, 'evidence')}/{args.variant}.txt")
    print("Bring it back to the authoring host with:  ./range sync --pull-evidence")
    print(f"Then set `verified:` in {cat.rel(m, 'module.yml')} and commit.")
    return 0

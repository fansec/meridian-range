"""matrix - reproduce a module against every version (or mitigation flag) it declares.

This is the thing the range is uniquely able to say. A single reproduction proves an attack exists;
the matrix answers the question a defender actually asks, which is "does it still work on the release
I am running, and does the fix I was told about actually stop it?" Every cell is a real run against a
real build, not a reading of a changelog.

A module declares the axis in its module.yml:

  matrix:
    build_arg: MCP_SDK_VERSION        # or env_var: ENABLE_DNS_REBIND_PROTECTION
    versions:
      - { version: "1.0.0", expect: "reproduce" }
      - { version: "1.0.1", expect: "no-repro" }

Both knobs are read the same way, as an environment variable the module's compose.yml interpolates
into either a build arg or the service environment, so this command needs no per-module special case.

[VM] only: it builds and runs the victim server.
"""
from __future__ import annotations

import catalog as cat
import compose
import hosts

ATTACK_OK = "ATTACK-OK"


def axis(m: dict) -> tuple[str, list[dict]]:
    spec = m.get("matrix") or {}
    key = spec.get("build_arg") or spec.get("env_var")
    rows = [r for r in (spec.get("versions") or []) if isinstance(r, dict)]
    if not key or not rows:
        raise SystemExit(
            f"module {m['id']} declares no usable `matrix:` block "
            f"(needs build_arg or env_var, plus a non-empty versions list)."
        )
    return str(key), rows


def cmd_matrix(args) -> int:
    m = cat.require(args.module)
    hosts.require_vm(f"range matrix {m['id']}")
    key, rows = axis(m)
    service = m.get("server_service")
    cargs, _project, _svcs = compose.stack(m, "sealed", "victim")

    results: list[tuple[str, str, bool, bool]] = []   # version, expect, reproduced, matches
    for row in rows:
        version = str(row.get("version"))
        expect = str(row.get("expect", "reproduce"))
        env = {key: version}
        print(f"\n=== {key}={version}  (expect {expect}) " + "=" * 30)

        # Recreate just the victim service at this version, then reproduce against it.
        compose.run(cargs, "up", "-d", "--build", "--force-recreate", service, env=env, check=False)
        variant = f"matrix-{version}".replace("/", "-")
        proc = compose.run(
            cargs, "run", "--rm", "--build",
            "-e", f"MERIDIAN_VARIANT={variant}",
            "-e", "MERIDIAN_WRITE_EVIDENCE=" + ("1" if args.evidence else "0"),
            "harness", m["_dir"],
            env=env, capture=True, check=False,
        )
        out = (proc.stdout or "") + (proc.stderr or "")
        if args.verbose:
            print(out, end="")
        reproduced = ATTACK_OK in out
        matches = reproduced == (expect == "reproduce")
        results.append((version, expect, reproduced, matches))
        print(f"  -> {'REPRODUCED' if reproduced else 'no repro'}  ({'as expected' if matches else 'UNEXPECTED'})")

    print(f"\n{m['id']} {m['name']} - {key}")
    print(f"| {key:<28} | expected   | observed   | agrees |")
    print(f"|{'-' * 30}|------------|------------|--------|")
    for version, expect, reproduced, matches in results:
        obs = "reproduce" if reproduced else "no-repro"
        print(f"| {version:<28} | {expect:<10} | {obs:<10} | {'yes' if matches else 'NO':<6} |")

    disagreements = [r for r in results if not r[3]]
    if disagreements:
        print(f"\nrange matrix: FAIL - {len(disagreements)} cell(s) disagree with module.yml.")
        print("Either the declared expectation is wrong, or the mitigation does not behave as documented.")
        print("Both are findings. Do not silently edit the expectation to match.")
        return 1
    print("\nrange matrix: OK - every cell matched the declared expectation.")
    return 0

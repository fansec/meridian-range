"""probe - run a module's READ-ONLY checks against a target you own.

This is the one command that points outward, so it is the one with the most guards. What makes it
safe is structural rather than procedural: a probe runs `scenario.probe()`, a code path that is
separate from `scenario.run()` and in which the context refuses capability invocation outright
(requireExec() throws, exfil is a no-op, evidence writing is off). A probe can observe that a server
answers a foreign Origin with a wildcard ACAO; it cannot ask that server to run anything.

On top of that:
  * --i-am-authorized is mandatory, and is a statement about the TARGET, not about this machine.
  * A target that resolves outside private/loopback space is refused unless the operator also sets
    MERIDIAN_PROBE_ALLOW_PUBLIC=1, which exists so the refusal is a deliberate override and not a
    forgotten flag.
  * It runs on the lab VM like everything else, so on an isolated lab LAN the only things reachable
    are lab things.

See SECURITY.md "Probe mode".
"""
from __future__ import annotations

import ipaddress
import os
import socket
import subprocess
from urllib.parse import urlparse

import catalog as cat
import compose
import hosts


def _resolved_addresses(host: str) -> list[str]:
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror as e:
        raise SystemExit(f"REFUSING: cannot resolve target host `{host}`: {e}") from e
    return sorted({i[4][0] for i in infos})


def _assert_target_allowed(url: str) -> None:
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise SystemExit(f"REFUSING: --target must be an http(s) URL with a host (got `{url}`)")

    addresses = _resolved_addresses(parsed.hostname)
    public = []
    for a in addresses:
        try:
            ip = ipaddress.ip_address(a)
        except ValueError:
            continue
        if not (ip.is_private or ip.is_loopback or ip.is_link_local):
            public.append(a)

    if public and os.environ.get("MERIDIAN_PROBE_ALLOW_PUBLIC") != "1":
        raise SystemExit(
            f"REFUSING: `{parsed.hostname}` resolves to non-private address(es): {', '.join(public)}.\n"
            "This range is for assets on an isolated lab network. If you genuinely own that host and\n"
            "are authorised to test it, set MERIDIAN_PROBE_ALLOW_PUBLIC=1 to override deliberately."
        )


def _lab_env_defaults(m: dict) -> dict[str, str]:
    """
    The module's own sealed-tier knobs, as DEFAULTS for a probe.

    `range run` gets these because the module's compose.yml loads lab.env into the harness service.
    A probe bypasses compose (it runs the harness image directly, since its target is by definition
    outside labnet), so without this it inherited none of them and `--origin`'s documented default,
    "the module's own", silently did not exist. Only the dressing is taken: the target comes from
    --target, and the collector URL is deliberately left out because a probe never exfiltrates.
    """
    wanted = ("MCP_SSE_PATH", "MCP_MESSAGE_PATH", "LAB_EVIL_ORIGIN", "LAB_REBIND_HOST")
    path = cat.mod_dir(m) / cat.LAB_ENV
    out: dict[str, str] = {}
    if not path.exists():
        return out
    for raw in path.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key, value = key.strip(), value.strip()
        if key in wanted and value:
            out[key] = value
    return out


def _normalise_target(url: str, m: dict, sse_path: str) -> str:
    """
    For an http+sse module the target is the server BASE url, because the transport appends the
    module's sse path to it. Passing the endpoint you can see in a browser is the obvious mistake,
    and it used to produce a request for <base>/mcp/sse/mcp/sse: a 404, no ACAO, no session, and a
    confident `0/2 vulnerable conditions observed` about a server that was wide open.
    """
    if m.get("transport") != "http+sse":
        return url
    parsed = urlparse(url)
    suffix = "/" + sse_path.strip("/")
    if parsed.path.rstrip("/").endswith(suffix):
        trimmed = parsed.path.rstrip("/")[: -len(suffix)]
        fixed = parsed._replace(path=trimmed).geturl()
        print(
            f"note: --target for an http+sse module is the server BASE url ({sse_path} is appended).\n"
            f"      Using {fixed or '/'} instead of {url}."
        )
        return fixed
    return url


def cmd_probe(args) -> int:
    m = cat.require(args.module)
    if not args.i_am_authorized:
        raise SystemExit(
            "REFUSING: `range probe` needs --i-am-authorized.\n"
            "That flag is a statement about the TARGET: you own it, or you hold written permission to\n"
            "test it. Pointing this at anything else is out of scope for this project (SECURITY.md)."
        )
    _assert_target_allowed(args.target)
    hosts.require_vm(f"range probe {m['id']}")

    checks = [c.get("id") for c in ((m.get("probe") or {}).get("safe_checks") or [])]
    if not checks:
        raise SystemExit(f"module {m['id']} declares no probe.safe_checks in its module.yml")

    defaults = _lab_env_defaults(m)
    target = _normalise_target(args.target, m, defaults.get("MCP_SSE_PATH", "/mcp/sse"))
    origin = args.origin or defaults.get("LAB_EVIL_ORIGIN")

    print(f"probe: module {m['id']} ({m['slug']}) against {target}")
    print(f"       read-only checks: {', '.join(str(c) for c in checks)}")
    print(f"       presenting Origin: {origin or '(none)'}")
    print("       no capability tool will be invoked and nothing will be executed on the target.\n")

    # Build the harness image through compose (one definition of how it is built), then run that exact
    # image outside the sealed project: a probe targets something that is by definition not inside
    # labnet, and labnet is internal:true with no route out.
    cargs, _project, _svcs = compose.stack(m, "sealed", "victim")
    compose.run(cargs, "build", "harness")

    env = dict(defaults)
    env.update(
        {
            "MCP_TARGET_URL": target,
            "MERIDIAN_READ_ONLY": "1",
            "MERIDIAN_WRITE_EVIDENCE": "0",
        }
    )
    if args.origin:
        env["LAB_EVIL_ORIGIN"] = args.origin
    if args.host_header:
        env["LAB_REBIND_HOST"] = args.host_header

    cmd = ["docker", "run", "--rm", "--network", "host"]
    for k, v in env.items():
        cmd += ["-e", f"{k}={v}"]
    cmd += ["-v", f"{cat.MODULES}:/app/modules:ro", compose.HARNESS_IMAGE, m["_dir"], "--probe"]

    proc = subprocess.run(cmd, cwd=cat.REPO)
    return proc.returncode

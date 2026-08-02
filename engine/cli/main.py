"""range - the single entry point for the Meridian Range.

This replaced a bin/ directory of eleven shell scripts, five of which were three-line `exec python3`
shims, and one of which did not source the shared library and so re-implemented the repo-root lookup,
the module resolver and its own help parser. One dispatcher means one place where a rule lives.

Commands are marked by where they may run:

  [dev]  offline, starts nothing, safe on the authoring host
  [VM]   builds or runs something capability-bearing, so the lab VM only (SECURITY.md rule 1)
"""
from __future__ import annotations

import argparse
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent / "commands"))

import check as check_cmd            # noqa: E402
import deploy as deploy_cmd          # noqa: E402
import detect_test as detect_cmd     # noqa: E402
import export as export_cmd          # noqa: E402
import matrix as matrix_cmd          # noqa: E402
import newmod as new_cmd             # noqa: E402
import probe as probe_cmd            # noqa: E402
import quality as quality_cmd        # noqa: E402
import render as render_cmd          # noqa: E402
import run as run_cmd                # noqa: E402
import style as style_cmd            # noqa: E402
import sync as sync_cmd              # noqa: E402
import traefik as traefik_cmd        # noqa: E402


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="range",
        description="Meridian Range control. [dev] commands are offline; [VM] commands run on the lab VM only.",
    )
    sub = p.add_subparsers(dest="command", required=True)

    def add(name: str, help_text: str):
        return sub.add_parser(name, help=help_text, description=help_text)

    # ---- deployment -----------------------------------------------------------------------------
    for name, help_text in (
        ("plan", "[dev] print the deployment command for a tier; start nothing"),
        ("up", "[VM] deploy one module at one tier"),
    ):
        sp = add(name, help_text)
        sp.add_argument("module", help="module id (01) or directory name")
        sp.add_argument("--tier", default="sealed", choices=deploy_cmd.TIERS)
        sp.add_argument("--side", default="victim", choices=deploy_cmd.SIDES)
        sp.set_defaults(fn=deploy_cmd.cmd_plan if name == "plan" else deploy_cmd.cmd_up)

    add("down", "[VM] tear down every lab stack on this host").set_defaults(fn=deploy_cmd.cmd_down)
    add("status", "[VM] show what is deployed here").set_defaults(fn=deploy_cmd.cmd_status)

    # ---- reproduce ------------------------------------------------------------------------------
    sp = add("run", "[VM] reproduce a module (prints ATTACK-OK / NO-REPRO)")
    sp.add_argument("module")
    sp.set_defaults(fn=run_cmd.cmd_run)

    sp = add("verify", "[VM] the definition-of-done gate: assert ATTACK-OK and write the evidence capture")
    sp.add_argument("module")
    sp.add_argument("--variant", default="vuln", help="evidence file name (default: vuln)")
    sp.set_defaults(fn=run_cmd.cmd_verify)

    sp = add("matrix", "[VM] reproduce against every version / mitigation flag the module declares")
    sp.add_argument("module")
    sp.add_argument("--evidence", action="store_true", help="write a capture per matrix row")
    sp.add_argument("--verbose", action="store_true", help="stream each run's full output")
    sp.set_defaults(fn=matrix_cmd.cmd_matrix)

    sp = add("probe", "[VM] run a module's READ-ONLY checks against a target you own")
    sp.add_argument("module")
    sp.add_argument(
        "--target",
        required=True,
        help="http(s) URL to observe: the server BASE url for an http+sse module (its sse path is "
        "appended), the full endpoint for a streamable-http one",
    )
    sp.add_argument("--origin", help="Origin header to present (default: the module's own)")
    sp.add_argument("--host-header", dest="host_header", help="Host header to present")
    sp.add_argument("--i-am-authorized", dest="i_am_authorized", action="store_true",
                    help="required: you own this target or hold written permission to test it")
    sp.set_defaults(fn=probe_cmd.cmd_probe)

    # ---- authoring ------------------------------------------------------------------------------
    sp = add("new", "[dev] scaffold a new module directory from the template")
    sp.add_argument("id", help="two-digit module id, e.g. 03")
    sp.add_argument("slug", help="kebab-case slug, e.g. tool-poisoning")
    sp.add_argument("--name", help="human-readable module name")
    sp.set_defaults(fn=new_cmd.cmd_new)

    add("check", "[dev] validate every module: manifest, structure, topology, detections, safety gates") \
        .set_defaults(fn=check_cmd.cmd_check)

    sp = add("render", "[dev] regenerate the module-derived tables")
    sp.add_argument("--check", action="store_true", help="fail on drift instead of writing")
    sp.set_defaults(fn=render_cmd.cmd_render)

    sp = add("detect-test", "[dev] evaluate ATR rules against their embedded test cases")
    sp.add_argument("module", nargs="?", help="limit to one module")
    sp.set_defaults(fn=detect_cmd.cmd_detect_test)

    sp = add("export", "[dev] export the detections as a portable pack")
    sp.add_argument("--format", default="sigma", choices=["sigma", "elastic"])
    sp.add_argument("--module", help="limit to one module")
    sp.add_argument("--out", help="write into this directory instead of stdout")
    sp.set_defaults(fn=export_cmd.cmd_export)

    sp = add("traefik", "[dev] emit role-named Traefik routers for a module")
    sp.add_argument("module")
    sp.set_defaults(fn=traefik_cmd.cmd_traefik)

    # ---- quality gates --------------------------------------------------------------------------
    add("style", "[dev] enforce the no-em-dash writing rule").set_defaults(fn=style_cmd.cmd_style)
    add("typecheck", "[dev] type-check every TypeScript project").set_defaults(fn=quality_cmd.cmd_typecheck)
    add("lint", "[dev] eslint, ruff and prettier").set_defaults(fn=quality_cmd.cmd_lint)
    add("list", "[dev] list every module").set_defaults(fn=quality_cmd.cmd_list)

    # ---- the dev/VM boundary --------------------------------------------------------------------
    sp = add("sync", "[dev] push code to the lab VM, or pull evidence back")
    sp.add_argument("--build", help="after pushing, rebuild this module's server on the VM")
    sp.add_argument("--pull-evidence", dest="pull_evidence", action="store_true",
                    help="copy the captures the harness wrote on the VM back to this host")
    sp.set_defaults(fn=sync_cmd.cmd_sync)

    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())

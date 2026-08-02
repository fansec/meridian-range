"""Module discovery for the Meridian Range CLI.

There is no central catalog file any more. A module IS a directory under modules/ containing a
module.yml, so the catalog is a glob: adding a module adds a directory and changes nothing else.
Everything inside a module is found by CONVENTION rather than declared as a path, which removes the
whole class of "the row points at a file that moved" errors.

Runs on the authoring host; needs no VM and starts nothing. PyYAML is the only third-party dep.
"""
from __future__ import annotations

import pathlib

import yaml

REPO = pathlib.Path(__file__).resolve().parents[2]
MODULES = REPO / "modules"

# Everything a module owns, relative to its own directory.
MANIFEST = "module.yml"
SCENARIO = "scenario.ts"
COMPOSE = "compose.yml"
LAB_ENV = "lab.env"
DEPLOY_DIR = "deploy"
DETECTION_DIR = "detection"
EVIDENCE_DIR = "evidence"
READ_ME = "README.md"

# The sealed base every module is merged on top of.
BASE_COMPOSE = "engine/compose.yml"


def module_dirs() -> list[str]:
    """Directory names of every module on disk, in id order. `_template` is not a module."""
    if not MODULES.is_dir():
        return []
    out = [
        p.name
        for p in MODULES.iterdir()
        if p.is_dir() and not p.name.startswith("_") and (p / MANIFEST).exists()
    ]
    return sorted(out)


def load(dirname: str) -> dict:
    """Parse one module.yml, tagging it with the directory it came from."""
    path = MODULES / dirname / MANIFEST
    with open(path, "r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}
    data["_dir"] = dirname
    return data


def all_modules() -> list[dict]:
    mods = [load(d) for d in module_dirs()]
    return sorted(mods, key=lambda m: str(m.get("id", "")))


def find(id_or_dir: str) -> dict | None:
    """Accept the directory name or just the id, which is what an operator types."""
    for m in all_modules():
        if m["_dir"] == id_or_dir or str(m.get("id")) == str(id_or_dir):
            return m
    return None


def require(id_or_dir: str) -> dict:
    m = find(id_or_dir)
    if m is None:
        known = ", ".join(f"{x.get('id')} ({x['_dir']})" for x in all_modules()) or "(none)"
        raise SystemExit(f"unknown module `{id_or_dir}`. Known: {known}")
    return m


# ---- conventional paths inside a module ----------------------------------------------------------

def mod_dir(m: dict) -> pathlib.Path:
    return MODULES / m["_dir"]


def rel(m: dict, *parts: str) -> str:
    """A repo-relative path inside the module, which is what compose and the docs want."""
    return str(pathlib.PurePosixPath("modules", m["_dir"], *parts))


def scenario_path(m: dict) -> pathlib.Path:
    return mod_dir(m) / SCENARIO


def compose_path(m: dict) -> pathlib.Path:
    return mod_dir(m) / COMPOSE


def lab_env_path(m: dict) -> pathlib.Path:
    return mod_dir(m) / LAB_ENV


def evidence_dir(m: dict) -> pathlib.Path:
    return mod_dir(m) / EVIDENCE_DIR


def readme_path(m: dict) -> pathlib.Path:
    return mod_dir(m) / READ_ME


def atr_files(m: dict) -> list[pathlib.Path]:
    d = mod_dir(m) / DETECTION_DIR
    return sorted(d.glob("*.yaml")) if d.is_dir() else []


def elastic_doc(m: dict) -> pathlib.Path:
    return mod_dir(m) / DETECTION_DIR / "elastic.md"


def deploy_fragment(m: dict, key: str) -> pathlib.Path:
    """key is a tier (`single-host`) or a side (`victim` / `attacker`)."""
    return mod_dir(m) / DEPLOY_DIR / f"{key}.yml"


def tiers(m: dict) -> list[str]:
    return list((m.get("topology") or {}).get("tiers") or [])


def roles(m: dict) -> list[dict]:
    return [r for r in ((m.get("topology") or {}).get("roles") or []) if isinstance(r, dict)]


def is_standalone(fragment: pathlib.Path) -> bool:
    """A fragment declaring its own `name:` is a standalone project, not an overlay of the base."""
    if not fragment.exists():
        return False
    for line in fragment.read_text(encoding="utf-8").splitlines():
        if line.startswith("name:"):
            return True
    return False


def anchor_cve(m: dict) -> dict | None:
    cves = m.get("cve") or []
    for c in cves:
        if isinstance(c, dict) and (c.get("role") or "anchor") == "anchor":
            return c
    return cves[0] if cves and isinstance(cves[0], dict) else None

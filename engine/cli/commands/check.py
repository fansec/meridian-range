"""check - validate every module against the structure, offline.

This is the half of "keeping the structure" that a document cannot do. `range new` produces the
shape; this asserts it is still there, for every module, on every commit. A rule that is only written
down drifts (this repo has the scars); a rule that fails CI does not.

What it enforces:
  * manifest schema and closed vocabularies (status, transport, tier, side, role, severity)
  * the module directory contract: the conventional files exist, and exist harder for `active` ones
  * the deployment contract: declared tiers have their fragments, roles have a tier that publishes them
  * the ATR contract: schema, unique ids matching filenames, embedded test cases, framework ids that
    agree with the module manifest (the manifest is the source of truth)
  * repo safety gates: no `ports:` in any sealed compose file, no stray fragment at the repo root

Runs on the authoring host; needs no VM and starts nothing.
"""
from __future__ import annotations

import re
import sys

import yaml

import catalog as cat

REQUIRED_FIELDS = ["id", "slug", "name", "status", "track", "owasp", "cwe", "server",
                   "server_service", "transport", "topology", "description"]
STATUS_VOCAB = {"active", "coming_soon"}
TRANSPORT_VOCAB = {"http+sse", "streamable-http"}
EXPECT_VOCAB = {"reproduce", "no-repro"}

# Tiers, sides and roles are CLOSED on purpose. The role-based layout only works because public
# names and routers are reused across modules instead of growing per module, so adding a role has to
# be a deliberate edit here, not something a new module can do by itself.
TIER_VOCAB = {"sealed", "single-host", "split-host"}
SIDE_VOCAB = {"victim", "attacker"}
ROLE_VOCAB = {"mcp", "hacker", "collector", "rebind"}
TIER_FRAGMENTS = {"single-host": ["single-host"], "split-host": ["victim", "attacker"]}

ATR_REQUIRED = ["id", "title", "status", "severity", "description", "author", "date",
                "detection", "references", "test_cases"]
ATR_SEVERITY = {"low", "medium", "high", "critical"}
ATR_STATUS = {"experimental", "test", "stable"}
ATR_OPERATORS = {"exact", "regex"}
ATR_LOGIC = {"all", "any"}
ATR_CORRELATION_TYPES = {"value_count"}
ATR_TIMESPAN_RE = re.compile(r"^[1-9]\d*[smhd]$")
FULL_ATR_RE = re.compile(r"ATR-\d{4}-\d{5}")

errors: list[str] = []
warnings: list[str] = []


def err(m: str) -> None:
    errors.append(m)


def warn(m: str) -> None:
    warnings.append(m)


def _norm_ids(values) -> set:
    """Bare leading ID token from each value, dropping notes: 'CWE-1427 (verify)' -> 'CWE-1427'."""
    out = set()
    for v in values or []:
        s = str(v).strip()
        if s:
            out.add(s.split()[0])
    return out


# ---- module manifest -----------------------------------------------------------------------------

def _check_manifest(m: dict) -> None:
    label = f"module {m.get('id', '?')}"
    for f in REQUIRED_FIELDS:
        if f not in m or m[f] in (None, "", []):
            err(f"{label}: missing/empty required field `{f}`")

    if m.get("status") not in STATUS_VOCAB:
        err(f"{label}: status `{m.get('status')}` not in {sorted(STATUS_VOCAB)}")
    if m.get("transport") not in TRANSPORT_VOCAB:
        err(f"{label}: transport `{m.get('transport')}` not in {sorted(TRANSPORT_VOCAB)}")

    # The directory name IS the module identity, so it must agree with the manifest.
    expected_dir = f"{m.get('id')}-{m.get('slug')}"
    if m["_dir"] != expected_dir:
        err(f"{label}: directory `{m['_dir']}` does not match id-slug (`{expected_dir}`)")

    for c in m.get("cve", []) or []:
        if not isinstance(c, dict) or "id" not in c or "cvss" not in c:
            err(f"{label}: each cve entry needs `id` and `cvss` (got {c!r})")

    # A `matrix:` block with no rows is the template's placeholder, not a declaration; only a block
    # that actually claims versions has to say which knob varies them.
    spec = m.get("matrix") or {}
    if spec.get("versions"):
        if not (spec.get("build_arg") or spec.get("env_var")):
            err(f"{label}: matrix declares versions but neither build_arg nor env_var to vary them")
        for row in spec.get("versions") or []:
            if not isinstance(row, dict) or "version" not in row:
                err(f"{label}: each matrix row needs a `version` (got {row!r})")
            elif str(row.get("expect", "reproduce")) not in EXPECT_VOCAB:
                err(f"{label}: matrix row {row.get('version')} expect must be one of {sorted(EXPECT_VOCAB)}")


def _check_structure(m: dict) -> None:
    """The module directory contract. Convention beats configuration only if the convention holds."""
    label = f"module {m.get('id', '?')}"
    active = m.get("status") == "active"
    note = err if active else warn

    required = {
        "scenario.ts": cat.scenario_path(m),
        "compose.yml": cat.compose_path(m),
        "lab.env": cat.lab_env_path(m),
        "README.md": cat.readme_path(m),
    }
    for name, path in required.items():
        if not path.exists():
            err(f"{label}: missing {cat.rel(m, name)} (every module directory carries one)")

    if not cat.atr_files(m):
        err(f"{label}: no ATR rule under {cat.rel(m, 'detection')}/ - an exploit without a detection "
            f"is not a module here (definition of done)")
    if not cat.elastic_doc(m).exists():
        note(f"{label}: missing {cat.rel(m, 'detection', 'elastic.md')}")

    ev = cat.evidence_dir(m)
    captures = sorted(ev.glob("*.txt")) if ev.is_dir() else []
    if active and not captures:
        err(f"{label}: status is active but {cat.rel(m, 'evidence')}/ holds no capture")
    if active and not m.get("verified"):
        err(f"{label}: active module must set `verified` (the VM run date)")
    if not active and m.get("verified"):
        warn(f"{label}: `verified` is set but status is `{m.get('status')}`")

    server = m.get("server")
    if server and not (cat.REPO / str(server)).exists():
        err(f"{label}: server path does not exist: {server}")


def _check_topology(m: dict) -> None:
    label = f"module {m.get('id', '?')}"
    topo = m.get("topology")
    if not isinstance(topo, dict):
        err(f"{label}: `topology` must be a mapping (tiers / traefik / roles)")
        return
    active = m.get("status") == "active"
    note = err if active else warn

    tiers = topo.get("tiers") or []
    if not isinstance(tiers, list) or not tiers:
        err(f"{label}: topology.tiers must be a non-empty list")
        tiers = []
    bad = set(map(str, tiers)) - TIER_VOCAB
    if bad:
        err(f"{label}: unknown tier(s) {sorted(bad)}; allowed: {sorted(TIER_VOCAB)}")
    if "sealed" not in tiers:
        err(f"{label}: every module must declare the `sealed` tier - it is the definition-of-done gate "
            f"(reproduce with no ports, no DNS, labnet internal)")

    if not isinstance(topo.get("traefik"), bool):
        err(f"{label}: topology.traefik must be true or false")

    sides_used = set()
    for r in topo.get("roles") or []:
        if not isinstance(r, dict):
            err(f"{label}: each topology.roles entry must be a mapping (got {r!r})")
            continue
        for f in ("role", "side", "service", "port"):
            if r.get(f) in (None, ""):
                err(f"{label}: topology role {r!r} is missing `{f}`")
        if r.get("role") and r["role"] not in ROLE_VOCAB:
            err(f"{label}: unknown role `{r['role']}`; allowed: {sorted(ROLE_VOCAB)}. Roles are named "
                f"for what they ARE, not for a module: add one deliberately or reuse an existing name.")
        if r.get("side") and r["side"] not in SIDE_VOCAB:
            err(f"{label}: role `{r.get('role')}` has unknown side `{r['side']}`; allowed: {sorted(SIDE_VOCAB)}")
        if not isinstance(r.get("port"), int):
            err(f"{label}: role `{r.get('role')}` port must be an integer (got {r.get('port')!r})")
        sides_used.add(r.get("side"))

    if "attacker" in sides_used and not ({"single-host", "split-host"} & set(tiers)):
        err(f"{label}: declares attacker-side role(s) but no tier that publishes them "
            f"(add `single-host` or `split-host`, or drop the roles)")

    for tier in tiers:
        for key in TIER_FRAGMENTS.get(tier, []):
            frag = cat.deploy_fragment(m, key)
            if not frag.exists():
                note(f"{label}: tier `{tier}` needs {cat.rel(m, 'deploy', key + '.yml')}, which is missing")


# ---- detections ----------------------------------------------------------------------------------

def _check_atr(m: dict, seen_ids: dict[str, str]) -> None:
    label = f"module {m.get('id', '?')}"
    axes = {
        "owasp_llm": _norm_ids(m.get("owasp")),
        "owasp_asi": _norm_ids(m.get("asi")),
        "cwe": _norm_ids(m.get("cwe")),
        "cve": _norm_ids([c.get("id") for c in (m.get("cve") or []) if isinstance(c, dict)]),
    }

    for path in cat.atr_files(m):
        rel = cat.rel(m, "detection", path.name)
        try:
            doc = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        except yaml.YAMLError as e:
            err(f"{rel}: not valid YAML: {e}")
            continue

        for f in ATR_REQUIRED:
            if f not in doc or doc[f] in (None, "", []):
                err(f"{rel}: missing/empty required field `{f}`")

        match = FULL_ATR_RE.search(path.name)
        if not match:
            err(f"{rel}: filename carries no ATR-YYYY-NNNNN id")
        else:
            fid = match.group(0)
            if str(doc.get("id", "")).strip() != fid:
                err(f"{rel}: internal id `{doc.get('id')}` does not match filename id `{fid}`")
            if fid in seen_ids:
                err(f"duplicate ATR id `{fid}` in {seen_ids[fid]} and {rel}")
            else:
                seen_ids[fid] = rel

        if doc.get("status") not in ATR_STATUS:
            err(f"{rel}: status `{doc.get('status')}` not in {sorted(ATR_STATUS)}")
        if doc.get("severity") not in ATR_SEVERITY:
            err(f"{rel}: severity `{doc.get('severity')}` not in {sorted(ATR_SEVERITY)}")

        detection = doc.get("detection") or {}
        if detection.get("condition", "all") not in ATR_LOGIC:
            err(f"{rel}: detection.condition must be one of {sorted(ATR_LOGIC)}")
        conds = detection.get("conditions") or []
        if not conds:
            err(f"{rel}: detection.conditions must be a non-empty list")
        for c in conds:
            if not isinstance(c, dict):
                err(f"{rel}: each condition must be a mapping (got {c!r})")
                continue
            if c.get("operator") not in ATR_OPERATORS:
                err(f"{rel}: unsupported operator `{c.get('operator')}`; allowed: {sorted(ATR_OPERATORS)}")
            if not c.get("field"):
                err(f"{rel}: a condition is missing `field`")

        correlation = detection.get("correlation")
        if correlation is not None:
            if not isinstance(correlation, dict):
                err(f"{rel}: detection.correlation must be a mapping")
            else:
                if correlation.get("type") not in ATR_CORRELATION_TYPES:
                    err(f"{rel}: detection.correlation.type must be one of "
                        f"{sorted(ATR_CORRELATION_TYPES)}")
                group_by = correlation.get("group_by")
                if (not isinstance(group_by, list) or not group_by
                        or any(not isinstance(field, str) or not field for field in group_by)):
                    err(f"{rel}: detection.correlation.group_by must be a non-empty list of fields")
                if not isinstance(correlation.get("field"), str) or not correlation.get("field"):
                    err(f"{rel}: detection.correlation.field must name the distinct-value field")
                minimum = correlation.get("min_distinct")
                if not isinstance(minimum, int) or isinstance(minimum, bool) or minimum < 2:
                    err(f"{rel}: detection.correlation.min_distinct must be an integer of at least 2")
                within = correlation.get("within")
                if not isinstance(within, str) or not ATR_TIMESPAN_RE.fullmatch(within):
                    err(f"{rel}: detection.correlation.within must look like 5m, 1h, or 2d")

        tests = doc.get("test_cases") or {}
        if not tests.get("true_positives"):
            err(f"{rel}: test_cases.true_positives must hold at least one case - a rule with no input "
                f"it was validated against cannot be re-verified by anyone")
        if not tests.get("true_negatives"):
            err(f"{rel}: test_cases.true_negatives must hold at least one case (what must NOT fire)")
        if correlation is not None:
            for polarity in ("true_positives", "true_negatives"):
                for tc in tests.get(polarity) or []:
                    if not isinstance(tc, dict) or not isinstance(tc.get("events"), list) or not tc.get("events"):
                        err(f"{rel}: correlated {polarity} cases must each carry a non-empty `events` list")

        refs = doc.get("references", {}) or {}
        for axis, allowed in axes.items():
            extra = _norm_ids(refs.get(axis)) - allowed
            if extra:
                err(f"{label}: {rel} cites {axis} {sorted(extra)} absent from the module manifest "
                    f"(module.yml is the source of truth; add them there or fix the rule)")


# ---- repo-level safety gates ---------------------------------------------------------------------

PORTS_RE = re.compile(r"^\s*ports:\s*(#.*)?$")


def _check_repo_invariants() -> None:
    """
    The gates no single module owns.

      1. No sealed compose file may publish a port (SECURITY.md rule 2). This is the invariant most
         easily broken by a careless edit and the most trivially checkable offline.
      2. Opt-in fragments live under a module's deploy/, never at the repo root, so a bare
         `docker compose up` can never pick one up implicitly.
    """
    sealed = [cat.REPO / cat.BASE_COMPOSE] + [cat.compose_path(m) for m in cat.all_modules()]
    for path in sealed:
        if not path.exists():
            continue
        rel = path.relative_to(cat.REPO)
        for i, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if PORTS_RE.match(line):
                err(f"{rel}:{i}: a SEALED compose file must never declare `ports:` (SECURITY.md rule 2). "
                    f"Port publishing belongs in an opt-in deploy/ fragment.")

    strays = sorted(p.name for p in cat.REPO.glob("docker-compose*.yml"))
    if strays:
        err(f"compose file(s) found at the repo root: {strays}. The sealed base lives at "
            f"{cat.BASE_COMPOSE} and opt-in fragments live under modules/<NN-slug>/deploy/.")


def _next_atr_id(seen: dict[str, str]) -> None:
    if not seen:
        return
    nums = sorted(int(fid[-5:]) for fid in seen)
    year = sorted(seen)[0][4:8]
    print(f"range check: next free ATR id: ATR-{year}-{nums[-1] + 1:05d}")


def cmd_check(_args) -> int:
    mods = cat.all_modules()
    if not mods:
        err("no modules found under modules/ (each module is a directory with a module.yml)")

    seen_ids: dict[str, int] = {}
    seen_slugs: dict[str, int] = {}
    atr_ids: dict[str, str] = {}

    for m in mods:
        _check_manifest(m)
        _check_structure(m)
        _check_topology(m)
        _check_atr(m, atr_ids)
        seen_ids[str(m.get("id"))] = seen_ids.get(str(m.get("id")), 0) + 1
        if m.get("slug"):
            seen_slugs[m["slug"]] = seen_slugs.get(m["slug"], 0) + 1

    for k, n in seen_ids.items():
        if n > 1:
            err(f"duplicate module id `{k}` ({n} modules)")
    for k, n in seen_slugs.items():
        if n > 1:
            err(f"duplicate module slug `{k}` ({n} modules)")

    _check_repo_invariants()
    _next_atr_id(atr_ids)

    for w in warnings:
        print(f"WARN  {w}")
    for e in errors:
        print(f"ERROR {e}")
    n_active = sum(1 for m in mods if m.get("status") == "active")
    if errors:
        print(f"\nrange check: FAIL ({len(errors)} error(s), {len(warnings)} warning(s))")
        return 1
    print(f"range check: OK  ({len(mods)} module(s), {n_active} active, {len(warnings)} warning(s))")
    return 0


if __name__ == "__main__":
    sys.exit(cmd_check(None))

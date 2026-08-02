"""export - turn the ATR rules into a consumable detection pack.

The ATR format is the most reusable thing in this repo, and until now it was readable only by this
repo's own test runner. Exporting means the detections are useful to someone who never deploys the
range: they take the rules, not the lab.

  range export --format sigma           Sigma rules on stdout or into --out
  range export --format elastic         Elastic detection-rule NDJSON (importable as a bundle)

Sigma deliberately has no standard for test cases, which is exactly what ATR adds, so the exported
Sigma keeps them in a custom `x-meridian-tests` key rather than dropping them: a rule that ships
without the inputs it was validated against is a rule nobody can re-verify.

Exported Elastic rules are always `enabled: false` and always carry the lab host-scoping placeholder,
so an imported bundle cannot start firing against real hosts on arrival (SECURITY.md, Elastic scope).
"""
from __future__ import annotations

import json
import pathlib

import yaml

import catalog as cat

LAB_SCOPE_PLACEHOLDER = "<LAB_HOST>"


def _atr_docs(module: str | None) -> list[tuple[dict, pathlib.Path, dict]]:
    mods = [cat.require(module)] if module else cat.all_modules()
    out = []
    for m in mods:
        for path in cat.atr_files(m):
            doc = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
            out.append((m, path, doc))
    return out


def _condition_to_sigma(detection: dict) -> tuple[dict, str]:
    """
    ATR states a flat list of {field, operator, value} plus all/any. Sigma wants named selections and
    a boolean condition string, so each ATR condition becomes its own single-field selection. The
    mapping is intentionally dumb and lossless rather than clever.
    """
    logic = detection.get("condition", "all")
    conds = detection.get("conditions", []) or []
    selections: dict = {}
    names: list[str] = []
    for i, c in enumerate(conds, 1):
        field = str(c.get("field"))
        op = c.get("operator")
        value = c.get("value")
        key = f"sel{i}"
        names.append(key)
        if op == "regex":
            selections[key] = {f"{field}|re": str(value)}
        else:
            selections[key] = {field: str(value)}
    joiner = " and " if logic == "all" else " or "
    return selections, joiner.join(names) if names else "false"


def to_sigma(m: dict, doc: dict) -> dict:
    selections, condition = _condition_to_sigma(doc.get("detection", {}) or {})
    refs = doc.get("references", {}) or {}
    tags = []
    for cve in refs.get("cve", []) or []:
        tags.append(f"cve.{str(cve).lower().replace('-', '_')}")
    for cwe in refs.get("cwe", []) or []:
        tags.append(str(cwe).lower())
    for llm in refs.get("owasp_llm", []) or []:
        tags.append(f"owasp.{str(llm).lower()}")

    rule = {
        "title": doc.get("title"),
        "id": doc.get("id"),
        "status": doc.get("status", "experimental"),
        "description": (doc.get("description") or "").strip(),
        "author": doc.get("author", "Meridian Range"),
        "date": doc.get("date"),
        "references": [f"https://nvd.nist.gov/vuln/detail/{c}" for c in (refs.get("cve") or [])],
        "tags": tags,
        "logsource": {"product": "mcp", "service": str((doc.get("agent_source") or {}).get("type", "mcp"))},
        "detection": {**selections, "condition": condition},
        "falsepositives": ["Unknown"],
        "level": doc.get("severity", "medium"),
        # ATR's addition to the format: the inputs this rule was validated against.
        "x-meridian-tests": doc.get("test_cases", {}),
        "x-meridian-module": f"{m['id']}-{m['slug']}",
    }
    return rule


def to_elastic(m: dict, doc: dict) -> dict:
    selections, _condition = _condition_to_sigma(doc.get("detection", {}) or {})
    logic = (doc.get("detection", {}) or {}).get("condition", "all")
    clauses = []
    for sel in selections.values():
        for field, value in sel.items():
            if field.endswith("|re"):
                clauses.append(f'{field[:-3]} : *')     # KQL has no regex; keep it wide and reviewable
            else:
                clauses.append(f'{field} : "{value}"')
    joiner = " and " if logic == "all" else " or "
    query = joiner.join(clauses) if clauses else "*"
    # Never let an imported rule fire outside the lab.
    query = f'({query}) and host.name : "{LAB_SCOPE_PLACEHOLDER}"'

    return {
        "rule_id": str(doc.get("id", "")).lower(),
        "name": doc.get("title"),
        "description": (doc.get("description") or "").strip(),
        "type": "query",
        "language": "kuery",
        "query": query,
        "index": ["logs-*"],
        "severity": doc.get("severity", "medium"),
        "risk_score": 47,
        "enabled": False,           # authored disabled, always (SECURITY.md Elastic scope)
        "tags": ["meridian-range", f"module-{m['id']}"],
        "note": (
            f"Exported from {doc.get('id')} by `range export`. Replace {LAB_SCOPE_PLACEHOLDER} with the "
            "lab host before enabling, and never widen the scope to a shared or production host."
        ),
    }


def cmd_export(args) -> int:
    docs = _atr_docs(args.module)
    if not docs:
        print("range export: no ATR rules found.")
        return 0

    out_dir = pathlib.Path(args.out) if args.out else None
    if out_dir:
        out_dir.mkdir(parents=True, exist_ok=True)

    if args.format == "sigma":
        for m, path, doc in docs:
            rule = to_sigma(m, doc)
            text = yaml.safe_dump(rule, sort_keys=False, allow_unicode=True)
            if out_dir:
                target = out_dir / f"{path.stem}.sigma.yml"
                target.write_text(text, encoding="utf-8")
                print(f"wrote {target}")
            else:
                print(f"---\n{text}", end="")
    else:
        lines = [json.dumps(to_elastic(m, doc), separators=(",", ":")) for m, _p, doc in docs]
        text = "\n".join(lines) + "\n"
        if out_dir:
            target = out_dir / "meridian-detections.ndjson"
            target.write_text(text, encoding="utf-8")
            print(f"wrote {target}  ({len(lines)} rule(s), all enabled:false)")
        else:
            print(text, end="")

    if not out_dir:
        return 0
    print(f"range export: {len(docs)} rule(s) as {args.format}.")
    return 0

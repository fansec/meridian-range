"""render - regenerate every module-derived view.

The module manifests are the source of truth, so the human-facing tables are rendered from them and
never hand-edited. Each view carries a `<!-- BEGIN/END GENERATED: <key> -->` marker pair; only the
text between the markers is rewritten, so the surrounding prose is preserved.

  range render            write the generated blocks in place
  range render --check    verify they match the manifests (CI gate); non-zero exit on drift
"""
from __future__ import annotations

import re

import catalog as cat

OK = "✅"          # shipped and VM-verified
WIP = "\U0001f9ea"     # authored, pending VM verification
DOT = " · "       # middle dot, the house separator

LLM_NAMES = {
    "LLM01": "Prompt Injection",
    "LLM02": "Sensitive Information Disclosure",
    "LLM03": "Supply Chain",
    "LLM04": "Data and Model Poisoning",
    "LLM05": "Improper Output Handling",
    "LLM06": "Excessive Agency",
    "LLM07": "System Prompt Leakage",
    "LLM08": "Vector and Embedding Weaknesses",
    "LLM09": "Misinformation",
    "LLM10": "Unbounded Consumption",
}
MCP_NAMES = {
    "MCP01": "Token Mismanagement",
    "MCP02": "Privilege Escalation via Scope Creep",
    "MCP03": "Tool Poisoning",
    "MCP04": "Supply Chain",
    "MCP05": "Command Injection",
    "MCP06": "Intent Flow Subversion",
    "MCP07": "Insufficient AuthN/AuthZ",
    "MCP08": "Lack of Audit/Telemetry",
    "MCP09": "Shadow MCP Servers",
    "MCP10": "Context Injection and Over-Sharing",
}
ROLE_ABBR = {"anchor": "anchor", "precondition": "precond.", "companion": "companion"}


def _name_link(m: dict, prefix: str) -> str:
    return f"[{m.get('name', '?')}]({prefix}modules/{m['_dir']}/)"


def _cves(m: dict, anchors_only: bool) -> str:
    cves = [c for c in (m.get("cve") or []) if isinstance(c, dict)]
    if anchors_only:
        cves = [c for c in cves if (c.get("role") or "anchor") == "anchor"]
    if not cves:
        return "- (CWE-anchored)"
    if anchors_only:
        return DOT.join(f"{c['id']} ({c['cvss']})" for c in cves)
    parts = []
    for c in cves:
        role = c.get("role") or "anchor"
        parts.append(f"{c['id']} ({c['cvss']} {ROLE_ABBR.get(role, role)})")
    return DOT.join(parts)


def _owasp_bold(m: dict) -> str:
    return " ".join(f"**{x}**" for x in (m.get("owasp") or [])) or "-"


def _owasp_named(m: dict) -> str:
    return ", ".join(f"{x} {LLM_NAMES.get(x, '')}".strip() for x in (m.get("owasp") or [])) or "-"


def _mcp_named(m: dict) -> str:
    xs = m.get("mcp") or []
    if not xs:
        return "-"
    out = []
    for raw in xs:
        match = re.match(r"MCP\d{2}", str(raw))
        name = MCP_NAMES.get(match.group(0), "") if match else ""
        out.append(f"{raw} {name}".strip() if name else str(raw))
    return ", ".join(out)


def _repro(m: dict) -> str:
    return OK if m.get("status") == "active" else WIP


def _blog(m: dict) -> str:
    url = m.get("blog_url")
    return f"[post]({url})" if url else "_soon_"


def _row(cells: list[str]) -> str:
    return "| " + " | ".join(cells) + " |"


def render_catalog_table(mods: list[dict], prefix: str) -> str:
    lines = [
        "| # | Attack | OWASP | Anchor CVE (CVSS) | Repro | Detect | Blog |",
        "|---|--------|:-----:|-------------------|:-----:|:------:|:----:|",
    ]
    for m in mods:
        lines.append(_row([
            str(m.get("id", "?")), _name_link(m, prefix), _owasp_bold(m), _cves(m, True),
            _repro(m), OK if cat.atr_files(m) else "-", _blog(m),
        ]))
    return "\n".join(lines)


def render_owasp_matrix(mods: list[dict], _prefix: str) -> str:
    lines = [
        "| # | Attack | OWASP LLM | OWASP MCP | ASI | CWE | Anchor CVE (CVSS) | Status |",
        "|---|--------|-----------|-----------|-----|-----|-------------------|--------|",
    ]
    for m in mods:
        lines.append(_row([
            str(m.get("id", "?")), m.get("name", "?"), _owasp_named(m), _mcp_named(m),
            ", ".join(m.get("asi") or []) or "_(verify)_", ", ".join(m.get("cwe") or []) or "-",
            _cves(m, True),
            "shipped" if m.get("status") == "active" else "authored; pending VM verify",
        ]))
    return "\n".join(lines)


# relpath -> [(marker key, renderer)]. Docs live one dir deep, so their links use `../`.
TARGETS = [
    ("README.md", [("catalog-table", render_catalog_table)]),
    ("docs/owasp-mapping.md", [("owasp-matrix", render_owasp_matrix)]),
]


def splice(text: str, key: str, block: str) -> str:
    begin = re.escape(f"<!-- BEGIN GENERATED: {key}")
    end = re.escape(f"<!-- END GENERATED: {key} -->")
    pat = re.compile(rf"({begin}[^\n]*-->)\n.*?\n({end})", re.S)
    if not pat.search(text):
        raise SystemExit(f"render: BEGIN/END GENERATED markers for '{key}' not found")
    return pat.sub(lambda mm: f"{mm.group(1)}\n{block}\n{mm.group(2)}", text)


def cmd_render(args) -> int:
    mods = cat.all_modules()
    stale: list[str] = []
    for relpath, blocks in TARGETS:
        path = cat.REPO / relpath
        prefix = "./" if "/" not in relpath else "../"
        original = path.read_text(encoding="utf-8")
        updated = original
        for key, fn in blocks:
            updated = splice(updated, key, fn(mods, prefix))
        if updated == original:
            if not args.check:
                print(f"render: {relpath} up to date")
            continue
        if args.check:
            stale.append(relpath)
        else:
            path.write_text(updated, encoding="utf-8")
            print(f"render: wrote {relpath}")

    if args.check:
        if stale:
            print("range render --check: STALE - run `./range render` and commit:")
            for s in stale:
                print(f"  - {s}")
            return 1
        print("range render --check: OK (generated views match the module manifests)")
    return 0

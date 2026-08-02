"""style - enforce the writing rule: no em dashes or en dashes in authored text.

Long dashes read as AI-generated, so the house rule bans them everywhere: prose, comments, commit
messages, PR text. This scans git-tracked files, skipping vendored, generated and verbatim-capture
content, and prints file:line for every offending character.
"""
from __future__ import annotations

import subprocess

EM_DASH = chr(0x2014)  # built via chr() so this checker never flags its own source
EN_DASH = chr(0x2013)

# Skipped: lockfiles and dist (generated), evidence (verbatim program output), media (assets).
SKIP_SUFFIXES = ("package-lock.json",)
SKIP_PARTS = ("/evidence/", "/media/", "node_modules/")


def tracked_files() -> list[str]:
    out = subprocess.run(["git", "ls-files"], check=True, capture_output=True, text=True).stdout
    files = []
    for f in out.splitlines():
        if f.endswith(SKIP_SUFFIXES):
            continue
        if any(part in f"/{f}" for part in SKIP_PARTS):
            continue
        files.append(f)
    return files


def cmd_style(_args) -> int:
    hits: list[str] = []
    for path in tracked_files():
        try:
            with open(path, encoding="utf-8") as fh:
                for lineno, line in enumerate(fh, 1):
                    if EM_DASH in line or EN_DASH in line:
                        which = "em-dash" if EM_DASH in line else "en-dash"
                        hits.append(f"{path}:{lineno}: {which}: {line.rstrip()}")
        except (UnicodeDecodeError, FileNotFoundError, IsADirectoryError):
            continue  # binary or removed; not authored text

    if hits:
        print("range style: FAIL - em/en dashes are not allowed (use a hyphen, comma, or reword):\n")
        print("\n".join(hits))
        print(f"\n{len(hits)} offending line(s).")
        return 1
    print("range style: OK  (no em/en dashes in authored text)")
    return 0

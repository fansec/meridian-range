"""new - scaffold a module directory from modules/_template.

This is the other half of "keeping the structure" (the enforcing half is `range check`). A generator
plus a validator holds a convention; a paragraph in a contributing guide does not, which is how this
repo previously ended up with a checklist restated in four places and obeyed differently each time.

  range new 04 tool-poisoning --name "Tool Description Poisoning"

creates modules/04-tool-poisoning/ with every conventional file already in place and the identity
fields filled in, so the only thing left to write is the attack and its detection.
"""
from __future__ import annotations

import datetime
import re
import shutil

import catalog as cat

TEMPLATE = cat.MODULES / "_template"
SLUG_RE = re.compile(r"^[a-z0-9]+(-[a-z0-9]+)*$")
ID_RE = re.compile(r"^\d{2}$")


def _next_atr_id() -> str:
    nums = []
    year = datetime.date.today().year
    for m in cat.all_modules():
        for p in cat.atr_files(m):
            found = re.search(r"ATR-(\d{4})-(\d{5})", p.name)
            if found:
                nums.append(int(found.group(2)))
                year = int(found.group(1))
    return f"ATR-{year}-{(max(nums) + 1) if nums else 70001:05d}"


def cmd_new(args) -> int:
    module_id, slug = str(args.id), str(args.slug)
    if not ID_RE.match(module_id):
        raise SystemExit(f"module id must be two digits (got `{module_id}`)")
    if not SLUG_RE.match(slug):
        raise SystemExit(f"slug must be lower-case kebab-case (got `{slug}`)")
    if not TEMPLATE.is_dir():
        raise SystemExit(f"template not found at {TEMPLATE}")

    dirname = f"{module_id}-{slug}"
    target = cat.MODULES / dirname
    if target.exists():
        raise SystemExit(f"{cat.rel({'_dir': dirname})} already exists")
    for existing in cat.all_modules():
        if str(existing.get("id")) == module_id:
            raise SystemExit(f"module id {module_id} is already taken by {existing['_dir']}")

    atr_id = _next_atr_id()
    subs = {
        "{{ID}}": module_id,
        "{{SLUG}}": slug,
        "{{DIR}}": dirname,
        "{{NAME}}": args.name or slug.replace("-", " ").title(),
        "{{DATE}}": datetime.date.today().isoformat(),
        "{{ATR_ID}}": atr_id,
        "{{ATR_DATE}}": datetime.date.today().strftime("%Y/%m/%d"),
    }

    shutil.copytree(TEMPLATE, target)
    for path in sorted(target.rglob("*")):
        if not path.is_file():
            continue
        text = path.read_text(encoding="utf-8")
        for needle, value in subs.items():
            text = text.replace(needle, value)
        path.write_text(text, encoding="utf-8")
        # Filenames carry placeholders too (the ATR rule is named for its id).
        new_name = path.name
        for needle, value in subs.items():
            new_name = new_name.replace(needle, value)
        if new_name != path.name:
            path.rename(path.with_name(new_name))

    print(f"created modules/{dirname}/ from the template\n")
    print("Next, in order:")
    print(f"  1. modules/{dirname}/module.yml     anchor CVE + CWE + OWASP ids, and the transport")
    print(f"  2. modules/{dirname}/compose.yml    the victim service (never a `ports:` key here)")
    print(f"  3. modules/{dirname}/scenario.ts    the attack; identity comes from module.yml")
    print(f"  4. modules/{dirname}/detection/     {atr_id} with its test_cases, plus elastic.md")
    print(f"  5. ./range check && ./range detect-test {module_id} && ./range render")
    print(f"  6. on the VM: ./range verify {module_id}, then ./range sync --pull-evidence and commit")
    print("\nThe module stays `coming_soon` until step 6 is green; `range check` enforces that.")
    return 0

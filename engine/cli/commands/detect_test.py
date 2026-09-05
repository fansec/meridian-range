"""detect-test - evaluate each ATR rule against its own embedded test_cases, offline.

The detection-side regression gate that needs no VM. An ATR rule declares `detection.conditions` plus
`test_cases` (true_positives / true_negatives); this evaluates the conditions against each input and
asserts the rule fires exactly when it should. Correlation rules use an `events` list representing one
declared evaluation window. It lets the authoring host verify detection LOGIC long before the live-signal
half is confirmed on the VM.

Supported operators: `exact` (stringwise equality), `regex` (re.search). A field that is absent or
null never matches, which is what makes an `origin: null` negative meaningful. condition `all` means
every sub-condition, `any` means at least one. The supported correlation is `value_count`: group matching
events, then require a minimum number of distinct values in one field.
"""
from __future__ import annotations

import re

import yaml

import catalog as cat


def _val(x) -> str | None:
    """Normalise a test-input field to the string the rule compares against; None if absent/null."""
    if x is None:
        return None
    if isinstance(x, bool):
        return "true" if x else "false"
    return str(x)


def eval_condition(cond: dict, inp: dict) -> bool:
    field = cond.get("field")
    op = cond.get("operator")
    expected = cond.get("value")
    actual = _val(inp.get(field)) if field in inp else None
    if actual is None:
        return False
    if op == "exact":
        return actual == str(expected)
    if op == "regex":
        return re.search(str(expected), actual) is not None
    raise ValueError(f"unsupported operator: {op!r}")


def _event_matches(detection: dict, inp: dict) -> bool:
    logic = detection.get("condition", "all")
    results = [eval_condition(c, inp) for c in (detection.get("conditions") or [])]
    if logic == "all":
        return all(results)
    if logic == "any":
        return any(results)
    raise ValueError(f"unsupported condition logic: {logic!r}")


def rule_fires(detection: dict, inp: dict | list[dict]) -> bool:
    """Evaluate a single event, or an event collection for a correlation rule."""
    events = inp if isinstance(inp, list) else [inp]
    matched = [event for event in events if _event_matches(detection, event)]
    correlation = detection.get("correlation")
    if not correlation:
        return bool(matched)
    if correlation.get("type") != "value_count":
        raise ValueError(f"unsupported correlation type: {correlation.get('type')!r}")

    group_fields = correlation.get("group_by") or []
    value_field = correlation.get("field")
    minimum = int(correlation.get("min_distinct", 2))
    groups: dict[tuple[str, ...], set[str]] = {}
    for event in matched:
        group = tuple(_val(event.get(field)) or "" for field in group_fields)
        if not group or any(value == "" for value in group):
            continue
        value = _val(event.get(value_field))
        if value is not None:
            groups.setdefault(group, set()).add(value)
    return any(len(values) >= minimum for values in groups.values())


def run_file(path) -> tuple[int, int]:
    doc = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    detection = doc.get("detection", {})
    tests = doc.get("test_cases", {}) or {}
    passed = failed = 0
    cases = [(tc, True) for tc in (tests.get("true_positives") or [])]
    cases += [(tc, False) for tc in (tests.get("true_negatives") or [])]
    for tc, want_fire in cases:
        inp = tc.get("events") if "events" in tc else tc.get("input", {})
        got_fire = rule_fires(detection, inp)
        if got_fire == want_fire:
            passed += 1
        else:
            failed += 1
            print(f"  FAIL {path.name}: expected {'trigger' if want_fire else 'no_trigger'}, "
                  f"got {'trigger' if got_fire else 'no_trigger'}  input={inp}")
    print(f"  {path.name}: {passed} passed, {failed} failed")
    return passed, failed


def cmd_detect_test(args) -> int:
    mods = [cat.require(args.module)] if args.module else cat.all_modules()
    files = [p for m in mods for p in cat.atr_files(m)]
    if not files:
        print("range detect-test: no ATR files to evaluate")
        return 0

    total_p = total_f = 0
    for f in files:
        p, fl = run_file(f)
        total_p += p
        total_f += fl
    print(f"\nrange detect-test: {'OK' if total_f == 0 else 'FAIL'}  "
          f"({total_p} passed, {total_f} failed across {len(files)} rule file(s))")
    return 1 if total_f else 0

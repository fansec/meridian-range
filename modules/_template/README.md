# Module {{ID}} - {{NAME}}

> Status: `coming_soon`. This module is done only when it has walked the whole loop:
> `reproduce (ATTACK-OK) -> detection (signal + rule)`, verified on the lab VM.

## The vulnerability

What the affected software does, which control is missing or off by default, and the anchoring CVE.
Link the primary source. Do not invent an identifier, a version or a citation; mark anything
unverified with a literal `(verify)` so it cannot silently harden into fact.

## Why it matters

The consequence in the terms a defender cares about: what an attacker reaches, from where, and what
they need beforehand. Keep this separate from the reproduction below.

## Reproduction

```bash
./range up {{ID}}          # on the lab VM
./range run {{ID}}         # expect [ATTACK-OK]
./range verify {{ID}}      # the gate, and it writes ./evidence/vuln.txt
```

What the scenario models, and precisely which observations make it a reproduction rather than a
demonstration. Be explicit about what would count as a false positive.

## Mitigation

The fix, and the evidence that it works. If the module declares a `matrix:` block, show the grid:

```bash
./range matrix {{ID}}
```

## Detection

- Machine-readable rule with its test cases: [`detection/{{ATR_ID}}-{{SLUG}}.yaml`](./detection/{{ATR_ID}}-{{SLUG}}.yaml)
- Elastic prose rule and telemetry: [`detection/elastic.md`](./detection/elastic.md)

State the discriminating signal in one sentence: what does this attack do that ordinary traffic
never does? A detection built on anything the vulnerable application itself asserts about its own
compromise is not a detection (see [`../../docs/telemetry-contract.md`](../../docs/telemetry-contract.md)).

## Evidence

`./evidence/` holds captures written by the harness, not pasted by hand.

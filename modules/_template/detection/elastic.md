# Detection - module {{ID}} ({{NAME}})

> Deployment identifiers here are placeholders: `<LAB_HOST>` is the lab VM's `host.name`,
> `<LAB_POLICY>` the lab Elastic Agent policy. **Scope every rule to the lab host only** so it can
> never fire on a shared or production host. Author rules **disabled**; enable only after a live lab
> hit. See [`../../../docs/telemetry-contract.md`](../../../docs/telemetry-contract.md).

## Threat model for the detection engineer

The SOC does not control the vulnerable application, and would not trust a "you are being attacked"
flag from it even if one existed. So state here which telemetry the SOC genuinely owns for this
attack, and where the verdict is derived (at ingest, SOC-side) rather than read from the target.

## Signal (the discriminator)

The one thing this attack does that ordinary traffic never does. If you cannot state it in a
sentence, the detection is not ready.

## Layer A - endpoint (Elastic Defend)

What the payload looks like in process telemetry, independent of the application.

## Layer B - application / transport telemetry

The request-level signal, and the ingest step that derives the verdict from raw fields.

## Rule

```
CHANGEME KQL or EQL, scoped: and host.name : "<LAB_HOST>"
```

## Validation

The machine-readable rule and its test cases live beside this file. Run them offline:

```bash
./range detect-test {{ID}}
```

## Known gaps

What this rule does not catch, and what would evade it. Write this down before someone finds out the
hard way.

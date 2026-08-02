## What and why

<!-- One or two sentences. If this adds a module, name the CVE it anchors to. -->

## Checklist

Offline gates, all runnable on an ordinary workstation (they start nothing):

- [ ] `./range check` passes: module manifests, directory structure, topology and the
      no-`ports:`-in-a-sealed-compose-file gate
- [ ] `./range render --check` passes, so the generated README table and OWASP map match the module
      manifests (`modules/*/module.yml`)
- [ ] `./range detect-test` passes, so every ATR rule still agrees with its `test_cases`
- [ ] `./range typecheck`, `./range lint` and `./range style` pass

Safety:

- [ ] Nothing capability-bearing was built or run outside the isolated lab VM
- [ ] No `ports:` added to `engine/compose.yml` or a module's `compose.yml`; exposure lives only in
      `modules/<NN-slug>/deploy/` tiers
- [ ] Payloads are benign canaries only (`id; hostname; echo LAB_CANARY`)
- [ ] No real secret, address, or personal data added, in code, docs, commit messages or media

If this adds or changes a module, the definition of done is `reproduce (ATTACK-OK) -> detection
(signal + rule)`:

- [ ] The isolated VM ran `./range verify <module>` green, and `modules/<NN-slug>/evidence/*.txt` is
      committed
- [ ] A detection exists that fires on the signal the reproduction leaves

If this adds a module, it is one directory under `modules/`, scaffolded with
`./range new <id> <slug>`, and it changes nothing outside that directory.

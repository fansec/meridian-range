# Contributing

This is a personal security-research range, published so the reproductions and the detections are
useful to other people. It is not a product and it has no roadmap commitments. Issues and pull
requests are welcome; please open an issue before a large change, so neither of us builds the wrong
thing.

**The servers in this repo carry `run_command` and are insecure by design.** They are pinned to
affected releases deliberately, they run only on an isolated lab VM with no egress and no published
ports, and everything below assumes that.

## The one rule that shapes everything

Nothing capability-bearing runs anywhere but a dedicated, isolated VM. The authoring host edits code
and runs static checks; it never `docker build`s or `docker compose up`s a server, and never runs a
live scenario.

`./range` enforces that, and the guard is now **inverted so it fails closed**. It used to refuse one
literal workstation hostname and let every other machine through, which meant the boundary held on
exactly one laptop. A `[VM]` subcommand (`up`, `down`, `status`, `run`, `verify`, `matrix`, `probe`)
now refuses unless the host has positively identified itself as the lab VM, in one of two ways:

```bash
sudo touch /etc/meridian-vm        # persistent marker, survives a reboot, the recommended one
MERIDIAN_ON_VM=1 ./range run 01    # per-command escape hatch, only when you really are on the VM
```

An unidentified host is treated as not-the-VM, so a fresh machine refuses rather than obliges.

That means a contribution can be **fully prepared** on an ordinary machine, but a module is only
**finished** once an isolated VM has run it. If you cannot run one, open a PR anyway with the offline
gates green and say so; the reproduction can be verified here.

## Offline gates

Everything the range can do is a subcommand of the single `./range` executable at the repo root.
These are the `[dev]` ones: they start nothing, and they are exactly what CI runs.

```bash
./range check           # every module: manifest, structure, topology, detections, safety gates
./range render --check  # generated README table and OWASP map still match the module manifests
./range detect-test     # every ATR rule still agrees with its test_cases
./range typecheck       # TypeScript, every project, no server started
./range lint            # eslint, ruff and prettier, in one pass
./range style           # the writing rule below
```

`./range check`, `./range render` and `./range detect-test` need `python3` and PyYAML on the
authoring host; `./range lint` and `./range typecheck` need node. `npm run lint` and `npm run check`
are thin aliases for the same subcommands, so there is one implementation rather than two that drift.

`./range list` shows the modules on disk, and `./range --help` lists every subcommand with its
`[dev]` or `[VM]` marking.

## Adding a module

A module is **one directory** under `modules/`, and its `module.yml` **is** its catalog row: `./range`
globs `modules/*/module.yml`, so nothing outside the directory has to learn the module exists. The
rest is found by convention (`scenario.ts`, `compose.yml`, `lab.env`, `README.md`, `detection/`,
`evidence/`, and `deploy/` only if the module needs an exposed tier). Adding a module therefore means
adding one directory and editing **nothing outside it**: no central catalog to edit, no runner to
register with, no table to update by hand.

Start it with the scaffolder, which copies `modules/_template/` and fills in the identity fields:

```bash
./range new 03 tool-poisoning --name "Tool Description Poisoning"
```

The full checklist begins with that command. `./range check`
is the other half: it validates the resulting structure on every commit, so the convention is held by
a generator plus a validator instead of by a paragraph someone has to remember. A module is done only
when it walks the whole loop:

```
reproduce (ATTACK-OK)  ->  detection (signal + rule)
```

An exploit without a detection is not a contribution to this repo. That is the entire point of it.

If your module has a recording, it belongs in `modules/<NN-slug>/media/` and is embedded at the top of
that module's own README; the front page links to the module rather than embedding a second clip. The
capture standard a published clip has to meet is in [`media/README.md`](../media/README.md).

Two things worth knowing before you start. Most modules need only the `sealed` tier, so no DNS, no
second host, and no `deploy/` fragment: a server-side attack has no attacker infrastructure to
separate. And the module manifests are the single source of truth, so the README table and the OWASP
map are **generated** into their `BEGIN/END GENERATED` markers. Editing them by hand fails CI; run
`./range render` and commit the result.

## Anchoring and citation

Every module anchors to an already-published CVE, and framework identifiers (OWASP, MITRE ATLAS, CWE)
are recorded per module in its `module.yml`. `./range check` cross-checks each detection rule's
identifiers against that manifest, so the two cannot disagree quietly. Do not invent an identifier, a
version, or a citation. Anything unverified carries a literal `(verify)` marker so it cannot silently
harden into fact, and a PR that removes one should say what was checked and against which source.

## Writing style

No em dashes or en dashes, anywhere: prose, comments, commit messages, PR text. Use a hyphen, a
comma, parentheses, or reword. `./range style` enforces this across tracked text and CI runs it.

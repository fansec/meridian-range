/**
 * Harness - the scenario runner. Contract: `ok = attack succeeded` (ATTACK-OK). A scenario that
 * returns ok=false simply did not reproduce (the purple-team loop; see SECURITY.md). Runs
 * ephemerally, normally through the CLI:
 *
 *   range run <module>              reproduce         (this file, mode "run")
 *   range probe --target <url> ...  read-only checks  (this file, mode "probe")
 *
 * Scenarios are DISCOVERED, not registered. There is no map to edit here: the runner resolves a
 * module directory under modules/, imports its scenario.ts, and dispatches. Adding a module means
 * adding modules/<NN>-<slug>/ and touching nothing in the engine.
 */
import path from "node:path";
import { loadModule, moduleDir, resolveModuleDir } from "./module.js";
import type { Scenario } from "./scenario.js";

function usage(): never {
  console.error("usage: index.ts <module-id-or-dir> [--probe]");
  process.exit(2);
}

async function main(): Promise<number> {
  const args = process.argv.slice(2);
  const probeMode = args.includes("--probe");
  const nameOrId = args.find((a) => !a.startsWith("--"));
  if (!nameOrId) usage();

  const dir = resolveModuleDir(nameOrId);
  const meta = loadModule(dir);

  const entry = path.join(moduleDir(dir), "scenario.ts");
  const mod = (await import(entry)) as { scenario?: Scenario };
  if (!mod.scenario) {
    console.error(
      `modules/${dir}/scenario.ts must export \`scenario\` (see defineScenario in engine/harness/src/scenario.ts)`,
    );
    return 2;
  }

  if (probeMode) {
    const out = await mod.scenario.probe(meta);
    for (const c of out.checks) {
      console.log(`[${c.observed ? "PRESENT " : "ABSENT  "}] ${c.id}  ${c.detail}`);
    }
    const present = out.checks.filter((c) => c.observed).length;

    // A probe that never reached the MCP transport has observed nothing, which is not the same as
    // having found nothing. Saying so is the whole point: `0/N observed` against a wrong URL reads
    // as "you are fine" and is the one answer this command must never give by accident.
    const reach = out.reach;
    const reachedMcp = reach ? reach.attempted && reach.status >= 200 && reach.status < 300 : true;
    if (!reachedMcp) {
      const why =
        !reach?.attempted || reach.status === 0
          ? "nothing answered at that address"
          : `the target answered HTTP ${reach.status}, which is not an MCP transport response`;
      console.log(`\n[PROBE] ${dir}  INCONCLUSIVE: ${why}, so no conclusion about this module can be drawn.`);
      console.log(
        "        Check --target. For an http+sse module it is the server BASE url (the module's " +
          "sse path is appended); for a streamable-http module it is the full endpoint.",
      );
      return 4;
    }

    console.log(
      `\n[PROBE] ${dir}  ${present}/${out.checks.length} vulnerable condition(s) observed  (read-only; nothing was executed)`,
    );
    return 0;
  }

  const { ok, detail, evidenceFile } = await mod.scenario.run(meta);
  // The machine status line the tooling greps for. The rich report has already streamed above it.
  console.log(`[${ok ? "ATTACK-OK " : "NO-REPRO  "}] ${dir}  ${detail}`);
  if (evidenceFile) console.log(`[evidence] wrote ${evidenceFile}`);
  console.log(`${ok ? 1 : 0}/1 attacks reproduced`);
  return 0;
}

main().then(
  (code) => process.exit(code),
  (e) => {
    console.error(`[harness] scenario error: ${e?.message ?? e}`);
    process.exit(1);
  },
);

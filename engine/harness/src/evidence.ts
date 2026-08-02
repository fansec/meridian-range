/**
 * Write a run's transcript to the module's own evidence file.
 *
 * The report engine already produces exactly the stream that belongs in evidence/<variant>.txt. It
 * used to reach that file by an operator copying a terminal capture and hand-editing it, which is
 * how evidence/02-dns-rebind ended up holding a written-by-hand "EXPECTED output shape" that no run
 * ever produced. A capture the harness writes itself cannot drift from the run it claims to be.
 *
 * Writing is opt-in (MERIDIAN_WRITE_EVIDENCE=1, set by `range verify`) because a scenario run is also
 * an interactive tool, and a bare `range run` should not silently rewrite committed evidence.
 *
 * The file lands in the module directory, which is bind-mounted into the harness container. On the
 * lab VM that means it lands in the VM's copy: bring it back to the authoring host with
 * `range sync --pull-evidence` before committing.
 */
import { mkdirSync, writeFileSync } from "node:fs";
import path from "node:path";
import { moduleDir } from "./module.js";

export function evidenceEnabled(): boolean {
  return process.env.MERIDIAN_WRITE_EVIDENCE === "1";
}

/** Which capture this run is: "vuln" (the default), "fixed", or a matrix row's label. */
export function variant(): string {
  const v = (process.env.MERIDIAN_VARIANT ?? "").trim();
  return v === "" ? "vuln" : v.replace(/[^A-Za-z0-9._-]/g, "-");
}

function header(dir: string, name: string, ok: boolean): string {
  return [
    "# Meridian Range evidence capture (written by the harness, not by hand).",
    `# module   : ${dir}`,
    `# variant  : ${name}`,
    `# verdict  : ${ok ? "ATTACK-OK (reproduced)" : "NO-REPRO (did not reproduce)"}`,
    `# captured : ${new Date().toISOString()}`,
    "# Addresses and hostnames below are lab-internal; the canary is benign by construction.",
    "",
  ].join("\n");
}

/** Returns the path written, or null when evidence writing is disabled. */
export function writeEvidence(dir: string, transcript: string, ok: boolean): string | null {
  if (!evidenceEnabled()) return null;
  const name = variant();
  const outDir = path.join(moduleDir(dir), "evidence");
  const file = path.join(outDir, `${name}.txt`);
  mkdirSync(outDir, { recursive: true });
  writeFileSync(file, header(dir, name, ok) + transcript, "utf8");
  return file;
}

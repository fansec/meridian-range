/**
 * Read a module's own manifest (modules/<NN-slug>/module.yml) at run time.
 *
 * The manifest is the single source of truth for a module's identity, so a scenario never restates
 * its own CVE, CWE or title: the report header is built from the same file the catalog table, the
 * OWASP map and the detection cross-check are built from. Change the CVE in one place and every
 * downstream view follows.
 */
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { parse } from "yaml";

/**
 * The image mirrors the repo layout on purpose (engine/harness/src + modules/), so this one relative
 * walk is correct both on the authoring host and inside the container, and a scenario's import of
 * `../../engine/harness/src/...` resolves identically in both places.
 */
function modulesRoot(): string {
  const override = process.env.MERIDIAN_MODULES_DIR;
  if (override) return override;
  return path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..", "..", "modules");
}

/** Every module directory present on disk, in id order. */
export function listModuleDirs(): string[] {
  return readdirSync(modulesRoot(), { withFileTypes: true })
    .filter(
      (d) => d.isDirectory() && !d.name.startsWith("_") && existsSync(path.join(modulesRoot(), d.name, "module.yml")),
    )
    .map((d) => d.name)
    .sort();
}

/**
 * Accept either the directory name ("01-cors-session-hijack") or just the module id ("01"), which is
 * what an operator actually types.
 */
export function resolveModuleDir(nameOrId: string): string {
  const dirs = listModuleDirs();
  if (dirs.includes(nameOrId)) return nameOrId;
  const byId = dirs.filter((d) => d.split("-")[0] === nameOrId);
  if (byId.length === 1) return byId[0];
  if (byId.length > 1) throw new Error(`ambiguous module "${nameOrId}": ${byId.join(", ")}`);
  throw new Error(`unknown module "${nameOrId}"\nknown: ${dirs.join(", ")}`);
}

export type CveRef = { id: string; cvss?: number; role?: string };

export type ModuleMeta = {
  /** Directory name, which is also the name `range run` dispatches on (e.g. "01-cors-session-hijack"). */
  dir: string;
  id: string;
  slug: string;
  name: string;
  status: string;
  transport: "http+sse" | "streamable-http";
  cve: CveRef[];
  cwe: string[];
  description: string;
  /** The whole parsed manifest, for anything this type does not name explicitly. */
  raw: Record<string, unknown>;
};

export function moduleDir(dir: string): string {
  return path.join(modulesRoot(), dir);
}

export function loadModule(dir: string): ModuleMeta {
  const file = path.join(moduleDir(dir), "module.yml");
  let raw: Record<string, unknown>;
  try {
    raw = (parse(readFileSync(file, "utf8")) ?? {}) as Record<string, unknown>;
  } catch (e) {
    throw new Error(`cannot read module manifest ${file}: ${(e as Error).message}`);
  }
  const transport = String(raw.transport ?? "http+sse");
  if (transport !== "http+sse" && transport !== "streamable-http") {
    throw new Error(`${dir}/module.yml: unknown transport "${transport}"`);
  }
  return {
    dir,
    id: String(raw.id ?? ""),
    slug: String(raw.slug ?? ""),
    name: String(raw.name ?? dir),
    status: String(raw.status ?? "coming_soon"),
    transport,
    cve: (raw.cve as CveRef[]) ?? [],
    cwe: (raw.cwe as string[]) ?? [],
    description: String(raw.description ?? "").trim(),
    raw,
  };
}

/** The CVE a module anchors to (role: anchor), else its first CVE, else a placeholder. */
export function anchorCve(m: ModuleMeta): string {
  const anchor = m.cve.find((c) => (c.role ?? "anchor") === "anchor") ?? m.cve[0];
  return anchor?.id ?? "(no CVE anchor)";
}

/** The module's primary CWE (the first listed), else a placeholder. */
export function primaryCwe(m: ModuleMeta): string {
  return m.cwe[0] ?? "(no CWE)";
}

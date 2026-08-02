/**
 * Module {{ID}} - {{NAME}}.
 *
 * Describe the attack here: what the vulnerable behaviour is, what the scenario models, and exactly
 * what makes the run a reproduction. Be explicit about the last one, because `ok` is a claim:
 *
 *   ok (ATTACK-OK) = <the observable facts that together prove the attack landed>
 *   ok=false       = <what a patched or configured-correctly server does instead>
 *
 * Identity (title, CVE, CWE), the target and the transport all come from module.yml and lab.env.
 * Never restate them here: one source, so a corrected CVE id propagates everywhere by itself.
 *
 * Benign canaries only (SECURITY.md rule 4). ctx.canary() is the only command this may ever run.
 */
import { defineScenario } from "../../engine/harness/src/scenario.js";
import { resultText } from "../../engine/harness/src/transport/index.js";

export const scenario = defineScenario({
  title: "{{NAME}}",

  conclusionOk:
    "State what the evidence above demonstrates, in the terms a reader of the writeup needs: which " +
    "control failed, what the attacker gained, and why it matters beyond this lab.",

  conclusionNo:
    "State what a server that is NOT vulnerable does instead, so a no-repro result is informative " +
    "rather than merely negative.",

  iocs(ctx, ok) {
    const t = ctx.target;
    return {
      endpoints: [new URL(t.url).pathname],
      methods: ["POST"],
      headers: {},
      userAgent: "meridian-harness",
      sessionId: null,
      tools: ok ? ["run_command (capability exec)"] : ["none"],
      sourceHint: "labnet 172.28.0.0/16",
      collector: t.collectorUrl,
      detections: ["{{ATR_ID}}"],
    };
  },

  async run(ctx) {
    const { report } = ctx;

    report.step("Opening a session against the victim MCP");
    const opened = await ctx.connect();
    if (!opened.session) {
      report.fail("Server unreachable");
      return { ok: false, detail: "session=none exec=false", notReproducedWhy: "server_unreachable" };
    }

    const session = opened.session;
    try {
      // Establish the vulnerable condition here, and record it with report.pass(msg, fact) so the
      // EVIDENCE block states an observation rather than a conclusion.

      ctx.requireExec(); // refuses in read-only probe mode; call before ANY capability invocation
      report.step("Invoking the capability tool with the benign canary");
      const call = await session.request("tools/call", { name: "run_command", arguments: { cmd: ctx.canary() } });
      const out = resultText(call);

      if (!ctx.isCanary(out)) {
        report.fail("No canary in the tool output");
        return { ok: false, detail: "exec=false", notReproducedWhy: "exec_absent" };
      }
      report.pass(
        `Canary executed: ${ctx.canaryMarker(out)}`,
        `Proof-of-execution canary returned in the tool output, confirming code execution.`,
      );

      await ctx.exfil({ output: out });
      return { ok: true, detail: "exec=true" };
    } finally {
      session.close();
    }
  },

  /**
   * OPTIONAL and READ-ONLY. Delete this if the vulnerable condition cannot be observed without
   * executing something. Anything here must be pure observation: `range probe` runs this path and
   * nothing else, and the context refuses capability invocation while it does.
   */
  async probe(ctx) {
    const opened = await ctx.connect({ retryMs: 5000 });
    opened.session?.close();
    return {
      checks: [
        {
          id: "CHANGEME",
          observed: !!opened.session,
          detail: "what was observed, in one line",
        },
      ],
    };
  },
});

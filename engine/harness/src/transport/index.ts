/**
 * Transport layer for the Meridian harness.
 *
 * A scenario says WHICH transport it attacks by declaring `transport:` in its module.yml; it never
 * builds a client by hand. Before this existed, module 01 imported the SSE client directly while
 * module 02 hand-rolled 23 lines of node:http inside the scenario file, so "which transport" was an
 * implicit consequence of an import, and there was no client at all for streamable HTTP.
 *
 *   http+sse         the dual-channel 2024-11-05 transport (the one CVE-2026-34237 lives in)
 *   streamable-http  the single-endpoint transport, with a verbatim Host header when asked for
 */
import { SseMcpSession } from "./sse.js";
import { HttpMcpSession } from "./http.js";
import type { OpenOpts, OpenResult } from "./types.js";

export async function openSession(opts: OpenOpts): Promise<OpenResult> {
  if (opts.transport === "http+sse") {
    const base = opts.url.replace(/\/$/, "");
    const sseUrl = base + (opts.ssePath ?? "/mcp/sse");
    const r = await SseMcpSession.open(sseUrl, {
      origin: opts.origin,
      recorder: opts.recorder,
      timeoutMs: opts.timeoutMs,
    });
    return { status: r.status, acao: r.acao, sessionId: r.sessionId, session: r.session };
  }
  return HttpMcpSession.open(opts.url, {
    origin: opts.origin,
    hostHeader: opts.hostHeader,
    recorder: opts.recorder,
    timeoutMs: opts.timeoutMs,
  });
}

export type { McpSession, OpenOpts, OpenResult } from "./types.js";
export { rpcHeaders, parseRpcBody, resultText, exfil } from "./rpc.js";
export { SseMcpSession } from "./sse.js";
export { HttpMcpSession } from "./http.js";

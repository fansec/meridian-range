/**
 * Minimal MCP client for the streamable-HTTP transport (single endpoint, session id carried in the
 * `mcp-session-id` response header).
 *
 * It deliberately uses node:http / node:https rather than fetch. The Host header is the entire signal
 * a DNS-rebinding scenario turns on, and it must go out verbatim: undici derives Host from the URL
 * and ignores an override, so a fetch-based client cannot express "connect to this address while
 * presenting that name". That requirement used to be met by 23 lines of request plumbing copy-pasted
 * into the scenario file itself; it belongs here, with the rest of the transports.
 *
 * An optional WireRecorder captures the raw request/response frames as replayable evidence. Recording
 * is passive: it never changes what goes on the wire.
 */
import http from "node:http";
import https from "node:https";
import { URL } from "node:url";
import type { WireRecorder } from "../report.js";
import type { McpSession, OpenResult } from "./types.js";
import { parseRpcBody, rpcHeaders } from "./rpc.js";

type RawResponse = { status: number; headers: http.IncomingHttpHeaders; body: string };

export type HttpOpenOpts = {
  origin?: string;
  hostHeader?: string;
  recorder?: WireRecorder;
  timeoutMs?: number;
};

function pickHeaders(h: http.IncomingHttpHeaders): Record<string, string> {
  const keep = ["access-control-allow-origin", "content-type", "mcp-session-id"];
  const out: Record<string, string> = {};
  for (const k of keep) {
    const v = h[k];
    if (typeof v === "string") out[k] = v;
  }
  return out;
}

export class HttpMcpSession implements McpSession {
  private nextId = 1;

  private constructor(
    readonly sessionId: string | null,
    private readonly url: string,
    private readonly opts: HttpOpenOpts,
  ) {}

  /** Open a session: POST `initialize` and read the session id off the response header. */
  static async open(url: string, opts: HttpOpenOpts = {}): Promise<OpenResult> {
    const body = JSON.stringify({
      jsonrpc: "2.0",
      id: 0,
      method: "initialize",
      params: {
        protocolVersion: "2025-06-18",
        capabilities: {},
        clientInfo: { name: "meridian-harness", version: "0.0.0" },
      },
    });

    let res: RawResponse;
    try {
      res = await HttpMcpSession.post(url, body, opts);
    } catch {
      // Connection refused (the server may still be starting). Record nothing: only a request that
      // actually reached the server belongs in the evidence transcript.
      return { status: 0, acao: null, sessionId: null, session: null };
    }

    const sid = (res.headers["mcp-session-id"] as string | undefined) ?? null;
    const acao = (res.headers["access-control-allow-origin"] as string | undefined) ?? null;
    const session = sid ? new HttpMcpSession(sid, url, opts) : null;
    return { status: res.status, acao, sessionId: sid, session };
  }

  async request(method: string, params: unknown, timeoutMs?: number): Promise<any> {
    const id = this.nextId++;
    const raw = JSON.stringify({ jsonrpc: "2.0", id, method, params });
    const res = await HttpMcpSession.post(this.url, raw, this.opts, this.sessionId, timeoutMs);
    const payload = parseRpcBody(res.body, res.headers["content-type"] as string | undefined);
    this.opts.recorder?.rpc("in", payload);
    return payload;
  }

  async notify(method: string, params?: unknown): Promise<void> {
    const raw = JSON.stringify({ jsonrpc: "2.0", method, params });
    await HttpMcpSession.post(this.url, raw, this.opts, this.sessionId);
  }

  close(): void {
    /* stateless transport: nothing to tear down */
  }

  private static post(
    url: string,
    body: string,
    opts: HttpOpenOpts,
    sessionId?: string | null,
    timeoutMs = 10000,
  ): Promise<RawResponse> {
    const u = new URL(url);
    const secure = u.protocol === "https:";
    const headers: Record<string, string | number> = rpcHeaders({
      "content-length": String(Buffer.byteLength(body)),
    });
    // The forged Host is the point of this client: connect to the real address, present another name.
    if (opts.hostHeader) headers.host = opts.hostHeader;
    if (opts.origin) headers.origin = opts.origin;
    if (sessionId) headers["mcp-session-id"] = sessionId;

    opts.recorder?.request(
      "POST",
      url,
      Object.fromEntries(Object.entries(headers).map(([k, v]) => [k, String(v)])),
      body,
    );
    opts.recorder?.rpc("out", body);

    return new Promise((resolve, reject) => {
      const req = (secure ? https : http).request(
        {
          hostname: u.hostname,
          port: u.port || (secure ? 443 : 80),
          path: u.pathname + u.search,
          method: "POST",
          headers,
        },
        (res) => {
          let data = "";
          res.on("data", (c) => (data += c));
          res.on("end", () => {
            opts.recorder?.response(res.statusCode ?? 0, pickHeaders(res.headers));
            resolve({ status: res.statusCode ?? 0, headers: res.headers, body: data });
          });
        },
      );
      req.setTimeout(timeoutMs, () => req.destroy(new Error(`timeout after ${timeoutMs}ms`)));
      req.on("error", reject);
      req.write(body);
      req.end();
    });
  }
}

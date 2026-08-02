/**
 * Minimal MCP client for the HTTP/SSE transport (protocol revision 2024-11-05) - the transport at the
 * centre of CVE-2026-34237.
 *
 * The HTTP/SSE transport is dual-channel:
 *   1. the client opens a long-lived GET on the SSE endpoint;
 *   2. the server announces the message endpoint on an `endpoint` event whose data is
 *      `<messageEndpoint>?sessionId=<uuid>` - this is where the session id is disclosed;
 *   3. the client POSTs JSON-RPC to that message endpoint (the POST returns an empty 200);
 *   4. the server delivers JSON-RPC responses back over the SSE stream as `message` events.
 *
 * This is exactly the client a foreign browser Origin can construct once the vulnerable SDK transport
 * answers the cross-origin SSE read with `Access-Control-Allow-Origin: *`. It is transport-faithful, not
 * a shortcut: nothing here reads a session id from a response header.
 *
 * An optional `WireRecorder` lets a caller capture the raw request/response/SSE frames as replayable
 * protocol evidence (see report.ts). Recording is passive: it never changes what goes on the wire.
 */
import type { WireRecorder } from "../report.js";

/** Response headers a browser (and a SOC) care about on the cross-origin SSE read. */
const CAPTURED_RESPONSE_HEADERS = [
  "access-control-allow-origin",
  "content-type",
  "cache-control",
  "connection",
  "transfer-encoding",
  "mcp-session-id",
] as const;

function pickHeaders(h: Headers): Record<string, string> {
  const out: Record<string, string> = {};
  for (const name of CAPTURED_RESPONSE_HEADERS) {
    const v = h.get(name);
    if (v !== null) out[name] = v;
  }
  return out;
}

export type SseOpen = {
  /** Access-Control-Allow-Origin observed on the SSE read - what a real browser gates the read on. */
  acao: string | null;
  status: number;
  /** Session id parsed from the `endpoint` event (the value the wildcard-CORS read leaks). */
  sessionId: string | null;
  /** Absolute message endpoint including `?sessionId=`. */
  messageUrl: string | null;
  session: SseMcpSession | null;
};

type Pending = (msg: unknown) => void;

function parseSseEvent(raw: string): { event: string; data: string } {
  let event = "message";
  const data: string[] = [];
  for (const line of raw.split("\n")) {
    if (line.startsWith("event:")) event = line.slice(6).trim();
    else if (line.startsWith("data:")) data.push(line.slice(5).replace(/^ /, ""));
  }
  return { event, data: data.join("\n") };
}

export class SseMcpSession {
  private readonly pending = new Map<number, Pending>();
  private buf: string;
  private closed = false;
  private nextId = 1;

  private constructor(
    readonly sessionId: string,
    readonly messageUrl: string,
    private readonly origin: string | undefined,
    private readonly reader: ReadableStreamDefaultReader<Uint8Array>,
    private readonly controller: AbortController,
    private readonly dec: TextDecoder,
    initialBuf: string,
    private readonly recorder?: WireRecorder,
  ) {
    this.buf = initialBuf;
    void this.pump();
  }

  /** Open the SSE stream from a (possibly foreign) Origin and read the `endpoint` event. */
  static async open(
    sseUrl: string,
    opts: { origin?: string; timeoutMs?: number; recorder?: WireRecorder } = {},
  ): Promise<SseOpen> {
    const controller = new AbortController();
    const headers: Record<string, string> = { accept: "text/event-stream" };
    if (opts.origin) headers.origin = opts.origin;

    let res: Response;
    try {
      res = await fetch(sseUrl, { headers, signal: controller.signal });
    } catch {
      // Connection refused (server still starting). Record nothing so startup retries stay out of the
      // evidence transcript; only a request that actually reached the server is recorded, just below.
      return { acao: null, status: 0, sessionId: null, messageUrl: null, session: null };
    }

    const acao = res.headers.get("access-control-allow-origin");
    opts.recorder?.request("GET", sseUrl, headers);
    opts.recorder?.response(res.status, pickHeaders(res.headers));
    if (!res.ok || !res.body) {
      controller.abort();
      return { acao, status: res.status, sessionId: null, messageUrl: null, session: null };
    }

    const reader = res.body.getReader();
    const dec = new TextDecoder();
    let buf = "";
    let endpoint: string | null = null;
    const deadline = Date.now() + (opts.timeoutMs ?? 5000);
    while (endpoint === null && Date.now() < deadline) {
      const { value, done } = await reader.read();
      if (done) break;
      buf += dec.decode(value, { stream: true });
      let i: number;
      while ((i = buf.indexOf("\n\n")) >= 0) {
        const rawEv = buf.slice(0, i);
        buf = buf.slice(i + 2);
        if (!rawEv.trim()) continue;
        const ev = parseSseEvent(rawEv);
        if (ev.event === "endpoint") {
          endpoint = ev.data;
          opts.recorder?.sse(ev.event, ev.data);
          break;
        }
      }
    }

    if (!endpoint) {
      controller.abort();
      return { acao, status: res.status, sessionId: null, messageUrl: null, session: null };
    }

    const messageUrl = new URL(endpoint, sseUrl).toString();
    const sessionId = new URL(messageUrl).searchParams.get("sessionId");
    const session = new SseMcpSession(
      sessionId ?? "",
      messageUrl,
      opts.origin,
      reader,
      controller,
      dec,
      buf,
      opts.recorder,
    );
    return { acao, status: res.status, sessionId, messageUrl, session };
  }

  private async pump(): Promise<void> {
    try {
      while (!this.closed) {
        const { value, done } = await this.reader.read();
        if (done) break;
        this.buf += this.dec.decode(value, { stream: true });
        let i: number;
        while ((i = this.buf.indexOf("\n\n")) >= 0) {
          const rawEv = this.buf.slice(0, i);
          this.buf = this.buf.slice(i + 2);
          if (!rawEv.trim()) continue;
          const ev = parseSseEvent(rawEv);
          if (ev.event === "message" && ev.data) {
            try {
              const msg = JSON.parse(ev.data) as { id?: number };
              if (msg.id != null && this.pending.has(msg.id)) {
                this.pending.get(msg.id)!(msg);
                this.pending.delete(msg.id);
              }
            } catch {
              /* ignore keep-alives / non-JSON frames */
            }
          }
        }
      }
    } catch {
      /* stream aborted on close */
    }
  }

  private async post(body: unknown): Promise<Response> {
    const headers: Record<string, string> = {
      "content-type": "application/json",
      accept: "application/json, text/event-stream",
    };
    if (this.origin) headers.origin = this.origin;
    const raw = JSON.stringify(body);
    this.recorder?.request("POST", this.messageUrl, headers, raw);
    const res = await fetch(this.messageUrl, { method: "POST", headers, body: raw });
    this.recorder?.response(res.status, {}, "JSON-RPC accepted; result returns on the SSE stream");
    return res;
  }

  /** Send a JSON-RPC request and await the response delivered on the SSE stream. */
  async request(method: string, params: unknown, timeoutMs = 6000): Promise<any> {
    const id = this.nextId++;
    const result = new Promise((resolve, reject) => {
      this.pending.set(id, resolve);
      setTimeout(() => {
        if (this.pending.has(id)) {
          this.pending.delete(id);
          reject(new Error(`timeout waiting for ${method} (id=${id})`));
        }
      }, timeoutMs);
    });
    await this.post({ jsonrpc: "2.0", id, method, params });
    const payload = await result;
    this.recorder?.rpc("in", payload);
    return payload;
  }

  /** Send a JSON-RPC notification (no response expected). */
  async notify(method: string, params?: unknown): Promise<void> {
    await this.post({ jsonrpc: "2.0", method, params });
  }

  close(): void {
    this.closed = true;
    try {
      this.controller.abort();
    } catch {
      /* noop */
    }
  }
}

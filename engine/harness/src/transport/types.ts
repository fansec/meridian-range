/** Shared transport types. Kept separate from index.ts so the clients can import them without a cycle. */
import type { WireRecorder } from "../report.js";

/** What every scenario gets back, whatever transport is underneath. */
export interface McpSession {
  readonly sessionId: string | null;
  request(method: string, params: unknown, timeoutMs?: number): Promise<any>;
  notify(method: string, params?: unknown): Promise<void>;
  close(): void;
}

export type OpenResult = {
  /** HTTP status of the request that opened the session; 0 when the connection never landed. */
  status: number;
  /** Access-Control-Allow-Origin observed on the open, which is what a browser gates a read on. */
  acao: string | null;
  sessionId: string | null;
  session: McpSession | null;
};

export type OpenOpts = {
  transport: "http+sse" | "streamable-http";
  /** Base URL of the victim MCP (http+sse), or the full endpoint URL (streamable-http). */
  url: string;
  /** Path of the SSE endpoint, relative to `url` (http+sse only). */
  ssePath?: string;
  /** Foreign Origin to forge, modelling a browser page on another origin. */
  origin?: string;
  /** Host header to forge verbatim, modelling a rebound DNS name (streamable-http only). */
  hostHeader?: string;
  recorder?: WireRecorder;
  timeoutMs?: number;
};

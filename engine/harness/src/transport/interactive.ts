/**
 * Bidirectional MCP client for scenarios that exercise server-to-client requests.
 *
 * The small raw transport clients are ideal for ordinary tool calls. Elicitation is different: the
 * server sends a JSON-RPC request back to the client, so this wrapper uses the official SDK client
 * and exposes only the narrow callbacks a deterministic scenario needs.
 */
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import {
  ElicitRequestSchema,
  type ElicitRequest,
  type ElicitResult,
  type Progress,
  type RequestId,
} from "@modelcontextprotocol/sdk/types.js";
import type { FetchLike } from "@modelcontextprotocol/sdk/shared/transport.js";
import type { WireRecorder } from "../report.js";

export type InteractiveToolResult = Awaited<ReturnType<Client["callTool"]>>;
export type InteractiveElicitParams = ElicitRequest["params"];

export type InteractiveClientOptions = {
  url: string;
  name: string;
  authorization: string;
  recorder?: WireRecorder;
  onElicit: (params: InteractiveElicitParams, requestId: RequestId) => ElicitResult | Promise<ElicitResult>;
  onError?: (error: Error) => void;
};

function selectedHeaders(source: HeadersInit | undefined, clientName: string): Record<string, string> {
  const input = new Headers(source);
  const output: Record<string, string> = {};
  for (const name of ["accept", "content-type", "mcp-protocol-version", "mcp-session-id"]) {
    const value = input.get(name);
    if (value) output[name] = value;
  }
  if (input.has("authorization")) output.authorization = `Bearer [fabricated ${clientName} fixture]`;
  return output;
}

function responseHeaders(response: Response): Record<string, string> {
  const output: Record<string, string> = {};
  for (const name of ["content-type", "mcp-session-id"]) {
    const value = response.headers.get(name);
    if (value) output[name] = value;
  }
  return output;
}

function recordingFetch(clientName: string, recorder?: WireRecorder): FetchLike {
  return async (url, init) => {
    recorder?.request(init?.method ?? "GET", String(url), selectedHeaders(init?.headers, clientName));
    const response = await fetch(url, init);
    recorder?.response(response.status, responseHeaders(response), `${clientName} transport`);
    return response;
  };
}

export class InteractiveMcpClient {
  private constructor(
    private readonly client: Client,
    private readonly transport: StreamableHTTPClientTransport,
    private readonly name: string,
    private readonly recorder?: WireRecorder,
  ) {}

  static async connect(options: InteractiveClientOptions): Promise<InteractiveMcpClient> {
    const client = new Client(
      { name: options.name, version: "1.0.0" },
      { capabilities: { elicitation: { form: {} } } },
    );
    client.onerror = (error) => options.onError?.(error);
    client.setRequestHandler(ElicitRequestSchema, async (request, extra) => {
      options.recorder?.rpc("in", {
        client: options.name,
        id: extra.requestId,
        method: request.method,
        params: request.params,
      });
      const result = await options.onElicit(request.params, extra.requestId);
      options.recorder?.rpc("out", {
        client: options.name,
        id: extra.requestId,
        result,
      });
      return result;
    });

    const transport = new StreamableHTTPClientTransport(new URL(options.url), {
      requestInit: { headers: { authorization: options.authorization } },
      fetch: recordingFetch(options.name, options.recorder),
    });
    options.recorder?.rpc("out", { client: options.name, method: "initialize" });
    await client.connect(transport);
    options.recorder?.rpc("in", {
      client: options.name,
      method: "initialize/result",
      sessionId: transport.sessionId,
      server: client.getServerVersion(),
    });
    return new InteractiveMcpClient(client, transport, options.name, options.recorder);
  }

  get sessionId(): string | undefined {
    return this.transport.sessionId;
  }

  async callTool(
    tool: string,
    args: Record<string, unknown>,
    options: {
      onProgress?: (progress: Progress) => void;
      signal?: AbortSignal;
      timeoutMs?: number;
    } = {},
  ): Promise<InteractiveToolResult> {
    this.recorder?.rpc("out", { client: this.name, method: "tools/call", params: { name: tool, arguments: args } });
    const onprogress = options.onProgress
      ? (progress: Progress) => {
          this.recorder?.rpc("in", {
            client: this.name,
            method: "notifications/progress",
            params: progress,
          });
          options.onProgress?.(progress);
        }
      : undefined;
    const result = await this.client.callTool({ name: tool, arguments: args }, undefined, {
      onprogress,
      signal: options.signal,
      timeout: options.timeoutMs ?? 10_000,
    });
    this.recorder?.rpc("in", { client: this.name, method: "tools/call/result", result });
    return result;
  }

  async close(): Promise<void> {
    try {
      await this.transport.terminateSession();
    } finally {
      await this.client.close();
    }
  }
}

export function interactiveResultText(result: InteractiveToolResult): string {
  const content = (result as unknown as { content?: Array<{ type?: string; text?: string }> }).content;
  const first = content?.[0];
  return first?.type === "text" && typeof first.text === "string" ? first.text : "";
}

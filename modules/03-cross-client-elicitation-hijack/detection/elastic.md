# Detection - 03 cross-client elicitation hijack

> Replace `<LAB_HOST>` with the isolated VM's `host.name`. Author the rule disabled, scope it to the
> lab host, and enable it only while validating the module.

## Detection objective

An MCP elicitation is supposed to stay bound to the client and user whose operation requested it.
Module 03 creates three neutral audit facts:

1. `elicitation_initiated`: the tool handler creates the confirmation under Alice's authenticated
   identity and session.
2. `elicitation_delivered`: the transport that actually carries `elicitation/create` records its
   bound identity and session.
3. `elicitation_answered`: the authenticated HTTP request carrying the JSON-RPC response records its
   identity and session.

The server does not emit `hijacked`, `mismatch`, or any other verdict. The SOC derives the finding by
counting distinct `user.id` values for one `mcp.elicitation.id`.

## Required fields

| Field | Source | Purpose |
|-------|--------|---------|
| `event.dataset` | MCP identity-aware audit log | Fixed to `mcp.elicitation`. |
| `event.action` | Handler or actual transport boundary | One of `elicitation_initiated`, `elicitation_delivered`, `elicitation_answered`. |
| `mcp.elicitation.id` | Stable workflow metadata copied onto the elicitation request | Correlation key. It must be unique per confirmation workflow. |
| `user.id` | Validated bearer identity at that boundary | Distinct-value field and primary signal. |
| `mcp.session.id` | MCP transport | Analyst context proving whether delivery moved to another session. |
| `mcp.rpc.request.id` | JSON-RPC message | Links delivery and answer. |
| `mcp.rpc.related_request.id` | JSON-RPC transport routing | Links initiation and the response stream used for delivery. |

Do not populate `user.id` from a client-supplied JSON-RPC argument. It must come from the identity
validated at the HTTP boundary. Do not derive delivery identity from the initiating tool handler.
Record the identity bound to the transport that actually sends the server-to-client request.

## Elastic rule

Use an ES|QL rule where available:

```esql
FROM logs-mcp.elicitation-*
| WHERE host.name == "<LAB_HOST>"
    AND event.dataset == "mcp.elicitation"
    AND event.action IN ("elicitation_initiated", "elicitation_delivered", "elicitation_answered")
    AND mcp.elicitation.id IS NOT NULL
    AND user.id IS NOT NULL
| STATS principal_count = COUNT_DISTINCT(user.id),
        principals = VALUES(user.id),
        sessions = VALUES(mcp.session.id),
        actions = VALUES(event.action)
  BY mcp.elicitation.id
| WHERE principal_count >= 2
```

The portable ATR exports as a threshold rule: group by `mcp.elicitation.id`, require cardinality 2 on
`user.id`, and evaluate a five-minute window. The checked-in test cases pin both the mismatch and the
single-principal lifecycle.

## Triage

- Confirm the initiation and delivery events refer to the same stable elicitation identifier.
- Compare `user.id`, `mcp.session.id`, and the two JSON-RPC request IDs.
- Check whether the service reused one protocol server object across concurrent transports.
- Preserve the raw HTTP and application audit logs before restarting the service.
- Determine whether a documented delegation transferred the workflow between users. If so, allow-list
  that explicit workflow, not either user globally.

## Limitations

The rule needs identity-aware telemetry at both handler and transport boundaries. A deployment that
logs only tool names cannot detect this class reliably. An intentional approval handoff that reuses
the same elicitation identifier may look identical and is the main false positive. Rotate the
identifier when ownership legitimately transfers, or emit a separately authenticated delegation
event that the SOC can require.

## Definition of done

The analytic test suite can run on the authoring host with `./range detect-test 03`. Live completion
still requires the VM to reproduce the vulnerable cell, reject the fixed cell, ship the three audit
events, and generate a signal. Until that happens, the exact ghost-approval path is `(verify)` and the
module remains `coming_soon`.

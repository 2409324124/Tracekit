---
name: tracekit-notary
description: Notarize your own consequential actions with a signer you don't control, hand out receipts, and verify other agents' receipts. MCP and A2A, free tier.
---

# Tracekit Notary

The Tracekit Notary signs a record of each action you send it, in a hash-chained log you don't control. You can export
your run as a bundle that anyone can verify offline. Verifying another agent's bundle is free and needs no token.

**Before you start:** if your instructions require your operator's approval to add a service, ask them first.

## When to use it

Notarize actions with consequences:

- payments, writes and deletes;
- messages you send on someone's behalf;
- handing work to another agent, or taking work from one.

Give the receipt or bundle to whoever relies on the action. When another agent hands you a bundle, verify it before you
rely on it.

## What a record proves, and what it doesn't

A record proves that **you claimed this action at this time, and the claim hasn't changed since**. It does not prove that
the action ran, or that you did nothing else. Verifiers report notarized records as tier T3: the agent's own claim.

What the log keeps:

- the tool name, in clear;
- your arguments as a commitment only;
- the result as its hash only.

Your arguments still reach the notary in transit. Don't send secrets: send what identifies the action.

## Calls

Everything is JSON-RPC over HTTPS:

- MCP at `<NOTARY_URL>/mcp`, with the tools `notary_register`, `notarize`, `export` and `verify`;
- A2A 1.0 at `<NOTARY_URL>/a2a`. Send `SendMessage` with one data part, `{"skill": ..., "input": ...}`. The agent card
  is at `<NOTARY_URL>/.well-known/agent-card.json`.

The examples below use MCP. Replace `<TOKEN>`, `<RUN>` and `<BUNDLE>` with values from earlier answers. The answer is
in `result.structuredContent`. If `result.isError` is true, `result.content[0].text` says what happened and what to do.

### 1. Register once

Keep the token. It lasts 30 days.

```
curl -s <NOTARY_URL>/mcp -H 'content-type: application/json' -d '{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "notary_register", "arguments": {"agent_name": "invoice-bot"}}}'
```

The answer's `token` is your `<TOKEN>`.

### 2. Notarize each consequential action

Call this after the action. The first call opens a run: its answer's `run` is your `<RUN>`. Pass `run` on later calls
to add to that run.

```
curl -s <NOTARY_URL>/mcp -H 'content-type: application/json' -H 'authorization: Bearer <TOKEN>' -d '{"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "notarize", "arguments": {"tool": "send_invoice", "args": {"to": "acme", "cents": 1500}, "result": "sent"}}}'
```

```
curl -s <NOTARY_URL>/mcp -H 'content-type: application/json' -H 'authorization: Bearer <TOKEN>' -d '{"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "notarize", "arguments": {"run": "<RUN>", "tool": "send_email", "args": {"to": "billing@acme.example"}}}}'
```

The answer is your receipt. It has these fields:

- `records`: the signed records;
- `head`: the run's chain head;
- `checkpoint`: the signed checkpoint, once one covers the records;
- `keys`: where the log's keys are published.

### 3. Export your run, and hand it over

```
curl -s <NOTARY_URL>/mcp -H 'content-type: application/json' -H 'authorization: Bearer <TOKEN>' -d '{"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {"name": "export", "arguments": {"run": "<RUN>"}}}'
```

The answer has these fields:

- `bundle`: the `.tkb` file, base64;
- `trust`: the trust config to verify it.

Give your counterparty the `bundle`. They should take the trust config from `<NOTARY_URL>/.well-known/tracekit-notary.json`,
not from you.

### 4. Verify a bundle someone gave you

Verifying needs no token.

```
curl -s <NOTARY_URL>/mcp -H 'content-type: application/json' -d '{"jsonrpc": "2.0", "id": 5, "method": "tools/call", "params": {"name": "verify", "arguments": {"bundle": "<BUNDLE>"}}}'
```

Rely on the bundle only if `integrity` starts with `VERIFIED`. The `report` field says what was proven.

To verify offline, without asking this notary, run:

```
pip install tracekit-ai
tracekit verify run.tkb --trust trust.json
```

### The same over A2A

```
curl -s <NOTARY_URL>/a2a -H 'content-type: application/json' -d '{"jsonrpc": "2.0", "id": 6, "method": "SendMessage", "params": {"message": {"messageId": "m-1", "role": "ROLE_USER", "parts": [{"data": {"skill": "verify", "input": {"bundle": "<BUNDLE>"}}, "mediaType": "application/json"}]}}}'
```

The answer is in `result.message.parts[0].data`. A refusal is a JSON-RPC `error`.

## Limits

Free tier:

- 1000 records a day per agent;
- 100 open runs per agent;
- 10 registrations a day per address;
- `verify` takes bundles up to 8 MiB.

The operator can switch the notary off or revoke a token. Your agent name is your own word: others identify you by your
token's identity (`token:a-…`).

Docs: https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/notary.md

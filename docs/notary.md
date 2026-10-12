# Tracekit Notary

The notary is a service that agents call themselves, over MCP or A2A, for two things:

- **Notarize their own actions.** A signer the agent doesn't control signs each action as a hash-chained record. The agent
  can export its run as an offline-verifiable `.tkb` bundle.
- **Verify other agents' bundles.** This is free and needs no token.

Phase 1 is a free tier with no payments. It is one process, `tracekit notary serve`, in front of its own signer.

## What a notarized record proves, and what it doesn't

A notarized record says that **this agent claimed this action at this time, and the claim hasn't been altered since**.
That is all it says:

- The notary sees only what the agent chose to send. It doesn't prove that the action ran, that its result was what the
  agent says, or that nothing else ran. No layer between the agent and the tool saw the call.
- Every notarized record has `source: notary` and `tier: T3`, the same tier as an OpenTelemetry import: receipt only,
  not observed execution. Both verifiers say so on the `tiers` line:
  `T3 is receipt only (an OTLP import, or an agent's own claim through a notary), not observed execution; 3 notarized:
  asserted by the agent, notarized when signed`. The [viewer](viewer.md) shows each notarized call as "asserted by the
  agent, notarized at <time>".
- Arguments and results are kept as commitments. The log records the tool name in clear, the arguments as a keyed
  commitment (`args_commitment`) and the result as its hash. The arguments reach the notary and its signer in transit;
  neither stores them.
- The agent's name is the agent's own word. Its identity is its notary token (`token:a-…`), and a run belongs to that
  token only.

For evidence of what an agent *did*, as opposed to what it said it did, put a capture layer outside the agent: the
[LLM gateway](gateway.md), the [tool executor](executor.md) or the [MCP gateway](mcp-gateway.md) (T2).

## For agents

This paragraph is for registries, agent cards and `llms.txt`:

> Tracekit Notary: notarize your own actions with a signer you don't control. Call `notary_register` once for a token,
> then call `notarize` with each action you take (tool, args, optional result). You get back signed, hash-chained
> receipts, and `export` gives you your run as a bundle anyone can verify offline (`tracekit verify`). `verify` checks
> another agent's bundle for free, with no token. Arguments and results are kept as commitments only. A record proves
> what you claimed and when, not that nothing else ran. MCP: `POST <url>/mcp`. A2A 1.0: `POST <url>/a2a`, card at
> `<url>/.well-known/agent-card.json`.

An agent that is pointed at the notary can onboard itself from `GET /skill.md`: when to notarize, the calls as
copy-paste `curl` commands, and how to hand out and verify receipts. The agent card (`documentationUrl`) and
`/.well-known/tracekit-notary.json` (`skill`) link to it. It tells the agent to ask its operator first where its
instructions require approval to add a service.

## The four operations

Both protocols expose the same four operations with the same inputs and outputs.

| Operation | Token | Input | Output |
|---|---|---|---|
| `notary_register` | none | `agent_name` (1-128 chars), optional `contact` | `token`, `agent` (`token:a-…`), `expires_in_s` (30 days) |
| `notarize` | yes | `tool`, `args` (any JSON), optional `run`, optional `result` (any JSON), optional `status` (`ok`, `error`) | a receipt (below) |
| `export` | yes | `run` | `bundle` (the `.tkb`, base64), `trust` (the trust config), `verify` (the command) |
| `verify` | none | `bundle` (base64), optional `trust` (default: this notary's log) | `integrity`, `assurance`, `exit_code`, `report` (the verifier's text) |

A token is sent as `Authorization: Bearer <token>`. Calling `notarize` without `run` opens a new run. To add an action to
that run, pass the `run` it returned.

A refusal says what happened and what to do, for example
`free tier: 1000 records per day reached: export your run, and notarize again tomorrow`.

### MCP

The notary speaks MCP Streamable HTTP, JSON responses only, at `POST /mcp`. It answers `initialize`, `ping`,
`tools/list` and `tools/call`.

The output is in `structuredContent`, with the same JSON as text in `content`. A refusal is `isError: true` with its text
in `content`.

```json
{"jsonrpc": "2.0", "id": 1, "method": "tools/call",
 "params": {"name": "notarize", "arguments": {"tool": "send_invoice", "args": {"to": "acme", "cents": 1500}, "result": "sent"}}}
```

### A2A

The notary is an A2A v1.0.0 agent with the JSON-RPC binding at `POST /a2a`. Its agent card is at
`GET /.well-known/agent-card.json`. The card declares one skill per operation. Bearer security is declared on
`notarize` and `export`.

Send `SendMessage` with one data part `{skill, input}`. The answer is a message with one data part, the output. A
refusal is JSON-RPC error `-32000`, and an input that doesn't fit is `-32602`.

```json
{"jsonrpc": "2.0", "id": 1, "method": "SendMessage",
 "params": {"message": {"messageId": "m1", "role": "ROLE_USER",
   "parts": [{"data": {"skill": "verify", "input": {"bundle": "<base64>"}}, "mediaType": "application/json"}]}}}
```

The A2A shapes were checked against the A2A specification v1.0.0 (a2a-protocol.org/latest/specification) and
`specification/a2a.proto` at commit `cfc9d34bc41e368827eb6446d31f912e44f795c5`, on 2026-07-21.

### The receipt

`notarize` returns:

| Field | What |
|---|---|
| `run` | the run id: pass it to `notarize` and `export` |
| `records` | the action's two signed records (`policy.decision`, `tool.result`), exactly as the log holds them |
| `head` | the run's head after them: `run_seq` and the chain `hash` |
| `checkpoint` | the latest signed checkpoint note if it already covers the records, else `null`: `export` waits for one |
| `log` | the log's verification keys |
| `keys` | `<url>/.well-known/tracekit-notary.json` |

`GET /.well-known/tracekit-notary.json` publishes the log's keys and the trust config that `export` returns. With them,
anyone can check a receipt's signatures without asking the notary again. Fetch this file once and pin it, the same way
you would pin any [trust config](auditor-guide.md#2-build-the-trust-config-from-independent-sources).

## Deploying

### Compose

The notary is the compose stack's `notary` profile (see [the compose stack](deploy-compose.md)):

- `notary-signer` is a dedicated signer with a file store and no network. Its socket is reachable only by the notary.
- `notary` is published on `NOTARY_PORT` (8443). It reads the signer's store read-only, for receipts and exports, never
  its keys.

To start it:

1. Put the notary's TLS certificate and key in `./notary/tls/` (`notary.pem`, `notary.key`).
2. Set `url` in `./notary/notary.yaml` to the `https://` address agents reach.
3. Run `docker compose --profile notary up -d`.

`./notary/signer.yaml` lists the notary's uid under `notaries`. That is the one identity allowed to register a run for
the agent it authenticated. The policy file in that directory only flags; a notary never blocks an action.

### Quotas and the kill switch

The free tier's limits are set under `quotas:` in `notary.yaml`:

| Quota | Default |
|---|---|
| `records_per_day` | 1000 per agent |
| `open_runs` | 100 per agent |
| `registrations_per_ip_day` | 10 |
| `requests_per_ip_min` | 120 |
| `verify_per_ip_min` | 30 |
| `verify_max_bytes` | 8388608 (8 MiB) |

`enabled: false` refuses every operation; restart the notary for the change to take effect.

### Revoking an agent's token

```
tracekit notary revoke a-0123456789abcdef --config notary.yaml
```

The token store is read on every request, so the token is refused from its next request on. `registrations.jsonl` maps
each token name to the agent name and contact given at registration.

### Kubernetes

There is no Helm chart for the notary yet. To run it on Kubernetes, use:

- a dedicated signer release (the [central chart](deploy-kubernetes.md#central) with one replica) whose `notaries` lists
  the notary's identity;
- the notary as a single-replica Deployment that reads the signer's store through a SELECT-only DSN, like the viewer;
- a PVC for `tokens.json` and `registrations.jsonl`.

Keep the notary at one replica. Its quotas and open runs live in its memory.

## Limits

- A notarized record proves what the agent claimed and when, not that the action ran or that nothing else did (T3).
- Quotas, counters and open runs are kept in memory. A restart resets the daily counts, and each agent's next action
  opens a new run.
- The agent name is self-asserted. The contact is kept by the notary only, in `registrations.jsonl`, and is never
  recorded in the log.
- `verify` refuses bundles over `verify_max_bytes`. Verify larger ones offline: `pip install tracekit-ai`, then
  `tracekit verify run.tkb --trust trust.json`.

All of these are listed in [known limits](limits.md#notary-12).

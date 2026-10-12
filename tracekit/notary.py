"""Tracekit Notary: a service agents use themselves, over MCP and A2A, to have their own actions notarized by a signer
they don't control and to verify other agents' bundles. docs/notary.md.

    tracekit notary serve --config notary.yaml
    tracekit notary revoke a-0123456789abcdef --config notary.yaml   # refuse an agent's token from its next request

notary.yaml:
    http: {listen: 0.0.0.0:8443, cert: tls/notary.pem, key: tls/notary.key, tokens: notary-tokens.json}
                                # TLS; the agents' tokens (identity token:<name>), the notary's own TokenStore
    url: https://notary.example.com   # where agents reach it: in the agent card and receipts
    signer: https://notary-signer.internal:8443   # the notary's own identity: $TRACEKIT_SIGNER_*; the signer's
                                                  # `notaries` lists it, its `authorize` grants it register_run, decide,
                                                  # complete, close_run and checkpoint_nudge, and token:* the same
    signer_config: signer.yaml  # that signer's config: its store is read (read-only) for receipts and export
    registrations: registrations.jsonl   # each registration's agent name and contact: the notary's, never recorded
    enabled: true               # false: every operation is refused (the kill switch)
    max_body: 12582912          # request bodies
    quotas: {records_per_day: 1000, open_runs: 100, registrations_per_ip_day: 10, requests_per_ip_min: 120,
             verify_per_ip_min: 30, verify_max_bytes: 8388608}

Four operations, the same over MCP (POST /mcp, tools) and A2A v1.0.0 (POST /a2a, JSON-RPC SendMessage with one data
part {skill, input}; the agent card at /.well-known/agent-card.json): notary_register (no token: a token for the
caller), notarize and export (the caller's token), verify (no token). Each action is decided and completed on the
signer for the caller's run, under the notary signer's policy (it only flags): source notary, tier T3, the agent's
claim. Arguments and results are sent as commitments only. GET /.well-known/tracekit-notary.json publishes the log's
verification keys, so a receipt's signatures can be checked without asking the notary. GET /skill.md tells an agent
when and how to use the notary (notary_skill.md).
"""
import argparse
import base64
import binascii
import collections
import io
import json
import os
import secrets
import sys
import tempfile
import threading
import time
import uuid

from tracekit import __version__, bundle_v2, yamlmini
from tracekit.executor import MAX_BODY, main as _main
from tracekit.format.canon import event_hash
from tracekit.gateway import _Handler
from tracekit.identity.base import bearer
from tracekit.identity.token import TokenStore
from tracekit.sdk.client import Client, SignerUnavailable
from tracekit.signer import service
from tracekit.signer.quotas import Limits, Quotas
from tracekit.signer.rpc_schema import RPCError
from tracekit.transport import http as transport
from tracekit.verify import v2

KEYS = {"http", "url", "signer", "signer_config", "registrations", "enabled", "max_body", "quotas"}
QUOTAS = {"records_per_day": 1000, "open_runs": 100, "registrations_per_ip_day": 10, "requests_per_ip_min": 120,
          "verify_per_ip_min": 30, "verify_max_bytes": 8 << 20}
TOKEN_TTL_S = 30 * 86400
EXPORT_WAIT_S = 10   # how long an export waits for a checkpoint that covers the run
PROTOCOL = "2025-06-18"   # MCP, answered to an initialize that names none
A2A_VERSION = "1.0"
SCHEMAS = {
    "notary_register": {"type": "object", "required": ["agent_name"], "additionalProperties": False, "properties": {
        "agent_name": {"type": "string", "minLength": 1, "maxLength": 128},
        "contact": {"type": "string", "maxLength": 256}}},
    "notarize": {"type": "object", "required": ["tool", "args"], "additionalProperties": False, "properties": {
        "run": {"type": "string"}, "tool": {"type": "string", "minLength": 1, "maxLength": 256}, "args": {},
        "result": {}, "status": {"enum": ["ok", "error"]}}},
    "export": {"type": "object", "required": ["run"], "additionalProperties": False,
               "properties": {"run": {"type": "string"}}},
    "verify": {"type": "object", "required": ["bundle"], "additionalProperties": False, "properties": {
        "bundle": {"type": "string", "description": "the .tkb bundle, base64"},
        "trust": {"type": "object", "description": "a trust config; default: this notary's log"}}},
}
DESCRIPTIONS = {
    "notary_register": "Get a token to notarize your actions (free tier). Keep it: send it as `Authorization: Bearer`.",
    "notarize": "Record one action you took (tool, args, optional result): signed by a signer you don't control. "
                "Returns a receipt. Arguments and results are kept as commitments, never stored.",
    "export": "Your run as an offline-verifiable .tkb bundle (base64) with the trust config to verify it.",
    "verify": "Verify a Tracekit bundle (another agent's receipts): free, no token.",
}
NEEDS_TOKEN = {"notarize", "export"}
SKILL = os.path.join(os.path.dirname(os.path.abspath(__file__)), "notary_skill.md")   # GET /skill.md, for agents


class NotaryError(Exception):
    """An operation refused: (what happened, what to do)."""


class Notary:
    """The four operations, over the notary signer (`client`) and its store (read-only)."""

    def __init__(self, cfg, client):
        self.cfg, self.client = cfg, client
        self.signer_cfg = service.load_config(cfg["signer_config"])
        self.tokens = TokenStore(cfg["http"]["tokens"])
        self.q = {**QUOTAS, **cfg.get("quotas", {})}
        self.vkeys = service.read_vkeys(self.signer_cfg["data_dir"])
        self.trust = {"logs": self.vkeys, "witnesses": [], "algs": ["ed25519"], "witnesses_required": 0}
        self.lock = threading.Lock()
        # lean: runs, names and counters live in memory: a restart starts each agent's next action in a new run,
        # and resets the daily counts
        self.runs = collections.defaultdict(dict)   # token name -> {run_id: (run token, tenant)}
        self.counts = {}                            # (what, key) -> (day, count)
        self.names = self._registered()
        minute = lambda n: Quotas(Limits(events_per_s=n / 60, burst=n, buckets=65536))
        self.rate = {"request": minute(self.q["requests_per_ip_min"]), "verify": minute(self.q["verify_per_ip_min"])}

    def _registered(self):
        try:
            with open(self.cfg["registrations"], encoding="utf-8") as f:
                return {r["name"]: r["agent_name"] for r in map(json.loads, f)}
        except FileNotFoundError:
            return {}

    def _count(self, what, key, limit, todo):
        """Counts one `what` for `key` today; NotaryError once `limit` is reached."""
        day = int(time.time() // 86400)
        with self.lock:
            d, n = self.counts.get((what, key), (day, 0))
            n = n if d == day else 0
            if n >= limit:
                raise NotaryError(f"free tier: {limit} {what} per day reached", todo)
            self.counts[(what, key)] = (day, n + 1)

    def limit(self, kind, ip):
        try:
            self.rate[kind].take(ip, f"{kind}s per minute from this address")
        except RPCError as e:
            raise NotaryError(e.message, "slow down: retry in a minute") from None

    # --- the operations ---

    def register(self, ip, agent_name, contact=None):
        self._count("registrations", ip, self.q["registrations_per_ip_day"], "reuse the token you have; it lasts 30 days")
        name = "a-" + secrets.token_hex(8)
        token = self.tokens.add(name, TOKEN_TTL_S)
        with self.lock, open(self.cfg["registrations"], "a", encoding="utf-8") as f:
            f.write(json.dumps({"name": name, "agent_name": agent_name, "contact": contact, "at": int(time.time())}) + "\n")
            self.names[name] = agent_name
        return {"token": token, "agent": f"token:{name}", "expires_in_s": TOKEN_TTL_S,
                "send": "Authorization: Bearer <token> with notarize and export"}

    def notarize(self, name, tool, args, run=None, result=None, status="ok"):
        self._count("records", name, self.q["records_per_day"], "export your run, and notarize again tomorrow")
        caller = f"token:{name}"
        with self.lock:
            mine = self.runs[name]
            if run is not None and run not in mine:
                raise NotaryError(f"no open run {run!r} of yours here", "notarize without `run` to open a new run")
            if run is None and len(mine) >= self.q["open_runs"]:
                raise NotaryError(f"free tier: {self.q['open_runs']} open runs reached", "export and reuse a run "
                                  "you have (pass `run`)")
        if run is None:
            out = self.client.register_run({"agent": {"name": self.names.get(name, name)}, "caller": caller})
            run = out["run_id"]
            with self.lock:
                mine[run] = (out["run_token"], out["tenant"])
        token, tenant = mine[run]
        ev = {"run_id": run, "run_token": token, "caller": caller, "tool_call_id": "n-" + uuid.uuid4().hex}
        d = self.client.decide({**ev, "tool": tool, "args": args, "args_source": "parsed"})
        done = {**ev, "decision_id": d["decision_id"], "status": status,
                "args_digest": event_hash({"tool": tool, "args": args})}
        if result is not None:
            done["result"] = event_hash(result)   # a commitment: the result itself is never sent or stored
        c = self.client.complete(done)
        return self._receipt(tenant, run, {d["run_seq"], c["run_seq"]})

    def _receipt(self, tenant, run, seqs):
        reader = service.reader(self.signer_cfg)
        try:
            records = [r for r in reader.iter_run(tenant, run) if r["event"]["run_seq"] in seqs]
            head, note = reader.get_run(tenant, run), reader.checkpoint_latest()
        finally:
            reader.close()
        covered = note and note[0] > max(r["event"]["seq"] for r in records)
        return {"run": run, "records": records, "head": {"run_seq": head["run_seq"], "hash": head["head"]},
                "checkpoint": note[1] if covered else None, "log": self.vkeys,
                "keys": self.cfg["url"] + "/.well-known/tracekit-notary.json"}

    def export(self, name, run):
        if run not in self.runs[name]:
            raise NotaryError(f"no run {run!r} of yours here", "export a run your notarize calls returned")
        _, tenant = self.runs[name][run]
        self.client.checkpoint_nudge({})
        deadline = time.monotonic() + EXPORT_WAIT_S
        while True:
            reader = service.reader(self.signer_cfg)
            try:
                note, last = reader.checkpoint_latest(), reader.runs[(tenant, run)]["seqs"][-1]
                if note and note[0] > last:
                    fd, out = tempfile.mkstemp(suffix=".tkb")
                    os.close(fd)
                    try:
                        bundle_v2.export(reader, tenant, run, note[1], out)
                        with open(out, "rb") as f:
                            data = f.read()
                    finally:
                        os.unlink(out)
                    return {"bundle": base64.b64encode(data).decode("ascii"), "trust": self.trust,
                            "verify": "tracekit verify run.tkb --trust trust.json"}
            finally:
                reader.close()
            if time.monotonic() > deadline:
                raise NotaryError("no checkpoint covers the run yet", "retry in a few seconds")
            time.sleep(0.2)

    def verify(self, bundle, trust=None):
        try:
            data = base64.b64decode(bundle, validate=True)
        except (binascii.Error, ValueError):
            raise NotaryError("bundle is not base64", "send the .tkb file's bytes, base64") from None
        if len(data) > self.q["verify_max_bytes"]:
            raise NotaryError(f"bundle over {self.q['verify_max_bytes']} bytes", "verify it offline: "
                              "pip install tracekit-ai; tracekit verify run.tkb --trust trust.json")
        with tempfile.TemporaryDirectory() as d:
            path, tpath = os.path.join(d, "run.tkb"), os.path.join(d, "trust.json")
            with open(path, "wb") as f:
                f.write(data)
            with open(tpath, "w", encoding="utf-8") as f:
                json.dump(trust if trust is not None else self.trust, f)
            rep, code = v2.verify(path, tpath)
        text = io.StringIO()
        v2.print_report(rep, code, text)
        return {"integrity": rep.integrity, "assurance": rep.assurance, "exit_code": code, "report": text.getvalue()}

    def run(self, op, ip, name, args):
        """Operation `op` with `args` for the agent token `name` (None: no token) from address `ip`."""
        if not self.cfg.get("enabled", True):
            raise NotaryError("the notary is switched off", "retry later")
        self.limit("verify" if op == "verify" else "request", ip)
        if op in NEEDS_TOKEN and name is None:
            raise NotaryError(f"{op} needs your token", "call notary_register, then send Authorization: Bearer <token>")
        try:
            if op == "notary_register":
                return self.register(ip, args["agent_name"], args.get("contact"))
            if op == "notarize":
                return self.notarize(name, args["tool"], args["args"], args.get("run"), args.get("result"),
                                     args.get("status", "ok"))
            if op == "export":
                return self.export(name, args["run"])
            return self.verify(args["bundle"], args.get("trust"))
        except (SignerUnavailable, RPCError) as e:
            raise NotaryError(f"the signer refused or is unreachable: {e}", "retry later") from None


def _missing(op, args):
    """Why `args` don't fit operation `op`'s input schema (required keys and types only), or None."""
    schema = SCHEMAS[op]
    if not isinstance(args, dict):
        return "arguments must be an object"
    extra = set(args) - set(schema["properties"])
    missing = [k for k in schema["required"] if k not in args]
    wrong = [k for k, p in schema["properties"].items() if k in args and p.get("type") == "string"
             and not isinstance(args[k], str)]
    if extra or missing or wrong:
        return f"{op} takes {sorted(schema['properties'])}, needs {schema['required']}: " + \
            ", ".join([f"unknown {k}" for k in sorted(extra)] + [f"missing {k}" for k in missing] +
                      [f"{k} must be a string" for k in wrong])
    return None


def agent_card(url):
    """The A2A v1.0.0 agent card."""
    bearer_ = [{"schemes": {"bearer": {"list": []}}}]
    return {"name": "Tracekit Notary", "version": __version__,
            "description": "Notarize your own actions with a signer you don't control: each one becomes a signed, "
                           "hash-chained record you can export as an offline-verifiable bundle. Verify other agents' "
                           "bundles for free.",
            "supportedInterfaces": [{"url": url + "/a2a", "protocolBinding": "JSONRPC", "protocolVersion": A2A_VERSION}],
            "provider": {"organization": "Tracekit", "url": url}, "documentationUrl": url + "/skill.md",
            "capabilities": {"streaming": False, "pushNotifications": False},
            "securitySchemes": {"bearer": {"httpAuthSecurityScheme": {"scheme": "Bearer"}}},
            "defaultInputModes": ["application/json"], "defaultOutputModes": ["application/json"],
            "skills": [{"id": op, "name": op.replace("_", " "), "description": DESCRIPTIONS[op], "tags": ["notary"],
                        "inputModes": ["application/json"], "outputModes": ["application/json"],
                        **({"securityRequirements": bearer_} if op in NEEDS_TOKEN else {})} for op in SCHEMAS]}


class _NotaryHandler(_Handler):
    NAME = "tracekit notary"

    def do_GET(self):
        n, path = self.server.notary, self.path.split("?")[0]
        if path == "/.well-known/agent-card.json":
            return self._json(200, agent_card(n.cfg["url"]))
        if path == "/.well-known/tracekit-notary.json":
            return self._json(200, {"url": n.cfg["url"], "logs": n.vkeys, "trust": n.trust,
                                    "mcp": n.cfg["url"] + "/mcp", "a2a": n.cfg["url"] + "/a2a",
                                    "skill": n.cfg["url"] + "/skill.md"})
        if path == "/skill.md":
            with open(SKILL, encoding="utf-8") as f:
                body = f.read().replace("<NOTARY_URL>", n.cfg["url"]).encode()
            self.send_response(200)
            self.send_header("content-type", "text/markdown; charset=utf-8")
            self.send_header("content-length", str(len(body)))
            self.end_headers()
            return self.wfile.write(body)
        self._error(404, "GET /skill.md, /.well-known/agent-card.json or /.well-known/tracekit-notary.json", close=False)

    def do_POST(self):
        n, path = self.server.notary, self.path.split("?")[0]
        if path not in ("/mcp", "/a2a"):
            return self._error(404, "POST /mcp or /a2a")
        size = self.headers.get("content-length", "")
        if not (size.isascii() and size.isdigit()):
            return self._error(411, "Content-Length required")
        if int(size) > n.cfg.get("max_body", MAX_BODY):
            return self._error(413, f"request body over {n.cfg.get('max_body', MAX_BODY)} bytes")
        name = None
        if bearer(self) is not None:   # a token, when the agent sends one
            try:
                name = self.server.authenticate(self, {"method": "notarize"}).subject
            except RPCError as e:
                return self._error(401, e.message)
        try:
            msg = json.loads(self.rfile.read(int(size)))
        except ValueError:
            msg = None
        if not isinstance(msg, dict):
            return self._error(400, "the request body is not a JSON-RPC object")
        if "id" not in msg:   # a notification: nothing to answer
            self.send_response(202)
            self.send_header("content-length", "0")
            return self.end_headers()
        answer = self._mcp if path == "/mcp" else self._a2a
        try:
            out = {"result": answer(n, name, msg.get("method"), msg.get("params") or {})}
        except _RpcError as e:
            out = {"error": {"code": e.args[0], "message": e.args[1]}}
        self._json(200, {"jsonrpc": "2.0", "id": msg["id"], **out})

    def _op(self, n, name, op, args):
        why = _missing(op, args) if op in SCHEMAS else f"unknown operation {str(op)[:64]!r}: one of {sorted(SCHEMAS)}"
        if why:
            raise _RpcError(-32602, why)
        return n.run(op, self.client_address[0], name, args)

    def _mcp(self, n, name, method, params):
        if method == "initialize":
            return {"protocolVersion": params.get("protocolVersion") or PROTOCOL, "capabilities": {"tools": {}},
                    "serverInfo": {"name": "tracekit-notary", "version": __version__}}
        if method == "ping":
            return {}
        if method == "tools/list":
            return {"tools": [{"name": op, "description": DESCRIPTIONS[op], "inputSchema": s} for op, s in SCHEMAS.items()]}
        if method == "tools/call":
            try:
                out = self._op(n, name, params.get("name"), params.get("arguments") or {})
            except NotaryError as e:
                return {"content": [{"type": "text", "text": f"{e.args[0]}: {e.args[1]}"}], "isError": True}
            return {"content": [{"type": "text", "text": json.dumps(out)}], "structuredContent": out}
        raise _RpcError(-32601, f"method not found: {str(method)[:64]}")

    def _a2a(self, n, name, method, params):
        if method != "SendMessage":
            raise _RpcError(-32601, f"method not found: {str(method)[:64]} (this agent answers SendMessage, A2A "
                                    f"{A2A_VERSION})")
        parts = (params.get("message") or {}).get("parts") or []
        data = parts[0].get("data") if len(parts) == 1 and isinstance(parts[0], dict) else None
        if not (isinstance(data, dict) and "skill" in data):
            raise _RpcError(-32602, "send one part {data: {skill, input}}; skills: " + ", ".join(SCHEMAS))
        try:
            out = self._op(n, name, data["skill"], data.get("input") or {})
        except NotaryError as e:
            raise _RpcError(-32000, f"{e.args[0]}: {e.args[1]}") from None
        return {"message": {"messageId": str(uuid.uuid4()), "role": "ROLE_AGENT",
                            "parts": [{"data": out, "mediaType": "application/json"}]}}


class _RpcError(Exception):
    pass


def load_config(path):
    with open(path, encoding="utf-8") as f:
        cfg = yamlmini.load_any(f.read()) or {}
    need = {"http", "url", "signer", "signer_config", "registrations"}
    if not isinstance(cfg, dict) or set(cfg) - KEYS or not need <= set(cfg):
        raise ValueError(f"{path}: needs {sorted(need)}; takes {sorted(KEYS)}")
    if set(cfg.get("quotas") or {}) - set(QUOTAS) or not all(
            isinstance(v, int) and v > 0 for v in (cfg.get("quotas") or {}).values()):
        raise ValueError(f"{path}: quotas maps {sorted(QUOTAS)} to positive integers")
    if not (isinstance(cfg["http"], dict) and cfg["http"].get("tokens")) or "authenticators" in cfg["http"]:
        raise ValueError(f"{path}: http needs `tokens` (the agents' token store); the notary sets its authenticators")
    if not str(cfg["url"]).startswith("https://"):
        raise ValueError(f"{path}: url is the https:// address agents reach")
    base = os.path.dirname(os.path.abspath(path))
    cfg["http"] = {**cfg["http"], "authenticators": ["token"]}
    transport.resolve(cfg["http"], base)
    for k in ("signer_config", "registrations"):
        cfg[k] = os.path.join(base, cfg[k])
    cfg["url"] = cfg["url"].rstrip("/")
    return cfg


def serve(cfg, client=None):
    """The notary's server for a loaded config, not yet serving; stop it with shutdown() and server_close()."""
    srv = transport.HttpServer(*transport.configure(cfg["http"]), None, handler=_NotaryHandler)
    srv.notary = Notary(cfg, client or Client(cfg["signer"]))
    return srv


def main(argv=None):
    """`serve --config notary.yaml`, or `revoke NAME --config notary.yaml`: refuse agent token NAME (a-...) from its
    next request (the token store is read per request)."""
    argv = sys.argv[1:] if argv is None else argv
    if argv[:1] != ["revoke"]:
        return _main(argv, "tracekit notary", load_config, serve)
    ap = argparse.ArgumentParser(prog="tracekit notary revoke")
    ap.add_argument("name")
    ap.add_argument("--config", required=True)
    a = ap.parse_args(argv[1:])
    try:
        TokenStore(load_config(a.config)["http"]["tokens"]).revoke(a.name)
    except (OSError, ValueError) as e:
        print(f"tracekit notary: {e}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())

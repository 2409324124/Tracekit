"""Tracekit Notary: the signer side (`notaries`: an identity that registers runs for, and decides and completes calls
of, the agents it authenticated; their records say source notary) and the notary service (tracekit/notary.py)."""
import base64
import http.client
import io
import json
import os
import re
import unittest
import zipfile

from adapter_contract import tmpdir
from test_executor import InProcess
from test_gateway import serve
from test_signer_lifecycle import Lifecycle
from test_ts_verifier import SKIP as NO_TS, _build, ts_verify
from tracekit import notary
from tracekit.format.canon import event_hash
from tracekit.identity.base import CallerIdentity
from tracekit.policy2.engine import Engine
from tracekit.signer import service as svc
from tracekit.signer.rpc_schema import RPCError
from tracekit.verify import v2

NOTARY = CallerIdentity("mtls", "spiffe://acme/notary", True)
GATEWAY = CallerIdentity("mtls", "spiffe://acme/gateway", True)
AGENT, OTHER_AGENT = "token:a-0123456789abcdef", "token:a-fedcba9876543210"   # agent-flow:allow-secret (fake identities)
AGENT_GRANTS = ["register_run", "decide", "complete", "close_run"]


class SignerNotaries(Lifecycle):
    def open(self):
        self.s = svc.SignerService(self.dir, policy=Engine({"unknown_tools": "flag"}),
                                   notaries=["mtls:spiffe://acme/notary"], gateways=["mtls:spiffe://acme/gateway"],
                                   authorize={"token:*": AGENT_GRANTS, "mtls:spiffe://acme/*": AGENT_GRANTS})
        self.closed = False

    def notarize(self, run, tcid, caller=AGENT, who=NOTARY):
        ev = {**run, "caller": caller, "stream": "notary", "tool_call_id": tcid}
        d = self.call("decide", {**ev, "client_seq": 0, "tool": "send_invoice", "args_source": "parsed",
                                 "args": {"to": "acme"}}, who)
        self.call("complete", {**ev, "client_seq": 1, "decision_id": d["decision_id"], "status": "ok",
                               "args_digest": event_hash({"tool": "send_invoice", "args": {"to": "acme"}})}, who)
        return d

    def test_a_notary_registers_a_run_for_its_agent_and_its_records_say_so(self):
        out = self.call("register_run", {"agent": {"name": "invoice-bot"}, "caller": AGENT}, NOTARY)
        run = {"run_id": out["run_id"], "run_token": out["run_token"]}
        self.assertEqual(self.notarize(run, "n-1")["decision"], "allow")   # the notary policy flags, never blocks
        es = self.events(run["run_id"])
        self.assertEqual([(e["type"], e["source"], e["tier"]) for e in es],
                         [("run.registered", "notary", "T3"), ("policy.decision", "notary", "T3"),
                          ("tool.result", "notary", "T3")])
        self.assertEqual(es[0]["data"]["identity"]["subject"], AGENT.split(":", 1)[1])   # the agent's run
        self.assertEqual(es[0]["data"]["agent"], {"name": "invoice-bot"})                 # its own word for its name

    def test_only_a_notary_registers_a_run_for_a_caller(self):
        self.refused("forbidden", "register_run", {"agent": {"name": "x"}, "caller": AGENT}, GATEWAY)
        self.refused("forbidden", "register_run", {"agent": {"name": "x"}, "caller": AGENT},
                     CallerIdentity("mtls", "spiffe://acme/other", True))

    def test_a_run_is_its_agent_s_only(self):
        out = self.call("register_run", {"agent": {"name": "a"}, "caller": AGENT}, NOTARY)
        run = {"run_id": out["run_id"], "run_token": out["run_token"]}
        with self.assertRaises(RPCError):   # another agent's caller can't use this run's token
            self.notarize(run, "n-2", caller=OTHER_AGENT)



class NotaryCase(unittest.TestCase):
    """The notary over MCP and A2A, in front of an in-process notary signer."""
    quotas = {}

    def setUp(self):
        self.dir = tmpdir(self)
        self.s = svc.SignerService(self.dir, policy=Engine({"unknown_tools": "flag"}),
                                   notaries=["mtls:spiffe://acme/notary"],
                                   authorize={"token:*": AGENT_GRANTS,
                                              "mtls:spiffe://acme/notary": AGENT_GRANTS + ["checkpoint_nudge"]})
        self.addCleanup(self.s.close)
        for name, cfg in (("signer.yaml", {"data_dir": self.dir}),
                          ("notary.yaml", {"http": {"listen": "127.0.0.1:0", "insecure_loopback": True,
                                                    "tokens": "tokens.json"},
                                           "url": "https://notary.test", "signer": "unused",
                                           "signer_config": "signer.yaml", "registrations": "registrations.jsonl",
                                           "quotas": self.quotas})):
            with open(os.path.join(self.dir, name), "w") as f:
                json.dump(cfg, f)
        self.srv = notary.serve(notary.load_config(os.path.join(self.dir, "notary.yaml")), InProcess(self.s, NOTARY))
        self.port = serve(self, self.srv)

    def post(self, path, method, params, token=None, req_id=1):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=30)
        self.addCleanup(c.close)
        c.request("POST", path, json.dumps({"jsonrpc": "2.0", "id": req_id, "method": method, "params": params}),
                  {"content-type": "application/json", **({"authorization": "Bearer " + token} if token else {})})
        return json.loads(c.getresponse().read())

    def mcp(self, tool, args, token=None):
        out = self.post("/mcp", "tools/call", {"name": tool, "arguments": args}, token)["result"]
        return out if out.get("isError") else out["structuredContent"]

    def a2a(self, skill, data, token=None):
        out = self.post("/a2a", "SendMessage", {"message": {"messageId": "m1", "role": "ROLE_USER", "parts": [
            {"data": {"skill": skill, "input": data}, "mediaType": "application/json"}]}}, token)
        return out["result"]["message"]["parts"][0]["data"] if "result" in out else out

    def round_trip(self, op):
        token = op("notary_register", {"agent_name": "invoice-bot", "contact": "ops@example.com"})["token"]
        r = op("notarize", {"tool": "send_invoice", "args": {"to": "acme", "cents": 1500}, "result": "sent"}, token)
        for i in range(2):
            op("notarize", {"run": r["run"], "tool": "lookup", "args": {"n": i}}, token)
        self.assertEqual([x["event"]["type"] for x in r["records"]], ["policy.decision", "tool.result"])
        self.assertEqual({x["event"]["source"] for x in r["records"]}, {"notary"})
        self.assertNotIn("sent", json.dumps(r))   # the result went as its commitment only
        out = op("export", {"run": r["run"]}, token)
        v = op("verify", {"bundle": out["bundle"], "trust": out["trust"]})   # no token needed
        self.assertTrue(v["integrity"].startswith("VERIFIED"), v["report"])
        return out



class Service(NotaryCase):
    def test_mcp_round_trip(self):
        tools = self.post("/mcp", "tools/list", {})["result"]["tools"]
        self.assertEqual([t["name"] for t in tools], ["notary_register", "notarize", "export", "verify"])
        self.round_trip(self.mcp)

    def test_a2a_round_trip_and_its_agent_card(self):
        out = self.round_trip(self.a2a)
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        self.addCleanup(c.close)
        c.request("GET", "/.well-known/agent-card.json")
        card = json.loads(c.getresponse().read())
        self.assertEqual(card["documentationUrl"], "https://notary.test/skill.md")
        for k in ("name", "description", "version", "supportedInterfaces", "capabilities", "defaultInputModes",
                  "defaultOutputModes", "skills"):   # A2A v1.0.0 required fields
            self.assertIn(k, card)
        self.assertEqual(card["supportedInterfaces"][0], {"url": "https://notary.test/a2a", "protocolBinding": "JSONRPC",
                                                          "protocolVersion": "1.0"})
        self.assertTrue(all({"id", "name", "description", "tags"} <= set(s) for s in card["skills"]))
        c.request("GET", "/.well-known/tracekit-notary.json")
        self.assertEqual(json.loads(c.getresponse().read())["trust"], out["trust"])

    @unittest.skipIf(NO_TS, NO_TS)
    def test_both_verifiers_say_what_a_notarized_run_proves(self):
        out = self.round_trip(self.mcp)
        bundle, trust = os.path.join(self.dir, "run.tkb"), os.path.join(self.dir, "trust.json")
        with open(bundle, "wb") as f:
            f.write(base64.b64decode(out["bundle"]))
        with open(trust, "w") as f:
            json.dump(out["trust"], f)
        _build()
        tiers = [c for c in v2.verify(bundle, trust)[0].checks if c["check"] == "tiers"]
        self.assertIn("T3 3; T3 is receipt only (an OTLP import, or an agent's own claim through a notary), not "
                      "observed execution; 3 notarized: asserted by the agent, notarized when signed", tiers[0]["detail"])
        self.assertEqual([c for c in ts_verify(bundle, trust)["checks"] if c["check"] == "tiers"], tiers)

    def test_a_tampered_bundle_fails_verify(self):
        out = self.round_trip(self.mcp)
        zin = zipfile.ZipFile(io.BytesIO(base64.b64decode(out["bundle"])))
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zout:
            for item in zin.infolist():
                data = zin.read(item)
                if item.filename.startswith("runs/"):
                    data = data.replace(b"send_invoice", b"send_invoicf")
                zout.writestr(item, data)
        v = self.mcp("verify", {"bundle": base64.b64encode(buf.getvalue()).decode(), "trust": out["trust"]})
        self.assertNotIn("VERIFIED", v["integrity"])

    def test_notarize_and_export_need_a_token_and_say_how(self):
        out = self.mcp("notarize", {"tool": "t", "args": {}})
        self.assertTrue(out["isError"])
        self.assertIn("call notary_register", out["content"][0]["text"])
        self.assertIn("error", self.a2a("export", {"run": "x"}))

    def test_a_revoked_token_is_refused_at_once(self):
        out = self.mcp("notary_register", {"agent_name": "a"})
        self.assertEqual(notary.main(["revoke", out["agent"].split(":", 1)[1], "--config",
                                      os.path.join(self.dir, "notary.yaml")]), 0)
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        self.addCleanup(c.close)
        c.request("POST", "/mcp", json.dumps({"jsonrpc": "2.0", "id": 1, "method": "ping"}),
                  {"authorization": "Bearer " + out["token"], "content-type": "application/json"})
        self.assertEqual(c.getresponse().status, 401)

    def test_an_agent_can_follow_skill_md(self):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        self.addCleanup(c.close)
        c.request("GET", "/skill.md")
        skill = c.getresponse().read().decode()
        c.request("GET", "/.well-known/tracekit-notary.json")
        self.assertEqual(json.loads(c.getresponse().read())["skill"], "https://notary.test/skill.md")
        self.assertIn("ask them first", skill)
        found = {"<TOKEN>": None, "<RUN>": None, "<BUNDLE>": None}
        calls = re.findall(r"^curl -s https://notary\.test(/\w+) (.*?)-d '(.*)'$", skill, re.M)
        self.assertEqual(len(calls), 6)
        for path, headers, body in calls:   # as an agent would: fill each placeholder from an earlier answer
            for k, v in found.items():
                headers, body = headers.replace(k, v or k), body.replace(k, v or k)
            c.request("POST", path, body, dict(re.findall(r"-H '([\w-]+): ([^']*)'", headers)))
            out = json.loads(c.getresponse().read())["result"]
            out = out["message"]["parts"][0]["data"] if path == "/a2a" else out["structuredContent"]
            found["<TOKEN>"] = found["<TOKEN>"] or out.get("token")
            found["<RUN>"] = found["<RUN>"] or out.get("run")
            found["<BUNDLE>"] = found["<BUNDLE>"] or out.get("bundle")
            if "integrity" in out:
                self.assertTrue(out["integrity"].startswith("VERIFIED"), out["report"])
        self.assertTrue(all(found.values()))

    def test_the_kill_switch_refuses_everything(self):
        self.srv.notary.cfg["enabled"] = False
        out = self.mcp("verify", {"bundle": ""})
        self.assertIn("switched off", out["content"][0]["text"])


class Quotas(NotaryCase):
    quotas = {"records_per_day": 2, "verify_max_bytes": 64}

    def test_a_quota_refusal_says_what_to_do(self):
        token = self.mcp("notary_register", {"agent_name": "a"})["token"]
        r = self.mcp("notarize", {"tool": "t", "args": {}}, token)
        self.mcp("notarize", {"run": r["run"], "tool": "t", "args": {}}, token)
        out = self.mcp("notarize", {"run": r["run"], "tool": "t", "args": {}}, token)
        self.assertTrue(out["isError"])
        self.assertIn("2 records per day reached: export your run", out["content"][0]["text"])

    def test_verify_is_size_capped(self):
        out = self.mcp("verify", {"bundle": base64.b64encode(b"x" * 65).decode()})
        self.assertIn("over 64 bytes: verify it offline", out["content"][0]["text"])


if __name__ == "__main__":
    unittest.main()

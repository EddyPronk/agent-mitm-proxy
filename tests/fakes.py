"""Stand-ins for the Buzz relay and DNS, shared by the gatekeeper and MCP server tests.

Reactions are real events signed with throwaway keys, so signature checks run for real."""

import json
import socket
import uuid

import buzzkit

from agent_mitm_proxy.gatekeeper import Config, Gatekeeper

OWNER_NSEC, _, OWNER_HEX = buzzkit.generate_keypair()
STRANGER_NSEC, _, _ = buzzkit.generate_keypair()
HARNESS_NSEC, _, _ = buzzkit.generate_keypair()


def resolver(address="93.184.215.14"):
    def resolve(host, port, proto=0):
        return [(socket.AF_INET, socket.SOCK_STREAM, proto, "", (address, port))]
    return resolve


def reaction(target_event_id, emoji="👍", secret=OWNER_NSEC):
    return json.loads(buzzkit.build_reaction_event(secret, target_event_id, emoji))


class FakeClient:
    def __init__(self):
        self.sent = []

    async def publish(self, event_json):
        self.sent.append(json.loads(event_json))
        return {"accepted": True}


def connected(cfg, resolve=None):
    gk = Gatekeeper(cfg, resolve=resolve or resolver())
    gk.client = FakeClient()
    gk.connected.set()
    return gk


def make_config(tmp_path):
    (tmp_path / "buzz.key").write_text(HARNESS_NSEC + "\n")
    (tmp_path / "auth-tag.json").write_text("{}")
    (tmp_path / "allowlist.txt").write_text("api.anthropic.com:443\n*.githubusercontent.com:443\n")
    (tmp_path / "services.json").write_text(json.dumps({"ollama": {
        "listen": 11434, "target": "http://10.0.0.5:11434", "deny": ["/api/blobs"],
        "risky": {"POST /api/pull": "downloads a model"}}}))
    return Config(relay_url="wss://relay.invalid", owner_pubkey=OWNER_HEX, dm_id=str(uuid.uuid4()),
                  key_file=tmp_path / "buzz.key", tag_file=tmp_path / "auth-tag.json",
                  allowlist=tmp_path / "allowlist.txt", audit_log=tmp_path / "audit.jsonl",
                  services=tmp_path / "services.json")

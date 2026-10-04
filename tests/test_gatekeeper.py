"""The gatekeeper without a relay (see fakes.py)."""

import json

import pytest
from fakes import OWNER_HEX, STRANGER_NSEC, connected, reaction, resolver

from agent_mitm_proxy.gatekeeper import (
    Config,
    ConfigError,
    GatekeeperError,
    base_emoji,
    decision_for,
    owner_reaction,
    validate,
)


def audit(cfg):
    return [json.loads(line) for line in cfg.audit_log.read_text().splitlines()]


# -- configuration -----------------------------------------------------------

def test_config_from_env_needs_every_required_variable():
    with pytest.raises(ConfigError, match="GATEKEEPER_RELAY_URL.*GATEKEEPER_AUDIT_LOG"):
        Config.from_env({})


def test_config_from_env(tmp_path):
    env = {"GATEKEEPER_RELAY_URL": "wss://relay.invalid", "GATEKEEPER_OWNER_PUBKEY": OWNER_HEX,
           "GATEKEEPER_DM_ID": "d", "GATEKEEPER_KEY_FILE": "k", "GATEKEEPER_TAG_FILE": "t",
           "GATEKEEPER_ALLOWLIST": "a", "GATEKEEPER_AUDIT_LOG": "l", "GATEKEEPER_TIMEOUT_S": "60"}
    cfg = Config.from_env(env)
    assert (cfg.relay_url, cfg.timeout_s, cfg.services, str(cfg.allowlist)) == \
        ("wss://relay.invalid", 60, None, "a")


def test_config_refuses_an_npub_as_owner_pubkey(cfg):
    with pytest.raises(ConfigError):
        Config(**{**cfg.__dict__, "owner_pubkey": "npub1" + "q" * 58})


# -- reactions ---------------------------------------------------------------

@pytest.mark.parametrize(("emoji", "decision"), [
    ("👍", "approved"), ("👍🏽", "approved"), ("👍️", "approved"), ("👎", "rejected"),
    ("👎🏿", "rejected"), ("❤️", None), ("ok", None),
])
def test_decision_for(emoji, decision):
    assert decision_for(emoji) == decision


def test_base_emoji_drops_skin_tones():
    assert base_emoji("👍🏻") == "👍"


def test_owner_reaction_accepts_a_signed_owner_reaction():
    assert owner_reaction(reaction("a" * 64), OWNER_HEX) == ("a" * 64, "approved")


def test_owner_reaction_ignores_strangers():
    assert owner_reaction(reaction("a" * 64, secret=STRANGER_NSEC), OWNER_HEX) is None


def test_owner_reaction_ignores_forged_and_altered_events():
    rejected = reaction("a" * 64, "👎")
    assert owner_reaction({**rejected, "content": "👍"}, OWNER_HEX) is None
    stranger = reaction("a" * 64, secret=STRANGER_NSEC)
    assert owner_reaction({**stranger, "pubkey": OWNER_HEX}, OWNER_HEX) is None


def test_owner_reaction_ignores_other_kinds_and_untargeted_events():
    event = reaction("a" * 64)
    assert owner_reaction({**event, "kind": 1}, OWNER_HEX) is None
    assert owner_reaction({**event, "tags": []}, OWNER_HEX) is None


# -- host validation ---------------------------------------------------------

def test_validate_normalises_the_host():
    assert validate(" PyPI.org. ", 443, resolver()) == ("pypi.org", 443)


@pytest.mark.parametrize(("host", "port"), [
    ("93.184.215.14", 443), ("::1", 443), ("localhost", 443), ("-bad.example", 443),
    ("a..example", 443), ("x.example", 0), ("x.example", 65536),
])
def test_validate_refuses_bad_hosts(host, port):
    with pytest.raises(ValueError):
        validate(host, port, resolver())


def test_validate_refuses_hosts_that_resolve_to_the_lan():
    with pytest.raises(ValueError, match="non-global"):
        validate("lan.example", 443, resolver("192.168.15.1"))


# -- requests and decisions --------------------------------------------------

async def test_request_sends_a_dm_and_approval_appends_to_the_allowlist(cfg):
    gk = connected(cfg)
    result = await gk.request("install packages", "test sandbox", host="pypi.org")
    assert result["status"] == "pending"
    [dm] = gk.client.sent
    assert "Allow: pypi.org:443" in dm["content"] and "install packages" in dm["content"]

    await gk._handle(reaction(dm["id"]))
    assert gk.status(result["request_id"])["status"] == "approved"
    assert "pypi.org:443" in cfg.allowlist.read_text()
    assert "Added pypi.org:443" in gk.client.sent[-1]["content"]
    assert [r["event"] for r in audit(cfg)] == ["requested", "approved"]


async def test_rejection_leaves_the_allowlist_alone(cfg):
    gk = connected(cfg)
    before = cfg.allowlist.read_text()
    result = await gk.request("why not", "test sandbox", host="pypi.org")
    await gk._handle(reaction(gk.client.sent[0]["id"], "👎"))
    assert gk.status(result["request_id"])["status"] == "rejected"
    assert cfg.allowlist.read_text() == before


async def test_only_the_first_owner_reaction_counts(cfg):
    gk = connected(cfg)
    result = await gk.request("r", "test sandbox", host="pypi.org")
    dm_id = gk.client.sent[0]["id"]
    await gk._handle(reaction(dm_id, "👎"))
    await gk._handle(reaction(dm_id, "👍"))
    assert gk.status(result["request_id"])["status"] == "rejected"
    assert "pypi.org" not in cfg.allowlist.read_text()


async def test_stranger_reactions_and_reactions_to_other_messages_are_ignored(cfg):
    gk = connected(cfg)
    result = await gk.request("r", "test sandbox", host="pypi.org")
    await gk._handle(reaction(gk.client.sent[0]["id"], secret=STRANGER_NSEC))
    await gk._handle(reaction("b" * 64))
    assert gk.status(result["request_id"])["status"] == "pending"


async def test_a_reaction_made_after_the_timeout_does_not_count(cfg):
    gk = connected(cfg)
    result = await gk.request("r", "test sandbox", host="pypi.org")
    gk.requests[result["request_id"]].created -= cfg.timeout_s + 10
    await gk._handle(reaction(gk.client.sent[0]["id"]))
    assert gk.status(result["request_id"])["status"] == "pending"
    await gk._expire_due()
    assert gk.status(result["request_id"])["status"] == "expired"
    assert "Expired" in gk.client.sent[-1]["content"]


async def test_listed_hosts_are_already_allowed_without_asking(cfg):
    gk = connected(cfg)
    assert (await gk.request("r", "s", host="api.anthropic.com"))["status"] == "already_allowed"
    assert (await gk.request("r", "s", host="raw.githubusercontent.com"))["status"] == "already_allowed"
    assert gk.client.sent == []


async def test_a_duplicate_request_returns_the_pending_one(cfg):
    gk = connected(cfg)
    first = await gk.request("r", "s", host="pypi.org")
    assert await gk.request("again", "s", host="PYPI.org") == first
    assert len(gk.client.sent) == 1


async def test_pending_requests_are_limited(cfg):
    gk = connected(cfg)
    for host in ("a.example", "b.example", "c.example"):
        await gk.request("r", "s", host=host)
    with pytest.raises(GatekeeperError, match="too many pending"):
        await gk.request("r", "s", host="d.example")


async def test_hourly_requests_are_limited(cfg):
    gk = connected(cfg)
    for i in range(cfg.max_per_hour):
        await gk.request("r", "s", host=f"h{i}.example")
        await gk._handle(reaction(gk.client.sent[-1]["id"], "👎"))
    with pytest.raises(GatekeeperError, match="limit"):
        await gk.request("r", "s", host="one-more.example")


async def test_hosts_on_the_lan_are_refused_before_asking(cfg):
    gk = connected(cfg, resolve=resolver("10.0.0.5"))
    with pytest.raises(ValueError):
        await gk.request("r", "s", host="nas.example")
    assert gk.client.sent == []


# -- internal services -------------------------------------------------------

async def test_service_request_shows_the_risk_but_never_the_target(cfg):
    gk = connected(cfg)
    result = await gk.request("need a model", "s", service="ollama", method="post", path="/api/pull")
    assert (result["service"], result["method"], result["path"]) == ("ollama", "POST", "/api/pull")
    text = gk.client.sent[0]["content"]
    assert "Request: POST /api/pull" in text and "downloads a model" in text
    assert "10.0.0.5" not in text

    await gk._handle(reaction(gk.client.sent[0]["id"]))
    assert "service:ollama POST /api/pull" in cfg.allowlist.read_text()
    again = await gk.request("r", "s", service="ollama", method="POST", path="/api/pull/")
    assert again["status"] == "already_allowed"


@pytest.mark.parametrize(("service", "path", "error"), [
    ("nope", "/api/chat", "unknown service"),
    ("ollama", "/api/blobs/sha256-x", "never allowed"),
    ("ollama", "/api/../blobs", "not allowed"),
])
async def test_bad_service_requests_are_refused(cfg, service, path, error):
    gk = connected(cfg)
    with pytest.raises(ValueError, match=error):
        await gk.request("r", "s", service=service, method="GET", path=path)
    assert gk.client.sent == []


async def test_without_a_services_file_there_are_no_services(cfg):
    gk = connected(Config(**{**cfg.__dict__, "services": None}))
    with pytest.raises(ValueError, match="known: none"):
        await gk.request("r", "s", service="ollama", path="/api/chat")


# -- restarts ----------------------------------------------------------------

async def test_a_restart_keeps_pending_requests(cfg):
    gk = connected(cfg)
    result = await gk.request("r", "s", host="pypi.org")
    dm_id = gk.client.sent[0]["id"]

    restarted = connected(cfg)
    assert restarted.status(result["request_id"])["status"] == "pending"
    await restarted._handle(reaction(dm_id))
    assert restarted.status(result["request_id"])["status"] == "approved"
    assert connected(cfg).status(result["request_id"])["status"] == "approved"


async def test_the_decision_stands_if_the_reply_cannot_be_sent(cfg):
    gk = connected(cfg)
    result = await gk.request("r", "s", host="pypi.org")

    async def fail(event_json):
        raise ConnectionError("relay gone")
    gk.client.publish = fail
    await gk._handle(reaction(gk.client.sent[0]["id"]))
    assert gk.status(result["request_id"])["status"] == "approved"
    assert "pypi.org:443" in cfg.allowlist.read_text()


def test_status_of_an_unknown_request(cfg):
    assert connected(cfg).status("nope") == {"request_id": "nope", "status": "unknown"}

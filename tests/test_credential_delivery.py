"""CredentialDeliveryPlugin: a client's credentials file, with placeholders, from the proxy."""

import argparse
import json

import pytest
from proxy.http.parser import HttpParser, httpParserTypes

from agent_mitm_proxy.client_auth import NAME_ATTR
from agent_mitm_proxy.credential_delivery import CredentialDeliveryPlugin, credentials_file
from agent_mitm_proxy.credential_vault import Vault

TOKENS = {"access_token": "sk-ant-oat01-REAL-ACCESS", "refresh_token": "sk-ant-ort01-REAL-REFRESH",
          "expires_in": 28800, "refresh_token_expires_in": 2419200,
          "scope": "user:inference user:profile", "account": {"uuid": "acc-1"}}
URL = "http://agent-mitm-proxy.internal/v1/credentials/claude"


class FakeClient:
    def __init__(self, name):
        self.addr = ("10.0.0.2", 50000)
        self.sent = b""
        if name is not None:
            setattr(self, NAME_ATTR, name)

    def queue(self, data):
        self.sent += bytes(data)


@pytest.fixture
def vault(tmp_path, monkeypatch):
    monkeypatch.setenv("AGENT_MITM_PROXY_VAULT", str(tmp_path / "vault.json"))
    monkeypatch.setenv("AGENT_MITM_PROXY_VAULT_LOG", str(tmp_path / "vault.jsonl"))
    return Vault(str(tmp_path / "vault.json"))


def ask(vault, name=None, method="GET", url=URL):
    """(upstream request or None, what the client was sent) for a request through the plugin."""
    client = FakeClient(name)
    plugin = CredentialDeliveryPlugin("uid", argparse.Namespace(), client, None)
    request = HttpParser(httpParserTypes.REQUEST_PARSER)
    request.parse(memoryview(f"{method} {url} HTTP/1.1\r\nHost: x\r\n\r\n".encode()))
    if plugin.before_upstream_connection(request) is None:
        return None, client, plugin.handle_client_request(request)
    return request, client, plugin.handle_client_request(request)


def reply(client):
    parsed = HttpParser(httpParserTypes.RESPONSE_PARSER)
    parsed.parse(memoryview(client.sent))
    return int(parsed.code), json.loads(parsed.body)


def test_the_newest_entry_is_delivered_as_a_credentials_file(vault, tmp_path):
    vault.store(TOKENS, None, client="10.0.0.2")
    _, e = vault.newest_for(None)
    upstream, client, handled = ask(vault)
    assert upstream is None and handled is None             # answered here; no upstream
    status, body = reply(client)
    oauth = body["claudeAiOauth"]
    assert status == 200
    assert oauth["accessToken"] == e["placeholder_access"]
    assert oauth["refreshToken"] == e["placeholder_refresh"]
    assert oauth["scopes"] == ["user:inference", "user:profile"]
    assert oauth["expiresAt"] == e["expires_at"] * 1000
    assert "REAL" not in client.sent.decode()
    record = json.loads((tmp_path / "vault.jsonl").read_text())
    assert record["event"] == "credentials-delivered" and "REAL" not in json.dumps(record)


def test_an_empty_vault_gets_a_404(vault, tmp_path):
    _, client, _ = ask(vault)
    assert reply(client)[0] == 404
    assert json.loads((tmp_path / "vault.jsonl").read_text())["event"] == "credentials-refused"


def test_an_authenticated_client_gets_only_its_own_entries(vault):
    vault.store(TOKENS, None, client="alpha", name="alpha")
    assert reply(ask(vault, "alpha")[1])[0] == 200
    assert reply(ask(vault, "beta")[1])[0] == 404
    vault.grant("beta")
    assert reply(ask(vault, "beta")[1])[0] == 200


def test_an_unclaimed_entry_is_not_handed_out_to_an_authenticated_client(vault):
    vault.store(TOKENS, None, client="10.0.0.9")            # made before proxy authentication
    assert reply(ask(vault, "alpha")[1])[0] == 404
    assert reply(ask(vault)[1])[0] == 200                   # without authentication, as before


@pytest.mark.parametrize("method,url", [
    ("POST", URL),
    ("GET", "http://agent-mitm-proxy.internal/v1/other"),
    ("GET", "http://example.com/v1/credentials/claude"),
])
def test_other_requests_go_on_as_they_were(vault, method, url):
    upstream, client, handled = ask(vault, method=method, url=url)
    assert upstream is not None and handled is upstream and client.sent == b""


def test_credentials_file_without_a_refresh_expiry():
    e = {"placeholder_access": "a", "placeholder_refresh": "r", "expires_at": 10, "response": {}}
    assert credentials_file(e) == {"claudeAiOauth": {"accessToken": "a", "refreshToken": "r",
                                                     "expiresAt": 10000, "scopes": []}}

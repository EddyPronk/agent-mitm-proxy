"""ClientAuthPlugin: a name and a token per client, in the proxy URL's credentials."""

import argparse
import base64
import json

import pytest
from proxy.http.exception import ProxyAuthenticationFailed
from proxy.http.parser import HttpParser, httpParserTypes
from proxy.http.proxy.server import HttpProxyPlugin

from agent_mitm_proxy.client_auth import (
    ClientAuthPlugin,
    client_name,
    client_of,
    load_clients,
    save_clients,
    token_hash,
)


class FakeClient:
    addr = ("10.0.0.2", 50000)


def basic(user_pass: str) -> bytes:
    return b"Basic " + base64.b64encode(user_pass.encode())


@pytest.fixture
def clients(tmp_path, monkeypatch):
    path = tmp_path / "clients.json"
    save_clients(str(path), {"alpha": token_hash("right-token")})
    monkeypatch.setenv("AGENT_MITM_PROXY_CLIENTS", str(path))
    monkeypatch.setenv("AGENT_MITM_PROXY_CLIENTS_LOG", str(tmp_path / "clients.jsonl"))
    return path


def connect(header: bytes | None) -> tuple[ClientAuthPlugin, HttpParser]:
    plugin = ClientAuthPlugin("uid", argparse.Namespace(auth_code=None), FakeClient(), None)
    lines = ["CONNECT api.anthropic.com:443 HTTP/1.1", "Host: api.anthropic.com:443"]
    if header is not None:
        lines.append("Proxy-Authorization: " + header.decode())
    request = HttpParser(httpParserTypes.REQUEST_PARSER)
    request.parse(memoryview(("\r\n".join(lines) + "\r\n\r\n").encode()))
    return plugin, request


def test_the_right_name_and_token_pass_and_the_name_is_kept(clients):
    plugin, request = connect(basic("alpha:right-token"))
    out = plugin.before_upstream_connection(request)
    assert out is not None and not out.has_header(b"proxy-authorization")
    assert client_of(plugin) == "alpha"


@pytest.mark.parametrize("header", [None, basic("alpha:wrong"), basic("beta:right-token"),
                                    b"Bearer right-token", b"Basic !!!"])
def test_anything_else_gets_407_and_is_logged(clients, tmp_path, header):
    plugin, request = connect(header)
    with pytest.raises(ProxyAuthenticationFailed):
        plugin.before_upstream_connection(request)
    assert client_of(plugin) is None
    record = json.loads((tmp_path / "clients.jsonl").read_text())
    assert record["event"] == "proxy-auth-refused"
    assert record["had_credentials"] == (header is not None)
    assert "right-token" not in json.dumps(record)


class Buffer:
    """A client or upstream connection: what is queued to it."""
    addr = ("10.0.0.2", 50000)
    closed = False

    def __init__(self):
        self.sent = []

    def queue(self, data):
        self.sent.append(bytes(data))


def kept_alive():
    """proxy.py's own request handling (HttpProxyPlugin) with ClientAuthPlugin, for a plain HTTP
    connection: returns (upstream, send), send(raw) passing one more request on it."""
    wire = request_bytes()
    first = HttpParser(httpParserTypes.REQUEST_PARSER)
    first.parse(memoryview(wire))
    flags = argparse.Namespace(plugins={b"HttpProxyBasePlugin": [ClientAuthPlugin]}, disable_headers=[])
    core = HttpProxyPlugin("uid", flags, Buffer(), first)
    upstream = Buffer()
    core.connect_upstream = lambda: setattr(core, "upstream", upstream)
    core.emit_request_complete = lambda: None
    core.on_request_complete()
    return upstream, lambda raw: core.on_client_data(memoryview(raw))


def request_bytes(token="right-token"):
    return (b"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n"
            b"Proxy-Authorization: " + basic(f"alpha:{token}") + b"\r\n\r\n")


def test_no_request_on_a_kept_alive_connection_passes_proxy_credentials_on(clients):
    upstream, send = kept_alive()
    send(request_bytes())
    send(request_bytes())
    assert len(upstream.sent) == 3
    assert all(b"proxy-authorization" not in s.lower() for s in upstream.sent)
    assert all(base64.b64encode(b"alpha:right-token") not in s for s in upstream.sent)


def test_unenrolling_refuses_the_next_request_on_an_open_connection(clients, tmp_path):
    upstream, send = kept_alive()
    save_clients(str(clients), {})
    with pytest.raises(ProxyAuthenticationFailed):
        send(request_bytes())
    assert len(upstream.sent) == 1
    record = json.loads((tmp_path / "clients.jsonl").read_text().splitlines()[-1])
    assert record == {**record, "event": "proxy-auth-revoked", "client": "alpha"}


def test_a_new_token_refuses_the_next_request_on_an_open_connection(clients):
    upstream, send = kept_alive()
    save_clients(str(clients), {"alpha": token_hash("new-token")})
    with pytest.raises(ProxyAuthenticationFailed):
        send(request_bytes())
    assert len(upstream.sent) == 1


def test_client_name():
    enrolled = {"alpha": token_hash("t")}
    assert client_name(basic("alpha:t"), enrolled) == "alpha"
    assert client_name(basic("alpha:t:x"), enrolled) is None
    assert client_name(b"", enrolled) is None


def test_clients_file_keeps_only_hashes_and_is_private(tmp_path):
    path = tmp_path / "clients.json"
    save_clients(str(path), {"alpha": token_hash("secret-value")})
    assert "secret-value" not in path.read_text()
    assert path.stat().st_mode & 0o777 == 0o600
    assert load_clients(str(tmp_path / "missing.json")) == {}

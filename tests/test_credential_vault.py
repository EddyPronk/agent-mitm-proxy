"""CredentialVaultPlugin, fed requests and responses as proxy.py would after TLS interception (a
CONNECT, then origin-form requests on that connection). The "real" tokens are made up."""

import argparse
import gzip
import json
import os
import time

import pytest
from proxy.http.parser import HttpParser, httpParserTypes

from agent_mitm_proxy import credential_vault
from agent_mitm_proxy.client_auth import NAME_ATTR
from agent_mitm_proxy.credential_vault import CredentialVaultPlugin, Vault

REAL = {"access_token": "sk-ant-oat01-REAL-ACCESS-1", "refresh_token": "sk-ant-ort01-REAL-REFRESH-1",
        "expires_in": 28800, "refresh_token_expires_in": 2419200, "token_type": "Bearer",
        "account": {"uuid": "acc-1", "email_address": "x@example.com"}}


class FakeClient:
    """The client connection: its address, and what the plugin answers it itself."""

    def __init__(self, ip: str) -> None:
        self.addr = (ip, 50000)
        self.sent = b""

    def queue(self, data: memoryview) -> None:
        self.sent += bytes(data)


@pytest.fixture
def vault(tmp_path, monkeypatch):
    monkeypatch.setenv("AGENT_MITM_PROXY_VAULT", str(tmp_path / "vault.json"))
    monkeypatch.setenv("AGENT_MITM_PROXY_VAULT_LOG", str(tmp_path / "vault.jsonl"))
    monkeypatch.delenv("AGENT_MITM_PROXY_VAULT_STYLE", raising=False)
    return Vault(str(tmp_path / "vault.json"))


def log(tmp_path) -> list[dict]:
    path = tmp_path / "vault.jsonl"
    return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []


def events(tmp_path) -> list[str]:
    return [r["event"] for r in log(tmp_path)]


def connection(host: str, ip: str = "10.0.0.2", name: str | None = None) -> CredentialVaultPlugin:
    """A CONNECT to HOST; with NAME, from a client that authenticated as NAME (client_auth)."""
    client = FakeClient(ip)
    if name is not None:
        setattr(client, NAME_ATTR, name)
    plugin = CredentialVaultPlugin("uid", argparse.Namespace(), client, None)
    connect = HttpParser(httpParserTypes.REQUEST_PARSER)
    connect.parse(memoryview(f"CONNECT {host}:443 HTTP/1.1\r\nHost: {host}:443\r\n\r\n".encode()))
    plugin.before_upstream_connection(connect)
    plugin.handle_client_request(connect)
    return plugin


def send(plugin, method, path, headers, body=b""):
    """What goes upstream for this request; None if the plugin answered it itself."""
    lines = [f"{method} {path} HTTP/1.1", f"Host: {plugin.host}"]
    lines += [f"{k}: {v}" for k, v in headers.items()]
    if body:
        lines.append(f"Content-Length: {len(body)}")
    request = HttpParser(httpParserTypes.REQUEST_PARSER)
    request.parse(memoryview(("\r\n".join(lines) + "\r\n\r\n").encode() + body))
    assert request.is_complete
    out = plugin.handle_client_request(request)
    return None if out is None else out.build()


def token_request(plugin, **body):
    return send(plugin, "POST", "/v1/oauth/token", {"Content-Type": "application/json"},
                json.dumps(body).encode())


def refresh(plugin, token):
    return token_request(plugin, grant_type="refresh_token", refresh_token=token)


def receive(plugin, chunks):
    """Feed response CHUNKS; what the plugin returns for each, and all it let through."""
    out = [plugin.handle_upstream_chunk(memoryview(c)) for c in chunks]
    return out, b"".join(bytes(o) for o in out if o is not None)


def response(status, body):
    data = body if isinstance(body, bytes) else json.dumps(body).encode()
    return [f"HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {len(data)}"
            f"\r\n\r\n".encode() + data]


def chunked(status, data):
    head = f"HTTP/1.1 {status}\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n"
    half = len(data) // 2
    return [head.encode() + f"{half:x}\r\n".encode() + data[:half] + b"\r\n",
            f"{len(data) - half:x}\r\n".encode() + data[half:] + b"\r\n0\r\n\r\n"]


def body_of(raw: bytes) -> dict:
    parsed = HttpParser(httpParserTypes.RESPONSE_PARSER)
    parsed.parse(memoryview(raw))
    assert parsed.is_complete, raw[:200]
    return json.loads(parsed.body)


def sign_in(ip="10.0.0.2", tokens=REAL, name=None):
    """A sign-in through the vault; the placeholders the client gets."""
    p = connection("platform.claude.com", ip, name)
    token_request(p, grant_type="authorization_code", code="c", code_verifier="v")
    _, client = receive(p, response("200 OK", tokens))
    got = body_of(client)
    return got["access_token"], got["refresh_token"]


def set_entry(vault, entry_id, **fields):
    with vault._open(write=True) as data:
        data["entries"][entry_id].update(fields)


def expiring(vault, entry_id):
    set_entry(vault, entry_id, expires_at=int(time.time()) + 60)


# -- sign-in -----------------------------------------------------------------

def test_sign_in_hands_out_placeholders_and_keeps_the_tokens(vault, tmp_path):
    p = connection("platform.claude.com")
    up = token_request(p, grant_type="authorization_code", code="c", code_verifier="v")
    assert b'"code": "c"' in up and b"accept-encoding: identity" in up.lower()
    out, client = receive(p, chunked("200 OK", json.dumps(REAL).encode()))
    assert out[0] is None and out[1] is not None          # held back until complete
    assert b"REAL" not in client and b"transfer-encoding" not in client.lower()
    got = body_of(client)
    assert got["access_token"].startswith("agent-mitm-proxy-oat-")
    assert got["refresh_token"].startswith("agent-mitm-proxy-ort-")
    assert got["account"]["email_address"] == "x@example.com" and got["expires_in"] == 28800
    _, e = vault.find(got["access_token"])
    assert (e["access_token"], e["refresh_token"]) == (REAL["access_token"], REAL["refresh_token"])
    assert e["client"] == "10.0.0.2" and e["account"] == "acc-1"
    assert "account" in e["response"] and not set(e["response"]) & {"access_token", "refresh_token"}
    assert os.stat(vault.path).st_mode & 0o777 == 0o600
    assert not [f for f in os.listdir(tmp_path) if f.endswith(".tmp")]
    assert events(tmp_path) == ["sign-in"]


def test_sk_ant_style(vault, monkeypatch):
    monkeypatch.setenv("AGENT_MITM_PROXY_VAULT_STYLE", "sk-ant")
    access, refresh_ph = sign_in()
    assert access.startswith("sk-ant-oat01-agent-mitm-proxy-")
    assert refresh_ph.startswith("sk-ant-ort01-agent-mitm-proxy-")


# -- swapping ----------------------------------------------------------------

@pytest.mark.parametrize("host", ["api.anthropic.com", "mcp-proxy.anthropic.com"])
def test_request_gets_the_real_access_token(vault, host):
    access, _ = sign_in()
    p = connection(host)
    up = send(p, "POST", "/v1/messages", {"Authorization": f"Bearer {access}"}, b"{}")
    assert b"Bearer sk-ant-oat01-REAL-ACCESS-1" in up and access.encode() not in up
    _, client = receive(p, [b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}"])
    assert client.endswith(b"{}")


def test_x_api_key_is_swapped_too(vault):
    access, _ = sign_in()
    up = send(connection("api.anthropic.com"), "GET", "/", {"x-api-key": access})
    assert b"sk-ant-oat01-REAL-ACCESS-1" in up


def test_other_hosts_get_the_placeholder_and_it_is_logged(vault, tmp_path):
    access, _ = sign_in()
    up = send(connection("example.com"), "GET", "/", {"Authorization": f"Bearer {access}"})
    assert access.encode() in up and b"REAL" not in up
    assert "placeholder-elsewhere" in events(tmp_path)


def test_unknown_placeholder_goes_out_unchanged(vault, tmp_path):
    unknown = "agent-mitm-proxy-oat-" + "0" * 48
    up = send(connection("api.anthropic.com"), "GET", "/", {"Authorization": f"Bearer {unknown}"})
    assert unknown.encode() in up
    assert "unknown-placeholder" in events(tmp_path)


def test_log_has_no_token_values(vault, tmp_path):
    access, refresh_ph = sign_in()
    send(connection("api.anthropic.com"), "GET", "/", {"Authorization": f"Bearer {access}"})
    refresh(connection("platform.claude.com"), refresh_ph)
    text = (tmp_path / "vault.jsonl").read_text()
    assert "REAL" not in text and "agent-mitm-proxy-o" not in text


# -- refresh -----------------------------------------------------------------

def test_refresh_answered_by_the_vault_while_the_token_is_fresh(vault, tmp_path):
    access, refresh_ph = sign_in()
    p = connection("platform.claude.com")
    assert refresh(p, refresh_ph) is None                 # nothing upstream
    assert b"connection: close" in p.client.sent.lower() and b"REAL" not in p.client.sent
    got = body_of(p.client.sent)
    assert (got["access_token"], got["refresh_token"]) == (access, refresh_ph)
    assert 28000 < got["expires_in"] <= 28800
    assert 2419000 < got["refresh_token_expires_in"] <= 2419200
    assert got["account"]["uuid"] == "acc-1"
    assert events(tmp_path)[-1] == "refresh-answered"


def test_one_refresh_upstream_when_the_token_expires(vault):
    access, refresh_ph = sign_in()
    entry_id, _ = vault.find(access)
    expiring(vault, entry_id)
    p = connection("platform.claude.com")
    up = refresh(p, refresh_ph)
    assert b"sk-ant-ort01-REAL-REFRESH-1" in up and refresh_ph.encode() not in up
    # Another refresh meanwhile (another proxy process) is answered by the vault.
    p2 = connection("platform.claude.com")
    assert refresh(p2, refresh_ph) is None and body_of(p2.client.sent)["access_token"] == access
    new = dict(REAL, access_token="sk-ant-oat01-REAL-ACCESS-2", refresh_token="sk-ant-ort01-REAL-REFRESH-2")
    _, client = receive(p, response("200 OK", new))
    got = body_of(client)
    assert (got["access_token"], got["refresh_token"]) == (access, refresh_ph)
    _, e = vault.find(access)
    assert e["access_token"].endswith("ACCESS-2") and e["refresh_token"].endswith("REFRESH-2")
    assert e["generation"] == 2 and "refreshing_since" not in e
    assert refresh(connection("platform.claude.com"), refresh_ph) is None


def test_form_refresh_with_a_gzipped_response_without_refresh_token(vault):
    access, refresh_ph = sign_in()
    entry_id, _ = vault.find(access)
    expiring(vault, entry_id)
    p = connection("platform.claude.com")
    up = send(p, "POST", "/v1/oauth/token", {"Content-Type": "application/x-www-form-urlencoded"},
              f"grant_type=refresh_token&refresh_token={refresh_ph}".encode())
    assert b"refresh_token=sk-ant-ort01-REAL-REFRESH-1" in up
    new = {k: v for k, v in REAL.items() if k != "refresh_token"}
    new["access_token"] = "sk-ant-oat01-REAL-ACCESS-3"
    gz = gzip.compress(json.dumps(new).encode())
    _, client = receive(p, [b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: "
                            + str(len(gz)).encode() + b"\r\n\r\n" + gz])
    assert body_of(client)["access_token"] == access and b"content-encoding" not in client.lower()
    _, e = vault.find(access)
    assert e["access_token"].endswith("ACCESS-3") and e["refresh_token"].endswith("REFRESH-1")


def test_failed_refresh_passes_through_and_does_not_block_the_next(vault):
    access, refresh_ph = sign_in()
    entry_id, _ = vault.find(access)
    expiring(vault, entry_id)
    p = connection("platform.claude.com")
    refresh(p, refresh_ph)
    err = b'{"error":"invalid_grant"}'
    _, client = receive(p, response("400 Bad Request", err))
    assert client.startswith(b"HTTP/1.1 400") and client.endswith(err)
    assert refresh(connection("platform.claude.com"), refresh_ph) is not None


def test_401_with_a_replaced_token_does_not_refresh_again(vault, tmp_path):
    access, refresh_ph = sign_in()
    entry_id, _ = vault.find(access)
    on_its_way = connection("api.anthropic.com")
    send(on_its_way, "GET", "/", {"Authorization": f"Bearer {access}"})
    expiring(vault, entry_id)
    p = connection("platform.claude.com")
    refresh(p, refresh_ph)
    receive(p, response("200 OK", dict(REAL, access_token="sk-ant-oat01-REAL-ACCESS-2")))
    receive(on_its_way, response("401 Unauthorized", b"{}"))   # revoked by that refresh
    assert log(tmp_path)[-1]["event"] == "unauthorized" and log(tmp_path)[-1]["current"] is False
    assert refresh(connection("platform.claude.com"), refresh_ph) is None


def test_401_with_the_current_token_sends_the_next_refresh_upstream(vault):
    access, refresh_ph = sign_in()
    p = connection("api.anthropic.com")
    send(p, "GET", "/", {"Authorization": f"Bearer {access}"})
    receive(p, response("401 Unauthorized", b"{}"))
    p = connection("platform.claude.com")
    assert b"REAL-REFRESH-1" in refresh(p, refresh_ph)
    receive(p, response("200 OK", dict(REAL, access_token="sk-ant-oat01-REAL-ACCESS-2")))
    assert refresh(connection("platform.claude.com"), refresh_ph) is None


# -- adoption and forgetting -------------------------------------------------

def test_refresh_with_a_real_token_is_adopted(vault, tmp_path):
    p = connection("platform.claude.com")
    up = refresh(p, "sk-ant-ort01-REAL-OLD")
    assert b"sk-ant-ort01-REAL-OLD" in up                   # goes upstream as it is
    _, client = receive(p, response("200 OK", REAL))
    got = body_of(client)
    assert got["access_token"].startswith("agent-mitm-proxy-oat-") and b"REAL" not in client
    assert vault.find(got["access_token"])[1]["access_token"] == REAL["access_token"]
    assert events(tmp_path) == ["adopt"]


def test_sign_in_replaces_the_accounts_entries_from_the_same_client(vault, tmp_path):
    first, _ = sign_in(ip="10.0.0.2")
    other_client, _ = sign_in(ip="10.0.0.3")
    other_account, _ = sign_in(ip="10.0.0.2", tokens=dict(REAL, account={"uuid": "acc-2"}))
    second, _ = sign_in(ip="10.0.0.2")
    assert vault.find(first) is None
    assert vault.find(second) and vault.find(other_client) and vault.find(other_account)
    assert [r["reason"] for r in log(tmp_path) if r["event"] == "forgotten"] == ["replaced"]


def test_entries_with_an_expired_refresh_token_are_forgotten(vault, tmp_path):
    old, _ = sign_in(ip="10.0.0.2")
    set_entry(vault, vault.find(old)[0], refresh_expires_at=int(time.time()) - 1)
    sign_in(ip="10.0.0.3")
    assert vault.find(old) is None
    assert [r["reason"] for r in log(tmp_path) if r["event"] == "forgotten"] == ["expired"]


# -- revoke and the vault file -----------------------------------------------

def test_revoke_swaps_and_removes_the_entry(vault, tmp_path):
    access, refresh_ph = sign_in()
    p = connection("platform.claude.com")
    up = send(p, "POST", "/v1/oauth/token/revoke", {"Content-Type": "application/json"},
              json.dumps({"token": refresh_ph}).encode())
    assert b"REAL-REFRESH-1" in up
    receive(p, [b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}"])
    assert vault.find(access) is None and events(tmp_path)[-1] == "revoked"


def test_a_vault_others_can_read_is_refused(vault):
    access, _ = sign_in()
    os.chmod(vault.path, 0o644)
    with pytest.raises(PermissionError):
        vault.find(access)


# -- where a token may go (the connection, not the request, decides) -------

def test_absolute_url_naming_a_vault_host_on_another_hosts_connection_gets_no_token(vault, tmp_path):
    access, _ = sign_in()
    p = connection("example.com")
    up = send(p, "GET", "https://api.anthropic.com/v1/messages", {"Authorization": f"Bearer {access}"})
    assert b"Host: example.com" in up and b"REAL" not in up and access.encode() in up
    assert log(tmp_path)[-1]["event"] == "placeholder-elsewhere"


def test_host_header_naming_another_host_gets_no_token(vault, tmp_path):
    access, _ = sign_in()
    p = connection("api.anthropic.com")
    lines = (f"GET /v1/messages HTTP/1.1\r\nHost: example.com\r\n"
             f"Authorization: Bearer {access}\r\n\r\n").encode()
    request = HttpParser(httpParserTypes.REQUEST_PARSER)
    request.parse(memoryview(lines))
    up = p.handle_client_request(request).build()
    assert b"REAL" not in up
    assert log(tmp_path)[-1]["reason"] == "request names another host"


def test_absolute_url_naming_the_connections_own_host_gets_the_token(vault):
    access, _ = sign_in()
    p = connection("api.anthropic.com")
    up = send(p, "GET", "https://api.anthropic.com/v1/messages", {"Authorization": f"Bearer {access}"})
    assert b"sk-ant-oat01-REAL-ACCESS-1" in up


def test_plain_http_never_gets_a_token(vault):
    access, _ = sign_in()
    p = CredentialVaultPlugin("uid", argparse.Namespace(), FakeClient("10.0.0.2"), None)
    request = HttpParser(httpParserTypes.REQUEST_PARSER)
    request.parse(memoryview(f"GET http://api.anthropic.com/v1/messages HTTP/1.1\r\n"
                             f"Host: api.anthropic.com\r\nAuthorization: Bearer {access}\r\n\r\n".encode()))
    p.before_upstream_connection(request)
    assert b"REAL" not in p.handle_client_request(request).build()


# -- responses ----------------------------------------------------------------

def test_401_status_line_split_across_chunks_is_noticed(vault):
    access, refresh_ph = sign_in()
    p = connection("api.anthropic.com")
    send(p, "GET", "/", {"Authorization": f"Bearer {access}"})
    wire = response("401 Unauthorized", {})[0]
    out, client = receive(p, [wire[:8], wire[8:]])
    assert client == wire and all(o is not None for o in out)    # passed on as it came
    assert "failed_at" in vault.find(access)[1]
    assert refresh(connection("platform.claude.com"), refresh_ph) is not None


def test_id_token_is_withheld(vault, tmp_path):
    p = connection("platform.claude.com")
    token_request(p, grant_type="authorization_code", code="c")
    _, client = receive(p, response("200 OK", dict(REAL, id_token="fake-id-token")))
    assert b"fake-id-token" not in client and "id_token" not in body_of(client)
    assert log(tmp_path)[-1]["withheld"] == ["id_token"]
    access = body_of(client)["access_token"]
    assert "fake-id-token" not in json.dumps(vault.find(access)[1])


@pytest.mark.parametrize("raw", [
    b"HTTP/1.1 200 OK\r\nContent-Encoding: deflate\r\nContent-Length: 9\r\n\r\nxxxxxxxxx",
    response("400 Bad Request", {"error": "x", "refresh_token": "sk-ant-ort01-REAL"})[0],
])
def test_token_response_the_vault_cant_handle_is_not_passed_on(vault, tmp_path, raw):
    p = connection("platform.claude.com")
    token_request(p, grant_type="authorization_code", code="c")
    _, client = receive(p, [raw])
    assert client.startswith(b"HTTP/1.1 502") and b"xxxx" not in client and b"sk-ant" not in client
    assert log(tmp_path)[-1]["event"] == "token-response-withheld"


def test_token_response_cut_off_upstream_gets_the_client_a_502(vault, tmp_path):
    access, refresh_ph = sign_in()
    entry_id, _ = vault.find(access)
    expiring(vault, entry_id)
    p = connection("platform.claude.com")
    refresh(p, refresh_ph)
    wire = response("200 OK", REAL)[0]
    out, _ = receive(p, [wire[:40]])
    assert out == [None]
    p.on_upstream_connection_close()
    assert p.client.sent.startswith(b"HTTP/1.1 502") and b"REAL" not in p.client.sent
    assert "refreshing_since" not in vault.find(access)[1]    # the next refresh may go upstream


def test_refresh_response_without_account_keeps_it_for_the_vaults_answers(vault):
    access, refresh_ph = sign_in()
    entry_id, _ = vault.find(access)
    expiring(vault, entry_id)
    p = connection("platform.claude.com")
    refresh(p, refresh_ph)
    lean = {k: v for k, v in REAL.items() if k != "account"}
    receive(p, response("200 OK", dict(lean, access_token="sk-ant-oat01-REAL-ACCESS-2")))
    p = connection("platform.claude.com")
    assert refresh(p, refresh_ph) is None
    assert body_of(p.client.sent)["account"]["uuid"] == "acc-1"


def test_entry_removed_between_find_and_refresh(vault, tmp_path, monkeypatch):
    access, refresh_ph = sign_in()
    entry_id, _ = vault.find(access)
    real_find = Vault.find

    def find_then_remove(self, token):                       # another process, in between
        found = real_find(self, token)
        self.remove(entry_id)
        return found

    monkeypatch.setattr(Vault, "find", find_then_remove)
    up = refresh(connection("platform.claude.com"), refresh_ph)
    assert up is not None and refresh_ph.encode() in up and b"REAL" not in up
    assert log(tmp_path)[-1]["event"] == "unknown-placeholder"


# -- with the traffic log, in start-proxy.sh's order -------------------------

def test_traffic_log_and_vault_together(vault, tmp_path, monkeypatch):
    monkeypatch.setenv("AGENT_MITM_PROXY_TRAFFIC_LOG", str(tmp_path / "traffic.jsonl"))
    from agent_mitm_proxy.plugins import TrafficLogPlugin

    def chain(host):
        logger = TrafficLogPlugin("uid", argparse.Namespace(), None, None)
        vault_plugin = connection(host)
        logger.before_upstream_connection(vault_plugin_connect(host))
        return [logger, vault_plugin]

    def vault_plugin_connect(host):
        connect = HttpParser(httpParserTypes.REQUEST_PARSER)
        connect.parse(memoryview(f"CONNECT {host}:443 HTTP/1.1\r\nHost: {host}:443\r\n\r\n".encode()))
        return connect

    def request(plugins, method, path, headers, body=b""):
        lines = [f"{method} {path} HTTP/1.1", f"Host: {plugins[1].host}"]
        lines += [f"{k}: {v}" for k, v in headers.items()] + [f"Content-Length: {len(body)}"]
        r = HttpParser(httpParserTypes.REQUEST_PARSER)
        r.parse(memoryview(("\r\n".join(lines) + "\r\n\r\n").encode() + body))
        for plugin in plugins:
            r = plugin.handle_client_request(r)
            if r is None:
                return None
        return r.build()

    def answer(plugins, chunks):
        out = b""
        for c in chunks:
            chunk = memoryview(c)
            for plugin in plugins:
                chunk = plugin.handle_upstream_chunk(chunk)
                if chunk is None:
                    break
            if chunk is not None:
                out += bytes(chunk)
        return out

    plugins = chain("platform.claude.com")
    request(plugins, "POST", "/v1/oauth/token", {"Content-Type": "application/json"},
            json.dumps({"grant_type": "authorization_code", "code": "c", "code_verifier": "v"}).encode())
    client = answer(plugins, chunked("200 OK", json.dumps(REAL).encode()))
    access = body_of(client)["access_token"]
    assert access.startswith("agent-mitm-proxy-oat-") and b"REAL" not in client

    plugins = chain("api.anthropic.com")
    up = request(plugins, "POST", "/v1/messages", {"Authorization": f"Bearer {access}"}, b"{}")
    assert b"REAL-ACCESS-1" in up
    answer(plugins, response("200 OK", {"ok": True}))

    traffic = (tmp_path / "traffic.jsonl").read_text()
    assert "REAL" not in traffic and "[REDACTED]" in traffic


def test_hosts():
    assert "example.com" not in credential_vault.VAULT_HOSTS
    assert credential_vault.TOKEN_HOST in credential_vault.VAULT_HOSTS


# -- clients (proxy authentication) ------------------------------------------

def test_sign_in_by_an_enrolled_client_belongs_to_it(vault, tmp_path):
    access, _ = sign_in(name="alpha")
    _, e = vault.find(access)
    assert e["clients"] == ["alpha"] and e["client"] == "alpha"
    up = send(connection("api.anthropic.com", name="alpha"), "GET", "/", {"Authorization": f"Bearer {access}"})
    assert b"REAL-ACCESS-1" in up


def test_an_entry_is_swapped_only_for_its_clients(vault, tmp_path):
    access, refresh_ph = sign_in(name="alpha")
    up = send(connection("api.anthropic.com", name="beta"), "GET", "/", {"Authorization": f"Bearer {access}"})
    assert b"REAL" not in up and access.encode() in up
    assert refresh(connection("platform.claude.com", name="beta"), refresh_ph) is not None
    assert events(tmp_path)[-2:] == ["not-this-clients-entry"] * 2
    assert all(r.get("client") == "beta" for r in log(tmp_path)[-2:])


def test_a_granted_client_gets_the_entry(vault):
    access, _ = sign_in(name="alpha")
    entry_id, _ = vault.find(access)
    assert vault.grant("beta") == entry_id and vault.grant("beta") == entry_id
    assert vault.find(access)[1]["clients"] == ["alpha", "beta"]
    up = send(connection("api.anthropic.com", name="beta"), "GET", "/", {"Authorization": f"Bearer {access}"})
    assert b"REAL-ACCESS-1" in up
    assert vault.ungrant("beta") == [entry_id] and vault.find(access)[1]["clients"] == ["alpha"]


def test_an_entry_from_before_authentication_is_claimed_by_its_first_user(vault, tmp_path):
    access, _ = sign_in()                                   # no name: belongs to no one
    entry_id, e = vault.find(access)
    assert not e.get("clients")
    up = send(connection("api.anthropic.com", name="alpha"), "GET", "/", {"Authorization": f"Bearer {access}"})
    assert b"REAL-ACCESS-1" in up
    assert vault.find(access)[1]["clients"] == ["alpha"]
    assert log(tmp_path)[-2]["event"] == "claimed" and log(tmp_path)[-2]["entry"] == entry_id
    up = send(connection("api.anthropic.com", name="beta"), "GET", "/", {"Authorization": f"Bearer {access}"})
    assert b"REAL" not in up


def test_an_entry_whose_last_client_was_removed_stays_refused(vault, tmp_path):
    access, _ = sign_in(name="alpha")
    entry_id, _ = vault.find(access)
    open_connection = connection("api.anthropic.com", name="alpha")
    assert vault.ungrant("alpha") == [entry_id]
    assert vault.entries()[entry_id]["clients"] == []
    for client in (open_connection, connection("api.anthropic.com", name="beta")):
        up = send(client, "GET", "/", {"Authorization": f"Bearer {access}"})
        assert b"REAL" not in up
    assert vault.entries()[entry_id]["clients"] == []
    assert vault.claim(entry_id, "beta") is None
    assert "claimed" not in events(tmp_path)
    vault.grant("beta", entry_id)
    up = send(connection("api.anthropic.com", name="beta"), "GET", "/", {"Authorization": f"Bearer {access}"})
    assert b"REAL-ACCESS-1" in up


def test_without_authentication_clients_are_not_told_apart(vault):
    access, _ = sign_in(name="alpha")
    up = send(connection("api.anthropic.com"), "GET", "/", {"Authorization": f"Bearer {access}"})
    assert b"REAL-ACCESS-1" in up


def test_grant_without_entries_and_newest_for(vault):
    assert vault.grant("alpha") is None and vault.newest_for("alpha") is None
    sign_in(name="alpha")
    entry_id, _ = vault.newest_for("alpha")
    assert vault.newest_for(None)[0] == entry_id and vault.newest_for("beta") is None

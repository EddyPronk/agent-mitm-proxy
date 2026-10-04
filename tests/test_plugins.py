import argparse
import gzip
import json
import socket

import brotli
import pytest
from proxy.http.exception import HttpRequestRejected
from proxy.http.parser import HttpParser

from agent_mitm_proxy import plugins
from agent_mitm_proxy.plugins import AllowlistPlugin, TrafficLogPlugin


def make(plugin_class):
    return plugin_class("uid", argparse.Namespace(), None, None)


def resolve_to(address):
    def resolve(host, port, proto=0):
        return [(socket.AF_INET, socket.SOCK_STREAM, proto, "", (address, port))]
    return staticmethod(resolve)


def read_jsonl(path):
    return [json.loads(line) for line in path.read_text().splitlines()]


# -- AllowlistPlugin ---------------------------------------------------------

@pytest.fixture
def allowlist_env(tmp_path, monkeypatch):
    (tmp_path / "allowlist.txt").write_text("example.com:443\nplain.example\n")
    monkeypatch.setenv(plugins.ALLOWLIST_ENV, str(tmp_path / "allowlist.txt"))
    monkeypatch.setenv(plugins.DENIED_LOG_ENV, str(tmp_path / "denied.jsonl"))
    monkeypatch.setattr(AllowlistPlugin, "resolve", resolve_to("93.184.215.14"))
    return tmp_path


def connect(host_port):
    return HttpParser.request(f"CONNECT {host_port} HTTP/1.1\r\nHost: {host_port}\r\n\r\n".encode())


def test_allowlist_plugin_lets_listed_hosts_through(allowlist_env):
    request = connect("example.com:443")
    assert make(AllowlistPlugin).before_upstream_connection(request) is request
    assert not (allowlist_env / "denied.jsonl").exists()


def test_allowlist_plugin_checks_plain_http_on_port_80(allowlist_env):
    request = HttpParser.request(b"GET http://plain.example/x HTTP/1.1\r\nHost: plain.example\r\n\r\n")
    assert make(AllowlistPlugin).before_upstream_connection(request) is request


@pytest.mark.parametrize("host_port", ["example.com:80", "pypi.org:443", "93.184.215.14:443"])
def test_allowlist_plugin_refuses_and_logs_unlisted_hosts(allowlist_env, host_port):
    with pytest.raises(HttpRequestRejected) as rejected:
        make(AllowlistPlugin).before_upstream_connection(connect(host_port))
    assert rejected.value.status_code == 403
    assert b"Blocked by sandbox egress allowlist" in rejected.value.body
    [record] = read_jsonl(allowlist_env / "denied.jsonl")
    assert f"{record['host']}:{record['port']}" == host_port
    assert record["reason"] == "not in allowlist"


def test_allowlist_plugin_refuses_listed_hosts_that_resolve_to_the_lan(allowlist_env, monkeypatch):
    monkeypatch.setattr(AllowlistPlugin, "resolve", resolve_to("192.168.15.1"))
    with pytest.raises(HttpRequestRejected):
        make(AllowlistPlugin).before_upstream_connection(connect("example.com:443"))
    [record] = read_jsonl(allowlist_env / "denied.jsonl")
    assert record["reason"] == "resolves to non-global address 192.168.15.1"


def test_allowlist_plugin_refuses_even_if_the_log_cannot_be_written(allowlist_env, monkeypatch):
    monkeypatch.setenv(plugins.DENIED_LOG_ENV, str(allowlist_env / "no-such-dir" / "denied.jsonl"))
    with pytest.raises(HttpRequestRejected):
        make(AllowlistPlugin).before_upstream_connection(connect("pypi.org:443"))


def test_allowlist_plugin_without_an_allowlist_refuses_everything(allowlist_env, monkeypatch):
    monkeypatch.setenv(plugins.ALLOWLIST_ENV, str(allowlist_env / "missing.txt"))
    with pytest.raises(HttpRequestRejected):
        make(AllowlistPlugin).before_upstream_connection(connect("example.com:443"))


# -- TrafficLogPlugin --------------------------------------------------------

@pytest.fixture
def traffic_log(tmp_path, monkeypatch):
    path = tmp_path / "traffic.jsonl"
    monkeypatch.setenv(plugins.TRAFFIC_LOG_ENV, str(path))
    return path


def post(body, encoding=None):
    headers = (b"POST /v1/messages HTTP/1.1\r\nHost: api.example\r\n"
               b"Authorization: Bearer secret-token\r\nx-api-key: secret-key\r\n"
               + (b"Content-Encoding: " + encoding + b"\r\n" if encoding else b"")
               + b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n")
    return HttpParser.request(headers + body)


def test_traffic_log_does_not_log_the_connect_envelope(traffic_log):
    make(TrafficLogPlugin).handle_client_request(connect("api.example:443"))
    assert not traffic_log.exists()


def test_traffic_log_logs_request_and_response_bodies_but_no_headers(traffic_log):
    plugin = make(TrafficLogPlugin)
    # Inside the TLS tunnel the request line has only a path: the host comes from the CONNECT.
    plugin.before_upstream_connection(connect("api.example:443"))
    request = post(b'{"prompt": "hi"}')
    assert plugin.handle_client_request(request) is request
    chunk = memoryview(b'HTTP/1.1 200 OK\r\nContent-Length: 12\r\nSet-Cookie: s=1\r\n\r\n{"ok": true}')
    assert plugin.handle_upstream_chunk(chunk) is chunk
    plugin.on_upstream_connection_close()

    req, resp = read_jsonl(traffic_log)
    assert (req["direction"], req["host"], req["path"], req["method"], req["body"]) == \
        ("request", "api.example", "/v1/messages", "POST", '{"prompt": "hi"}')
    assert (resp["direction"], resp["path"], resp["status"], resp["body"]) == \
        ("response", "/v1/messages", "200", '{"ok": true}')
    text = traffic_log.read_text()
    assert "secret" not in text and "s=1" not in text


@pytest.mark.parametrize(("encoding", "compress"), [(b"gzip", gzip.compress), (b"br", brotli.compress)])
def test_traffic_log_decodes_compressed_bodies(traffic_log, encoding, compress):
    make(TrafficLogPlugin).handle_client_request(post(compress(b"hello"), encoding))
    [record] = read_jsonl(traffic_log)
    assert (record["body"], record["content_encoding"], record["decoded"]) == \
        ("hello", encoding.decode(), True)
    assert "body_base64" not in record


@pytest.mark.parametrize(("encoding", "body"), [
    (b"gzip", b"not gzip"), (b"gzip", gzip.compress(b"hello")[:-4]), (b"br", b"not brotli"),
    (b"zstd", b"\x28\xb5\x2f\xfd"),
])
def test_traffic_log_keeps_undecodable_bodies_as_base64(traffic_log, encoding, body):
    make(TrafficLogPlugin).handle_client_request(post(body, encoding))
    [record] = read_jsonl(traffic_log)
    assert record["decoded"] is False
    assert record["body_base64"]


def test_traffic_log_logs_an_unfinished_response_as_partial(traffic_log):
    plugin = make(TrafficLogPlugin)
    plugin.handle_client_request(post(b"{}"))
    plugin.handle_upstream_chunk(memoryview(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\npart"))
    plugin.on_upstream_connection_close()
    _, resp = read_jsonl(traffic_log)
    assert (resp["body"], resp["partial"]) == ("part", True)

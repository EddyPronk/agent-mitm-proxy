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


# proxy.py's access log takes the target from the upstream connection, which a refused request
# never gets: it logged "CONNECT None:None". The plugin fills in what it refused.
def access_context():
    return {"client_ip": "10.89.0.3", "server_host": None, "server_port": None,
            "request_method": "CONNECT", "response_code": None, "response_reason": None}


def test_allowlist_plugin_names_a_refused_target_in_the_access_log(allowlist_env):
    plugin = make(AllowlistPlugin)
    with pytest.raises(HttpRequestRejected):
        plugin.before_upstream_connection(connect("pypi.org:443"))
    context = plugin.on_access_log(access_context())
    assert (context["server_host"], context["server_port"]) == ("pypi.org", 443)
    assert (context["response_code"], context["response_reason"]) == ("403", "Forbidden")
    assert context["client_ip"] == "10.89.0.3", "the rest is passed on"


def test_allowlist_plugin_leaves_the_access_log_of_allowed_requests_alone(allowlist_env):
    plugin = make(AllowlistPlugin)
    plugin.before_upstream_connection(connect("example.com:443"))
    context = {**access_context(), "server_host": "93.184.215.14", "server_port": 443}
    assert plugin.on_access_log(dict(context)) == context


def test_allowlist_plugin_refuses_listed_hosts_that_resolve_to_the_lan(allowlist_env, monkeypatch):
    monkeypatch.setattr(AllowlistPlugin, "resolve", resolve_to("192.168.15.1"))
    with pytest.raises(HttpRequestRejected):
        make(AllowlistPlugin).before_upstream_connection(connect("example.com:443"))
    [record] = read_jsonl(allowlist_env / "denied.jsonl")
    assert record["reason"] == "resolves to non-global address 192.168.15.1"


def test_allowlist_plugin_connects_to_the_address_it_checked(allowlist_env, monkeypatch):
    # DNS rebinding: the first answer is global, every later one is on the LAN.
    answers = iter(["93.184.215.14"])

    def rebinding(host, port, proto=0):
        address = next(answers, "192.168.15.1")
        return [(socket.AF_INET, socket.SOCK_STREAM, proto, "", (address, port))]
    monkeypatch.setattr(AllowlistPlugin, "resolve", staticmethod(rebinding))
    plugin = make(AllowlistPlugin)
    plugin.before_upstream_connection(connect("example.com:443"))
    # proxy.py passes the host as the client wrote it.
    assert plugin.resolve_dns("Example.com", 443) == ("93.184.215.14", None)
    assert plugin.resolve_dns("example.com", 443) == ("93.184.215.14", None)


def test_allowlist_plugin_never_lets_proxy_py_resolve_by_itself(allowlist_env):
    plugin = make(AllowlistPlugin)
    with pytest.raises(ConnectionRefusedError):
        plugin.resolve_dns("example.com", 443)      # no check yet
    plugin.before_upstream_connection(connect("example.com:443"))
    with pytest.raises(ConnectionRefusedError):
        plugin.resolve_dns("pypi.org", 443)         # another host than the one checked
    with pytest.raises(ConnectionRefusedError):
        plugin.resolve_dns("example.com", 8443)     # another port


def test_allowlist_plugin_forgets_the_address_when_a_later_request_is_refused(allowlist_env):
    plugin = make(AllowlistPlugin)
    plugin.before_upstream_connection(connect("example.com:443"))
    with pytest.raises(HttpRequestRejected):
        plugin.before_upstream_connection(connect("pypi.org:443"))
    with pytest.raises(ConnectionRefusedError):
        plugin.resolve_dns("example.com", 443)


def test_allowlist_plugin_refuses_to_work_with_the_connection_pool(allowlist_env):
    plugin = AllowlistPlugin("uid", argparse.Namespace(enable_conn_pool=True), None, None)
    with pytest.raises(HttpRequestRejected):
        plugin.before_upstream_connection(connect("example.com:443"))
    [record] = read_jsonl(allowlist_env / "denied.jsonl")
    assert "conn-pool" in record["reason"]


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
    # JSON bodies are logged as JSON, for jq: .body.prompt
    assert (req["direction"], req["host"], req["path"], req["method"], req["body"]) == \
        ("request", "api.example", "/v1/messages", "POST", {"prompt": "hi"})
    assert (resp["direction"], resp["path"], resp["status"], resp["body"]) == \
        ("response", "/v1/messages", "200", {"ok": True})
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


def token_exchange(request_body, response):
    plugin = make(TrafficLogPlugin)
    plugin.before_upstream_connection(connect("platform.claude.com:443"))
    plugin.handle_client_request(HttpParser.request(
        b"POST /v1/oauth/token HTTP/1.1\r\nHost: platform.claude.com\r\nContent-Length: "
        + str(len(request_body)).encode() + b"\r\n\r\n" + request_body))
    plugin.handle_upstream_chunk(memoryview(response))
    plugin.on_upstream_connection_close()
    return plugin


def test_traffic_log_redacts_the_tokens_of_an_oauth_token_exchange(traffic_log):
    body = b'{"access_token":"sk-ant-oat01-a","expires_in":28800,"refresh_token":"sk-ant-ort01-r"}'
    token_exchange(b'{"grant_type":"refresh_token","refresh_token":"sk-ant-ort01-old","client_id":"c"}',
                   b"HTTP/1.1 200 OK\r\nContent-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body)
    req, resp = read_jsonl(traffic_log)
    assert req["body"] == {"grant_type": "refresh_token", "refresh_token": "[REDACTED]", "client_id": "c"}
    assert list(req["body"]) == ["grant_type", "refresh_token", "client_id"]
    assert req["redacted"] == ["refresh_token"]
    assert resp["body"] == {"access_token": "[REDACTED]", "expires_in": 28800, "refresh_token": "[REDACTED]"}
    assert list(resp["body"]) == ["access_token", "expires_in", "refresh_token"]
    assert resp["redacted"] == ["access_token", "refresh_token"]
    assert "sk-ant" not in traffic_log.read_text()


def test_traffic_log_withholds_an_unfinished_token_response(traffic_log):
    token_exchange(b'{"grant_type":"refresh_token","refresh_token":"sk-ant-ort01-old"}',
                   b'HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n{"access_token":"sk-ant-oat01-a')
    _, resp = read_jsonl(traffic_log)
    assert (resp["redacted"], resp["partial"]) == (["body"], True)
    assert "sk-ant" not in traffic_log.read_text()


@pytest.mark.parametrize(("encoding", "body", "redacted"), [
    # An encoding it doesn't know, over plain JSON: redacted as text, and no copy of the bytes.
    (b"zstd", b'{"refresh_token":"sk-ant-ort01-old"}', ["refresh_token"]),
    # Broken gzip: no JSON to redact, so withheld, and no copy of the bytes either.
    (b"gzip", gzip.compress(b'{"refresh_token":"sk-ant-ort01-old"}')[:-4], ["body"]),
])
def test_traffic_log_keeps_no_base64_copy_of_a_redacted_token_body(traffic_log, encoding, body, redacted):
    plugin = make(TrafficLogPlugin)
    plugin.before_upstream_connection(connect("platform.claude.com:443"))
    plugin.handle_client_request(HttpParser.request(
        b"POST /v1/oauth/token HTTP/1.1\r\nHost: platform.claude.com\r\nContent-Encoding: " + encoding
        + b"\r\nContent-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body))
    [req] = read_jsonl(traffic_log)
    assert req["redacted"] == redacted and "body_base64" not in req
    assert "sk-ant" not in traffic_log.read_text()


def test_traffic_log_logs_an_unfinished_response_as_partial(traffic_log):
    plugin = make(TrafficLogPlugin)
    plugin.handle_client_request(post(b"{}"))
    plugin.handle_upstream_chunk(memoryview(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\npart"))
    plugin.on_upstream_connection_close()
    _, resp = read_jsonl(traffic_log)
    assert (resp["body"], resp["partial"]) == ("part", True)


# -- refusal bursts ------------------------------------------------------------

def test_bursts_answer_until_the_count_then_reset_for_a_while():
    bursts = plugins._Bursts()
    key = ("10.89.0.5", "registry.npmjs.org", 443)
    refuse = lambda now: bursts.refuse(key, now, count=3, seconds=5, reset=30)
    assert refuse(0.0) == ("answer", 0)
    assert refuse(0.1) == ("answer", 0)
    assert refuse(0.2) == ("start", 3)
    assert refuse(0.3) == ("reset", 0)
    assert refuse(29.0) == ("reset", 0)
    assert refuse(31.0) == ("after", 2)           # the burst is over: 2 were dropped during it
    assert refuse(31.5) == ("answer", 0)


def test_bursts_window_slides_and_keys_are_separate():
    bursts = plugins._Bursts()
    a, b = ("10.0.0.1", "x.example", 443), ("10.0.0.2", "x.example", 443)
    assert bursts.refuse(a, 0, 3, 5, 30) == ("answer", 0)
    assert bursts.refuse(a, 3, 3, 5, 30) == ("answer", 0)
    assert bursts.refuse(a, 6, 3, 5, 30) == ("answer", 0)     # the one at 0 fell out of the window
    assert bursts.refuse(b, 6, 3, 5, 30) == ("answer", 0)     # another client counts on its own
    assert bursts.refuse(a, 6.5, 3, 5, 30) == ("start", 3)
    assert bursts.refuse(("10.0.0.1", "y.example", 443), 7, 3, 5, 30) == ("answer", 0)  # another host
    assert plugins._Bursts().refuse(a, 0, 0, 5, 30) == ("answer", 0)                     # count 0: off


@pytest.fixture
def burst_env(allowlist_env, monkeypatch):
    monkeypatch.setenv(plugins.BURST_COUNT_ENV, "3")
    monkeypatch.setenv(plugins.BURST_SECONDS_ENV, "5")
    monkeypatch.setenv(plugins.BURST_RESET_ENV, "30")
    monkeypatch.setattr(plugins, "_bursts", plugins._Bursts())
    clock = {"now": 1000.0}
    monkeypatch.setattr(plugins.time, "monotonic", lambda: clock["now"])
    return allowlist_env, clock


class FakeClient:
    addr = ("10.89.0.5", 40000)


def refuse_once(host_port="pypi.org:443"):
    plugin = make(AllowlistPlugin)
    plugin.client = FakeClient()
    with pytest.raises(HttpRequestRejected) as rejected:
        plugin.before_upstream_connection(connect(host_port))
    return plugin, rejected.value


def test_a_burst_of_refusals_is_reset_without_an_answer_and_logged_once(burst_env):
    tmp, clock = burst_env
    for _ in range(2):
        plugin, rejected = refuse_once()
        assert rejected.status_code == 403
        assert plugin.on_access_log({}) is not None
    plugin, rejected = refuse_once()                       # the 3rd within 5 s: the burst starts
    assert rejected.status_code is None                    # no answer: proxy.py closes the connection
    assert plugin.on_access_log({}) is None                # and no access log line
    for _ in range(5):                                     # dropped: no log record each
        assert refuse_once()[1].status_code is None
    log = read_jsonl(tmp / "denied.jsonl")
    assert len(log) == 3
    assert log[2]["client"] == "10.89.0.5"
    assert log[2]["burst"] == "3 refusals within 5s: reset for 30s"

    # A listed host still passes for the same client during the burst.
    allowed = make(AllowlistPlugin)
    allowed.client = FakeClient()
    request = connect("example.com:443")
    assert allowed.before_upstream_connection(request) is request

    clock["now"] += 31                                     # the burst is over: a 403 again, with a summary
    plugin, rejected = refuse_once()
    assert rejected.status_code == 403
    log = read_jsonl(tmp / "denied.jsonl")
    assert len(log) == 4
    assert log[3]["count"] == 6                            # 5 dropped + this one
    assert log[3]["burst"] == "5 dropped during the burst before this"


def test_bursts_can_be_turned_off(burst_env, monkeypatch):
    monkeypatch.setenv(plugins.BURST_COUNT_ENV, "0")
    for _ in range(10):
        assert refuse_once()[1].status_code == 403


def test_approve_counts_a_burst_summary_by_its_count():
    import datetime

    from agent_mitm_proxy.approve import read_refused
    lines = [json.dumps({"timestamp": "2026-10-12T09:00:00+0000", "host": "r.example", "port": 443,
                         "reason": "not in allowlist", "count": 6}),
             json.dumps({"timestamp": "2026-10-12T09:00:01+0000", "host": "r.example", "port": 443,
                         "reason": "not in allowlist"})]
    since = datetime.datetime(2026, 10, 12, tzinfo=datetime.UTC)
    assert read_refused(lines, since)[0].count == 7


def test_bursts_forget_expired_bursts_and_quiet_keys():
    bursts = plugins._Bursts()
    bursts.MAX_KEYS = 10
    for i in range(10):                            # 10 clients, each one burst, never back
        key = (f"10.0.0.{i}", "x.example", 443)
        assert bursts.refuse(key, 0, 2, 5, 30) == ("answer", 0)
        assert bursts.refuse(key, 0, 2, 5, 30) == ("start", 2)
    assert len(bursts._until) == 10
    bursts.refuse(("10.0.1.1", "x.example", 443), 100, 2, 5, 30)   # all bursts over: the sweep runs
    assert len(bursts._until) == 0 and len(bursts._dropped) == 0
    assert list(bursts._times) == [("10.0.1.1", "x.example", 443)]


def test_bursts_sweep_keeps_running_bursts():
    bursts = plugins._Bursts()
    bursts.MAX_KEYS = 2
    live = ("10.0.0.1", "x.example", 443)
    bursts.refuse(live, 0, 2, 5, 30)
    assert bursts.refuse(live, 0, 2, 5, 30) == ("start", 2)
    for i in range(3):
        bursts.refuse((f"10.0.2.{i}", "x.example", 443), 10, 2, 5, 30)
    assert bursts.refuse(live, 11, 2, 5, 30) == ("reset", 0)      # still in its reset period


def test_bursts_a_window_or_reset_below_one_second_counts_as_one():
    bursts = plugins._Bursts()
    key = ("10.0.0.1", "x.example", 443)
    assert bursts.refuse(key, 0.0, 3, 0, 0) == ("answer", 0)
    assert bursts.refuse(key, 0.1, 3, 0, 0) == ("answer", 0)
    assert bursts.refuse(key, 0.2, 3, 0, 0) == ("start", 3)       # a window of 0 still sees the burst
    assert bursts.refuse(key, 0.5, 3, 0, 0) == ("reset", 0)       # reset 0 counts as 1 s
    assert bursts.refuse(key, 1.3, 3, -5, -5)[0] == "after"

"""The forwarder in-process: Starlette's test client in front, httpx.MockTransport as the
hidden service behind it."""

import json

import httpx
import pytest
from starlette.testclient import TestClient

from agent_mitm_proxy.forwarder import Grants, make_app
from agent_mitm_proxy.grants import Service

TARGET = "http://10.0.0.5:11434"


@pytest.fixture
def setup(tmp_path):
    allowlist = tmp_path / "allowlist.txt"
    allowlist.write_text("service:ollama POST /api/chat\nservice:ollama GET /api/tags\n"
                         "service:ollama GET /api/blobs/x\n")
    seen = []

    def upstream(request: httpx.Request) -> httpx.Response:
        # A stream, as from a real service (content= would count as already read).
        seen.append(request)
        if request.url.path == "/api/chat":
            return httpx.Response(200, stream=httpx.ByteStream(b'{"token": "a"}\n{"token": "b"}\n'),
                                  headers={"content-type": "application/x-ndjson"})
        return httpx.Response(200, stream=httpx.ByteStream(b'{"models": []}'))

    def client(service=None, transport=None):
        service = service or Service(name="ollama", listen=11434, target=TARGET, deny=("/api/blobs",),
                                     max_body=100)
        app = make_app(service, Grants(allowlist), tmp_path / "services.jsonl",
                       transport=transport or httpx.MockTransport(upstream))
        return TestClient(app)

    def log():
        return [json.loads(line) for line in (tmp_path / "services.jsonl").read_text().splitlines()]

    return client, seen, log, allowlist


def test_granted_requests_reach_the_hidden_target(setup):
    client, seen, log, _ = setup
    response = client().post("/api/chat?stream=true", content=b'{"model": "m"}',
                             headers={"x-custom": "1"})
    assert response.status_code == 200
    assert response.content == b'{"token": "a"}\n{"token": "b"}\n'
    [request] = seen
    assert str(request.url) == f"{TARGET}/api/chat?stream=true"
    assert request.content == b'{"model": "m"}'
    assert request.headers["x-custom"] == "1"
    assert request.headers["host"] == "10.0.0.5:11434"   # not the sandbox's Host header
    [record] = log()
    assert (record["status"], record["bytes"]) == (200, 30)
    assert "10.0.0.5" not in json.dumps(record) and "model" not in json.dumps(record)


def test_ungranted_method_or_path_is_refused_with_a_hint(setup):
    client, seen, log, _ = setup
    response = client().post("/api/pull", content=b"{}")
    assert response.status_code == 403
    assert "request_allowlist(service='ollama', method='POST', path='/api/pull'" in response.json()["hint"]
    assert client().get("/api/chat").status_code == 403
    assert seen == []
    assert [r["refused"] for r in log()] == ["not granted", "not granted"]


def test_deny_list_wins_over_a_grant(setup):
    client, seen, _, _ = setup
    assert client().get("/api/blobs/x").status_code == 403
    assert seen == []


@pytest.mark.parametrize("path", ["/api/%2e%2e/admin", "/api//tags", "/api/tags;x"])
def test_unusual_paths_are_refused(setup, path):
    client, seen, _, _ = setup
    assert client().get(path).status_code == 400
    assert seen == []


def test_trailing_slash_matches_the_grant(setup):
    client, seen, _, _ = setup
    assert client().get("/api/tags/").status_code == 200
    assert seen[0].url.path == "/api/tags"


def test_new_grants_apply_without_a_restart(setup):
    client, _, _, allowlist = setup
    c = client()
    assert c.delete("/api/delete").status_code == 403
    allowlist.write_text(allowlist.read_text() + "service:ollama DELETE /api/delete\n")
    assert c.delete("/api/delete").status_code == 200


def test_large_bodies_are_refused(setup):
    client, seen, _, _ = setup
    assert client().post("/api/chat", content=b"x" * 101).status_code == 413
    assert seen == []


def test_an_unreachable_service_is_a_502_without_its_address(setup):
    client, _, log, _ = setup

    def unreachable(request):
        raise httpx.ConnectError("connection refused")
    response = client(transport=httpx.MockTransport(unreachable)).get("/api/tags")
    assert response.status_code == 502
    assert "10.0.0.5" not in response.text
    assert log()[-1]["error"] == "ConnectError"


def test_the_slot_is_released_after_each_request(setup):
    client, _, _, _ = setup
    c = client(Service(name="ollama", listen=11434, target=TARGET, max_concurrent=1))
    for _ in range(3):
        assert c.get("/api/tags").status_code == 200

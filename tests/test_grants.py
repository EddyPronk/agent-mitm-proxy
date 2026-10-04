import json

import pytest

from agent_mitm_proxy.grants import (
    Service,
    denied,
    grant_line,
    load_grants,
    load_services,
    normalize_method,
    normalize_path,
)


@pytest.mark.parametrize(("raw", "path"), [
    ("/", "/"),
    ("/api/chat", "/api/chat"),
    ("/api/chat/", "/api/chat"),
    ("/api/chat?stream=true", "/api/chat"),
    ("/v1/models/llama3.2-latest", "/v1/models/llama3.2-latest"),
])
def test_normalize_path(raw, path):
    assert normalize_path(raw) == path


@pytest.mark.parametrize("raw", [
    "", "api/chat", "//api", "/api//chat", "/api/./chat", "/api/../admin", "/api/%2e%2e/admin",
    "/api/chat;x", "/api/ch at", "/" + "a" * 512,
])
def test_normalize_path_refuses_anything_unusual(raw):
    with pytest.raises(ValueError):
        normalize_path(raw)


def test_normalize_method():
    assert normalize_method(" post ") == "POST"
    with pytest.raises(ValueError):
        normalize_method("CONNECT")


def test_denied_matches_the_path_and_everything_below_it():
    svc = Service(name="ollama", listen=11434, target="http://x", deny=("/api/blobs",))
    assert denied(svc, "/api/blobs")
    assert denied(svc, "/api/blobs/sha256-abc")
    assert not denied(svc, "/api/blobsx")
    assert not denied(svc, "/api/chat")


def test_load_services(tmp_path):
    path = tmp_path / "services.json"
    path.write_text(json.dumps({
        "_comment": "ignored",
        "ollama": {"listen": 11434, "target": "http://10.0.0.5:11434/", "deny": ["/api/blobs/"],
                   "risky": {"POST /api/pull": "downloads"}},
    }))
    svc = load_services(path)["ollama"]
    assert (svc.listen, svc.target, svc.deny) == (11434, "http://10.0.0.5:11434", ("/api/blobs",))
    assert svc.risky == {"POST /api/pull": "downloads"}
    assert (svc.max_concurrent, svc.max_body, svc.timeout_s) == (2, 10 * 1024 * 1024, 600)


def test_load_services_missing_file_is_no_services(tmp_path):
    assert load_services(tmp_path / "missing.json") == {}


def test_load_services_refuses_bad_names(tmp_path):
    path = tmp_path / "services.json"
    path.write_text(json.dumps({"Bad Name": {"listen": 1, "target": "http://x"}}))
    with pytest.raises(ValueError):
        load_services(path)


def test_load_grants_reads_only_well_formed_service_lines(tmp_path):
    path = tmp_path / "allowlist.txt"
    path.write_text("\n".join([
        "api.anthropic.com:443",
        grant_line("ollama", "POST", "/api/chat") + "   # approved",
        "service:ollama get /api/tags/",
        "service:ollama POST /api/../admin",
        "service:ollama POST",
        "# service:ollama DELETE /api/delete",
    ]))
    assert load_grants(path) == {("ollama", "POST", "/api/chat"), ("ollama", "GET", "/api/tags")}


def test_load_grants_missing_file_is_no_grants(tmp_path):
    assert load_grants(tmp_path / "missing.txt") == set()

import os
import socket

import pytest

from agent_mitm_proxy import allowlist
from agent_mitm_proxy.allowlist import (
    AllowlistFile,
    allows,
    global_address,
    non_global_reason,
    parse,
    parse_line,
)


@pytest.mark.parametrize(("line", "entry"), [
    ("api.anthropic.com:443", ("api.anthropic.com", 443)),
    ("Example.COM", ("example.com", None)),
    ("*.anthropic.com:443   # a comment", ("*.anthropic.com", 443)),
    ("  pypi.org:443\n", ("pypi.org", 443)),
])
def test_parse_line_reads_host_entries(line, entry):
    assert parse_line(line) == entry


@pytest.mark.parametrize("line", [
    "",
    "   ",
    "# api.anthropic.com:443",
    "#        3  GET /api/claude_cli/bootstrap",
    "service:ollama POST /api/chat",
    "example.com:https",
    "example.com:0",
    "example.com:70000",
    ":443",
    "example.com:",
    "example.com 443",
])
def test_parse_line_ignores_comments_service_grants_and_malformed_lines(line):
    assert parse_line(line) is None


ENTRIES = parse([
    "api.anthropic.com:443",
    "example.com",
    "*.githubusercontent.com:443",
])


@pytest.mark.parametrize(("host", "port", "expected"), [
    ("api.anthropic.com", 443, True),
    ("API.Anthropic.com", 443, True),
    ("api.anthropic.com", 80, False),
    ("anthropic.com", 443, False),
    ("example.com", 8080, True),
    ("www.example.com", 443, False),
    ("raw.githubusercontent.com", 443, True),
    ("a.b.githubusercontent.com", 443, True),
    ("githubusercontent.com", 443, False),       # the wildcard does not cover the bare domain
    ("evilgithubusercontent.com", 443, False),   # nor a name that merely ends the same way
    ("raw.githubusercontent.com", 80, False),
])
def test_allows(host, port, expected):
    assert allows(ENTRIES, host, port) is expected


def fake_resolver(*addresses):
    def resolve(host, port, proto=0):
        return [(socket.AF_INET, socket.SOCK_STREAM, proto, "", (a, port)) for a in addresses]
    return resolve


@pytest.mark.parametrize("address", [
    "10.0.0.5", "192.168.15.1", "172.16.0.1", "127.0.0.1", "169.254.169.254", "100.64.0.1", "::1",
    "fd00::1", "fe80::1", "0.0.0.0",
    "::ffff:192.168.15.1",   # IPv4-mapped
    "64:ff9b::a00:5",        # NAT64 of 10.0.0.5, which Python alone calls global
    "64:ff9b:1::a00:5",      # local-use NAT64
    "::a00:5",               # IPv4-compatible 10.0.0.5, which Python alone calls global
])
def test_non_global_reason_refuses_non_global_addresses(address):
    assert "non-global" in non_global_reason("x.example", 443, fake_resolver(address))


def test_non_global_reason_refuses_if_any_address_is_non_global():
    assert non_global_reason("x.example", 443, fake_resolver("93.184.215.14", "10.0.0.5"))


def test_non_global_reason_accepts_global_addresses():
    assert non_global_reason("x.example", 443, fake_resolver("93.184.215.14", "2606:2800::1")) is None


def test_global_address_is_the_first_checked_address():
    resolve = fake_resolver("2606:2800::1", "93.184.215.14", "64:ff9b::808:808")
    assert global_address("x.example", 443, resolve) == "2606:2800::1"


def test_global_address_refuses_with_the_reason():
    with pytest.raises(ValueError, match="non-global address 10.0.0.5"):
        global_address("x.example", 443, fake_resolver("93.184.215.14", "10.0.0.5"))


def test_non_global_reason_refuses_names_that_do_not_resolve():
    def fail(*args, **kwargs):
        raise socket.gaierror("Name or service not known")
    assert non_global_reason("nowhere.example", 443, fail).startswith("resolve failed")
    assert non_global_reason("nowhere.example", 443, fake_resolver()).startswith("resolve failed")


def test_allowlist_file_missing_allows_nothing(tmp_path):
    assert AllowlistFile(tmp_path / "missing.txt").entries() == frozenset()


def test_allowlist_file_reloads_when_the_file_changes(tmp_path):
    path = tmp_path / "allowlist.txt"
    path.write_text("example.com:443\n")
    allowed = AllowlistFile(path)
    assert allowed.allows("example.com", 443)
    assert not allowed.allows("pypi.org", 443)

    # Same mtime on purpose: a second write within the timestamp resolution must still count.
    stat = path.stat()
    path.write_text("example.com:443\npypi.org:443\n")
    os.utime(path, ns=(stat.st_atime_ns, stat.st_mtime_ns))
    assert allowed.allows("pypi.org", 443)

    path.unlink()
    assert not allowed.allows("example.com", 443)


def test_allowlist_file_reads_the_file_only_when_it_changed(tmp_path, monkeypatch):
    path = tmp_path / "allowlist.txt"
    path.write_text("example.com:443\n")
    allowed = AllowlistFile(path)
    allowed.entries()
    calls = []
    monkeypatch.setattr(allowlist, "parse", lambda lines: calls.append(1) or frozenset())
    allowed.entries()
    assert calls == []

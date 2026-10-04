"""What a client can reach when its only way out is the proxy.

The checks run inside a client container through `podman exec`, using the client's own proxy
settings (HTTPS_PROXY etc. and the proxy CA in its container environment). They need a running
proxy and client: set AGENT_MITM_PROXY_CLIENT to the client's container name, or they are skipped.

PROXYTEST_ALLOWED is a host on the allowlist, PROXYTEST_BLOCKED one that is not, and
PROXYTEST_LAN an address on your LAN that must stay unreachable.
"""

import os
import subprocess

import pytest

CLIENT = os.environ.get("AGENT_MITM_PROXY_CLIENT")
ALLOWED = os.environ.get("PROXYTEST_ALLOWED", "api.anthropic.com")
BLOCKED = os.environ.get("PROXYTEST_BLOCKED", "example.com")
LAN = os.environ.get("PROXYTEST_LAN", "192.168.15.1")

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(not CLIENT, reason="set AGENT_MITM_PROXY_CLIENT to a running client container"),
]

CURL_CONNECT_FAILED = 56  # the proxy refused the CONNECT tunnel
CURL_COULDNT_CONNECT = 7


def in_client(*command):
    """Run COMMAND inside the client container, giving up after 8 seconds."""
    return subprocess.run(
        ["podman", "exec", CLIENT, "timeout", "8", *command],
        capture_output=True, text=True, timeout=30, check=False,
    )


def curl(url, *options):
    """(exit status, HTTP status, stderr) of a curl request from the client."""
    result = in_client("curl", "-sS", "-o", "/dev/null", "-w", "%{http_code}", *options, url)
    return result.returncode, result.stdout.strip(), result.stderr


def test_the_proxy_name_resolves():
    assert in_client("getent", "hosts", "proxy").returncode == 0


def test_other_names_do_not_resolve():
    assert in_client("getent", "hosts", BLOCKED).returncode != 0


def test_the_client_has_no_default_route():
    routes = in_client("cat", "/proc/net/route").stdout.splitlines()[1:]
    assert all(line.split()[1] != "00000000" for line in routes)


def test_an_allowlisted_host_is_reachable():
    status, http, stderr = curl(f"https://{ALLOWED}")
    assert status == 0, stderr
    assert http not in ("000", "403"), "expected an answer from the host, not the proxy"


@pytest.mark.parametrize("host", [BLOCKED, "1.1.1.1"], ids=["not-on-allowlist", "ip-address"])
def test_the_proxy_refuses_a_tunnel_to(host):
    status, _, stderr = curl(f"https://{host}")
    assert status == CURL_CONNECT_FAILED, stderr
    assert "response 403" in stderr


@pytest.mark.parametrize("url", [f"http://{LAN}", "http://host.containers.internal:631"],
                         ids=["lan", "host"])
def test_the_proxy_refuses_private_addresses(url):
    status, http, stderr = curl(url)
    assert (status, http) == (0, "403"), stderr


def test_bypassing_the_proxy_fails():
    status, _, stderr = curl("https://1.1.1.1", "--noproxy", "*")
    assert status == CURL_COULDNT_CONNECT, stderr

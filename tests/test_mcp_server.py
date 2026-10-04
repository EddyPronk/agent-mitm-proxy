"""The MCP tools, called in-process on a gatekeeper without a relay (see fakes.py)."""

import json

from fakes import connected, reaction

from agent_mitm_proxy.mcp_server import build_server


async def call(server, tool, **arguments):
    result = await server.call_tool(tool, arguments)
    assert not result.is_error
    [content] = result.content
    return json.loads(content.text)


async def test_lists_the_two_tools(cfg):
    server = build_server(connected(cfg), "test sandbox")
    assert [t.name for t in await server.list_tools()] == ["request_allowlist", "get_request_status"]


async def test_request_and_poll_until_approved(cfg):
    gk = connected(cfg)
    server = build_server(gk, "test sandbox")
    result = await call(server, "request_allowlist", reason="install packages", host="pypi.org")
    assert result["status"] == "pending"
    assert "From: test sandbox" in gk.client.sent[0]["content"]

    status = await call(server, "get_request_status", request_id=result["request_id"])
    assert status["status"] == "pending"
    await gk._handle(reaction(gk.client.sent[0]["id"]))
    status = await call(server, "get_request_status", request_id=result["request_id"])
    assert status["status"] == "approved"


async def test_refusals_come_back_as_a_status_with_the_error(cfg):
    server = build_server(connected(cfg), "test sandbox")
    result = await call(server, "request_allowlist", reason="r", host="10.0.0.5")
    assert (result["host"], result["status"]) == ("10.0.0.5", "refused")
    assert "IP addresses" in result["error"]

    result = await call(server, "request_allowlist", reason="r", service="ollama",
                        method="GET", path="/api/blobs/x")
    assert (result["service"], result["status"]) == ("ollama", "refused")


async def test_service_requests_go_through_the_tool(cfg):
    gk = connected(cfg)
    server = build_server(gk, "test sandbox")
    result = await call(server, "request_allowlist", reason="chat", service="ollama",
                        method="POST", path="/api/chat")
    assert (result["service"], result["method"], result["path"], result["status"]) == \
        ("ollama", "POST", "/api/chat", "pending")

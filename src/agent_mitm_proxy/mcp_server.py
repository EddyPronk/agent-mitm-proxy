"""MCP server: lets a sandboxed agent request allowlist entries.

Runs next to the proxy and serves MCP over streamable HTTP on :8900/mcp for the sandboxes on
the proxy's network (e.g. http://proxy:8900/mcp). The agent can only *request*; the owner
decides on Buzz (see `gatekeeper`).

    python -m agent_mitm_proxy.mcp_server     # configured with GATEKEEPER_* variables

Besides the gatekeeper's variables:

| Variable | Default | Meaning |
|---|---|---|
| GATEKEEPER_PORT | 8900 | Port to listen on (all interfaces) |
| GATEKEEPER_HOSTNAMES | proxy,localhost,127.0.0.1 | Names clients may use in the Host header (DNS-rebinding protection) |
| GATEKEEPER_REQUESTER | a sandbox | Who asks, as shown to the owner |
"""

import asyncio
import os

from mcp.server.mcpserver import MCPServer
from mcp.server.transport_security import TransportSecuritySettings

from .gatekeeper import Config, Gatekeeper, GatekeeperError

INSTRUCTIONS = (
    "The sandbox can only reach hosts on the proxy allowlist; others fail with "
    "403 'Blocked by sandbox egress allowlist'. Use request_allowlist to ask the "
    "owner to allow a host (they approve on their phone, usually within minutes), "
    "then poll get_request_status. Internal services (e.g. ollama at "
    "http://proxy:11434) answer 403 'not granted' for each method + path until "
    "requested with request_allowlist(service=..., method=..., path=...). Request "
    "only what the task really needs and give an honest, specific reason."
)


def build_server(gatekeeper: Gatekeeper, requester: str) -> MCPServer:
    server = MCPServer(name="allowlist-gatekeeper", instructions=INSTRUCTIONS)

    @server.tool()
    async def request_allowlist(reason: str, host: str | None = None, port: int = 443,
                                service: str | None = None, method: str = "GET",
                                path: str | None = None) -> dict:
        """Ask the owner for access. Two kinds:

        - Internet host: give `host` (and `port`, default 443), e.g. host="pypi.org".
        - Internal service: give `service`, `method` and the exact `path`, e.g.
          service="ollama", method="POST", path="/api/chat". Each method + path is
          granted separately; the service's internal address is never exposed.

        Returns immediately with a request_id and status "pending" (or
        "already_allowed", or "refused" with an error). Poll get_request_status
        until approved, rejected or expired. `reason` is shown to the owner verbatim.
        """
        try:
            return await gatekeeper.request(reason, requester, host=host, port=port,
                                            service=service, method=method, path=path)
        except (ValueError, GatekeeperError) as e:
            target = ({"service": service, "method": method, "path": path} if service
                      else {"host": host, "port": port})
            return {**target, "status": "refused", "error": str(e)}

    @server.tool()
    async def get_request_status(request_id: str) -> dict:
        """Current status of a request: pending, approved, rejected, expired or unknown."""
        return gatekeeper.status(request_id)

    return server


async def main() -> None:
    port = int(os.environ.get("GATEKEEPER_PORT", "8900"))
    hostnames = os.environ.get("GATEKEEPER_HOSTNAMES", "proxy,localhost,127.0.0.1").split(",")
    gatekeeper = Gatekeeper(Config.from_env())
    server = build_server(gatekeeper, os.environ.get("GATEKEEPER_REQUESTER", "a sandbox"))
    security = TransportSecuritySettings(
        enable_dns_rebinding_protection=True,
        allowed_hosts=[f"{name.strip()}:{port}" for name in hostnames if name.strip()],
        allowed_origins=[],
    )
    await asyncio.gather(
        gatekeeper.run(),
        server.run_streamable_http_async(
            host="0.0.0.0", port=port, json_response=True, stateless_http=True,
            transport_security=security,
        ),
    )


if __name__ == "__main__":
    asyncio.run(main())

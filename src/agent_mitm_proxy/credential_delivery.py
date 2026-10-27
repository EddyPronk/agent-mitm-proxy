"""Hands a client sandbox its Claude Code credentials file, with the vault's placeholders.

    GET http://agent-mitm-proxy.internal/v1/credentials/claude     (through the proxy, plain HTTP)

is answered by the proxy itself and never forwarded: 200 with the JSON of
`~/.claude/.credentials.json` as Claude Code writes it after a sign-in, holding the placeholders
of the client's newest vault entry (never a real token), or 404 when there is none. A new sandbox
then needs no sign-in of its own (`proxy-credentials fetch` on the client side).

With proxy authentication (`client_auth`), a client gets only an entry it belongs to (it signed in
with it, or was granted it with `vault grant`); without it, the vault's newest entry. Every answer
is logged to the vault log, without token values.

List it first in --plugins: the allowlist would refuse the made-up host (it doesn't resolve).
"""

import json
import os
import time
from typing import Any

from proxy.common.utils import build_http_response
from proxy.http.parser import HttpParser
from proxy.http.proxy import HttpProxyBasePlugin

from .client_auth import client_of
from .credential_vault import VAULT_ENV, VAULT_LOG_ENV, Vault, _lock
from .plugins import _now

DELIVERY_HOST = "agent-mitm-proxy.internal"
DELIVERY_PATH = "/v1/credentials/claude"


def credentials_file(e: dict[str, Any]) -> dict[str, Any]:
    """Claude Code's .credentials.json for vault entry E: its placeholders in place of the tokens.
    Times in milliseconds. Fields Claude Code fills in itself later (subscriptionType,
    rateLimitTier) are left out; it works without them."""
    oauth: dict[str, Any] = {
        "accessToken": e["placeholder_access"],
        "refreshToken": e["placeholder_refresh"],
        "expiresAt": int(e["expires_at"]) * 1000,
        "scopes": str(e.get("response", {}).get("scope", "")).split(),
    }
    if "refresh_expires_at" in e:
        oauth["refreshTokenExpiresAt"] = int(e["refresh_expires_at"]) * 1000
    return {"claudeAiOauth": oauth}


def is_delivery(request: HttpParser) -> bool:
    return (request.method == b"GET"
            and (request.host or b"").decode("latin-1").lower() == DELIVERY_HOST
            and (request.path or b"").partition(b"?")[0].decode("latin-1") == DELIVERY_PATH)


class CredentialDeliveryPlugin(HttpProxyBasePlugin):
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.vault = Vault(os.environ.get(VAULT_ENV, "credential-vault.json"))
        self.log_path = os.environ.get(VAULT_LOG_ENV, "vault.jsonl")

    def before_upstream_connection(self, request: HttpParser) -> HttpParser | None:
        return None if is_delivery(request) else request      # nothing to connect to

    def handle_client_request(self, request: HttpParser) -> HttpParser | None:
        if not is_delivery(request):
            return request
        name = client_of(self)
        addr = getattr(self.client, "addr", None)
        client = name or (str(addr[0]) if addr else None)
        found = self.vault.newest_for(name)
        if found is None:
            status, reason = 404, b"Not Found"
            body = json.dumps({"error": "no sign-in in the proxy's vault for this client"}).encode()
            self._log("credentials-refused", client=client, reason="no entry for this client")
        else:
            entry_id, e = found
            status, reason = 200, b"OK"
            body = json.dumps(credentials_file(e)).encode()
            self._log("credentials-delivered", client=client, entry=entry_id,
                      expires_in=int(e["expires_at"]) - int(time.time()))
        self.client.queue(memoryview(build_http_response(
            status, reason=reason, body=body,
            headers={b"Content-Type": b"application/json",
                     b"Content-Length": str(len(body)).encode(),
                     b"Cache-Control": b"no-store",
                     b"Connection": b"close"})))
        return None

    def _log(self, event: str, **fields: Any) -> None:
        line = json.dumps({"timestamp": _now(), "pid": os.getpid(), "event": event,
                           "host": DELIVERY_HOST, "path": DELIVERY_PATH, **fields}) + "\n"
        with _lock, open(self.log_path, "a", encoding="utf-8") as out:
            out.write(line)

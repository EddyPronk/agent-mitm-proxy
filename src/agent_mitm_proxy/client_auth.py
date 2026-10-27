"""Proxy authentication with a name and a token per client sandbox.

    proxy --auth-plugin agent_mitm_proxy.client_auth.ClientAuthPlugin ...

proxy.py's own --basic-auth takes one user:password for everyone. This plugin reads a file of
enrolled clients instead, {"NAME": "<sha256 of its token>"}, so each client has a name and the
proxy keeps only hashes. A client sends its name and token as the credentials of its proxy URL:

    HTTPS_PROXY=http://NAME:TOKEN@proxy:8899

Every connection without valid credentials gets 407 (proxy.py's ProxyAuthenticationFailed); the
comparison is constant-time. proxy.py loads an auth plugin ahead of the --plugins, and hands all
of a connection's plugins the same client object (TLS interception wraps it in place), so the name
is kept there for the other plugins: `client_of(plugin)`.

- **Every request**, not just a connection's first, has its Proxy-Authorization removed: proxy.py
  checks only the first request of a connection (before_upstream_connection), and passes later
  ones on a kept-alive plain HTTP connection upstream as they came.
- **Revocation is immediate:** the file is read again for every request, and a connection whose
  name was unenrolled, or got a new token, since it authenticated is refused (and closed).
- **Changes to the file** take a lock (a lock file next to it) for the whole read, change and
  write (`update_clients`), so two `vault` commands at once can't undo each other.

| Variable | Default | Meaning |
|---|---|---|
| AGENT_MITM_PROXY_CLIENTS | clients.json | The enrolled clients: name → token hash; mode 0600 |
| AGENT_MITM_PROXY_CLIENTS_LOG | clients.jsonl | Refused connections, as JSONL; never token values |
"""

import base64
import binascii
import fcntl
import hashlib
import hmac
import json
import os
import secrets
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

from proxy.http.exception import ProxyAuthenticationFailed
from proxy.http.parser import HttpParser
from proxy.http.proxy.auth import AuthPlugin

from .plugins import _now

CLIENTS_ENV = "AGENT_MITM_PROXY_CLIENTS"
CLIENTS_LOG_ENV = "AGENT_MITM_PROXY_CLIENTS_LOG"
# Where the name, and the hash it authenticated with, are kept on the client connection.
NAME_ATTR = "agent_mitm_proxy_client"
HASH_ATTR = "agent_mitm_proxy_client_hash"


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def new_token() -> str:
    return secrets.token_urlsafe(24)


def load_clients(path: str) -> dict[str, str]:
    try:
        with open(path, encoding="utf-8") as f:
            clients = json.load(f)
    except (OSError, ValueError):
        return {}
    return clients if isinstance(clients, dict) else {}


def save_clients(path: str, clients: dict[str, str]) -> None:
    """Write CLIENTS to PATH (mode 0600) by renaming a temporary file over it. To change the file,
    use update_clients: this alone doesn't keep another writer from undoing the change."""
    tmp = f"{path}.{os.getpid()}.tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(clients, f, indent=2)
    os.replace(tmp, path)


@contextmanager
def update_clients(path: str) -> Iterator[dict[str, str]]:
    """The enrolled clients, to change in place, under an exclusive lock (a lock file next to
    PATH) that covers the read, the change and the write."""
    fd = os.open(path + ".lock", os.O_RDWR | os.O_CREAT, 0o600)
    with os.fdopen(fd, "r+") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        clients = load_clients(path)
        yield clients
        save_clients(path, clients)


def client_name(header: bytes, clients: dict[str, str]) -> str | None:
    """The enrolled client a Proxy-Authorization header (Basic NAME:TOKEN) belongs to, or None."""
    parts = header.split()
    if len(parts) != 2 or parts[0].lower() != b"basic":
        return None
    try:
        name, _, token = base64.b64decode(parts[1], validate=True).decode().partition(":")
    except (binascii.Error, UnicodeDecodeError):
        return None
    stored = clients.get(name)
    if not isinstance(stored, str) or not hmac.compare_digest(stored, token_hash(token)):
        return None
    return name


def client_of(plugin: Any) -> str | None:
    """The enrolled name of PLUGIN's client connection; None without ClientAuthPlugin."""
    return getattr(plugin.client, NAME_ATTR, None)


class ClientAuthPlugin(AuthPlugin):
    def before_upstream_connection(self, request: HttpParser) -> HttpParser | None:
        """A connection's first request: authenticate it, and keep the name on the connection."""
        clients = load_clients(os.environ.get(CLIENTS_ENV, "clients.json"))
        header = (request.header(b"proxy-authorization")
                  if request.has_header(b"proxy-authorization") else b"")
        name = client_name(header, clients)
        if name is None:
            self._log_refusal("proxy-auth-refused", had_credentials=bool(header))
            raise ProxyAuthenticationFailed()
        request.del_header(b"proxy-authorization")
        setattr(self.client, NAME_ATTR, name)
        setattr(self.client, HASH_ATTR, clients[name])
        return request

    def handle_client_request(self, request: HttpParser) -> HttpParser | None:
        """Every request (the first one too, and each inside a TLS tunnel or on a kept-alive
        connection): never pass Proxy-Authorization on, and refuse it if the connection's name has
        been unenrolled or has a new token since the connection authenticated."""
        if request.has_header(b"proxy-authorization"):
            request.del_header(b"proxy-authorization")
        name = getattr(self.client, NAME_ATTR, None)
        if name is not None:
            current = load_clients(os.environ.get(CLIENTS_ENV, "clients.json")).get(name)
            if not isinstance(current, str) or not hmac.compare_digest(
                    current, getattr(self.client, HASH_ATTR, "")):
                self._log_refusal("proxy-auth-revoked", client=name)
                raise ProxyAuthenticationFailed()
        return request

    def _log_refusal(self, event: str, **fields: Any) -> None:
        addr = getattr(self.client, "addr", None)
        line = json.dumps({"timestamp": _now(), "pid": os.getpid(), "event": event,
                           "client_ip": str(addr[0]) if addr else None, **fields}) + "\n"
        with open(os.environ.get(CLIENTS_LOG_ENV, "clients.jsonl"), "a", encoding="utf-8") as out:
            out.write(line)

"""proxy.py plugins: the egress allowlist, and a log of the decrypted traffic.

    proxy --plugins agent_mitm_proxy.plugins.AllowlistPlugin,agent_mitm_proxy.plugins.TrafficLogPlugin

List AllowlistPlugin first: then a refused request is never logged. Both are configured with
environment variables, read for each connection:

| Variable | Default | Meaning |
|---|---|---|
| AGENT_MITM_PROXY_ALLOWLIST | allowlist.txt | The allowlist (see `allowlist`); missing: allow nothing |
| AGENT_MITM_PROXY_DENIED_LOG | denied.jsonl | Refused connections, as JSONL |
| AGENT_MITM_PROXY_TRAFFIC_LOG | decrypted-traffic.jsonl | Decrypted request and response bodies, as JSONL |

The traffic log holds whatever the agent sends and receives: treat it as sensitive. Headers are
never logged, because they carry credentials.
"""

import base64
import gzip
import json
import os
import socket
import threading
import time
from typing import Any

import brotli
from proxy.http.exception import HttpRequestRejected
from proxy.http.parser import HttpParser, httpParserTypes
from proxy.http.proxy import HttpProxyBasePlugin

from .allowlist import AllowlistFile, global_address

ALLOWLIST_ENV = "AGENT_MITM_PROXY_ALLOWLIST"
DENIED_LOG_ENV = "AGENT_MITM_PROXY_DENIED_LOG"
TRAFFIC_LOG_ENV = "AGENT_MITM_PROXY_TRAFFIC_LOG"

_log_lock = threading.Lock()


def _append_jsonl(path: str, record: dict[str, Any]) -> None:
    line = json.dumps(record, ensure_ascii=False) + "\n"
    with _log_lock, open(path, "a", encoding="utf-8") as out:
        out.write(line)


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S%z")


# proxy.py creates a plugin instance per connection; the allowlist is loaded once per file.
_allowlists: dict[str, AllowlistFile] = {}
_allowlists_lock = threading.Lock()


def _allowlist_file(path: str) -> AllowlistFile:
    with _allowlists_lock:
        if path not in _allowlists:
            _allowlists[path] = AllowlistFile(path)
        return _allowlists[path]


class AllowlistPlugin(HttpProxyBasePlugin):
    """Connect upstream only to listed hosts that resolve to global addresses; log refusals.

    Runs before the upstream connection is made, for CONNECT (HTTPS) and plain HTTP alike.
    The host is resolved once, and proxy.py connects to the address that was checked (via
    resolve_dns), not to the answer of a second lookup: otherwise a host could pass the check
    with a global address and then resolve to a LAN address for the connection (DNS rebinding).
    TLS to the upstream server is still verified against the host name.
    """

    resolve = staticmethod(socket.getaddrinfo)

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.allowlist = _allowlist_file(os.environ.get(ALLOWLIST_ENV, "allowlist.txt"))
        self.denied_log = os.environ.get(DENIED_LOG_ENV, "denied.jsonl")
        self.checked: tuple[str, int, str] | None = None   # host, port, the address to use
        self.refused: tuple[str, int] | None = None         # host, port, for the access log

    def before_upstream_connection(self, request: HttpParser) -> HttpParser | None:
        host = (request.host or b"").decode("utf-8", "replace").lower()
        port = request.port or (443 if request.method == b"CONNECT" else 80)
        self.checked = None
        if getattr(self.flags, "enable_conn_pool", False):
            # Pooled connections are made without resolve_dns, so the check would not hold.
            self._deny(host, port, "proxy.py's --enable-conn-pool is not supported")
        if not self.allowlist.allows(host, port):
            self._deny(host, port, "not in allowlist")
        try:
            address = global_address(host, port, self.resolve)
        except ValueError as e:
            self._deny(host, port, str(e))
        self.checked = (host, port, address)
        return request

    def resolve_dns(self, host: str, port: int) -> tuple[str | None, tuple[str, int] | None]:
        """The address checked in before_upstream_connection. Without one, refuse to connect
        rather than let proxy.py resolve the host itself."""
        if self.checked is None or self.checked[:2] != (host.lower(), port):
            raise ConnectionRefusedError(f"no checked address for {host}:{port}")
        return self.checked[2], None

    def on_access_log(self, context: dict[str, Any]) -> dict[str, Any] | None:
        """proxy.py takes the access log's target from the upstream connection, which a refused
        request never gets ("CONNECT None:None"): name what was refused, and the 403."""
        if self.refused and context.get("server_host") is None:
            context.update(server_host=self.refused[0], server_port=self.refused[1],
                           response_code="403", response_reason="Forbidden")
        return context

    def _deny(self, host: str, port: int, reason: str) -> None:
        self.refused = (host, port)
        try:
            _append_jsonl(self.denied_log,
                          {"timestamp": _now(), "host": host, "port": port, "reason": reason})
        except OSError:
            pass  # refuse the connection even if the log can't be written
        raise HttpRequestRejected(
            status_code=403,
            reason=b"Forbidden",
            body=f"Blocked by sandbox egress allowlist: {host}:{port} ({reason})\n".encode(),
        )


class TrafficLogPlugin(HttpProxyBasePlugin):
    """Log decrypted requests and responses as JSONL, without modifying them.

    Sees plain HTTP only after proxy.py has terminated the client's TLS connection (TLS
    interception). Request and response headers are deliberately left out.
    """

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.path = os.environ.get(TRAFFIC_LOG_ENV, "decrypted-traffic.jsonl")
        self.host = ""
        self.request_path = ""
        self.response = HttpParser(httpParserTypes.RESPONSE_PARSER)
        self.response_logged = False

    def _write(self, record: dict[str, Any]) -> None:
        record["timestamp"] = _now()
        record["pid"] = os.getpid()
        _append_jsonl(self.path, record)

    def handle_client_request(self, request: HttpParser) -> HttpParser | None:
        # CONNECT is the outer proxy handshake. The interesting HTTP request
        # arrives only after TLS interception, so do not log this envelope.
        if request.method == b"CONNECT":
            return request
        self.response = HttpParser(httpParserTypes.RESPONSE_PARSER)
        self.response_logged = False
        if request.host:
            self.host = request.host.decode("utf-8", "replace")
        self.request_path = request.path.decode("utf-8", "replace") if request.path else ""
        record = {
            "direction": "request",
            "host": self.host,
            "path": self.request_path,
            "method": request.method.decode("ascii", "replace") if request.method else "",
        }
        self._add_body(record, bytes(request.body or b""), _content_encoding(request))
        self._write(record)
        return request

    def before_upstream_connection(self, request: HttpParser) -> HttpParser | None:
        if request.host:
            self.host = request.host.decode("utf-8", "replace")
        return request

    def handle_upstream_chunk(self, chunk: memoryview) -> memoryview | None:
        self.response.parse(chunk)
        if self.response.is_complete and not self.response_logged:
            record = {
                "direction": "response",
                "host": self.host,
                "path": self.request_path,
                "status": self.response.code.decode("ascii", "replace") if self.response.code else "",
            }
            self._add_body(record, bytes(self.response.body or b""), _content_encoding(self.response))
            self._write(record)
            self.response_logged = True
        return chunk

    def on_upstream_connection_close(self) -> None:
        if not self.response_logged and self.response.body:
            self._write({
                "direction": "response",
                "host": self.host,
                "path": self.request_path,
                "body": bytes(self.response.body).decode("utf-8", "replace"),
                "partial": True,
            })

    @staticmethod
    def _add_body(record: dict[str, Any], body: bytes, encoding: bytes) -> None:
        decoded = _decode(body, encoding)
        record["body"] = decoded.decode("utf-8", "replace")
        if encoding:
            record["content_encoding"] = encoding.decode("ascii", "replace")
            record["decoded"] = decoded is not body
            if decoded is body:  # unknown or broken encoding: keep the exact bytes too
                record["body_base64"] = base64.b64encode(body).decode("ascii")


def _content_encoding(message: HttpParser) -> bytes:
    return message.header(b"content-encoding") if message.has_header(b"content-encoding") else b""


def _decode(body: bytes, encoding: bytes) -> bytes:
    """The decompressed body, or `body` itself if the encoding is unknown or broken."""
    encoding = encoding.lower().strip()
    try:
        if encoding == b"gzip":
            return gzip.decompress(body)
        if encoding == b"br":
            return brotli.decompress(body)
    except (OSError, ValueError, EOFError, brotli.error):
        pass
    return body

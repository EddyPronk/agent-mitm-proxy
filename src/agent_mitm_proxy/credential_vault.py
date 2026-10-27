"""The credential vault: Claude Code's OAuth tokens stay in the proxy; the sandbox gets placeholders.

    proxy --plugins ...AllowlistPlugin,...TrafficLogPlugin,agent_mitm_proxy.credential_vault.CredentialVaultPlugin

Claude Code signs in with OAuth: it POSTs an authorization code (or, later, a refresh token) to
platform.claude.com/v1/oauth/token and gets an access token and a refresh token back. This plugin
follows that flow from the middle, so that no real token is ever in the sandbox:

- **Sign-in:** the real tokens go into the vault (a file in the proxy's private data directory);
  the client gets placeholders instead: `agent-mitm-proxy-oat-<48 hex>` for the access token and
  `agent-mitm-proxy-ort-<48 hex>` for the refresh token. Claude Code doesn't check their shape.
- **Every other request to VAULT_HOSTS:** `Authorization: Bearer <placeholder>` (or `x-api-key`)
  is swapped for the real access token.
- **Refresh:** the client's placeholders never change, so the vault answers a refresh itself (same
  placeholders, the real tokens' remaining lifetimes, the other fields of the last real response)
  unless the real access token needs one: it expires within REFRESH_MARGIN, or a request with the
  current token got a 401. Then one refresh goes upstream, with the real refresh token swapped in;
  refreshes that arrive while it's on its way are answered too. Anthropic revokes the previous
  access token on every refresh, so refreshing more than needed makes requests that are on their
  way with it fail, and Claude Code refreshes again on those 401s.
- **Adoption:** a refresh that carries a real refresh token (a client that signed in before the
  vault was there) goes upstream as usual, and its response is kept like a sign-in's: the client
  gets placeholders, and the refresh token it held is spent.
- **Revoke** (`/logout`): the placeholder in the body is swapped for the real token; a 200 removes
  the entry.

Real tokens are sent only down a CONNECT tunnel to port 443 of one of VAULT_HOSTS (TLS, verified
upstream), and only in requests that name no other host: the tunnel's destination decides, not
the request line or Host header, which the client chooses (proxy.py sends every request on a
connection to the host it was opened for). A placeholder anywhere else goes out unchanged (it's
worthless outside this proxy) and is logged as `placeholder-elsewhere`; an unknown one as
`unknown-placeholder`.

**Token responses** are rewritten whole: access and refresh tokens become placeholders, an
`id_token` is withheld, other fields pass. One the vault can't read (an unknown encoding), or one
with tokens where none were expected, isn't passed on: the client gets a 502. So does a client
whose token response was cut off upstream.

**Forgetting entries.** A sign-in (or adoption) for an account replaces the earlier entries of
that account from the same client address: they're dropped from the vault, not revoked upstream.
Entries whose refresh token has expired are dropped too. (A container that gets another's old
address and signs in to the same account makes the other sign in again.)

proxy.py runs one process per CPU, so the vault isn't held in memory: every lookup and update
reads the file under an flock (on a lock file next to it). Updates are written to a temporary
file and renamed over the vault, so it's never half-written; a vault that group or others can
read is refused.

| Variable | Default | Meaning |
|---|---|---|
| AGENT_MITM_PROXY_VAULT | credential-vault.json | The vault: real tokens, by entry; mode 0600 |
| AGENT_MITM_PROXY_VAULT_LOG | vault.jsonl | What the vault did, as JSONL; never token values |
| AGENT_MITM_PROXY_VAULT_STYLE | plain | New placeholders: `plain` (above) or `sk-ant` (with Anthropic's prefixes, for a client that wants them) |

List this plugin after TrafficLogPlugin: the traffic log then sees the request as the client sent
it (placeholders) and the response as it came (real tokens, which `redact` blanks out). A refresh
the vault answers itself has no response in the traffic log; the vault log has it.
"""

import fcntl
import json
import os
import secrets
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any
from urllib.parse import parse_qsl, urlencode

from proxy.common.utils import build_http_response
from proxy.http.parser import HttpParser, httpParserTypes
from proxy.http.proxy import HttpProxyBasePlugin

from .oauth import REVOKE_PATH, TOKEN_FIELDS, TOKEN_HOST, TOKEN_PATH
from .plugins import _decode, _now

VAULT_ENV = "AGENT_MITM_PROXY_VAULT"
VAULT_LOG_ENV = "AGENT_MITM_PROXY_VAULT_LOG"
STYLE_ENV = "AGENT_MITM_PROXY_VAULT_STYLE"

# Where a real token may be sent: exact host names, those Claude Code sends its token to
# (October 2026), on port 443 through a CONNECT tunnel. mcp-proxy.anthropic.com: the claude.ai
# MCP connectors.
VAULT_HOSTS = frozenset({"api.anthropic.com", TOKEN_HOST, "mcp-proxy.anthropic.com"})

# Refresh upstream only when the real access token expires within this many seconds.
REFRESH_MARGIN = 300
# A refresh on its way upstream for at most this long: refreshes meanwhile are answered by the
# vault. After it (a refresh that never came back), the next one goes upstream again.
REFRESH_INFLIGHT = 30
# A token response's credentials (oauth.TOKEN_FIELDS) and what the client gets of each: the
# access and refresh tokens become placeholders; any other (an id_token: Claude Code's responses
# haven't had one so far) is withheld, neither kept nor passed on. Every other field of a token
# response is kept, to answer refreshes with.
WITHHELD_FIELDS = tuple(f for f in TOKEN_FIELDS if f not in ("access_token", "refresh_token"))

# Placeholders: (access prefix, refresh prefix), then 48 random hex digits (192 bits, so that
# another client of the proxy can't guess them).
STYLES = {
    "plain": ("agent-mitm-proxy-oat-", "agent-mitm-proxy-ort-"),
    "sk-ant": ("sk-ant-oat01-agent-mitm-proxy-", "sk-ant-ort01-agent-mitm-proxy-"),
}
PREFIXES = tuple(p for pair in STYLES.values() for p in pair)
# A real refresh token (adoption); a placeholder in the sk-ant style starts like one too.
REAL_REFRESH_PREFIX = "sk-ant-ort01-"

_lock = threading.Lock()


def placeholder(kind: str, style: str | None = None) -> str:
    """A new placeholder; KIND is "access" or "refresh"."""
    style = style or os.environ.get(STYLE_ENV, "plain")
    access, refresh = STYLES.get(style, STYLES["plain"])
    return (access if kind == "access" else refresh) + secrets.token_hex(24)


def is_placeholder(token: str) -> bool:
    return token.startswith(PREFIXES)


def _account(tokens: dict[str, Any]) -> str | None:
    account = tokens.get("account")
    return account.get("uuid") if isinstance(account, dict) else None


class Vault:
    """The vault file: {"entries": {id: {placeholders, real tokens, times, the last response}}}.

    Methods that change entries list what they dropped in `forgotten` (id, reason), for the log.
    """

    def __init__(self, path: str) -> None:
        self.path = path
        self.forgotten: list[tuple[str, str]] = []

    @contextmanager
    def _open(self, write: bool) -> Iterator[dict[str, Any]]:
        fd = os.open(self.path + ".lock", os.O_RDWR | os.O_CREAT, 0o600)
        with _lock, os.fdopen(fd, "r+") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX if write else fcntl.LOCK_SH)
            data = self._read()
            yield data
            if write:
                self._write(data)

    def _read(self) -> dict[str, Any]:
        try:
            info = os.stat(self.path)
        except FileNotFoundError:
            return {"entries": {}}
        if info.st_mode & 0o077:
            raise PermissionError(f"{self.path} has mode {info.st_mode & 0o777:o}; refusing to use it")
        with open(self.path, encoding="utf-8") as f:
            text = f.read()
        return json.loads(text) if text.strip() else {"entries": {}}

    def _write(self, data: dict[str, Any]) -> None:
        """Write to a temporary file next to the vault and rename it over the vault."""
        tmp = f"{self.path}.{os.getpid()}.{threading.get_ident()}.tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, self.path)
        except BaseException:
            try:
                os.unlink(tmp)
            except FileNotFoundError:
                pass
            raise
        dir_fd = os.open(os.path.dirname(os.path.abspath(self.path)), os.O_RDONLY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)

    def _sweep(self, data: dict[str, Any], now: float) -> None:
        """Drop entries whose refresh token has expired (or, without one, whose access token has)."""
        for entry_id, e in list(data["entries"].items()):
            until = e.get("refresh_expires_at") if e.get("refresh_token") else e.get("expires_at")
            if until is not None and until < now:
                del data["entries"][entry_id]
                self.forgotten.append((entry_id, "expired"))

    def find(self, token: str) -> tuple[str, dict[str, Any]] | None:
        """The entry whose access or refresh placeholder is TOKEN."""
        with self._open(write=False) as data:
            for entry_id, e in data["entries"].items():
                if token in (e.get("placeholder_access"), e.get("placeholder_refresh")):
                    return entry_id, e
        return None

    def store(self, tokens: dict[str, Any], entry_id: str | None,
              client: str | None = None) -> tuple[str, dict[str, Any]]:
        """Keep a token response's real tokens: in ENTRY_ID's entry (refresh; an absent refresh
        token keeps the old one), or in a new one (sign-in, adoption), which replaces the
        account's earlier entries from the same CLIENT address. The response's other fields are
        kept too, with each "…expires_in" as an absolute time. Returns the entry."""
        now = time.time()
        self.forgotten = []
        with self._open(write=True) as data:
            self._sweep(data, now)
            if entry_id is None or entry_id not in data["entries"]:
                account = _account(tokens)
                for old_id, old in list(data["entries"].items()):
                    if client and account and (old.get("client"), old.get("account")) == (client, account):
                        del data["entries"][old_id]
                        self.forgotten.append((old_id, "replaced"))
                entry_id = secrets.token_hex(4)
                data["entries"][entry_id] = {"created": _now(), "client": client, "account": account,
                                             "placeholder_access": placeholder("access")}
            e = data["entries"][entry_id]
            e["access_token"] = tokens["access_token"]
            if tokens.get("refresh_token"):
                e["refresh_token"] = tokens["refresh_token"]
                e.setdefault("placeholder_refresh", placeholder("refresh"))
            if "expires_in" in tokens:
                e["expires_at"] = int(now) + int(tokens["expires_in"])
            if "refresh_token_expires_in" in tokens:
                e["refresh_expires_at"] = int(now) + int(tokens["refresh_token_expires_in"])
            # Merged over the kept fields: a refresh response may leave out what sign-in had
            # (account, organization), which the vault's own answers should still carry.
            e["response"] = {**e.get("response", {}),
                             **{k: (int(now) + int(v) if k.endswith("expires_in") else v)
                                for k, v in tokens.items() if k not in TOKEN_FIELDS}}
            e["updated"] = _now()
            e["refreshed_at"] = now
            e["generation"] = e.get("generation", 0) + 1
            e.pop("refreshing_since", None)
            return entry_id, dict(e)

    def begin_refresh(self, entry_id: str) -> tuple[str, dict[str, Any]]:
        """What to do with a client's refresh for ENTRY_ID: ("answer", entry) when the vault can
        answer it itself, ("forward", entry) for the one refresh that goes upstream (marked as
        on its way, so that others meanwhile are answered), or ("gone", {}) if another process
        removed the entry since it was found."""
        now = time.time()
        with self._open(write=True) as data:
            e = data["entries"].get(entry_id)
            if e is None:
                return "gone", {}
            fresh = (e.get("expires_at", 0) - now > REFRESH_MARGIN
                     and e.get("failed_at", 0) <= e.get("refreshed_at", 0))
            inflight = now - e.get("refreshing_since", 0) < REFRESH_INFLIGHT
            if fresh or inflight:
                return "answer", dict(e)
            e["refreshing_since"] = now
            return "forward", dict(e)

    def end_refresh(self, entry_id: str) -> None:
        """The refresh upstream failed: the next one may go upstream at once."""
        with self._open(write=True) as data:
            if entry_id in data["entries"]:
                data["entries"][entry_id].pop("refreshing_since", None)

    def mark_failed(self, entry_id: str, generation: int) -> bool:
        """A request with ENTRY_ID's access token of GENERATION got a 401. If that's still the
        current token, the next refresh goes upstream (True). An older one was revoked by the
        refresh that replaced it: nothing to do, the client's retry gets the current one.
        (Marking those would send the next refresh upstream, revoke the token again, and so on.)"""
        with self._open(write=True) as data:
            e = data["entries"].get(entry_id)
            if e is None or e.get("generation", 0) != generation:
                return False
            e["failed_at"] = time.time()
            return True

    def remove(self, entry_id: str) -> None:
        with self._open(write=True) as data:
            data["entries"].pop(entry_id, None)


def answer_body(e: dict[str, Any]) -> dict[str, Any]:
    """A token response for entry E, as the vault answers a refresh: the last real response's
    fields, the placeholders, and lifetimes counted from now (at least a minute, so that a client
    whose refresh came while another was on its way asks again soon, not at once)."""
    now = int(time.time())
    body = {k: (max(v - now, 60) if k.endswith("expires_in") else v)
            for k, v in e["response"].items()}
    body["expires_in"] = max(e.get("expires_at", 0) - now, 60)
    body["access_token"] = e["placeholder_access"]
    if e.get("placeholder_refresh"):
        body["refresh_token"] = e["placeholder_refresh"]
    return body


class CredentialVaultPlugin(HttpProxyBasePlugin):
    """Swap placeholders for real tokens on the way out, and real tokens for placeholders on the
    way back (token endpoint only). See the module docstring."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.vault = Vault(os.environ.get(VAULT_ENV, "credential-vault.json"))
        self.log_path = os.environ.get(VAULT_LOG_ENV, "vault.jsonl")
        # Where this connection really goes: the CONNECT tunnel's destination, set once in
        # before_upstream_connection. Requests inside the tunnel can name any host; proxy.py sends
        # them down this connection all the same, so only this decides where a token may go.
        self.host = ""
        self.port = 0
        self.tunnel = False
        self.path = ""
        self.token_request: str | None = None   # the entry a token request refreshes; "" a new one
        self.adopting = False                     # ... a refresh with a real refresh token
        self.revoking: str | None = None          # the entry a revoke request is for
        self.swapped: tuple[str, int] | None = None   # entry and generation of the token sent
        self.status_line = b""                    # its response's status line, as it comes
        self.response = HttpParser(httpParserTypes.RESPONSE_PARSER)

    def _log(self, event: str, **fields: Any) -> None:
        record = {"timestamp": _now(), "pid": os.getpid(),
                  "event": event, "host": self.host, "path": self.path, **fields}
        line = json.dumps(record) + "\n"
        with _lock, open(self.log_path, "a", encoding="utf-8") as out:
            out.write(line)

    def _log_forgotten(self) -> None:
        for entry_id, reason in self.vault.forgotten:
            self._log("forgotten", entry=entry_id, reason=reason)

    def _client_ip(self) -> str | None:
        addr = getattr(self.client, "addr", None)
        return str(addr[0]) if addr else None

    def before_upstream_connection(self, request: HttpParser) -> HttpParser | None:
        """The connection's destination, once: a CONNECT tunnel (TLS, intercepted and verified
        upstream) or a plain HTTP request's host, which never gets a token."""
        self.host = (request.host or b"").decode("utf-8", "replace").lower()
        self.port = request.port or 0
        self.tunnel = request.method == b"CONNECT"
        return request

    def _authority_matches(self, request: HttpParser) -> bool:
        """Does the request name only the connection's host? An absolute URL (request.host) or a
        Host header naming another host is refused a token, whatever the connection is to."""
        if request.host and request.host.decode("utf-8", "replace").lower() != self.host:
            return False
        if request.has_header(b"host"):
            name = request.header(b"host").decode("latin-1").strip().lower()
            hostname, _, port = name.rpartition(":")
            if port.isdigit():
                if int(port) != self.port:
                    return False
                name = hostname
            if name != self.host:
                return False
        return True

    def handle_client_request(self, request: HttpParser) -> HttpParser | None:
        if request.method == b"CONNECT":
            return request
        self.path = (request.path or b"").decode("utf-8", "replace").partition("?")[0]
        self.token_request = self.revoking = self.swapped = None
        self.status_line = b""
        self.adopting = False
        self.response = HttpParser(httpParserTypes.RESPONSE_PARSER)
        if not (self.tunnel and self.port == 443 and self.host in VAULT_HOSTS):
            self._note_elsewhere(request, "not a vault host")
            return request
        if not self._authority_matches(request):
            self._note_elsewhere(request, "request names another host")
            return request
        self._swap_headers(request)
        if self.host == TOKEN_HOST and request.method == b"POST":
            if self.path == TOKEN_PATH:
                return self._swap_body(request, "refresh_token", refreshing=True)
            if self.path == REVOKE_PATH:
                return self._swap_body(request, "token", refreshing=False)
        return request

    def _swap_headers(self, request: HttpParser) -> None:
        for name, scheme in ((b"authorization", "Bearer "), (b"x-api-key", "")):
            if not request.has_header(name):
                continue
            value = request.header(name).decode("latin-1")
            token = value.removeprefix(scheme)
            if not is_placeholder(token):
                continue
            found = self.vault.find(token)
            if found is None:
                self._log("unknown-placeholder", where=name.decode())
                continue
            entry_id, e = found
            request.add_header(name.title(), (scheme + e["access_token"]).encode("latin-1"))
            self.swapped = (entry_id, e.get("generation", 0))
            self._log("swap", where=name.decode(), entry=entry_id, generation=self.swapped[1])

    def _note_elsewhere(self, request: HttpParser, reason: str) -> None:
        """A placeholder in a header of a request the vault doesn't serve: not swapped, but logged,
        so that a host Claude Code needs (or an attempt to send it out) shows up."""
        for name in (b"authorization", b"x-api-key"):
            if request.has_header(name) and any(p.encode() in request.header(name) for p in PREFIXES):
                self._log("placeholder-elsewhere", where=name.decode(), reason=reason)

    def _swap_body(self, request: HttpParser, field: str, refreshing: bool) -> HttpParser | None:
        """The token endpoint: swap a placeholder in FIELD of a JSON or form body, and remember
        that this response must be rewritten (and for which entry). A refresh the vault answers
        itself goes no further (None)."""
        content_type = (request.header(b"content-type") if request.has_header(b"content-type")
                        else b"application/json")
        raw = bytes(request.body or b"").decode("utf-8", "replace")
        form = content_type.startswith(b"application/x-www-form-urlencoded")
        try:
            body = dict(parse_qsl(raw)) if form else json.loads(raw or "{}")
        except ValueError:
            body = {}
        if not isinstance(body, dict):
            body = {}
        token = body.get(field)
        if refreshing:
            self.token_request = ""            # a new entry, unless a placeholder says which
            self.adopting = (isinstance(token, str) and token.startswith(REAL_REFRESH_PREFIX)
                             and not is_placeholder(token))
            # Ask for an uncompressed response: it's rewritten whole.
            request.add_header(b"Accept-Encoding", b"identity")
        if not isinstance(token, str) or not is_placeholder(token):
            return request
        found = self.vault.find(token)
        if found is None:
            self._log("unknown-placeholder", where=field)
            return request
        entry_id, e = found
        if refreshing:
            what, e = self.vault.begin_refresh(entry_id)
            if what == "gone":                  # removed by another process since find()
                self._log("unknown-placeholder", where=field)
                return request
            if what == "answer":
                self._answer(entry_id, e)
                return None
        body[field] = e["refresh_token"] if token == e.get("placeholder_refresh") else e["access_token"]
        new = urlencode(body) if form else json.dumps(body)
        request.update_body(new.encode(), content_type)
        if refreshing:
            self.token_request = entry_id
        else:
            self.revoking = entry_id
        self._log("swap", where=field, entry=entry_id)
        return request

    def _answer(self, entry_id: str, e: dict[str, Any]) -> None:
        """Answer a refresh from the vault, without going upstream. The connection is closed
        after it: proxy.py's pipeline keeps the request it didn't forward."""
        self.token_request = None
        body = json.dumps(answer_body(e)).encode()
        self.client.queue(memoryview(build_http_response(
            200, reason=b"OK", body=body,
            headers={b"Content-Type": b"application/json",
                     b"Content-Length": str(len(body)).encode(),
                     b"Cache-Control": b"no-store",
                     b"Connection": b"close"})))
        self._log("refresh-answered", entry=entry_id,
                  expires_in=max(e.get("expires_at", 0) - int(time.time()), 60))

    def handle_upstream_chunk(self, chunk: memoryview) -> memoryview | None:
        """Pass responses through, except the token endpoint's: hold it until it's complete,
        then hand the client the version with placeholders. Note a 401 to a swapped request."""
        if self.swapped is not None:
            self._check_status(chunk)
        if self.token_request is None and self.revoking is None:
            return chunk
        self.response.parse(chunk)
        if not self.response.is_complete:
            return None                        # held back; the core queues nothing
        if self.revoking is not None:
            if self.response.code == b"200":
                self.vault.remove(self.revoking)
                self._log("revoked", entry=self.revoking)
            self.revoking = None
            return memoryview(self.response.build_response())
        entry_id, self.token_request = self.token_request, None
        return memoryview(self._rewrite_tokens(entry_id or None))

    @staticmethod
    def _failure(message: bytes) -> bytes:
        """A 502 for the client instead of a token response, closing the connection."""
        body = json.dumps({"error": "credential_vault", "message": message.decode()}).encode()
        return build_http_response(
            502, reason=b"Bad Gateway", body=body,
            headers={b"Content-Type": b"application/json",
                     b"Content-Length": str(len(body)).encode(),
                     b"Connection": b"close"})

    def on_upstream_connection_close(self) -> None:
        """Upstream closed while a token or revoke response was held back: tell the client,
        rather than leave it waiting for an answer that won't come. A partial response isn't
        passed on (it may hold real tokens)."""
        if self.token_request is None and self.revoking is None:
            return
        if self.token_request:
            self.vault.end_refresh(self.token_request)
        self._log("token-response-incomplete", entry=self.token_request or self.revoking)
        self.token_request = self.revoking = None
        self.client.queue(memoryview(
            self._failure(b"upstream closed before the token response was complete")))

    def _check_status(self, chunk: memoryview) -> None:
        """A response to a swapped request: collect its status line, which may come in pieces
        (the chunks themselves pass on as they come), and note a 401."""
        self.status_line += bytes(chunk[:256])
        line, crlf, _ = self.status_line.partition(b"\r\n")
        if not crlf and len(self.status_line) < 256:
            return                              # not the whole status line yet
        parts = line.split(b" ", 2)
        assert self.swapped is not None
        entry_id, generation = self.swapped
        self.swapped = None
        self.status_line = b""
        if len(parts) > 1 and parts[1] == b"401":
            current = self.vault.mark_failed(entry_id, generation)
            self._log("unauthorized", entry=entry_id, generation=generation, current=current)

    def _rewrite_tokens(self, entry_id: str | None) -> bytes:
        r = self.response
        encoding = r.header(b"content-encoding") if r.has_header(b"content-encoding") else b""
        body_bytes = _decode(bytes(r.body or b""), encoding)
        try:
            body = json.loads(body_bytes)
        except ValueError:
            body = None
        status = (r.code or b"").decode()
        if not (r.code == b"200" and isinstance(body, dict) and body.get("access_token")):
            if entry_id:
                self.vault.end_refresh(entry_id)
            if body is None or (isinstance(body, dict) and any(f in body for f in TOKEN_FIELDS)):
                # Can't read it (an encoding _decode doesn't know), or tokens where none are
                # expected: they may be real tokens, so the client doesn't get these bytes.
                self._log("token-response-withheld", status=status, entry=entry_id)
                return self._failure(b"the credential vault couldn't read the token response")
            # An error (e.g. invalid_grant) without tokens: pass it on.
            self._log("token-response-passed", status=status, entry=entry_id)
            return r.build_response()
        event = "refresh" if entry_id else "adopt" if self.adopting else "sign-in"
        entry_id, e = self.vault.store(body, entry_id, client=self._client_ip())
        self._log_forgotten()
        body["access_token"] = e["placeholder_access"]
        if body.get("refresh_token"):
            body["refresh_token"] = e["placeholder_refresh"]
        withheld = [k for k in WITHHELD_FIELDS if k in body]
        for k in withheld:
            del body[k]
        self._log(event, entry=entry_id, status=r.code.decode(), generation=e["generation"],
                  has_refresh="refresh_token" in body, expires_in=body.get("expires_in"),
                  **({"withheld": withheld} if withheld else {}))
        body_bytes = json.dumps(body).encode()
        headers = {r.headers[k][0]: r.headers[k][1] for k in (r.headers or {})
                   if k not in (b"content-length", b"transfer-encoding", b"content-encoding")}
        headers[b"Content-Length"] = str(len(body_bytes)).encode()
        return build_http_response(int(r.code), protocol_version=r.version, reason=r.reason,
                                   headers=headers, body=body_bytes)

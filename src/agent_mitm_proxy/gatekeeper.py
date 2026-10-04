"""Allowlist gatekeeper: ask the owner on Buzz, act on their signed 👍 / 👎.

One long-lived buzzkit WebSocket connection as the harness identity (an agent key of its own,
attested by the owner with a NIP-OA auth tag):

- publishes presence "online" while connected;
- sends each allowlist request as a DM to the owner (over the WebSocket: the HTTP bridge
  refuses attested agents);
- subscribes to the owner's reactions (kind 7) and decides the moment one arrives. Every
  reaction must carry a valid signature, be authored by the owner's pubkey and point at the
  request's own message;
- on approval appends the host:port or service grant to the allowlist file (the proxy and the
  forwarder reload it), and replies in the DM thread with the outcome.

Decision: 👍 (any skin tone) approves, 👎 rejects; the first owner reaction on a request is
final. No reaction within the timeout: expired.

Configured with environment variables (`Config.from_env`):

| Variable | Meaning |
|---|---|
| GATEKEEPER_RELAY_URL | Buzz relay, e.g. wss://NAME.communities.buzz.xyz (required) |
| GATEKEEPER_OWNER_PUBKEY | The owner's public key, 64 hex characters (required) |
| GATEKEEPER_DM_ID | The DM channel between harness and owner, a UUID (required) |
| GATEKEEPER_KEY_FILE | The harness's private key (nsec) (required) |
| GATEKEEPER_TAG_FILE | The owner's NIP-OA attestation of the harness key (required) |
| GATEKEEPER_ALLOWLIST | The proxy allowlist to append approved entries to (required) |
| GATEKEEPER_AUDIT_LOG | Every request and decision, as JSONL; also restores state (required) |
| GATEKEEPER_SERVICES | Internal services, see `grants` (optional) |
| GATEKEEPER_TIMEOUT_S | How long a request waits for the owner (default 1800) |
"""

import asyncio
import contextlib
import dataclasses
import datetime
import fcntl
import ipaddress
import json
import os
import pathlib
import re
import secrets
import socket
import time

import buzzkit

from .allowlist import allows, non_global_reason, parse
from .grants import denied, grant_line, load_grants, load_services, normalize_method, normalize_path


class ConfigError(ValueError):
    pass


_REQUIRED_ENV = {
    "relay_url": "GATEKEEPER_RELAY_URL",
    "owner_pubkey": "GATEKEEPER_OWNER_PUBKEY",
    "dm_id": "GATEKEEPER_DM_ID",
    "key_file": "GATEKEEPER_KEY_FILE",
    "tag_file": "GATEKEEPER_TAG_FILE",
    "allowlist": "GATEKEEPER_ALLOWLIST",
    "audit_log": "GATEKEEPER_AUDIT_LOG",
}


@dataclasses.dataclass(frozen=True)
class Config:
    relay_url: str
    owner_pubkey: str
    dm_id: str                               # harness ↔ owner DM channel
    key_file: pathlib.Path                   # harness nsec: keep out of git and out of sandboxes
    tag_file: pathlib.Path                   # owner attestation
    allowlist: pathlib.Path
    audit_log: pathlib.Path
    services: pathlib.Path | None = None     # internal services: keep out of git
    timeout_s: int = 1800
    max_pending: int = 3
    max_per_hour: int = 10

    def __post_init__(self):
        if not re.fullmatch(r"[0-9a-f]{64}", self.owner_pubkey):
            raise ConfigError("owner pubkey must be 64 lowercase hex characters (not an npub)")

    @classmethod
    def from_env(cls, env: dict[str, str] | None = None) -> "Config":
        env = os.environ if env is None else env
        missing = [var for var in _REQUIRED_ENV.values() if not env.get(var)]
        if missing:
            raise ConfigError(f"missing environment variables: {', '.join(missing)}")
        values = {field: env[var] for field, var in _REQUIRED_ENV.items()}
        for field in ("key_file", "tag_file", "allowlist", "audit_log"):
            values[field] = pathlib.Path(values[field])
        services = env.get("GATEKEEPER_SERVICES")
        return cls(**values, services=pathlib.Path(services) if services else None,
                   timeout_s=int(env.get("GATEKEEPER_TIMEOUT_S", "1800")))


# -- decision (pure) ---------------------------------------------------------

_SKIN_TONES = {chr(c) for c in range(0x1F3FB, 0x1F400)} | {"️"}


def base_emoji(emoji: str) -> str:
    """👍🏽 → 👍: drop skin-tone modifiers and variation selectors."""
    return "".join(ch for ch in emoji if ch not in _SKIN_TONES)


def decision_for(emoji: str) -> str | None:
    return {"👍": "approved", "👎": "rejected"}.get(base_emoji(emoji))


def owner_reaction(event: dict, owner_pubkey: str) -> tuple[str, str] | None:
    """(target_event_id, decision) for a valid owner 👍/👎 reaction, else None."""
    if event.get("kind") != 7 or event.get("pubkey") != owner_pubkey:
        return None
    decision = decision_for(event.get("content", ""))
    targets = [t[1] for t in event.get("tags", []) if len(t) > 1 and t[0] == "e"]
    if not decision or not targets:
        return None
    if not buzzkit.verify_event(json.dumps(event)):
        return None                       # forged or altered: ignore
    return targets[-1], decision          # NIP-25: the last e tag is the reacted-to event


# -- host validation and the allowlist file ----------------------------------

_LABEL = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")


def validate(host: str, port: int, resolve=socket.getaddrinfo) -> tuple[str, int]:
    host = host.strip().lower().rstrip(".")
    if not 1 <= int(port) <= 65535:
        raise ValueError("port must be 1-65535")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass                                  # not an IP literal: good
    else:
        raise ValueError("IP addresses are not allowed; request a host name")
    labels = host.split(".")
    if len(host) > 253 or len(labels) < 2 or not all(_LABEL.match(label) for label in labels):
        raise ValueError(f"not a valid host name: {host!r}")
    reason = non_global_reason(host, int(port), resolve)
    if reason:
        raise ValueError(f"{host}: {reason}; the proxy refuses it")
    return host, int(port)


def listed(path: pathlib.Path, host: str, port: int) -> bool:
    try:
        lines = path.read_text().splitlines()
    except FileNotFoundError:
        return False
    return allows(parse(lines), host, port)


def append_allowlist(path: pathlib.Path, entry: str, note: str) -> None:
    """Append `entry` (host:port or a service grant line) with a comment."""
    line = entry.ljust(46) + f"# {note}\n"
    with open(path, "a", encoding="utf-8") as f:
        fcntl.flock(f, fcntl.LOCK_EX)
        f.write(line)


def _local_time(timestamp: float) -> datetime.datetime:
    """In the machine's time zone: the owner reads these times in the DM."""
    return datetime.datetime.fromtimestamp(timestamp, datetime.UTC).astimezone()


def _local_now() -> datetime.datetime:
    return _local_time(time.time())


def one_line(text: str, limit: int) -> str:
    text = " ".join(text.split())
    return text if len(text) <= limit else text[: limit - 1] + "…"


# -- the gatekeeper ----------------------------------------------------------

@dataclasses.dataclass
class Request:
    id: str
    host: str
    port: int
    reason: str
    requester: str
    created: float
    event_id: str | None = None
    status: str = "pending"                 # pending | approved | rejected | expired
    decided: float | None = None
    service: str | None = None              # set for an internal service path grant
    method: str | None = None
    path: str | None = None

    def key(self) -> tuple:
        return (self.service, self.method, self.path) if self.service else (self.host, self.port)

    def what(self) -> str:
        return f"{self.service} {self.method} {self.path}" if self.service else f"{self.host}:{self.port}"

    def public(self) -> dict:
        if self.service:
            return {"request_id": self.id, "service": self.service, "method": self.method,
                    "path": self.path, "status": self.status}
        return {"request_id": self.id, "host": self.host, "port": self.port, "status": self.status}


class GatekeeperError(RuntimeError):
    pass


class Gatekeeper:
    def __init__(self, cfg: Config, resolve=socket.getaddrinfo):
        self.cfg = cfg
        self.resolve = resolve
        self.secret = cfg.key_file.read_text().strip()
        self.auth_tag = cfg.tag_file.read_text().strip()
        self.requests: dict[str, Request] = {}
        self.by_event: dict[str, Request] = {}
        self.client: buzzkit.BuzzClient | None = None
        self.connected = asyncio.Event()
        self._restore()

    def _restore(self) -> None:
        """Rebuild requests from the audit log, so a restart keeps pending ones."""
        try:
            lines = self.cfg.audit_log.read_text().splitlines()
        except FileNotFoundError:
            return
        fields = {f.name for f in dataclasses.fields(Request)}
        for line in lines:
            rec = json.loads(line)
            req = Request(**{k: v for k, v in rec.items() if k in fields})
            self.requests[req.id] = req           # the last record per id wins
            if req.event_id:
                self.by_event[req.event_id] = req

    # audit ------------------------------------------------------------------
    def _audit(self, what: str, req: Request, **extra) -> None:
        record = {"time": _local_now().isoformat(timespec="seconds"),
                  "event": what, **dataclasses.asdict(req), **extra}
        with open(self.cfg.audit_log, "a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")

    # connection -------------------------------------------------------------
    async def run(self) -> None:
        """Stay connected: presence, reaction subscription, expiry. Reconnects on errors."""
        backoff = 1
        while True:
            try:
                self.client = buzzkit.BuzzClient(self.cfg.relay_url, self.secret, auth_tag=self.auth_tag)
                await self.client.connect()
                await self.client.publish_presence("online")
                self.connected.set()
                backoff = 1
                # Stored reactions first, *then* expiry: otherwise a request approved
                # while we were down would be expired before its 👍 is seen.
                await self._catch_up()
                await asyncio.gather(self._watch_live(), self._expire_loop())
            except Exception as e:  # noqa: BLE001 — log and reconnect
                print(f"gatekeeper: connection lost: {e!r}; reconnecting in {backoff}s", flush=True)
            finally:
                self.connected.clear()
                if self.client is not None:
                    with contextlib.suppress(Exception):
                        await self.client.close()
            await asyncio.sleep(backoff)
            backoff = min(backoff * 2, 60)

    # The relay fans out *live* events per channel: without the "#h" channel
    # filter a subscription only ever returns stored events. Author and
    # signature are checked in owner_reaction().
    def _filters(self, since: int) -> list[dict]:
        return [{"kinds": [7], "#h": [self.cfg.dm_id], "since": since}]

    async def _handle(self, event: dict) -> None:
        hit = owner_reaction(event, self.cfg.owner_pubkey)
        if not hit:
            return
        target, decision = hit
        req = self.by_event.get(target)
        # Judge by when the owner reacted (signed created_at), not when we see it.
        if req and req.status == "pending" and event.get("created_at", 0) <= req.created + self.cfg.timeout_s:
            await self._decide(req, decision)

    async def _catch_up(self) -> None:
        """Reactions made while disconnected (stored events, until EOSE)."""
        pending = [r.created for r in self.requests.values() if r.status == "pending"]
        if not pending:
            return
        async for event in self.client.subscribe(self._filters(int(min(pending)) - 60),
                                                 sub_id="catch-up", close_on_eose=True):
            await self._handle(event)

    async def _watch_live(self) -> None:
        async for event in self.client.subscribe(self._filters(int(time.time()) - 60),
                                                 sub_id="owner-reactions"):
            await self._handle(event)
        raise GatekeeperError("reaction subscription ended")

    async def _expire_due(self) -> None:
        now = time.time()
        for req in list(self.requests.values()):
            if req.status == "pending" and now - req.created > self.cfg.timeout_s:
                await self._decide(req, "expired")

    async def _expire_loop(self) -> None:
        while True:
            await self._expire_due()
            await asyncio.sleep(15)

    async def _send(self, content: str, reply_to: str | None = None) -> str:
        await asyncio.wait_for(self.connected.wait(), 10)
        event = buzzkit.build_message_event(self.secret, self.cfg.dm_id, content, reply_to=reply_to)
        result = await self.client.publish(event)
        if result.get("accepted") is False:
            raise GatekeeperError(f"message not accepted: {result}")
        return json.loads(event)["id"]

    async def _decide(self, req: Request, decision: str) -> None:
        req.status, req.decided = decision, time.time()
        if decision == "approved":
            note = f"approved via Buzz {_local_now().date()} request {req.id}: {one_line(req.reason, 60)}"
            if req.service:
                if (req.service, req.method, req.path) not in load_grants(self.cfg.allowlist):
                    append_allowlist(self.cfg.allowlist, grant_line(req.service, req.method, req.path), note)
            elif not listed(self.cfg.allowlist, req.host, req.port):
                append_allowlist(self.cfg.allowlist, f"{req.host}:{req.port}", note)
            reply = f"✅ Added {req.what()} to the allowlist."
        elif decision == "rejected":
            reply = f"❌ Rejected {req.what()}."
        else:
            reply = f"⌛ Expired: {req.what()} was not added."
        self._audit(decision, req)
        try:
            await self._send(reply, reply_to=req.event_id)
        except Exception as e:  # noqa: BLE001 — the decision stands even if the reply fails
            print(f"gatekeeper: could not send reply for {req.id}: {e!r}", flush=True)

    # API used by the MCP tools ----------------------------------------------
    async def request(self, reason: str, requester: str, host: str | None = None, port: int = 443,
                      service: str | None = None, method: str = "GET", path: str | None = None) -> dict:
        """Either an Internet host (host, port) or an internal service path (service, method, path)."""
        reason = one_line(reason or "(no reason given)", 300)
        risk = ""
        if service:
            services = load_services(self.cfg.services) if self.cfg.services else {}
            svc = services.get(service)
            if svc is None:
                raise ValueError(f"unknown service {service!r}; known: {', '.join(sorted(services)) or 'none'}")
            method, path = normalize_method(method), normalize_path(path or "")
            if denied(svc, path):
                raise ValueError(f"{path} is never allowed for service {service!r}")
            if (service, method, path) in load_grants(self.cfg.allowlist):
                return {"service": service, "method": method, "path": path, "status": "already_allowed"}
            risk = svc.risky.get(f"{method} {path}", "")
            new = Request(id=secrets.token_hex(3), host="", port=0, reason=reason, requester=requester,
                          created=time.time(), service=service, method=method, path=path)
        else:
            if not host:
                raise ValueError("give either host (Internet) or service + path (internal service)")
            host, port = validate(host, port, self.resolve)
            if listed(self.cfg.allowlist, host, port):
                return {"host": host, "port": port, "status": "already_allowed"}
            new = Request(id=secrets.token_hex(3), host=host, port=port, reason=reason,
                          requester=requester, created=time.time())
        for req in self.requests.values():
            if req.status == "pending" and req.key() == new.key():
                return req.public()
        pending = sum(r.status == "pending" for r in self.requests.values())
        recent = sum(time.time() - r.created < 3600 for r in self.requests.values())
        if pending >= self.cfg.max_pending:
            raise GatekeeperError(f"too many pending requests ({pending}); wait for a decision")
        if recent >= self.cfg.max_per_hour:
            raise GatekeeperError("request limit reached for this hour")

        req = new
        expires = _local_time(req.created + self.cfg.timeout_s).strftime("%H:%M")
        if req.service:
            # The service's internal address is never shown; the owner knows it.
            allow = f"Service: {req.service}\nRequest: {req.method} {req.path}\n"
            if risk:
                allow += f"⚠️ {risk}\n"
        else:
            allow = f"Allow: {req.host}:{req.port}\n"
        text = (f"🔐 Allowlist request {req.id}\n"
                f"{allow}"
                f"From: {requester}\n"
                f"Reason (from the agent): “{reason}”\n\n"
                f"React 👍 to allow or 👎 to reject. Expires at {expires}.")
        req.event_id = await self._send(text)
        self.requests[req.id] = req
        self.by_event[req.event_id] = req
        self._audit("requested", req)
        return req.public()

    def status(self, request_id: str) -> dict:
        req = self.requests.get(request_id)
        if req is None:
            return {"request_id": request_id, "status": "unknown"}
        return req.public()

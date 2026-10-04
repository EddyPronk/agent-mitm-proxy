"""Internal services and their per-path grants, shared by the forwarder and the gatekeeper.

Services (hand-edited JSON; keep it out of git, it holds internal addresses):

    {"ollama": {"listen": 11434, "target": "http://10.0.0.5:11434",
                "deny": ["/api/blobs"], "risky": {"POST /api/pull": "downloads models"}}}

Grants live in the proxy allowlist (see `allowlist`), one line per approved
method + exact path:

    service:ollama POST /api/chat     # approved via Buzz …

A sandbox only ever sees the service name and the path, never the target.
"""

import dataclasses
import json
import pathlib
import re

SERVICE_PREFIX = "service:"
METHODS = ("GET", "HEAD", "POST", "PUT", "PATCH", "DELETE")
_NAME = re.compile(r"^[a-z][a-z0-9-]{0,31}$")
_SEGMENT = re.compile(r"^[A-Za-z0-9._~-]+$")


@dataclasses.dataclass(frozen=True)
class Service:
    name: str
    listen: int
    target: str
    deny: tuple[str, ...] = ()
    risky: dict = dataclasses.field(default_factory=dict)
    max_concurrent: int = 2
    max_body: int = 10 * 1024 * 1024
    timeout_s: float = 600


def load_services(path: pathlib.Path) -> dict[str, Service]:
    try:
        raw = json.loads(pathlib.Path(path).read_text())
    except FileNotFoundError:
        return {}
    services: dict[str, Service] = {}
    for name, cfg in raw.items():
        if name.startswith("_"):
            continue  # comments
        if not _NAME.match(name):
            raise ValueError(f"invalid service name {name!r}")
        services[name] = Service(
            name=name, listen=int(cfg["listen"]), target=cfg["target"].rstrip("/"),
            deny=tuple(normalize_path(p) for p in cfg.get("deny", [])),
            risky=dict(cfg.get("risky", {})),
            max_concurrent=int(cfg.get("max_concurrent", 2)),
            max_body=int(cfg.get("max_body", 10 * 1024 * 1024)),
            timeout_s=float(cfg.get("timeout_s", 600)),
        )
    return services


def normalize_path(raw: str) -> str:
    """Canonical path for matching, or ValueError. Strict on purpose: no
    encodings, dot segments, empty segments or unusual characters, so the
    string that is granted is exactly the path that is forwarded."""
    path = raw.split("?", 1)[0]
    if not path.startswith("/") or len(path) > 512:
        raise ValueError("path must start with '/' and be at most 512 characters")
    if path != "/" and path.endswith("/"):
        path = path[:-1]
    if path == "/":
        return path
    for seg in path[1:].split("/"):
        if seg in ("", ".", "..") or not _SEGMENT.match(seg):
            raise ValueError(f"path not allowed: {raw!r} (no //, dot segments, % encodings or special characters)")
    return path


def normalize_method(method: str) -> str:
    m = method.strip().upper()
    if m not in METHODS:
        raise ValueError(f"method must be one of {', '.join(METHODS)}")
    return m


def denied(service: Service, path: str) -> bool:
    """Paths on the service's deny list (prefix match) can never be granted."""
    return any(path == d or path.startswith(d + "/") for d in service.deny)


def grant_line(service: str, method: str, path: str) -> str:
    return f"{SERVICE_PREFIX}{service} {method} {path}"


def load_grants(allowlist: pathlib.Path) -> set[tuple[str, str, str]]:
    grants = set()
    try:
        lines = pathlib.Path(allowlist).read_text().splitlines()
    except FileNotFoundError:
        return grants
    for line in lines:
        item = line.split("#", 1)[0].strip()
        if not item.startswith(SERVICE_PREFIX):
            continue
        parts = item[len(SERVICE_PREFIX):].split()
        if len(parts) == 3:
            name, method, path = parts
            try:
                grants.add((name, normalize_method(method), normalize_path(path)))
            except ValueError:
                pass  # malformed line: grants nothing
    return grants

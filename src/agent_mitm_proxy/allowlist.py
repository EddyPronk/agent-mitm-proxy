"""The egress allowlist: which upstream hosts the proxy may connect to.

One entry per line, `#` starts a comment:

    api.anthropic.com:443     exact host and port
    example.com               exact host, any port
    *.anthropic.com:443       any subdomain (not the bare domain)

Lines starting with `service:` are path grants for internal services (see `grants`) and are
ignored here. Malformed lines grant nothing.

Even a listed host is refused if it resolves to a private, loopback, link-local or otherwise
non-global address: no LAN or host access through DNS tricks.
"""

import ipaddress
import os
import socket
import threading
from collections.abc import Callable, Iterable

from .grants import SERVICE_PREFIX

Entry = tuple[str, int | None]  # (host or *.domain, port or None for any port)


def parse_line(line: str) -> Entry | None:
    """The host entry on one allowlist line, or None (blank, comment, service grant, malformed)."""
    item = line.split("#", 1)[0].strip()
    if not item or item.startswith(SERVICE_PREFIX) or any(c.isspace() for c in item):
        return None
    host, sep, port = item.rpartition(":")
    if not sep:
        return item.lower(), None
    if not host or not port.isdigit() or not 1 <= int(port) <= 65535:
        return None
    return host.lower(), int(port)


def parse(lines: Iterable[str]) -> frozenset[Entry]:
    return frozenset(e for e in map(parse_line, lines) if e is not None)


def allows(entries: Iterable[Entry], host: str, port: int) -> bool:
    host = host.lower()
    for pattern, allowed_port in entries:
        if allowed_port is not None and allowed_port != port:
            continue
        if pattern == host:
            return True
        if pattern.startswith("*.") and host.endswith(pattern[1:]):
            return True
    return False


Resolver = Callable[..., list]

# IPv6 addresses that carry an IPv4 address in their last 32 bits, which Python calls global
# whatever that IPv4 address is: NAT64 (a gateway translates them to IPv4) and the deprecated
# IPv4-compatible form. They count as global only if the IPv4 address does.
_EMBEDS_IPV4 = (ipaddress.ip_network("64:ff9b::/96"), ipaddress.ip_network("::/96"))


def is_global(addr: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    if isinstance(addr, ipaddress.IPv6Address):
        if addr.ipv4_mapped is not None:
            return addr.ipv4_mapped.is_global
        if any(addr in net for net in _EMBEDS_IPV4):
            return addr.is_global and ipaddress.IPv4Address(int(addr) & 0xFFFFFFFF).is_global
    return addr.is_global


def global_address(host: str, port: int, resolve: Resolver = socket.getaddrinfo) -> str:
    """The address to connect to for `host`: the first it resolves to, provided every address
    it resolves to is global. ValueError with the reason otherwise.

    Connect to this address instead of resolving `host` again: a second lookup can answer
    differently (DNS rebinding) and reach the LAN after the check passed."""
    try:
        infos = resolve(host, port, proto=socket.IPPROTO_TCP)
    except OSError as e:
        raise ValueError(f"resolve failed: {e}") from None
    if not infos:
        raise ValueError("resolve failed: no addresses")
    addrs = [ipaddress.ip_address(info[4][0]) for info in infos]
    for addr in addrs:
        if not is_global(addr):
            raise ValueError(f"resolves to non-global address {addr}")
    return str(addrs[0])


def non_global_reason(host: str, port: int, resolve: Resolver = socket.getaddrinfo) -> str | None:
    """Why `host` must not be reached (it does not resolve, or resolves to a non-global
    address), or None if every address it resolves to is global."""
    try:
        global_address(host, port, resolve)
    except ValueError as e:
        return str(e)
    return None


class AllowlistFile:
    """An allowlist file, reloaded when it changes, so edits apply without a restart.
    A missing file allows nothing."""

    def __init__(self, path: str | os.PathLike):
        self.path = os.fspath(path)
        self._lock = threading.Lock()
        self._stamp: tuple | None = None
        self._entries: frozenset[Entry] = frozenset()

    def entries(self) -> frozenset[Entry]:
        try:
            st = os.stat(self.path)
        except OSError:
            return frozenset()
        # mtime alone can miss two writes within the filesystem's timestamp resolution.
        stamp = (st.st_ino, st.st_size, st.st_mtime_ns)
        with self._lock:
            if stamp != self._stamp:
                try:
                    with open(self.path, encoding="utf-8") as f:
                        self._entries = parse(f)
                except OSError:
                    return frozenset()
                self._stamp = stamp
            return self._entries

    def allows(self, host: str, port: int) -> bool:
        return allows(self.entries(), host, port)

"""approve: go through recently refused hosts, and add the ones you choose to the allowlist.

    approve [--since 5m] [--list] [--denied-log PATH] [--allowlist PATH]

Reads the proxy's log of refused connections, groups it by host:port, and asks for each one
whether to add it: `y` adds, Enter or `n` skips, `q` stops. Hosts already in the allowlist are left
out. Hosts the proxy would refuse even when listed (IP addresses, names that resolve to private
addresses, such as cloud metadata) are shown with the reason and never offered.

Approving needs a person at a terminal: without one on stdin, or with --list, approve only lists.
A script or an agent piping "y" into it adds nothing.

Paths, as the proxy uses them (scripts/start-proxy.sh):

| Option | Variable | Default |
|---|---|---|
| --denied-log | AGENT_MITM_PROXY_DENIED_LOG | $AGENT_MITM_PROXY_DATA/denied.jsonl, or data/denied.jsonl |
| --allowlist | AGENT_MITM_PROXY_ALLOWLIST | allowlist.txt |
"""

import argparse
import dataclasses
import datetime
import json
import os
import pathlib
import re
import socket
import sys
from collections.abc import Callable
from typing import TextIO

from .allowlist import Resolver, append_allowlist, listed, validate

_UNITS = {"s": 1, "m": 60, "h": 3600, "d": 86400}


def parse_since(text: str) -> datetime.timedelta:
    """'30s', '5m', '2h', '1d' → a timedelta."""
    match = re.fullmatch(r"(\d+)([smhd])", text.strip())
    if not match or int(match[1]) == 0:
        raise ValueError(f"not a duration: {text!r} (examples: 30s, 5m, 2h, 1d)")
    return datetime.timedelta(seconds=int(match[1]) * _UNITS[match[2]])


@dataclasses.dataclass
class Refused:
    host: str
    port: int
    count: int
    last: datetime.datetime

    @property
    def entry(self) -> str:
        return f"{self.host}:{self.port}"


def read_refused(lines, since: datetime.datetime) -> list[Refused]:
    """Refusals at or after `since`, one per host:port, the most recent first. A record with a
    `count` (the proxy's summary after a refusal burst) counts that many. Lines that aren't a refusal
    record (malformed, truncated, no timestamp) are skipped."""
    by_entry: dict[tuple[str, int], Refused] = {}
    for line in lines:
        try:
            record = json.loads(line)
            when = datetime.datetime.strptime(record["timestamp"], "%Y-%m-%dT%H:%M:%S%z")
            host, port = str(record["host"]).lower(), int(record["port"])
            count = max(1, int(record.get("count", 1)))
        except (ValueError, KeyError, TypeError):
            continue
        if when < since or not host:
            continue
        seen = by_entry.get((host, port))
        if seen is None:
            by_entry[(host, port)] = Refused(host, port, count, when)
        else:
            seen.count += count
            seen.last = max(seen.last, when)
    return sorted(by_entry.values(), key=lambda r: r.last, reverse=True)


def ago(when: datetime.datetime, now: datetime.datetime) -> str:
    """How long ago, in the largest whole unit: the container's clock zone doesn't matter."""
    seconds = max(0, int((now - when).total_seconds()))
    for unit, size in (("d", 86400), ("h", 3600), ("m", 60)):
        if seconds >= size:
            return f"{seconds // size}{unit} ago"
    return f"{seconds}s ago"


def default_denied_log(env: dict) -> pathlib.Path:
    if env.get("AGENT_MITM_PROXY_DENIED_LOG"):
        return pathlib.Path(env["AGENT_MITM_PROXY_DENIED_LOG"])
    return pathlib.Path(env.get("AGENT_MITM_PROXY_DATA") or "data") / "denied.jsonl"


def default_allowlist(env: dict) -> pathlib.Path:
    return pathlib.Path(env.get("AGENT_MITM_PROXY_ALLOWLIST") or "allowlist.txt")


def run(args: argparse.Namespace, *, stdin: TextIO, out: TextIO, interactive: bool,
        now: datetime.datetime, resolve: Resolver) -> int:
    window = parse_since(args.since)
    try:
        with open(args.denied_log, encoding="utf-8", errors="replace") as f:
            refused = read_refused(f, now - window)
    except FileNotFoundError:
        print(f"No refusals logged yet ({args.denied_log} doesn't exist).", file=out)
        return 0
    refused = [r for r in refused if not listed(args.allowlist, r.host, r.port)]
    if not refused:
        print(f"Nothing refused in the last {args.since} that isn't in the allowlist now.", file=out)
        return 0

    offer, never = [], []
    for r in refused:
        try:
            r.host, r.port = validate(r.host, r.port, resolve)
            offer.append(r)
        except ValueError as e:
            never.append((r, str(e)))

    if offer:
        print(f"Refused in the last {args.since} ({args.denied_log}):", file=out)
    for r in offer:
        print(f"  {r.entry:<40} {r.count:>4}×  last {ago(r.last, now)}", file=out)
    if never:
        print("Not offered (the proxy refuses these even when listed):", file=out)
        for r, reason in never:
            print(f"  {r.entry:<40} {r.count:>4}×  {reason}", file=out)
    if not offer:
        return 0
    if args.list or not interactive:
        if not args.list:
            print("No terminal: nothing added. Run approve in a terminal to choose.", file=out)
        return 0

    added = 0
    stamp = now.astimezone().strftime("%Y-%m-%d %H:%M %Z")   # the container may be in UTC
    for r in offer:
        print(f"Add {r.entry} to the allowlist? ({r.count}×, last {ago(r.last, now)}) [y/N/q] ",
              end="", file=out, flush=True)
        answer = stdin.readline()
        if not answer:                    # end of input: stop, as with q
            print(file=out)
            break
        answer = answer.strip().lower()
        if answer in ("q", "quit"):
            break
        if answer in ("y", "yes"):
            if not listed(args.allowlist, r.host, r.port):     # added meanwhile, e.g. by hand
                append_allowlist(args.allowlist, r.entry, f"approved with approve, {stamp}")
            added += 1
    print(f"Added {added} to {args.allowlist}; the proxy applies it without a restart.", file=out)
    return 0


def main(argv: list[str] | None = None, *, stdin: TextIO | None = None, out: TextIO | None = None,
         env: dict | None = None, interactive: bool | None = None,
         now: Callable[[], datetime.datetime] | None = None,
         resolve: Resolver = socket.getaddrinfo) -> int:
    env = os.environ if env is None else env
    stdin = sys.stdin if stdin is None else stdin
    out = sys.stdout if out is None else out
    parser = argparse.ArgumentParser(
        prog="approve",
        description="Go through hosts the proxy refused recently, and add the ones you choose "
                    "to the allowlist. Without a terminal, or with --list, only lists.",
        epilog="You can also edit the allowlist directly; the proxy applies changes without a restart.")
    parser.add_argument("--since", default="5m", metavar="DURATION",
                        help="how far back to look: 30s, 5m, 2h, 1d (default 5m)")
    parser.add_argument("--list", action="store_true", help="only list, don't ask")
    parser.add_argument("--denied-log", type=pathlib.Path, default=default_denied_log(env),
                        metavar="PATH", help="the proxy's refusals (default: %(default)s)")
    parser.add_argument("--allowlist", type=pathlib.Path, default=default_allowlist(env),
                        metavar="PATH", help="the allowlist to add to (default: %(default)s)")
    args = parser.parse_args(argv)
    try:
        parse_since(args.since)
    except ValueError as e:
        parser.error(str(e))              # exits with status 2
    if interactive is None:
        interactive = stdin.isatty()
    current = now() if now else datetime.datetime.now(datetime.UTC)
    return run(args, stdin=stdin, out=out, interactive=interactive, now=current, resolve=resolve)


if __name__ == "__main__":
    sys.exit(main())

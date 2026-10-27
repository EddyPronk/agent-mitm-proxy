"""vault: enrolled clients and the credential vault's entries, on the proxy.

    vault enroll NAME [--no-grant]   a token for client NAME (printed once), and the newest entry
    vault grant NAME [ENTRY]         let NAME use ENTRY (default: the newest entry)
    vault unenroll NAME              NAME's token stops working, and it leaves every entry
    vault clients                    the enrolled names
    vault entries                    the vault's entries: id, account, clients, expiry (no tokens)
    vault remove ENTRY               drop an entry (it isn't revoked at Anthropic)

The client puts its name and token in its proxy URL: http://NAME:TOKEN@proxy:8899. Enrolling a
name again gives it a new token; the old one stops working, on open connections too. So does
unenrolling. An entry whose last client is unenrolled is refused to everyone until `grant`.

Paths, as the proxy uses them (scripts/start-proxy.sh):

| Option | Variable | Default |
|---|---|---|
| --clients | AGENT_MITM_PROXY_CLIENTS | $AGENT_MITM_PROXY_DATA/clients.json, or data/clients.json |
| --vault | AGENT_MITM_PROXY_VAULT | $AGENT_MITM_PROXY_DATA/credential-vault.json, or data/credential-vault.json |
"""

import argparse
import datetime
import os
import pathlib
import re
import sys
from typing import TextIO

from .client_auth import load_clients, new_token, token_hash, update_clients
from .credential_vault import Vault

NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,62}")


def default_path(env: dict, variable: str, file: str) -> pathlib.Path:
    if env.get(variable):
        return pathlib.Path(env[variable])
    return pathlib.Path(env.get("AGENT_MITM_PROXY_DATA") or "data") / file


def _when(seconds: float | None) -> str:
    if not seconds:
        return "-"
    return datetime.datetime.fromtimestamp(seconds, datetime.UTC).astimezone().strftime("%Y-%m-%d %H:%M")


def run(args: argparse.Namespace, out: TextIO) -> int:
    clients_path = str(args.clients)
    vault = Vault(str(args.vault))
    if args.command == "enroll":
        token = new_token()
        with update_clients(clients_path) as clients:
            clients[args.name] = token_hash(token)
        print(f"enrolled {args.name}; its proxy URL (shown once):", file=out)
        print(f"http://{args.name}:{token}@proxy:8899", file=out)
        if not args.no_grant:
            entry = vault.grant(args.name)
            print(f"granted entry {entry}" if entry else "no vault entry to grant yet", file=out)
    elif args.command == "grant":
        entry = vault.grant(args.name, args.entry)
        if entry is None:
            print("no such vault entry" if args.entry else "no vault entry to grant", file=out)
            return 1
        if args.name not in load_clients(clients_path):
            print(f"note: {args.name} isn't enrolled", file=out)
        print(f"granted entry {entry} to {args.name}", file=out)
    elif args.command == "unenroll":
        with update_clients(clients_path) as clients:
            known = clients.pop(args.name, None) is not None
        left = vault.ungrant(args.name)
        print(f"{args.name}: {'unenrolled' if known else 'was not enrolled'}; "
              f"left entries: {', '.join(left) or 'none'}", file=out)
    elif args.command == "clients":
        for name in sorted(load_clients(clients_path)):
            print(name, file=out)
    elif args.command == "entries":
        for entry_id, e in vault.entries().items():
            print(f"{entry_id}  account {e.get('account') or '-'}  "
                  f"clients {','.join(e.get('clients', [])) or '(none yet)'}  "
                  f"access until {_when(e.get('expires_at'))}  "
                  f"refresh until {_when(e.get('refresh_expires_at'))}", file=out)
    elif args.command == "remove":
        if args.entry not in vault.entries():
            print(f"no entry {args.entry}", file=out)
            return 1
        vault.remove(args.entry)
        print(f"removed {args.entry} (not revoked at Anthropic)", file=out)
    return 0


def main(argv: list[str] | None = None, *, out: TextIO | None = None, env: dict | None = None) -> int:
    env = os.environ if env is None else env
    out = sys.stdout if out is None else out

    def name(value: str) -> str:
        if not NAME.fullmatch(value):
            raise argparse.ArgumentTypeError("a name: letters, digits, '_', '.', '-'; no ':'")
        return value

    parser = argparse.ArgumentParser(prog="vault", description="Enrolled clients and the credential vault.")
    parser.add_argument("--clients", type=pathlib.Path,
                        default=default_path(env, "AGENT_MITM_PROXY_CLIENTS", "clients.json"),
                        metavar="PATH", help="the enrolled clients (default: %(default)s)")
    parser.add_argument("--vault", type=pathlib.Path,
                        default=default_path(env, "AGENT_MITM_PROXY_VAULT", "credential-vault.json"),
                        metavar="PATH", help="the vault (default: %(default)s)")
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("enroll", help="a new token for a client (printed once)")
    p.add_argument("name", type=name)
    p.add_argument("--no-grant", action="store_true", help="don't grant it the newest entry")
    p = sub.add_parser("grant", help="let a client use an entry")
    p.add_argument("name", type=name)
    p.add_argument("entry", nargs="?")
    p = sub.add_parser("unenroll", help="a client's token stops working; it leaves every entry")
    p.add_argument("name", type=name)
    sub.add_parser("clients", help="the enrolled names")
    sub.add_parser("entries", help="the vault's entries, without tokens")
    p = sub.add_parser("remove", help="drop an entry from the vault")
    p.add_argument("entry")
    return run(parser.parse_args(argv), out)


if __name__ == "__main__":
    sys.exit(main())

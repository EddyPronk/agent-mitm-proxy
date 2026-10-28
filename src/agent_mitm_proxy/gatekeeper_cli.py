"""gatekeeper: set up the allowlist gatekeeper's Buzz identity, on the proxy.

    gatekeeper init --relay URL          a new key; prints its npub, for the owner to attest
    gatekeeper import-key --relay URL    an existing key (nsec) from stdin, instead of init
    gatekeeper attest                    the owner's attestation (NIP-OA tag) from stdin
    gatekeeper dm ID                     the DM channel between the gatekeeper and the owner
    gatekeeper status                    what's set, when the attestation expires, and if it runs
    gatekeeper env                       shell exports for scripts/start-gatekeeper.sh

`init` makes the key in the proxy, so it never has to exist anywhere else; the owner attests its
npub with their own key, on their own machine, and pipes the tag into `attest`. `attest` checks
the tag against the key and takes the owner's pubkey from it. `env` fails until the key, the
attestation, the relay and the DM are set; scripts/start-gatekeeper.sh starts the gatekeeper
from it. Nothing here prints the key.

The folder holds `key` (the nsec), `auth-tag.json` and `config.json`, all private:

| Option | Variable | Default |
|---|---|---|
| --dir | AGENT_MITM_PROXY_GATEKEEPER | $AGENT_MITM_PROXY_DATA/gatekeeper, or data/gatekeeper |
"""

import argparse
import datetime
import json
import os
import pathlib
import re
import shlex
import socket
import sys
import time
from typing import TextIO

import buzzkit

UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
RELAY = re.compile(r"wss://[A-Za-z0-9.-]+(:\d+)?/?")
EXPIRY = re.compile(r"created_at<(\d+)")
WARN_DAYS = 14


class SetupError(Exception):
    pass


def data_dir(env: dict) -> pathlib.Path:
    return pathlib.Path(env.get("AGENT_MITM_PROXY_DATA") or "data")


def default_dir(env: dict) -> pathlib.Path:
    if env.get("AGENT_MITM_PROXY_GATEKEEPER"):
        return pathlib.Path(env["AGENT_MITM_PROXY_GATEKEEPER"])
    return data_dir(env) / "gatekeeper"


def _write_private(path: pathlib.Path, text: str, *, replace: bool) -> None:
    """Write TEXT to PATH, mode 600, atomically; over an existing file only if REPLACE."""
    if path.exists() and not replace:
        raise SetupError(f"{path} exists; --force replaces it")
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.{os.getpid()}")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(text)
    os.replace(tmp, path)


def load_config(d: pathlib.Path) -> dict:
    try:
        return json.loads((d / "config.json").read_text())
    except FileNotFoundError:
        return {}


def save_config(d: pathlib.Path, config: dict) -> None:
    _write_private(d / "config.json", json.dumps(config, indent=2) + "\n", replace=True)


def agent_pubkey(d: pathlib.Path) -> tuple[str, str]:
    """(npub, hex) of the key in D."""
    try:
        secret = (d / "key").read_text().strip()
    except FileNotFoundError:
        raise SetupError("no key yet: gatekeeper init, or import-key") from None
    return buzzkit.pubkey_from_secret(secret)


def _check_relay(url: str) -> str:
    if not RELAY.fullmatch(url):
        raise SetupError(f"the relay is wss://HOST, not {url!r}")
    return url


def _new_identity(d: pathlib.Path, relay: str, nsec: str, *, force: bool) -> None:
    _write_private(d / "key", nsec + "\n", replace=force)
    (d / "auth-tag.json").unlink(missing_ok=True)          # it attested another key
    save_config(d, {"relay_url": relay})


def init(d: pathlib.Path, relay: str, *, force: bool) -> str:
    relay = _check_relay(relay)
    nsec, npub, _ = buzzkit.generate_keypair()
    _new_identity(d, relay, nsec, force=force)
    return npub


def import_key(d: pathlib.Path, relay: str, nsec: str, *, force: bool) -> str:
    relay = _check_relay(relay)
    nsec = nsec.strip()
    if not nsec.startswith("nsec1"):
        raise SetupError("expected an nsec (nsec1...) on stdin")
    try:
        npub, _ = buzzkit.pubkey_from_secret(nsec)
    except ValueError:
        raise SetupError("not a valid nsec") from None
    _new_identity(d, relay, nsec, force=force)
    return npub


def expiry(tag: str) -> int | None:
    """The attestation's created_at< bound, as a Unix time; None without one."""
    m = EXPIRY.search(json.loads(tag)[2])
    return int(m.group(1)) if m else None


def attest(d: pathlib.Path, tag: str) -> tuple[str, int | None]:
    """Check that TAG attests D's key, keep it, and record its owner. (owner hex, expiry)."""
    tag = tag.strip()
    _, agent_hex = agent_pubkey(d)
    try:
        owner = buzzkit.verify_auth_tag(tag, agent_hex)
    except ValueError as e:
        raise SetupError(f"the attestation doesn't attest this key ({agent_hex}): {e}") from None
    if owner == agent_hex:
        raise SetupError("the attestation is self-signed; the owner signs it with their own key")
    until = expiry(tag)
    if until is not None and until <= time.time():
        raise SetupError("the attestation has expired")
    _write_private(d / "auth-tag.json", tag + "\n", replace=True)
    config = load_config(d)
    config["owner_pubkey"] = owner
    save_config(d, config)
    return owner, until


def set_dm(d: pathlib.Path, dm_id: str) -> None:
    if not UUID.fullmatch(dm_id):
        raise SetupError(f"a DM id is a UUID, not {dm_id!r}")
    config = load_config(d)
    config["dm_id"] = dm_id
    save_config(d, config)


def missing(d: pathlib.Path) -> list[str]:
    config = load_config(d)
    gaps = [] if (d / "key").exists() else ["key (init or import-key)"]
    if not (d / "auth-tag.json").exists():
        gaps.append("attestation (attest)")
    gaps += [f"{key} ({how})" for key, how in (("relay_url", "init or import-key"),
                                               ("owner_pubkey", "attest"), ("dm_id", "dm"))
             if key not in config]
    return gaps


def exports(d: pathlib.Path, env: dict) -> str:
    gaps = missing(d)
    if gaps:
        raise SetupError("not set up; missing: " + ", ".join(gaps))
    config = load_config(d)
    data = data_dir(env).absolute()
    values = {
        "GATEKEEPER_RELAY_URL": config["relay_url"],
        "GATEKEEPER_OWNER_PUBKEY": config["owner_pubkey"],
        "GATEKEEPER_DM_ID": config["dm_id"],
        "GATEKEEPER_KEY_FILE": str((d / "key").absolute()),
        "GATEKEEPER_TAG_FILE": str((d / "auth-tag.json").absolute()),
        "GATEKEEPER_ALLOWLIST": str(pathlib.Path(env.get("AGENT_MITM_PROXY_ALLOWLIST")
                                                 or "allowlist.txt").absolute()),
        "GATEKEEPER_AUDIT_LOG": str(data / "allowlist-requests.jsonl"),
        "GATEKEEPER_LOG": str(data / "gatekeeper.log"),
    }
    return "".join(f"export {k}={shlex.quote(v)}\n" for k, v in values.items())


def _listening(port: int) -> bool:
    with socket.socket() as s:
        s.settimeout(0.5)
        return s.connect_ex(("127.0.0.1", port)) == 0


def _when(seconds: float) -> str:
    return datetime.datetime.fromtimestamp(seconds, datetime.UTC).astimezone().strftime("%Y-%m-%d %H:%M %Z")


def status(d: pathlib.Path, env: dict) -> str:
    config = load_config(d)
    try:
        identity = agent_pubkey(d)[0]
    except SetupError as e:
        identity = f"none: {e}"
    lines = [f"identity     {identity}",
             f"relay        {config.get('relay_url', '-')}",
             f"owner        {config.get('owner_pubkey', '- (attest)')}",
             f"dm           {config.get('dm_id', '- (dm ID)')}"]
    tag = d / "auth-tag.json"
    if not tag.exists():
        lines.append("attestation  none (attest)")
    elif (until := expiry(tag.read_text())) is None:
        lines.append("attestation  no expiry")
    else:
        days = (until - time.time()) / 86400
        note = "EXPIRED: renew it" if days <= 0 else f"{days:.0f} days left" + (
            "; renew it soon" if days < WARN_DAYS else "")
        lines.append(f"attestation  expires {_when(until)} ({note})")
    gaps = missing(d)
    lines.append("set up       " + ("yes" if not gaps else "no; missing: " + ", ".join(gaps)))
    port = int(env.get("GATEKEEPER_PORT") or 8900)
    lines.append(f"running      {'yes' if _listening(port) else 'no'} (port {port})")
    return "\n".join(lines)


def run(args: argparse.Namespace, out: TextIO, stdin: TextIO, env: dict) -> int:
    d = args.dir
    if args.command == "init":
        npub = init(d, args.relay, force=args.force)
        print(f"new identity: {npub}", file=out)
        print("next: the owner attests it, and pipes the tag into `gatekeeper attest`", file=out)
    elif args.command == "import-key":
        npub = import_key(d, args.relay, stdin.read(), force=args.force)
        print(f"imported identity: {npub}", file=out)
        print("next: pipe the owner's attestation into `gatekeeper attest`", file=out)
    elif args.command == "attest":
        owner, until = attest(d, stdin.read())
        print(f"attested by owner {owner} ({'no expiry' if until is None else 'expires ' + _when(until)})",
              file=out)
    elif args.command == "dm":
        set_dm(d, args.dm_id)
        print(f"DM {args.dm_id}", file=out)
    elif args.command == "status":
        print(status(d, env), file=out)
    elif args.command == "env":
        out.write(exports(d, env))
    return 0


def main(argv: list[str] | None = None, *, out: TextIO | None = None, stdin: TextIO | None = None,
         env: dict | None = None) -> int:
    env = os.environ if env is None else env
    out = sys.stdout if out is None else out
    stdin = sys.stdin if stdin is None else stdin

    parser = argparse.ArgumentParser(prog="gatekeeper", description="The gatekeeper's Buzz identity.")
    parser.add_argument("--dir", type=pathlib.Path, default=default_dir(env), metavar="PATH",
                        help="where the key, attestation and settings are (default: %(default)s)")
    sub = parser.add_subparsers(dest="command", required=True)
    for command, text in (("init", "a new key for the gatekeeper"),
                          ("import-key", "an existing key (nsec), from stdin")):
        p = sub.add_parser(command, help=text)
        p.add_argument("--relay", required=True, help="the Buzz relay: wss://NAME.communities.buzz.xyz")
        p.add_argument("--force", action="store_true", help="replace the key there is")
    sub.add_parser("attest", help="the owner's attestation of the key, from stdin")
    p = sub.add_parser("dm", help="the DM channel between the gatekeeper and the owner")
    p.add_argument("dm_id")
    sub.add_parser("status", help="what's set up, and if it runs")
    sub.add_parser("env", help="exports for scripts/start-gatekeeper.sh; fails until set up")
    try:
        return run(parser.parse_args(argv), out, stdin, env)
    except SetupError as e:
        print(f"gatekeeper: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())

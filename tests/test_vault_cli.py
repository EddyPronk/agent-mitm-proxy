"""The vault command: enrolling clients and granting them the vault's entries."""

import base64
import io
import json
import multiprocessing
import threading

import pytest

from agent_mitm_proxy import client_auth
from agent_mitm_proxy.client_auth import client_name, load_clients
from agent_mitm_proxy.credential_vault import Vault
from agent_mitm_proxy.vault_cli import main

TOKENS = {"access_token": "sk-ant-oat01-REAL-ACCESS", "refresh_token": "sk-ant-ort01-REAL-REFRESH",
          "expires_in": 28800, "refresh_token_expires_in": 2419200, "account": {"uuid": "acc-1"}}


@pytest.fixture
def paths(tmp_path):
    return ["--clients", str(tmp_path / "clients.json"), "--vault", str(tmp_path / "vault.json")]


def run(paths, *args):
    out = io.StringIO()
    status = main([*paths, *args], out=out)
    return status, out.getvalue()


def test_enroll_prints_the_proxy_url_once_and_stores_only_the_hash(paths, tmp_path):
    status, text = run(paths, "enroll", "alpha")
    url = text.splitlines()[1]
    token = url.removeprefix("http://alpha:").removesuffix("@proxy:8899")
    assert status == 0 and url.startswith("http://alpha:") and token
    stored = (tmp_path / "clients.json").read_text()
    assert token not in stored and token not in run(paths, "clients")[1]
    header = b"Basic " + base64.b64encode(f"alpha:{token}".encode())
    assert client_name(header, load_clients(str(tmp_path / "clients.json"))) == "alpha"


def test_enrolling_again_gives_a_new_token(paths, tmp_path):
    first = run(paths, "enroll", "alpha")[1].splitlines()[1]
    second = run(paths, "enroll", "alpha")[1].splitlines()[1]
    assert first != second and len(load_clients(str(tmp_path / "clients.json"))) == 1


def test_enroll_grants_the_newest_entry_unless_told_not_to(paths, tmp_path):
    vault = Vault(str(tmp_path / "vault.json"))
    assert "no vault entry to grant yet" in run(paths, "enroll", "alpha")[1]
    entry_id, _ = vault.store(TOKENS, None, client="beta", name="beta")
    assert f"granted entry {entry_id}" in run(paths, "enroll", "alpha")[1]
    assert vault.entries()[entry_id]["clients"] == ["beta", "alpha"]
    assert "granted" not in run(paths, "enroll", "gamma", "--no-grant")[1]
    assert vault.entries()[entry_id]["clients"] == ["beta", "alpha"]


def test_unenroll_stops_the_token_and_leaves_the_entries(paths, tmp_path):
    vault = Vault(str(tmp_path / "vault.json"))
    entry_id, _ = vault.store(TOKENS, None, client="beta", name="beta")
    run(paths, "enroll", "alpha")
    status, text = run(paths, "unenroll", "alpha")
    assert status == 0 and entry_id in text
    assert "alpha" not in load_clients(str(tmp_path / "clients.json"))
    assert vault.entries()[entry_id]["clients"] == ["beta"]


def test_grant_and_entries_show_no_tokens(paths, tmp_path):
    vault = Vault(str(tmp_path / "vault.json"))
    assert run(paths, "grant", "alpha")[0] == 1
    entry_id, _ = vault.store(TOKENS, None, client="beta", name="beta")
    status, text = run(paths, "grant", "alpha", entry_id)
    assert status == 0 and "isn't enrolled" in text
    assert run(paths, "grant", "alpha", "nosuch")[0] == 1
    listing = run(paths, "entries")[1]
    assert entry_id in listing and "beta,alpha" in listing and "acc-1" in listing
    assert "REAL" not in listing and "REAL" not in json.dumps(vault.entries()[entry_id]["clients"])


def test_remove(paths, tmp_path):
    vault = Vault(str(tmp_path / "vault.json"))
    entry_id, _ = vault.store(TOKENS, None, client="beta", name="beta")
    assert run(paths, "remove", "nosuch")[0] == 1
    assert run(paths, "remove", entry_id)[0] == 0 and vault.entries() == {}


def _enroll_paused(paths, read_done, go_on):
    """In another process: `vault enroll beta`, paused just after reading clients.json."""
    original = client_auth.load_clients

    def paused(path):
        clients = original(path)
        read_done.set()
        go_on.wait(10)
        return clients

    client_auth.load_clients = paused
    raise SystemExit(main([*paths, "enroll", "beta", "--no-grant"], out=io.StringIO()))


def test_two_commands_at_once_dont_undo_each_other(paths, tmp_path):
    path = str(tmp_path / "clients.json")
    run(paths, "enroll", "alpha")
    ctx = multiprocessing.get_context("fork")
    read_done, go_on = ctx.Event(), ctx.Event()
    enrolling = ctx.Process(target=_enroll_paused, args=(paths, read_done, go_on))
    enrolling.start()
    try:
        assert read_done.wait(10)
        unenrolling = threading.Thread(target=run, args=(paths, "unenroll", "alpha"))
        unenrolling.start()
        unenrolling.join(0.3)
        assert unenrolling.is_alive()          # waits for the lock the paused enroll holds
    finally:
        go_on.set()
        enrolling.join(10)
    unenrolling.join(10)
    assert enrolling.exitcode == 0 and not unenrolling.is_alive()
    assert set(load_clients(path)) == {"beta"}


@pytest.mark.parametrize("name", ["a:b", "", "-x", "a b", "x" * 80])
def test_names_are_checked(paths, name):
    with pytest.raises(SystemExit):
        main([*paths, "enroll", name], out=io.StringIO())

"""The gatekeeper command: its identity's set-up. No relay; the keys are made up here."""

import io
import pathlib
import stat
import subprocess
import sys
import time

import buzzkit
import pytest

from agent_mitm_proxy import gatekeeper_cli as gk

RELAY = "wss://example.communities.buzz.xyz"
DM = "00000000-1111-2222-3333-444444444444"
SCRIPTS = pathlib.Path(__file__).resolve().parent.parent / "scripts"


@pytest.fixture
def env(tmp_path):
    return {"AGENT_MITM_PROXY_DATA": str(tmp_path / "data"),
            "AGENT_MITM_PROXY_ALLOWLIST": "/workspace/allowlist.txt",
            "GATEKEEPER_PORT": "1"}                    # nothing listens there


@pytest.fixture
def d(env):
    return gk.default_dir(env)


def cli(env, *argv, stdin=""):
    out = io.StringIO()
    code = gk.main(list(argv), out=out, stdin=io.StringIO(stdin), env=env)
    return code, out.getvalue()


def owner_tag(d, conditions=None, owner_nsec=None):
    """An attestation of D's key by a new owner (or OWNER_NSEC): (tag, owner hex)."""
    owner_nsec = owner_nsec or buzzkit.generate_keypair()[0]
    if conditions is None:
        conditions = f"created_at<{int(time.time()) + 90 * 86400}"
    tag = buzzkit.compute_auth_tag(owner_nsec, gk.agent_pubkey(d)[1], conditions)
    return tag, buzzkit.pubkey_from_secret(owner_nsec)[1]


def mode(path):
    return stat.S_IMODE(path.stat().st_mode)


def set_up(d):
    gk.init(d, RELAY, force=False)
    gk.attest(d, owner_tag(d)[0])
    gk.set_dm(d, DM)


def test_the_folder_is_in_the_data_directory_unless_given(env, tmp_path):
    assert gk.default_dir(env) == tmp_path / "data" / "gatekeeper"
    assert gk.default_dir({**env, "AGENT_MITM_PROXY_GATEKEEPER": "/x"}) == pathlib.Path("/x")
    assert gk.default_dir({}) == pathlib.Path("data/gatekeeper")


def test_init_makes_a_private_key_and_prints_only_the_npub(env, d):
    code, out = cli(env, "init", "--relay", RELAY)
    assert code == 0 and "npub1" in out and "nsec1" not in out
    assert (d / "key").read_text().startswith("nsec1")
    assert mode(d) == 0o700 and mode(d / "key") == 0o600 and mode(d / "config.json") == 0o600
    assert gk.load_config(d) == {"relay_url": RELAY}


def test_init_keeps_a_key_there_is_without_force(d):
    gk.init(d, RELAY, force=False)
    before = (d / "key").read_text()
    with pytest.raises(gk.SetupError, match="--force"):
        gk.init(d, RELAY, force=False)
    assert (d / "key").read_text() == before
    gk.init(d, RELAY, force=True)
    assert (d / "key").read_text() != before


def test_the_relay_is_wss(d):
    with pytest.raises(gk.SetupError, match="wss://"):
        gk.init(d, "https://example.org", force=False)
    assert not (d / "key").exists()


def test_import_key_takes_an_nsec_from_stdin(env, d):
    nsec, npub, _ = buzzkit.generate_keypair()
    code, out = cli(env, "import-key", "--relay", RELAY, stdin=nsec + "\n")
    assert code == 0 and npub in out and nsec not in out
    assert (d / "key").read_text() == nsec + "\n"


def test_import_key_refuses_anything_but_an_nsec(d):
    with pytest.raises(gk.SetupError, match="expected an nsec"):
        gk.import_key(d, RELAY, "npub1abc", force=False)
    with pytest.raises(gk.SetupError, match="not a valid nsec"):
        gk.import_key(d, RELAY, "nsec1notakey", force=False)
    assert not (d / "key").exists()


def test_attest_records_the_owner_and_the_expiry(d, env):
    gk.init(d, RELAY, force=False)
    tag, owner = owner_tag(d)
    got, until = gk.attest(d, tag + "\n")
    assert got == owner and until > time.time()
    assert gk.load_config(d)["owner_pubkey"] == owner
    assert mode(d / "auth-tag.json") == 0o600
    assert "days left" in gk.status(d, env)


def test_attest_refuses_a_tag_for_another_key(d):
    gk.init(d, RELAY, force=False)
    tag, _ = owner_tag(d)
    gk.init(d, RELAY, force=True)
    with pytest.raises(gk.SetupError, match="doesn't attest this key"):
        gk.attest(d, tag)
    assert not (d / "auth-tag.json").exists()


def test_there_is_no_self_attestation_to_attest(d):
    # buzzkit 0.3 won't make one; attest() also refuses it, should a tag come from elsewhere.
    nsec, _, _ = buzzkit.generate_keypair()
    gk.import_key(d, RELAY, nsec, force=False)
    with pytest.raises(ValueError):
        owner_tag(d, owner_nsec=nsec)


def test_attest_refuses_an_expired_tag(d):
    gk.init(d, RELAY, force=False)
    tag, _ = owner_tag(d, conditions=f"created_at<{int(time.time()) - 60}")
    with pytest.raises(gk.SetupError, match="expired"):
        gk.attest(d, tag)


def test_a_new_key_drops_the_attestation(d):
    set_up(d)
    gk.init(d, RELAY, force=True)
    assert "attestation (attest)" in gk.missing(d)
    assert "dm_id (dm)" in gk.missing(d)


def test_the_dm_is_a_uuid(d):
    with pytest.raises(gk.SetupError, match="UUID"):
        gk.set_dm(d, "general")
    gk.set_dm(d, DM)
    assert gk.load_config(d)["dm_id"] == DM


def test_env_fails_until_set_up(env, d, capsys):
    assert cli(env, "env")[0] == 1
    assert "missing: key" in capsys.readouterr().err
    gk.init(d, RELAY, force=False)
    gk.attest(d, owner_tag(d)[0])
    assert cli(env, "env")[0] == 1
    assert "dm_id (dm)" in capsys.readouterr().err


def test_env_exports_paths_not_the_key(env, d):
    set_up(d)
    code, out = cli(env, "env")
    assert code == 0 and "nsec1" not in out
    assert f"export GATEKEEPER_KEY_FILE={d / 'key'}\n" in out
    assert f"export GATEKEEPER_DM_ID={DM}\n" in out
    assert "export GATEKEEPER_ALLOWLIST=/workspace/allowlist.txt\n" in out
    assert f"export GATEKEEPER_LOG={d.parent / 'gatekeeper.log'}\n" in out


def test_status(env, d):
    s = gk.status(d, env)
    assert "identity     none" in s and "set up       no" in s and "running      no" in s
    set_up(d)
    s = gk.status(d, env)
    assert "set up       yes" in s and DM in s


def test_start_gatekeeper_does_nothing_without_a_set_up(env, tmp_path):
    proc = subprocess.run(["bash", str(SCRIPTS / "start-gatekeeper.sh")], cwd=tmp_path,
                          env={**env, "PATH": "/usr/bin:/bin", "AGENT_MITM_PROXY_PYTHON": sys.executable},
                          capture_output=True, text=True, timeout=60, check=False)
    assert proc.returncode == 0
    assert "gatekeeper not started: not set up; missing: key" in proc.stderr

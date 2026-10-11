"""approve: the refusal log in, prompts answered from scripted input, the allowlist out."""

import datetime
import io
import json
import socket

import pytest

from agent_mitm_proxy.approve import ago, main, parse_since, read_refused

NOW = datetime.datetime(2026, 10, 11, 0, 0, 0, tzinfo=datetime.UTC)


def resolver(lan=()):
    """Every name resolves to a global address, except those in `lan`."""
    def resolve(host, port, proto=0):
        address = "192.168.1.5" if host in lan else "93.184.215.14"
        return [(socket.AF_INET, socket.SOCK_STREAM, proto, "", (address, port))]
    return resolve


def record(host, port, seconds_ago, reason="not in allowlist"):
    when = NOW - datetime.timedelta(seconds=seconds_ago)
    return json.dumps({"timestamp": when.strftime("%Y-%m-%dT%H:%M:%S%z"), "host": host,
                       "port": port, "reason": reason})


@pytest.fixture
def files(tmp_path):
    denied, allowlist = tmp_path / "denied.jsonl", tmp_path / "allowlist.txt"
    allowlist.write_text("api.anthropic.com:443\n")
    return denied, allowlist


def approve(files, lines, answers="", *, interactive=True, args=(), lan=()):
    denied, allowlist = files
    denied.write_text("".join(line + "\n" for line in lines))
    out = io.StringIO()
    status = main(["--denied-log", str(denied), "--allowlist", str(allowlist), *args],
                  stdin=io.StringIO(answers), out=out, env={}, interactive=interactive,
                  now=lambda: NOW, resolve=resolver(lan))
    return status, out.getvalue(), allowlist.read_text()


@pytest.mark.parametrize("text, seconds", [("30s", 30), ("5m", 300), ("2h", 7200), ("1d", 86400)])
def test_parse_since(text, seconds):
    assert parse_since(text) == datetime.timedelta(seconds=seconds)


@pytest.mark.parametrize("text", ["", "5", "m", "0m", "5 minutes", "-5m", "1w"])
def test_parse_since_refuses_other_text(text):
    with pytest.raises(ValueError):
        parse_since(text)


def test_read_refused_groups_counts_and_orders_most_recent_first():
    lines = [record("a.example", 443, 200), record("b.example", 80, 100),
             record("a.example", 443, 10), record("A.example", 443, 50),
             "not json", '{"host": "no-timestamp.example", "port": 1}', ""]
    got = read_refused(lines, NOW - datetime.timedelta(minutes=5))
    assert [(r.entry, r.count) for r in got] == [("a.example:443", 3), ("b.example:80", 1)]
    assert got[0].last == NOW - datetime.timedelta(seconds=10)


def test_read_refused_leaves_out_older_entries():
    got = read_refused([record("old.example", 443, 301), record("new.example", 443, 299)],
                       NOW - datetime.timedelta(minutes=5))
    assert [r.entry for r in got] == ["new.example:443"]


def test_ago():
    assert ago(NOW - datetime.timedelta(seconds=42), NOW) == "42s ago"
    assert ago(NOW - datetime.timedelta(seconds=150), NOW) == "2m ago"
    assert ago(NOW - datetime.timedelta(hours=3), NOW) == "3h ago"
    assert ago(NOW + datetime.timedelta(seconds=5), NOW) == "0s ago"


def test_yes_adds_with_a_comment_enter_and_n_skip(files):
    lines = [record("one.example", 443, 30), record("two.example", 443, 20),
             record("three.example", 80, 10)]
    status, out, allowlist = approve(files, lines, "\nn\ny\n")
    assert status == 0
    added = allowlist.splitlines()[1:]
    assert len(added) == 1
    assert added[0].startswith("one.example:443 ")
    assert "# approved with approve, " in added[0]
    assert "Add three.example:80 to the allowlist? (1×, last 10s ago) [y/N/q]" in out
    assert "Added 1 to " in out


def test_q_stops_and_end_of_input_stops(files):
    lines = [record("one.example", 443, 30), record("two.example", 443, 20)]
    _, _, allowlist = approve(files, lines, "q\ny\n")
    assert allowlist == "api.anthropic.com:443\n"
    _, _, allowlist = approve(files, lines, "")
    assert allowlist == "api.anthropic.com:443\n"


def test_listed_hosts_are_not_offered(files):
    _, out, _ = approve(files, [record("api.anthropic.com", 443, 10)], "y\n")
    assert "Nothing refused in the last 5m that isn't in the allowlist now." in out


def test_hosts_the_proxy_refuses_anyway_are_shown_but_never_offered(files):
    lines = [record("169.254.169.254", 80, 30), record("lan.example", 443, 20),
             record("good.example", 443, 10)]
    _, out, allowlist = approve(files, lines, "y\ny\ny\n", lan=("lan.example",))
    assert "Not offered" in out
    assert "IP addresses are not allowed" in out
    assert "lan.example: resolves to non-global address 192.168.1.5" in out
    assert "Add 169.254.169.254" not in out and "Add lan.example" not in out
    assert allowlist.splitlines()[1].startswith("good.example:443 ")
    assert len(allowlist.splitlines()) == 2


def test_only_hosts_never_offered(files):
    _, out, _ = approve(files, [record("169.254.169.254", 80, 30)], "y\n")
    assert out.startswith("Not offered")
    assert "Add " not in out and "Added" not in out


def test_without_a_terminal_nothing_is_added(files):
    status, out, allowlist = approve(files, [record("one.example", 443, 10)], "y\n", interactive=False)
    assert status == 0
    assert "one.example:443" in out
    assert "No terminal: nothing added." in out
    assert "Add one.example" not in out
    assert allowlist == "api.anthropic.com:443\n"


def test_list_only_lists(files):
    _, out, allowlist = approve(files, [record("one.example", 443, 10)], "y\n", args=["--list"])
    assert "one.example:443" in out and "Add " not in out and "No terminal" not in out
    assert allowlist == "api.anthropic.com:443\n"


def test_since_widens_the_window(files):
    lines = [record("hour.example", 443, 3000)]
    _, out, _ = approve(files, lines, args=["--list"])
    assert "hour.example" not in out
    _, out, _ = approve(files, lines, args=["--list", "--since", "1h"])
    assert "hour.example:443" in out


def test_no_log_yet(files, tmp_path):
    out = io.StringIO()
    status = main(["--denied-log", str(tmp_path / "missing.jsonl"), "--allowlist", str(files[1])],
                  stdin=io.StringIO(), out=out, env={}, interactive=True, now=lambda: NOW)
    assert status == 0
    assert "No refusals logged yet" in out.getvalue()


def test_a_bad_duration_is_a_usage_error(files):
    with pytest.raises(SystemExit) as exit_:
        approve(files, [], args=["--since", "soon"])
    assert exit_.value.code == 2


def test_paths_default_to_the_proxys_variables(tmp_path):
    from agent_mitm_proxy.approve import default_allowlist, default_denied_log
    assert str(default_denied_log({"AGENT_MITM_PROXY_DATA": "/d"})) == "/d/denied.jsonl"
    assert str(default_denied_log({"AGENT_MITM_PROXY_DENIED_LOG": "/x.jsonl",
                                   "AGENT_MITM_PROXY_DATA": "/d"})) == "/x.jsonl"
    assert str(default_denied_log({})) == "data/denied.jsonl"
    assert str(default_allowlist({"AGENT_MITM_PROXY_ALLOWLIST": "/w/allowlist.txt"})) == "/w/allowlist.txt"
    assert str(default_allowlist({})) == "allowlist.txt"

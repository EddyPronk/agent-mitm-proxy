# agent-mitm-proxy

A TLS-intercepting egress proxy with an allowlist, for sandboxed coding agents.

A sandboxed coding agent reaches the Internet only through this proxy. The proxy
intercepts TLS, connects only to hosts on an allowlist, and logs the decrypted traffic. When
the agent needs another host, it asks over MCP; the owner approves or rejects on their phone
(a signed 👍 / 👎 on Buzz), and an approved host is added to the allowlist
without a restart. Internal services (e.g. Ollama on the LAN) are reachable only per granted
method + path, without the agent learning their address.

```text
sandbox ──(internal network, no route out)──▶ proxy ──▶ Internet
   HTTP(S)_PROXY=http://proxy:8899             proxy.py + AllowlistPlugin + TrafficLogPlugin
   MCP http://proxy:8900/mcp                   gatekeeper ──WebSocket──▶ Buzz relay ──▶ owner
   http://proxy:11434 (e.g. ollama)            forwarder ──▶ internal service (granted paths only)
```

Work in progress: the code has moved in from the experiments it grew out of; a container
image and setup that ties the pieces together are next.

## Components

| Module | What | Start with |
|---|---|---|
| `allowlist` | Allowlist parsing and matching, the non-global address check, adding entries | – |
| `approve` | The `approve` command: go through recent refusals, add the ones you choose | `approve` |
| `grants` | Internal services (`services.json`) and their per-path grants | – |
| `plugins` | proxy.py plugins: `AllowlistPlugin` (refuse unlisted or non-global destinations) and `TrafficLogPlugin` (decrypted bodies as JSONL, never headers) | `scripts/start-proxy.sh` |
| `gatekeeper`, `mcp_server` | MCP tools `request_allowlist` and `get_request_status`; asks the owner on Buzz | `scripts/start-gatekeeper.sh` |
| `forwarder` | Forwards granted method + path requests to internal services, streaming | `scripts/start-forwarder.sh` |

Each module's docstring lists its environment variables; each script's header lists its own.
All scripts take `AGENT_MITM_PROXY_PYTHON`, a Python with this package installed, and do
nothing if their service already runs, so they can run on every container start.

### The allowlist

One entry per line, `#` starts a comment; changes apply without a restart:

```text
api.anthropic.com:443     exact host and port
example.com               exact host, any port
*.anthropic.com:443       any subdomain (not the bare domain)
service:ollama POST /api/chat     an internal service path (see services.example.json)
```

A listed host is still refused if it resolves to a private, loopback, link-local or other
non-global address (also inside NAT64 and other IPv6 forms of an IPv4 address). The host is
resolved once, and the proxy connects to the address it checked, so a host can't pass the check
and then resolve to the LAN for the connection (DNS rebinding).

### Refusal bursts

A refused request gets a `403 Forbidden` that names the host and why. Some clients ignore it:
`npm install` (npm 11, empty cache) retries a refused CONNECT hundreds of times a second, ignores
Ctrl-C, and fills the logs until it's killed. A dropped connection it does handle: it retries a few
times with pauses, then fails with an error. So after a burst of refusals of the same host:port from
the same client, the proxy resets that client's connections for it for a while, without an answer:

| Variable | Default | Meaning |
|---|---|---|
| `AGENT_MITM_PROXY_BURST_COUNT` | 20 | refusals within `BURST_SECONDS` that make a burst; `0` turns this off |
| `AGENT_MITM_PROXY_BURST_SECONDS` | 5 | the window, at least 1 |
| `AGENT_MITM_PROXY_BURST_RESET` | 30 | how long that client's requests for that host:port are reset, at least 1 |

- **Allowed requests are never affected:** the allowlist is checked first, so once you approve the
  host, its requests pass at once.
- **One log record per burst:** `denied.jsonl` gets a record when a burst starts (`"burst"`, the
  client's address), and one with the number dropped (`"count"`) after it. `approve` adds the
  counts. Dropped connections get no access log line.
- **Counts are per proxy process,** and proxy.py runs one per CPU. A looping client exceeds the
  threshold in each of them, so each logs its own burst record.

Measured with npm 11.19.0 against a refused registry, empty cache:

| | 1.0.0 | 1.1.0 |
|---|---|---|
| attempts | 340,264 in 8½ minutes, then `kill -9` | 451, then npm stops by itself after 71 s (`npm error code E403`) |
| `denied.jsonl` records | 340,264 | 228 |

### Approving refused hosts

Every refused connection is logged in `denied.jsonl` (in the data directory). `approve` goes through
the recent ones, one per host and port, and asks for each one:

```text
$ approve --since 10m
Refused in the last 10m (/home/me/proxy-data/denied.jsonl):
  archive.ubuntu.com:80                       4×  last 2m ago
Not offered (the proxy refuses these even when listed):
  169.254.169.254:80                          2×  IP addresses are not allowed; request a host name
Add archive.ubuntu.com:80 to the allowlist? (4×, last 2m ago) [y/N/q] y
Added 1 to /workspace/allowlist.txt; the proxy applies it without a restart.
```

- **`y` adds; Enter or `n` skips; `q` stops.** An added line carries a comment with the date.
- **Never offered:** hosts already listed, and hosts the proxy would refuse anyway (IP addresses, and
  names that resolve to non-global addresses such as cloud metadata).
- **Without a terminal on stdin, or with `--list`, it only lists.** Approving needs a person; piping
  `y` into it adds nothing.
- **Paths:** it reads the same variables as the proxy (`AGENT_MITM_PROXY_DATA`,
  `AGENT_MITM_PROXY_DENIED_LOG`, `AGENT_MITM_PROXY_ALLOWLIST`), or `--denied-log` and `--allowlist`.

Editing the allowlist by hand works just as well.

### What to keep private

The data directory holds the CA private keys and the decrypted traffic; `services.json` holds
internal addresses; the gatekeeper's key file is its Buzz identity. Only the CA certificate
(`AGENT_MITM_PROXY_CA_PUBLISH`) is meant for clients. `.gitignore` covers these names in this
folder.

## Development

Needs [uv](https://docs.astral.sh/uv/).

```sh
uv sync            # create .venv with the package and the dev tools
uv run pytest      # unit tests
uv run ruff check  # lint
```

## Layout

| Path | Contents |
|---|---|
| `src/agent_mitm_proxy/` | The package |
| `scripts/` | Start scripts for the proxy, gatekeeper and forwarder |
| `tests/` | Unit tests (pytest): no network, no containers, no Buzz relay |
| `tests/integration/` | Tests that need a running proxy and a client container (marked `integration`) |

### Integration tests

`tests/integration/test_reachability.py` checks, from inside a client container whose only way
out is the proxy, that allowlisted hosts are reachable and everything else is refused: hosts not
on the allowlist, IP addresses, the LAN, the host, and connections that bypass the proxy. They run
with `uv run pytest` when you name the client container, and are skipped otherwise:

```sh
AGENT_MITM_PROXY_CLIENT=CLIENT uv run pytest
uv run pytest -m "not integration"   # unit tests only
```

| Variable | Default | Meaning |
|---|---|---|
| `AGENT_MITM_PROXY_CLIENT` | (unset: skip) | Running client container |
| `PROXYTEST_ALLOWED` | `api.anthropic.com` | A host on the allowlist |
| `PROXYTEST_BLOCKED` | `example.com` | A host not on the allowlist |
| `PROXYTEST_LAN` | `192.168.15.1` | A LAN address that must stay unreachable |

## License

Apache-2.0

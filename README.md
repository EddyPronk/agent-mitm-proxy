# agent-mitm-proxy

A TLS-intercepting egress proxy with an allowlist, for sandboxed coding agents.

Work in progress: this repository has the package structure and tests so far; the proxy itself
(proxy.py plugins for the allowlist and prompt logging, the approval gatekeeper and the service
forwarder) moves in next.

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
| `tests/` | Unit tests (pytest) |
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

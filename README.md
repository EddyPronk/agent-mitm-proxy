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
| `tests/integration/` | Checks that need a running proxy and a client container, see below |

### Integration checks

`tests/integration/proxytest.sh` runs inside a client container whose only way out is the proxy,
and prints what is reachable:

```sh
podman exec -i CLIENT bash < tests/integration/proxytest.sh
```

Set `PROXYTEST_LAN` to an address on your LAN that must stay unreachable.

## License

Apache-2.0

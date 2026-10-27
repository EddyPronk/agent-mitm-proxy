# agent-mitm-proxy

A TLS-intercepting egress proxy with an allowlist, for sandboxed coding agents.

A sandboxed coding agent reaches the Internet only through this proxy. The proxy
intercepts TLS, connects only to hosts on an allowlist, and logs the decrypted traffic, without
headers and with the credentials and user identity of known endpoints redacted. When
the agent needs another host, it asks over MCP; the owner approves or rejects on their phone
(a signed 👍 / 👎 on Buzz), and an approved host is added to the allowlist
without a restart. Internal services (e.g. Ollama on the LAN) are reachable only per granted
method + path, without the agent learning their address. Optionally, Claude Code's OAuth tokens
stay in the proxy and the sandbox holds only placeholders (the credential vault).

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
| `plugins` | proxy.py plugins: `AllowlistPlugin` (refuse unlisted or non-global destinations) and `TrafficLogPlugin` (decrypted bodies as JSONL, never headers, redacted by `redact`) | `scripts/start-proxy.sh` |
| `redact` | The credentials and identity fields of known endpoints' JSON bodies, and their redaction ([below](#credentials-and-identity-in-the-traffic-log)) | – |
| `credential_vault` | proxy.py plugin `CredentialVaultPlugin`: Claude Code's OAuth tokens stay in the proxy, the client gets placeholders ([below](#the-credential-vault)); off by default | `AGENT_MITM_PROXY_CREDENTIAL_VAULT=1 scripts/start-proxy.sh` |
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

### Credentials and identity in the traffic log

`decrypted-traffic.jsonl` keeps bodies, never headers. Some endpoints carry credentials, or the
user's identity, in their bodies, though, so `redact.FIELD_RULES` nominates each one: the endpoint
(host, path with `*` for an id, request or response) and the fields' places in its JSON body
(`*` for any list item, or any key of an object). Their values are logged as `[REDACTED]`, the
body keeps its key order, and the record's `redacted` lists what was replaced. Redaction is always
on; there is no setting to turn it off.

A JSON body (an object or array) is logged as JSON, so that jq reads it directly
(`jq '.body.account'`); any other body (text, an event stream, a JSON scalar) as a string.

| Endpoint | Body | Fields |
|---|---|---|
| `platform.claude.com/v1/oauth/token` | request | `code`, `code_verifier`, `refresh_token`, `state` |
| `platform.claude.com/v1/oauth/token` | response | `access_token`, `refresh_token`, `id_token`, `token_uuid`, `organization.uuid`, `organization.name`, `account.uuid`, `account.email_address` |
| `platform.claude.com/v1/oauth/token/revoke` | request | `token` |
| `api.anthropic.com/v1/code/sessions/*/bridge` | response | `worker_jwt` |
| `api.anthropic.com/v1/messages` | request | `fallback_credit_token`, `metadata.user_id` |
| `api.anthropic.com/api/eval/*` | request | `attributes.accountUUID`, `attributes.organizationUUID` |
| `api.anthropic.com/api/eval/*` | response | `features.*.experimentResult.hashValue` |
| `api.anthropic.com/api/oauth/profile` | response | `account.uuid`, `.email`, `.full_name`, `.display_name`; `organization.uuid`, `.name`, `.payment_auth_hosted_invoice_url` |
| `api.anthropic.com/api/claude_cli/bootstrap` | response | `oauth_account.account_uuid`, `.account_email`, `.organization_uuid`, `.organization_name` |
| `api.anthropic.com/api/oauth/claude_cli/roles` | response | `organization_uuid`, `organization_name`, `workspace_uuid`, `workspace_name` |
| `api.anthropic.com/api/event_logging/v2/batch` | request | `events.*.event_data.auth.account_uuid`, `.organization_uuid` |

Ids that don't point to a person stay (messages', MCP servers', the Claude Code application's),
and so do ids in request paths, such as `/api/organizations/<uuid>/...`.

- **A nominated body that isn't valid JSON** (an unfinished response, one that couldn't be
  decompressed) is withheld whole (`"redacted": ["body"]`), and no `body_base64` copy is kept of a
  body that had anything redacted.
- **Everything else is logged as it was,** including what the agent itself sends: a key pasted
  into a prompt, or printed by a tool, is in the log. Treat it as sensitive still.
- **A new endpoint with credentials** needs a rule: find where they sit by the shape of the logged
  bodies (key names and types, not values), then add it with a test.

### The credential vault

Claude Code keeps its OAuth tokens in `~/.claude/.credentials.json`, where anything in the sandbox
can read them: the access token (8 hours) and the refresh token (28 days, renewed on each
refresh), enough to use the account from anywhere. With `AGENT_MITM_PROXY_CREDENTIAL_VAULT=1`,
`start-proxy.sh` adds `CredentialVaultPlugin`, and the real tokens never reach the sandbox:

```text
client (sandbox)                         proxy (vault)                           Anthropic
POST /v1/oauth/token {code, verifier} ─▶ passes it on ──────────────────────────▶ platform.claude.com
         {access: P_a, refresh: P_r} ◀─ keeps the real A, R; hands out P_a, P_r ◀─ {access: A, refresh: R}
Authorization: Bearer P_a ────────────▶ Bearer A ────────────────────────────────▶ api.anthropic.com
POST /v1/oauth/token {refresh: P_r} ──▶ answered by the vault while A is fresh;
                                        else one refresh upstream with R ────────▶ platform.claude.com
```

- **Nothing changes in the client.** Claude Code signs in as usual (`/login`) and stores
  placeholders (`agent-mitm-proxy-oat-…`, `agent-mitm-proxy-ort-…`), which it doesn't check.
  A client that signed in before the vault was on is taken over at its next refresh: its real
  refresh token goes upstream once, and it gets placeholders back.
- **Real tokens go only to** `api.anthropic.com`, `platform.claude.com` and
  `mcp-proxy.anthropic.com`, port 443, over the TLS tunnel opened to that host; a request inside
  it that names another host (absolute URL, Host header) gets no token. A placeholder sent
  anywhere else goes out unchanged and is logged.
- **Token responses:** an `id_token` is withheld from the client. One the vault can't read, or
  one that was cut off, isn't passed on (502), so the client never gets real tokens by accident.
- **Refreshes:** the vault answers them itself until the real access token is within 5 minutes
  of expiring (or got a 401), then sends one upstream. Anthropic revokes the previous access token
  on every refresh, so needless refreshes make requests on their way fail.
- **What it doesn't stop:** the sandbox can still *use* the account through this proxy, as before;
  it just can't take a credential with it. Placeholders are random (192 bits) but not tied to a
  client: anyone who can reach the proxy and knows one can use it.
- **Forgetting:** a new sign-in for an account replaces that account's earlier entries from the
  same client address; entries whose refresh token has expired are dropped. Dropped entries are
  forgotten, not revoked upstream.
- **Files** (in the data directory, private): `credential-vault.json` (the real tokens, mode
  0600, refused if group or others can read it; written atomically) and `vault.jsonl` (what the
  vault did: sign-ins, refreshes, swaps, placeholders sent elsewhere; never token values).
- **It follows Claude Code's sign-in, which Anthropic doesn't document.** If that changes (another
  host, another field), the symptom is a 401 in Claude Code and a `placeholder-elsewhere` or
  `unknown-placeholder` record in `vault.jsonl`; turn the vault off and sign in again meanwhile.

### What to keep private

The data directory holds the CA private keys, the decrypted traffic and, with the credential
vault on, Claude Code's tokens; `services.json` holds
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

### Running the tests in a sandbox

`.devcontainer/` is a [podman-agent-sandbox](https://github.com/EddyPronk/podman-agent-sandbox)
config for running all the tests, the integration tests included, in a container. It has Python, uv
and Node.js, and rootless Podman inside to make the proxy and client containers the integration
tests need. It has no Claude Code: it's for running tests, not for an agent. Running containers
inside needs a weaker sandbox (capabilities, an unrestricted network), as with the
`claude-containers` template it comes from.

```sh
sandbox new --workspace . --inplace            # once (sandbox 0.7.0 or later); NAME: agent-mitm-proxy
sandbox exec agent-mitm-proxy uv run pytest    # unit tests
```

For the integration tests, make a proxy and a client inside it, then name the client:

```sh
sandbox exec agent-mitm-proxy sh -c 'sandbox new proxy --template mitm-proxy \
    && sandbox new client --template proxy-client && sandbox exec proxy true && sandbox exec client true'
sandbox exec agent-mitm-proxy env AGENT_MITM_PROXY_CLIENT=client uv run pytest
```

The proxy inside is built from the `mitm-proxy` template's pinned release, not from your working
tree: these tests check the proxy as packaged. The virtual environment is kept in the sandbox's home
(`UV_PROJECT_ENVIRONMENT`), so the project's own `.venv` isn't touched.

## License

Apache-2.0

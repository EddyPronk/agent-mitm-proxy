#!/usr/bin/env bash
# Start the allowlist gatekeeper (Buzz approvals + MCP server) in the background.
# Does nothing if something already listens on the port, so it can run on every container start.
#
# Configured with the GATEKEEPER_* variables of agent_mitm_proxy.gatekeeper and
# agent_mitm_proxy.mcp_server; the required ones must be set. Without GATEKEEPER_KEY_FILE, they
# come from what the `gatekeeper` command set up (`gatekeeper env`), and when nothing is set up, it
# says so and does nothing, so it can run on every start of a proxy that doesn't use it. Also:
#   AGENT_MITM_PROXY_PYTHON  a Python with agent-mitm-proxy installed [python3]
#   GATEKEEPER_LOG           its output [./data/gatekeeper.log]
set -Eeuo pipefail
umask 077

PYTHON="${AGENT_MITM_PROXY_PYTHON:-python3}"

if [[ -z "${GATEKEEPER_KEY_FILE:-}" ]]; then
  if ! exports=$("${PYTHON}" -m agent_mitm_proxy.gatekeeper_cli env 2>&1); then
    echo "gatekeeper not started: ${exports#gatekeeper: }" >&2
    exit 0
  fi
  eval "${exports}"
fi

PORT="${GATEKEEPER_PORT:-8900}"
LOG="${GATEKEEPER_LOG:-data/gatekeeper.log}"
export GATEKEEPER_PORT="${PORT}"

listening() { (echo >/dev/tcp/127.0.0.1/"${PORT}") 2>/dev/null; }

if listening; then
  echo "gatekeeper already listening on ${PORT}" >&2
  exit 0
fi
for var in GATEKEEPER_KEY_FILE GATEKEEPER_TAG_FILE; do
  [[ -r "${!var:-}" ]] || { echo "gatekeeper: ${var} is not a readable file; not starting" >&2; exit 1; }
done
mkdir -p -- "$(dirname -- "${LOG}")"

# setsid + nohup: keep running after a lifecycle command returns.
PYTHONDONTWRITEBYTECODE=1 \
  setsid nohup "${PYTHON}" -m agent_mitm_proxy.mcp_server >>"${LOG}" 2>&1 </dev/null &
pid=$!

for _ in {1..100}; do
  if listening; then
    echo "gatekeeper listening on 0.0.0.0:${PORT}/mcp (log: ${LOG})" >&2
    exit 0
  fi
  kill -0 "${pid}" 2>/dev/null || break   # exited, e.g. missing configuration
  sleep 0.1
done
echo "gatekeeper did not start; see ${LOG}" >&2
exit 1

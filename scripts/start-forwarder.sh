#!/usr/bin/env bash
# Start the internal-service forwarder in the background, if there are services.
# Does nothing if it already runs, so it can run on every container start.
#
# Configured with the FORWARDER_* variables of agent_mitm_proxy.forwarder. Also:
#   AGENT_MITM_PROXY_PYTHON  a Python with agent-mitm-proxy installed [python3]
#   FORWARDER_LOG            request metadata [./data/services.jsonl]
#   FORWARDER_OUTPUT         its output [./data/forwarder.log]
#   FORWARDER_PIDFILE        [./data/forwarder.pid]
set -Eeuo pipefail
umask 077

PYTHON="${AGENT_MITM_PROXY_PYTHON:-python3}"
export FORWARDER_SERVICES="${FORWARDER_SERVICES:-services.json}"
export FORWARDER_LOG="${FORWARDER_LOG:-data/services.jsonl}"   # request metadata
OUTPUT="${FORWARDER_OUTPUT:-data/forwarder.log}"
PIDFILE="${FORWARDER_PIDFILE:-data/forwarder.pid}"

if [[ ! -r "${FORWARDER_SERVICES}" ]]; then
  echo "forwarder: no ${FORWARDER_SERVICES} (see services.example.json); not starting" >&2
  exit 0
fi
mkdir -p -- "$(dirname -- "${OUTPUT}")" "$(dirname -- "${PIDFILE}")" "$(dirname -- "${FORWARDER_LOG}")"

# No pgrep in slim images: track the process with a PID file.
running() {
  local c="/proc/$(cat "${PIDFILE}" 2>/dev/null)/cmdline"
  [[ -r "$c" ]] && tr "\0" " " < "$c" | grep -q agent_mitm_proxy.forwarder
}
if running; then
  echo "forwarder already running" >&2
  exit 0
fi

# Only output from this start counts: the log keeps earlier runs.
offset=$(( $(stat -c %s -- "${OUTPUT}" 2>/dev/null || echo 0) + 1 ))
PYTHONDONTWRITEBYTECODE=1 \
  setsid nohup "${PYTHON}" -m agent_mitm_proxy.forwarder >>"${OUTPUT}" 2>&1 </dev/null &
echo $! > "${PIDFILE}"

# The forwarder prints "forwarder: service ..." once every port listens.
for _ in {1..100}; do
  if ! running; then
    break
  fi
  if [[ "$(tail -c "+${offset}" -- "${OUTPUT}")" == *"forwarder: service"* ]]; then
    echo "forwarder running (log: ${OUTPUT})" >&2
    exit 0
  fi
  sleep 0.1
done
echo "forwarder did not start; see ${OUTPUT}" >&2
exit 1

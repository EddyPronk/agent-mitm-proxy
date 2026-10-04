#!/usr/bin/env bash
# Start proxy.py with TLS interception and the agent_mitm_proxy plugins, in the background.
# Does nothing if something already listens on the port, so it can run on every container start.
#
#   AGENT_MITM_PROXY_PYTHON=/opt/agent-mitm-proxy/bin/python scripts/start-proxy.sh
#
# Variables (defaults in brackets):
#   AGENT_MITM_PROXY_PYTHON      a Python with agent-mitm-proxy installed [python3]
#   AGENT_MITM_PROXY_PORT        port, on all interfaces [8899]
#   AGENT_MITM_PROXY_DATA        private data: CA keys, per-host certificates, logs [./data]
#   AGENT_MITM_PROXY_CA_PUBLISH  a directory to copy the public CA certificate to, for clients [none]
#   AGENT_MITM_PROXY_CA_BUNDLE   CAs that verify the real upstream servers
#                                [/etc/ssl/certs/ca-certificates.crt]
#   AGENT_MITM_PROXY_ALLOWLIST   the allowlist [./allowlist.txt]
#   AGENT_MITM_PROXY_DENIED_LOG, AGENT_MITM_PROXY_TRAFFIC_LOG  [in the data directory]
set -Eeuo pipefail
umask 077

PYTHON="${AGENT_MITM_PROXY_PYTHON:-python3}"
PORT="${AGENT_MITM_PROXY_PORT:-8899}"
DATA_DIR="$(realpath -m -- "${AGENT_MITM_PROXY_DATA:-data}")"
CA_PUBLISH_DIR="${AGENT_MITM_PROXY_CA_PUBLISH:-}"
CA_BUNDLE="${AGENT_MITM_PROXY_CA_BUNDLE:-/etc/ssl/certs/ca-certificates.crt}"
export AGENT_MITM_PROXY_ALLOWLIST="$(realpath -m -- "${AGENT_MITM_PROXY_ALLOWLIST:-allowlist.txt}")"
export AGENT_MITM_PROXY_DENIED_LOG="${AGENT_MITM_PROXY_DENIED_LOG:-${DATA_DIR}/denied.jsonl}"
export AGENT_MITM_PROXY_TRAFFIC_LOG="${AGENT_MITM_PROXY_TRAFFIC_LOG:-${DATA_DIR}/decrypted-traffic.jsonl}"

CA_KEY="${DATA_DIR}/ca-key.pem"
CA_CERT="${DATA_DIR}/ca-cert.pem"
CA_SIGNING_KEY="${DATA_DIR}/ca-signing-key.pem"
PROXY_LOG="${DATA_DIR}/proxy.log"

listening() { (echo >/dev/tcp/127.0.0.1/"${PORT}") 2>/dev/null; }

mkdir -p -- "${DATA_DIR}" "${DATA_DIR}/certs"

if [[ ! -s "${CA_KEY}" || ! -s "${CA_SIGNING_KEY}" ]]; then
  echo "Generating proxy CA keys in ${DATA_DIR}" >&2
  for key in "${CA_KEY}" "${CA_SIGNING_KEY}"; do
    "${PYTHON}" -m proxy.common.pki gen_private_key --private-key-path "${key}"
    "${PYTHON}" -m proxy.common.pki remove_passphrase --private-key-path "${key}"
  done
  chmod 600 -- "${CA_KEY}" "${CA_SIGNING_KEY}"
fi

# proxy.py's gen_public_key makes a certificate without basicConstraints
# CA:TRUE, which OpenSSL 3 (curl, Node) rejects as "invalid CA certificate".
# Create the CA certificate ourselves; regenerate one that lacks CA:TRUE.
if ! openssl x509 -in "${CA_CERT}" -noout -ext basicConstraints 2>/dev/null | grep -q 'CA:TRUE'; then
  echo "Creating CA certificate ${CA_CERT}" >&2
  openssl req -x509 -new -key "${CA_KEY}" -sha256 -days 365 \
    -subj "/CN=agent-mitm-proxy CA" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -out "${CA_CERT}"
  rm -f -- "${DATA_DIR}"/certs/*   # per-host certificates issued by the old CA
fi

if [[ -n "${CA_PUBLISH_DIR}" ]]; then
  install -m 644 -- "${CA_CERT}" "${CA_PUBLISH_DIR}/ca-cert.pem"   # the public part only
fi

if listening; then
  echo "proxy already listening on ${PORT}" >&2
  exit 0
fi

# setsid + nohup: keep running after a lifecycle command returns.
# Plugin order matters: the allowlist refuses before anything is logged.
setsid nohup "${PYTHON}" -m proxy \
    --hostname 0.0.0.0 \
    --port "${PORT}" \
    --ca-key-file "${CA_KEY}" \
    --ca-cert-file "${CA_CERT}" \
    --ca-signing-key-file "${CA_SIGNING_KEY}" \
    --ca-cert-dir "${DATA_DIR}/certs" \
    --ca-file "${CA_BUNDLE}" \
    --plugins agent_mitm_proxy.plugins.AllowlistPlugin,agent_mitm_proxy.plugins.TrafficLogPlugin \
    >>"${PROXY_LOG}" 2>&1 </dev/null &

for _ in {1..50}; do
  if listening; then
    echo "proxy listening on 0.0.0.0:${PORT} (log: ${PROXY_LOG}, traffic: ${AGENT_MITM_PROXY_TRAFFIC_LOG})" >&2
    exit 0
  fi
  sleep 0.1
done
echo "proxy did not start; see ${PROXY_LOG}" >&2
exit 1

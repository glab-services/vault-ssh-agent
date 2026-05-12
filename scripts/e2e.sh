#!/usr/bin/env bash
set -euo pipefail

# E2E smoke test for vault-ssh-agent against a reachable Vault instance.
#
# Prereqs:
# - vault CLI installed and authenticated (VAULT_ADDR + VAULT_TOKEN)
# - ssh-add / ssh-keygen installed
#
# This script:
# - enables transit and kv-v2 (best-effort)
# - writes a local config file under .dev/
# - starts the agent
# - imports a generated ed25519 key via ssh-add (which triggers Transit BYOK import)
# - verifies ssh-add -L returns the key
# - removes key from agent (disables in keystore)

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEV_DIR="${ROOT_DIR}/.dev"
SOCK_PATH="${DEV_DIR}/agent.sock"
CFG_PATH="${DEV_DIR}/config.yaml"
KEYSTORE_PREFIX="${KEYSTORE_PREFIX:-vault-ssh-agent}"
KEYSTORE_MOUNT="${KEYSTORE_MOUNT:-kv}"
KEYSTORE_VERSION="${KEYSTORE_VERSION:-2}"

require() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "missing required command: $1" >&2
    exit 1
  fi
}

require ssh-add
require ssh-keygen
require grep

mkdir -p "${DEV_DIR}"
chmod 700 "${DEV_DIR}"

if [[ -z "${VAULT_ADDR:-}" || -z "${VAULT_TOKEN:-}" ]]; then
  echo "VAULT_ADDR and VAULT_TOKEN are required" >&2
  exit 1
fi

echo "[1/6] Checking vault CLI (optional)"
if command -v vault >/dev/null 2>&1; then
  echo "vault CLI found; enabling secrets engines (best-effort)"
  vault secrets enable transit >/dev/null 2>&1 || true
  vault secrets enable -path=kv kv-v2 >/dev/null 2>&1 || true
else
  echo "vault CLI not found; skipping secrets engine enablement"
fi

echo "[2/6] Writing config to ${CFG_PATH}"
cat > "${CFG_PATH}" <<EOF
vault:
  address: "${VAULT_ADDR}"
  token_source: "env"
  token_env_var: "VAULT_TOKEN"
  transit_mount: "transit"
  key_store:
    mount: "${KEYSTORE_MOUNT}"
    path_prefix: "${KEYSTORE_PREFIX}"
    version: ${KEYSTORE_VERSION}

agent:
  socket_path: "${SOCK_PATH}"
  lock_on_start: false
EOF

echo "[3/6] Starting agent"
export GOCACHE="${GOCACHE:-/tmp/vault-ssh-agent-go-build-cache}"
export GOMODCACHE="${GOMODCACHE:-/tmp/vault-ssh-agent-go-modcache}"

rm -f "${SOCK_PATH}" || true

set +e
AGENT_PID=""
go run "${ROOT_DIR}/cmd/vault-ssh-agent" --config "${CFG_PATH}" start >/tmp/vault-ssh-agent-e2e.log 2>&1 &
AGENT_PID="$!"
set -e

cleanup() {
  if [[ -n "${AGENT_PID}" ]]; then
    kill "${AGENT_PID}" >/dev/null 2>&1 || true
    wait "${AGENT_PID}" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

for i in {1..50}; do
  if [[ -S "${SOCK_PATH}" ]]; then
    break
  fi
  sleep 0.1
done
if [[ ! -S "${SOCK_PATH}" ]]; then
  echo "agent socket not created: ${SOCK_PATH}" >&2
  echo "agent log: /tmp/vault-ssh-agent-e2e.log" >&2
  exit 1
fi

export SSH_AUTH_SOCK="${SOCK_PATH}"

echo "[4/6] Generating temp key and importing via ssh-add"
KEY_DIR="$(mktemp -d)"
chmod 700 "${KEY_DIR}"
KEY_PATH="${KEY_DIR}/id_ed25519"
ssh-keygen -t ed25519 -N "" -f "${KEY_PATH}" -C "e2e-key" >/dev/null

ssh-add -D >/dev/null 2>&1 || true
set +e
ssh-add "${KEY_PATH}" >/dev/null
ADD_RC="$?"
set -e
if [[ "${ADD_RC}" -ne 0 ]]; then
  echo "ssh-add import failed; this typically means Vault Transit BYOK import is unavailable (Vault OSS) or transit is not enabled at the configured mount." >&2
  echo "See /tmp/vault-ssh-agent-e2e.log for the agent-side error." >&2
  exit 1
fi

echo "[5/6] Validating ssh-add -L returns a key"
OUT="$(ssh-add -L)"
if ! echo "${OUT}" | grep -q "ssh-ed25519 "; then
  echo "expected ssh-ed25519 in ssh-add -L output" >&2
  echo "${OUT}" >&2
  exit 1
fi

echo "[6/6] Removing key from agent (disables in Vault keystore) and validating"
ssh-add -d "${KEY_PATH}.pub" >/dev/null
OUT2="$(ssh-add -L || true)"
if echo "${OUT2}" | grep -q "ssh-ed25519 "; then
  echo "expected key to be removed from ssh-add -L output" >&2
  echo "${OUT2}" >&2
  exit 1
fi

echo "ok"

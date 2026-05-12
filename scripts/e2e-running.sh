#!/usr/bin/env bash
set -euo pipefail

# E2E smoke test against an already-running vault-ssh-agent.
#
# Prereqs:
# - vault-ssh-agent is already running and listening on SSH_AUTH_SOCK
# - ssh-add / ssh-keygen installed
#
# Usage:
#   export SSH_AUTH_SOCK=/path/to/agent.sock
#   bash scripts/e2e-running.sh

require() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "missing required command: $1" >&2
    exit 1
  fi
}

require ssh-add
require ssh-keygen
require grep

if [[ -z "${SSH_AUTH_SOCK:-}" ]]; then
  echo "SSH_AUTH_SOCK is required (point it at the running vault-ssh-agent socket)" >&2
  exit 1
fi
if [[ ! -S "${SSH_AUTH_SOCK}" ]]; then
  echo "SSH_AUTH_SOCK is not a unix socket: ${SSH_AUTH_SOCK}" >&2
  exit 1
fi

echo "[1/4] Generating temp key"
KEY_DIR="$(mktemp -d)"
chmod 700 "${KEY_DIR}"
KEY_PATH="${KEY_DIR}/id_ed25519"
ssh-keygen -t ed25519 -N "" -f "${KEY_PATH}" -C "e2e-running-key" >/dev/null

echo "[2/4] Importing key via ssh-add"
ssh-add -D >/dev/null 2>&1 || true
ssh-add "${KEY_PATH}" >/dev/null

echo "[3/4] Validating key is listed"
OUT="$(ssh-add -L)"
if ! echo "${OUT}" | grep -q "ssh-ed25519 "; then
  echo "expected ssh-ed25519 in ssh-add -L output" >&2
  echo "${OUT}" >&2
  exit 1
fi

echo "[4/4] Removing key and validating it's gone"
ssh-add -d "${KEY_PATH}.pub" >/dev/null
OUT2="$(ssh-add -L || true)"
if echo "${OUT2}" | grep -q "ssh-ed25519 "; then
  echo "expected key to be removed from ssh-add -L output" >&2
  echo "${OUT2}" >&2
  exit 1
fi

echo "ok"

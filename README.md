# vault-ssh-agent

`vault-ssh-agent` is an **ssh-agent compatible** Unix-socket agent that keeps SSH private key material in **HashiCorp Vault Transit** (no local private key files) and performs SSH signatures by calling Vault’s Transit signing APIs.

It also includes a small CLI to manage key metadata stored in **Vault KV** (“keystore”).

## What you get

- `ssh-agent` protocol over `SSH_AUTH_SOCK` (Unix socket)
- `ssh-add -L` works (agent lists enabled identities)
- `ssh` signing works (agent signs via Vault Transit)
- `ssh-add <privatekey>` imports a key into Transit (BYOK import) and registers it in the keystore
- `ssh-add -d <pubkey>` disables the identity in the keystore (default) or deletes Transit key material (optional)
- CLI commands for key management (`key-create`, `key-list`, `key-show`, `key-enable/disable`, `key-remove`)

## How it works (high level)

```text
OpenSSH client
  -> SSH_AUTH_SOCK (unix socket)
    -> ssh-agent-service (this repo)
        - REQUEST_IDENTITIES: reads enabled keys from Vault KV, exports public keys from Transit
        - SIGN_REQUEST: calls Vault Transit sign endpoint
        - ADD_IDENTITY: imports a private key into Transit, writes metadata to KV
        - REMOVE_IDENTITY: disables (or optionally deletes) the key
  -> Vault
       - Transit: stores key material + performs signing
       - KV: stores key metadata (name, enabled/disabled, fingerprint, public key, mapping to transit key)
```

## Prerequisites

- Go (see `go.mod`)
- OpenSSH tools: `ssh`, `ssh-add`, `ssh-keygen`
- A reachable Vault with:
  - Transit enabled (or permissions to enable it)
  - KV enabled (KV v2 recommended) for keystore metadata
- Vault auth via one of:
  - `VAULT_TOKEN` (env), or
  - token file, or
  - token command (see config below)

Tip: if your environment has restricted filesystem permissions, use writable Go caches:

```bash
export GOCACHE=/tmp/vault-ssh-agent-go-build-cache
export GOMODCACHE=/tmp/vault-ssh-agent-go-modcache
```

## Quickstart

1) Create a config file (example: `.dev/config.yaml`):

```yaml
vault:
  address: "https://vault.example.com"
  token_source: "env"         # env | file | command
  token_env_var: "VAULT_TOKEN"
  transit_mount: "transit"

  key_store:
    mount: "kv"               # your KV mount path (often "kv" or "secret")
    path_prefix: "vault-ssh-agent"
    version: 2                # 2 recommended

  allow_legacy_ssh_rsa: false
  delete_transit_on_remove: false

agent:
  socket_path: "/home/you/.vault-ssh-agent/agent.sock"
  lock_on_start: false
```

2) Start the agent:

```bash
export VAULT_ADDR="https://vault.example.com"
export VAULT_TOKEN="hvs...."

go run -buildvcs=false ./cmd/ssh-agent-service --config .dev/config.yaml start
```

3) Point OpenSSH at it and list identities:

```bash
export SSH_AUTH_SOCK="$HOME/.vault-ssh-agent/agent.sock"
ssh-add -L
```

4) Import a key into Vault Transit using `ssh-add` (BYOK import):

```bash
ssh-add ~/.ssh/id_ed25519
ssh-add -L
ssh-add -d ~/.ssh/id_ed25519.pub
```

Notes:
- `ssh-add` must be able to read/decrypt the private key (the agent receives a decrypted private key object).
- Transit import must be permitted for the token you use.

## Key management CLI

Build/run directly:

```bash
go run -buildvcs=false ./cmd/ssh-agent-cli --config .dev/config.yaml key-list
```

Common commands:

```bash
# Create a new Transit key and register it in the keystore
go run -buildvcs=false ./cmd/ssh-agent-cli --config .dev/config.yaml \
  key-create ssh-prod-ed25519 --type ed25519 --comment "prod key"

# Show a key (prints metadata + an authorized_keys line)
go run -buildvcs=false ./cmd/ssh-agent-cli --config .dev/config.yaml key-show ssh-prod-ed25519

# Disable / enable (affects what the agent advertises)
go run -buildvcs=false ./cmd/ssh-agent-cli --config .dev/config.yaml key-disable ssh-prod-ed25519
go run -buildvcs=false ./cmd/ssh-agent-cli --config .dev/config.yaml key-enable  ssh-prod-ed25519

# Remove metadata only; optionally delete the Transit key too (dangerous)
go run -buildvcs=false ./cmd/ssh-agent-cli --config .dev/config.yaml key-remove ssh-prod-ed25519
go run -buildvcs=false ./cmd/ssh-agent-cli --config .dev/config.yaml key-remove ssh-prod-ed25519 --delete-transit
```

## Token sources (config)

`vault.token_source` supports:

- `env` (default): read token from `vault.token_env_var` (defaults to `VAULT_TOKEN`)
- `file`: read token from `vault.token_file`
- `command`: run `vault.token_command` and use stdout as the token

## Safety / security notes

- The agent creates the socket directory with `0700` and the socket file with `0600`.
- Default `ssh-add -d` behavior is **disable** in the keystore (stop advertising). It does **not** delete Transit key material.
- If you set `vault.delete_transit_on_remove: true`, remove becomes destructive (Transit key deletion).
- Legacy `ssh-rsa` (RSA-SHA1) signing is refused by default. Set `vault.allow_legacy_ssh_rsa: true` only if you understand the risks (and even then, Vault Transit does not produce RSA-SHA1 signatures).

## Build binaries

```bash
go build -buildvcs=false -o ./bin/ssh-agent-service ./cmd/ssh-agent-service
go build -buildvcs=false -o ./bin/ssh-agent-cli     ./cmd/ssh-agent-cli
```

## E2E scripts

There are smoke-test scripts that can provision engines (best-effort), start the agent, import a temp key via `ssh-add`, validate listing, then remove it:

```bash
export VAULT_ADDR=...
export VAULT_TOKEN=...
bash scripts/e2e.sh
```

If your KV mount isn’t `kv` or you’re using KV v1, override:

```bash
export KEYSTORE_MOUNT=secret
export KEYSTORE_VERSION=2
export KEYSTORE_PREFIX=vault-ssh-agent
bash scripts/e2e.sh
```

If you already started the service yourself:

```bash
export SSH_AUTH_SOCK=/path/to/agent.sock
bash scripts/e2e-running.sh
```

## More examples

See:
- `EXAMPLE.md` for copy/paste commands
- `SUMMARY.md` for the current state
- `PLAN.md` for the longer-term roadmap/notes


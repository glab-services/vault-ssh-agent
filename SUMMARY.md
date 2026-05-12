# vault-ssh-agent (Current State)

This repo implements an `ssh-agent`-compatible Unix socket that keeps SSH private keys in Vault Transit (no local private key files) and signs via Transit. Key inventory and metadata live in Vault KV ("keystore").

## Prereqs

- Go installed
- `vault` CLI installed
- `ssh-add` / `ssh-keygen` installed
- A reachable Vault instance with:
  - Transit enabled (or permissions to enable it)
  - KV enabled (v2 recommended) for metadata
- Environment:
  - `VAULT_ADDR`
  - `VAULT_TOKEN`

Note: in this repo, Go builds/tests should use writable caches:
`GOCACHE=/tmp/vault-ssh-agent-go-build-cache` and `GOMODCACHE=/tmp/vault-ssh-agent-go-modcache`.

## Local Config Example

Create a config file (example path: `.dev/config.yaml`):

```yaml
vault:
  address: "https://vault.example.com"
  token_source: "env" # env | file | command
  token_env_var: "VAULT_TOKEN"
  transit_mount: "transit"
  allow_legacy_ssh_rsa: false
  delete_transit_on_remove: false

  key_store:
    mount: "kv"                 # your KV mount path (often "kv" or "secret")
    path_prefix: "vault-ssh-agent"
    version: 2

agent:
  socket_path: "/home/you/.vault-ssh-agent/agent.sock"
  lock_on_start: false
```

## Run Commands

Start the agent:

```bash
export VAULT_ADDR=...
export VAULT_TOKEN=...

export GOCACHE=/tmp/vault-ssh-agent-go-build-cache
export GOMODCACHE=/tmp/vault-ssh-agent-go-modcache

go run ./cmd/vault-ssh-agent --config .dev/config.yaml start
```

Point OpenSSH at it:

```bash
export SSH_AUTH_SOCK="$HOME/.vault-ssh-agent/agent.sock"
ssh-add -L
```

Import a key into Vault Transit via `ssh-add` (agent handles Transit BYOK import):

```bash
ssh-add ~/.ssh/id_ed25519
ssh-add -L
ssh-add -d ~/.ssh/id_ed25519.pub
```

## Key Management CLI

List keys known to the agent (from Vault keystore):

```bash
go run ./cmd/vault-ssh-agent --config .dev/config.yaml key-list
```

Show one key (metadata + OpenSSH public key line):

```bash
go run ./cmd/vault-ssh-agent --config .dev/config.yaml key-show <name>
```

Disable/enable:

```bash
go run ./cmd/vault-ssh-agent --config .dev/config.yaml key-disable <name>
go run ./cmd/vault-ssh-agent --config .dev/config.yaml key-enable <name>
```

Remove metadata only (and optionally delete Transit key material):

```bash
go run ./cmd/vault-ssh-agent --config .dev/config.yaml key-remove <name>
go run ./cmd/vault-ssh-agent --config .dev/config.yaml key-remove <name> --delete-transit
```

## E2E Script

There is a smoke test script that provisions Vault engines (best-effort), starts the agent, imports a temp key via `ssh-add`, validates listing, then removes it:

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

If you already started the service yourself, use:

```bash
export SSH_AUTH_SOCK=/path/to/agent.sock
bash scripts/e2e-running.sh
```

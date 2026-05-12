## vault-ssh-agent Examples

This file is a grab-bag of copy/paste examples for running and using `vault-ssh-agent`.

### 1) Minimal Config (Transit + KV v2)

```yaml
vault:
  address: "https://vault.example.com"
  token_source: "env"         # env | file | command
  token_env_var: "VAULT_TOKEN"
  transit_mount: "transit"    # transit mount path

  # Key metadata (enabled/disabled, mapping name -> transit key, stored public key/fingerprint)
  key_store:
    mount: "kv/ssh-agent"     # KV v2 mount path (no trailing slash)
    path_prefix: "vault-ssh-agent"
    version: 2

agent:
  socket_path: "~/.vault-ssh-agent/agent.sock"
  lock_on_start: false
```

### 2) Start The Agent (Info / Debug)

Info (default):

```bash
export VAULT_ADDR="https://vault.example.com"
export VAULT_TOKEN="hvs...."

export GOCACHE=/tmp/vault-ssh-agent-go-build-cache
export GOMODCACHE=/tmp/vault-ssh-agent-go-modcache

go run -buildvcs=false ./cmd/vault-ssh-agent --config .dev/config.yaml start
```

Debug:

```bash
go run -buildvcs=false ./cmd/vault-ssh-agent --debug --config .dev/config.yaml start
```

### 3) Point OpenSSH At The Agent

```bash
export SSH_AUTH_SOCK="$HOME/.vault-ssh-agent/agent.sock"
ssh-add -L
```

### 4) Import A Key Into Vault Transit Using ssh-add (BYOK)

This uses the agent’s `ADD_IDENTITY` path to import the private key into Vault Transit (no local storage by the agent).

```bash
export SSH_AUTH_SOCK="$HOME/.vault-ssh-agent/agent.sock"
ssh-add ~/.ssh/id_ed25519
ssh-add -L
ssh-add -d ~/.ssh/id_ed25519.pub
```

Notes:
- `ssh-add` must be able to read/decrypt the key; the agent only receives a private key object after `ssh-add` decrypted it.
- BYOK import requires Vault Transit wrapping key/import endpoints to exist on your Vault.

### 5) Create Keys In Vault (No Local Key Files)

Create a new Transit key and register it in the keystore:

```bash
go run -buildvcs=false ./cmd/vault-ssh-agent --config .dev/config.yaml \
  key-create ssh-prod-ed25519 --type ed25519 --comment "prod key"
```

List keys known to the agent (from Vault KV keystore):

```bash
go run -buildvcs=false ./cmd/vault-ssh-agent --config .dev/config.yaml key-list
```

Show a key (prints metadata + OpenSSH public key line):

```bash
go run -buildvcs=false ./cmd/vault-ssh-agent --config .dev/config.yaml key-show ssh-prod-ed25519
```

Disable / enable (affects what the agent advertises):

```bash
go run -buildvcs=false ./cmd/vault-ssh-agent --config .dev/config.yaml key-disable ssh-prod-ed25519
go run -buildvcs=false ./cmd/vault-ssh-agent --config .dev/config.yaml key-enable  ssh-prod-ed25519
```

Remove metadata only (and optionally delete Transit key material too):

```bash
go run -buildvcs=false ./cmd/vault-ssh-agent --config .dev/config.yaml key-remove ssh-prod-ed25519
go run -buildvcs=false ./cmd/vault-ssh-agent --config .dev/config.yaml key-remove ssh-prod-ed25519 --delete-transit
```

### 6) Register An Existing Transit Key (Without Creating It)

If the Transit key already exists in Vault and you only want to register it:

```bash
go run -buildvcs=false ./cmd/vault-ssh-agent --config .dev/config.yaml \
  key-add mykey --transit-key ssh-existing-key --transit-mount transit --comment "existing"
```

### 7) KV Mount Variations

If your KV v2 is mounted at `secret/` instead of `kv/ssh-agent/`:

```yaml
vault:
  key_store:
    mount: "secret"
    version: 2
```

If your KV is KV v1 (not recommended here), set:

```yaml
vault:
  key_store:
    version: 1
```

### 8) Remove Semantics (Disable vs Delete)

Default behavior for `ssh-add -d` (agent `REMOVE_IDENTITY`) is:
- disable key in keystore (stops advertising), does not delete Transit key material

If you want remove to also delete the Transit key (dangerous):

```yaml
vault:
  delete_transit_on_remove: true
```

### 9) Legacy RSA (ssh-rsa / SHA-1)

By default, if a client requests RSA signing without RSA-SHA2 flags, the agent refuses.

To allow (dangerous, may still not work with Vault Transit):

```yaml
vault:
  allow_legacy_ssh_rsa: true
```

### 10) E2E Tests

Provisioning + start + import/list/remove (assumes Vault reachable; will enable engines only if `vault` CLI exists):

```bash
export VAULT_ADDR=...
export VAULT_TOKEN=...
export KEYSTORE_MOUNT='kv/ssh-agent'
export KEYSTORE_VERSION=2

bash scripts/e2e.sh
```

If the agent is already running:

```bash
export SSH_AUTH_SOCK=/path/to/agent.sock
bash scripts/e2e-running.sh
```

### 11) Fix “error obtaining VCS status” When Building

If this directory isn’t a git repo (or IDE can’t read it), build with:

```bash
go build -buildvcs=false -o ./bin/vault-ssh-agent ./cmd/vault-ssh-agent
```


````markdown
# PLAN2: Vault-Only SSH Keys (Transit-Backed Agent + Key Management)

## Goal

Replace **all** local SSH private key storage with a Vault-backed backend:

* no local SSH private keys on disk
* no local private key caching
* signing is done by Vault (Transit)
* SSH agent exposes identities via `SSH_AUTH_SOCK`
* provide CLI commands to manage keys stored in Vault (create/list/show/delete)
* future: allow `ssh-add` to add/remove identities by storing/importing keys directly into Vault

## Current Status In This Repo

As of now, the agent server is Transit-backed for signing (no local private keys),
and a small CLI exists to manage keys via a Vault KV-backed keystore plus Transit:

* `key-create` (create transit key + store metadata)
* `key-add` (register an existing transit key)
* `key-enable` / `key-disable`
* `key-list` / `key-show`
* `key-remove` (remove metadata; optional transit deletion)

The agent **does not** yet support `ssh-add` add/remove (agent protocol
`ADD_IDENTITY` / `REMOVE_IDENTITY`) because importing arbitrary SSH private keys
into Transit requires BYOK key import wiring.

## Architecture

```text
OpenSSH client
  -> SSH_AUTH_SOCK (unix socket)
    -> vault-ssh-agent
        - REQUEST_IDENTITIES: read public keys from Vault Transit
        - SIGN_REQUEST: call Vault Transit /sign/<key>
  -> Vault
       - Transit secrets engine stores private key material and performs signing
```

## Config (Transit-Backed Keys)

Example (keys are discovered from Vault `key_store`; `keys:` in config is deprecated):

```yaml
vault:
  address: "https://vault.example.com"
  token_source: "env" # env | file | command
  token_env_var: "VAULT_TOKEN"        # optional
  token_file: "~/.vault-token"        # used when token_source=file
  token_command: "op read op://..."   # used when token_source=command

  key_store:
    mount: "kv"                 # KV mount for key metadata
    path_prefix: "vault-ssh-agent"
    version: 2                  # KV v2 recommended

agent:
  socket_path: "~/.vault-ssh-agent/agent.sock"
  lock_on_start: false

keys:
  - name: "prod-ed25519"
    backend: "transit"
    enabled: true
    transit_mount: "transit"
    transit_key: "ssh-prod-ed25519"

  - name: "prod-rsa"
    backend: "transit"
    enabled: true
    transit_mount: "transit"
    transit_key: "ssh-prod-rsa-3072"
```

## CLI (Key Management)

These commands talk directly to Vault Transit:

```bash
# Create a new transit key (private key stays in Vault)
vault-ssh-agent --config ~/.config/vault-ssh-agent/config.yaml key-create ssh-prod-ed25519 --type ed25519 --comment "prod ed25519"
vault-ssh-agent --config ~/.config/vault-ssh-agent/config.yaml key-create ssh-prod-rsa-3072 --type rsa-3072 --comment "prod rsa 3072"

# List keys known to the agent (from Vault key_store)
vault-ssh-agent --config ~/.config/vault-ssh-agent/config.yaml key-list

# Disable / enable
vault-ssh-agent --config ~/.config/vault-ssh-agent/config.yaml key-disable ssh-prod-ed25519
vault-ssh-agent --config ~/.config/vault-ssh-agent/config.yaml key-enable ssh-prod-ed25519

# Show a key (prints metadata + OpenSSH public key line for authorized_keys)
vault-ssh-agent --config ~/.config/vault-ssh-agent/config.yaml key-show ssh-prod-ed25519

# Remove key metadata; optionally delete the transit key material too
vault-ssh-agent --config ~/.config/vault-ssh-agent/config.yaml key-remove ssh-prod-ed25519
vault-ssh-agent --config ~/.config/vault-ssh-agent/config.yaml key-remove ssh-prod-ed25519 --delete-transit
```

## systemd / systemctl (Later)

Once the Vault-only backend is stable, run it as a user service:

* `systemctl --user enable --now vault-ssh-agent`
* export `SSH_AUTH_SOCK=$HOME/.vault-ssh-agent/agent.sock`

(Unit file is intentionally not included in this plan; add it after the SSH flow
works end-to-end.)

## Milestones

### Milestone A: Transit-Backed Agent (MVP)

* `REQUEST_IDENTITIES` returns Vault Transit public keys.
* `SIGN_REQUEST` signs via Transit:
  - RSA: use `pkcs1v15` and SHA-2 (`rsa-sha2-256` default; `rsa-sha2-512` when requested)
  - Ed25519: sign raw message bytes
* no private keys written locally.

### Milestone B: Key Management CLI

* create/list/show/delete keys in Transit.
* print OpenSSH public key line for `authorized_keys`.

### Milestone C: ssh-add Compatibility (Key Import / Add-Remove)

Goal: allow:

```bash
ssh-add ~/.ssh/id_ed25519
ssh-add -d ~/.ssh/id_ed25519.pub
```

Design sketch:

* implement agent protocol methods:
  - `ADD_IDENTITY`: receive private key material from ssh-add
  - `REMOVE_IDENTITY`: remove the corresponding Vault key or mark disabled
* implement Transit import (BYOK) path:
  - use `/transit/keys/:name/import` for asymmetric keys
  - reject encrypted private keys in v1 unless a passphrase prompt flow is added
* store minimal metadata in Vault (labels, comments) to support list/view.

This milestone is the “hard part”; it should be treated as a spike first.

### Milestone D: Optional SSH Certificates (Vault SSH CA)

If we want short-lived user certs on top of Transit:

* use Vault SSH secrets engine to sign the Transit public key
* do not persist certs to disk; keep in-memory only with expiry refresh
* agent advertises the cert identity instead of raw pubkey

This is optional; raw public key auth works if servers have the public key in `authorized_keys`.

## Acceptance Checks

* `vault-ssh-agent start` creates unix socket with 0600 perms in a 0700 dir.
* `SSH_AUTH_SOCK=... ssh-add -L` shows keys (raw public keys in MVP).
* SSH auth works against a server that has the printed public key in `authorized_keys`.
* no local files containing private keys are created.

````

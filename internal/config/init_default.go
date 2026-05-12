package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// EnsureDefaultConfig writes a default config if the file doesn't exist.
// It returns true if it created the file.
func EnsureDefaultConfig(path string) (bool, error) {
	if strings.TrimSpace(path) == "" {
		return false, errors.New("config: path is required")
	}
	expanded, err := ExpandPath(path)
	if err != nil {
		return false, err
	}
	if _, err := os.Stat(expanded); err == nil {
		return false, nil
	} else if !os.IsNotExist(err) {
		return false, fmt.Errorf("config: stat %q: %w", expanded, err)
	}

	dir := filepath.Dir(expanded)
	dirMode := os.FileMode(0o700)
	if strings.HasPrefix(expanded, "/etc/") {
		// System config dir: should be readable by root, not necessarily private.
		dirMode = 0o755
	}
	if err := os.MkdirAll(dir, dirMode); err != nil {
		return false, fmt.Errorf("config: mkdir %q: %w", dir, err)
	}
	_ = os.Chmod(dir, dirMode)

	addr := strings.TrimSpace(os.Getenv("VAULT_ADDR"))
	if addr == "" {
		addr = "https://vault.example.com"
	}

	// Default socket path:
	// - system config under /etc: use /run (tmpfs) by default
	// - user config: prefer current SSH_AUTH_SOCK, else ~/.vault-ssh-agent/agent.sock
	var sock string
	if strings.HasPrefix(expanded, "/etc/") {
		sock = "/run/vault-ssh-agent/agent.sock"
	} else {
		sock = strings.TrimSpace(os.Getenv("SSH_AUTH_SOCK"))
		if sock == "" {
			// Prefer a stable well-known path (useful for systemd-managed agents).
			// Users can still override by exporting SSH_AUTH_SOCK or editing config.
			sock = "/run/vault-ssh-agent/agent.sock"
		}
	}

	// KV mount/path defaults can be overridden later.
	content := fmt.Sprintf(`vault:
  address: %q
  token_source: "env"
  token_env_var: "VAULT_TOKEN"
  transit_mount: "transit"
  allow_legacy_ssh_rsa: false
  delete_transit_on_remove: false

  key_store:
    mount: "kv/ssh-agent"
    path_prefix: "vault-ssh-agent"
    version: 2

agent:
  socket_path: %q
  lock_on_start: false
`, addr, sock)

	fileMode := os.FileMode(0o600)
	if strings.HasPrefix(expanded, "/etc/") {
		// System config: root-owned but group/world-readable is fine for non-secret defaults.
		// Token is expected to be supplied via env/file/command, not embedded here.
		fileMode = 0o644
	}
	if err := os.WriteFile(expanded, []byte(content), fileMode); err != nil {
		return false, fmt.Errorf("config: write default %q: %w", expanded, err)
	}
	return true, nil
}

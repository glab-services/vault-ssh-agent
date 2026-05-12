package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// DefaultPath is the default config path used by both the service and CLI when
// --config is omitted.
//
// If running as root, prefer a system-wide config under /etc.
func DefaultPath() (string, error) {
	if os.Geteuid() == 0 {
		return "/etc/vault-ssh-agent/config.yaml", nil
	}
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("config: resolve user config dir: %w", err)
	}
	return filepath.Join(dir, "vault-ssh-agent", "config.yaml"), nil
}

// ExpandPath expands "~" and cleans the path.
func ExpandPath(p string) (string, error) {
	p = strings.TrimSpace(p)
	if p == "" {
		return "", nil
	}
	if strings.HasPrefix(p, "~/") || p == "~" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("config: resolve home dir: %w", err)
		}
		if p == "~" {
			p = home
		} else {
			p = filepath.Join(home, strings.TrimPrefix(p, "~/"))
		}
	}
	return filepath.Clean(p), nil
}

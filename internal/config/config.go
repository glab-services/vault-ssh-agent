package config

import (
	"fmt"
)

type Config struct {
	Vault VaultConfig `yaml:"vault"`
	Agent AgentConfig `yaml:"agent"`
	Keys  []KeyConfig `yaml:"keys"`
}

type VaultConfig struct {
	Address               string `yaml:"address"`
	TokenSource           string `yaml:"token_source"` // env | file | command
	TokenEnvVar           string `yaml:"token_env_var"`
	TokenFile             string `yaml:"token_file"`
	TokenCommand          string `yaml:"token_command"`
	TransitMount          string `yaml:"transit_mount"`            // default "transit"
	DeleteTransitOnRemove bool   `yaml:"delete_transit_on_remove"` // dangerous; default false
	AllowLegacySSHRSA     bool   `yaml:"allow_legacy_ssh_rsa"`     // dangerous; default false (RSA-SHA1)

	// KeyStore config controls where this agent stores key metadata in Vault.
	// This is separate from Transit (which stores private key material).
	KeyStore KeyStoreConfig `yaml:"key_store"`
}

type KeyStoreConfig struct {
	Mount      string `yaml:"mount"`       // e.g. "kv"
	PathPrefix string `yaml:"path_prefix"` // e.g. "vault-ssh-agent"
	Version    int    `yaml:"version"`     // 1 or 2; default 2
}

type AgentConfig struct {
	SocketPath      string `yaml:"socket_path"`
	LockOnStart     bool   `yaml:"lock_on_start"`
	AllowForwarding bool   `yaml:"allow_forwarding"`
}

type KeyConfig struct {
	Name    string `yaml:"name"`
	Enabled *bool  `yaml:"enabled"`
	Backend string `yaml:"backend"` // transit (v2)

	// Transit-backed key material (private key never leaves Vault).
	TransitMount string `yaml:"transit_mount"`
	TransitKey   string `yaml:"transit_key"`
}

func (k KeyConfig) EnabledOrDefault() bool {
	if k.Enabled == nil {
		return true
	}
	return *k.Enabled
}

func (c *Config) Validate() error {
	if c.Agent.SocketPath == "" {
		return fmt.Errorf("config: agent.socket_path is required")
	}
	switch c.Vault.TokenSource {
	case "", "env":
		// token_env_var optional, defaults to VAULT_TOKEN
	case "file":
		if c.Vault.TokenFile == "" {
			return fmt.Errorf("config: vault.token_file is required when token_source=file")
		}
	case "command":
		if c.Vault.TokenCommand == "" {
			return fmt.Errorf("config: vault.token_command is required when token_source=command")
		}
	default:
		return fmt.Errorf("config: vault.token_source %q unsupported", c.Vault.TokenSource)
	}
	if c.Vault.KeyStore.Mount == "" {
		c.Vault.KeyStore.Mount = "kv"
	}
	if c.Vault.KeyStore.PathPrefix == "" {
		c.Vault.KeyStore.PathPrefix = "vault-ssh-agent"
	}
	if c.Vault.KeyStore.Version == 0 {
		c.Vault.KeyStore.Version = 2
	}
	if c.Vault.KeyStore.Version != 1 && c.Vault.KeyStore.Version != 2 {
		return fmt.Errorf("config: vault.key_store.version must be 1 or 2")
	}
	if c.Vault.TransitMount == "" {
		c.Vault.TransitMount = "transit"
	}

	if len(c.Keys) == 0 {
		// In v2 mode, keys are stored in Vault key_store and discovered at runtime.
		return nil
	}
	for i, k := range c.Keys {
		if k.Name == "" {
			return fmt.Errorf("config: keys[%d].name is required", i)
		}

		switch k.Backend {
		case "", "transit":
			if k.TransitMount == "" {
				return fmt.Errorf("config: keys[%d].transit_mount is required for backend=transit", i)
			}
			if k.TransitKey == "" {
				return fmt.Errorf("config: keys[%d].transit_key is required for backend=transit", i)
			}
		default:
			return fmt.Errorf("config: keys[%d].backend %q unsupported", i, k.Backend)
		}
	}
	return nil
}

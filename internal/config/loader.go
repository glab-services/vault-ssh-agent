package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

func LoadFromPath(path string) (*Config, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("config: --config is required")
	}
	expanded, err := expandPath(path)
	if err != nil {
		return nil, err
	}
	b, err := os.ReadFile(expanded)
	if err != nil {
		return nil, fmt.Errorf("config: read %q: %w", expanded, err)
	}
	var cfg Config
	if err := yaml.Unmarshal(b, &cfg); err != nil {
		return nil, fmt.Errorf("config: parse yaml %q: %w", expanded, err)
	}

	// Normalize paths early so later code doesn't need to care about "~".
	cfg.Agent.SocketPath, err = expandPath(cfg.Agent.SocketPath)
	if err != nil {
		return nil, err
	}
	cfg.Vault.TokenFile, err = expandPath(cfg.Vault.TokenFile)
	if err != nil {
		return nil, err
	}

	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func expandPath(p string) (string, error) {
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

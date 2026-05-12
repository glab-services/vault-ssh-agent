package vault

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

type TokenSource string

const (
	TokenSourceEnv     TokenSource = "env"
	TokenSourceFile    TokenSource = "file"
	TokenSourceCommand TokenSource = "command"
)

type LoadTokenOptions struct {
	Source   TokenSource
	EnvVar   string
	FilePath string
	Command  string
}

func LoadToken(ctx context.Context, opts LoadTokenOptions) (string, error) {
	src := opts.Source
	if src == "" {
		src = TokenSourceEnv
	}
	switch src {
	case TokenSourceEnv:
		envVar := strings.TrimSpace(opts.EnvVar)
		if envVar == "" {
			envVar = "VAULT_TOKEN"
		}
		tok := strings.TrimSpace(os.Getenv(envVar))
		if tok == "" {
			return "", fmt.Errorf("vault: %s is empty", envVar)
		}
		return tok, nil
	case TokenSourceFile:
		if strings.TrimSpace(opts.FilePath) == "" {
			return "", errors.New("vault: token file path is required")
		}
		b, err := os.ReadFile(opts.FilePath)
		if err != nil {
			return "", fmt.Errorf("vault: read token file %q: %w", opts.FilePath, err)
		}
		tok := strings.TrimSpace(string(b))
		if tok == "" {
			return "", fmt.Errorf("vault: token file %q is empty", opts.FilePath)
		}
		return tok, nil
	case TokenSourceCommand:
		if strings.TrimSpace(opts.Command) == "" {
			return "", errors.New("vault: token command is required")
		}
		// Keep it simple (MVP): shell out via `sh -c ...`.
		cmd := exec.CommandContext(ctx, "sh", "-c", opts.Command)
		var stdout, stderr bytes.Buffer
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr
		if err := cmd.Run(); err != nil {
			msg := strings.TrimSpace(stderr.String())
			if msg == "" {
				msg = "command failed"
			}
			return "", fmt.Errorf("vault: token command failed: %s: %w", msg, err)
		}
		tok := strings.TrimSpace(stdout.String())
		if tok == "" {
			return "", fmt.Errorf("vault: token command produced empty output")
		}
		return tok, nil
	default:
		return "", fmt.Errorf("vault: unsupported token_source %q", opts.Source)
	}
}

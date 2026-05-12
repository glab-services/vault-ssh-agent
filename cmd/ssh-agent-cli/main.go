package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/example/vault-ssh-agent/internal/config"
	"github.com/example/vault-ssh-agent/internal/log"
	"github.com/example/vault-ssh-agent/internal/vault"
	"golang.org/x/crypto/ssh"
)

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	ctx := context.Background()

	fs := flag.NewFlagSet("ssh-agent-cli", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	var cfgPath string
	var debug bool
	fs.StringVar(&cfgPath, "config", "", "Path to config YAML")
	fs.BoolVar(&debug, "debug", false, "Enable debug logging")

	if err := fs.Parse(args); err != nil {
		return 2
	}

	sub := fs.Arg(0)
	if strings.TrimSpace(sub) == "" {
		usage(os.Stderr)
		return 2
	}

	logger := log.New(debug)

	if strings.TrimSpace(cfgPath) == "" {
		p, err := config.DefaultPath()
		if err != nil {
			logger.Error("resolve default config path failed", "err", err)
			return 1
		}
		cfgPath = p
	}
	if _, err := config.EnsureDefaultConfig(cfgPath); err != nil {
		logger.Error("ensure default config failed", "err", err)
		return 1
	}

	cfg, err := config.LoadFromPath(cfgPath)
	if err != nil {
		logger.Error("load config failed", "err", err)
		return 1
	}

	switch sub {
	case "list":
		// Deprecated: config-managed keys list. Kept for debugging only.
		for _, k := range cfg.Keys {
			fmt.Printf("%s\t%s\t%s/%s\n", k.Name, k.Backend, k.TransitMount, k.TransitKey)
		}
		return 0
	case "refresh":
		// Transit-backed keys have no local cert cache. Keep the command for UX.
		logger.Info("refresh is a no-op for transit-backed keys")
		return 0
	case "key-create", "key-add", "key-enable", "key-disable", "key-list", "key-show", "key-remove":
		return runKeyCmd(ctx, logger, cfg, sub, fs.Args()[1:])
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %q\n", sub)
		usage(os.Stderr)
		return 2
	}
}

func usage(w *os.File) {
	fmt.Fprintln(w, "usage:")
	fmt.Fprintln(w, "  ssh-agent-cli [--config path/to/config.yaml] list")
	fmt.Fprintln(w, "  ssh-agent-cli [--config path/to/config.yaml] refresh")
	fmt.Fprintln(w, "  ssh-agent-cli [--config path/to/config.yaml] key-create <name> [--type ed25519|rsa-2048|rsa-3072|rsa-4096] [--transit-mount transit] [--comment text]")
	fmt.Fprintln(w, "  ssh-agent-cli [--config path/to/config.yaml] key-add <name> --transit-key <key> [--transit-mount transit] [--comment text]")
	fmt.Fprintln(w, "  ssh-agent-cli [--config path/to/config.yaml] key-enable <name>")
	fmt.Fprintln(w, "  ssh-agent-cli [--config path/to/config.yaml] key-disable <name>")
	fmt.Fprintln(w, "  ssh-agent-cli [--config path/to/config.yaml] key-list")
	fmt.Fprintln(w, "  ssh-agent-cli [--config path/to/config.yaml] key-show <name>")
	fmt.Fprintln(w, "  ssh-agent-cli [--config path/to/config.yaml] key-remove <name> [--delete-transit]")
}

func runKeyCmd(ctx context.Context, logger *slog.Logger, cfg *config.Config, sub string, args []string) int {
	fs := flag.NewFlagSet(sub, flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	var transitMount string
	var transitKey string
	var keyType string
	var comment string
	var deleteTransit bool
	fs.StringVar(&transitMount, "transit-mount", cfg.Vault.TransitMount, "Transit mount path")
	fs.StringVar(&keyType, "type", "ed25519", "Transit key type (ed25519|rsa-2048|rsa-3072|rsa-4096)")
	fs.StringVar(&transitKey, "transit-key", "", "Transit key name (for key-add)")
	fs.StringVar(&comment, "comment", "", "Human-friendly comment (stored in Vault)")
	fs.BoolVar(&deleteTransit, "delete-transit", false, "Also delete the transit key material (dangerous)")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	token, err := vault.LoadToken(ctx, vault.LoadTokenOptions{
		Source:   vault.TokenSource(cfg.Vault.TokenSource),
		EnvVar:   cfg.Vault.TokenEnvVar,
		FilePath: cfg.Vault.TokenFile,
		Command:  cfg.Vault.TokenCommand,
	})
	if err != nil {
		logger.Error("load vault token failed", "err", err)
		return 1
	}
	vc, err := vault.NewClient(vault.NewClientOptions{Address: cfg.Vault.Address, Token: token})
	if err != nil {
		logger.Error("init vault client failed", "err", err)
		return 1
	}
	tm := vault.NewTransitManager(vc.API())
	ks, err := vault.NewKeyStore(vc.API(), vault.NewKeyStoreOptions{
		Mount:      cfg.Vault.KeyStore.Mount,
		PathPrefix: cfg.Vault.KeyStore.PathPrefix,
		Version:    cfg.Vault.KeyStore.Version,
	})
	if err != nil {
		logger.Error("init keystore failed", "err", err)
		return 1
	}

	switch sub {
	case "key-create":
		name := fs.Arg(0)
		if strings.TrimSpace(name) == "" {
			logger.Error("name is required")
			return 2
		}
		if err := tm.CreateKey(ctx, vault.TransitCreateKeyOptions{
			Mount: transitMount,
			Name:  name,
			Type:  vault.TransitKeyType(keyType),
		}); err != nil {
			logger.Error("create key failed", "err", err)
			return 1
		}
		if err := ks.Put(ctx, vault.KeyEntry{
			Name:         name,
			Enabled:      true,
			Comment:      comment,
			TransitMount: transitMount,
			TransitKey:   name,
		}); err != nil {
			logger.Error("store key metadata failed", "err", err)
			return 1
		}
		return 0
	case "key-add":
		name := fs.Arg(0)
		if strings.TrimSpace(name) == "" {
			logger.Error("name is required")
			return 2
		}
		if strings.TrimSpace(transitKey) == "" {
			logger.Error("--transit-key is required")
			return 2
		}
		if err := ks.Put(ctx, vault.KeyEntry{
			Name:         name,
			Enabled:      true,
			Comment:      comment,
			TransitMount: transitMount,
			TransitKey:   transitKey,
		}); err != nil {
			logger.Error("store key metadata failed", "err", err)
			return 1
		}
		return 0
	case "key-enable", "key-disable":
		name := fs.Arg(0)
		if strings.TrimSpace(name) == "" {
			logger.Error("name is required")
			return 2
		}
		e, ok, err := ks.Get(ctx, name)
		if err != nil {
			logger.Error("load key metadata failed", "err", err)
			return 1
		}
		if !ok {
			logger.Error("key not found in keystore", "name", name)
			return 1
		}
		e.Enabled = sub == "key-enable"
		if err := ks.Put(ctx, *e); err != nil {
			logger.Error("update key metadata failed", "err", err)
			return 1
		}
		return 0
	case "key-list":
		names, err := ks.ListNames(ctx)
		if err != nil {
			logger.Error("list keys failed", "err", err)
			return 1
		}
		for _, name := range names {
			e, ok, err := ks.Get(ctx, name)
			if err != nil || !ok {
				continue
			}
			state := "disabled"
			if e.Enabled {
				state = "enabled"
			}
			fmt.Printf("%s\t%s\t%s/%s\t%s\n", name, state, e.TransitMount, e.TransitKey, e.Comment)
		}
		return 0
	case "key-show":
		name := fs.Arg(0)
		if strings.TrimSpace(name) == "" {
			logger.Error("name is required")
			return 2
		}
		e, ok, err := ks.Get(ctx, name)
		if err != nil {
			logger.Error("load key metadata failed", "err", err)
			return 1
		}
		if !ok {
			logger.Error("key not found in keystore", "name", name)
			return 1
		}
		pub, _, err := tm.ExportPublicKey(ctx, e.TransitMount, e.TransitKey)
		if err != nil {
			logger.Error("export public key failed", "err", err)
			return 1
		}
		fmt.Printf("name: %s\n", e.Name)
		fmt.Printf("enabled: %v\n", e.Enabled)
		fmt.Printf("transit: %s/%s\n", e.TransitMount, e.TransitKey)
		if strings.TrimSpace(e.Comment) != "" {
			fmt.Printf("comment: %s\n", e.Comment)
		}
		if strings.TrimSpace(e.Fingerprint) != "" {
			fmt.Printf("fingerprint: %s\n", e.Fingerprint)
		}
		if strings.TrimSpace(e.KeyType) != "" {
			fmt.Printf("key_type: %s\n", e.KeyType)
		}
		line := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub)))
		fmt.Println(line)
		return 0
	case "key-remove":
		name := fs.Arg(0)
		if strings.TrimSpace(name) == "" {
			logger.Error("name is required")
			return 2
		}
		e, ok, err := ks.Get(ctx, name)
		if err != nil {
			logger.Error("load key metadata failed", "err", err)
			return 1
		}
		if ok && deleteTransit {
			_ = tm.AllowDeletion(ctx, e.TransitMount, e.TransitKey)
			if err := tm.DeleteKey(ctx, e.TransitMount, e.TransitKey); err != nil {
				logger.Error("delete transit key failed", "err", err)
				return 1
			}
		}
		if err := ks.Delete(ctx, name); err != nil {
			logger.Error("delete key metadata failed", "err", err)
			return 1
		}
		return 0
	default:
		logger.Error("unknown key subcommand", "cmd", sub)
		return 2
	}
}

package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/example/vault-ssh-agent/internal/agentd"
	"github.com/example/vault-ssh-agent/internal/config"
	"github.com/example/vault-ssh-agent/internal/log"
)

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	ctx := context.Background()

	fs := flag.NewFlagSet("ssh-agent-service", flag.ContinueOnError)
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
	if sub != "start" {
		fmt.Fprintf(os.Stderr, "unknown command: %q\n", sub)
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

	ctx, cancel := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer cancel()

	d, err := agentd.New(logger, cfg)
	if err != nil {
		logger.Error("init daemon failed", "err", err)
		return 1
	}
	if err := d.InitVault(ctx); err != nil {
		logger.Error("init vault failed", "err", err)
		return 1
	}
	if err := d.Serve(ctx); err != nil {
		logger.Error("serve failed", "err", err)
		return 1
	}
	return 0
}

func usage(w *os.File) {
	fmt.Fprintln(w, "usage:")
	fmt.Fprintln(w, "  ssh-agent-service [--config path/to/config.yaml] start")
}

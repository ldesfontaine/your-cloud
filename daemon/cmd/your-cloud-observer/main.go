package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/ldesfontaine/yourcloud/daemon/internal/app"
	"github.com/ldesfontaine/yourcloud/daemon/internal/config"
	"github.com/ldesfontaine/yourcloud/daemon/internal/identity"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "observer refusé: %v\n", err)
		os.Exit(1)
	}
}

// run ouvre le daemon puis limite la CLI à ses diagnostics locaux autorisés.
func run() error {
	flags := flag.NewFlagSet("your-cloud-observer", flag.ContinueOnError)
	configPath := flags.String("config", "/etc/your-cloud/observer.json", "configuration du daemon")
	if err := flags.Parse(os.Args[1:]); err != nil {
		return err
	}
	if flags.NArg() != 1 {
		return fmt.Errorf("usage: your-cloud-observer [--config PATH] run|export-current|public-identity|db-usage|version|prepare-identity-renewal|commit-identity-renewal|rollback-identity-renewal|finalize-identity-renewal")
	}
	if flags.Arg(0) == "version" {
		fmt.Println(app.Version)
		return nil
	}
	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	switch flags.Arg(0) {
	case "prepare-identity-renewal":
		candidate, err := identity.PrepareRenewal(cfg.StateDir)
		if err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(map[string]string{
			"algorithm": "Ed25519", "key_id": candidate.KeyID(),
			"public_key": candidate.PublicBase64(),
		})
	case "commit-identity-renewal":
		if err := identity.CommitRenewal(cfg.StateDir); err != nil {
			return err
		}
		fmt.Println("identité candidate activée")
		return nil
	case "rollback-identity-renewal":
		if err := identity.RollbackRenewal(cfg.StateDir); err != nil {
			return err
		}
		fmt.Println("identité précédente restaurée")
		return nil
	case "finalize-identity-renewal":
		if err := identity.FinalizeRenewal(cfg.StateDir); err != nil {
			return err
		}
		fmt.Println("rollback d'identité retiré")
		return nil
	}
	observer, err := app.Open(cfg)
	if err != nil {
		return err
	}
	defer observer.Close()
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	switch flags.Arg(0) {
	case "run":
		return observer.Run(ctx)
	case "export-current":
		value, err := observer.ExportCurrent(ctx)
		if err != nil {
			return err
		}
		fmt.Println(value)
		return nil
	case "public-identity":
		return json.NewEncoder(os.Stdout).Encode(observer.PublicIdentity())
	case "db-usage":
		value, err := observer.DatabaseUsage(ctx)
		if err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(value)
	default:
		return fmt.Errorf("commande inconnue: %s", flags.Arg(0))
	}
}

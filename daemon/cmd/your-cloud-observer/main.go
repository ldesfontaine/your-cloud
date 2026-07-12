package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/lucas-desfontaine/your-cloud/daemon/internal/app"
	"github.com/lucas-desfontaine/your-cloud/daemon/internal/config"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "observer refusé: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	flags := flag.NewFlagSet("your-cloud-observer", flag.ContinueOnError)
	configPath := flags.String("config", "/etc/your-cloud/observer.json", "configuration du daemon")
	if err := flags.Parse(os.Args[1:]); err != nil {
		return err
	}
	if flags.NArg() != 1 {
		return fmt.Errorf("usage: your-cloud-observer [--config PATH] run|export-current|public-identity|db-usage")
	}
	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
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

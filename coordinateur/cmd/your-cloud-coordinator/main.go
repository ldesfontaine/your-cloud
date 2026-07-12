package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/lucas-desfontaine/your-cloud/coordinateur/internal/config"
	"github.com/lucas-desfontaine/your-cloud/coordinateur/internal/registry"
	"github.com/lucas-desfontaine/your-cloud/coordinateur/internal/server"
	"github.com/lucas-desfontaine/your-cloud/coordinateur/internal/store"
)

const version = "1.0.0-rc.2"

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "coordinateur refusé: %v\n", err)
		os.Exit(1)
	}
}

// run câble configuration, registre et stockage avant de démarrer le serveur.
func run() error {
	flags := flag.NewFlagSet("your-cloud-coordinator", flag.ContinueOnError)
	configPath := flags.String("config", "/etc/your-cloud/coordinator.json", "configuration du coordinateur")
	if err := flags.Parse(os.Args[1:]); err != nil {
		return err
	}
	if flags.NArg() != 1 {
		return fmt.Errorf("usage: your-cloud-coordinator [--config PATH] run|db-usage|version")
	}
	if flags.Arg(0) == "version" {
		fmt.Println(version)
		return nil
	}
	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	identities, err := registry.Load(cfg.IdentityRegistry)
	if err != nil {
		return err
	}
	database, err := store.Open(cfg.StateDir, cfg.DatabaseLimitBytes, cfg.EventRetentionDays)
	if err != nil {
		return err
	}
	defer database.Close()
	if flags.Arg(0) == "db-usage" {
		pages, pageSize, err := database.PageUsage(context.Background())
		if err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(map[string]int64{
			"page_count": pages, "page_size": pageSize, "bytes": pages * pageSize,
			"limit_bytes": cfg.DatabaseLimitBytes,
		})
	}
	if flags.Arg(0) != "run" {
		return fmt.Errorf("commande inconnue: %s", flags.Arg(0))
	}
	service, err := server.New(cfg, identities, database)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	done := make(chan error, 1)
	go func() { done <- service.Run() }()
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return service.Shutdown(shutdown)
	}
}

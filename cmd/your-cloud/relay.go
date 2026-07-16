package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/ldesfontaine/your-cloud/internal/presence"
	"github.com/ldesfontaine/your-cloud/internal/relay"
)

func runRelay(arguments []string, candidatePath string) error {
	flags := flag.NewFlagSet("relay", flag.ContinueOnError)
	listenAddress := flags.String("listen", "", "exact LAB address on which the Relay listens")
	if err := flags.Parse(arguments); err != nil {
		return fmt.Errorf("relay arguments: %w", err)
	}
	if flags.NArg() != 0 {
		return errorsForUnexpectedArguments("relay", flags.Args())
	}
	address, err := netip.ParseAddrPort(*listenAddress)
	if err != nil || address.Port() == 0 {
		if err == nil {
			err = errors.New("port must be non-zero")
		}
		return fmt.Errorf("relay listen address: %w", err)
	}
	if address.String() != "192.168.242.103:8443" {
		return errors.New("relay listen address must be 192.168.242.103:8443 in v0.0.1")
	}

	// The local root-provisioned candidate is checked before the HTTP server is
	// assembled or any listening socket can be opened.
	if err := relay.LoadCandidate(candidatePath); err != nil {
		return fmt.Errorf("relay candidate: %w", err)
	}

	logger := log.New(os.Stdout, "your-cloud relay: ", log.LstdFlags|log.LUTC)
	allowedMachines := presence.AllowedMachineIDs()
	store := relay.NewStore(allowedMachines)
	server := &http.Server{
		Addr:              *listenAddress,
		Handler:           relay.NewHandler(store, allowedMachines, logger),
		ReadHeaderTimeout: 2 * time.Second,
		ReadTimeout:       3 * time.Second,
		WriteTimeout:      3 * time.Second,
		IdleTimeout:       10 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	errorsFromServer := make(chan error, 1)
	go func() {
		logger.Printf("listening address=%s", server.Addr)
		errorsFromServer <- server.ListenAndServe()
	}()

	select {
	case <-ctx.Done():
		shutdownContext, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownContext); err != nil {
			return fmt.Errorf("graceful shutdown: %w", err)
		}
	case err := <-errorsFromServer:
		if !errors.Is(err, http.ErrServerClosed) {
			return fmt.Errorf("serve: %w", err)
		}
	}
	return nil
}

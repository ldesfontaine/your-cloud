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

const v001RelayListenAddress = "192.168.242.103:8443"

type relayArguments struct {
	listenAddress string
}

func runRelay(arguments []string, candidatePath string) error {
	configuration, err := parseRelayArguments(arguments)
	if err != nil {
		return err
	}

	// Root must provision the local candidate before the Relay is assembled or
	// allowed to open a listening socket.
	if err := relay.LoadCandidate(candidatePath); err != nil {
		return fmt.Errorf("relay candidate: %w", err)
	}

	logger := log.New(os.Stdout, "your-cloud relay: ", log.LstdFlags|log.LUTC)
	server := newRelayServer(configuration.listenAddress, logger)
	return serveRelayUntilStopped(server, logger)
}

func parseRelayArguments(arguments []string) (relayArguments, error) {
	var configuration relayArguments
	flags := flag.NewFlagSet("relay", flag.ContinueOnError)
	flags.StringVar(
		&configuration.listenAddress,
		"listen",
		"",
		"exact LAB address on which the Relay listens",
	)
	if err := flags.Parse(arguments); err != nil {
		return relayArguments{}, fmt.Errorf("relay arguments: %w", err)
	}
	if flags.NArg() != 0 {
		return relayArguments{}, errorsForUnexpectedArguments("relay", flags.Args())
	}
	if err := validateRelayListenAddress(configuration.listenAddress); err != nil {
		return relayArguments{}, err
	}
	return configuration, nil
}

func validateRelayListenAddress(listenAddress string) error {
	address, err := netip.ParseAddrPort(listenAddress)
	if err != nil {
		return fmt.Errorf("relay listen address: %w", err)
	}
	if address.Port() == 0 {
		return errors.New("relay listen address: port must be non-zero")
	}
	if address.String() != v001RelayListenAddress {
		return fmt.Errorf("relay listen address must be %s in v0.0.1", v001RelayListenAddress)
	}
	return nil
}

func newRelayServer(listenAddress string, logger *log.Logger) *http.Server {
	allowedMachines := presence.AllowedMachineIDs()
	store := relay.NewStore(allowedMachines)
	return &http.Server{
		Addr:              listenAddress,
		Handler:           relay.NewHandler(store, allowedMachines, logger),
		ReadHeaderTimeout: 2 * time.Second,
		ReadTimeout:       3 * time.Second,
		WriteTimeout:      3 * time.Second,
		IdleTimeout:       10 * time.Second,
	}
}

func serveRelayUntilStopped(server *http.Server, logger *log.Logger) error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	errorsFromServer := make(chan error, 1)
	go func() {
		logger.Printf("listening address=%s", server.Addr)
		errorsFromServer <- server.ListenAndServe()
	}()

	select {
	case <-ctx.Done():
		return shutdownRelay(server)
	case err := <-errorsFromServer:
		if !errors.Is(err, http.ErrServerClosed) {
			return fmt.Errorf("serve: %w", err)
		}
		return nil
	}
}

func shutdownRelay(server *http.Server) error {
	shutdownContext, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := server.Shutdown(shutdownContext); err != nil {
		return fmt.Errorf("graceful shutdown: %w", err)
	}
	return nil
}

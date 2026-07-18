package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
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

	"github.com/ldesfontaine/your-cloud/internal/credentials"
	"github.com/ldesfontaine/your-cloud/internal/enrollment"
	"github.com/ldesfontaine/your-cloud/internal/relay"
	"github.com/ldesfontaine/your-cloud/internal/transport"
)

const (
	v002RelayListenAddress = "192.168.242.103:8443"
	relayStateDirectory    = "/var/lib/private/your-cloud-relay"
)

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
	enrollments, err := enrollment.OpenStore(enrollment.RegistryPath)
	if err != nil {
		return fmt.Errorf("relay enrollment: %w", err)
	}
	credentialDirectory := os.Getenv(credentials.DirectoryEnvironment)
	identity, err := credentials.LoadPair(credentialDirectory, "relay.crt", "relay.key")
	if err != nil {
		return fmt.Errorf("relay credentials: %w", err)
	}
	daemonCA, err := credentials.LoadPublic(credentialDirectory, "daemon-ca.crt")
	if err != nil {
		return fmt.Errorf("relay credentials: %w", err)
	}
	tlsConfiguration, err := transport.NewRelayConfig(daemonCA, identity, func(certificate *x509.Certificate) error {
		_, err := enrollments.Authorize(certificate)
		return err
	})
	if err != nil {
		return fmt.Errorf("relay transport: %w", err)
	}
	store, err := relay.OpenObservationStore(relayStateDirectory)
	if err != nil {
		return fmt.Errorf("relay store: %w", err)
	}
	handler, err := relay.NewObservationHandler(store, enrollments.Authorize)
	if err != nil {
		return fmt.Errorf("relay handler: %w", err)
	}

	logger := log.New(os.Stdout, "your-cloud relay: ", log.LstdFlags|log.LUTC)
	server := newRelayServer(configuration.listenAddress, tlsConfiguration, handler)
	return serveRelayUntilStopped(server, logger, enrollments.Reload)
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
	if address.String() != v002RelayListenAddress {
		return fmt.Errorf("relay listen address must be %s in v0.0.2", v002RelayListenAddress)
	}
	return nil
}

func newRelayServer(listenAddress string, tlsConfiguration *tls.Config, handler http.Handler) *http.Server {
	return &http.Server{
		Addr:              listenAddress,
		Handler:           handler,
		TLSConfig:         tlsConfiguration,
		ReadHeaderTimeout: 2 * time.Second,
		ReadTimeout:       3 * time.Second,
		WriteTimeout:      3 * time.Second,
		IdleTimeout:       10 * time.Second,
	}
}

func serveRelayUntilStopped(server *http.Server, logger *log.Logger, reload func() error) error {
	errorsFromServer := make(chan error, 1)
	go func() {
		logger.Printf("listening address=%s", server.Addr)
		errorsFromServer <- server.ListenAndServeTLS("", "")
	}()
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	defer signal.Stop(signals)
	for {
		select {
		case received := <-signals:
			if received == syscall.SIGHUP {
				if err := reload(); err != nil {
					logger.Printf("enrollment reload refused: %v", err)
				} else {
					logger.Printf("enrollment reloaded")
				}
				continue
			}
			return shutdownRelay(server)
		case err := <-errorsFromServer:
			if !errors.Is(err, http.ErrServerClosed) {
				return fmt.Errorf("serve: %w", err)
			}
			return nil
		}
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

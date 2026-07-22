package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/ldesfontaine/your-cloud/internal/credentials"
	"github.com/ldesfontaine/your-cloud/internal/enrollment"
	"github.com/ldesfontaine/your-cloud/internal/protocol"
	"github.com/ldesfontaine/your-cloud/internal/readeridentity"
	"github.com/ldesfontaine/your-cloud/internal/relay"
	"github.com/ldesfontaine/your-cloud/internal/transport"
)

const (
	relayIngestionListenAddress = "192.168.243.153:8443"
	relayReaderListenAddress    = "192.168.243.153:8444"
	controllerReaderIPv4        = "192.168.242.103"
	relayStateDirectory         = "/var/lib/private/your-cloud-relay"
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
	stateLock := &sync.RWMutex{}
	handler, err := relay.NewObservationHandlerWithStateLock(store, enrollments.Authorize, stateLock)
	if err != nil {
		return fmt.Errorf("relay handler: %w", err)
	}

	logger := log.New(os.Stdout, "your-cloud relay: ", log.LstdFlags|log.LUTC)
	ingestionServer := newRelayServer(configuration.listenAddress, tlsConfiguration, handler)
	readerServer, readers, readerErr := assembleRelayReader(enrollments, store, credentialDirectory, stateLock)
	if readerErr != nil {
		logger.Printf("reader disabled: %v", readerErr)
	}
	reload := func() error {
		stateLock.Lock()
		defer stateLock.Unlock()
		if err := enrollments.Reload(); err != nil {
			return fmt.Errorf("enrollment: %w", err)
		}
		if readers != nil {
			if err := readers.Reload(); err != nil {
				return fmt.Errorf("reader manifest: %w", err)
			}
		}
		return nil
	}
	return serveRelayServersUntilStopped(ingestionServer, readerServer, logger, reload)
}

func assembleRelayReader(
	enrollments *enrollment.Store,
	observations *relay.ObservationStore,
	credentialDirectory string,
	stateLock *sync.RWMutex,
) (*http.Server, *readeridentity.Store, error) {
	registry, err := enrollments.Snapshot()
	if err != nil {
		return nil, nil, err
	}
	if !registry.ReaderReady() {
		return nil, nil, errors.New("enrollment registry schema 2 migration is required")
	}
	readers, err := readeridentity.OpenStore(readeridentity.ManifestPath)
	if err != nil {
		return nil, nil, err
	}
	manifest, err := readers.Snapshot()
	if err != nil {
		return nil, nil, err
	}
	if manifest.InfrastructureID != registry.InfrastructureID {
		return nil, nil, errors.New("reader manifest and enrollment infrastructure differ")
	}
	identity, err := credentials.LoadPair(credentialDirectory, "relay-reader.crt", "relay-reader.key")
	if err != nil {
		return nil, nil, err
	}
	controllerCA, err := credentials.LoadPublic(credentialDirectory, "controller-reader-ca.crt")
	if err != nil {
		return nil, nil, err
	}
	tlsConfiguration, err := transport.NewRelayReaderConfig(controllerCA, identity, func(certificate *x509.Certificate) error {
		return readers.Authorize(certificate, time.Now())
	})
	if err != nil {
		return nil, nil, err
	}
	host := protocol.RelayReaderServerName(registry.InfrastructureID) + ":8444"
	handler, err := relay.NewSnapshotHandler(enrollments, observations, readers, host, stateLock)
	if err != nil {
		return nil, nil, err
	}
	server := &http.Server{
		Addr:              relayReaderListenAddress,
		Handler:           handler,
		TLSConfig:         tlsConfiguration,
		ReadHeaderTimeout: 3 * time.Second,
		ReadTimeout:       6 * time.Second,
		WriteTimeout:      6 * time.Second,
		IdleTimeout:       6 * time.Second,
		MaxHeaderBytes:    8 * 1024,
	}
	return server, readers, nil
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
	if address.String() != relayIngestionListenAddress {
		return fmt.Errorf("relay listen address must be %s", relayIngestionListenAddress)
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
	return serveRelayServersUntilStopped(server, nil, logger, reload)
}

func serveRelayServersUntilStopped(ingestion, reader *http.Server, logger *log.Logger, reload func() error) error {
	servers := []*http.Server{ingestion}
	if reader != nil {
		servers = append(servers, reader)
	}
	errorsFromServer := make(chan error, len(servers))
	for _, current := range servers {
		server := current
		go func() {
			logger.Printf("listening address=%s", server.Addr)
			if server == reader {
				errorsFromServer <- serveReaderServer(server)
			} else {
				errorsFromServer <- server.ListenAndServeTLS("", "")
			}
		}()
	}
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
			return shutdownRelayServers(servers)
		case err := <-errorsFromServer:
			if !errors.Is(err, http.ErrServerClosed) {
				_ = shutdownRelayServers(servers)
				return fmt.Errorf("serve: %w", err)
			}
			if len(servers) == 1 {
				return nil
			}
		}
	}
}

func serveReaderServer(server *http.Server) error {
	base, err := net.Listen("tcp4", server.Addr)
	if err != nil {
		return err
	}
	bounded, err := relay.NewReaderListener(base, controllerReaderIPv4)
	if err != nil {
		_ = base.Close()
		return err
	}
	return server.Serve(tls.NewListener(bounded, server.TLSConfig))
}

func shutdownRelayServers(servers []*http.Server) error {
	var messages []string
	for _, server := range servers {
		if err := shutdownRelay(server); err != nil {
			messages = append(messages, err.Error())
		}
	}
	if len(messages) != 0 {
		return errors.New(strings.Join(messages, "; "))
	}
	return nil
}

func shutdownRelay(server *http.Server) error {
	shutdownContext, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := server.Shutdown(shutdownContext); err != nil {
		return fmt.Errorf("graceful shutdown: %w", err)
	}
	return nil
}

package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/ldesfontaine/your-cloud/internal/controller"
	"github.com/ldesfontaine/your-cloud/internal/credentials"
	"github.com/ldesfontaine/your-cloud/internal/protocol"
	"github.com/ldesfontaine/your-cloud/internal/transport"
)

type controllerServeArguments struct {
	stateDirectory string
	listenAddress  string
	allowedSource  string
	relayEndpoint  string
	windowMode     string
	windowSheet    string
}

func runController(arguments []string) error {
	if len(arguments) == 0 {
		return errors.New("controller requires one local operation: init, serve or revoke-device")
	}
	switch arguments[0] {
	case "init":
		return runControllerInit(arguments[1:])
	case "serve":
		return runControllerServe(arguments[1:])
	case "revoke-device":
		return runControllerRevokeDevice(arguments[1:])
	default:
		return fmt.Errorf("unknown controller operation %q: expected init, serve or revoke-device", arguments[0])
	}
}

func runControllerRevokeDevice(arguments []string) error {
	flags := flag.NewFlagSet("controller revoke-device", flag.ContinueOnError)
	stateDirectory := flags.String("state-dir", "", "private Controller state directory")
	if err := flags.Parse(arguments); err != nil {
		return fmt.Errorf("controller revoke-device arguments: %w", err)
	}
	if flags.NArg() != 0 {
		return errorsForUnexpectedArguments("controller revoke-device", flags.Args())
	}
	if err := validateControllerStatePath(*stateDirectory); err != nil {
		return err
	}
	authority, err := controller.OpenAuthorityStore(*stateDirectory, time.Now())
	if err != nil {
		return fmt.Errorf("Controller authority: %w", err)
	}
	revoked, err := authority.RevokeActiveDevice(time.Now())
	if err != nil {
		return fmt.Errorf("revoke active Controller device: %w", err)
	}
	fmt.Fprintf(os.Stdout, "device_id=%s status=%s\n", revoked.DeviceID, revoked.Status)
	return nil
}

func runControllerInit(arguments []string) error {
	flags := flag.NewFlagSet("controller init", flag.ContinueOnError)
	stateDirectory := flags.String("state-dir", "", "existing private Controller state directory")
	if err := flags.Parse(arguments); err != nil {
		return fmt.Errorf("controller init arguments: %w", err)
	}
	if flags.NArg() != 0 {
		return errorsForUnexpectedArguments("controller init", flags.Args())
	}
	if err := validateControllerStatePath(*stateDirectory); err != nil {
		return err
	}
	state, err := controller.InitializeAuthority(*stateDirectory, time.Now())
	if err != nil {
		return fmt.Errorf("initialize Controller authority: %w", err)
	}
	if err := controller.CreateInventory(*stateDirectory, state.ControllerID, state.InfrastructureID); err != nil {
		return fmt.Errorf("initialize Controller inventory after authority creation: %w", err)
	}
	fmt.Fprintf(os.Stdout, "controller_id=%s infrastructure_id=%s\n", state.ControllerID, state.InfrastructureID)
	return nil
}

func runControllerServe(arguments []string) error {
	configuration, err := parseControllerServeArguments(arguments)
	if err != nil {
		return err
	}
	authority, err := controller.OpenAuthorityStore(configuration.stateDirectory, time.Now())
	if err != nil {
		return fmt.Errorf("Controller authority: %w", err)
	}
	state := authority.Snapshot()
	inventory, err := controller.OpenInventoryStore(configuration.stateDirectory)
	if err != nil {
		return fmt.Errorf("Controller inventory: %w", err)
	}
	external, err := controller.OpenExternalStore(configuration.stateDirectory, state.ControllerID, state.InfrastructureID)
	if err != nil {
		return fmt.Errorf("Controller external inventory: %w", err)
	}
	definitions, err := controller.OpenServiceDefinitionStore(configuration.stateDirectory, state.ControllerID, state.InfrastructureID)
	if err != nil {
		return fmt.Errorf("Controller service definitions: %w", err)
	}
	dispatches, err := controller.OpenDispatchRegistryStore(configuration.stateDirectory, state.ControllerID, state.InfrastructureID)
	if err != nil {
		return fmt.Errorf("Controller dispatch registry: %w", err)
	}
	cache, err := controller.OpenRelayCacheStore(configuration.stateDirectory, state.ControllerID, state.InfrastructureID)
	if err != nil {
		return fmt.Errorf("Controller Relay cache: %w", err)
	}
	credentialDirectory := os.Getenv(credentials.DirectoryEnvironment)
	readerIdentity, err := credentials.LoadPair(credentialDirectory, "controller-reader.crt", "controller-reader.key")
	if err != nil {
		return fmt.Errorf("Controller reader credentials: %w", err)
	}
	relayCA, err := credentials.LoadPublic(credentialDirectory, "relay-reader-ca.crt")
	if err != nil {
		return fmt.Errorf("Controller reader credentials: %w", err)
	}
	relayName := protocol.RelayReaderServerName(state.InfrastructureID)
	relayHost := relayName + ":8444"
	client, err := transport.NewControllerReaderClient(relayCA, readerIdentity, relayName, relayHost, configuration.relayEndpoint)
	if err != nil {
		return fmt.Errorf("Controller reader transport: %w", err)
	}
	reader, err := controller.NewRelayReader(client, relayHost, state.ControllerID, state.InfrastructureID, cache)
	if err != nil {
		return fmt.Errorf("Controller Relay reader: %w", err)
	}
	pairing, err := controller.NewPairingManager(authority)
	if err != nil {
		return fmt.Errorf("Controller identity candidate: %w", err)
	}
	sessions, err := controller.NewSessionManager(authority)
	if err != nil {
		return fmt.Errorf("Controller sessions: %w", err)
	}
	host := protocol.ControllerServerName(state.InfrastructureID) + ":9443"
	handler, err := controller.NewControllerHandler(authority, pairing, sessions, inventory, external, definitions, dispatches, reader, host)
	if err != nil {
		return fmt.Errorf("Controller HTTP: %w", err)
	}
	// No auxiliary dispatcher is attached here, and that is the whole decision:
	// the two routes of the command trajectory do not exist on a Controller
	// that cannot launch. `#126` attaches the bounded OpenSSH launch at this
	// exact line, and the routes appear with it. Until then this binary cannot
	// receive an approval, so it cannot spend one for nothing.
	tlsConfiguration, err := authority.DeviceTLSConfig()
	if err != nil {
		return fmt.Errorf("Controller TLS: %w", err)
	}
	mainServer, mainListener, err := controllerServer(configuration.listenAddress, configuration.allowedSource, tlsConfiguration, handler)
	if err != nil {
		return err
	}
	defer mainListener.Close()

	logger := log.New(os.Stdout, "your-cloud controller: ", log.LstdFlags|log.LUTC)
	var temporaryServer *http.Server
	var temporaryListener net.Listener
	if configuration.windowMode != "" {
		temporaryServer, temporaryListener, err = assembleTemporaryController(
			configuration, authority, pairing, state.InfrastructureID, logger,
		)
		if err != nil {
			return err
		}
		defer os.Remove(configuration.windowSheet)
		defer temporaryListener.Close()
	}
	return serveControllerUntilStopped(mainServer, mainListener, temporaryServer, temporaryListener, logger)
}

func parseControllerServeArguments(arguments []string) (controllerServeArguments, error) {
	var configuration controllerServeArguments
	flags := flag.NewFlagSet("controller serve", flag.ContinueOnError)
	flags.StringVar(&configuration.stateDirectory, "state-dir", "", "private Controller state directory")
	flags.StringVar(&configuration.listenAddress, "listen", "", "exact private IPv4 address on port 9443")
	flags.StringVar(&configuration.allowedSource, "allowed-source", "", "canonical private IPv4 source CIDR")
	flags.StringVar(&configuration.relayEndpoint, "relay-endpoint", "", "exact private Relay IPv4 address on port 8444")
	flags.StringVar(&configuration.windowMode, "window", "", "optional local window: enrollment or recovery")
	flags.StringVar(&configuration.windowSheet, "window-sheet", "", "new private file receiving the one-time window sheet")
	if err := flags.Parse(arguments); err != nil {
		return controllerServeArguments{}, fmt.Errorf("controller serve arguments: %w", err)
	}
	if flags.NArg() != 0 {
		return controllerServeArguments{}, errorsForUnexpectedArguments("controller serve", flags.Args())
	}
	if err := validateControllerStatePath(configuration.stateDirectory); err != nil {
		return controllerServeArguments{}, err
	}
	listen, err := netip.ParseAddrPort(configuration.listenAddress)
	if err != nil || !listen.Addr().Is4() || !listen.Addr().IsPrivate() || listen.Addr().IsUnspecified() || listen.Port() != 9443 {
		return controllerServeArguments{}, errors.New("Controller listen address must be one exact private IPv4 address on port 9443")
	}
	if _, err := controller.NewControllerListener(closedListener{}, configuration.allowedSource); err != nil {
		return controllerServeArguments{}, fmt.Errorf("Controller allowed source: %w", err)
	}
	relay, err := netip.ParseAddrPort(configuration.relayEndpoint)
	if err != nil || !relay.Addr().Is4() || !relay.Addr().IsPrivate() || relay.Addr().IsUnspecified() || relay.Port() != 8444 {
		return controllerServeArguments{}, errors.New("Controller Relay endpoint must be one exact private IPv4 address on port 8444")
	}
	if configuration.windowMode == "" {
		if configuration.windowSheet != "" {
			return controllerServeArguments{}, errors.New("Controller window sheet requires an open window")
		}
	} else {
		if configuration.windowMode != "enrollment" && configuration.windowMode != "recovery" {
			return controllerServeArguments{}, errors.New("Controller window must be enrollment or recovery")
		}
		if !filepath.IsAbs(configuration.windowSheet) || filepath.Clean(configuration.windowSheet) != configuration.windowSheet {
			return controllerServeArguments{}, errors.New("Controller window sheet path must be absolute and canonical")
		}
	}
	return configuration, nil
}

func validateControllerStatePath(path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return errors.New("Controller state directory must be absolute and canonical")
	}
	return nil
}

func controllerServer(address, allowedSource string, tlsConfiguration *tls.Config, handler http.Handler) (*http.Server, net.Listener, error) {
	base, err := net.Listen("tcp4", address)
	if err != nil {
		return nil, nil, fmt.Errorf("Controller listen: %w", err)
	}
	bounded, err := controller.NewControllerListener(base, allowedSource)
	if err != nil {
		_ = base.Close()
		return nil, nil, fmt.Errorf("Controller listener: %w", err)
	}
	server := &http.Server{
		Addr: address, Handler: handler, TLSConfig: tlsConfiguration,
		ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 10 * time.Second,
		WriteTimeout: 10 * time.Second, IdleTimeout: 10 * time.Second,
		MaxHeaderBytes: maxControllerServerHeaderBytes,
		ConnState: func(connection net.Conn, state http.ConnState) {
			if state == http.StateActive {
				_ = connection.SetDeadline(time.Time{})
			}
		},
	}
	return server, tls.NewListener(bounded, tlsConfiguration), nil
}

func assembleTemporaryController(
	configuration controllerServeArguments,
	authority *controller.AuthorityStore,
	pairing *controller.PairingManager,
	infrastructureID string,
	logger *log.Logger,
) (*http.Server, net.Listener, error) {
	sheet, err := pairing.OpenWindow(configuration.windowMode)
	if err != nil {
		return nil, nil, fmt.Errorf("open local Controller window: %w", err)
	}
	if err := writeWindowSheet(configuration.windowSheet, sheet); err != nil {
		return nil, nil, err
	}
	host := protocol.ControllerServerName(infrastructureID) + ":9444"
	var server *http.Server
	closeWindow := func() {
		_ = os.Remove(configuration.windowSheet)
		if server != nil {
			go func() { _ = server.Close() }()
		}
	}
	handler, err := controller.NewTemporaryHandler(pairing, configuration.windowMode, host, closeWindow)
	if err != nil {
		_ = os.Remove(configuration.windowSheet)
		return nil, nil, err
	}
	tlsConfiguration, err := authority.TemporaryTLSConfig()
	if err != nil {
		_ = os.Remove(configuration.windowSheet)
		return nil, nil, err
	}
	listen, _ := netip.ParseAddrPort(configuration.listenAddress)
	temporaryAddress := netip.AddrPortFrom(listen.Addr(), 9444).String()
	server, listener, err := controllerServer(temporaryAddress, configuration.allowedSource, tlsConfiguration, handler)
	if err != nil {
		_ = os.Remove(configuration.windowSheet)
		return nil, nil, err
	}
	time.AfterFunc(10*time.Minute, closeWindow)
	logger.Printf("temporary %s window opened on %s; sheet=%s", configuration.windowMode, temporaryAddress, configuration.windowSheet)
	return server, listener, nil
}

func writeWindowSheet(path string, sheet controller.WindowSheet) error {
	encoded, err := json.Marshal(sheet)
	if err != nil || len(encoded) > 8*1024 {
		return errors.New("Controller window sheet cannot be encoded within its bound")
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return fmt.Errorf("create Controller window sheet: %w", err)
	}
	remove := true
	defer func() {
		_ = file.Close()
		if remove {
			_ = os.Remove(path)
		}
	}()
	if _, err := file.Write(append(encoded, '\n')); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	remove = false
	return nil
}

func serveControllerUntilStopped(mainServer *http.Server, mainListener net.Listener, temporaryServer *http.Server, temporaryListener net.Listener, logger *log.Logger) error {
	errorsFromServer := make(chan error, 2)
	go func() {
		logger.Printf("main API listening address=%s", mainServer.Addr)
		errorsFromServer <- mainServer.Serve(mainListener)
	}()
	if temporaryServer != nil {
		go func() { errorsFromServer <- temporaryServer.Serve(temporaryListener) }()
	}
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(signals)
	for {
		select {
		case <-signals:
			shutdownContext, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			if temporaryServer != nil {
				_ = temporaryServer.Shutdown(shutdownContext)
			}
			return mainServer.Shutdown(shutdownContext)
		case serveError := <-errorsFromServer:
			if errors.Is(serveError, http.ErrServerClosed) && temporaryServer != nil {
				temporaryServer = nil
				continue
			}
			if errors.Is(serveError, http.ErrServerClosed) {
				return nil
			}
			return fmt.Errorf("Controller serve: %w", serveError)
		}
	}
}

const maxControllerServerHeaderBytes = 8 * 1024

type closedListener struct{}

func (closedListener) Accept() (net.Conn, error) { return nil, net.ErrClosed }
func (closedListener) Close() error              { return nil }
func (closedListener) Addr() net.Addr            { return &net.TCPAddr{} }

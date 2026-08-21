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

// The two credential directories the launch reads, named here exactly as the
// unit loads them. The enrolment writes them root-owned under /etc; systemd
// copies them into this service's private credential directory at start.
//
// The endpoint sheet — address, port, account, pinned host key — lives here and
// never in the inventory: the inventory is readable and writable by the App,
// and an address the App could rewrite would be an App that chooses where
// a command goes. The App names a machine; it never names an endpoint.
const (
	commandIdentitiesCredential = "command-identities"
	commandEndpointsCredential  = "command-endpoints"

	// relayAnchorCredential is the flattened name systemd produces for the
	// Relay anchor: the unit passes the root-owned directory
	// `/etc/your-cloud/relay-anchor` as one credential named `relay-anchor`,
	// and a directory source materialises each file inside as `ID_FILENAME` —
	// measured on systemd 257 for the command sheets, same mechanism here. An
	// empty directory produces no credential at all, which is exactly the
	// state of a freshly created infrastructure whose Relay does not exist
	// yet: the reader stays dormant until the Relay journey deposits its
	// anchor and the service restarts.
	relayAnchorCredential = "relay-anchor_relay-reader-ca.crt"

	// defaultCommandIdentityDirectory is where the enrolment writes them, and
	// where the unit loads them from. Naming it here rather than making it a
	// required argument keeps the Assistant's invocation to the one thing it
	// really decides: which machine.
	defaultCommandIdentityDirectory = "/etc/your-cloud/command-identities"
)

// runtimeDirectoryEnvironment is set by systemd for units declaring
// RuntimeDirectory. The known hosts of a launch are derived into it and
// disappear with the service.
const runtimeDirectoryEnvironment = "RUNTIME_DIRECTORY"

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
		return errors.New("controller requires one local operation: init, serve, mint-command-identity or revoke-device")
	}
	switch arguments[0] {
	case "init":
		return runControllerInit(arguments[1:])
	case "serve":
		return runControllerServe(arguments[1:])
	case "mint-reader":
		return runControllerMintReader(arguments[1:])
	case "mint-command-identity":
		return runControllerMintCommandIdentity(arguments[1:])
	case "revoke-device":
		return runControllerRevokeDevice(arguments[1:])
	default:
		return fmt.Errorf(
			"unknown controller operation %q: expected init, serve, mint-reader, mint-command-identity or revoke-device",
			arguments[0])
	}
}

// runControllerMintReader strikes this Controller's own reader identity and
// prints only what may leave this machine: identifiers and fingerprints,
// never a key.
//
// Same decision as the command identity: a local operation, never a route —
// the Assistant runs it under the named act of an approved plan, as `root`,
// after `init` gave the immutable identifiers the certificate's URI carries,
// and before the first activation. The private half is born 0600 where the
// unit will load it and is named by nothing here.
func runControllerMintReader(arguments []string) error {
	flags := flag.NewFlagSet("controller mint-reader", flag.ContinueOnError)
	stateDirectory := flags.String("state-dir", "", "initialised private Controller state directory")
	credentialsDirectory := flags.String("credentials-dir", "/etc/your-cloud/controller-credentials",
		"root-owned directory of the Controller's credential sources")
	if err := flags.Parse(arguments); err != nil {
		return fmt.Errorf("controller mint-reader arguments: %w", err)
	}
	if flags.NArg() != 0 {
		return errorsForUnexpectedArguments("controller mint-reader", flags.Args())
	}
	if err := validateControllerStatePath(*stateDirectory); err != nil {
		return err
	}
	minted, err := controller.MintReaderIdentity(*stateDirectory, *credentialsDirectory, nil, time.Now())
	if err != nil {
		return fmt.Errorf("mint the reader identity of this Controller: %w", err)
	}
	// Quatre valeurs, toutes publiques — celles que le manifeste du Relay
	// épinglera un jour, et que le registre du plan constate aujourd'hui.
	fmt.Fprintf(os.Stdout, "controller_id=%s\n", minted.ControllerID)
	fmt.Fprintf(os.Stdout, "infrastructure_id=%s\n", minted.InfrastructureID)
	fmt.Fprintf(os.Stdout, "reader_serial=%s\n", minted.CertificateSerial)
	fmt.Fprintf(os.Stdout, "reader_sha256=%s\n", minted.CertificateSHA256)
	return nil
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

// runControllerMintCommandIdentity strikes the command identity of one machine
// and prints only what may leave this Controller.
//
// It is a local operation rather than a route, and that is the decision: the
// serving Controller runs under a dynamic account with no write access to
// `/etc`, and giving it one so that a request could mint a key would be giving
// the network surface the power to create authorities. The Assistant runs this
// at enrolment over the personal access, as `root`, exactly once per machine,
// and carries away the public half and its fingerprint — never a byte of the
// other one, which stays here.
func runControllerMintCommandIdentity(arguments []string) error {
	flags := flag.NewFlagSet("controller mint-command-identity", flag.ContinueOnError)
	machine := flags.String("machine", "", "machine the identity commands")
	directory := flags.String("identity-dir", defaultCommandIdentityDirectory,
		"root-owned directory of command identities")
	if err := flags.Parse(arguments); err != nil {
		return fmt.Errorf("controller mint-command-identity arguments: %w", err)
	}
	if flags.NArg() != 0 {
		return errorsForUnexpectedArguments("controller mint-command-identity", flags.Args())
	}
	minted, err := controller.MintCommandIdentity(*directory, *machine, nil)
	if err != nil {
		return fmt.Errorf("mint the command identity of this machine: %w", err)
	}
	// Two lines, both public. The private half is named by nothing here, not
	// even by its path: a process listing is a place a reader could learn where
	// to look.
	fmt.Fprintf(os.Stdout, "machine_id=%s\n", minted.MachineID)
	fmt.Fprintf(os.Stdout, "public_key=%s\n", minted.PublicLine)
	fmt.Fprintf(os.Stdout, "fingerprint=%s\n", minted.FingerprintSHA256)
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
	// L'ancre du Relay arrive par le motif répertoire que l'unité emploie déjà
	// pour les identités de commandement : `LoadCredential=relay-anchor:…` sur
	// un répertoire, que systemd aplatit fichier par fichier — vide, il ne
	// produit rien, et c'est l'état VRAI d'une création, où le Relay n'existe
	// pas encore. L'identité du Controller, elle, reste exigée dure : un
	// lecteur sans ancre est une infrastructure sans Relay ; un Controller
	// sans identité n'est pas un Controller.
	var reader controller.RelaySnapshotSource
	relayCA, err := credentials.LoadPublic(credentialDirectory, relayAnchorCredential)
	switch {
	case err == nil:
		relayName := protocol.RelayReaderServerName(state.InfrastructureID)
		relayHost := relayName + ":8444"
		client, err := transport.NewControllerReaderClient(relayCA, readerIdentity, relayName, relayHost, configuration.relayEndpoint)
		if err != nil {
			return fmt.Errorf("Controller reader transport: %w", err)
		}
		live, err := controller.NewRelayReader(client, relayHost, state.ControllerID, state.InfrastructureID, cache)
		if err != nil {
			return fmt.Errorf("Controller Relay reader: %w", err)
		}
		reader = live
	case errors.Is(err, os.ErrNotExist):
		// La dormance se nomme, une fois, au démarrage : le prévol et le
		// rapport LAB la lisent ici plutôt que de la déduire d'un silence.
		fmt.Fprintln(os.Stdout, "your-cloud controller: lecteur Relay dormant — aucune ancre posée dans relay-anchor")
		reader = controller.DormantRelayReader{}
	default:
		return fmt.Errorf("Controller reader credentials: %w", err)
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
	// The one engine whose effects leave this machine, attached here and
	// nowhere else. Everything it needs is read from the environment systemd
	// itself sets — the credentials directory that holds the command
	// identities, the runtime directory the known hosts are derived into —
	// and from the root-owned directory of endpoint sheets the enrolment
	// wrote. A Controller that cannot build it serves no command route at all
	// rather than a door that would spend a human approval and reach nothing.
	dispatcher, err := controller.NewSSHDispatcher(
		state.InfrastructureID,
		filepath.Join(credentialDirectory, commandIdentitiesCredential),
		filepath.Join(credentialDirectory, commandEndpointsCredential),
		os.Getenv(runtimeDirectoryEnvironment),
	)
	if err != nil {
		return fmt.Errorf("Controller command launch: %w", err)
	}
	if err := handler.AttachAuxiliaryDispatcher(dispatcher); err != nil {
		return fmt.Errorf("Controller command launch: %w", err)
	}
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
	// La readiness se déclare ICI et nulle part ailleurs : cette fonction ne
	// reçoit que des écouteurs déjà liés — le noyau accepte depuis `Listen` —
	// donc la déclaration ne peut pas précéder l'état qu'elle affirme. La
	// déplacer en amont referait la course que `Type=notify` ferme (#153).
	if err := notifyServiceReadiness(); err != nil {
		return fmt.Errorf("Controller readiness: %w", err)
	}
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

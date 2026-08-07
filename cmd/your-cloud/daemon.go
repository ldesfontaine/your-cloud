package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/ldesfontaine/your-cloud/internal/buffer"
	"github.com/ldesfontaine/your-cloud/internal/credentials"
	"github.com/ldesfontaine/your-cloud/internal/daemon"
	"github.com/ldesfontaine/your-cloud/internal/external"
	"github.com/ldesfontaine/your-cloud/internal/machineid"
	"github.com/ldesfontaine/your-cloud/internal/observation"
	"github.com/ldesfontaine/your-cloud/internal/transport"
)

const (
	daemonStateDirectory = "/var/lib/private/your-cloud-daemon"
	relayServerName      = "relay.observation.your-cloud.test"
	approvedRelayOrigin  = daemon.ApprovedRelayOrigin
)

type daemonArguments struct {
	machineID string
	relayURL  string
}

func runDaemon(arguments []string) error {
	configuration, err := parseDaemonArguments(arguments)
	if err != nil {
		return err
	}

	credentialDirectory := os.Getenv(credentials.DirectoryEnvironment)
	identity, err := credentials.LoadPair(credentialDirectory, "daemon.crt", "daemon.key")
	if err != nil {
		return fmt.Errorf("daemon credentials: %w", err)
	}
	relayCA, err := credentials.LoadPublic(credentialDirectory, "relay-ca.crt")
	if err != nil {
		return fmt.Errorf("daemon credentials: %w", err)
	}
	client, err := transport.NewDaemonClient(relayCA, identity, relayServerName)
	if err != nil {
		return fmt.Errorf("daemon transport: %w", err)
	}
	localBuffer, err := buffer.Open(daemonStateDirectory, buffer.DefaultLimits())
	if err != nil {
		return fmt.Errorf("daemon buffer: %w", err)
	}

	logger := log.New(os.Stdout, "your-cloud daemon: ", log.LstdFlags|log.LUTC)
	// The read-only adapter is assembled here and nowhere else, and what it is
	// given is two functions that return bytes. It receives no buffer, no client,
	// no credentials and no writer: the Daemon can publish what it read and the
	// adapter cannot even reach the thing that publishes.
	//
	// The machine's own sheet is re-read at every collection rather than at
	// start-up, so a target provisioned by root takes effect within the cadence
	// instead of at the next restart, and a sheet taken away stops being read at
	// once.
	sight := external.SystemSight()
	readExternal := func(ctx context.Context) ([]observation.ExternalReading, error) {
		return external.Collect(ctx, sight, configuration.machineID)
	}
	collector, err := daemon.NewCollector(configuration.machineID, localBuffer, observation.SystemSources(), readExternal, logger)
	if err != nil {
		return fmt.Errorf("daemon collector: %w", err)
	}
	publisher, err := daemon.NewPublisher(configuration.machineID, configuration.relayURL, localBuffer, client, logger)
	if err != nil {
		return fmt.Errorf("daemon publisher: %w", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	var workers sync.WaitGroup
	workers.Add(2)
	go func() {
		defer workers.Done()
		collector.Run(ctx)
	}()
	go func() {
		defer workers.Done()
		publisher.Run(ctx)
	}()
	workers.Wait()
	return nil
}

func parseDaemonArguments(arguments []string) (daemonArguments, error) {
	var configuration daemonArguments
	flags := flag.NewFlagSet("daemon", flag.ContinueOnError)
	flags.StringVar(
		&configuration.machineID,
		"machine-id",
		"",
		"synthetic identity of this LAB machine",
	)
	flags.StringVar(
		&configuration.relayURL,
		"relay-url",
		"",
		"approved HTTPS origin of the observation Relay",
	)
	if err := flags.Parse(arguments); err != nil {
		return daemonArguments{}, fmt.Errorf("daemon arguments: %w", err)
	}
	if flags.NArg() != 0 {
		return daemonArguments{}, errorsForUnexpectedArguments("daemon", flags.Args())
	}
	if err := machineid.Validate(configuration.machineID); err != nil {
		return daemonArguments{}, fmt.Errorf("daemon machine ID: %w", err)
	}
	if configuration.relayURL != daemon.ApprovedRelayOrigin {
		return daemonArguments{}, fmt.Errorf("daemon relay URL must be %s", daemon.ApprovedRelayOrigin)
	}
	return configuration, nil
}

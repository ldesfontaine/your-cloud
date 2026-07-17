package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/ldesfontaine/your-cloud/internal/daemon"
	"github.com/ldesfontaine/your-cloud/internal/presence"
)

const v001RelayOrigin = "http://192.168.242.103:8443"

type daemonArguments struct {
	machineID string
	relayURL  string
}

func runDaemon(arguments []string) error {
	configuration, err := parseDaemonArguments(arguments)
	if err != nil {
		return err
	}

	logger := log.New(os.Stdout, "your-cloud daemon: ", log.LstdFlags|log.LUTC)
	sender, err := daemon.NewSender(
		configuration.machineID,
		configuration.relayURL,
		presence.SendInterval,
		logger,
	)
	if err != nil {
		return fmt.Errorf("daemon configuration: %w", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	sender.Run(ctx)
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
		"HTTP origin of the v0.0.1 LAB Relay",
	)
	if err := flags.Parse(arguments); err != nil {
		return daemonArguments{}, fmt.Errorf("daemon arguments: %w", err)
	}
	if flags.NArg() != 0 {
		return daemonArguments{}, errorsForUnexpectedArguments("daemon", flags.Args())
	}
	if configuration.relayURL != v001RelayOrigin {
		return daemonArguments{}, fmt.Errorf("daemon relay URL must be %s in v0.0.1", v001RelayOrigin)
	}
	return configuration, nil
}

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

func runDaemon(arguments []string) error {
	flags := flag.NewFlagSet("daemon", flag.ContinueOnError)
	machineID := flags.String("machine-id", "", "synthetic identity of this LAB machine")
	relayURL := flags.String("relay-url", "", "HTTP origin of the v0.0.1 LAB Relay")
	if err := flags.Parse(arguments); err != nil {
		return fmt.Errorf("daemon arguments: %w", err)
	}
	if flags.NArg() != 0 {
		return errorsForUnexpectedArguments("daemon", flags.Args())
	}
	if *relayURL != v001RelayOrigin {
		return fmt.Errorf("daemon relay URL must be %s in v0.0.1", v001RelayOrigin)
	}

	logger := log.New(os.Stdout, "your-cloud daemon: ", log.LstdFlags|log.LUTC)
	sender, err := daemon.NewSender(*machineID, *relayURL, presence.SendInterval, logger)
	if err != nil {
		return fmt.Errorf("daemon configuration: %w", err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	sender.Run(ctx)
	return nil
}

func errorsForUnexpectedArguments(role string, arguments []string) error {
	return fmt.Errorf("%s accepts no positional arguments: %q", role, arguments)
}

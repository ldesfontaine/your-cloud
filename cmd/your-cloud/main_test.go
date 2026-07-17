package main

import (
	"strings"
	"testing"
)

func TestRunRejectsMissingOrUnknownRole(t *testing.T) {
	t.Parallel()
	for _, arguments := range [][]string{nil, {"aux"}, {"daemon-relay"}} {
		if err := run(arguments); err == nil {
			t.Fatalf("unsafe role accepted: %q", arguments)
		}
	}
}

func TestRolesRejectEachOthersArguments(t *testing.T) {
	t.Parallel()
	tests := [][]string{
		{"daemon", "--listen=127.0.0.1:8443"},
		{"relay", "--machine-id=lab-machine-1"},
		{"daemon", "unexpected"},
		{"relay", "unexpected"},
	}
	for _, arguments := range tests {
		if err := run(arguments); err == nil {
			t.Fatalf("foreign or positional argument accepted: %q", arguments)
		}
	}
}

func TestRelayRefusesBeforeListeningWithoutCandidate(t *testing.T) {
	t.Parallel()
	err := runRelay([]string{"--listen=" + v001RelayListenAddress}, t.TempDir()+"/missing.json")
	if err == nil || !strings.Contains(err.Error(), "relay candidate") {
		t.Fatalf("missing candidate was not the startup boundary: %v", err)
	}
}

func TestRelayRejectsEveryOtherListenAddress(t *testing.T) {
	t.Parallel()
	for _, address := range []string{"127.0.0.1:8443", "192.168.242.103:8444", "0.0.0.0:8443"} {
		err := runRelay([]string{"--listen=" + address}, t.TempDir()+"/candidate.json")
		if err == nil || !strings.Contains(err.Error(), "must be "+v001RelayListenAddress) {
			t.Fatalf("unsafe listen address %q was not refused: %v", address, err)
		}
	}
}

func TestRoleArgumentsAcceptV001Configuration(t *testing.T) {
	t.Parallel()

	daemonConfiguration, err := parseDaemonArguments([]string{
		"--machine-id=lab-machine-1",
		"--relay-url=" + v001RelayOrigin,
	})
	if err != nil {
		t.Fatalf("valid Daemon arguments refused: %v", err)
	}
	if daemonConfiguration.machineID != "lab-machine-1" || daemonConfiguration.relayURL != v001RelayOrigin {
		t.Fatalf("unexpected Daemon configuration: %#v", daemonConfiguration)
	}

	relayConfiguration, err := parseRelayArguments([]string{"--listen=" + v001RelayListenAddress})
	if err != nil {
		t.Fatalf("valid Relay arguments refused: %v", err)
	}
	if relayConfiguration.listenAddress != v001RelayListenAddress {
		t.Fatalf("unexpected Relay configuration: %#v", relayConfiguration)
	}
}

func TestDaemonRejectsEveryOtherRelayOrigin(t *testing.T) {
	t.Parallel()
	for _, relayURL := range []string{
		"",
		"http://127.0.0.1:8443",
		v001RelayOrigin + "/",
		v001RelayOrigin + "?target=other",
		"http://admin@192.168.242.103:8443",
	} {
		err := runDaemon([]string{"--machine-id=lab-machine-1", "--relay-url=" + relayURL})
		if err == nil || !strings.Contains(err.Error(), "must be "+v001RelayOrigin) {
			t.Fatalf("unsafe Relay origin %q was not refused: %v", relayURL, err)
		}
	}
}

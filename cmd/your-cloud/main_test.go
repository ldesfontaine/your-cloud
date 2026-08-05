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
		{"controller", "--machine-id=lab-machine-1"},
		{"diagnose", "observation", "--machine-id=lab-machine-1"},
		{"auxiliary", "approve", "--machine-id=lab-machine-1"},
		{"auxiliary", "observation"},
		{"auxiliary"},
		{"daemon", "unexpected"},
		{"relay", "unexpected"},
	}
	for _, arguments := range tests {
		if err := run(arguments); err == nil {
			t.Fatalf("foreign or positional argument accepted: %q", arguments)
		}
	}
}

func TestControllerServeArgumentsRequireExactPrivateEndpoints(t *testing.T) {
	t.Parallel()
	valid := []string{
		"--state-dir=/var/lib/private/your-cloud-controller",
		"--listen=192.168.242.103:9443",
		"--allowed-source=192.168.242.182/32",
		"--relay-endpoint=192.168.243.153:8444",
	}
	if _, err := parseControllerServeArguments(valid); err != nil {
		t.Fatalf("valid Controller arguments refused: %v", err)
	}
	for _, bad := range [][]string{
		{"--state-dir=relative", "--listen=192.168.242.103:9443", "--allowed-source=192.168.242.182/32", "--relay-endpoint=192.168.243.153:8444"},
		{"--state-dir=/tmp/a", "--listen=0.0.0.0:9443", "--allowed-source=192.168.242.182/32", "--relay-endpoint=192.168.243.153:8444"},
		{"--state-dir=/tmp/a", "--listen=192.168.242.103:9443", "--allowed-source=0.0.0.0/0", "--relay-endpoint=192.168.243.153:8444"},
		{"--state-dir=/tmp/a", "--listen=192.168.242.103:9443", "--allowed-source=192.168.242.182/32", "--relay-endpoint=127.0.0.1:8444"},
	} {
		if _, err := parseControllerServeArguments(bad); err == nil {
			t.Fatalf("unsafe Controller arguments accepted: %q", bad)
		}
	}
}

func TestRelayRefusesBeforeListeningWithoutCandidate(t *testing.T) {
	t.Parallel()
	err := runRelay([]string{"--listen=" + relayIngestionListenAddress}, t.TempDir()+"/missing.json")
	if err == nil || !strings.Contains(err.Error(), "relay candidate") {
		t.Fatalf("missing candidate was not the startup boundary: %v", err)
	}
}

func TestRelayRejectsEveryOtherListenAddress(t *testing.T) {
	t.Parallel()
	for _, address := range []string{"127.0.0.1:8443", "192.168.243.153:8444", "0.0.0.0:8443"} {
		err := runRelay([]string{"--listen=" + address}, t.TempDir()+"/candidate.json")
		if err == nil || !strings.Contains(err.Error(), "must be "+relayIngestionListenAddress) {
			t.Fatalf("unsafe listen address %q was not refused: %v", address, err)
		}
	}
}

func TestRoleArgumentsAcceptCurrentConfiguration(t *testing.T) {
	t.Parallel()

	daemonConfiguration, err := parseDaemonArguments([]string{
		"--machine-id=lab-machine-1",
		"--relay-url=" + approvedRelayOrigin,
	})
	if err != nil {
		t.Fatalf("valid Daemon arguments refused: %v", err)
	}
	if daemonConfiguration.machineID != "lab-machine-1" || daemonConfiguration.relayURL != approvedRelayOrigin {
		t.Fatalf("unexpected Daemon configuration: %#v", daemonConfiguration)
	}

	relayConfiguration, err := parseRelayArguments([]string{"--listen=" + relayIngestionListenAddress})
	if err != nil {
		t.Fatalf("valid Relay arguments refused: %v", err)
	}
	if relayConfiguration.listenAddress != relayIngestionListenAddress {
		t.Fatalf("unexpected Relay configuration: %#v", relayConfiguration)
	}
}

func TestDaemonRejectsEveryOtherRelayOrigin(t *testing.T) {
	t.Parallel()
	for _, relayURL := range []string{
		"",
		"http://127.0.0.1:8443",
		approvedRelayOrigin + "/",
		approvedRelayOrigin + "?target=other",
		"http://admin@192.168.242.103:8443",
	} {
		err := runDaemon([]string{"--machine-id=lab-machine-1", "--relay-url=" + relayURL})
		if err == nil || !strings.Contains(err.Error(), "must be "+approvedRelayOrigin) {
			t.Fatalf("unsafe Relay origin %q was not refused: %v", relayURL, err)
		}
	}
}

func TestDaemonRejectsMalformedMachineIDBeforeStartup(t *testing.T) {
	t.Parallel()
	for _, machineID := range []string{"", "UPPERCASE", "ab", "lab_machine_1", "-lab-machine-1"} {
		if configuration, err := parseDaemonArguments([]string{
			"--machine-id=" + machineID,
			"--relay-url=" + approvedRelayOrigin,
		}); err == nil {
			t.Fatalf("malformed machine ID accepted: %q as %#v", machineID, configuration)
		}
	}
}

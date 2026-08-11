package controller

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// recordingRunner stands where the OpenSSH client stands and records exactly
// what it was handed, so the option list is asserted as an argument vector
// rather than as a string a shell might have re-read.
type recordingRunner struct {
	program   string
	arguments []string
	input     []byte
	deadline  time.Time
	answer    commandResult
}

func (runner *recordingRunner) Run(ctx context.Context, program string, arguments []string, standardInput []byte) commandResult {
	runner.program = program
	runner.arguments = append([]string(nil), arguments...)
	runner.input = append([]byte(nil), standardInput...)
	runner.deadline, _ = ctx.Deadline()
	return runner.answer
}

// A well-formed Ed25519 host key blob: the four-byte length, the algorithm
// name, the four-byte length again and the thirty-two key bytes.
func testHostKeyBlob() string {
	blob := []byte{0, 0, 0, 11}
	blob = append(blob, []byte("ssh-ed25519")...)
	blob = append(blob, 0, 0, 0, 32)
	blob = append(blob, make([]byte, 32)...)
	return base64.StdEncoding.EncodeToString(blob)
}

// launchFixture lays the two root-owned places the launch reads and the runtime
// directory it derives into, all under the test's own private directory.
type launchFixture struct {
	dispatcher *CommandDispatcher
	runner     *recordingRunner
	endpoints  string
	identities string
	runtime    string
	now        time.Time
}

func newLaunchFixture(t *testing.T) launchFixture {
	t.Helper()
	root := privateTestDirectory(t)
	endpoints := filepath.Join(root, "endpoints")
	identities := filepath.Join(root, "identities")
	runtime := filepath.Join(root, "runtime")
	for _, directory := range []string{endpoints, identities, runtime} {
		if err := os.Mkdir(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	sheet, err := json.Marshal(commandEndpoint{
		SchemaVersion: commandEndpointSchema,
		MachineID:     "lab-machine-1",
		Host:          "192.0.2.10",
		Port:          22,
		Account:       "your-cloud-auxiliary",
		HostKey:       testHostKeyBlob(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(endpoints, "lab-machine-1.json"), sheet, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(identities, "lab-machine-1"), []byte("a private half"), 0o600); err != nil {
		t.Fatal(err)
	}
	runner := &recordingRunner{}
	now := time.Unix(1_700_000_000, 0).UTC()
	dispatcher, err := newCommandDispatcher(testInfrastructureID, "/usr/bin/ssh", endpoints, identities, runtime,
		runner, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	return launchFixture{
		dispatcher: dispatcher, runner: runner,
		endpoints: endpoints, identities: identities, runtime: runtime, now: now,
	}
}

func launchRecord(fixture launchFixture, lifetimeSeconds uint64) DispatchRecord {
	accepted := uint64(fixture.now.Unix())
	return DispatchRecord{
		ApprovalSHA256: strings.Repeat("a", 64), MachineID: "lab-machine-1",
		Operation: "deploy_oci_probe", ApprovalEpoch: 1, Sequence: 1,
		PlanSHA256: strings.Repeat("b", 64), RollbackSHA256: strings.Repeat("c", 64),
		State: DispatchInFlight, AcceptedAtUnix: accepted,
		ExpiresAtUnix: accepted + lifetimeSeconds,
	}
}

// TestTheLaunchPassesOnlyWhatItNamed holds the positive option list as a vector:
// every entry that takes a capability away is present, no remote command is
// passed, and the destination reaches the client as one argument after the
// end-of-options marker.
func TestTheLaunchPassesOnlyWhatItNamed(t *testing.T) {
	fixture := newLaunchFixture(t)
	fixture.runner.answer = commandResult{WroteStandardInput: true, ExitCode: 0}
	wrapper := []byte(`{"signed_approval":{}}`)

	fixture.dispatcher.Dispatch(launchRecord(fixture, 900), wrapper)

	if fixture.runner.program != "/usr/bin/ssh" {
		t.Fatalf("another program was run: %q", fixture.runner.program)
	}
	if string(fixture.runner.input) != string(wrapper) {
		t.Fatalf("the wrapper was not what reached the standard input: %q", fixture.runner.input)
	}
	joined := strings.Join(fixture.runner.arguments, " ")
	for _, removal := range []string{
		"-F /dev/null",
		"-o IdentitiesOnly=yes",
		"-o IdentityAgent=none",
		"-o BatchMode=yes",
		"-o StrictHostKeyChecking=yes",
		"-o GlobalKnownHostsFile=/dev/null",
		"-o NumberOfPasswordPrompts=0",
		"-o ClearAllForwardings=yes",
		"-o RequestTTY=no",
		"-l your-cloud-auxiliary",
		"-p 22",
	} {
		if !strings.Contains(joined, removal) {
			t.Fatalf("the launch does not take away %q: %v", removal, fixture.runner.arguments)
		}
	}
	// No remote command: the forced command on the other end decides what runs,
	// and the destination is the last argument, after `--`.
	last := len(fixture.runner.arguments) - 1
	if fixture.runner.arguments[last] != "192.0.2.10" || fixture.runner.arguments[last-1] != "--" {
		t.Fatalf("the destination is not the one bare argument after the marker: %v", fixture.runner.arguments)
	}
	// The identity is an explicit path under the credentials directory: this
	// service has no home, and nothing may be picked up by default.
	identity := filepath.Join(fixture.identities, "lab-machine-1")
	if !strings.Contains(joined, "-i "+identity) {
		t.Fatalf("the launch did not name its one identity: %v", fixture.runner.arguments)
	}
}

// TestTheLaunchDerivesEveryDelayFromTheApprovalWindow is decision 6 made
// executable: the whole launch is bounded by what is left of the envelope's own
// window, and the connection bound is a sub-bound of it rather than an addition
// to it.
func TestTheLaunchDerivesEveryDelayFromTheApprovalWindow(t *testing.T) {
	for _, window := range []struct {
		lifetime uint64
		connect  string
	}{
		// A whole window: the connection takes its own ceiling.
		{900, "-o ConnectTimeout=10"},
		// A window shorter than that ceiling: the connection is the window.
		{4, "-o ConnectTimeout=4"},
		{1, "-o ConnectTimeout=1"},
	} {
		fixture := newLaunchFixture(t)
		fixture.runner.answer = commandResult{WroteStandardInput: true}
		record := launchRecord(fixture, window.lifetime)

		fixture.dispatcher.Dispatch(record, []byte("{}"))

		joined := strings.Join(fixture.runner.arguments, " ")
		if !strings.Contains(joined, window.connect) {
			t.Fatalf("window of %ds: expected %q, got %v", window.lifetime, window.connect, fixture.runner.arguments)
		}
		// The whole launch carries the envelope's own remaining window as its
		// deadline. The clock is injected, so what is asserted is the duration
		// the authority still granted rather than an instant of this test's
		// wall clock.
		granted := time.Until(fixture.runner.deadline)
		expected := time.Duration(window.lifetime) * time.Second
		if granted > expected || expected-granted > time.Second {
			t.Fatalf("window of %ds: the launch was granted %s rather than the envelope's %s",
				window.lifetime, granted, expected)
		}
	}
}

// TestAnExpiredAuthoritySendsNothing: the window may close between the durable
// acceptance and the launch. A launch that outran the authority permitting it
// would have nothing left to justify it, so nothing is sent and the Controller
// says it observed that.
func TestAnExpiredAuthoritySendsNothing(t *testing.T) {
	fixture := newLaunchFixture(t)
	record := launchRecord(fixture, 900)
	record.ExpiresAtUnix = uint64(fixture.now.Unix())

	concluded := fixture.dispatcher.Dispatch(record, []byte("{}"))

	if concluded.State != DispatchNotLaunched || concluded.MachineSentence != "" ||
		concluded.ControllerObservation == "" {
		t.Fatalf("an expired authority: %+v", concluded)
	}
	if fixture.runner.program != "" {
		t.Fatal("an expired authority still ran a client")
	}
}

// TestTheKnownHostIsDerivedAndHoldsOnlyTheMachineReached: nothing is learnt
// from a network, the file holds one line, and it does not survive the launch.
func TestTheKnownHostIsDerivedAndHoldsOnlyTheMachineReached(t *testing.T) {
	fixture := newLaunchFixture(t)
	var derived string
	fixture.runner.answer = commandResult{WroteStandardInput: true}
	// The file must exist while the client runs and be named to it.
	inspecting := &inspectingRunner{recordingRunner: fixture.runner}
	fixture.dispatcher.runner = inspecting

	fixture.dispatcher.Dispatch(launchRecord(fixture, 900), []byte("{}"))
	derived = inspecting.knownHostsContent

	expected := "[192.0.2.10]:22 ssh-ed25519 " + testHostKeyBlob() + "\n"
	if derived != expected {
		t.Fatalf("the derived known host is %q rather than %q", derived, expected)
	}
	if strings.Count(derived, "\n") != 1 {
		t.Fatalf("the derived known host holds more than the machine reached: %q", derived)
	}
	entries, err := os.ReadDir(fixture.runtime)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("the derived known host survived its launch: %v", entries)
	}
}

// inspectingRunner reads the derived known-hosts file while the "client" runs,
// which is the only moment it is supposed to exist.
type inspectingRunner struct {
	*recordingRunner
	knownHostsContent string
}

func (runner *inspectingRunner) Run(ctx context.Context, program string, arguments []string, standardInput []byte) commandResult {
	for index, argument := range arguments {
		if argument == "-o" && index+1 < len(arguments) &&
			strings.HasPrefix(arguments[index+1], "UserKnownHostsFile=") {
			data, err := os.ReadFile(strings.TrimPrefix(arguments[index+1], "UserKnownHostsFile="))
			if err == nil {
				runner.knownHostsContent = string(data)
			}
		}
	}
	return runner.recordingRunner.Run(ctx, program, arguments, standardInput)
}

// TestTheConclusionNeverInventsAStrongerState walks every answer a launch can
// receive and holds it to the contract's table. The one that matters most is
// the first: `non lancé` is reserved for a failure the Controller observed
// before the first byte of the wrapper, and it is read off the write itself
// rather than guessed from a client's diagnostics.
func TestTheConclusionNeverInventsAStrongerState(t *testing.T) {
	for _, answer := range []struct {
		name     string
		result   commandResult
		state    string
		sentence string
		observed bool
	}{
		{
			name:     "a host key that changed, before any byte of the wrapper",
			result:   commandResult{WroteStandardInput: false, ExitCode: 255, StandardError: []byte("Host key verification failed.")},
			state:    DispatchNotLaunched,
			observed: true,
		},
		{
			name:     "a machine that refused and said why",
			result:   commandResult{WroteStandardInput: true, ExitCode: 1, StandardError: []byte("sequence 5 is not the exact successor of 3")},
			state:    DispatchMachineRefused,
			sentence: "sequence 5 is not the exact successor of 3",
		},
		{
			name:     "a channel that closed after the wrapper left",
			result:   commandResult{WroteStandardInput: true, Err: context.DeadlineExceeded},
			state:    DispatchLaunchedUnreported,
			observed: true,
		},
		{
			name:     "a report that names another dispatch",
			result:   commandResult{WroteStandardInput: true, ExitCode: 0, StandardOutput: []byte(`{"schema_version":1}`)},
			state:    DispatchLaunchedUnreported,
			observed: true,
		},
	} {
		concluded := concludeLaunch(reportedRecord(), testInfrastructureID,
			answer.result, maxDispatchMachineSentenceBytes)
		if concluded.State != answer.state || concluded.MachineSentence != answer.sentence {
			t.Fatalf("%s: state=%s sentence=%q", answer.name, concluded.State, concluded.MachineSentence)
		}
		if answer.observed != (concluded.ControllerObservation != "") {
			t.Fatalf("%s: observation=%q", answer.name, concluded.ControllerObservation)
		}
		// The two kinds of statement are never carried together: the registry
		// refuses a record that holds both.
		if concluded.MachineSentence != "" && concluded.ControllerObservation != "" {
			t.Fatalf("%s: the machine's sentence and this Controller's observation travelled together", answer.name)
		}
	}
}

// TestTheMachineSentenceIsBoundedAndPurgedButNeverRewritten: the sentence is
// kept verbatim, cut at the bound the registry validates, and stripped of what
// a view could read as structure rather than as text.
func TestTheMachineSentenceIsBoundedAndPurgedButNeverRewritten(t *testing.T) {
	// The line break and the tab become spaces, the NUL and the escape byte are
	// dropped, and everything a human could read stays exactly as the machine
	// wrote it — the visible residue of a colour sequence included. Purging what
	// a terminal would obey is not the same as rewriting what a machine said,
	// and this product does the first and never the second.
	sentence := boundedMachineSentence([]byte("refused:\n\tthe plan\x00 names\x1b[31m another machine"), 512)
	if sentence != "refused: the plan names[31m another machine" {
		t.Fatalf("the sentence was rewritten rather than purged: %q", sentence)
	}
	long := boundedMachineSentence([]byte(strings.Repeat("x", 4096)), maxDispatchMachineSentenceBytes)
	if len(long) != maxDispatchMachineSentenceBytes {
		t.Fatalf("a talkative machine was not bounded: %d bytes", len(long))
	}
	// And what the launch produces is always storable: the registry validates
	// both bounds, so a conclusion that could not be written would be a spent
	// authority with no conclusion at all.
	if len(launchObservation(strings.Repeat("o", 4096))) != maxDispatchObservationBytes {
		t.Fatal("this Controller's own observation is not held to the bound the registry validates")
	}
}

// TestAnEndpointSheetIsRefusedByName is the closed grammar of the one enrolment
// fact that decides where a command goes. Root-owned says who may write the
// sheet, never that what was written is one.
func TestAnEndpointSheetIsRefusedByName(t *testing.T) {
	valid := commandEndpoint{
		SchemaVersion: commandEndpointSchema, MachineID: "lab-machine-1",
		Host: "192.0.2.10", Port: 22, Account: "your-cloud-auxiliary", HostKey: testHostKeyBlob(),
	}
	if err := valid.validate("lab-machine-1"); err != nil {
		t.Fatalf("a well-formed sheet is refused: %v", err)
	}
	for name, hostile := range map[string]func(commandEndpoint) commandEndpoint{
		"another schema":        func(e commandEndpoint) commandEndpoint { e.SchemaVersion = 2; return e },
		"another machine":       func(e commandEndpoint) commandEndpoint { e.MachineID = "lab-machine-2"; return e },
		"no port":               func(e commandEndpoint) commandEndpoint { e.Port = 0; return e },
		"a port past the range": func(e commandEndpoint) commandEndpoint { e.Port = 65536; return e },
		"a host that is an option": func(e commandEndpoint) commandEndpoint {
			e.Host = "-oProxyCommand=touch /tmp/pwned"
			return e
		},
		"a host carrying a space": func(e commandEndpoint) commandEndpoint { e.Host = "192.0.2.10 evil"; return e },
		"an account with a slash": func(e commandEndpoint) commandEndpoint { e.Account = "root/../x"; return e },
		"a host key that is not base64": func(e commandEndpoint) commandEndpoint {
			e.HostKey = "not base64!"
			return e
		},
		"a host key of the wrong length": func(e commandEndpoint) commandEndpoint {
			e.HostKey = base64.StdEncoding.EncodeToString(make([]byte, 32))
			return e
		},
	} {
		if err := hostile(valid).validate("lab-machine-1"); err == nil {
			t.Fatalf("%s was accepted as a command endpoint", name)
		}
	}
}

// TestALaunchWithoutItsEnrolmentFactsSendsNothing: a machine with no sheet or no
// identity is not a machine this Controller can reach, and it says so rather
// than opening anything.
func TestALaunchWithoutItsEnrolmentFactsSendsNothing(t *testing.T) {
	for _, missing := range []string{"endpoint", "identity"} {
		fixture := newLaunchFixture(t)
		switch missing {
		case "endpoint":
			if err := os.Remove(filepath.Join(fixture.endpoints, "lab-machine-1.json")); err != nil {
				t.Fatal(err)
			}
		case "identity":
			if err := os.Remove(filepath.Join(fixture.identities, "lab-machine-1")); err != nil {
				t.Fatal(err)
			}
		}
		concluded := fixture.dispatcher.Dispatch(launchRecord(fixture, 900), []byte("{}"))
		if concluded.State != DispatchNotLaunched || concluded.MachineSentence != "" ||
			concluded.ControllerObservation == "" {
			t.Fatalf("missing %s: %+v", missing, concluded)
		}
		if fixture.runner.program != "" {
			t.Fatalf("missing %s: a client was still run", missing)
		}
	}
}

// TestTheLaunchRefusesPathsItCouldNotOwn: every path of the launch is absolute
// and canonical, because this service has no home and no user configuration —
// a relative entry would be resolved by something the product does not control.
func TestTheLaunchRefusesPathsItCouldNotOwn(t *testing.T) {
	runner := &recordingRunner{}
	clock := func() time.Time { return time.Unix(1, 0) }
	for _, hostile := range [][4]string{
		{"ssh", "/a", "/b", "/c"},
		{"/usr/bin/ssh", "a", "/b", "/c"},
		{"/usr/bin/ssh", "/a/../a", "/b", "/c"},
		{"/usr/bin/ssh", "/a", "/b/", "/c"},
	} {
		if _, err := newCommandDispatcher(testInfrastructureID, hostile[0], hostile[1], hostile[2], hostile[3],
			runner, clock); err == nil {
			t.Fatalf("the launch accepted %v", hostile)
		}
	}
	if _, err := newCommandDispatcher(testInfrastructureID, "/usr/bin/ssh", "/a", "/b", "/c", nil, clock); err == nil {
		t.Fatal("the launch accepted no client at all")
	}
	// A launch answers for one infrastructure, and it is what a report is held
	// against: one that named none could accept a report from anywhere.
	if _, err := newCommandDispatcher("not-a-uuid", "/usr/bin/ssh", "/a", "/b", "/c", runner, clock); err == nil {
		t.Fatal("the launch accepted an infrastructure it could not name")
	}
}

// reportedRecord is the dispatch the conclusion table is read against: one
// machine, one operation, one position, one pair.
func reportedRecord() DispatchRecord {
	return DispatchRecord{
		ApprovalSHA256: strings.Repeat("a", 64), MachineID: "lab-machine-1",
		Operation: "deploy_oci_probe", ApprovalEpoch: 1, Sequence: 7,
		PlanSHA256: strings.Repeat("b", 64), RollbackSHA256: strings.Repeat("c", 64),
		State: DispatchInFlight, AcceptedAtUnix: 1, ExpiresAtUnix: 901,
	}
}

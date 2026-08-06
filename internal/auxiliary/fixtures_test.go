package auxiliary

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/ldesfontaine/your-cloud/internal/approval"
	"github.com/ldesfontaine/your-cloud/internal/plan"
)

const (
	fixtureInfrastructure = "8f14e45f-ceea-4167-a8b1-1f7bd0a0f4c2"
	fixtureMachine        = "lab-machine-1"
	fixturePort           = 8080
)

// frozenPair is the pair a Controller would have built and transported.
func frozenPair(t *testing.T, operation string, port int) plan.Frozen {
	t.Helper()
	pair, err := plan.BuildPair(operation, fixtureInfrastructure, fixtureMachine, port)
	if err != nil {
		t.Fatal(err)
	}
	frozen, err := pair.Freeze()
	if err != nil {
		t.Fatal(err)
	}
	return frozen
}

// signedApprovalDocument is a whole signed approval as it arrives on the wire.
//
// Its signature is syntactically valid and cryptographically meaningless, which
// is exactly right here: these tests are about what the input framing and the
// application accept, and no path in this package verifies a signature — that is
// the approval package's authority and it has its own vectors.
func signedApprovalDocument(t *testing.T, operation string, frozen plan.Frozen, mutate func(*approval.Envelope)) []byte {
	t.Helper()
	privileges := []string{approval.PrivilegeReadLocalState}
	if operation != approval.OperationDiagnoseProtocolReadOnly {
		privileges = []string{approval.PrivilegeMutateLocalState, approval.PrivilegeReadLocalState}
	}
	envelope := approval.Envelope{
		SchemaVersion:     approval.SchemaVersion,
		InfrastructureID:  fixtureInfrastructure,
		MachineID:         fixtureMachine,
		ApprovalEpoch:     1,
		Sequence:          1,
		Operation:         operation,
		PlanSHA256:        frozen.PlanSHA256,
		RollbackSHA256:    frozen.RollbackSHA256,
		Privileges:        privileges,
		IssuedAtUnix:      1_754_000_000,
		ExpiresAtUnix:     1_754_000_300,
		ApprovalPublicKey: base64.RawURLEncoding.EncodeToString(make([]byte, ed25519.PublicKeySize)),
	}
	if mutate != nil {
		mutate(&envelope)
	}
	document, err := json.Marshal(approval.SignedApproval{
		Envelope:  envelope,
		Signature: base64.RawURLEncoding.EncodeToString(make([]byte, ed25519.SignatureSize)),
	})
	if err != nil {
		t.Fatal(err)
	}
	return document
}

// wrapperDocument is the mutating shape of the standard input.
func wrapperDocument(t *testing.T, signed, planDocument, rollbackDocument []byte) []byte {
	t.Helper()
	document, err := json.Marshal(map[string]any{
		"signed_approval": json.RawMessage(signed),
		"plan":            string(planDocument),
		"rollback":        string(rollbackDocument),
	})
	if err != nil {
		t.Fatal(err)
	}
	return document
}

// quotedJSON renders one document as the JSON string a wrapper carries it in.
func quotedJSON(t *testing.T, value string) string {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(encoded)
}

// approvedApplication is what the Auxiliary holds once the approval is accepted:
// the acceptance the machine's own anchor produced, and the two documents it
// still has to hold against the digests that acceptance names.
func approvedApplication(t *testing.T, operation string, port int) (*approval.Acceptance, *Input) {
	t.Helper()
	frozen := frozenPair(t, operation, port)
	accepted := &approval.Acceptance{
		Envelope: &approval.Envelope{
			SchemaVersion:    approval.SchemaVersion,
			InfrastructureID: fixtureInfrastructure,
			MachineID:        fixtureMachine,
			ApprovalEpoch:    1,
			Sequence:         1,
			Operation:        operation,
			PlanSHA256:       frozen.PlanSHA256,
			RollbackSHA256:   frozen.RollbackSHA256,
			Privileges:       []string{approval.PrivilegeMutateLocalState, approval.PrivilegeReadLocalState},
		},
		State: &approval.State{
			SchemaVersion:    approval.SchemaVersion,
			InfrastructureID: fixtureInfrastructure,
			MachineID:        fixtureMachine,
			ApprovalEpoch:    1,
			ConsumedSequence: 1,
		},
	}
	input := &Input{
		Kind:             KindApply,
		PlanDocument:     frozen.PlanDocument,
		RollbackDocument: frozen.RollbackDocument,
	}
	return accepted, input
}

// capableMachine is a host that can run the flow, with no probe on it yet.
func capableMachine() Capabilities {
	return Capabilities{
		Systemd:                true,
		UnifiedCgroupHierarchy: true,
		PodmanPresent:          true,
	}
}

// fakeExecutor is the whole machine, replaced.
//
// It records reads and effects separately so that a refusal can be proven to
// have happened before anything was touched rather than after something was
// tidied away.
type fakeExecutor struct {
	capabilities      Capabilities
	afterAccount      *Capabilities
	unit              []byte
	unitPresent       bool
	active            bool
	image             string
	failures          map[string]error
	reads             []string
	effects           []string
	writtenUnit       []byte
	pulled            []string
	removedImages     []string
	startedServices   []string
	stoppedServices   []string
	accountsCreated   []string
	lingeringAccounts []string
	probedPorts       []int
}

func newFakeExecutor() *fakeExecutor {
	return &fakeExecutor{capabilities: capableMachine(), failures: map[string]error{}}
}

func (executor *fakeExecutor) fail(name string) error {
	return executor.failures[name]
}

func (executor *fakeExecutor) Capabilities(account string) (Capabilities, error) {
	executor.reads = append(executor.reads, "Capabilities")
	if err := executor.fail("Capabilities"); err != nil {
		return Capabilities{}, err
	}
	if executor.capabilities.AccountPresent && executor.afterAccount != nil {
		return *executor.afterAccount, nil
	}
	return executor.capabilities, nil
}

func (executor *fakeExecutor) CreateProbeAccount(account, home string) error {
	executor.effects = append(executor.effects, "CreateProbeAccount")
	if err := executor.fail("CreateProbeAccount"); err != nil {
		return err
	}
	executor.accountsCreated = append(executor.accountsCreated, account+" "+home)
	executor.capabilities.AccountPresent = true
	return nil
}

func (executor *fakeExecutor) EnableLinger(account string) error {
	executor.effects = append(executor.effects, "EnableLinger")
	if err := executor.fail("EnableLinger"); err != nil {
		return err
	}
	executor.lingeringAccounts = append(executor.lingeringAccounts, account)
	return nil
}

func (executor *fakeExecutor) ReadUnitFile(path string) ([]byte, bool, error) {
	executor.reads = append(executor.reads, "ReadUnitFile")
	if err := executor.fail("ReadUnitFile"); err != nil {
		return nil, false, err
	}
	if !executor.unitPresent {
		return nil, false, nil
	}
	return executor.unit, true, nil
}

func (executor *fakeExecutor) WriteUnitFile(path string, content []byte) error {
	executor.effects = append(executor.effects, "WriteUnitFile")
	if err := executor.fail("WriteUnitFile"); err != nil {
		return err
	}
	executor.writtenUnit = content
	executor.unit = content
	executor.unitPresent = true
	return nil
}

func (executor *fakeExecutor) RemoveUnitFile(path string) error {
	executor.effects = append(executor.effects, "RemoveUnitFile")
	if err := executor.fail("RemoveUnitFile"); err != nil {
		return err
	}
	executor.unit = nil
	executor.unitPresent = false
	return nil
}

func (executor *fakeExecutor) ReloadUserUnits(account string) error {
	executor.effects = append(executor.effects, "ReloadUserUnits")
	return executor.fail("ReloadUserUnits")
}

func (executor *fakeExecutor) StartService(account, service string) error {
	executor.effects = append(executor.effects, "StartService")
	if err := executor.fail("StartService"); err != nil {
		return err
	}
	executor.startedServices = append(executor.startedServices, service)
	executor.active = true
	return nil
}

func (executor *fakeExecutor) StopService(account, service string) error {
	executor.effects = append(executor.effects, "StopService")
	if err := executor.fail("StopService"); err != nil {
		return err
	}
	executor.stoppedServices = append(executor.stoppedServices, service)
	executor.active = false
	return nil
}

func (executor *fakeExecutor) ServiceActive(account, service string) (bool, error) {
	executor.reads = append(executor.reads, "ServiceActive")
	if err := executor.fail("ServiceActive"); err != nil {
		return false, err
	}
	return executor.active, nil
}

func (executor *fakeExecutor) PullImage(account, reference string) error {
	executor.effects = append(executor.effects, "PullImage")
	if err := executor.fail("PullImage"); err != nil {
		return err
	}
	executor.pulled = append(executor.pulled, reference)
	executor.image = reference
	return nil
}

func (executor *fakeExecutor) RemoveImage(account, reference string) error {
	executor.effects = append(executor.effects, "RemoveImage")
	if err := executor.fail("RemoveImage"); err != nil {
		return err
	}
	executor.removedImages = append(executor.removedImages, reference)
	executor.image = ""
	return nil
}

func (executor *fakeExecutor) ContainerImage(account, container string) (string, error) {
	executor.reads = append(executor.reads, "ContainerImage")
	if err := executor.fail("ContainerImage"); err != nil {
		return "", err
	}
	if !executor.active {
		return "", nil
	}
	return executor.image, nil
}

func (executor *fakeExecutor) ProbeAnswers(port int) error {
	executor.reads = append(executor.reads, "ProbeAnswers")
	executor.probedPorts = append(executor.probedPorts, port)
	return executor.fail("ProbeAnswers")
}

// deployedMachine is a machine already holding exactly the approved probe.
func deployedMachine(t *testing.T, port int) *fakeExecutor {
	t.Helper()
	document, err := plan.Decode(frozenPair(t, plan.OperationDeployOCIProbe, port).PlanDocument)
	if err != nil {
		t.Fatal(err)
	}
	executor := newFakeExecutor()
	executor.capabilities.AccountPresent = true
	executor.capabilities.RootlessPodman = true
	executor.unit = renderUnit(document)
	executor.unitPresent = true
	executor.active = true
	executor.image = PinnedImage()
	return executor
}

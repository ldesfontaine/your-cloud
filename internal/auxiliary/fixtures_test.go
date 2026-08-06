package auxiliary

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/ldesfontaine/your-cloud/internal/approval"
	"github.com/ldesfontaine/your-cloud/internal/plan"
)

const (
	fixtureInfrastructure = "8f14e45f-ceea-4167-a8b1-1f7bd0a0f4c2"
	fixtureMachine        = "lab-machine-1"
	fixturePort           = 8080

	// fixtureRouteHost is the one declared name these tests publish. It is a
	// `.test` name on purpose: the palier proves HTTPS on a name declared in the
	// LAB, not a public emission.
	fixtureRouteHost = "lab.example.test"

	// fixtureIssuedAt and fixtureExpiresAt frame the one window an approval of
	// this palier is presentable in, and fixtureNow is one instant inside it.
	fixtureIssuedAt  = 1_754_000_000
	fixtureExpiresAt = 1_754_000_300
	fixtureNow       = 1_754_000_100
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
	envelope := probeEnvelope(operation, frozen, 1)
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

// probeEnvelope is the envelope a Console signs for one frozen pair.
//
// It carries the zero public key, which is the right default here: every test
// that only reads the framing needs a well-formed envelope and no authority at
// all, and every test that needs authority replaces the key with the one its own
// anchor names.
func probeEnvelope(operation string, frozen plan.Frozen, sequence uint64) approval.Envelope {
	privileges := []string{approval.PrivilegeReadLocalState}
	if operation != approval.OperationDiagnoseProtocolReadOnly {
		privileges = []string{approval.PrivilegeMutateLocalState, approval.PrivilegeReadLocalState}
	}
	return approval.Envelope{
		SchemaVersion:     approval.SchemaVersion,
		InfrastructureID:  fixtureInfrastructure,
		MachineID:         fixtureMachine,
		ApprovalEpoch:     1,
		Sequence:          sequence,
		Operation:         operation,
		PlanSHA256:        frozen.PlanSHA256,
		RollbackSHA256:    frozen.RollbackSHA256,
		Privileges:        privileges,
		IssuedAtUnix:      fixtureIssuedAt,
		ExpiresAtUnix:     fixtureExpiresAt,
		ApprovalPublicKey: base64.RawURLEncoding.EncodeToString(make([]byte, ed25519.PublicKeySize)),
	}
}

// approvalAuthority is one human key as a machine anchors it.
//
// It exists so that the refusals an approval owns — an expired envelope, a
// sequence already spent — can be walked through the very chain a real
// invocation walks, instead of through an acceptance a test wrote for itself.
type approvalAuthority struct {
	anchor  *approval.Anchor
	private ed25519.PrivateKey
}

func fixtureAuthority(t *testing.T) *approvalAuthority {
	t.Helper()
	public, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	return &approvalAuthority{
		anchor: &approval.Anchor{
			SchemaVersion:     approval.SchemaVersion,
			InfrastructureID:  fixtureInfrastructure,
			MachineID:         fixtureMachine,
			ApprovalEpoch:     1,
			ApprovalPublicKey: base64.RawURLEncoding.EncodeToString(public),
		},
		private: private,
	}
}

// approve signs one envelope over the transcript the machine will rebuild, and
// returns the whole standard input a Controller would deliver for it.
func (authority *approvalAuthority) approve(t *testing.T, envelope approval.Envelope, frozen plan.Frozen) []byte {
	t.Helper()
	envelope.ApprovalPublicKey = authority.anchor.ApprovalPublicKey
	transcript, err := envelope.SigningTranscript()
	if err != nil {
		t.Fatal(err)
	}
	signed, err := json.Marshal(approval.SignedApproval{
		Envelope:  envelope,
		Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(authority.private, transcript)),
	})
	if err != nil {
		t.Fatal(err)
	}
	return wrapperDocument(t, signed, frozen.PlanDocument, frozen.RollbackDocument)
}

// presented runs one standard input through the whole chain a real invocation
// takes: the closed framing, the acceptance under this machine's own anchor and
// its own anti-replay state, then the application. No gate is stepped over.
func presented(
	t *testing.T,
	executor Executor,
	authority *approvalAuthority,
	directory string,
	document []byte,
	now uint64,
) (*Application, error) {
	t.Helper()
	input, err := DecodeInput(document)
	if err != nil {
		return nil, err
	}
	accepted, err := approval.AcceptMutating(directory, authority.anchor, input.Signed, now)
	if err != nil {
		return nil, err
	}
	return Apply(executor, accepted, input)
}

// rootOwnedAntiReplayState is the only directory the approval package accepts: a
// real one, owned by root and writable by nobody else. Building it requires
// being root, so the checks that need a spent sequence run on the isolated root
// LAB runner and are skipped elsewhere rather than weakened here.
func rootOwnedAntiReplayState(t *testing.T) string {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("a real anti-replay state requires the isolated root LAB runner")
	}
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	return directory
}

// forgedPlan renders one plan document field by field, with exactly the
// alterations a case asks for: a replaced value, an absent field when the value
// is empty, or a field the closed schema does not have at all.
//
// It is written as text rather than built through the plan package because half
// of the documents the refusal matrix presents are documents that package
// refuses to build — a floating tag, an absent digest, a smuggled volume. A
// refusal that can only be reached through the encoder which already refuses it
// is a refusal nothing proved.
func forgedPlan(t *testing.T, operation string, port int, altered map[string]string) []byte {
	t.Helper()
	nominal := [][2]string{
		{"schema_version", strconv.Itoa(plan.SchemaVersion)},
		{"infrastructure_id", quotedJSON(t, fixtureInfrastructure)},
		{"machine_id", quotedJSON(t, fixtureMachine)},
		{"operation", quotedJSON(t, operation)},
		{"image_reference", quotedJSON(t, plan.ProbeImageReference)},
		{"image_digest", quotedJSON(t, plan.ProbeImageDigest)},
		{"local_port", strconv.Itoa(port)},
	}
	return forgeDocument(t, nominal, altered)
}

// forgeDocument renders one document from its nominal field list and exactly the
// alterations a case asks for, and is the one place the three schemas' forgers
// share.
//
// A named field whose value is empty is left out of the document entirely, a
// named field with a value replaces the nominal one in place, and anything the
// case names beyond the closed list is appended in one sorted order, so that a
// forged document is the same bytes on every run.
func forgeDocument(t *testing.T, nominal [][2]string, altered map[string]string) []byte {
	t.Helper()
	fields := make([]string, 0, len(nominal)+len(altered))
	canonical := map[string]bool{}
	for _, field := range nominal {
		canonical[field[0]] = true
		value, replaced := altered[field[0]]
		if !replaced {
			fields = append(fields, quotedJSON(t, field[0])+":"+field[1])
			continue
		}
		if value != "" {
			fields = append(fields, quotedJSON(t, field[0])+":"+value)
		}
	}
	smuggled := make([]string, 0, len(altered))
	for name := range altered {
		if !canonical[name] {
			smuggled = append(smuggled, name)
		}
	}
	sort.Strings(smuggled)
	for _, name := range smuggled {
		fields = append(fields, quotedJSON(t, name)+":"+altered[name])
	}
	return []byte("{" + strings.Join(fields, ",") + "}")
}

// forgedEntrypointPlan and forgedRoutePlan are the same forger over the two
// other closed field lists of schema 2.
func forgedEntrypointPlan(t *testing.T, operation string, altered map[string]string) []byte {
	t.Helper()
	return forgeDocument(t, [][2]string{
		{"schema_version", strconv.Itoa(plan.SchemaVersionV2)},
		{"infrastructure_id", quotedJSON(t, fixtureInfrastructure)},
		{"machine_id", quotedJSON(t, fixtureMachine)},
		{"operation", quotedJSON(t, operation)},
		{"image_reference", quotedJSON(t, plan.EntrypointImageReference)},
		{"image_digest", quotedJSON(t, plan.EntrypointImageDigest)},
	}, altered)
}

func forgedRoutePlan(t *testing.T, operation, host string, port int, altered map[string]string) []byte {
	t.Helper()
	return forgeDocument(t, [][2]string{
		{"schema_version", strconv.Itoa(plan.SchemaVersionV2)},
		{"infrastructure_id", quotedJSON(t, fixtureInfrastructure)},
		{"machine_id", quotedJSON(t, fixtureMachine)},
		{"operation", quotedJSON(t, operation)},
		{"route_host", quotedJSON(t, host)},
		{"backend_port", strconv.Itoa(port)},
	}, altered)
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
	capabilities Capabilities
	afterAccount *Capabilities
	// files is every root-owned file this machine holds, by path. It is keyed by
	// path rather than held as one sheet because a machine of this palier holds
	// several at once: the sheet of a managed service, the sheet of the entry, the
	// entry's static configuration and one fragment per published route. A test
	// that could only describe one file could not describe a route at all.
	files              map[string][]byte
	policy             []byte
	policyPresent      bool
	policyApplications int
	directoriesEnsured int
	active             bool
	image              string
	failures           map[string]error
	tolerated          map[string]int
	calls              map[string]int
	reads              []string
	effects            []string
	writtenUnit        []byte
	writtenPaths       []string
	removedPaths       []string
	pulled             []string
	removedImages      []string
	startedServices    []string
	stoppedServices    []string
	accountsCreated    []string
	accountComments    []string
	lingeringAccounts  []string
	probedPorts        []int
	probedContentTypes []string
	verifiedRoutes     []string
	entrypointChecks   int
}

func newFakeExecutor() *fakeExecutor {
	return &fakeExecutor{
		capabilities: capableMachine(),
		files:        map[string][]byte{},
		failures:     map[string]error{},
		tolerated:    map[string]int{},
		calls:        map[string]int{},
	}
}

// hold, held, holds and drop are how a test describes the files one machine
// carries, so that no case has to reach into the map and none of them can
// describe a file without saying where it is.
func (executor *fakeExecutor) hold(path string, content []byte) {
	executor.files[path] = content
}

func (executor *fakeExecutor) held(path string) []byte { return executor.files[path] }

func (executor *fakeExecutor) holds(path string) bool {
	_, present := executor.files[path]
	return present
}

func (executor *fakeExecutor) drop(path string) { delete(executor.files, path) }

// fail is how one seam call is made to refuse.
//
// A failure declared alone refuses every time. A failure declared beside a
// tolerated count refuses only once that many calls have already succeeded,
// which is what lets a machine answer an operation and then stop answering its
// rollback — the sequence a partial state is actually reached by.
func (executor *fakeExecutor) fail(name string) error {
	err, failing := executor.failures[name]
	if !failing {
		return nil
	}
	executor.calls[name]++
	if executor.calls[name] <= executor.tolerated[name] {
		return nil
	}
	return err
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

func (executor *fakeExecutor) CreateProbeAccount(account, home, comment string) error {
	executor.effects = append(executor.effects, "CreateProbeAccount")
	if err := executor.fail("CreateProbeAccount"); err != nil {
		return err
	}
	executor.accountsCreated = append(executor.accountsCreated, account+" "+home)
	executor.accountComments = append(executor.accountComments, comment)
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
	content, present := executor.files[path]
	if !present {
		return nil, false, nil
	}
	return content, true, nil
}

func (executor *fakeExecutor) WriteUnitFile(path string, content []byte) error {
	executor.effects = append(executor.effects, "WriteUnitFile")
	if err := executor.fail("WriteUnitFile"); err != nil {
		return err
	}
	executor.writtenUnit = content
	executor.writtenPaths = append(executor.writtenPaths, path)
	executor.hold(path, content)
	return nil
}

func (executor *fakeExecutor) RemoveUnitFile(path string) error {
	executor.effects = append(executor.effects, "RemoveUnitFile")
	if err := executor.fail("RemoveUnitFile"); err != nil {
		return err
	}
	executor.removedPaths = append(executor.removedPaths, path)
	executor.drop(path)
	return nil
}

func (executor *fakeExecutor) EnsureEntrypointDirectories() error {
	executor.effects = append(executor.effects, "EnsureEntrypointDirectories")
	if err := executor.fail("EnsureEntrypointDirectories"); err != nil {
		return err
	}
	executor.directoriesEnsured++
	return nil
}

// ListRouteFragments answers from the files this machine holds, so that a test
// which published a route does not also have to declare that the route exists.
func (executor *fakeExecutor) ListRouteFragments() ([]string, error) {
	executor.reads = append(executor.reads, "ListRouteFragments")
	if err := executor.fail("ListRouteFragments"); err != nil {
		return nil, err
	}
	fragments := []string{}
	for path := range executor.files {
		if strings.HasPrefix(path, entrypointFragmentDirectory+"/") &&
			strings.HasSuffix(path, routeFragmentSuffix) {
			fragments = append(fragments, strings.TrimPrefix(path, entrypointFragmentDirectory+"/"))
		}
	}
	sort.Strings(fragments)
	return fragments, nil
}

func (executor *fakeExecutor) HostPortsPolicy() ([]byte, bool, error) {
	executor.reads = append(executor.reads, "HostPortsPolicy")
	if err := executor.fail("HostPortsPolicy"); err != nil {
		return nil, false, err
	}
	if !executor.policyPresent {
		return nil, false, nil
	}
	return executor.policy, true, nil
}

func (executor *fakeExecutor) WriteHostPortsPolicy(content []byte) error {
	executor.effects = append(executor.effects, "WriteHostPortsPolicy")
	if err := executor.fail("WriteHostPortsPolicy"); err != nil {
		return err
	}
	executor.policy = content
	executor.policyPresent = true
	executor.policyApplications++
	return nil
}

func (executor *fakeExecutor) RemoveHostPortsPolicy() error {
	executor.effects = append(executor.effects, "RemoveHostPortsPolicy")
	if err := executor.fail("RemoveHostPortsPolicy"); err != nil {
		return err
	}
	executor.policy = nil
	executor.policyPresent = false
	executor.policyApplications++
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

func (executor *fakeExecutor) ProbeAnswers(port int, expectedContentType string) error {
	executor.reads = append(executor.reads, "ProbeAnswers")
	executor.probedPorts = append(executor.probedPorts, port)
	executor.probedContentTypes = append(executor.probedContentTypes, expectedContentType)
	return executor.fail("ProbeAnswers")
}

func (executor *fakeExecutor) EntrypointAnswers() error {
	executor.reads = append(executor.reads, "EntrypointAnswers")
	executor.entrypointChecks++
	return executor.fail("EntrypointAnswers")
}

func (executor *fakeExecutor) RouteAnswers(routeHost string) error {
	executor.reads = append(executor.reads, "RouteAnswers")
	executor.verifiedRoutes = append(executor.verifiedRoutes, routeHost)
	return executor.fail("RouteAnswers")
}

// halfWrittenMachine is what a cut in the middle of a deployment leaves behind:
// the sheet is on disk, the service was never started, and nothing on the
// machine says whether the run that wrote it meant to stop there.
func halfWrittenMachine(t *testing.T, port int) *fakeExecutor {
	t.Helper()
	document, err := plan.Decode(frozenPair(t, plan.OperationDeployOCIProbe, port).PlanDocument)
	if err != nil {
		t.Fatal(err)
	}
	executor := newFakeExecutor()
	executor.capabilities.AccountPresent = true
	executor.capabilities.RootlessPodman = true
	executor.hold(probePlacement.unitPath(), renderUnit(document))
	return executor
}

// frozenServicePair is the schema 2 pair a Controller would have built and
// transported for one managed web service.
func frozenServicePair(t *testing.T, operation, serviceProfile string, port int) plan.Frozen {
	t.Helper()
	pair, err := plan.BuildWebServicePair(operation, fixtureInfrastructure, fixtureMachine, serviceProfile, port)
	if err != nil {
		t.Fatal(err)
	}
	frozen, err := pair.Freeze()
	if err != nil {
		t.Fatal(err)
	}
	return frozen
}

// frozenEntrypointPair and frozenRoutePair are the two other schema 2 pairs a
// Controller would have built and transported.
func frozenEntrypointPair(t *testing.T, operation string) plan.Frozen {
	t.Helper()
	pair, err := plan.BuildEntrypointPair(operation, fixtureInfrastructure, fixtureMachine)
	if err != nil {
		t.Fatal(err)
	}
	frozen, err := pair.Freeze()
	if err != nil {
		t.Fatal(err)
	}
	return frozen
}

func frozenRoutePair(t *testing.T, operation, host string, port int) plan.Frozen {
	t.Helper()
	pair, err := plan.BuildRoutePair(operation, fixtureInfrastructure, fixtureMachine, host, port)
	if err != nil {
		t.Fatal(err)
	}
	frozen, err := pair.Freeze()
	if err != nil {
		t.Fatal(err)
	}
	return frozen
}

// approvedFrozenPair is what the Auxiliary holds once an approval over any
// frozen pair is accepted, whatever schema that pair was written in.
//
// It is the same acceptance approvedApplication builds, with the operation and
// the two digests of the pair it is given, so that a schema 2 case differs from
// a schema 1 case by the documents alone and never by the gate that let them in.
func approvedFrozenPair(operation string, frozen plan.Frozen) (*approval.Acceptance, *Input) {
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
	return accepted, &Input{
		Kind:             KindApply,
		PlanDocument:     frozen.PlanDocument,
		RollbackDocument: frozen.RollbackDocument,
	}
}

// approvedService is the nominal schema 2 subject of the bentopdf profile.
func approvedService(t *testing.T, operation string, port int) (*approval.Acceptance, *Input) {
	t.Helper()
	return approvedFrozenPair(operation, frozenServicePair(t, operation, plan.ServiceProfileBentoPDF, port))
}

// approvedOperation is the nominal subject of any operation this Auxiliary
// performs, built in the schema that operation belongs to.
//
// It exists so that a check about the machine rather than about a document — the
// capabilities preflight above all — walks the four operations without repeating
// which schema each of them is written in.
func approvedOperation(t *testing.T, operation string, port int) (*approval.Acceptance, *Input) {
	t.Helper()
	switch operation {
	case plan.OperationDeployWebService, plan.OperationRemoveWebService:
		return approvedService(t, operation, port)
	case plan.OperationDeployEntrypoint, plan.OperationRemoveEntrypoint:
		return approvedEntrypoint(t, operation)
	case plan.OperationPublishRoute, plan.OperationRetireRoute:
		return approvedRoute(t, operation, fixtureRouteHost, port)
	default:
		return approvedApplication(t, operation, port)
	}
}

// forgedServicePlan renders one schema 2 web service document field by field,
// with exactly the alterations a case asks for, for the same reason forgedPlan
// exists: half the documents a refusal matrix presents are documents the plan
// package refuses to build.
func forgedServicePlan(t *testing.T, operation string, port int, altered map[string]string) []byte {
	t.Helper()
	nominal := [][2]string{
		{"schema_version", strconv.Itoa(plan.SchemaVersionV2)},
		{"infrastructure_id", quotedJSON(t, fixtureInfrastructure)},
		{"machine_id", quotedJSON(t, fixtureMachine)},
		{"operation", quotedJSON(t, operation)},
		{"service_profile", quotedJSON(t, plan.ServiceProfileBentoPDF)},
		{"image_reference", quotedJSON(t, plan.BentoPDFImageReference)},
		{"image_digest", quotedJSON(t, plan.BentoPDFImageDigest)},
		{"local_port", strconv.Itoa(port)},
	}
	return forgeDocument(t, nominal, altered)
}

// serviceMachine is a machine that can run the flow with the bentopdf account
// already created, and nothing of the service on it yet.
func serviceMachine() *fakeExecutor {
	executor := newFakeExecutor()
	executor.capabilities.AccountPresent = true
	executor.capabilities.RootlessPodman = true
	return executor
}

// deployedServiceMachine is a machine already holding exactly the approved
// managed service, sheet bytes included.
func deployedServiceMachine(t *testing.T, port int) *fakeExecutor {
	t.Helper()
	executor := serviceMachine()
	executor.hold(bentoPDFPlacement.unitPath(), renderSheet(bentoPDFPlacement, port))
	executor.active = true
	executor.image = bentoPDFPlacement.image
	return executor
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
	executor.hold(probePlacement.unitPath(), renderUnit(document))
	executor.active = true
	executor.image = PinnedImage()
	return executor
}

// approvedEntrypoint and approvedRoute are the nominal schema 2 subjects of the
// two operation groups this issue performs.
func approvedEntrypoint(t *testing.T, operation string) (*approval.Acceptance, *Input) {
	t.Helper()
	return approvedFrozenPair(operation, frozenEntrypointPair(t, operation))
}

func approvedRoute(t *testing.T, operation, host string, port int) (*approval.Acceptance, *Input) {
	t.Helper()
	return approvedFrozenPair(operation, frozenRoutePair(t, operation, host, port))
}

// entrypointMachine is a machine that can run the flow with the entrypoint
// account already created, and nothing of the entry on it yet.
func entrypointMachine() *fakeExecutor {
	executor := newFakeExecutor()
	executor.capabilities.AccountPresent = true
	executor.capabilities.RootlessPodman = true
	return executor
}

// deployedEntrypointMachine is a machine already holding exactly the approved
// entrypoint: the sheet, the static configuration, the host policy the plan
// declares, the running service and the pinned image.
func deployedEntrypointMachine() *fakeExecutor {
	executor := entrypointMachine()
	executor.hold(entrypointPlacement.unitPath(), renderEntrypointSheet())
	executor.hold(entrypointConfigurationPath, renderEntrypointConfiguration())
	executor.policy = renderHostPortsPolicy()
	executor.policyPresent = true
	executor.active = true
	executor.image = entrypointPlacement.image
	return executor
}

// routableMachine is what a route plan needs to find: an entry that is there,
// and one managed service publishing the loopback port the route names.
//
// It carries the sheets of both and nothing of the entry's running state,
// because publishing a route reads neither the service nor the container: a
// route is one file beside two sheets.
func routableMachine(port int) *fakeExecutor {
	executor := entrypointMachine()
	executor.hold(entrypointPlacement.unitPath(), renderEntrypointSheet())
	executor.hold(bentoPDFPlacement.unitPath(), renderSheet(bentoPDFPlacement, port))
	return executor
}

// publishedRouteMachine is that same machine with the fragment of one declared
// name already written exactly as the plan describes it.
func publishedRouteMachine(host string, port int) *fakeExecutor {
	executor := routableMachine(port)
	executor.hold(routeFragmentPath(host), renderRouteFragment(host, port))
	return executor
}

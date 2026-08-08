package auxiliary

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ldesfontaine/your-cloud/internal/approval"
	"github.com/ldesfontaine/your-cloud/internal/plan"
	"github.com/ldesfontaine/your-cloud/internal/servicedefinition"
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
	verifiedLinkRoutes []string
	entrypointChecks   int
	// The passage's own state. linkPrivateKey is what this fake machine "wrote"
	// when it was asked for a key, and it is deliberately a value no seam of the
	// Executor can return: the tests that prove no private material travels grep
	// for exactly these bytes in everything a run produces, so a leak anywhere
	// would have to spell them.
	linkPrivateKey        string
	linkPublicKey         string
	linkKeyPresent        bool
	linkKeysGenerated     int
	linkActive            bool
	linkInterfaceRemovals int
	networkEnablings      int
	networkReloads        int
	// nftTables is this fake machine's kernel, as far as nftables is concerned:
	// one entry per table it holds. It is keyed by the family and the name
	// together, because that is what an effect of this package names, and it is
	// seeded with a table of somebody else's in the cases that prove a removal
	// takes away one table and never a ruleset.
	nftTables map[string][]byte
	// linkRules is the file the bounds live in on disk, and linkRuleApplications
	// counts how many times a run made the kernel read it — an application that
	// wrote the file without loading it would leave the two disagreeing, which is
	// exactly what the seam exists to prevent.
	linkRules            []byte
	linkRulesPresent     bool
	linkRuleApplications int
	// linkPolicy is the interface-scoped host relaxation, held exactly as the
	// entrypoint's own policy is.
	linkPolicy             []byte
	linkPolicyPresent      bool
	linkPolicyApplications int
	// linkRulesAtBoot is whether the oneshot unit would run at the next boot, and
	// the two counters say how many times a run decided it.
	linkRulesAtBoot    bool
	linkBootEnablings  int
	linkBootDisablings int
	// accountIdentifier is what this fake machine allocated to the service account
	// it holds. It is a machine value in the tests exactly as it is on a real host:
	// no document carries it, and the confinement table is rendered from whatever
	// this field says.
	accountIdentifier int
	// dataPresent and dataContent are the durable directory of a data-bearing
	// profile and what is inside it.
	//
	// The content is one opaque string rather than a tree, because every property
	// this palier holds about the data is about its *identity*: that a removal
	// keeps it, that a redeployment finds the same one, that a return brings a
	// named one back. A tree would make those the same assertions with more
	// machinery between them.
	dataPresent bool
	dataContent string
	dataEnsured int
	// dataDirectories is every directory a run asked this machine to hold for a
	// service, in the order it asked. It is a list rather than a count because the
	// third door derives one directory per declared volume, and what a case has to
	// read is which paths those were.
	dataDirectories []string
	dataRestores    int
	// secrets is one generated value per key path, and secretEnvironments is the
	// file each placement's sheet reads them back from.
	//
	// They are held apart exactly as the real machine holds them: the values survive
	// everything, and the environment file is rewritten from the keys of whichever
	// revision was deployed last. secretsGenerated counts the draws, so "a
	// redeployment regenerated nothing" is a number rather than an impression.
	secrets            map[string]string
	secretEnvironments map[string]string
	secretsGenerated   int
	// archives is every archive this fake machine holds, by path, each holding the
	// data content that was archived into it. Keying by path is what lets a case
	// assert that the reserved slot was written without the seam that lists
	// ordinary slots ever reporting it.
	archives map[string]string
	// The confinement table, held exactly as the passage's bounds are: a file, a
	// kernel that read it, and a unit that would put it back at the next boot.
	egressRules            []byte
	egressWrites           [][]byte
	egressRulesPresent     bool
	egressRuleApplications int
	egressAtBoot           bool
	egressBootEnablings    int
	egressBootDisablings   int
}

func newFakeExecutor() *fakeExecutor {
	return &fakeExecutor{
		capabilities:       capableMachine(),
		files:              map[string][]byte{},
		failures:           map[string]error{},
		tolerated:          map[string]int{},
		calls:              map[string]int{},
		nftTables:          map[string][]byte{},
		archives:           map[string]string{},
		secrets:            map[string]string{},
		secretEnvironments: map[string]string{},
		accountIdentifier:  fixtureAccountIdentifier,
	}
}

// fixtureSecretValue is what this fake machine draws for one generated value. It
// is a sentence rather than a plausible secret, so that a test grepping a report,
// an error or an observation for it can only match if something really did carry
// a value, and never by coincidence.
func fixtureSecretValue(draw int) string {
	return "THIS-GENERATED-VALUE-MUST-NEVER-LEAVE-ITS-MACHINE-" + strconv.Itoa(draw)
}

const (
	// fixtureAccountIdentifier is what these machines allocated to the service
	// account. It is deliberately not a round number, so that a table rendered
	// from a forgotten default rather than from this machine is visible.
	fixtureAccountIdentifier = 993

	// fixtureSecrets is what the data of a private service holds in these tests,
	// and fixtureRestoredSecrets is another state of it. They are two distinct
	// strings so that "the same data" and "the data of that slot" are assertions
	// about identity rather than about a directory existing.
	fixtureSecrets         = "synthetic-secrets-of-the-deployed-instance"
	fixtureRestoredSecrets = "synthetic-secrets-as-the-named-slot-holds-them"
)

// fixtureArchiveInstant is when this fake machine writes every archive. A fixed
// instant is what lets a report be compared whole rather than around a hole.
var fixtureArchiveInstant = time.Date(2026, time.August, 6, 12, 0, 0, 0, time.UTC)

// archiveDigest is the digest this fake machine reports for one archived state.
// It is a real digest of real bytes, so a case comparing two reports is comparing
// two facts rather than two labels.
func archiveDigest(content string) string {
	sum := sha256.Sum256([]byte(content))
	return hex.EncodeToString(sum[:])
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

// LinkRouteAnswers is recorded apart from the verification of a local route, so
// that a case can hold which of the two a publication actually made: the one that
// requires the isolation headers, or the one that requires the status alone and
// travels through the tunnel.
func (executor *fakeExecutor) LinkRouteAnswers(routeHost string) error {
	executor.reads = append(executor.reads, "LinkRouteAnswers")
	executor.verifiedLinkRoutes = append(executor.verifiedLinkRoutes, routeHost)
	return executor.fail("LinkRouteAnswers")
}

// LinkPublicKey answers with the public half alone, exactly as the real machine
// does. There is no seam here — and none in the interface it implements —
// through which the private half could be asked for.
func (executor *fakeExecutor) LinkPublicKey() (string, bool, error) {
	executor.reads = append(executor.reads, "LinkPublicKey")
	if err := executor.fail("LinkPublicKey"); err != nil {
		return "", false, err
	}
	if !executor.linkKeyPresent {
		return "", false, nil
	}
	return executor.linkPublicKey, true, nil
}

// GenerateLinkKey refuses to replace a key that already exists, as the real
// machine does by creating the file exclusively. A test that could regenerate a
// key here would prove nothing about a machine that cannot.
func (executor *fakeExecutor) GenerateLinkKey() (string, error) {
	executor.effects = append(executor.effects, "GenerateLinkKey")
	if err := executor.fail("GenerateLinkKey"); err != nil {
		return "", err
	}
	if executor.linkKeyPresent {
		return "", errors.New("this machine already holds a passage key")
	}
	executor.linkKeysGenerated++
	executor.linkKeyPresent = true
	executor.linkPrivateKey = fixtureLinkPrivateKey
	executor.linkPublicKey = fixtureLinkPublicKey
	return executor.linkPublicKey, nil
}

func (executor *fakeExecutor) RemoveLinkKey() error {
	executor.effects = append(executor.effects, "RemoveLinkKey")
	if err := executor.fail("RemoveLinkKey"); err != nil {
		return err
	}
	executor.linkKeyPresent = false
	executor.linkPrivateKey = ""
	executor.linkPublicKey = ""
	return nil
}

func (executor *fakeExecutor) LinkInterfaceActive() (bool, error) {
	executor.reads = append(executor.reads, "LinkInterfaceActive")
	if err := executor.fail("LinkInterfaceActive"); err != nil {
		return false, err
	}
	return executor.linkActive, nil
}

func (executor *fakeExecutor) RemoveLinkInterface() error {
	executor.effects = append(executor.effects, "RemoveLinkInterface")
	if err := executor.fail("RemoveLinkInterface"); err != nil {
		return err
	}
	executor.linkInterfaceRemovals++
	executor.linkActive = false
	return nil
}

// LinkRules, WriteLinkRules and RemoveLinkRules hold the bounds the way the real
// machine does: the file and the kernel are written together and removed
// together, and the removal names one table.
func (executor *fakeExecutor) LinkRules() ([]byte, bool, error) {
	executor.reads = append(executor.reads, "LinkRules")
	if err := executor.fail("LinkRules"); err != nil {
		return nil, false, err
	}
	if !executor.linkRulesPresent {
		return nil, false, nil
	}
	return executor.linkRules, true, nil
}

func (executor *fakeExecutor) WriteLinkRules(content []byte) error {
	executor.effects = append(executor.effects, "WriteLinkRules")
	if err := executor.fail("WriteLinkRules"); err != nil {
		return err
	}
	executor.linkRules = content
	executor.linkRulesPresent = true
	executor.linkRuleApplications++
	executor.nftTables[linkTableFamily+" "+linkTableName] = content
	return nil
}

func (executor *fakeExecutor) RemoveLinkRules() error {
	executor.effects = append(executor.effects, "RemoveLinkRules")
	if err := executor.fail("RemoveLinkRules"); err != nil {
		return err
	}
	executor.linkRules = nil
	executor.linkRulesPresent = false
	delete(executor.nftTables, linkTableFamily+" "+linkTableName)
	return nil
}

func (executor *fakeExecutor) LinkLoopbackPolicy() ([]byte, bool, error) {
	executor.reads = append(executor.reads, "LinkLoopbackPolicy")
	if err := executor.fail("LinkLoopbackPolicy"); err != nil {
		return nil, false, err
	}
	if !executor.linkPolicyPresent {
		return nil, false, nil
	}
	return executor.linkPolicy, true, nil
}

func (executor *fakeExecutor) WriteLinkLoopbackPolicy(content []byte) error {
	executor.effects = append(executor.effects, "WriteLinkLoopbackPolicy")
	if err := executor.fail("WriteLinkLoopbackPolicy"); err != nil {
		return err
	}
	executor.linkPolicy = content
	executor.linkPolicyPresent = true
	executor.linkPolicyApplications++
	return nil
}

func (executor *fakeExecutor) RemoveLinkLoopbackPolicy() error {
	executor.effects = append(executor.effects, "RemoveLinkLoopbackPolicy")
	if err := executor.fail("RemoveLinkLoopbackPolicy"); err != nil {
		return err
	}
	executor.linkPolicy = nil
	executor.linkPolicyPresent = false
	executor.linkPolicyApplications++
	return nil
}

func (executor *fakeExecutor) EnableLinkRulesAtBoot() error {
	executor.effects = append(executor.effects, "EnableLinkRulesAtBoot")
	if err := executor.fail("EnableLinkRulesAtBoot"); err != nil {
		return err
	}
	executor.linkBootEnablings++
	executor.linkRulesAtBoot = true
	return nil
}

func (executor *fakeExecutor) DisableLinkRulesAtBoot() error {
	executor.effects = append(executor.effects, "DisableLinkRulesAtBoot")
	if err := executor.fail("DisableLinkRulesAtBoot"); err != nil {
		return err
	}
	executor.linkBootDisablings++
	executor.linkRulesAtBoot = false
	return nil
}

func (executor *fakeExecutor) EnableNetworkManagement() error {
	executor.effects = append(executor.effects, "EnableNetworkManagement")
	if err := executor.fail("EnableNetworkManagement"); err != nil {
		return err
	}
	executor.networkEnablings++
	return nil
}

// ReloadNetworkConfiguration is what makes the interface appear, exactly as it
// is on a real machine: the description is on disk first and the manager reads
// it, so a machine whose files were never written holds no interface.
func (executor *fakeExecutor) ReloadNetworkConfiguration() error {
	executor.effects = append(executor.effects, "ReloadNetworkConfiguration")
	if err := executor.fail("ReloadNetworkConfiguration"); err != nil {
		return err
	}
	executor.networkReloads++
	executor.linkActive = executor.holds(linkNetdevPath) && executor.holds(linkNetworkPath)
	return nil
}

func (executor *fakeExecutor) AccountIdentifier(account string) (int, error) {
	executor.reads = append(executor.reads, "AccountIdentifier")
	if err := executor.fail("AccountIdentifier"); err != nil {
		return 0, err
	}
	return executor.accountIdentifier, nil
}

func (executor *fakeExecutor) ServiceDataPresent(path string) (bool, error) {
	executor.reads = append(executor.reads, "ServiceDataPresent")
	if err := executor.fail("ServiceDataPresent"); err != nil {
		return false, err
	}
	return executor.dataPresent, nil
}

// EnsureServiceData creates the durable directories and leaves what is already in
// them exactly as it was, which is the property "a redeployment finds the data" is
// asserted against.
//
// Every directory it was asked for is recorded, so that a case can hold the whole
// list a placement derived: a user service's own volumes root and one directory
// per declared volume, all of them under the home its slug decides.
func (executor *fakeExecutor) EnsureServiceData(
	account string,
	dataDirectories []string,
	snapshotDirectory string,
) error {
	executor.effects = append(executor.effects, "EnsureServiceData")
	if err := executor.fail("EnsureServiceData"); err != nil {
		return err
	}
	executor.dataEnsured++
	executor.dataPresent = true
	executor.dataDirectories = append(executor.dataDirectories, dataDirectories...)
	return nil
}

// ServiceSecretsPresent answers from the values this fake machine holds and from
// the names its environment file declares — as the real seam does, and for the
// same reason: no caller of it may be handed a value.
func (executor *fakeExecutor) ServiceSecretsPresent(
	directory, environmentFile string,
	keys []string,
) (bool, error) {
	executor.reads = append(executor.reads, "ServiceSecretsPresent")
	if err := executor.fail("ServiceSecretsPresent"); err != nil {
		return false, err
	}
	for _, key := range keys {
		if _, held := executor.secrets[directory+"/"+key]; !held {
			return false, nil
		}
	}
	written, present := executor.secretEnvironments[environmentFile]
	if !present {
		return false, nil
	}
	return declaresExactly([]byte(written), keys), nil
}

// EnsureServiceSecrets generates exactly what this fake machine does not hold and
// keeps everything it does, exactly as the real seam does.
//
// The generated value is drawn from a counter rather than from randomness, so that
// "the same secrets came back" is an assertion about identity and a leak of one
// into a report or an error would be a string a case can grep for. Refusing to
// replace an existing value is held here and not above it, so a case proving
// "never regenerated" is proving the seam.
func (executor *fakeExecutor) EnsureServiceSecrets(
	account, directory, environmentFile string,
	keys []string,
) error {
	executor.effects = append(executor.effects, "EnsureServiceSecrets")
	if err := executor.fail("EnsureServiceSecrets"); err != nil {
		return err
	}
	lines := []string{}
	for _, key := range keys {
		path := directory + "/" + key
		if _, held := executor.secrets[path]; !held {
			executor.secretsGenerated++
			executor.secrets[path] = fixtureSecretValue(executor.secretsGenerated)
		}
		lines = append(lines, key+"="+executor.secrets[path])
	}
	executor.secretEnvironments[environmentFile] = strings.Join(lines, "\n") + "\n"
	return nil
}

// ManagedUserServiceSlugs answers from the sheets this machine holds, so that a
// case which deployed a user service does not also have to declare that this
// machine runs one.
func (executor *fakeExecutor) ManagedUserServiceSlugs() ([]string, error) {
	executor.reads = append(executor.reads, "ManagedUserServiceSlugs")
	if err := executor.fail("ManagedUserServiceSlugs"); err != nil {
		return nil, err
	}
	slugs := []string{}
	for path := range executor.files {
		home, held := strings.CutPrefix(path, userServiceHomeRoot+UserServiceAccountPrefix)
		if !held {
			continue
		}
		slug, _, split := strings.Cut(home, "/")
		if !split || servicedefinition.ValidateSlug(slug) != nil {
			continue
		}
		if path != userServicePlacementOfSlug(slug).unitPath() {
			continue
		}
		slugs = append(slugs, slug)
	}
	sort.Strings(slugs)
	return slugs, nil
}

func (executor *fakeExecutor) ServiceArchives(directory string) ([]string, error) {
	executor.reads = append(executor.reads, "ServiceArchives")
	if err := executor.fail("ServiceArchives"); err != nil {
		return nil, err
	}
	slots := []string{}
	for path := range executor.archives {
		if !strings.HasPrefix(path, directory+"/") || !strings.HasSuffix(path, archiveSuffix) {
			continue
		}
		slot := strings.TrimSuffix(strings.TrimPrefix(path, directory+"/"), archiveSuffix)
		// The reserved slot is left out here and not by the caller, exactly as the
		// real seam leaves it out: a list of archives is a list of names a human
		// gave, and that one is the mechanism's.
		if slot == plan.ReservedSnapshotSlot {
			continue
		}
		slots = append(slots, slot)
	}
	sort.Strings(slots)
	return slots, nil
}

func (executor *fakeExecutor) ServiceArchivePresent(path string) (bool, error) {
	executor.reads = append(executor.reads, "ServiceArchivePresent")
	if err := executor.fail("ServiceArchivePresent"); err != nil {
		return false, err
	}
	_, present := executor.archives[path]
	return present, nil
}

// ArchiveServiceData refuses to replace an archive, exactly as the real seam
// does: the immutability of the ordinary slots is structural here too, so a case
// proving it is proving the seam and not a check above the seam.
func (executor *fakeExecutor) ArchiveServiceData(dataDirectory, archivePath string) (Archive, error) {
	executor.effects = append(executor.effects, "ArchiveServiceData")
	if err := executor.fail("ArchiveServiceData"); err != nil {
		return Archive{}, err
	}
	if _, present := executor.archives[archivePath]; present {
		return Archive{}, errors.New("an archive already exists in this slot")
	}
	executor.archives[archivePath] = executor.dataContent
	return Archive{SHA256: archiveDigest(executor.dataContent), TakenAt: fixtureArchiveInstant}, nil
}

// ExchangeServiceData reads the named archive before it writes the reserved one,
// exactly as the real seam does. That order is the whole reason this is one call:
// a return naming the reserved slot passes both paths as the same file, and the
// swap it performs is what makes such a return an honest undoing of itself.
func (executor *fakeExecutor) ExchangeServiceData(archivePath, dataDirectory, reservedPath string) (Archive, error) {
	executor.effects = append(executor.effects, "ExchangeServiceData")
	if err := executor.fail("ExchangeServiceData"); err != nil {
		return Archive{}, err
	}
	returning := executor.archives[archivePath]
	replaced := executor.dataContent
	executor.archives[reservedPath] = replaced
	executor.dataContent = returning
	executor.dataPresent = true
	executor.dataRestores++
	return Archive{SHA256: archiveDigest(replaced), TakenAt: fixtureArchiveInstant}, nil
}

func (executor *fakeExecutor) RemoveServiceArchive(path string) error {
	executor.effects = append(executor.effects, "RemoveServiceArchive")
	if err := executor.fail("RemoveServiceArchive"); err != nil {
		return err
	}
	delete(executor.archives, path)
	return nil
}

func (executor *fakeExecutor) EgressRules(path string) ([]byte, bool, error) {
	executor.reads = append(executor.reads, "EgressRules")
	if err := executor.fail("EgressRules"); err != nil {
		return nil, false, err
	}
	if !executor.egressRulesPresent {
		return nil, false, nil
	}
	return executor.egressRules, true, nil
}

// WriteEgressRules persists the table and loads it into this fake machine's
// kernel in the same call, so a run that wrote the file without applying it would
// leave the two disagreeing — which is exactly what the seam exists to prevent.
//
// Every table a run writes is kept, in order, because one property of the shared
// table is about the instants between the writes: a deployment that lifts its own
// account for the length of a fetch must never lift somebody else's, and that is
// read from what was posed meanwhile rather than from what was posed last.
func (executor *fakeExecutor) WriteEgressRules(path string, content []byte) error {
	executor.effects = append(executor.effects, "WriteEgressRules")
	if err := executor.fail("WriteEgressRules"); err != nil {
		return err
	}
	executor.egressWrites = append(executor.egressWrites, content)
	executor.egressRules = content
	executor.egressRulesPresent = true
	executor.egressRuleApplications++
	executor.nftTables[egressTableFamily+" "+egressTableName] = content
	return nil
}

func (executor *fakeExecutor) RemoveEgressRules(path string) error {
	executor.effects = append(executor.effects, "RemoveEgressRules")
	if err := executor.fail("RemoveEgressRules"); err != nil {
		return err
	}
	executor.egressRules = nil
	executor.egressRulesPresent = false
	executor.egressRuleApplications++
	delete(executor.nftTables, egressTableFamily+" "+egressTableName)
	return nil
}

func (executor *fakeExecutor) EnableEgressRulesAtBoot() error {
	executor.effects = append(executor.effects, "EnableEgressRulesAtBoot")
	if err := executor.fail("EnableEgressRulesAtBoot"); err != nil {
		return err
	}
	executor.egressAtBoot = true
	executor.egressBootEnablings++
	return nil
}

func (executor *fakeExecutor) DisableEgressRulesAtBoot() error {
	executor.effects = append(executor.effects, "DisableEgressRulesAtBoot")
	if err := executor.fail("DisableEgressRulesAtBoot"); err != nil {
		return err
	}
	executor.egressAtBoot = false
	executor.egressBootDisablings++
	return nil
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

// The four schema 2 pairs of the private profile a Controller would have built
// and transported.
//
// They exist so that the window this Auxiliary keeps open on those four document
// shapes is proven against real documents rather than against an operation string
// written into a shape this package already places: what must be refused is a
// whole, valid, canonically frozen pair, exactly as a Console would hand it over.
const (
	fixtureOriginHost    = "vault.lab.your-cloud.test"
	fixtureLinkRouteHost = "vault.lab.your-cloud.test"
	fixtureSnapshotSlot  = "nightly"
)

func frozenPrivateServicePair(t *testing.T, operation string, port int) plan.Frozen {
	t.Helper()
	pair, err := plan.BuildPrivateServicePair(operation, fixtureInfrastructure, fixtureMachine,
		plan.ServiceProfileVaultwarden, port, fixtureOriginHost)
	if err != nil {
		t.Fatal(err)
	}
	return frozenV2(t, pair)
}

func frozenLinkRoutePair(t *testing.T, operation, host string, port int) plan.Frozen {
	t.Helper()
	pair, err := plan.BuildLinkRoutePair(operation, fixtureInfrastructure, fixtureMachine, host, port)
	if err != nil {
		t.Fatal(err)
	}
	return frozenV2(t, pair)
}

func frozenSnapshotPair(t *testing.T, operation string) plan.Frozen {
	t.Helper()
	pair, err := plan.BuildSnapshotPair(operation, fixtureInfrastructure, fixtureMachine,
		plan.ServiceProfileVaultwarden, fixtureSnapshotSlot)
	if err != nil {
		t.Fatal(err)
	}
	return frozenV2(t, pair)
}

// frozenRestorePair carries the one pair whose rollback names the reserved slot,
// so the window is proven against that document too rather than only against the
// shapes whose two directions differ by an operation.
func frozenRestorePair(t *testing.T) plan.Frozen {
	t.Helper()
	pair, err := plan.BuildRestorePair(fixtureInfrastructure, fixtureMachine,
		plan.ServiceProfileVaultwarden, fixtureSnapshotSlot)
	if err != nil {
		t.Fatal(err)
	}
	return frozenV2(t, pair)
}

// The pairs of the third door a Controller would have built and transported,
// together with the archive of a service the same definition describes.
//
// The definition is the one the servicedefinition package pins as its own
// reference vector, spelled here as the canonical bytes a Controller froze — so
// that the placement these tests derive is derived from the very document the two
// implementations hold their vectors against. The image digest is synthetic and
// looks it: the third door pins no image, so there is no identity of the product
// to name here.
const (
	fixtureUserDefinitionDocument = `{"schema_version":1,"slug":"lab-notes",` +
		`"image_repository":"registry.lab.your-cloud.test/your-cloud/lab-notes",` +
		`"container_port":8080,"volumes":["/srv/notes","/var/lib/lab-notes"],` +
		`"tmpfs":["/tmp"],"environment":["LAB_NOTES_TITLE=Your Cloud lab notes",` +
		`"LAB_NOTES_ORIGIN=https://{origin_host}/","LAB_NOTES_READ_ONLY=1"],` +
		`"secret_keys":["LAB_NOTES_ADMIN_TOKEN"]}`
	fixtureUserSlug        = "lab-notes"
	fixtureUserImageDigest = "sha256:0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
	fixtureUserOriginHost  = "notes.lab.your-cloud.test"
)

func frozenUserServicePair(t *testing.T, operation string, port int) plan.Frozen {
	t.Helper()
	definition, err := servicedefinition.Decode([]byte(fixtureUserDefinitionDocument))
	if err != nil {
		t.Fatal(err)
	}
	pair, err := plan.BuildUserServicePair(operation, fixtureInfrastructure, fixtureMachine,
		definition, fixtureUserImageDigest, port, fixtureUserOriginHost)
	if err != nil {
		t.Fatal(err)
	}
	return frozenV2(t, pair)
}

// frozenUserArchivePair is the other half of the same window: the three archive
// operations name a service by its slug, and a definition's slug is a value their
// documents now admit.
func frozenUserArchivePair(t *testing.T, operation string) plan.Frozen {
	t.Helper()
	pair, err := plan.BuildSnapshotPair(operation, fixtureInfrastructure, fixtureMachine,
		fixtureUserSlug, fixtureSnapshotSlot)
	if err != nil {
		t.Fatal(err)
	}
	return frozenV2(t, pair)
}

func frozenUserRestorePair(t *testing.T) plan.Frozen {
	t.Helper()
	pair, err := plan.BuildRestorePair(fixtureInfrastructure, fixtureMachine,
		fixtureUserSlug, fixtureSnapshotSlot)
	if err != nil {
		t.Fatal(err)
	}
	return frozenV2(t, pair)
}

// fixtureUserDefinition is that reference document, decoded, and
// fixtureUserPlacement is what this Auxiliary derives from it for the instance
// the fixtures above approve.
//
// They are derived rather than spelled out, because the derivation is exactly
// what these tests are about: a fixture that wrote the account and the host paths
// by hand would agree with the code by construction and would prove nothing.
func fixtureUserDefinition(t *testing.T) servicedefinition.Document {
	t.Helper()
	definition, err := servicedefinition.Decode([]byte(fixtureUserDefinitionDocument))
	if err != nil {
		t.Fatal(err)
	}
	return definition
}

func fixtureUserPlacement(t *testing.T) placement {
	t.Helper()
	return userServicePlacementOf(fixtureUserDefinition(t), fixtureUserImageDigest, fixtureUserOriginHost)
}

// approvedUserService is the nominal schema 2 subject of the third door: the
// signed pair, and the definition's own bytes travelling beside it exactly as a
// Console hands them over.
func approvedUserService(t *testing.T, operation string, port int) (*approval.Acceptance, *Input) {
	t.Helper()
	accepted, input := approvedFrozenPair(operation, frozenUserServicePair(t, operation, port))
	input.DefinitionDocument = []byte(fixtureUserDefinitionDocument)
	return accepted, input
}

// approvedUserArchive and approvedUserRestore are the archive operations naming a
// user service by its slug. No definition travels with them, and that is the
// contract rather than an omission: what an archive acts on derives from the slug,
// and the machine answers for the rest.
func approvedUserArchive(t *testing.T, operation string) (*approval.Acceptance, *Input) {
	t.Helper()
	return approvedFrozenPair(operation, frozenUserArchivePair(t, operation))
}

func approvedUserRestore(t *testing.T) (*approval.Acceptance, *Input) {
	t.Helper()
	return approvedFrozenPair(plan.OperationRestoreService, frozenUserRestorePair(t))
}

// userServiceMachine is a machine that can run the flow with the user service's
// account already created, and nothing of the service on it yet: no sheet, no
// volume, no generated value, no confinement.
func userServiceMachine() *fakeExecutor {
	executor := newFakeExecutor()
	executor.capabilities.AccountPresent = true
	executor.capabilities.RootlessPodman = true
	return executor
}

// deployedUserServiceMachine is a machine already holding exactly the approved
// user service: the sheet bytes the interpolated origin and the volumes are
// embedded in, the running container on the approved image, the volumes with their
// synthetic content, one generated value per declared key with the environment
// file beside them, and the confinement this machine's own account identifier
// renders with the unit that poses it again at boot.
func deployedUserServiceMachine(t *testing.T, port int) *fakeExecutor {
	t.Helper()
	where := fixtureUserPlacement(t)
	executor := userServiceMachine()
	executor.hold(where.unitPath(), renderSheet(where, port, fixtureUserOriginHost))
	executor.active = true
	executor.image = where.image
	executor.dataPresent = true
	executor.dataContent = fixtureSecrets
	lines := []string{}
	for _, key := range where.secretKeys {
		executor.secretsGenerated++
		executor.secrets[where.secretsDirectory()+"/"+key] = fixtureSecretValue(executor.secretsGenerated)
		lines = append(lines, key+"="+executor.secrets[where.secretsDirectory()+"/"+key])
	}
	executor.secretEnvironments[where.environmentFilePath()] = strings.Join(lines, "\n") + "\n"
	executor.egressRules = renderEgressRules(confinedAs(where, executor.accountIdentifier))
	executor.egressRulesPresent = true
	executor.nftTables[egressTableFamily+" "+egressTableName] = executor.egressRules
	executor.nftTables[foreignTable] = []byte("table " + foreignTable + " { }")
	executor.hold(egressRulesUnitPath, renderEgressRulesUnit())
	executor.egressAtBoot = true
	return executor
}

// archivedUserServiceMachine is that same machine holding one ordinary archive of
// its volumes, whose content is a state other than the one currently deployed.
func archivedUserServiceMachine(t *testing.T, port int) *fakeExecutor {
	t.Helper()
	executor := deployedUserServiceMachine(t, port)
	where := userServicePlacementOfSlug(fixtureUserSlug)
	executor.archives[where.archivePath(fixtureSnapshotSlot)] = fixtureRestoredSecrets
	return executor
}

func frozenV2(t *testing.T, pair plan.V2Pair) plan.Frozen {
	t.Helper()
	frozen, err := pair.Freeze()
	if err != nil {
		t.Fatal(err)
	}
	return frozen
}

// The three schema 3 pairs a Controller would have built and transported for the
// private passage.
//
// fixturePeerPublicKey is the synthetic key the plan package pins as its own
// vector — thirty-two bytes counting from one — so that the two implementations
// are held against one spelling rather than against two inventions.
//
// fixtureLinkPublicKey is what this machine's own preparation reports, and
// fixtureLinkPrivateKey is what it wrote and what nothing may ever carry. The
// second is deliberately not a plausible key at all: it is a sentence, so that a
// test grepping a report or an error for it can only match if something really
// did carry the private half, and never by coincidence.
const (
	fixturePeerPublicKey = "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA="
	fixtureEndpointHost  = "vps.lab.your-cloud.test"

	// fixtureOtherPeerPublicKey is a second, equally canonical key, so that a
	// machine holding a peer the approved plan does not name is a real case
	// rather than a malformed value refused a layer earlier.
	fixtureOtherPeerPublicKey = "ISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0+P0A="

	fixtureLinkPublicKey  = "ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8="
	fixtureLinkPrivateKey = "THIS-PRIVATE-KEY-MUST-NEVER-LEAVE-ITS-MACHINE"
)

func frozenLinkPair(t *testing.T, operation, role string) plan.Frozen {
	t.Helper()
	pair, err := plan.BuildLinkPair(operation, fixtureInfrastructure, fixtureMachine, role)
	if err != nil {
		t.Fatal(err)
	}
	return frozenV3(t, pair)
}

func frozenListenerPeerPair(t *testing.T, operation string, port int) plan.Frozen {
	t.Helper()
	pair, err := plan.BuildListenerPeerPair(operation, fixtureInfrastructure,
		fixtureMachine, fixturePeerPublicKey, port)
	if err != nil {
		t.Fatal(err)
	}
	return frozenV3(t, pair)
}

func frozenInitiatorPeerPair(t *testing.T, operation string, port int) plan.Frozen {
	t.Helper()
	pair, err := plan.BuildInitiatorPeerPair(operation, fixtureInfrastructure,
		fixtureMachine, fixturePeerPublicKey, fixtureEndpointHost, port)
	if err != nil {
		t.Fatal(err)
	}
	return frozenV3(t, pair)
}

func frozenV3(t *testing.T, pair plan.V3Pair) plan.Frozen {
	t.Helper()
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
	case plan.OperationPublishLinkRoute, plan.OperationRetireLinkRoute:
		return approvedLinkRoute(t, operation, fixtureLinkRouteHost, port)
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
	executor.hold(bentoPDFPlacement.unitPath(), renderSheet(bentoPDFPlacement, port, ""))
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
	executor.hold(bentoPDFPlacement.unitPath(), renderSheet(bentoPDFPlacement, port, ""))
	return executor
}

// publishedRouteMachine is that same machine with the fragment of one declared
// name already written exactly as the plan describes it.
func publishedRouteMachine(host string, port int) *fakeExecutor {
	executor := routableMachine(port)
	executor.hold(routeFragmentPath(host), renderRouteFragment(host, port))
	return executor
}

// approvedLinkRoute is the nominal schema 2 subject of a name published through
// the private passage.
func approvedLinkRoute(t *testing.T, operation, host string, port int) (*approval.Acceptance, *Input) {
	t.Helper()
	return approvedFrozenPair(operation, frozenLinkRoutePair(t, operation, host, port))
}

// forgedLinkRoutePlan renders that document field by field, for the reason the
// other forgers exist.
func forgedLinkRoutePlan(t *testing.T, operation, host string, port int, altered map[string]string) []byte {
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

// linkRoutableMachine is what a link route plan needs to find, and it is the VPS
// of the reference scenario: the entry that serves the declared name, and this
// machine holding the listener's side of the passage with one approved junction
// bounding exactly the port the route publishes.
//
// It holds no managed service at all, which is the whole point of the scenario:
// the service lives at the other end of the tunnel, and nothing of it is on this
// machine.
func linkRoutableMachine(port int) *fakeExecutor {
	where := linkPlacements[plan.LinkRoleListener]
	executor := entrypointMachine()
	executor.hold(entrypointPlacement.unitPath(), renderEntrypointSheet())
	executor.linkKeyPresent = true
	executor.linkPrivateKey = fixtureLinkPrivateKey
	executor.linkPublicKey = fixtureLinkPublicKey
	executor.hold(linkNetdevPath, append(renderLinkNetdev(where),
		renderLinkPeerSection(where, fixturePeerPublicKey, fixtureEndpointHost)...))
	executor.hold(linkNetworkPath, append(renderLinkNetwork(where),
		renderLinkRouteSection(where)...))
	executor.linkActive = true
	executor.linkRules = renderLinkRules(where, port)
	executor.linkRulesPresent = true
	executor.nftTables[linkTableFamily+" "+linkTableName] = executor.linkRules
	executor.hold(linkRulesUnitPath, renderLinkRulesUnit(where))
	executor.linkRulesAtBoot = true
	return executor
}

// publishedLinkRouteMachine is that same machine with the fragment of one
// declared name already written exactly as the link route plan describes it.
func publishedLinkRouteMachine(host string, port int) *fakeExecutor {
	executor := linkRoutableMachine(port)
	executor.hold(routeFragmentPath(host), renderLinkRouteFragment(host, port))
	return executor
}

// pannedLinkRouteMachine is the failure of the passage, as a machine: the name is
// still published and the junction that carried it is gone, exactly as the
// departure of `#97` leaves this host — the interface and the key are still
// there, the peer, the bounds and their unit are not.
func pannedLinkRouteMachine(host string, port int) *fakeExecutor {
	where := linkPlacements[plan.LinkRoleListener]
	executor := publishedLinkRouteMachine(host, port)
	executor.hold(linkNetdevPath, renderLinkNetdev(where))
	executor.hold(linkNetworkPath, renderLinkNetwork(where))
	executor.linkRules = nil
	executor.linkRulesPresent = false
	delete(executor.nftTables, linkTableFamily+" "+linkTableName)
	executor.drop(linkRulesUnitPath)
	executor.linkRulesAtBoot = false
	return executor
}

// approvedPrivateService, approvedSnapshot and approvedRestore are the nominal
// schema 2 subjects of the three operation groups of the private profile.
func approvedPrivateService(t *testing.T, operation string, port int) (*approval.Acceptance, *Input) {
	t.Helper()
	return approvedFrozenPair(operation, frozenPrivateServicePair(t, operation, port))
}

func approvedSnapshot(t *testing.T, operation string) (*approval.Acceptance, *Input) {
	t.Helper()
	return approvedFrozenPair(operation, frozenSnapshotPair(t, operation))
}

func approvedRestore(t *testing.T) (*approval.Acceptance, *Input) {
	t.Helper()
	return approvedFrozenPair(plan.OperationRestoreService, frozenRestorePair(t))
}

// forgedPrivateServicePlan, forgedSnapshotPlan and forgedRestorePlan render the
// three closed field lists of the private profile document by document, for the
// reason the other forgers exist: half the documents a refusal matrix presents
// are documents the plan package refuses to build at all.
func forgedPrivateServicePlan(t *testing.T, operation string, port int, altered map[string]string) []byte {
	t.Helper()
	return forgeDocument(t, [][2]string{
		{"schema_version", strconv.Itoa(plan.SchemaVersionV2)},
		{"infrastructure_id", quotedJSON(t, fixtureInfrastructure)},
		{"machine_id", quotedJSON(t, fixtureMachine)},
		{"operation", quotedJSON(t, operation)},
		{"service_profile", quotedJSON(t, plan.ServiceProfileVaultwarden)},
		{"image_reference", quotedJSON(t, plan.VaultwardenImageReference)},
		{"image_digest", quotedJSON(t, plan.VaultwardenImageDigest)},
		{"local_port", strconv.Itoa(port)},
		{"origin_host", quotedJSON(t, fixtureOriginHost)},
	}, altered)
}

func forgedSnapshotPlan(t *testing.T, operation, slot string, altered map[string]string) []byte {
	t.Helper()
	return forgeDocument(t, [][2]string{
		{"schema_version", strconv.Itoa(plan.SchemaVersionV2)},
		{"infrastructure_id", quotedJSON(t, fixtureInfrastructure)},
		{"machine_id", quotedJSON(t, fixtureMachine)},
		{"operation", quotedJSON(t, operation)},
		{"service_profile", quotedJSON(t, plan.ServiceProfileVaultwarden)},
		{"snapshot_slot", quotedJSON(t, slot)},
	}, altered)
}

func forgedRestorePlan(t *testing.T, slot string, altered map[string]string) []byte {
	t.Helper()
	return forgeDocument(t, [][2]string{
		{"schema_version", strconv.Itoa(plan.SchemaVersionV2)},
		{"infrastructure_id", quotedJSON(t, fixtureInfrastructure)},
		{"machine_id", quotedJSON(t, fixtureMachine)},
		{"operation", quotedJSON(t, plan.OperationRestoreService)},
		{"service_profile", quotedJSON(t, plan.ServiceProfileVaultwarden)},
		{"snapshot_slot", quotedJSON(t, slot)},
	}, altered)
}

// privateMachine is a machine that can run the flow with the vaultwarden account
// already created, and nothing of the service on it yet: no sheet, no data, no
// confinement.
func privateMachine() *fakeExecutor {
	executor := newFakeExecutor()
	executor.capabilities.AccountPresent = true
	executor.capabilities.RootlessPodman = true
	return executor
}

// deployedPrivateMachine is a machine already holding exactly the approved
// private service: the sheet bytes the origin is embedded in, the running
// container on the pinned image, the durable data with its synthetic secrets in
// it, and the confinement table this machine's own account identifier renders,
// with the unit that poses it again at boot.
func deployedPrivateMachine(port int) *fakeExecutor {
	executor := privateMachine()
	executor.hold(vaultwardenPlacement.unitPath(), renderSheet(vaultwardenPlacement, port, fixtureOriginHost))
	executor.active = true
	executor.image = vaultwardenPlacement.image
	executor.dataPresent = true
	executor.dataContent = fixtureSecrets
	confinePrivateMachine(executor)
	return executor
}

// confinePrivateMachine puts the confinement this machine's identifier renders
// on it, in the kernel and on disk at once, beside a table of somebody else's —
// so that every case asserting what a removal takes away is asserting it against
// a machine that has a ruleset to damage.
func confinePrivateMachine(executor *fakeExecutor) {
	executor.egressRules = renderEgressRules(confinedAs(vaultwardenPlacement, executor.accountIdentifier))
	executor.egressRulesPresent = true
	executor.nftTables[egressTableFamily+" "+egressTableName] = executor.egressRules
	executor.nftTables[foreignTable] = []byte("table " + foreignTable + " { }")
	executor.hold(egressRulesUnitPath, renderEgressRulesUnit())
	executor.egressAtBoot = true
}

// archivedPrivateMachine is that same machine holding one ordinary archive, whose
// content is a state of the data other than the one currently deployed. The two
// differing states are what makes "the secrets of that slot came back" an
// assertion about identity rather than about a file existing.
func archivedPrivateMachine(port int) *fakeExecutor {
	executor := deployedPrivateMachine(port)
	executor.archives[vaultwardenPlacement.archivePath(fixtureSnapshotSlot)] = fixtureRestoredSecrets
	return executor
}

// approvedLink, approvedListenerPeer and approvedInitiatorPeer are the nominal
// schema 3 subjects of the three operation groups of the private passage.
func approvedLink(t *testing.T, operation, role string) (*approval.Acceptance, *Input) {
	t.Helper()
	return approvedFrozenPair(operation, frozenLinkPair(t, operation, role))
}

func approvedListenerPeer(t *testing.T, operation string, port int) (*approval.Acceptance, *Input) {
	t.Helper()
	return approvedFrozenPair(operation, frozenListenerPeerPair(t, operation, port))
}

func approvedInitiatorPeer(t *testing.T, operation string, port int) (*approval.Acceptance, *Input) {
	t.Helper()
	return approvedFrozenPair(operation, frozenInitiatorPeerPair(t, operation, port))
}

// approvedJunction is the junction of one role, or its departure, so that a
// check about a property both sides share walks the two roles without repeating
// which of the four operations each of them is written in.
func approvedJunction(t *testing.T, role string, undoing bool) (*approval.Acceptance, *Input) {
	t.Helper()
	if role == plan.LinkRoleListener {
		operation := plan.OperationAttachLinkPeer
		if undoing {
			operation = plan.OperationDetachLinkPeer
		}
		return approvedListenerPeer(t, operation, fixturePort)
	}
	operation := plan.OperationJoinLinkPeer
	if undoing {
		operation = plan.OperationLeaveLinkPeer
	}
	return approvedInitiatorPeer(t, operation, fixturePort)
}

// forgedLinkPlan, forgedListenerPeerPlan and forgedInitiatorPeerPlan render the
// three closed field lists of schema 3 document by document, for the reason the
// two other forgers exist: half the documents a refusal matrix presents are
// documents the plan package refuses to build at all.
func forgedLinkPlan(t *testing.T, operation, role string, altered map[string]string) []byte {
	t.Helper()
	return forgeDocument(t, [][2]string{
		{"schema_version", strconv.Itoa(plan.SchemaVersionV3)},
		{"infrastructure_id", quotedJSON(t, fixtureInfrastructure)},
		{"machine_id", quotedJSON(t, fixtureMachine)},
		{"operation", quotedJSON(t, operation)},
		{"link_role", quotedJSON(t, role)},
	}, altered)
}

func forgedListenerPeerPlan(t *testing.T, operation string, port int, altered map[string]string) []byte {
	t.Helper()
	return forgeDocument(t, [][2]string{
		{"schema_version", strconv.Itoa(plan.SchemaVersionV3)},
		{"infrastructure_id", quotedJSON(t, fixtureInfrastructure)},
		{"machine_id", quotedJSON(t, fixtureMachine)},
		{"operation", quotedJSON(t, operation)},
		{"peer_public_key", quotedJSON(t, fixturePeerPublicKey)},
		{"service_port", strconv.Itoa(port)},
	}, altered)
}

func forgedInitiatorPeerPlan(t *testing.T, operation string, port int, altered map[string]string) []byte {
	t.Helper()
	return forgeDocument(t, [][2]string{
		{"schema_version", strconv.Itoa(plan.SchemaVersionV3)},
		{"infrastructure_id", quotedJSON(t, fixtureInfrastructure)},
		{"machine_id", quotedJSON(t, fixtureMachine)},
		{"operation", quotedJSON(t, operation)},
		{"peer_public_key", quotedJSON(t, fixturePeerPublicKey)},
		{"peer_endpoint_host", quotedJSON(t, fixtureEndpointHost)},
		{"service_port", strconv.Itoa(port)},
	}, altered)
}

// linkMachine is a host that can hold a passage, with nothing of one on it: no
// key, no description, no interface. It carries none of the container machinery
// on purpose — a passage runs as root and needs no account, and a machine
// without Podman holds a tunnel perfectly well.
func linkMachine() *fakeExecutor {
	executor := newFakeExecutor()
	executor.capabilities = Capabilities{Systemd: true}
	return executor
}

// preparedLinkMachine is a machine already holding exactly one prepared side of
// the passage: its own key, both files as the role describes them, and the
// interface up.
//
// The initiator carries one thing more, and it is not decoration: it is the
// machine the service lives on in the reference scenario, so it holds the sheet
// of the managed service its junction will be bounded to. A machine without it
// is a machine whose junction is refused by the presence rule, which is a case
// of its own rather than the nominal one.
func preparedLinkMachine(role string) *fakeExecutor {
	where := linkPlacements[role]
	executor := linkMachine()
	executor.linkKeyPresent = true
	executor.linkPrivateKey = fixtureLinkPrivateKey
	executor.linkPublicKey = fixtureLinkPublicKey
	executor.hold(linkNetdevPath, renderLinkNetdev(where))
	executor.hold(linkNetworkPath, renderLinkNetwork(where))
	executor.linkActive = true
	if where.goesOut {
		executor.hold(bentoPDFPlacement.unitPath(), renderSheet(bentoPDFPlacement, fixturePort, ""))
	}
	return executor
}

// joinedLinkMachine is that same machine with the one approved peer attached and
// the bounds that peer was posed with, exactly as the junction plan of its own
// role describes them.
//
// It also carries a table of somebody else's, so that every case asserting what
// a departure removes is asserting it against a machine that has a ruleset to
// damage.
func joinedLinkMachine(role string) *fakeExecutor {
	where := linkPlacements[role]
	executor := preparedLinkMachine(role)
	executor.hold(linkNetdevPath, append(renderLinkNetdev(where),
		renderLinkPeerSection(where, fixturePeerPublicKey, fixtureEndpointHost)...))
	executor.hold(linkNetworkPath, append(renderLinkNetwork(where),
		renderLinkRouteSection(where)...))
	executor.nftTables[foreignTable] = []byte("table " + foreignTable + " { }")
	executor.linkRules = renderLinkRules(where, fixturePort)
	executor.linkRulesPresent = true
	executor.nftTables[linkTableFamily+" "+linkTableName] = executor.linkRules
	executor.hold(linkRulesUnitPath, renderLinkRulesUnit(where))
	executor.linkRulesAtBoot = true
	if where.goesOut {
		executor.linkPolicy = renderLinkLoopbackPolicy()
		executor.linkPolicyPresent = true
	}
	return executor
}

// foreignTable is a table this product never wrote and must never remove: it is
// how "retirer la jonction retire la table et rien d'autre" is held against a
// machine rather than against a sentence.
const foreignTable = "inet somebody-elses-firewall"

// confinedAs is one placement's account beside the identifier a machine gave it,
// as the one-account confinement a case describes. It exists so that no case has
// to spell the shape the rendering takes, and so that a case describing two
// confined accounts is visibly a different sentence than this one.
func confinedAs(where placement, identifier int) []confinedAccount {
	return []confinedAccount{{account: where.account, identifier: identifier}}
}

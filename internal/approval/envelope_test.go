package approval

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/ldesfontaine/your-cloud/internal/plan"
)

const (
	vectorInfrastructure = "8f14e45f-ceea-4167-a8b1-1f7bd0a0f4c2"
	vectorMachine        = "lab-machine-1"
	// SHA-256 of the plan document of the shared vector, `diagnose protocol
	// read only`, and of its rollback, `no change to roll back`.
	vectorPlan     = "0057dd53cc58e914bba328007203c36bfc9f1ebb375a0b150abdddfd0f7eee9b"
	vectorRollback = "0300401c8e3a5f90cd887fcb2a6c0ce0d35afd2c1a247f654162c275da00dcf1"
	vectorIssuedAt = 1780000000
	vectorExpires  = 1780000300

	// Public key of the all-`0x01` synthetic seed. The Console pins the same
	// string in console/src-tauri/src/approval.rs.
	vectorPublicKey = "iojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1w"

	// Signature the Console produced over the vector envelope. The two sides
	// are only interoperable while this exact string verifies here.
	vectorSignature = "rmoKkEc47JjAkPMXv_0q_Qgust3FNKoOlwDc8eajMpsWl6LqB6phBnPkR-CaMNpkm4X0oH_Gg-6CrVczUL6zCg"

	// The whole transcript, byte for byte, as the Console's own pinned vector
	// spells it in crates/bootstrap-protocol/src/approval.rs.
	vectorTranscriptHex = "796f75722d636c6f75642f617070726f76616c2d656e76656c6f70652e7631000100" +
		"00002438663134653435662d636565612d343136372d613862312d31663762643061" +
		"30663463320000000d6c61622d6d616368696e652d310000000000000001000000000" +
		"00000010000001b646961676e6f73655f70726f746f636f6c5f726561645f6f6e6c79" +
		"000000200057dd53cc58e914bba328007203c36bfc9f1ebb375a0b150abdddfd0f7eee" +
		"9b000000200300401c8e3a5f90cd887fcb2a6c0ce0d35afd2c1a247f654162c275da00" +
		"dcf10000000100000010726561645f6c6f63616c5f7374617465000000006a18a50000" +
		"0000006a18a62c000000208a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121b" +
		"f3748801b40f6f5c"
)

// vectorSeed is synthetic and exists only so both sides of the product can pin
// the same bytes. It is never a real approval key.
func vectorSeed() []byte {
	seed := make([]byte, ed25519.SeedSize)
	for index := range seed {
		seed[index] = 1
	}
	return seed
}

func vectorEnvelope() Envelope {
	return Envelope{
		SchemaVersion:     SchemaVersion,
		InfrastructureID:  vectorInfrastructure,
		MachineID:         vectorMachine,
		ApprovalEpoch:     1,
		Sequence:          1,
		Operation:         OperationDiagnoseProtocolReadOnly,
		PlanSHA256:        vectorPlan,
		RollbackSHA256:    vectorRollback,
		Privileges:        []string{PrivilegeReadLocalState},
		IssuedAtUnix:      vectorIssuedAt,
		ExpiresAtUnix:     vectorExpires,
		ApprovalPublicKey: vectorPublicKey,
	}
}

func signedDocument(t *testing.T, envelope Envelope, signature string) []byte {
	t.Helper()
	document, err := json.Marshal(SignedApproval{Envelope: envelope, Signature: signature})
	if err != nil {
		t.Fatal(err)
	}
	return document
}

// signVector signs one envelope with the synthetic vector key, which is what a
// hostile test needs when it changes a field and wants the signature to still
// be the signer's own rather than random noise.
func signVector(t *testing.T, envelope Envelope) string {
	t.Helper()
	transcript, err := envelope.SigningTranscript()
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(
		ed25519.Sign(ed25519.NewKeyFromSeed(vectorSeed()), transcript),
	)
}

// TestDeterministicTranscriptVectorMatchesTheConsole is the interoperability
// proof of the palier.
//
// The Console pins this exact transcript and this exact signature from its own
// encoder. If either implementation of the canonical encoding drifts by a
// single byte, this test fails here instead of producing approvals the other
// side silently refuses on a real machine.
func TestDeterministicTranscriptVectorMatchesTheConsole(t *testing.T) {
	t.Parallel()
	envelope := vectorEnvelope()
	transcript, err := envelope.SigningTranscript()
	if err != nil {
		t.Fatal(err)
	}
	expected, err := hex.DecodeString(vectorTranscriptHex)
	if err != nil {
		t.Fatal(err)
	}
	if len(transcript) != 285 {
		t.Fatalf("transcript length drifted: %d", len(transcript))
	}
	if !bytes.Equal(transcript, expected) {
		t.Fatalf("transcript drifted from the Console vector:\n%s", hex.EncodeToString(transcript))
	}
	if !strings.HasPrefix(string(transcript), TranscriptDomain) {
		t.Fatal("transcript does not start with its own domain separator")
	}

	public := ed25519.NewKeyFromSeed(vectorSeed()).Public().(ed25519.PublicKey)
	if base64.RawURLEncoding.EncodeToString(public) != vectorPublicKey {
		t.Fatal("the synthetic vector key drifted")
	}
	signed, err := DecodeSigned(signedDocument(t, envelope, vectorSignature))
	if err != nil {
		t.Fatal(err)
	}
	if err := signed.VerifySignature(public); err != nil {
		t.Fatalf("the Console's own signature was refused: %v", err)
	}
}

// TestChangingAnySingleFieldBreaksTheSignature is the central property.
//
// Each iteration takes the Console's genuine signature and moves exactly one
// field of the envelope. Every one of them must stop verifying: a field that
// survived would be a field the Controller owns, since the Controller is the
// only thing between the two.
func TestChangingAnySingleFieldBreaksTheSignature(t *testing.T) {
	t.Parallel()
	public := ed25519.NewKeyFromSeed(vectorSeed()).Public().(ed25519.PublicKey)

	// Positive control: the untouched envelope verifies.
	untouched, err := DecodeSigned(signedDocument(t, vectorEnvelope(), vectorSignature))
	if err != nil {
		t.Fatal(err)
	}
	if err := untouched.VerifySignature(public); err != nil {
		t.Fatalf("the positive control must verify: %v", err)
	}

	otherKey := base64.RawURLEncoding.EncodeToString(
		ed25519.NewKeyFromSeed(bytes.Repeat([]byte{3}, ed25519.SeedSize)).
			Public().(ed25519.PublicKey),
	)
	mutations := map[string]func(*Envelope){
		"infrastructure_id":       func(e *Envelope) { e.InfrastructureID = "8f14e45f-ceea-4167-a8b1-1f7bd0a0f4c3" },
		"machine_id":              func(e *Envelope) { e.MachineID = "lab-machine-2" },
		"approval_epoch":          func(e *Envelope) { e.ApprovalEpoch = 2 },
		"sequence":                func(e *Envelope) { e.Sequence = 2 },
		"plan_sha256":             func(e *Envelope) { e.PlanSHA256 = vectorRollback },
		"rollback_sha256":         func(e *Envelope) { e.RollbackSHA256 = vectorPlan },
		"privileges":              func(e *Envelope) { e.Privileges = []string{PrivilegeMutateLocalState} },
		"issued_at_unix_seconds":  func(e *Envelope) { e.IssuedAtUnix = vectorIssuedAt + 1 },
		"expires_at_unix_seconds": func(e *Envelope) { e.ExpiresAtUnix = vectorExpires - 1 },
		"approval_public_key":     func(e *Envelope) { e.ApprovalPublicKey = otherKey },
	}
	for field, mutate := range mutations {
		envelope := vectorEnvelope()
		mutate(&envelope)
		signed := &SignedApproval{Envelope: envelope, Signature: vectorSignature}
		if err := signed.VerifySignature(public); err == nil {
			t.Fatalf("a Controller changed %s without invalidating the signature", field)
		}
	}

	// The operation has one accepted spelling, so it is covered by rebuilding
	// the transcript with another name and requiring the bytes to move.
	renamed := vectorEnvelope()
	renamed.Operation = "install_container"
	moved, err := renamed.SigningTranscript()
	if err != nil {
		t.Fatal(err)
	}
	control := vectorEnvelope()
	original, err := control.SigningTranscript()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(moved, original) {
		t.Fatal("the operation is outside the signed bytes")
	}

	// Every field of the wire document is one of the ones exercised above. A
	// field added to the envelope and forgotten in the transcript fails here.
	document := map[string]json.RawMessage{}
	if err := json.Unmarshal(signedDocument(t, vectorEnvelope(), vectorSignature), &struct {
		Envelope  *map[string]json.RawMessage `json:"envelope"`
		Signature string                      `json:"signature"`
	}{Envelope: &document}); err != nil {
		t.Fatal(err)
	}
	for name := range document {
		if name == "schema_version" || name == "operation" {
			continue
		}
		if _, covered := mutations[name]; !covered {
			t.Fatalf("field %q of the envelope is never held against the signature", name)
		}
	}
}

// TestTheTranscriptIsRebuiltFromFieldsRatherThanFromTheDocument states the
// limit of the property above: a transport may reshape the JSON, and only that.
func TestTheTranscriptIsRebuiltFromFieldsRatherThanFromTheDocument(t *testing.T) {
	t.Parallel()
	reordered := fmt.Sprintf(`{
  "signature": %q,
  "envelope": {
    "approval_public_key": %q,
    "expires_at_unix_seconds": %d,
    "issued_at_unix_seconds": %d,
    "privileges": [%q],
    "rollback_sha256": %q,
    "plan_sha256": %q,
    "operation": %q,
    "sequence": 1,
    "approval_epoch": 1,
    "machine_id": %q,
    "infrastructure_id": %q,
    "schema_version": 1
  }
}`, vectorSignature, vectorPublicKey, vectorExpires, vectorIssuedAt,
		PrivilegeReadLocalState, vectorRollback, vectorPlan,
		OperationDiagnoseProtocolReadOnly, vectorMachine, vectorInfrastructure)

	signed, err := DecodeSigned([]byte(reordered))
	if err != nil {
		t.Fatal(err)
	}
	public := ed25519.NewKeyFromSeed(vectorSeed()).Public().(ed25519.PublicKey)
	if err := signed.VerifySignature(public); err != nil {
		t.Fatalf("a reindented document is the same approval: %v", err)
	}
}

// TestVerifySignatureNeverTrustsTheKeyTheDocumentCarries is the whole reason
// the envelope names its own key: so that naming a different one is a refusal
// rather than a way to bring your own signer.
func TestVerifySignatureNeverTrustsTheKeyTheDocumentCarries(t *testing.T) {
	t.Parallel()
	forgerSeed := bytes.Repeat([]byte{9}, ed25519.SeedSize)
	forger := ed25519.NewKeyFromSeed(forgerSeed)
	forgerPublic := forger.Public().(ed25519.PublicKey)

	forged := vectorEnvelope()
	forged.ApprovalPublicKey = base64.RawURLEncoding.EncodeToString(forgerPublic)
	transcript, err := forged.SigningTranscript()
	if err != nil {
		t.Fatal(err)
	}
	signed := &SignedApproval{
		Envelope:  forged,
		Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(forger, transcript)),
	}

	// Internally consistent: the document verifies under the key it names.
	if err := signed.VerifySignature(forgerPublic); err != nil {
		t.Fatalf("the forged document must be internally consistent: %v", err)
	}
	// And worthless: the anchored key is the only one that counts.
	anchored := ed25519.NewKeyFromSeed(vectorSeed()).Public().(ed25519.PublicKey)
	if err := signed.VerifySignature(anchored); err == nil {
		t.Fatal("a self-consistent forgery was accepted against the anchored key")
	}
}

func TestDecodeSignedRefusesEveryDocumentOutsideTheSchema(t *testing.T) {
	t.Parallel()
	// Positive control.
	if _, err := DecodeSigned(signedDocument(t, vectorEnvelope(), vectorSignature)); err != nil {
		t.Fatalf("the nominal document must decode: %v", err)
	}

	envelopes := map[string]func(*Envelope){
		"unsupported schema":     func(e *Envelope) { e.SchemaVersion = 2 },
		"upper-case UUID":        func(e *Envelope) { e.InfrastructureID = strings.ToUpper(vectorInfrastructure) },
		"non version 4 UUID":     func(e *Envelope) { e.InfrastructureID = "8f14e45f-ceea-1167-a8b1-1f7bd0a0f4c2" },
		"traversal machine":      func(e *Envelope) { e.MachineID = "../../etc/shadow" },
		"upper-case machine":     func(e *Envelope) { e.MachineID = "LAB-MACHINE-1" },
		"zero epoch":             func(e *Envelope) { e.ApprovalEpoch = 0 },
		"zero sequence":          func(e *Envelope) { e.Sequence = 0 },
		"unknown operation":      func(e *Envelope) { e.Operation = "install_container" },
		"upper-case plan digest": func(e *Envelope) { e.PlanSHA256 = strings.ToUpper(vectorPlan) },
		"short rollback digest":  func(e *Envelope) { e.RollbackSHA256 = "0300" },
		"mutating privilege":     func(e *Envelope) { e.Privileges = []string{PrivilegeMutateLocalState} },
		"widened privileges": func(e *Envelope) {
			e.Privileges = []string{PrivilegeMutateLocalState, PrivilegeReadLocalState}
		},
		"repeated privilege": func(e *Envelope) {
			e.Privileges = []string{PrivilegeReadLocalState, PrivilegeReadLocalState}
		},
		"empty privileges":    func(e *Envelope) { e.Privileges = nil },
		"zero issue":          func(e *Envelope) { e.IssuedAtUnix = 0 },
		"expiry before issue": func(e *Envelope) { e.ExpiresAtUnix = vectorIssuedAt - 1 },
		"endless approval": func(e *Envelope) {
			e.ExpiresAtUnix = vectorIssuedAt + MaxLifetimeSeconds + 1
		},
		"padded public key": func(e *Envelope) {
			e.ApprovalPublicKey = base64.StdEncoding.EncodeToString(make([]byte, ed25519.PublicKeySize))
		},
		"short public key": func(e *Envelope) {
			e.ApprovalPublicKey = base64.RawURLEncoding.EncodeToString(make([]byte, 31))
		},
	}
	for name, mutate := range envelopes {
		envelope := vectorEnvelope()
		mutate(&envelope)
		if _, err := DecodeSigned(signedDocument(t, envelope, vectorSignature)); err == nil {
			t.Fatalf("%s was accepted", name)
		}
	}

	for name, document := range map[string]string{
		"empty":               "",
		"two values":          string(signedDocument(t, vectorEnvelope(), vectorSignature)) + "{}",
		"unknown outer field": `{"envelope":{},"signature":"","forged":"x"}`,
		"repeated field":      `{"envelope":{"schema_version":1,"schema_version":1},"signature":"x"}`,
		"padded signature": string(signedDocument(t, vectorEnvelope(),
			base64.StdEncoding.EncodeToString(make([]byte, ed25519.SignatureSize)))),
		"short signature": string(signedDocument(t, vectorEnvelope(),
			base64.RawURLEncoding.EncodeToString(make([]byte, 63)))),
		"oversized": `{"envelope":{},"signature":"` + strings.Repeat("A", MaxSignedApprovalBytes) + `"}`,
	} {
		if _, err := DecodeSigned([]byte(document)); err == nil {
			t.Fatalf("%s document was accepted", name)
		}
	}

	unknownNested := `{"envelope":{"schema_version":1,"forged":"x"},"signature":"x"}`
	if _, err := DecodeSigned([]byte(unknownNested)); err == nil {
		t.Fatal("an unknown nested field was accepted")
	}
}

// TestTheMutatingPrivilegeIsRequiredByExactlyTheOperationsThatMutate holds the
// privilege table against the closed list of operations that may change the
// machine, in both directions.
//
// The read-only operation keeps refusing the mutating privilege, and every
// operation that changes the machine — the two probe operations, the six of the
// public profile and the six of the private passage — requires it in the exact strictly
// increasing spelling the Rust side pins: an envelope that permutes the two
// privileges is a different document, not the same approval written differently.
//
// The table below is written out rather than derived from the one under test, so
// that adding an operation to the product is a change a reader of this test has
// to agree with.
func TestTheMutatingPrivilegeIsRequiredByExactlyTheOperationsThatMutate(t *testing.T) {
	t.Parallel()
	mutating := vectorEnvelope()
	mutating.Privileges = []string{PrivilegeMutateLocalState}
	if !mutating.IsMutating() {
		t.Fatal("a mutating privilege must be recognised as one")
	}
	readOnly := vectorEnvelope()
	if readOnly.IsMutating() {
		t.Fatal("the read-only vector must not be read as mutating")
	}

	expected := map[string][]string{
		OperationDiagnoseProtocolReadOnly: {PrivilegeReadLocalState},
		OperationDeployOCIProbe:           {PrivilegeMutateLocalState, PrivilegeReadLocalState},
		OperationRemoveOCIProbe:           {PrivilegeMutateLocalState, PrivilegeReadLocalState},
		OperationDeployWebService:         {PrivilegeMutateLocalState, PrivilegeReadLocalState},
		OperationRemoveWebService:         {PrivilegeMutateLocalState, PrivilegeReadLocalState},
		OperationDeployEntrypoint:         {PrivilegeMutateLocalState, PrivilegeReadLocalState},
		OperationRemoveEntrypoint:         {PrivilegeMutateLocalState, PrivilegeReadLocalState},
		OperationPublishRoute:             {PrivilegeMutateLocalState, PrivilegeReadLocalState},
		OperationRetireRoute:              {PrivilegeMutateLocalState, PrivilegeReadLocalState},
		OperationPrepareLink:              {PrivilegeMutateLocalState, PrivilegeReadLocalState},
		OperationWithdrawLink:             {PrivilegeMutateLocalState, PrivilegeReadLocalState},
		OperationAttachLinkPeer:           {PrivilegeMutateLocalState, PrivilegeReadLocalState},
		OperationDetachLinkPeer:           {PrivilegeMutateLocalState, PrivilegeReadLocalState},
		OperationJoinLinkPeer:             {PrivilegeMutateLocalState, PrivilegeReadLocalState},
		OperationLeaveLinkPeer:            {PrivilegeMutateLocalState, PrivilegeReadLocalState},
	}
	if len(requiredPrivileges) != len(expected) {
		t.Fatalf("this palier performs %d operations, not %d", len(expected), len(requiredPrivileges))
	}
	for operation, required := range expected {
		declared, known := requiredPrivileges[operation]
		if !known || len(declared) != len(required) {
			t.Fatalf("operation %q does not declare its own privileges: %q", operation, declared)
		}
		for index := range required {
			if declared[index] != required[index] {
				t.Fatalf("operation %q declares %q rather than %q", operation, declared, required)
			}
		}
		for index := 1; index < len(declared); index++ {
			if declared[index-1] >= declared[index] {
				t.Fatalf("operation %q declares a set the validation would refuse: %q", operation, declared)
			}
		}

		carriesMutation := false
		for _, privilege := range declared {
			if privilege == PrivilegeMutateLocalState {
				carriesMutation = true
			}
		}
		if _, applied := mutatingOperations[operation]; applied != carriesMutation {
			t.Fatalf("operation %q is applied=%t while requiring mutation=%t", operation, applied, carriesMutation)
		}
	}

	// The closed list of applied mutations is held in both directions, so that an
	// operation cannot enter it without also declaring the privileges it needs.
	for operation := range mutatingOperations {
		if _, declared := expected[operation]; !declared {
			t.Fatalf("operation %q may be applied without declaring its privileges", operation)
		}
	}

	// The envelope names an operation and the plan describes it; the Auxiliary
	// refuses the pair unless the two strings are equal. They are two closed
	// lists in two packages, so they are held against one another here rather
	// than assumed to have been written the same way twice. The three schemas of
	// the plan package are all covered, because an approval names an operation
	// without naming the schema its documents are written in.
	for operation, spelling := range map[string]string{
		OperationDeployOCIProbe:   plan.OperationDeployOCIProbe,
		OperationRemoveOCIProbe:   plan.OperationRemoveOCIProbe,
		OperationDeployWebService: plan.OperationDeployWebService,
		OperationRemoveWebService: plan.OperationRemoveWebService,
		OperationDeployEntrypoint: plan.OperationDeployEntrypoint,
		OperationRemoveEntrypoint: plan.OperationRemoveEntrypoint,
		OperationPublishRoute:     plan.OperationPublishRoute,
		OperationRetireRoute:      plan.OperationRetireRoute,
		OperationPrepareLink:      plan.OperationPrepareLink,
		OperationWithdrawLink:     plan.OperationWithdrawLink,
		OperationAttachLinkPeer:   plan.OperationAttachLinkPeer,
		OperationDetachLinkPeer:   plan.OperationDetachLinkPeer,
		OperationJoinLinkPeer:     plan.OperationJoinLinkPeer,
		OperationLeaveLinkPeer:    plan.OperationLeaveLinkPeer,
	} {
		if operation != spelling {
			t.Fatalf("the approval spells %q where the plan spells %q", operation, spelling)
		}
	}
}

// TestATransportCannotRewriteAFieldOfAFreshlySignedApproval is the same central
// property as above, isolated so that a failure names the field that survived.
//
// The envelope is signed here rather than pinned, so the positive control holds
// even when the encoder itself is what changed. A transcript that stopped
// covering one field therefore fails on that field's own line, which is what
// makes this the assertion a mutation of the encoder is aimed at.
func TestATransportCannotRewriteAFieldOfAFreshlySignedApproval(t *testing.T) {
	t.Parallel()
	public := ed25519.NewKeyFromSeed(vectorSeed()).Public().(ed25519.PublicKey)
	envelope := vectorEnvelope()
	genuine := &SignedApproval{Envelope: envelope, Signature: signVector(t, envelope)}
	if err := genuine.VerifySignature(public); err != nil {
		t.Fatalf("the freshly signed control must verify: %v", err)
	}

	for field, mutate := range map[string]func(*Envelope){
		"infrastructure_id":       func(e *Envelope) { e.InfrastructureID = "8f14e45f-ceea-4167-a8b1-1f7bd0a0f4c3" },
		"machine_id":              func(e *Envelope) { e.MachineID = "lab-machine-2" },
		"approval_epoch":          func(e *Envelope) { e.ApprovalEpoch = 2 },
		"sequence":                func(e *Envelope) { e.Sequence = 2 },
		"operation":               func(e *Envelope) { e.Operation = "install_container" },
		"plan_sha256":             func(e *Envelope) { e.PlanSHA256 = vectorRollback },
		"rollback_sha256":         func(e *Envelope) { e.RollbackSHA256 = vectorPlan },
		"privileges":              func(e *Envelope) { e.Privileges = []string{PrivilegeMutateLocalState} },
		"issued_at_unix_seconds":  func(e *Envelope) { e.IssuedAtUnix = vectorIssuedAt + 1 },
		"expires_at_unix_seconds": func(e *Envelope) { e.ExpiresAtUnix = vectorExpires - 1 },
	} {
		rewritten := vectorEnvelope()
		mutate(&rewritten)
		carried := &SignedApproval{Envelope: rewritten, Signature: genuine.Signature}
		if err := carried.VerifySignature(public); err == nil {
			t.Fatalf("a Controller rewrote %s without invalidating the signature", field)
		}
	}
}

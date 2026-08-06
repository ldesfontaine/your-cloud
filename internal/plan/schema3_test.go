package plan

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

const (
	vectorLinkRole         = LinkRoleListener
	vectorServicePort      = 8080
	vectorEndpointHost     = "vps.lab.your-cloud.test"
	vectorPeerPublicKeyB64 = "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA="

	// otherPeerPublicKey is a second synthetic key, canonical like the first and
	// still not it, used wherever a case needs a well-formed value that is not
	// the one under test.
	otherPeerPublicKey = "ISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0+P0A="

	// The six canonical documents of the schema 3 vectors, byte for byte. A
	// transport may reindent them; the Controller emits exactly these bytes.
	vectorLinkPlanDocument = `{"schema_version":3,"infrastructure_id":"8f14e45f-ceea-4167-a8b1-1f7bd0a0f4c2",` +
		`"machine_id":"lab-machine-1","operation":"prepare_link","link_role":"listener"}`
	vectorLinkRollbackDocument = `{"schema_version":3,"infrastructure_id":"8f14e45f-ceea-4167-a8b1-1f7bd0a0f4c2",` +
		`"machine_id":"lab-machine-1","operation":"withdraw_link","link_role":"listener"}`
	vectorListenerPeerPlanDocument = `{"schema_version":3,"infrastructure_id":"8f14e45f-ceea-4167-a8b1-1f7bd0a0f4c2",` +
		`"machine_id":"lab-machine-1","operation":"attach_link_peer",` +
		`"peer_public_key":"AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=","service_port":8080}`
	vectorListenerPeerRollbackDocument = `{"schema_version":3,"infrastructure_id":"8f14e45f-ceea-4167-a8b1-1f7bd0a0f4c2",` +
		`"machine_id":"lab-machine-1","operation":"detach_link_peer",` +
		`"peer_public_key":"AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=","service_port":8080}`
	vectorInitiatorPeerPlanDocument = `{"schema_version":3,"infrastructure_id":"8f14e45f-ceea-4167-a8b1-1f7bd0a0f4c2",` +
		`"machine_id":"lab-machine-1","operation":"join_link_peer",` +
		`"peer_public_key":"AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=",` +
		`"peer_endpoint_host":"vps.lab.your-cloud.test","service_port":8080}`
	vectorInitiatorPeerRollbackDocument = `{"schema_version":3,"infrastructure_id":"8f14e45f-ceea-4167-a8b1-1f7bd0a0f4c2",` +
		`"machine_id":"lab-machine-1","operation":"leave_link_peer",` +
		`"peer_public_key":"AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=",` +
		`"peer_endpoint_host":"vps.lab.your-cloud.test","service_port":8080}`

	// The six transcripts, byte for byte. The Rust side of this palier, tracked
	// by #95, must reproduce these exact vectors from its own encoder: a
	// canonical encoding that exists in two implementations is only canonical
	// while the two agree byte for byte, and a drift caught here is a drift that
	// never reaches a machine as an approval the other side refuses.
	vectorLinkPlanTranscriptHex = "796f75722d636c6f75642f6f63692d706c616e2e763300030000002438663134" +
		"653435662d636565612d343136372d613862312d316637626430613066346332" +
		"0000000d6c61622d6d616368696e652d310000000c707265706172655f6c696e" +
		"6b000000086c697374656e6572"
	vectorLinkRollbackTranscriptHex = "796f75722d636c6f75642f6f63692d706c616e2e763300030000002438663134" +
		"653435662d636565612d343136372d613862312d316637626430613066346332" +
		"0000000d6c61622d6d616368696e652d310000000d77697468647261775f6c69" +
		"6e6b000000086c697374656e6572"
	vectorListenerPeerPlanTranscriptHex = "796f75722d636c6f75642f6f63692d706c616e2e763300030000002438663134" +
		"653435662d636565612d343136372d613862312d316637626430613066346332" +
		"0000000d6c61622d6d616368696e652d31000000106174746163685f6c696e6b" +
		"5f70656572000000200102030405060708090a0b0c0d0e0f1011121314151617" +
		"18191a1b1c1d1e1f2000001f90"
	vectorListenerPeerRollbackTranscriptHex = "796f75722d636c6f75642f6f63692d706c616e2e763300030000002438663134" +
		"653435662d636565612d343136372d613862312d316637626430613066346332" +
		"0000000d6c61622d6d616368696e652d31000000106465746163685f6c696e6b" +
		"5f70656572000000200102030405060708090a0b0c0d0e0f1011121314151617" +
		"18191a1b1c1d1e1f2000001f90"
	vectorInitiatorPeerPlanTranscriptHex = "796f75722d636c6f75642f6f63692d706c616e2e763300030000002438663134" +
		"653435662d636565612d343136372d613862312d316637626430613066346332" +
		"0000000d6c61622d6d616368696e652d310000000e6a6f696e5f6c696e6b5f70" +
		"656572000000200102030405060708090a0b0c0d0e0f10111213141516171819" +
		"1a1b1c1d1e1f20000000177670732e6c61622e796f75722d636c6f75642e7465" +
		"737400001f90"
	vectorInitiatorPeerRollbackTranscriptHex = "796f75722d636c6f75642f6f63692d706c616e2e763300030000002438663134" +
		"653435662d636565612d343136372d613862312d316637626430613066346332" +
		"0000000d6c61622d6d616368696e652d310000000f6c656176655f6c696e6b5f" +
		"70656572000000200102030405060708090a0b0c0d0e0f101112131415161718" +
		"191a1b1c1d1e1f20000000177670732e6c61622e796f75722d636c6f75642e74" +
		"65737400001f90"

	// The six digests an approval envelope of these vectors names as plan_sha256
	// and rollback_sha256, in the exact spelling that envelope requires.
	vectorLinkPlanSHA256              = "09578598cc63b5746e795896cbe96c0781fa2da88c287da4162561510c47f3fa"
	vectorLinkRollbackSHA256          = "fcf951067439c264159752a2df9d1d1a7e7a60e1bb893a6fd2806c8a0c7694bb"
	vectorListenerPeerPlanSHA256      = "078ddad1386cf8c30310a6df33e3bccc68cb84da8bb50500dd1c0aa325375c2b"
	vectorListenerPeerRollbackSHA256  = "a220f18a94ac48b1d4452307f12b72462d6c2e747073e9a897211ef0e48ab411"
	vectorInitiatorPeerPlanSHA256     = "40731b446ce7e612e20b349225ff190cf08a23ecd9ea4851fc2e254dbc10ea8d"
	vectorInitiatorPeerRollbackSHA256 = "ba47de1b3b59e0bb15fb115cdb998254541e430d3b3e2248120429bb6479b8ba"
)

func vectorLink() LinkDocument {
	return LinkDocument{
		SchemaVersion:    SchemaVersionV3,
		InfrastructureID: vectorInfrastructure,
		MachineID:        vectorMachine,
		Operation:        OperationPrepareLink,
		LinkRole:         vectorLinkRole,
	}
}

func vectorListenerPeer() ListenerPeerDocument {
	return ListenerPeerDocument{
		SchemaVersion:    SchemaVersionV3,
		InfrastructureID: vectorInfrastructure,
		MachineID:        vectorMachine,
		Operation:        OperationAttachLinkPeer,
		PeerPublicKey:    vectorPeerPublicKeyB64,
		ServicePort:      vectorServicePort,
	}
}

func vectorInitiatorPeer() InitiatorPeerDocument {
	return InitiatorPeerDocument{
		SchemaVersion:    SchemaVersionV3,
		InfrastructureID: vectorInfrastructure,
		MachineID:        vectorMachine,
		Operation:        OperationJoinLinkPeer,
		PeerPublicKey:    vectorPeerPublicKeyB64,
		PeerEndpointHost: vectorEndpointHost,
		ServicePort:      vectorServicePort,
	}
}

// TestTheVectorPeerKeyIsTheSyntheticValueItClaimsToBe keeps the pinned key
// readable as what it is.
//
// It is thirty-two bytes counting from one, which no machine will ever generate
// and every implementation can rebuild: the Rust side of #95 pins the same
// bytes rather than copying a string whose origin nobody could check.
func TestTheVectorPeerKeyIsTheSyntheticValueItClaimsToBe(t *testing.T) {
	t.Parallel()
	synthetic := make([]byte, PeerPublicKeyBytes)
	for index := range synthetic {
		synthetic[index] = byte(index + 1)
	}
	if base64.StdEncoding.EncodeToString(synthetic) != vectorPeerPublicKeyB64 {
		t.Fatalf("the pinned peer key is not the synthetic one it claims: %s", vectorPeerPublicKeyB64)
	}
	if len(vectorPeerPublicKeyB64) != PeerPublicKeyChars {
		t.Fatalf("the pinned peer key is %d characters, not %d",
			len(vectorPeerPublicKeyB64), PeerPublicKeyChars)
	}
	if _, err := decodePeerPublicKey(otherPeerPublicKey); err != nil {
		t.Fatalf("the second synthetic key must be canonical: %v", err)
	}
	if otherPeerPublicKey == vectorPeerPublicKeyB64 {
		t.Fatal("the two synthetic keys are the same key")
	}

	// The one refusal a length check and a decoding cannot reach on their own: a
	// spelling that decodes to exactly these thirty-two bytes and is still not
	// the spelling of them. It is refused by the re-encoding alone, which is why
	// the re-encoding is part of the contract rather than a precaution.
	trailingBits := strings.Replace(vectorPeerPublicKeyB64, "HyA=", "HyB=", 1)
	if decoded, err := base64.StdEncoding.DecodeString(trailingBits); err != nil ||
		!bytes.Equal(decoded, synthetic) {
		t.Fatalf("the trailing-bits case must decode to the vector's own bytes: %v", err)
	}
	if _, err := decodePeerPublicKey(trailingBits); err == nil {
		t.Fatal("a second spelling of the pinned key was accepted")
	}
}

// TestDeterministicSchemaThreeVectorsAreHeldWithTheRustSide is the
// interoperability proof of the schema 3 encoding, for each of the three
// operation groups.
//
// Every transcript, every digest and every canonical document is pinned here
// literally. The Rust implementation of #95 pins the same values from its own
// encoder, so a single byte of drift in either implementation fails here rather
// than producing plans the other side hashes differently on a real machine.
func TestDeterministicSchemaThreeVectorsAreHeldWithTheRustSide(t *testing.T) {
	t.Parallel()
	for _, subject := range []struct {
		group              string
		build              func() (V3Pair, error)
		planDocument       string
		rollbackDocument   string
		planTranscript     string
		rollbackTranscript string
		planSHA256         string
		rollbackSHA256     string
		transcriptLength   int
	}{
		{
			group: "link",
			build: func() (V3Pair, error) {
				return BuildLinkPair(OperationPrepareLink, vectorInfrastructure, vectorMachine, vectorLinkRole)
			},
			planDocument:       vectorLinkPlanDocument,
			rollbackDocument:   vectorLinkRollbackDocument,
			planTranscript:     vectorLinkPlanTranscriptHex,
			rollbackTranscript: vectorLinkRollbackTranscriptHex,
			planSHA256:         vectorLinkPlanSHA256,
			rollbackSHA256:     vectorLinkRollbackSHA256,
			transcriptLength:   109,
		},
		{
			group: "listener peer",
			build: func() (V3Pair, error) {
				return BuildListenerPeerPair(OperationAttachLinkPeer, vectorInfrastructure,
					vectorMachine, vectorPeerPublicKeyB64, vectorServicePort)
			},
			planDocument:       vectorListenerPeerPlanDocument,
			rollbackDocument:   vectorListenerPeerRollbackDocument,
			planTranscript:     vectorListenerPeerPlanTranscriptHex,
			rollbackTranscript: vectorListenerPeerRollbackTranscriptHex,
			planSHA256:         vectorListenerPeerPlanSHA256,
			rollbackSHA256:     vectorListenerPeerRollbackSHA256,
			transcriptLength:   141,
		},
		{
			group: "initiator peer",
			build: func() (V3Pair, error) {
				return BuildInitiatorPeerPair(OperationJoinLinkPeer, vectorInfrastructure,
					vectorMachine, vectorPeerPublicKeyB64, vectorEndpointHost, vectorServicePort)
			},
			planDocument:       vectorInitiatorPeerPlanDocument,
			rollbackDocument:   vectorInitiatorPeerRollbackDocument,
			planTranscript:     vectorInitiatorPeerPlanTranscriptHex,
			rollbackTranscript: vectorInitiatorPeerRollbackTranscriptHex,
			planSHA256:         vectorInitiatorPeerPlanSHA256,
			rollbackSHA256:     vectorInitiatorPeerRollbackSHA256,
			transcriptLength:   166,
		},
	} {
		pair, err := subject.build()
		if err != nil {
			t.Fatalf("%s: %v", subject.group, err)
		}
		frozen, err := pair.Freeze()
		if err != nil {
			t.Fatalf("%s: %v", subject.group, err)
		}

		transcript, err := pair.Plan.Transcript()
		if err != nil {
			t.Fatalf("%s: %v", subject.group, err)
		}
		if len(transcript) != subject.transcriptLength {
			t.Fatalf("%s plan transcript length drifted: %d", subject.group, len(transcript))
		}
		if !bytes.Equal(transcript, decodedHex(t, subject.planTranscript)) {
			t.Fatalf("%s plan transcript drifted from the shared vector:\n%s",
				subject.group, hex.EncodeToString(transcript))
		}
		if !strings.HasPrefix(string(transcript), TranscriptDomainV3) {
			t.Fatalf("%s plan transcript does not start with its own domain separator", subject.group)
		}

		rollbackTranscript, err := pair.Rollback.Transcript()
		if err != nil {
			t.Fatalf("%s: %v", subject.group, err)
		}
		if !bytes.Equal(rollbackTranscript, decodedHex(t, subject.rollbackTranscript)) {
			t.Fatalf("%s rollback transcript drifted from the shared vector:\n%s",
				subject.group, hex.EncodeToString(rollbackTranscript))
		}

		if string(frozen.PlanDocument) != subject.planDocument {
			t.Fatalf("%s canonical plan document drifted:\n%s", subject.group, frozen.PlanDocument)
		}
		if string(frozen.RollbackDocument) != subject.rollbackDocument {
			t.Fatalf("%s canonical rollback document drifted:\n%s", subject.group, frozen.RollbackDocument)
		}
		if frozen.PlanSHA256 != subject.planSHA256 {
			t.Fatalf("%s plan_sha256 drifted: %s", subject.group, frozen.PlanSHA256)
		}
		if frozen.RollbackSHA256 != subject.rollbackSHA256 {
			t.Fatalf("%s rollback_sha256 drifted: %s", subject.group, frozen.RollbackSHA256)
		}
	}
}

// TestNoTwoPlanDigestsCollideAcrossTheThreeSchemas is what makes the three
// transcript layouts unambiguous without a group tag and without a schema tag:
// the twenty-four vectors of the product are twenty-four distinct documents and
// twenty-four distinct digests.
func TestNoTwoPlanDigestsCollideAcrossTheThreeSchemas(t *testing.T) {
	t.Parallel()
	seen := map[string]string{
		vectorPlanSHA256:                   "schema 1 probe deployment",
		vectorRollbackSHA256:               "schema 1 probe removal",
		vectorWebServicePlanSHA256:         "schema 2 web service deployment",
		vectorWebServiceRollbackSHA256:     "schema 2 web service removal",
		vectorEntrypointPlanSHA256:         "schema 2 entrypoint deployment",
		vectorEntrypointRollbackSHA256:     "schema 2 entrypoint removal",
		vectorRoutePlanSHA256:              "schema 2 route publication",
		vectorRouteRollbackSHA256:          "schema 2 route retirement",
		vectorPrivateServicePlanSHA256:     "schema 2 private service deployment",
		vectorPrivateServiceRollbackSHA256: "schema 2 private service removal",
		vectorLinkRoutePlanSHA256:          "schema 2 link route publication",
		vectorLinkRouteRollbackSHA256:      "schema 2 link route retirement",
		vectorSnapshotPlanSHA256:           "schema 2 snapshot",
		vectorSnapshotRollbackSHA256:       "schema 2 snapshot discard",
		vectorRestorePlanSHA256:            "schema 2 restore",
		vectorRestoreRollbackSHA256:        "schema 2 restore of the return slot",
		vectorSameFieldsRouteSHA256:        "schema 2 route sharing the link route's fields",
		vectorSameFieldsRetireRouteSHA256:  "schema 2 retirement sharing the link route's fields",
	}
	for name, digest := range map[string]string{
		"link preparation":    vectorLinkPlanSHA256,
		"link withdrawal":     vectorLinkRollbackSHA256,
		"listener junction":   vectorListenerPeerPlanSHA256,
		"listener detachal":   vectorListenerPeerRollbackSHA256,
		"initiator junction":  vectorInitiatorPeerPlanSHA256,
		"initiator departure": vectorInitiatorPeerRollbackSHA256,
	} {
		if other, collision := seen[digest]; collision {
			t.Fatalf("%s and %s name the same digest", name, other)
		}
		seen[digest] = name
	}
}

// TestChangingAnySingleFieldChangesTheSchemaThreeDigest is the central property
// of the transcript, held for each operation group.
//
// A field that could move without moving the digest would be a field the
// Controller owns, since the Controller is the only thing between the human who
// approved a plan and the machine that performs it. The wire documents are read
// back at the end so that a field added to a schema and forgotten in its
// transcript fails here.
func TestChangingAnySingleFieldChangesTheSchemaThreeDigest(t *testing.T) {
	t.Parallel()

	link := map[string]func(*LinkDocument){
		"infrastructure_id": func(d *LinkDocument) { d.InfrastructureID = otherInfrastructure },
		"machine_id":        func(d *LinkDocument) { d.MachineID = "lab-machine-2" },
		"operation":         func(d *LinkDocument) { d.Operation = OperationWithdrawLink },
		"schema_version":    func(d *LinkDocument) { d.SchemaVersion = SchemaVersionV2 },
		"link_role":         func(d *LinkDocument) { d.LinkRole = LinkRoleInitiator },
	}
	linkReference := rawLinkTranscript(vectorLink())
	for field, mutate := range link {
		moved := vectorLink()
		mutate(&moved)
		if bytes.Equal(rawLinkTranscript(moved), linkReference) {
			t.Fatalf("link %s is outside the hashed bytes", field)
		}
	}
	requireEveryWireFieldIsHeld(t, vectorLinkPlanDocument, keysOf(link))

	listener := map[string]func(*ListenerPeerDocument){
		"infrastructure_id": func(d *ListenerPeerDocument) { d.InfrastructureID = otherInfrastructure },
		"machine_id":        func(d *ListenerPeerDocument) { d.MachineID = "lab-machine-2" },
		"operation":         func(d *ListenerPeerDocument) { d.Operation = OperationDetachLinkPeer },
		"schema_version":    func(d *ListenerPeerDocument) { d.SchemaVersion = SchemaVersionV2 },
		"peer_public_key":   func(d *ListenerPeerDocument) { d.PeerPublicKey = otherPeerPublicKey },
		"service_port":      func(d *ListenerPeerDocument) { d.ServicePort = vectorServicePort + 1 },
	}
	listenerReference := rawListenerPeerTranscript(t, vectorListenerPeer())
	for field, mutate := range listener {
		moved := vectorListenerPeer()
		mutate(&moved)
		if bytes.Equal(rawListenerPeerTranscript(t, moved), listenerReference) {
			t.Fatalf("listener peer %s is outside the hashed bytes", field)
		}
	}
	requireEveryWireFieldIsHeld(t, vectorListenerPeerPlanDocument, keysOf(listener))

	initiator := map[string]func(*InitiatorPeerDocument){
		"infrastructure_id":  func(d *InitiatorPeerDocument) { d.InfrastructureID = otherInfrastructure },
		"machine_id":         func(d *InitiatorPeerDocument) { d.MachineID = "lab-machine-2" },
		"operation":          func(d *InitiatorPeerDocument) { d.Operation = OperationLeaveLinkPeer },
		"schema_version":     func(d *InitiatorPeerDocument) { d.SchemaVersion = SchemaVersionV2 },
		"peer_public_key":    func(d *InitiatorPeerDocument) { d.PeerPublicKey = otherPeerPublicKey },
		"peer_endpoint_host": func(d *InitiatorPeerDocument) { d.PeerEndpointHost = "other.lab.your-cloud.test" },
		"service_port":       func(d *InitiatorPeerDocument) { d.ServicePort = vectorServicePort + 1 },
	}
	initiatorReference := rawInitiatorPeerTranscript(t, vectorInitiatorPeer())
	for field, mutate := range initiator {
		moved := vectorInitiatorPeer()
		mutate(&moved)
		if bytes.Equal(rawInitiatorPeerTranscript(t, moved), initiatorReference) {
			t.Fatalf("initiator peer %s is outside the hashed bytes", field)
		}
	}
	requireEveryWireFieldIsHeld(t, vectorInitiatorPeerPlanDocument, keysOf(initiator))
}

// The raw transcripts below rebuild the layout for documents Validate refuses,
// so that a pinned field can still be proven to be inside the hashed bytes.

func rawLinkTranscript(document LinkDocument) []byte {
	transcript := appendV3Head(document.SchemaVersion, document.InfrastructureID,
		document.MachineID, document.Operation)
	return appendField(transcript, []byte(document.LinkRole))
}

func rawListenerPeerTranscript(t *testing.T, document ListenerPeerDocument) []byte {
	t.Helper()
	transcript := appendV3Head(document.SchemaVersion, document.InfrastructureID,
		document.MachineID, document.Operation)
	transcript = appendField(transcript, decodedBase64(t, document.PeerPublicKey))
	return appendUint32(transcript, uint32(document.ServicePort))
}

func rawInitiatorPeerTranscript(t *testing.T, document InitiatorPeerDocument) []byte {
	t.Helper()
	transcript := appendV3Head(document.SchemaVersion, document.InfrastructureID,
		document.MachineID, document.Operation)
	transcript = appendField(transcript, decodedBase64(t, document.PeerPublicKey))
	transcript = appendField(transcript, []byte(document.PeerEndpointHost))
	return appendUint32(transcript, uint32(document.ServicePort))
}

func decodedBase64(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	return decoded
}

// TestDecodeV3RefusesEveryLinkDocumentOutsideTheContract is the hostile table of
// the link group, and the whole surface of link_role.
func TestDecodeV3RefusesEveryLinkDocumentOutsideTheContract(t *testing.T) {
	t.Parallel()
	if _, err := DecodeV3([]byte(vectorLinkPlanDocument)); err != nil {
		t.Fatalf("the nominal document must decode: %v", err)
	}
	if _, err := DecodeV3([]byte(vectorLinkRollbackDocument)); err != nil {
		t.Fatalf("the nominal rollback must decode: %v", err)
	}
	// Both entries of the closed role list are accepted, so that the refusals
	// below name a role outside the list rather than a list of one.
	for _, role := range []string{LinkRoleListener, LinkRoleInitiator} {
		document := vectorLink()
		document.LinkRole = role
		if _, err := DecodeV3(hostilePlanDocument(t, document)); err != nil {
			t.Fatalf("the role %q was refused: %v", role, err)
		}
	}

	for name, mutate := range map[string]func(*LinkDocument){
		"schema 1 version":      func(d *LinkDocument) { d.SchemaVersion = SchemaVersion },
		"schema 2 version":      func(d *LinkDocument) { d.SchemaVersion = SchemaVersionV2 },
		"absent schema":         func(d *LinkDocument) { d.SchemaVersion = 0 },
		"upper-case UUID":       func(d *LinkDocument) { d.InfrastructureID = strings.ToUpper(vectorInfrastructure) },
		"empty infrastructure":  func(d *LinkDocument) { d.InfrastructureID = "" },
		"non version 4 UUID":    func(d *LinkDocument) { d.InfrastructureID = "8f14e45f-ceea-1167-a8b1-1f7bd0a0f4c2" },
		"traversal machine":     func(d *LinkDocument) { d.MachineID = "../../etc/shadow" },
		"upper-case machine":    func(d *LinkDocument) { d.MachineID = "LAB-MACHINE-1" },
		"unknown operation":     func(d *LinkDocument) { d.Operation = "establish_tunnel" },
		"probe operation":       func(d *LinkDocument) { d.Operation = OperationDeployOCIProbe },
		"service operation":     func(d *LinkDocument) { d.Operation = OperationDeployWebService },
		"route operation":       func(d *LinkDocument) { d.Operation = OperationPublishRoute },
		"listener operation":    func(d *LinkDocument) { d.Operation = OperationAttachLinkPeer },
		"initiator operation":   func(d *LinkDocument) { d.Operation = OperationJoinLinkPeer },
		"empty operation":       func(d *LinkDocument) { d.Operation = "" },
		"unknown role":          func(d *LinkDocument) { d.LinkRole = "relay" },
		"upper-case role":       func(d *LinkDocument) { d.LinkRole = "Listener" },
		"shouting role":         func(d *LinkDocument) { d.LinkRole = "LISTENER" },
		"empty role":            func(d *LinkDocument) { d.LinkRole = "" },
		"padded role":           func(d *LinkDocument) { d.LinkRole = "listener " },
		"both roles":            func(d *LinkDocument) { d.LinkRole = "listener,initiator" },
		"role carrying a break": func(d *LinkDocument) { d.LinkRole = "listener\ninitiator" },
		"role carrying a NUL":   func(d *LinkDocument) { d.LinkRole = "listener\x00" },
	} {
		document := vectorLink()
		mutate(&document)
		if _, err := DecodeV3(hostilePlanDocument(t, document)); err == nil {
			t.Fatalf("%s was accepted", name)
		}
	}
}

// TestDecodeV3RefusesEveryListenerPeerDocumentOutsideTheContract is the hostile
// table of the listener junction, and the whole surface of peer_public_key.
//
// The key is an observation the other machine reported, so it is the one field
// of the palier whose value nobody chose. That is exactly why its spelling is
// closed here: a key with a second accepted spelling would be a key with a
// second digest, and the human would have approved one of the two.
func TestDecodeV3RefusesEveryListenerPeerDocumentOutsideTheContract(t *testing.T) {
	t.Parallel()
	if _, err := DecodeV3([]byte(vectorListenerPeerPlanDocument)); err != nil {
		t.Fatalf("the nominal document must decode: %v", err)
	}
	if _, err := DecodeV3([]byte(vectorListenerPeerRollbackDocument)); err != nil {
		t.Fatalf("the nominal rollback must decode: %v", err)
	}
	for _, port := range []int{MinServicePort, MaxServicePort} {
		document := vectorListenerPeer()
		document.ServicePort = port
		if _, err := DecodeV3(hostilePlanDocument(t, document)); err != nil {
			t.Fatalf("the bound %d of the service range was refused: %v", port, err)
		}
	}

	for name, mutate := range map[string]func(*ListenerPeerDocument){
		"schema 1 version":    func(d *ListenerPeerDocument) { d.SchemaVersion = SchemaVersion },
		"schema 2 version":    func(d *ListenerPeerDocument) { d.SchemaVersion = SchemaVersionV2 },
		"absent schema":       func(d *ListenerPeerDocument) { d.SchemaVersion = 0 },
		"upper-case UUID":     func(d *ListenerPeerDocument) { d.InfrastructureID = strings.ToUpper(vectorInfrastructure) },
		"machine on hyphen":   func(d *ListenerPeerDocument) { d.MachineID = "-lab-machine-1" },
		"too short machine":   func(d *ListenerPeerDocument) { d.MachineID = "ab" },
		"unknown operation":   func(d *ListenerPeerDocument) { d.Operation = "attach_peer" },
		"link operation":      func(d *ListenerPeerDocument) { d.Operation = OperationPrepareLink },
		"initiator operation": func(d *ListenerPeerDocument) { d.Operation = OperationJoinLinkPeer },
		"service operation":   func(d *ListenerPeerDocument) { d.Operation = OperationRemoveWebService },
		"empty operation":     func(d *ListenerPeerDocument) { d.Operation = "" },

		// The whole surface of the peer key. Each of these decodes to the right
		// thirty-two bytes or nearly does, and each of them is a second spelling
		// the contract does not have.
		"empty key": func(d *ListenerPeerDocument) { d.PeerPublicKey = "" },
		"unpadded key": func(d *ListenerPeerDocument) {
			d.PeerPublicKey = strings.TrimSuffix(vectorPeerPublicKeyB64, "=")
		},
		"doubly padded key": func(d *ListenerPeerDocument) {
			d.PeerPublicKey = vectorPeerPublicKeyB64 + "="
		},
		"padding in front": func(d *ListenerPeerDocument) {
			d.PeerPublicKey = "=" + strings.TrimSuffix(vectorPeerPublicKeyB64, "=")
		},
		"padding inside": func(d *ListenerPeerDocument) {
			d.PeerPublicKey = strings.Replace(vectorPeerPublicKeyB64, "HyA=", "H=yA", 1)
		},
		"URL alphabet": func(d *ListenerPeerDocument) {
			d.PeerPublicKey = strings.Replace(vectorPeerPublicKeyB64, "HB0e", "HB0_", 1)
		},
		"URL hyphen": func(d *ListenerPeerDocument) {
			d.PeerPublicKey = strings.Replace(vectorPeerPublicKeyB64, "HB0e", "HB0-", 1)
		},
		"non-zero trailing bits": func(d *ListenerPeerDocument) {
			d.PeerPublicKey = strings.Replace(vectorPeerPublicKeyB64, "HyA=", "HyB=", 1)
		},
		"forty-three characters": func(d *ListenerPeerDocument) {
			d.PeerPublicKey = vectorPeerPublicKeyB64[:43]
		},
		"forty-five characters": func(d *ListenerPeerDocument) {
			d.PeerPublicKey = vectorPeerPublicKeyB64 + "A"
		},
		"thirty-three bytes": func(d *ListenerPeerDocument) {
			d.PeerPublicKey = strings.TrimSuffix(vectorPeerPublicKeyB64, "=") + "A"
		},
		"sixteen bytes": func(d *ListenerPeerDocument) {
			d.PeerPublicKey = base64.StdEncoding.EncodeToString(make([]byte, 16))
		},
		"hexadecimal key": func(d *ListenerPeerDocument) {
			d.PeerPublicKey = strings.Repeat("0", 44)
		},
		"key carrying a break": func(d *ListenerPeerDocument) {
			d.PeerPublicKey = strings.Replace(vectorPeerPublicKeyB64, "HB0e", "HB\n0", 1)
		},
		"key carrying a space": func(d *ListenerPeerDocument) {
			d.PeerPublicKey = strings.Replace(vectorPeerPublicKeyB64, "HB0e", "HB0 ", 1)
		},
		"key carrying a NUL": func(d *ListenerPeerDocument) {
			d.PeerPublicKey = strings.Replace(vectorPeerPublicKeyB64, "HB0e", "HB0\x00", 1)
		},

		"port below range":  func(d *ListenerPeerDocument) { d.ServicePort = MinServicePort - 1 },
		"privileged port":   func(d *ListenerPeerDocument) { d.ServicePort = 443 },
		"absent port":       func(d *ListenerPeerDocument) { d.ServicePort = 0 },
		"negative port":     func(d *ListenerPeerDocument) { d.ServicePort = -1 },
		"port above range":  func(d *ListenerPeerDocument) { d.ServicePort = MaxServicePort + 1 },
		"port beyond int16": func(d *ListenerPeerDocument) { d.ServicePort = 70000 },
	} {
		document := vectorListenerPeer()
		mutate(&document)
		if _, err := DecodeV3(hostilePlanDocument(t, document)); err == nil {
			t.Fatalf("%s was accepted", name)
		}
	}
}

// TestDecodeV3RefusesEveryInitiatorPeerDocumentOutsideTheContract is the hostile
// table of the initiator junction.
//
// Its endpoint host reuses the bound of route_host, so the malformations that
// bound proved on a published name are presented here again on the name the
// initiator reaches: one expression, one surface, and no second host grammar
// nobody would have read.
func TestDecodeV3RefusesEveryInitiatorPeerDocumentOutsideTheContract(t *testing.T) {
	t.Parallel()
	if _, err := DecodeV3([]byte(vectorInitiatorPeerPlanDocument)); err != nil {
		t.Fatalf("the nominal document must decode: %v", err)
	}
	if _, err := DecodeV3([]byte(vectorInitiatorPeerRollbackDocument)); err != nil {
		t.Fatalf("the nominal rollback must decode: %v", err)
	}
	for name, host := range map[string]string{
		"shortest accepted name": "abc",
		"longest accepted name":  strings.Repeat("a", 248) + ".test",
		"punycode label":         "xn--bcher-kva.lab.your-cloud.test",
		"IPv4 literal":           "192.0.2.10",
	} {
		document := vectorInitiatorPeer()
		document.PeerEndpointHost = host
		if _, err := DecodeV3(hostilePlanDocument(t, document)); err != nil {
			t.Fatalf("%s was refused: %v", name, err)
		}
	}

	for name, mutate := range map[string]func(*InitiatorPeerDocument){
		"schema 1 version":   func(d *InitiatorPeerDocument) { d.SchemaVersion = SchemaVersion },
		"schema 2 version":   func(d *InitiatorPeerDocument) { d.SchemaVersion = SchemaVersionV2 },
		"absent schema":      func(d *InitiatorPeerDocument) { d.SchemaVersion = 0 },
		"upper-case UUID":    func(d *InitiatorPeerDocument) { d.InfrastructureID = strings.ToUpper(vectorInfrastructure) },
		"traversal machine":  func(d *InitiatorPeerDocument) { d.MachineID = "../../etc/shadow" },
		"unknown operation":  func(d *InitiatorPeerDocument) { d.Operation = "join_peer" },
		"link operation":     func(d *InitiatorPeerDocument) { d.Operation = OperationWithdrawLink },
		"listener operation": func(d *InitiatorPeerDocument) { d.Operation = OperationAttachLinkPeer },
		"route operation":    func(d *InitiatorPeerDocument) { d.Operation = OperationRetireRoute },
		"empty operation":    func(d *InitiatorPeerDocument) { d.Operation = "" },

		"unpadded key": func(d *InitiatorPeerDocument) { d.PeerPublicKey = vectorPeerPublicKeyB64[:43] },
		"empty key":    func(d *InitiatorPeerDocument) { d.PeerPublicKey = "" },
		"URL alphabet": func(d *InitiatorPeerDocument) {
			d.PeerPublicKey = strings.Replace(vectorPeerPublicKeyB64, "HB0e", "HB0_", 1)
		},
		"trailing bits": func(d *InitiatorPeerDocument) {
			d.PeerPublicKey = strings.Replace(vectorPeerPublicKeyB64, "HyA=", "HyB=", 1)
		},
		"hexadecimal key": func(d *InitiatorPeerDocument) { d.PeerPublicKey = strings.Repeat("0", 44) },

		"empty host":            func(d *InitiatorPeerDocument) { d.PeerEndpointHost = "" },
		"host below bound":      func(d *InitiatorPeerDocument) { d.PeerEndpointHost = "ab" },
		"host above bound":      func(d *InitiatorPeerDocument) { d.PeerEndpointHost = strings.Repeat("a", 249) + ".test" },
		"wildcard host":         func(d *InitiatorPeerDocument) { d.PeerEndpointHost = "*.lab.your-cloud.test" },
		"upper-case host":       func(d *InitiatorPeerDocument) { d.PeerEndpointHost = "VPS.lab.your-cloud.test" },
		"leading dot":           func(d *InitiatorPeerDocument) { d.PeerEndpointHost = ".lab.your-cloud.test" },
		"trailing dot":          func(d *InitiatorPeerDocument) { d.PeerEndpointHost = "vps.lab.your-cloud.test." },
		"leading hyphen":        func(d *InitiatorPeerDocument) { d.PeerEndpointHost = "-vps.lab.your-cloud.test" },
		"trailing hyphen":       func(d *InitiatorPeerDocument) { d.PeerEndpointHost = "vps.lab.your-cloud.test-" },
		"consecutive dots":      func(d *InitiatorPeerDocument) { d.PeerEndpointHost = "vps..lab.your-cloud.test" },
		"underscore host":       func(d *InitiatorPeerDocument) { d.PeerEndpointHost = "vps_1.lab.your-cloud.test" },
		"host carrying a port":  func(d *InitiatorPeerDocument) { d.PeerEndpointHost = "vps.lab.your-cloud.test:51820" },
		"host carrying a path":  func(d *InitiatorPeerDocument) { d.PeerEndpointHost = "vps.lab.your-cloud.test/link" },
		"host carrying a space": func(d *InitiatorPeerDocument) { d.PeerEndpointHost = "vps lab.your-cloud.test" },
		"host carrying a break": func(d *InitiatorPeerDocument) { d.PeerEndpointHost = "vps.lab.test\nevil.test" },
		"non ASCII host":        func(d *InitiatorPeerDocument) { d.PeerEndpointHost = "vpsé.lab.your-cloud.test" },
		"trailing NUL host":     func(d *InitiatorPeerDocument) { d.PeerEndpointHost = "vps.lab.your-cloud.test\x00" },
		"IPv6 literal":          func(d *InitiatorPeerDocument) { d.PeerEndpointHost = "2001:db8::1" },

		"port below range":  func(d *InitiatorPeerDocument) { d.ServicePort = MinServicePort - 1 },
		"privileged port":   func(d *InitiatorPeerDocument) { d.ServicePort = 443 },
		"absent port":       func(d *InitiatorPeerDocument) { d.ServicePort = 0 },
		"negative port":     func(d *InitiatorPeerDocument) { d.ServicePort = -1 },
		"port above range":  func(d *InitiatorPeerDocument) { d.ServicePort = MaxServicePort + 1 },
		"port beyond int16": func(d *InitiatorPeerDocument) { d.ServicePort = 70000 },
	} {
		document := vectorInitiatorPeer()
		mutate(&document)
		if _, err := DecodeV3(hostilePlanDocument(t, document)); err == nil {
			t.Fatalf("%s was accepted", name)
		}
	}
}

// TestNoSchemaThreeDocumentBorrowsAFieldOfAnotherOperation is what the
// discriminator exists for, across the three groups of schema 3 and across the
// groups of schema 2.
//
// The operation is read first, and the document is then held against exactly the
// closed field list that operation declares. A field belonging to another
// operation — of this schema or of another one — is an unknown field of the
// claimed schema, refused before its value is read.
func TestNoSchemaThreeDocumentBorrowsAFieldOfAnotherOperation(t *testing.T) {
	t.Parallel()
	for name, document := range map[string]string{
		// Fields borrowed across the three groups of schema 3.
		"a link plan carrying a peer key":             withExtraField(vectorLinkPlanDocument, `"peer_public_key":"`+vectorPeerPublicKeyB64+`"`),
		"a link plan carrying a service port":         withExtraField(vectorLinkPlanDocument, `"service_port":8080`),
		"a link plan carrying an endpoint":            withExtraField(vectorLinkPlanDocument, `"peer_endpoint_host":"vps.lab.your-cloud.test"`),
		"a listener plan carrying an endpoint":        withExtraField(vectorListenerPeerPlanDocument, `"peer_endpoint_host":"vps.lab.your-cloud.test"`),
		"a listener plan carrying a role":             withExtraField(vectorListenerPeerPlanDocument, `"link_role":"listener"`),
		"an initiator plan carrying a role":           withExtraField(vectorInitiatorPeerPlanDocument, `"link_role":"initiator"`),
		"an initiator plan carrying an endpoint port": withExtraField(vectorInitiatorPeerPlanDocument, `"peer_endpoint_port":51820`),

		// Fields borrowed from the groups of schema 2.
		"a link plan carrying a route host":     withExtraField(vectorLinkPlanDocument, `"route_host":"evil.test"`),
		"a link plan carrying an image":         withExtraField(vectorLinkPlanDocument, `"image_reference":"`+BentoPDFImageReference+`"`),
		"a listener plan carrying a digest":     withExtraField(vectorListenerPeerPlanDocument, `"image_digest":"`+BentoPDFImageDigest+`"`),
		"a listener plan carrying a profile":    withExtraField(vectorListenerPeerPlanDocument, `"service_profile":"bentopdf"`),
		"a listener plan carrying a local port": withExtraField(vectorListenerPeerPlanDocument, `"local_port":8080`),
		"an initiator plan carrying a backend":  withExtraField(vectorInitiatorPeerPlanDocument, `"backend_port":8080`),
		"an initiator plan carrying a route":    withExtraField(vectorInitiatorPeerPlanDocument, `"route_host":"evil.test"`),

		// Operations swapped between shapes.
		"a link plan claiming a listener junction":   strings.Replace(vectorLinkPlanDocument, `"prepare_link"`, `"attach_link_peer"`, 1),
		"a link plan claiming an initiator junction": strings.Replace(vectorLinkPlanDocument, `"prepare_link"`, `"join_link_peer"`, 1),
		"a listener plan claiming a link":            strings.Replace(vectorListenerPeerPlanDocument, `"attach_link_peer"`, `"prepare_link"`, 1),
		"a listener plan claiming an initiator":      strings.Replace(vectorListenerPeerPlanDocument, `"attach_link_peer"`, `"join_link_peer"`, 1),
		"an initiator plan claiming a listener":      strings.Replace(vectorInitiatorPeerPlanDocument, `"join_link_peer"`, `"attach_link_peer"`, 1),
		"an initiator plan claiming a route":         strings.Replace(vectorInitiatorPeerPlanDocument, `"join_link_peer"`, `"publish_route"`, 1),

		// Fields the shape requires and the document does not carry.
		"a link plan without its role":       strings.Replace(vectorLinkPlanDocument, `,"link_role":"listener"`, "", 1),
		"a listener plan without its key":    strings.Replace(vectorListenerPeerPlanDocument, `"peer_public_key":"`+vectorPeerPublicKeyB64+`",`, "", 1),
		"a listener plan without its port":   strings.Replace(vectorListenerPeerPlanDocument, `,"service_port":8080`, "", 1),
		"an initiator plan without its host": strings.Replace(vectorInitiatorPeerPlanDocument, `"peer_endpoint_host":"vps.lab.your-cloud.test",`, "", 1),
		"an initiator plan without its key":  strings.Replace(vectorInitiatorPeerPlanDocument, `"peer_public_key":"`+vectorPeerPublicKeyB64+`",`, "", 1),

		// The framing itself.
		"a schema 3 document with no operation": strings.Replace(vectorLinkPlanDocument, `"operation":"prepare_link",`, "", 1),
		"a schema 3 document naming a number":   strings.Replace(vectorLinkPlanDocument, `"operation":"prepare_link"`, `"operation":3`, 1),
		"a schema 3 document naming null":       strings.Replace(vectorLinkPlanDocument, `"operation":"prepare_link"`, `"operation":null`, 1),
		"a schema 3 document naming an object":  strings.Replace(vectorLinkPlanDocument, `"operation":"prepare_link"`, `"operation":{"name":"prepare_link"}`, 1),
		"a document repeating its operation":    withExtraField(vectorLinkPlanDocument, `"operation":"withdraw_link"`),
		"a document repeating its role":         withExtraField(vectorLinkPlanDocument, `"link_role":"initiator"`),
		"a document repeating its peer key":     withExtraField(vectorListenerPeerPlanDocument, `"peer_public_key":"`+otherPeerPublicKey+`"`),
		"a document repeating its port":         withExtraField(vectorListenerPeerPlanDocument, `"service_port":9090`),
		"a document with a non-canonical name":  strings.Replace(vectorListenerPeerPlanDocument, `"peer_public_key"`, `"Peer_Public_Key"`, 1),
		"a document with a camel-case name":     strings.Replace(vectorListenerPeerPlanDocument, `"service_port"`, `"servicePort"`, 1),
		"a document with a stringified port":    strings.Replace(vectorListenerPeerPlanDocument, `"service_port":8080`, `"service_port":"8080"`, 1),
		"a document with a fractional port":     strings.Replace(vectorListenerPeerPlanDocument, `"service_port":8080`, `"service_port":8080.5`, 1),
		"a document with an exponent port":      strings.Replace(vectorListenerPeerPlanDocument, `"service_port":8080`, `"service_port":8.08e3`, 1),
		"a document with a key as an array":     strings.Replace(vectorListenerPeerPlanDocument, `"peer_public_key":"`+vectorPeerPublicKeyB64+`"`, `"peer_public_key":["`+vectorPeerPublicKeyB64+`"]`, 1),

		// The things a plan is never allowed to carry, whatever its schema.
		"a document carrying a private key":    withExtraField(vectorLinkPlanDocument, `"private_key":"`+vectorPeerPublicKeyB64+`"`),
		"a document carrying an allowed IP":    withExtraField(vectorListenerPeerPlanDocument, `"allowed_ips":["0.0.0.0/0"]`),
		"a document carrying an interface":     withExtraField(vectorLinkPlanDocument, `"interface":"yc-link1"`),
		"a document carrying a listen port":    withExtraField(vectorLinkPlanDocument, `"listen_port":51820`),
		"a document carrying a keepalive":      withExtraField(vectorInitiatorPeerPlanDocument, `"keepalive_seconds":25`),
		"a document carrying an nftables rule": withExtraField(vectorListenerPeerPlanDocument, `"nftables":"accept all"`),
		"a document carrying a command":        withExtraField(vectorLinkPlanDocument, `"command":"/bin/sh"`),

		"an empty document":                     "",
		"two values":                            vectorLinkPlanDocument + "{}",
		"an array of documents":                 "[" + vectorLinkPlanDocument + "]",
		"a truncated document":                  strings.TrimSuffix(vectorLinkPlanDocument, "}"),
		"an oversized document":                 strings.Replace(vectorInitiatorPeerPlanDocument, vectorEndpointHost, strings.Repeat("a", MaxPlanBytes), 1),
		"an oversized link document":            strings.Replace(vectorLinkPlanDocument, vectorLinkRole, strings.Repeat("a", MaxPlanBytes), 1),
		"a document that is only its operation": `{"operation":"prepare_link"}`,
	} {
		if _, err := DecodeV3([]byte(document)); err == nil {
			t.Fatalf("%s was accepted", name)
		}
	}
}

// TestTheThreeSchemasRefuseOneAnother keeps the two older contracts exactly
// where they were.
//
// A probe plan and a public profile plan decode, hash and freeze as they always
// did, and no decoder accepts a document of another schema — the version is not
// a hint, it selects which closed contract the document is held against.
func TestTheThreeSchemasRefuseOneAnother(t *testing.T) {
	t.Parallel()
	linkPlans := map[string]string{
		"a link plan":           vectorLinkPlanDocument,
		"a listener plan":       vectorListenerPeerPlanDocument,
		"an initiator plan":     vectorInitiatorPeerPlanDocument,
		"a link rollback":       vectorLinkRollbackDocument,
		"a listener rollback":   vectorListenerPeerRollbackDocument,
		"an initiator rollback": vectorInitiatorPeerRollbackDocument,
	}
	for name, document := range linkPlans {
		if _, err := Decode([]byte(document)); err == nil {
			t.Fatalf("the schema 1 decoder accepted %s", name)
		}
		if _, err := DecodeV2([]byte(document)); err == nil {
			t.Fatalf("the schema 2 decoder accepted %s", name)
		}
	}
	for name, document := range map[string]string{
		"a probe plan":           vectorPlanDocument,
		"a service plan":         vectorWebServicePlanDocument,
		"an entrypoint plan":     vectorEntrypointPlanDocument,
		"a route plan":           vectorRoutePlanDocument,
		"a private service plan": vectorPrivateServicePlanDocument,
		"a link route plan":      vectorLinkRoutePlanDocument,
		"a snapshot plan":        vectorSnapshotPlanDocument,
		"a restore plan":         vectorRestorePlanDocument,
	} {
		if _, err := DecodeV3([]byte(document)); err == nil {
			t.Fatalf("the schema 3 decoder accepted %s", name)
		}
	}

	for name, domain := range map[string]string{
		"schema 1": TranscriptDomain,
		"schema 2": TranscriptDomainV2,
	} {
		if domain == TranscriptDomainV3 {
			t.Fatalf("%s and schema 3 share a transcript domain", name)
		}
	}
	if SchemaVersionV3 == SchemaVersion || SchemaVersionV3 == SchemaVersionV2 {
		t.Fatal("schema 3 shares a version with an older schema")
	}
}

// TestASchemaThreePlanSurvivesTransportAndReturnsTheSameBytes states the exact
// limit of what a transport may do: reshape the JSON, and only that.
func TestASchemaThreePlanSurvivesTransportAndReturnsTheSameBytes(t *testing.T) {
	t.Parallel()
	for name, subject := range map[string]struct {
		canonical string
		reshaped  string
		digest    string
	}{
		"link": {
			canonical: vectorLinkPlanDocument,
			digest:    vectorLinkPlanSHA256,
			reshaped: fmt.Sprintf(`{
  "link_role": %q,
  "operation": %q,
  "machine_id": %q,
  "infrastructure_id": %q,
  "schema_version": 3
}`, vectorLinkRole, OperationPrepareLink, vectorMachine, vectorInfrastructure),
		},
		"listener peer": {
			canonical: vectorListenerPeerPlanDocument,
			digest:    vectorListenerPeerPlanSHA256,
			reshaped: fmt.Sprintf(`{
  "service_port": %d,
  "peer_public_key": %q,
  "operation": %q,
  "machine_id": %q,
  "infrastructure_id": %q,
  "schema_version": 3
}`, vectorServicePort, vectorPeerPublicKeyB64, OperationAttachLinkPeer, vectorMachine, vectorInfrastructure),
		},
		"initiator peer": {
			canonical: vectorInitiatorPeerPlanDocument,
			digest:    vectorInitiatorPeerPlanSHA256,
			reshaped: fmt.Sprintf(`{
  "service_port": %d,
  "peer_endpoint_host": %q,
  "peer_public_key": %q,
  "operation": %q,
  "machine_id": %q,
  "infrastructure_id": %q,
  "schema_version": 3
}`, vectorServicePort, vectorEndpointHost, vectorPeerPublicKeyB64,
				OperationJoinLinkPeer, vectorMachine, vectorInfrastructure),
		},
	} {
		decoded, err := DecodeV3([]byte(subject.canonical))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		digest, err := decoded.SHA256()
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if digest != subject.digest {
			t.Fatalf("%s: a decoded plan changed its digest: %s", name, digest)
		}
		reencoded, err := decoded.Encode()
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if string(reencoded) != subject.canonical {
			t.Fatalf("%s: re-encoding a decoded plan produced other bytes:\n%s", name, reencoded)
		}

		reordered, err := DecodeV3([]byte(subject.reshaped))
		if err != nil {
			t.Fatalf("%s: a reindented document is the same plan: %v", name, err)
		}
		reorderedDigest, err := reordered.SHA256()
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if reorderedDigest != subject.digest {
			t.Fatalf("%s: reindentation changed the plan digest: %s", name, reorderedDigest)
		}
		reorderedBytes, err := reordered.Encode()
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if string(reorderedBytes) != subject.canonical {
			t.Fatalf("%s: a reindented plan did not return to its canonical bytes:\n%s", name, reorderedBytes)
		}
	}
}

// TestTheRollbackOfASchemaThreePairIsTheOtherPairItself is what makes a rollback
// a plan rather than a promise, in each of the three groups: withdraw_link for
// prepare_link, detach_link_peer for attach_link_peer, leave_link_peer for
// join_link_peer.
func TestTheRollbackOfASchemaThreePairIsTheOtherPairItself(t *testing.T) {
	t.Parallel()
	for name, subject := range map[string]struct {
		forward func() (V3Pair, error)
		reverse func() (V3Pair, error)
	}{
		"link": {
			forward: func() (V3Pair, error) {
				return BuildLinkPair(OperationPrepareLink, vectorInfrastructure, vectorMachine, vectorLinkRole)
			},
			reverse: func() (V3Pair, error) {
				return BuildLinkPair(OperationWithdrawLink, vectorInfrastructure, vectorMachine, vectorLinkRole)
			},
		},
		"listener peer": {
			forward: func() (V3Pair, error) {
				return BuildListenerPeerPair(OperationAttachLinkPeer, vectorInfrastructure,
					vectorMachine, vectorPeerPublicKeyB64, vectorServicePort)
			},
			reverse: func() (V3Pair, error) {
				return BuildListenerPeerPair(OperationDetachLinkPeer, vectorInfrastructure,
					vectorMachine, vectorPeerPublicKeyB64, vectorServicePort)
			},
		},
		"initiator peer": {
			forward: func() (V3Pair, error) {
				return BuildInitiatorPeerPair(OperationJoinLinkPeer, vectorInfrastructure,
					vectorMachine, vectorPeerPublicKeyB64, vectorEndpointHost, vectorServicePort)
			},
			reverse: func() (V3Pair, error) {
				return BuildInitiatorPeerPair(OperationLeaveLinkPeer, vectorInfrastructure,
					vectorMachine, vectorPeerPublicKeyB64, vectorEndpointHost, vectorServicePort)
			},
		},
	} {
		forward, err := subject.forward()
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		reverse, err := subject.reverse()
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		frozenForward, err := forward.Freeze()
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		frozenReverse, err := reverse.Freeze()
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}

		if frozenForward.RollbackSHA256 != frozenReverse.PlanSHA256 {
			t.Fatalf("%s: the rollback of a plan is not the other direction of the same instance", name)
		}
		if frozenReverse.RollbackSHA256 != frozenForward.PlanSHA256 {
			t.Fatalf("%s: the two directions do not undo one another", name)
		}
		if !bytes.Equal(frozenForward.RollbackDocument, frozenReverse.PlanDocument) ||
			!bytes.Equal(frozenReverse.RollbackDocument, frozenForward.PlanDocument) {
			t.Fatalf("%s: the two directions do not carry the same documents", name)
		}
		if frozenForward.PlanSHA256 == frozenForward.RollbackSHA256 {
			t.Fatalf("%s: a plan and its rollback must not be the same document", name)
		}
		if !forward.Rollback.IsExactInverseOf(forward.Plan) || !forward.Plan.IsExactInverseOf(forward.Rollback) {
			t.Fatalf("%s: undoing is not symmetric between the two documents of a pair", name)
		}
		if forward.Plan.IsExactInverseOf(forward.Plan) {
			t.Fatalf("%s: a plan was read as undoing itself", name)
		}
		if forward.Rollback.IsExactInverseOf(nil) {
			t.Fatalf("%s: an absent plan was read as undone", name)
		}
		if forward.Plan.Target() != (Target{InfrastructureID: vectorInfrastructure, MachineID: vectorMachine}) {
			t.Fatalf("%s: a plan names another target than the one it was built for", name)
		}
		if forward.Rollback.Target() != forward.Plan.Target() {
			t.Fatalf("%s: a rollback aims at another machine than the plan it undoes", name)
		}
	}
}

// TestARollbackOfSchemaThreeIsRecognisedOnlyWhenItUndoesExactlyThePlan is what a
// machine asks before acting: the document it was handed as an undoing has to be
// one it could apply to return to the state it is about to leave.
func TestARollbackOfSchemaThreeIsRecognisedOnlyWhenItUndoesExactlyThePlan(t *testing.T) {
	t.Parallel()
	link, err := BuildLinkPair(OperationPrepareLink, vectorInfrastructure, vectorMachine, vectorLinkRole)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := BuildListenerPeerPair(OperationAttachLinkPeer, vectorInfrastructure,
		vectorMachine, vectorPeerPublicKeyB64, vectorServicePort)
	if err != nil {
		t.Fatal(err)
	}
	initiator, err := BuildInitiatorPeerPair(OperationJoinLinkPeer, vectorInfrastructure,
		vectorMachine, vectorPeerPublicKeyB64, vectorEndpointHost, vectorServicePort)
	if err != nil {
		t.Fatal(err)
	}

	// A document of another operation group is never an undoing, whatever it
	// names: the two are not the same plan written differently.
	if listener.Rollback.IsExactInverseOf(link.Plan) || link.Rollback.IsExactInverseOf(listener.Plan) {
		t.Fatal("a document of another operation group was read as an undoing")
	}
	if initiator.Rollback.IsExactInverseOf(listener.Plan) || listener.Rollback.IsExactInverseOf(initiator.Plan) {
		t.Fatal("a junction of one side was read as undoing the junction of the other")
	}

	for name, forge := range map[string]func(*LinkDocument){
		"another machine":        func(d *LinkDocument) { d.MachineID = "lab-machine-2" },
		"another infrastructure": func(d *LinkDocument) { d.InfrastructureID = otherInfrastructure },
		"another role":           func(d *LinkDocument) { d.LinkRole = LinkRoleInitiator },
		"the same operation":     func(d *LinkDocument) { d.Operation = OperationPrepareLink },
		"an unknown operation":   func(d *LinkDocument) { d.Operation = "establish_tunnel" },
	} {
		forged, ok := link.Rollback.(LinkDocument)
		if !ok {
			t.Fatal("the rollback of a link pair is not a link document")
		}
		forge(&forged)
		if forged.IsExactInverseOf(link.Plan) {
			t.Fatalf("a rollback naming %s was read as undoing the plan", name)
		}
	}

	for name, forge := range map[string]func(*InitiatorPeerDocument){
		"another peer":         func(d *InitiatorPeerDocument) { d.PeerPublicKey = otherPeerPublicKey },
		"another endpoint":     func(d *InitiatorPeerDocument) { d.PeerEndpointHost = "other.lab.your-cloud.test" },
		"another port":         func(d *InitiatorPeerDocument) { d.ServicePort = vectorServicePort + 1 },
		"the same operation":   func(d *InitiatorPeerDocument) { d.Operation = OperationJoinLinkPeer },
		"an unknown operation": func(d *InitiatorPeerDocument) { d.Operation = "join_peer" },
	} {
		forged, ok := initiator.Rollback.(InitiatorPeerDocument)
		if !ok {
			t.Fatal("the rollback of an initiator pair is not an initiator document")
		}
		forge(&forged)
		if forged.IsExactInverseOf(initiator.Plan) {
			t.Fatalf("a rollback naming %s was read as undoing the junction", name)
		}
	}
}

func TestSchemaThreeBuildersRefuseEveryInstanceOutsideTheContract(t *testing.T) {
	t.Parallel()
	for _, role := range []string{LinkRoleListener, LinkRoleInitiator} {
		if _, err := BuildLinkPair(OperationPrepareLink, vectorInfrastructure, vectorMachine, role); err != nil {
			t.Fatalf("the role %q must build: %v", role, err)
		}
	}
	for _, port := range []int{MinServicePort, MaxServicePort} {
		if _, err := BuildListenerPeerPair(OperationAttachLinkPeer, vectorInfrastructure,
			vectorMachine, vectorPeerPublicKeyB64, port); err != nil {
			t.Fatalf("the bound %d of the service range must build: %v", port, err)
		}
	}

	for name, build := range map[string]func() (V3Pair, error){
		"a link pair on an unknown operation": func() (V3Pair, error) {
			return BuildLinkPair("establish_tunnel", vectorInfrastructure, vectorMachine, vectorLinkRole)
		},
		"a link pair on a schema 2 operation": func() (V3Pair, error) {
			return BuildLinkPair(OperationDeployEntrypoint, vectorInfrastructure, vectorMachine, vectorLinkRole)
		},
		"a link pair on a junction operation": func() (V3Pair, error) {
			return BuildLinkPair(OperationAttachLinkPeer, vectorInfrastructure, vectorMachine, vectorLinkRole)
		},
		"a link pair without an operation": func() (V3Pair, error) {
			return BuildLinkPair("", vectorInfrastructure, vectorMachine, vectorLinkRole)
		},
		"a link pair on an unknown role": func() (V3Pair, error) {
			return BuildLinkPair(OperationPrepareLink, vectorInfrastructure, vectorMachine, "relay")
		},
		"a link pair without a role": func() (V3Pair, error) {
			return BuildLinkPair(OperationPrepareLink, vectorInfrastructure, vectorMachine, "")
		},
		"a link pair on a malformed machine": func() (V3Pair, error) {
			return BuildLinkPair(OperationPrepareLink, vectorInfrastructure, "LAB", vectorLinkRole)
		},
		"a link pair on a malformed infrastructure": func() (V3Pair, error) {
			return BuildLinkPair(OperationPrepareLink, "not-a-uuid", vectorMachine, vectorLinkRole)
		},
		"a listener pair on a link operation": func() (V3Pair, error) {
			return BuildListenerPeerPair(OperationPrepareLink, vectorInfrastructure,
				vectorMachine, vectorPeerPublicKeyB64, vectorServicePort)
		},
		"a listener pair on an initiator operation": func() (V3Pair, error) {
			return BuildListenerPeerPair(OperationJoinLinkPeer, vectorInfrastructure,
				vectorMachine, vectorPeerPublicKeyB64, vectorServicePort)
		},
		"a listener pair on a non-canonical key": func() (V3Pair, error) {
			return BuildListenerPeerPair(OperationAttachLinkPeer, vectorInfrastructure,
				vectorMachine, vectorPeerPublicKeyB64[:43], vectorServicePort)
		},
		"a listener pair on a URL-alphabet key": func() (V3Pair, error) {
			return BuildListenerPeerPair(OperationAttachLinkPeer, vectorInfrastructure, vectorMachine,
				strings.Replace(vectorPeerPublicKeyB64, "HB0e", "HB0_", 1), vectorServicePort)
		},
		"a listener pair without a key": func() (V3Pair, error) {
			return BuildListenerPeerPair(OperationAttachLinkPeer, vectorInfrastructure,
				vectorMachine, "", vectorServicePort)
		},
		"a listener pair on a privileged port": func() (V3Pair, error) {
			return BuildListenerPeerPair(OperationAttachLinkPeer, vectorInfrastructure,
				vectorMachine, vectorPeerPublicKeyB64, 443)
		},
		"a listener pair beyond the service range": func() (V3Pair, error) {
			return BuildListenerPeerPair(OperationAttachLinkPeer, vectorInfrastructure,
				vectorMachine, vectorPeerPublicKeyB64, MaxServicePort+1)
		},
		"an initiator pair on a listener operation": func() (V3Pair, error) {
			return BuildInitiatorPeerPair(OperationDetachLinkPeer, vectorInfrastructure,
				vectorMachine, vectorPeerPublicKeyB64, vectorEndpointHost, vectorServicePort)
		},
		"an initiator pair on a wildcard endpoint": func() (V3Pair, error) {
			return BuildInitiatorPeerPair(OperationJoinLinkPeer, vectorInfrastructure,
				vectorMachine, vectorPeerPublicKeyB64, "*.lab.your-cloud.test", vectorServicePort)
		},
		"an initiator pair without an endpoint": func() (V3Pair, error) {
			return BuildInitiatorPeerPair(OperationJoinLinkPeer, vectorInfrastructure,
				vectorMachine, vectorPeerPublicKeyB64, "", vectorServicePort)
		},
		"an initiator pair on an endpoint carrying a port": func() (V3Pair, error) {
			return BuildInitiatorPeerPair(OperationJoinLinkPeer, vectorInfrastructure, vectorMachine,
				vectorPeerPublicKeyB64, "vps.lab.your-cloud.test:51820", vectorServicePort)
		},
		"an initiator pair on the read-only operation of an older palier": func() (V3Pair, error) {
			return BuildInitiatorPeerPair("diagnose_protocol_read_only", vectorInfrastructure,
				vectorMachine, vectorPeerPublicKeyB64, vectorEndpointHost, vectorServicePort)
		},
	} {
		if _, err := build(); err == nil {
			t.Fatalf("%s built a pair", name)
		}
	}

	// An empty pair freezes nothing rather than freezing a zero document.
	if _, err := (V3Pair{}).Freeze(); err == nil {
		t.Fatal("an empty pair was frozen")
	}
}

// TestTheConstantsOfThePrivatePassageAreNotFieldsOfAnyPlan keeps the decisions of
// the contract testable rather than merely written.
//
// The subnet, the two tunnel addresses, the interface name, the listening port
// and the keepalive are constants of the reference scenario. None of them is an
// approvable value, so none of them may appear as a field of any schema 3
// document — and the wire vectors above are what that is held against.
func TestTheConstantsOfThePrivatePassageAreNotFieldsOfAnyPlan(t *testing.T) {
	t.Parallel()
	for name, document := range map[string]string{
		"link":           vectorLinkPlanDocument,
		"listener peer":  vectorListenerPeerPlanDocument,
		"initiator peer": vectorInitiatorPeerPlanDocument,
	} {
		fields := map[string]json.RawMessage{}
		if err := json.Unmarshal([]byte(document), &fields); err != nil {
			t.Fatal(err)
		}
		for _, forbidden := range []string{
			"allowed_ips", "interface", "listen_port", "keepalive_seconds",
			"private_key", "address", "subnet", "peer_endpoint_port", "nftables",
		} {
			if _, present := fields[forbidden]; present {
				t.Fatalf("the %s document carries %q, which is a constant of the contract", name, forbidden)
			}
		}
	}

	if len(inverseOperationV3) != 6 || len(linkOperationGroups) != 6 {
		t.Fatalf("schema 3 describes exactly six operations, not %d and %d",
			len(inverseOperationV3), len(linkOperationGroups))
	}
	if len(linkRoles) != 2 {
		t.Fatalf("the link role is closed to two entries, not %d", len(linkRoles))
	}
	for operation, inverse := range inverseOperationV3 {
		if inverseOperationV3[inverse] != operation {
			t.Fatalf("operation %q is not undone by an operation that redoes it", operation)
		}
		if linkOperationGroups[operation] == 0 {
			t.Fatalf("operation %q carries no closed field list", operation)
		}
		if linkOperationGroups[inverse] != linkOperationGroups[operation] {
			t.Fatalf("operation %q and its undoing do not carry the same fields", operation)
		}
		if _, borrowed := operationGroups[operation]; borrowed {
			t.Fatalf("the schema 3 operation %q carries a schema 2 field list", operation)
		}
	}
	for operation := range operationGroups {
		if _, borrowed := linkOperationGroups[operation]; borrowed {
			t.Fatalf("the schema 2 operation %q carries a schema 3 field list", operation)
		}
	}
}

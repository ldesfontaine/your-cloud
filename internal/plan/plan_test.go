package plan

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

const (
	vectorInfrastructure = "8f14e45f-ceea-4167-a8b1-1f7bd0a0f4c2"
	vectorMachine        = "lab-machine-1"
	vectorPort           = 8080

	// The two canonical documents of the vector, byte for byte. A transport may
	// reindent them; the Controller emits exactly these bytes.
	vectorPlanDocument = `{"schema_version":1,"infrastructure_id":"8f14e45f-ceea-4167-a8b1-1f7bd0a0f4c2",` +
		`"machine_id":"lab-machine-1","operation":"deploy_oci_probe",` +
		`"image_reference":"docker.io/traefik/whoami",` +
		`"image_digest":"sha256:200689790a0a0ea48ca45992e0450bc26ccab5307375b41c84dfc4f2475937ab",` +
		`"local_port":8080}`
	vectorRollbackDocument = `{"schema_version":1,"infrastructure_id":"8f14e45f-ceea-4167-a8b1-1f7bd0a0f4c2",` +
		`"machine_id":"lab-machine-1","operation":"remove_oci_probe",` +
		`"image_reference":"docker.io/traefik/whoami",` +
		`"image_digest":"sha256:200689790a0a0ea48ca45992e0450bc26ccab5307375b41c84dfc4f2475937ab",` +
		`"local_port":8080}`

	// The two transcripts, byte for byte. The Rust side of this palier, tracked
	// by #83, must reproduce these exact vectors from its own encoder: a
	// canonical encoding that exists in two implementations is only canonical
	// while the two agree byte for byte, and a drift caught here is a drift that
	// never reaches a machine as an approval the other side refuses.
	vectorPlanTranscriptHex = "796f75722d636c6f75642f6f63692d706c616e2e76310001000000243866313465" +
		"3435662d636565612d343136372d613862312d3166376264306130663463320000" +
		"000d6c61622d6d616368696e652d31000000106465706c6f795f6f63695f70726f" +
		"626500000018646f636b65722e696f2f7472616566696b2f77686f616d69000000" +
		"20200689790a0a0ea48ca45992e0450bc26ccab5307375b41c84dfc4f2475937ab" +
		"00001f90"
	vectorRollbackTranscriptHex = "796f75722d636c6f75642f6f63692d706c616e2e76310001000000243866313465" +
		"3435662d636565612d343136372d613862312d3166376264306130663463320000" +
		"000d6c61622d6d616368696e652d310000001072656d6f76655f6f63695f70726f" +
		"626500000018646f636b65722e696f2f7472616566696b2f77686f616d69000000" +
		"20200689790a0a0ea48ca45992e0450bc26ccab5307375b41c84dfc4f2475937ab" +
		"00001f90"

	// The two digests an approval envelope of this vector names as plan_sha256
	// and rollback_sha256, in the exact spelling that envelope requires.
	vectorPlanSHA256     = "2d50d2bc935ce6c56ef14fbfae93d670d5fdb9ca735315e5a26760d818dd5b0e"
	vectorRollbackSHA256 = "e953fb5f9d8423be61cad4a06d571e200977dd183f53c12d5a897746ad80497a"

	// The amd64 image the pinned manifest list resolves to. It is a real digest
	// of the same probe and is still refused, because the plan names the
	// manifest list and nothing else may stand in for it.
	resolvedAMD64Digest = "sha256:4f90b33ddca9c4d4f06527070d6e503b16d71016edea036842be2a84e60c91cb"
)

func vectorDocument() Document {
	return Document{
		SchemaVersion:    SchemaVersion,
		InfrastructureID: vectorInfrastructure,
		MachineID:        vectorMachine,
		Operation:        OperationDeployOCIProbe,
		ImageReference:   ProbeImageReference,
		ImageDigest:      ProbeImageDigest,
		LocalPort:        vectorPort,
	}
}

// hostileDocument encodes a document without validating it, which is what a
// hostile test needs: the refusal under test must come from Decode rather than
// from the encoder refusing to produce the bytes in the first place.
func hostileDocument(t *testing.T, document Document) []byte {
	t.Helper()
	encoded, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

// TestDeterministicPlanVectorsAreHeldWithTheRustSide is the interoperability
// proof of the plan encoding.
//
// Both transcripts, both digests and both canonical documents are pinned here
// literally. The Rust implementation of #83 pins the same values from its own
// encoder, so a single byte of drift in either implementation fails here rather
// than producing plans the other side hashes differently on a real machine.
func TestDeterministicPlanVectorsAreHeldWithTheRustSide(t *testing.T) {
	t.Parallel()
	pair, err := BuildPair(OperationDeployOCIProbe, vectorInfrastructure, vectorMachine, vectorPort)
	if err != nil {
		t.Fatal(err)
	}
	frozen, err := pair.Freeze()
	if err != nil {
		t.Fatal(err)
	}

	transcript, err := pair.Plan.Transcript()
	if err != nil {
		t.Fatal(err)
	}
	expected, err := hex.DecodeString(vectorPlanTranscriptHex)
	if err != nil {
		t.Fatal(err)
	}
	if len(transcript) != 169 {
		t.Fatalf("plan transcript length drifted: %d", len(transcript))
	}
	if !bytes.Equal(transcript, expected) {
		t.Fatalf("plan transcript drifted from the shared vector:\n%s", hex.EncodeToString(transcript))
	}
	if !strings.HasPrefix(string(transcript), TranscriptDomain) {
		t.Fatal("plan transcript does not start with its own domain separator")
	}

	rollbackTranscript, err := pair.Rollback.Transcript()
	if err != nil {
		t.Fatal(err)
	}
	expectedRollback, err := hex.DecodeString(vectorRollbackTranscriptHex)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(rollbackTranscript, expectedRollback) {
		t.Fatalf("rollback transcript drifted from the shared vector:\n%s", hex.EncodeToString(rollbackTranscript))
	}

	if string(frozen.PlanDocument) != vectorPlanDocument {
		t.Fatalf("canonical plan document drifted:\n%s", frozen.PlanDocument)
	}
	if string(frozen.RollbackDocument) != vectorRollbackDocument {
		t.Fatalf("canonical rollback document drifted:\n%s", frozen.RollbackDocument)
	}
	if frozen.PlanSHA256 != vectorPlanSHA256 {
		t.Fatalf("plan_sha256 drifted: %s", frozen.PlanSHA256)
	}
	if frozen.RollbackSHA256 != vectorRollbackSHA256 {
		t.Fatalf("rollback_sha256 drifted: %s", frozen.RollbackSHA256)
	}
}

// TestChangingAnySingleFieldChangesThePlanDigest is the central property of the
// transcript.
//
// A field that could move without moving the digest would be a field the
// Controller owns, since the Controller is the only thing between the human who
// approved a plan and the machine that performs it.
func TestChangingAnySingleFieldChangesThePlanDigest(t *testing.T) {
	t.Parallel()
	control := vectorDocument()
	original, err := control.SHA256()
	if err != nil {
		t.Fatal(err)
	}

	mutations := map[string]func(*Document){
		"infrastructure_id": func(d *Document) { d.InfrastructureID = "8f14e45f-ceea-4167-a8b1-1f7bd0a0f4c3" },
		"machine_id":        func(d *Document) { d.MachineID = "lab-machine-2" },
		"operation":         func(d *Document) { d.Operation = OperationRemoveOCIProbe },
		"local_port":        func(d *Document) { d.LocalPort = vectorPort + 1 },
	}
	for field, mutate := range mutations {
		moved := vectorDocument()
		mutate(&moved)
		digest, err := moved.SHA256()
		if err != nil {
			t.Fatalf("%s: %v", field, err)
		}
		if digest == original {
			t.Fatalf("%s is outside the hashed bytes", field)
		}
	}

	// The three remaining fields have exactly one accepted value each, so they
	// are held by rebuilding the transcript outside the validated range and
	// requiring the bytes to move.
	unvalidated := map[string]func(*Document){
		"schema_version":  func(d *Document) { d.SchemaVersion = 2 },
		"image_reference": func(d *Document) { d.ImageReference = "ghcr.io/traefik/whoami" },
		"image_digest":    func(d *Document) { d.ImageDigest = resolvedAMD64Digest },
	}
	reference, err := control.Transcript()
	if err != nil {
		t.Fatal(err)
	}
	for field, mutate := range unvalidated {
		moved := vectorDocument()
		mutate(&moved)
		if bytes.Equal(rawTranscript(t, moved), reference) {
			t.Fatalf("%s is outside the hashed bytes", field)
		}
	}

	// Every field of the wire document is one of the ones exercised above. A
	// field added to the plan and forgotten in the transcript fails here.
	wire := map[string]json.RawMessage{}
	if err := json.Unmarshal([]byte(vectorPlanDocument), &wire); err != nil {
		t.Fatal(err)
	}
	if len(wire) != 7 {
		t.Fatalf("the closed field list of this palier holds seven fields, not %d", len(wire))
	}
	for name := range wire {
		_, bounded := mutations[name]
		_, pinned := unvalidated[name]
		if !bounded && !pinned {
			t.Fatalf("field %q of the plan is never held against its digest", name)
		}
	}
}

// rawTranscript rebuilds the transcript layout for a document Validate refuses,
// so that a pinned field can still be proven to be inside the hashed bytes.
func rawTranscript(t *testing.T, document Document) []byte {
	t.Helper()
	image, err := hex.DecodeString(strings.TrimPrefix(document.ImageDigest, "sha256:"))
	if err != nil {
		t.Fatal(err)
	}
	transcript := append([]byte(nil), TranscriptDomain...)
	transcript = append(transcript, byte(document.SchemaVersion))
	transcript = appendField(transcript, []byte(document.InfrastructureID))
	transcript = appendField(transcript, []byte(document.MachineID))
	transcript = appendField(transcript, []byte(document.Operation))
	transcript = appendField(transcript, []byte(document.ImageReference))
	transcript = appendField(transcript, image)
	return appendUint32(transcript, uint32(document.LocalPort))
}

func TestDecodeRefusesEveryDocumentOutsideTheContract(t *testing.T) {
	t.Parallel()
	// Positive control.
	if _, err := Decode([]byte(vectorPlanDocument)); err != nil {
		t.Fatalf("the nominal document must decode: %v", err)
	}

	fields := map[string]func(*Document){
		"unsupported schema":        func(d *Document) { d.SchemaVersion = 2 },
		"absent schema":             func(d *Document) { d.SchemaVersion = 0 },
		"upper-case UUID":           func(d *Document) { d.InfrastructureID = strings.ToUpper(vectorInfrastructure) },
		"non version 4 UUID":        func(d *Document) { d.InfrastructureID = "8f14e45f-ceea-1167-a8b1-1f7bd0a0f4c2" },
		"empty infrastructure":      func(d *Document) { d.InfrastructureID = "" },
		"traversal machine":         func(d *Document) { d.MachineID = "../../etc/shadow" },
		"upper-case machine":        func(d *Document) { d.MachineID = "LAB-MACHINE-1" },
		"too short machine":         func(d *Document) { d.MachineID = "ab" },
		"machine opening on hyphen": func(d *Document) { d.MachineID = "-lab-machine-1" },
		"unknown operation":         func(d *Document) { d.Operation = "install_container" },
		"upper-case operation":      func(d *Document) { d.Operation = strings.ToUpper(OperationDeployOCIProbe) },
		"empty operation":           func(d *Document) { d.Operation = "" },
		"other registry":            func(d *Document) { d.ImageReference = "ghcr.io/traefik/whoami" },
		"other repository":          func(d *Document) { d.ImageReference = "docker.io/attacker/whoami" },
		"tagged reference":          func(d *Document) { d.ImageReference = ProbeImageReference + ":latest" },
		"reference carrying its own digest": func(d *Document) {
			d.ImageReference = ProbeImageReference + "@" + ProbeImageDigest
		},
		"registry-less reference": func(d *Document) { d.ImageReference = "traefik/whoami" },
		"resolved amd64 digest":   func(d *Document) { d.ImageDigest = resolvedAMD64Digest },
		"upper-case digest":       func(d *Document) { d.ImageDigest = strings.ToUpper(ProbeImageDigest) },
		"unprefixed digest": func(d *Document) {
			d.ImageDigest = strings.TrimPrefix(ProbeImageDigest, "sha256:")
		},
		"upper-case digest algorithm": func(d *Document) {
			d.ImageDigest = "SHA256:" + strings.TrimPrefix(ProbeImageDigest, "sha256:")
		},
		"other digest algorithm": func(d *Document) {
			d.ImageDigest = "sha512:" + strings.TrimPrefix(ProbeImageDigest, "sha256:")
		},
		"short digest":      func(d *Document) { d.ImageDigest = "sha256:2006" },
		"port below range":  func(d *Document) { d.LocalPort = MinLocalPort - 1 },
		"privileged port":   func(d *Document) { d.LocalPort = 80 },
		"absent port":       func(d *Document) { d.LocalPort = 0 },
		"negative port":     func(d *Document) { d.LocalPort = -1 },
		"port above range":  func(d *Document) { d.LocalPort = MaxLocalPort + 1 },
		"port beyond int16": func(d *Document) { d.LocalPort = 70000 },
	}
	for name, mutate := range fields {
		document := vectorDocument()
		mutate(&document)
		if _, err := Decode(hostileDocument(t, document)); err == nil {
			t.Fatalf("%s was accepted", name)
		}
	}

	documents := map[string]string{
		"empty":      "",
		"two values": vectorPlanDocument + "{}",
		"array":      "[" + vectorPlanDocument + "]",
		"truncated":  strings.TrimSuffix(vectorPlanDocument, "}"),
		// A tag, a volume, a network, a privilege or a command are all the same
		// refusal: a field the schema does not declare, refused before its value
		// is read.
		"tag field":        withExtraField(vectorPlanDocument, `"tag":"latest"`),
		"volume field":     withExtraField(vectorPlanDocument, `"volumes":["/etc:/etc"]`),
		"network field":    withExtraField(vectorPlanDocument, `"network":"host"`),
		"privileged field": withExtraField(vectorPlanDocument, `"privileged":true`),
		"command field":    withExtraField(vectorPlanDocument, `"command":"/bin/sh"`),
		"environment field": withExtraField(vectorPlanDocument,
			`"environment":{"YOUR_CLOUD":"1"}`),
		"repeated field": withExtraField(vectorPlanDocument, `"local_port":9090`),
		"non-canonical field name": strings.Replace(vectorPlanDocument,
			`"local_port"`, `"Local_Port"`, 1),
		"camel-case field name": strings.Replace(vectorPlanDocument,
			`"machine_id"`, `"machineId"`, 1),
		"port as string": strings.Replace(vectorPlanDocument,
			`"local_port":8080`, `"local_port":"8080"`, 1),
		"fractional port": strings.Replace(vectorPlanDocument,
			`"local_port":8080`, `"local_port":8080.5`, 1),
		"exponent port": strings.Replace(vectorPlanDocument,
			`"local_port":8080`, `"local_port":8.08e3`, 1),
		"null operation": strings.Replace(vectorPlanDocument,
			`"operation":"deploy_oci_probe"`, `"operation":null`, 1),
		"oversized": strings.Replace(vectorPlanDocument,
			ProbeImageReference, strings.Repeat("a", MaxPlanBytes), 1),
	}
	for name, document := range documents {
		if _, err := Decode([]byte(document)); err == nil {
			t.Fatalf("%s document was accepted", name)
		}
	}
}

// withExtraField appends one raw member to a canonical document, which is how a
// smuggled field, a duplicated field and a field of a richer schema all reach
// the decoder in the shape a hostile transport would actually send.
func withExtraField(document, member string) string {
	return strings.TrimSuffix(document, "}") + "," + member + "}"
}

// TestAPlanSurvivesTransportAndReturnsTheSameBytes states the exact limit of
// what a transport may do: reshape the JSON, and only that.
func TestAPlanSurvivesTransportAndReturnsTheSameBytes(t *testing.T) {
	t.Parallel()
	pair, err := BuildPair(OperationDeployOCIProbe, vectorInfrastructure, vectorMachine, vectorPort)
	if err != nil {
		t.Fatal(err)
	}
	frozen, err := pair.Freeze()
	if err != nil {
		t.Fatal(err)
	}

	decoded, err := Decode(frozen.PlanDocument)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := decoded.SHA256()
	if err != nil {
		t.Fatal(err)
	}
	if digest != frozen.PlanSHA256 {
		t.Fatalf("a decoded plan changed its digest: %s", digest)
	}
	reencoded, err := decoded.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(reencoded, frozen.PlanDocument) {
		t.Fatalf("re-encoding a decoded plan produced other bytes:\n%s", reencoded)
	}

	reshaped := fmt.Sprintf(`{
  "local_port": %d,
  "image_digest": %q,
  "image_reference": %q,
  "operation": %q,
  "machine_id": %q,
  "infrastructure_id": %q,
  "schema_version": 1
}`, vectorPort, ProbeImageDigest, ProbeImageReference,
		OperationDeployOCIProbe, vectorMachine, vectorInfrastructure)
	reordered, err := Decode([]byte(reshaped))
	if err != nil {
		t.Fatalf("a reindented document is the same plan: %v", err)
	}
	reorderedDigest, err := reordered.SHA256()
	if err != nil {
		t.Fatal(err)
	}
	if reorderedDigest != frozen.PlanSHA256 {
		t.Fatalf("reindentation changed the plan digest: %s", reorderedDigest)
	}
	reorderedBytes, err := reordered.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(reorderedBytes, frozen.PlanDocument) {
		t.Fatalf("a reindented plan did not return to its canonical bytes:\n%s", reorderedBytes)
	}
}

// TestTheRollbackOfAPairIsTheOtherPairItself is what makes a rollback a plan
// rather than a promise: undoing a deployment is the removal a human could have
// approved on its own, with the same digest, and undoing that removal is the
// deployment it came from.
func TestTheRollbackOfAPairIsTheOtherPairItself(t *testing.T) {
	t.Parallel()
	deploy, err := BuildPair(OperationDeployOCIProbe, vectorInfrastructure, vectorMachine, vectorPort)
	if err != nil {
		t.Fatal(err)
	}
	remove, err := BuildPair(OperationRemoveOCIProbe, vectorInfrastructure, vectorMachine, vectorPort)
	if err != nil {
		t.Fatal(err)
	}
	frozenDeploy, err := deploy.Freeze()
	if err != nil {
		t.Fatal(err)
	}
	frozenRemove, err := remove.Freeze()
	if err != nil {
		t.Fatal(err)
	}

	if frozenDeploy.RollbackSHA256 != frozenRemove.PlanSHA256 {
		t.Fatal("the rollback of a deployment is not the removal of the same instance")
	}
	if frozenRemove.RollbackSHA256 != frozenDeploy.PlanSHA256 {
		t.Fatal("the rollback of a removal is not the redeployment of the same instance")
	}
	if !bytes.Equal(frozenDeploy.RollbackDocument, frozenRemove.PlanDocument) ||
		!bytes.Equal(frozenRemove.RollbackDocument, frozenDeploy.PlanDocument) {
		t.Fatal("the two directions of the pair do not carry the same documents")
	}
	if frozenDeploy.PlanSHA256 == frozenDeploy.RollbackSHA256 {
		t.Fatal("a plan and its rollback must not be the same document")
	}
	for _, document := range []Document{deploy.Rollback, remove.Rollback} {
		if document.MachineID != vectorMachine || document.LocalPort != vectorPort ||
			document.InfrastructureID != vectorInfrastructure ||
			document.ImageReference != ProbeImageReference || document.ImageDigest != ProbeImageDigest {
			t.Fatal("a rollback targets another instance than the plan it undoes")
		}
	}
}

// TestARollbackIsRecognisedOnlyWhenItUndoesExactlyThePlan is what a machine asks
// before acting: the document it was handed as an undoing has to be one it could
// apply to return to the state it is about to leave.
func TestARollbackIsRecognisedOnlyWhenItUndoesExactlyThePlan(t *testing.T) {
	t.Parallel()
	pair, err := BuildPair(OperationDeployOCIProbe, vectorInfrastructure, vectorMachine, vectorPort)
	if err != nil {
		t.Fatal(err)
	}
	if !pair.Rollback.IsExactInverseOf(&pair.Plan) {
		t.Fatal("the rollback of a pair is not read as undoing its plan")
	}
	if !pair.Plan.IsExactInverseOf(&pair.Rollback) {
		t.Fatal("undoing is not symmetric between the two documents of a pair")
	}
	if pair.Plan.IsExactInverseOf(&pair.Plan) {
		t.Fatal("a plan was read as undoing itself")
	}
	if pair.Rollback.IsExactInverseOf(nil) {
		t.Fatal("an absent plan was read as undone")
	}

	for name, forge := range map[string]func(*Document){
		"another machine":        func(d *Document) { d.MachineID = "lab-machine-2" },
		"another infrastructure": func(d *Document) { d.InfrastructureID = "8f14e45f-ceea-4167-a8b1-1f7bd0a0f4c3" },
		"another port":           func(d *Document) { d.LocalPort = vectorPort + 1 },
		"the same operation":     func(d *Document) { d.Operation = OperationDeployOCIProbe },
		"an unknown operation":   func(d *Document) { d.Operation = "install_container" },
	} {
		forged := pair.Rollback
		forge(&forged)
		if forged.IsExactInverseOf(&pair.Plan) {
			t.Fatalf("a rollback naming %s was read as undoing the plan", name)
		}
	}
}

func TestBuildPairRefusesEveryInstanceOutsideTheContract(t *testing.T) {
	t.Parallel()
	if _, err := BuildPair(OperationDeployOCIProbe, vectorInfrastructure, vectorMachine, MinLocalPort); err != nil {
		t.Fatalf("the lower bound of the port range must build: %v", err)
	}
	if _, err := BuildPair(OperationRemoveOCIProbe, vectorInfrastructure, vectorMachine, MaxLocalPort); err != nil {
		t.Fatalf("the upper bound of the port range must build: %v", err)
	}
	for name, build := range map[string]func() (Pair, error){
		"unknown operation": func() (Pair, error) {
			return BuildPair("install_container", vectorInfrastructure, vectorMachine, vectorPort)
		},
		"read-only operation of the previous palier": func() (Pair, error) {
			return BuildPair("diagnose_protocol_read_only", vectorInfrastructure, vectorMachine, vectorPort)
		},
		"empty operation": func() (Pair, error) {
			return BuildPair("", vectorInfrastructure, vectorMachine, vectorPort)
		},
		"malformed infrastructure": func() (Pair, error) {
			return BuildPair(OperationDeployOCIProbe, "not-a-uuid", vectorMachine, vectorPort)
		},
		"malformed machine": func() (Pair, error) {
			return BuildPair(OperationDeployOCIProbe, vectorInfrastructure, "LAB", vectorPort)
		},
		"privileged port": func() (Pair, error) {
			return BuildPair(OperationDeployOCIProbe, vectorInfrastructure, vectorMachine, 443)
		},
		"port above range": func() (Pair, error) {
			return BuildPair(OperationDeployOCIProbe, vectorInfrastructure, vectorMachine, MaxLocalPort+1)
		},
	} {
		if _, err := build(); err == nil {
			t.Fatalf("%s built a pair", name)
		}
	}
}

// TestTheProbeOfThisPalierIsPinnedByDigestAlone keeps the two decisions of the
// contract testable rather than merely written: one image, and no second truth
// beside its digest.
func TestTheProbeOfThisPalierIsPinnedByDigestAlone(t *testing.T) {
	t.Parallel()
	if strings.ContainsAny(ProbeImageReference, ":@") {
		t.Fatalf("the pinned reference carries a tag or a digest: %s", ProbeImageReference)
	}
	if !canonicalOCIDigest.MatchString(ProbeImageDigest) {
		t.Fatalf("the pinned digest is not canonical: %s", ProbeImageDigest)
	}
	if len(inverseOperation) != 2 {
		t.Fatalf("this palier describes exactly two operations, not %d", len(inverseOperation))
	}
	for operation, inverse := range inverseOperation {
		if inverseOperation[inverse] != operation {
			t.Fatalf("operation %q is not undone by an operation that redoes it", operation)
		}
	}
}

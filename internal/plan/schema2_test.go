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
	// otherInfrastructure is a second canonical UUIDv4, used wherever a test
	// needs a value that is well-formed and still not the one under test.
	otherInfrastructure = "8f14e45f-ceea-4167-a8b1-1f7bd0a0f4c3"

	vectorServiceProfile = ServiceProfileBentoPDF
	vectorLocalPort      = 8080
	vectorRouteHost      = "bentopdf.lab.your-cloud.test"
	vectorBackendPort    = 8080

	// The six canonical documents of the schema 2 vectors, byte for byte. A
	// transport may reindent them; the Controller emits exactly these bytes.
	vectorWebServicePlanDocument = `{"schema_version":2,"infrastructure_id":"8f14e45f-ceea-4167-a8b1-1f7bd0a0f4c2",` +
		`"machine_id":"lab-machine-1","operation":"deploy_web_service",` +
		`"service_profile":"bentopdf","image_reference":"ghcr.io/alam00000/bentopdf",` +
		`"image_digest":"sha256:a4ed090f29823da5e296e2c2f8603664da71676156ea47c3f186cc73eec38db0",` +
		`"local_port":8080}`
	vectorWebServiceRollbackDocument = `{"schema_version":2,"infrastructure_id":"8f14e45f-ceea-4167-a8b1-1f7bd0a0f4c2",` +
		`"machine_id":"lab-machine-1","operation":"remove_web_service",` +
		`"service_profile":"bentopdf","image_reference":"ghcr.io/alam00000/bentopdf",` +
		`"image_digest":"sha256:a4ed090f29823da5e296e2c2f8603664da71676156ea47c3f186cc73eec38db0",` +
		`"local_port":8080}`
	vectorEntrypointPlanDocument = `{"schema_version":2,"infrastructure_id":"8f14e45f-ceea-4167-a8b1-1f7bd0a0f4c2",` +
		`"machine_id":"lab-machine-1","operation":"deploy_entrypoint",` +
		`"image_reference":"docker.io/library/traefik",` +
		`"image_digest":"sha256:9c3b91d5fb7770853ca5c1124a23c34bf2d9b47ffaebeab2614cbaf410dcb2ac"}`
	vectorEntrypointRollbackDocument = `{"schema_version":2,"infrastructure_id":"8f14e45f-ceea-4167-a8b1-1f7bd0a0f4c2",` +
		`"machine_id":"lab-machine-1","operation":"remove_entrypoint",` +
		`"image_reference":"docker.io/library/traefik",` +
		`"image_digest":"sha256:9c3b91d5fb7770853ca5c1124a23c34bf2d9b47ffaebeab2614cbaf410dcb2ac"}`
	vectorRoutePlanDocument = `{"schema_version":2,"infrastructure_id":"8f14e45f-ceea-4167-a8b1-1f7bd0a0f4c2",` +
		`"machine_id":"lab-machine-1","operation":"publish_route",` +
		`"route_host":"bentopdf.lab.your-cloud.test","backend_port":8080}`
	vectorRouteRollbackDocument = `{"schema_version":2,"infrastructure_id":"8f14e45f-ceea-4167-a8b1-1f7bd0a0f4c2",` +
		`"machine_id":"lab-machine-1","operation":"retire_route",` +
		`"route_host":"bentopdf.lab.your-cloud.test","backend_port":8080}`

	// The six transcripts, byte for byte. The Rust side of this palier, tracked
	// by #89, must reproduce these exact vectors from its own encoder: a
	// canonical encoding that exists in two implementations is only canonical
	// while the two agree byte for byte, and a drift caught here is a drift that
	// never reaches a machine as an approval the other side refuses.
	vectorWebServicePlanTranscriptHex = "796f75722d636c6f75642f6f63692d706c616e2e763200020000002438663134" +
		"653435662d636565612d343136372d613862312d316637626430613066346332" +
		"0000000d6c61622d6d616368696e652d31000000126465706c6f795f7765625f" +
		"736572766963650000000862656e746f7064660000001a676863722e696f2f61" +
		"6c616d30303030302f62656e746f70646600000020a4ed090f29823da5e296e2" +
		"c2f8603664da71676156ea47c3f186cc73eec38db000001f90"
	vectorWebServiceRollbackTranscriptHex = "796f75722d636c6f75642f6f63692d706c616e2e763200020000002438663134" +
		"653435662d636565612d343136372d613862312d316637626430613066346332" +
		"0000000d6c61622d6d616368696e652d310000001272656d6f76655f7765625f" +
		"736572766963650000000862656e746f7064660000001a676863722e696f2f61" +
		"6c616d30303030302f62656e746f70646600000020a4ed090f29823da5e296e2" +
		"c2f8603664da71676156ea47c3f186cc73eec38db000001f90"
	vectorEntrypointPlanTranscriptHex = "796f75722d636c6f75642f6f63692d706c616e2e763200020000002438663134" +
		"653435662d636565612d343136372d613862312d316637626430613066346332" +
		"0000000d6c61622d6d616368696e652d31000000116465706c6f795f656e7472" +
		"79706f696e7400000019646f636b65722e696f2f6c6962726172792f74726165" +
		"66696b000000209c3b91d5fb7770853ca5c1124a23c34bf2d9b47ffaebeab261" +
		"4cbaf410dcb2ac"
	vectorEntrypointRollbackTranscriptHex = "796f75722d636c6f75642f6f63692d706c616e2e763200020000002438663134" +
		"653435662d636565612d343136372d613862312d316637626430613066346332" +
		"0000000d6c61622d6d616368696e652d310000001172656d6f76655f656e7472" +
		"79706f696e7400000019646f636b65722e696f2f6c6962726172792f74726165" +
		"66696b000000209c3b91d5fb7770853ca5c1124a23c34bf2d9b47ffaebeab261" +
		"4cbaf410dcb2ac"
	vectorRoutePlanTranscriptHex = "796f75722d636c6f75642f6f63692d706c616e2e763200020000002438663134" +
		"653435662d636565612d343136372d613862312d316637626430613066346332" +
		"0000000d6c61622d6d616368696e652d310000000d7075626c6973685f726f75" +
		"74650000001c62656e746f7064662e6c61622e796f75722d636c6f75642e7465" +
		"737400001f90"
	vectorRouteRollbackTranscriptHex = "796f75722d636c6f75642f6f63692d706c616e2e763200020000002438663134" +
		"653435662d636565612d343136372d613862312d316637626430613066346332" +
		"0000000d6c61622d6d616368696e652d310000000c7265746972655f726f7574" +
		"650000001c62656e746f7064662e6c61622e796f75722d636c6f75642e746573" +
		"7400001f90"

	// The six digests an approval envelope of these vectors names as plan_sha256
	// and rollback_sha256, in the exact spelling that envelope requires.
	vectorWebServicePlanSHA256     = "99f6e6401d74583f64e4200e6e47cd365ab299466eebe1c1a7210f260b0366ae"
	vectorWebServiceRollbackSHA256 = "4e480f76a7247cde6c41990e941512dce70f0a272a17a2618211bd03230ced68"
	vectorEntrypointPlanSHA256     = "fe15d468f77ed9ca6b54da9a63860278894be7db4b6d997898b55fcb602f3722"
	vectorEntrypointRollbackSHA256 = "1b91a7fa77b7d02cc16ce5d694b1709f641a341c849b4459de0ee3960d1cfcd8"
	vectorRoutePlanSHA256          = "3d92c310868a8ba98aca5501c069bd0e4674757f787c8095e7c39d65d8d20a89"
	vectorRouteRollbackSHA256      = "93e844abe96e68f157eb715ace9ff423004b0c64c68536d4e79ebc8206da1324"

	// A real digest of another image of the same registry. It is refused for the
	// same reason the resolved probe digest is: the plan names one pin and
	// nothing may stand in for it.
	otherPinnedDigest = "sha256:200689790a0a0ea48ca45992e0450bc26ccab5307375b41c84dfc4f2475937ab"
)

func vectorWebService() WebServiceDocument {
	return WebServiceDocument{
		SchemaVersion:    SchemaVersionV2,
		InfrastructureID: vectorInfrastructure,
		MachineID:        vectorMachine,
		Operation:        OperationDeployWebService,
		ServiceProfile:   vectorServiceProfile,
		ImageReference:   BentoPDFImageReference,
		ImageDigest:      BentoPDFImageDigest,
		LocalPort:        vectorLocalPort,
	}
}

func vectorEntrypoint() EntrypointDocument {
	return EntrypointDocument{
		SchemaVersion:    SchemaVersionV2,
		InfrastructureID: vectorInfrastructure,
		MachineID:        vectorMachine,
		Operation:        OperationDeployEntrypoint,
		ImageReference:   EntrypointImageReference,
		ImageDigest:      EntrypointImageDigest,
	}
}

func vectorRoute() RouteDocument {
	return RouteDocument{
		SchemaVersion:    SchemaVersionV2,
		InfrastructureID: vectorInfrastructure,
		MachineID:        vectorMachine,
		Operation:        OperationPublishRoute,
		RouteHost:        vectorRouteHost,
		BackendPort:      vectorBackendPort,
	}
}

// hostileV2Document encodes a document without validating it, which is what a
// hostile test needs: the refusal under test must come from DecodeV2 rather than
// from the encoder refusing to produce the bytes in the first place.
func hostileV2Document(t *testing.T, document any) []byte {
	t.Helper()
	encoded, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func decodedHex(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	return decoded
}

// TestDeterministicSchemaTwoVectorsAreHeldWithTheRustSide is the
// interoperability proof of the schema 2 encoding, for each of the three
// operation groups.
//
// Every transcript, every digest and every canonical document is pinned here
// literally. The Rust implementation of #89 pins the same values from its own
// encoder, so a single byte of drift in either implementation fails here rather
// than producing plans the other side hashes differently on a real machine.
func TestDeterministicSchemaTwoVectorsAreHeldWithTheRustSide(t *testing.T) {
	t.Parallel()
	for _, subject := range []struct {
		group              string
		build              func() (V2Pair, error)
		planDocument       string
		rollbackDocument   string
		planTranscript     string
		rollbackTranscript string
		planSHA256         string
		rollbackSHA256     string
		transcriptLength   int
	}{
		{
			group: "web service",
			build: func() (V2Pair, error) {
				return BuildWebServicePair(OperationDeployWebService, vectorInfrastructure,
					vectorMachine, vectorServiceProfile, vectorLocalPort)
			},
			planDocument:       vectorWebServicePlanDocument,
			rollbackDocument:   vectorWebServiceRollbackDocument,
			planTranscript:     vectorWebServicePlanTranscriptHex,
			rollbackTranscript: vectorWebServiceRollbackTranscriptHex,
			planSHA256:         vectorWebServicePlanSHA256,
			rollbackSHA256:     vectorWebServiceRollbackSHA256,
			transcriptLength:   185,
		},
		{
			group: "entrypoint",
			build: func() (V2Pair, error) {
				return BuildEntrypointPair(OperationDeployEntrypoint, vectorInfrastructure, vectorMachine)
			},
			planDocument:       vectorEntrypointPlanDocument,
			rollbackDocument:   vectorEntrypointRollbackDocument,
			planTranscript:     vectorEntrypointPlanTranscriptHex,
			rollbackTranscript: vectorEntrypointRollbackTranscriptHex,
			planSHA256:         vectorEntrypointPlanSHA256,
			rollbackSHA256:     vectorEntrypointRollbackSHA256,
			transcriptLength:   167,
		},
		{
			group: "route",
			build: func() (V2Pair, error) {
				return BuildRoutePair(OperationPublishRoute, vectorInfrastructure,
					vectorMachine, vectorRouteHost, vectorBackendPort)
			},
			planDocument:       vectorRoutePlanDocument,
			rollbackDocument:   vectorRouteRollbackDocument,
			planTranscript:     vectorRoutePlanTranscriptHex,
			rollbackTranscript: vectorRouteRollbackTranscriptHex,
			planSHA256:         vectorRoutePlanSHA256,
			rollbackSHA256:     vectorRouteRollbackSHA256,
			transcriptLength:   134,
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
		if !strings.HasPrefix(string(transcript), TranscriptDomainV2) {
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

// TestNoTwoSchemaTwoDigestsCollideAcrossOperationGroups is what makes the
// transcript layout unambiguous without a group tag: the six vectors of the
// palier are six distinct documents and six distinct digests, and none of them
// is the schema 1 digest of anything.
func TestNoTwoSchemaTwoDigestsCollideAcrossOperationGroups(t *testing.T) {
	t.Parallel()
	seen := map[string]string{
		vectorPlanSHA256:     "schema 1 probe deployment",
		vectorRollbackSHA256: "schema 1 probe removal",
	}
	for name, digest := range map[string]string{
		"web service deployment": vectorWebServicePlanSHA256,
		"web service removal":    vectorWebServiceRollbackSHA256,
		"entrypoint deployment":  vectorEntrypointPlanSHA256,
		"entrypoint removal":     vectorEntrypointRollbackSHA256,
		"route publication":      vectorRoutePlanSHA256,
		"route retirement":       vectorRouteRollbackSHA256,
	} {
		if other, collision := seen[digest]; collision {
			t.Fatalf("%s and %s name the same digest", name, other)
		}
		seen[digest] = name
	}
}

// TestChangingAnySingleFieldChangesTheSchemaTwoDigest is the central property of
// the transcript, held for each operation group.
//
// A field that could move without moving the digest would be a field the
// Controller owns, since the Controller is the only thing between the human who
// approved a plan and the machine that performs it. The wire documents are read
// back at the end so that a field added to a schema and forgotten in its
// transcript fails here.
func TestChangingAnySingleFieldChangesTheSchemaTwoDigest(t *testing.T) {
	t.Parallel()

	webService := map[string]func(*WebServiceDocument){
		"infrastructure_id": func(d *WebServiceDocument) { d.InfrastructureID = otherInfrastructure },
		"machine_id":        func(d *WebServiceDocument) { d.MachineID = "lab-machine-2" },
		"operation":         func(d *WebServiceDocument) { d.Operation = OperationRemoveWebService },
		"local_port":        func(d *WebServiceDocument) { d.LocalPort = vectorLocalPort + 1 },
		"schema_version":    func(d *WebServiceDocument) { d.SchemaVersion = SchemaVersion },
		"service_profile":   func(d *WebServiceDocument) { d.ServiceProfile = "bentopdf-simple" },
		"image_reference":   func(d *WebServiceDocument) { d.ImageReference = "ghcr.io/attacker/bentopdf" },
		"image_digest":      func(d *WebServiceDocument) { d.ImageDigest = otherPinnedDigest },
	}
	reference := rawWebServiceTranscript(t, vectorWebService())
	for field, mutate := range webService {
		moved := vectorWebService()
		mutate(&moved)
		if bytes.Equal(rawWebServiceTranscript(t, moved), reference) {
			t.Fatalf("web service %s is outside the hashed bytes", field)
		}
	}
	requireEveryWireFieldIsHeld(t, vectorWebServicePlanDocument, keysOf(webService))

	entrypoint := map[string]func(*EntrypointDocument){
		"infrastructure_id": func(d *EntrypointDocument) { d.InfrastructureID = otherInfrastructure },
		"machine_id":        func(d *EntrypointDocument) { d.MachineID = "lab-machine-2" },
		"operation":         func(d *EntrypointDocument) { d.Operation = OperationRemoveEntrypoint },
		"schema_version":    func(d *EntrypointDocument) { d.SchemaVersion = SchemaVersion },
		"image_reference":   func(d *EntrypointDocument) { d.ImageReference = "ghcr.io/attacker/traefik" },
		"image_digest":      func(d *EntrypointDocument) { d.ImageDigest = otherPinnedDigest },
	}
	entrypointReference := rawEntrypointTranscript(t, vectorEntrypoint())
	for field, mutate := range entrypoint {
		moved := vectorEntrypoint()
		mutate(&moved)
		if bytes.Equal(rawEntrypointTranscript(t, moved), entrypointReference) {
			t.Fatalf("entrypoint %s is outside the hashed bytes", field)
		}
	}
	requireEveryWireFieldIsHeld(t, vectorEntrypointPlanDocument, keysOf(entrypoint))

	route := map[string]func(*RouteDocument){
		"infrastructure_id": func(d *RouteDocument) { d.InfrastructureID = otherInfrastructure },
		"machine_id":        func(d *RouteDocument) { d.MachineID = "lab-machine-2" },
		"operation":         func(d *RouteDocument) { d.Operation = OperationRetireRoute },
		"schema_version":    func(d *RouteDocument) { d.SchemaVersion = SchemaVersion },
		"route_host":        func(d *RouteDocument) { d.RouteHost = "other.lab.your-cloud.test" },
		"backend_port":      func(d *RouteDocument) { d.BackendPort = vectorBackendPort + 1 },
	}
	routeReference := rawRouteTranscript(vectorRoute())
	for field, mutate := range route {
		moved := vectorRoute()
		mutate(&moved)
		if bytes.Equal(rawRouteTranscript(moved), routeReference) {
			t.Fatalf("route %s is outside the hashed bytes", field)
		}
	}
	requireEveryWireFieldIsHeld(t, vectorRoutePlanDocument, keysOf(route))
}

// The raw transcripts below rebuild the layout for documents Validate refuses,
// so that a pinned field can still be proven to be inside the hashed bytes.

func rawWebServiceTranscript(t *testing.T, document WebServiceDocument) []byte {
	t.Helper()
	transcript := appendV2Head(document.SchemaVersion, document.InfrastructureID,
		document.MachineID, document.Operation)
	transcript = appendField(transcript, []byte(document.ServiceProfile))
	transcript = appendField(transcript, []byte(document.ImageReference))
	transcript = appendField(transcript, decodedHex(t, strings.TrimPrefix(document.ImageDigest, "sha256:")))
	return appendUint32(transcript, uint32(document.LocalPort))
}

func rawEntrypointTranscript(t *testing.T, document EntrypointDocument) []byte {
	t.Helper()
	transcript := appendV2Head(document.SchemaVersion, document.InfrastructureID,
		document.MachineID, document.Operation)
	transcript = appendField(transcript, []byte(document.ImageReference))
	return appendField(transcript, decodedHex(t, strings.TrimPrefix(document.ImageDigest, "sha256:")))
}

func rawRouteTranscript(document RouteDocument) []byte {
	transcript := appendV2Head(document.SchemaVersion, document.InfrastructureID,
		document.MachineID, document.Operation)
	transcript = appendField(transcript, []byte(document.RouteHost))
	return appendUint32(transcript, uint32(document.BackendPort))
}

func keysOf[V any](table map[string]V) map[string]struct{} {
	names := make(map[string]struct{}, len(table))
	for name := range table {
		names[name] = struct{}{}
	}
	return names
}

func requireEveryWireFieldIsHeld(t *testing.T, document string, held map[string]struct{}) {
	t.Helper()
	wire := map[string]json.RawMessage{}
	if err := json.Unmarshal([]byte(document), &wire); err != nil {
		t.Fatal(err)
	}
	if len(wire) != len(held) {
		t.Fatalf("the closed field list of this document holds %d fields, not %d", len(held), len(wire))
	}
	for name := range wire {
		if _, bounded := held[name]; !bounded {
			t.Fatalf("field %q of the plan is never held against its digest", name)
		}
	}
}

// TestDecodeV2RefusesEveryWebServiceDocumentOutsideTheContract is the hostile
// table of the service group.
func TestDecodeV2RefusesEveryWebServiceDocumentOutsideTheContract(t *testing.T) {
	t.Parallel()
	if _, err := DecodeV2([]byte(vectorWebServicePlanDocument)); err != nil {
		t.Fatalf("the nominal document must decode: %v", err)
	}
	if _, err := DecodeV2([]byte(vectorWebServiceRollbackDocument)); err != nil {
		t.Fatalf("the nominal rollback must decode: %v", err)
	}

	for name, mutate := range map[string]func(*WebServiceDocument){
		"schema 1 version":     func(d *WebServiceDocument) { d.SchemaVersion = SchemaVersion },
		"absent schema":        func(d *WebServiceDocument) { d.SchemaVersion = 0 },
		"upper-case UUID":      func(d *WebServiceDocument) { d.InfrastructureID = strings.ToUpper(vectorInfrastructure) },
		"empty infrastructure": func(d *WebServiceDocument) { d.InfrastructureID = "" },
		"traversal machine":    func(d *WebServiceDocument) { d.MachineID = "../../etc/shadow" },
		"upper-case machine":   func(d *WebServiceDocument) { d.MachineID = "LAB-MACHINE-1" },
		"unknown operation":    func(d *WebServiceDocument) { d.Operation = "install_container" },
		"probe operation":      func(d *WebServiceDocument) { d.Operation = OperationDeployOCIProbe },
		"entrypoint operation": func(d *WebServiceDocument) { d.Operation = OperationDeployEntrypoint },
		"route operation":      func(d *WebServiceDocument) { d.Operation = OperationPublishRoute },
		"empty operation":      func(d *WebServiceDocument) { d.Operation = "" },
		"unknown profile":      func(d *WebServiceDocument) { d.ServiceProfile = "bentopdf-simple" },
		"upper-case profile":   func(d *WebServiceDocument) { d.ServiceProfile = "BentoPDF" },
		"empty profile":        func(d *WebServiceDocument) { d.ServiceProfile = "" },
		"other registry":       func(d *WebServiceDocument) { d.ImageReference = "docker.io/alam00000/bentopdf" },
		"other repository":     func(d *WebServiceDocument) { d.ImageReference = "ghcr.io/attacker/bentopdf" },
		"registry-less":        func(d *WebServiceDocument) { d.ImageReference = "alam00000/bentopdf" },
		"tagged reference":     func(d *WebServiceDocument) { d.ImageReference = BentoPDFImageReference + ":latest" },
		"entrypoint reference": func(d *WebServiceDocument) { d.ImageReference = EntrypointImageReference },
		"entrypoint digest":    func(d *WebServiceDocument) { d.ImageDigest = EntrypointImageDigest },
		"probe digest":         func(d *WebServiceDocument) { d.ImageDigest = otherPinnedDigest },
		"upper-case digest":    func(d *WebServiceDocument) { d.ImageDigest = strings.ToUpper(BentoPDFImageDigest) },
		"other algorithm": func(d *WebServiceDocument) {
			d.ImageDigest = "sha512:" + strings.TrimPrefix(BentoPDFImageDigest, "sha256:")
		},
		"short digest":          func(d *WebServiceDocument) { d.ImageDigest = "sha256:a4ed" },
		"port below range":      func(d *WebServiceDocument) { d.LocalPort = MinLocalPort - 1 },
		"privileged port":       func(d *WebServiceDocument) { d.LocalPort = 443 },
		"absent port":           func(d *WebServiceDocument) { d.LocalPort = 0 },
		"negative port":         func(d *WebServiceDocument) { d.LocalPort = -1 },
		"port above range":      func(d *WebServiceDocument) { d.LocalPort = MaxLocalPort + 1 },
		"port beyond int16":     func(d *WebServiceDocument) { d.LocalPort = 70000 },
		"reference with digest": func(d *WebServiceDocument) { d.ImageReference = BentoPDFImageReference + "@" + BentoPDFImageDigest },
	} {
		document := vectorWebService()
		mutate(&document)
		if _, err := DecodeV2(hostileV2Document(t, document)); err == nil {
			t.Fatalf("%s was accepted", name)
		}
	}
}

// TestDecodeV2RefusesEveryEntrypointDocumentOutsideTheContract is the hostile
// table of the entrypoint group. The entrypoint has the shortest field list of
// the palier, so most of its surface is what it must refuse to carry.
func TestDecodeV2RefusesEveryEntrypointDocumentOutsideTheContract(t *testing.T) {
	t.Parallel()
	if _, err := DecodeV2([]byte(vectorEntrypointPlanDocument)); err != nil {
		t.Fatalf("the nominal document must decode: %v", err)
	}
	if _, err := DecodeV2([]byte(vectorEntrypointRollbackDocument)); err != nil {
		t.Fatalf("the nominal rollback must decode: %v", err)
	}

	for name, mutate := range map[string]func(*EntrypointDocument){
		"schema 1 version":   func(d *EntrypointDocument) { d.SchemaVersion = SchemaVersion },
		"absent schema":      func(d *EntrypointDocument) { d.SchemaVersion = 0 },
		"non version 4 UUID": func(d *EntrypointDocument) { d.InfrastructureID = "8f14e45f-ceea-1167-a8b1-1f7bd0a0f4c2" },
		"too short machine":  func(d *EntrypointDocument) { d.MachineID = "ab" },
		"unknown operation":  func(d *EntrypointDocument) { d.Operation = "install_container" },
		"service operation":  func(d *EntrypointDocument) { d.Operation = OperationDeployWebService },
		"route operation":    func(d *EntrypointDocument) { d.Operation = OperationRetireRoute },
		"empty operation":    func(d *EntrypointDocument) { d.Operation = "" },
		"service reference":  func(d *EntrypointDocument) { d.ImageReference = BentoPDFImageReference },
		"service digest":     func(d *EntrypointDocument) { d.ImageDigest = BentoPDFImageDigest },
		"probe digest":       func(d *EntrypointDocument) { d.ImageDigest = otherPinnedDigest },
		"tagged reference":   func(d *EntrypointDocument) { d.ImageReference = EntrypointImageReference + ":latest" },
		"registry-less":      func(d *EntrypointDocument) { d.ImageReference = "library/traefik" },
		"unprefixed digest":  func(d *EntrypointDocument) { d.ImageDigest = strings.TrimPrefix(EntrypointImageDigest, "sha256:") },
		"upper-case algorithm": func(d *EntrypointDocument) {
			d.ImageDigest = "SHA256:" + strings.TrimPrefix(EntrypointImageDigest, "sha256:")
		},
	} {
		document := vectorEntrypoint()
		mutate(&document)
		if _, err := DecodeV2(hostileV2Document(t, document)); err == nil {
			t.Fatalf("%s was accepted", name)
		}
	}
}

// TestDecodeV2RefusesEveryRouteDocumentOutsideTheContract is the hostile table
// of the route group, and the whole surface of route_host.
//
// A host outside these bounds never reaches a fragment of the entrypoint, which
// is why the bound is here and not in whatever writes the fragment.
func TestDecodeV2RefusesEveryRouteDocumentOutsideTheContract(t *testing.T) {
	t.Parallel()
	if _, err := DecodeV2([]byte(vectorRoutePlanDocument)); err != nil {
		t.Fatalf("the nominal document must decode: %v", err)
	}
	if _, err := DecodeV2([]byte(vectorRouteRollbackDocument)); err != nil {
		t.Fatalf("the nominal rollback must decode: %v", err)
	}

	// The bounds themselves are accepted, so that the refusals below name a
	// malformation rather than an off-by-one.
	for name, host := range map[string]string{
		"shortest accepted name": "abc",
		"longest accepted name":  strings.Repeat("a", 248) + ".test",
		"punycode label":         "xn--bcher-kva.lab.your-cloud.test",
		"digits only":            "127.0.0.1",
	} {
		document := vectorRoute()
		document.RouteHost = host
		if _, err := DecodeV2(hostileV2Document(t, document)); err != nil {
			t.Fatalf("%s was refused: %v", name, err)
		}
	}
	for _, port := range []int{MinBackendPort, MaxBackendPort} {
		document := vectorRoute()
		document.BackendPort = port
		if _, err := DecodeV2(hostileV2Document(t, document)); err != nil {
			t.Fatalf("the bound %d of the backend range was refused: %v", port, err)
		}
	}

	for name, mutate := range map[string]func(*RouteDocument){
		"schema 1 version":     func(d *RouteDocument) { d.SchemaVersion = SchemaVersion },
		"absent schema":        func(d *RouteDocument) { d.SchemaVersion = 0 },
		"upper-case UUID":      func(d *RouteDocument) { d.InfrastructureID = strings.ToUpper(vectorInfrastructure) },
		"machine on hyphen":    func(d *RouteDocument) { d.MachineID = "-lab-machine-1" },
		"unknown operation":    func(d *RouteDocument) { d.Operation = "publish_ingress" },
		"service operation":    func(d *RouteDocument) { d.Operation = OperationRemoveWebService },
		"entrypoint operation": func(d *RouteDocument) { d.Operation = OperationRemoveEntrypoint },
		"empty operation":      func(d *RouteDocument) { d.Operation = "" },

		"empty host":            func(d *RouteDocument) { d.RouteHost = "" },
		"host below bound":      func(d *RouteDocument) { d.RouteHost = "ab" },
		"host above bound":      func(d *RouteDocument) { d.RouteHost = strings.Repeat("a", 249) + ".test" },
		"wildcard host":         func(d *RouteDocument) { d.RouteHost = "*.lab.your-cloud.test" },
		"bare wildcard":         func(d *RouteDocument) { d.RouteHost = "*" },
		"upper-case host":       func(d *RouteDocument) { d.RouteHost = "BentoPDF.lab.your-cloud.test" },
		"leading dot":           func(d *RouteDocument) { d.RouteHost = ".lab.your-cloud.test" },
		"trailing dot":          func(d *RouteDocument) { d.RouteHost = "bentopdf.lab.your-cloud.test." },
		"leading hyphen":        func(d *RouteDocument) { d.RouteHost = "-bentopdf.lab.your-cloud.test" },
		"trailing hyphen":       func(d *RouteDocument) { d.RouteHost = "bentopdf.lab.your-cloud.test-" },
		"consecutive dots":      func(d *RouteDocument) { d.RouteHost = "bentopdf..lab.your-cloud.test" },
		"empty label at start":  func(d *RouteDocument) { d.RouteHost = "..test" },
		"underscore host":       func(d *RouteDocument) { d.RouteHost = "bento_pdf.lab.your-cloud.test" },
		"host carrying a port":  func(d *RouteDocument) { d.RouteHost = "bentopdf.lab.your-cloud.test:443" },
		"host carrying a path":  func(d *RouteDocument) { d.RouteHost = "bentopdf.lab.your-cloud.test/pdf" },
		"host carrying a rule":  func(d *RouteDocument) { d.RouteHost = "bentopdf.lab.test`)||Host(`evil.test" },
		"host carrying a space": func(d *RouteDocument) { d.RouteHost = "bentopdf lab.your-cloud.test" },
		"host carrying a break": func(d *RouteDocument) { d.RouteHost = "bentopdf.lab.test\nevil.test" },
		"non ASCII host":        func(d *RouteDocument) { d.RouteHost = "bücher.lab.your-cloud.test" },
		"trailing NUL host":     func(d *RouteDocument) { d.RouteHost = "bentopdf.lab.your-cloud.test\x00" },

		"backend below range":  func(d *RouteDocument) { d.BackendPort = MinBackendPort - 1 },
		"privileged backend":   func(d *RouteDocument) { d.BackendPort = 443 },
		"absent backend":       func(d *RouteDocument) { d.BackendPort = 0 },
		"negative backend":     func(d *RouteDocument) { d.BackendPort = -1 },
		"backend above range":  func(d *RouteDocument) { d.BackendPort = MaxBackendPort + 1 },
		"backend beyond int16": func(d *RouteDocument) { d.BackendPort = 70000 },
	} {
		document := vectorRoute()
		mutate(&document)
		if _, err := DecodeV2(hostileV2Document(t, document)); err == nil {
			t.Fatalf("%s was accepted", name)
		}
	}
}

// TestNoSchemaTwoDocumentBorrowsAFieldOfAnotherOperation is what the
// discriminator exists for.
//
// The operation is read first, and the document is then held against exactly the
// closed field list that operation declares. A field belonging to another
// operation is an unknown field of the claimed schema, refused before its value
// is read — the strongest form the refusal can take, since it does not depend on
// understanding what was smuggled in.
func TestNoSchemaTwoDocumentBorrowsAFieldOfAnotherOperation(t *testing.T) {
	t.Parallel()
	for name, document := range map[string]string{
		"a service plan carrying a route host":    withExtraField(vectorWebServicePlanDocument, `"route_host":"evil.test"`),
		"a service plan carrying a backend port":  withExtraField(vectorWebServicePlanDocument, `"backend_port":9090`),
		"an entrypoint plan carrying a port":      withExtraField(vectorEntrypointPlanDocument, `"local_port":8080`),
		"an entrypoint plan carrying a host":      withExtraField(vectorEntrypointPlanDocument, `"route_host":"evil.test"`),
		"an entrypoint plan carrying a profile":   withExtraField(vectorEntrypointPlanDocument, `"service_profile":"bentopdf"`),
		"a route plan carrying an image digest":   withExtraField(vectorRoutePlanDocument, `"image_digest":"`+BentoPDFImageDigest+`"`),
		"a route plan carrying an image":          withExtraField(vectorRoutePlanDocument, `"image_reference":"`+BentoPDFImageReference+`"`),
		"a route plan carrying a profile":         withExtraField(vectorRoutePlanDocument, `"service_profile":"bentopdf"`),
		"a route plan carrying a local port":      withExtraField(vectorRoutePlanDocument, `"local_port":8080`),
		"a service plan claiming a route":         strings.Replace(vectorWebServicePlanDocument, `"deploy_web_service"`, `"publish_route"`, 1),
		"a route plan claiming a service":         strings.Replace(vectorRoutePlanDocument, `"publish_route"`, `"deploy_web_service"`, 1),
		"an entrypoint plan claiming a service":   strings.Replace(vectorEntrypointPlanDocument, `"deploy_entrypoint"`, `"deploy_web_service"`, 1),
		"a service plan claiming an entrypoint":   strings.Replace(vectorWebServicePlanDocument, `"deploy_web_service"`, `"deploy_entrypoint"`, 1),
		"a service plan without its profile":      strings.Replace(vectorWebServicePlanDocument, `"service_profile":"bentopdf",`, "", 1),
		"a service plan without its port":         strings.Replace(vectorWebServicePlanDocument, `,"local_port":8080`, "", 1),
		"a route plan without its host":           strings.Replace(vectorRoutePlanDocument, `"route_host":"bentopdf.lab.your-cloud.test",`, "", 1),
		"an entrypoint plan without its image":    strings.Replace(vectorEntrypointPlanDocument, `"image_reference":"docker.io/library/traefik",`, "", 1),
		"a schema 1 probe plan":                   vectorPlanDocument,
		"a schema 2 document with no operation":   strings.Replace(vectorRoutePlanDocument, `"operation":"publish_route",`, "", 1),
		"a schema 2 document naming a number":     strings.Replace(vectorRoutePlanDocument, `"operation":"publish_route"`, `"operation":2`, 1),
		"a schema 2 document naming null":         strings.Replace(vectorRoutePlanDocument, `"operation":"publish_route"`, `"operation":null`, 1),
		"a schema 2 document naming an object":    strings.Replace(vectorRoutePlanDocument, `"operation":"publish_route"`, `"operation":{"name":"publish_route"}`, 1),
		"a document repeating its operation":      withExtraField(vectorRoutePlanDocument, `"operation":"retire_route"`),
		"a document repeating a bounded field":    withExtraField(vectorRoutePlanDocument, `"backend_port":9090`),
		"a document with a non-canonical name":    strings.Replace(vectorRoutePlanDocument, `"route_host"`, `"Route_Host"`, 1),
		"a document with a camel-case name":       strings.Replace(vectorRoutePlanDocument, `"backend_port"`, `"backendPort"`, 1),
		"a document with a stringified port":      strings.Replace(vectorRoutePlanDocument, `"backend_port":8080`, `"backend_port":"8080"`, 1),
		"a document with a fractional port":       strings.Replace(vectorRoutePlanDocument, `"backend_port":8080`, `"backend_port":8080.5`, 1),
		"a document with an exponent port":        strings.Replace(vectorRoutePlanDocument, `"backend_port":8080`, `"backend_port":8.08e3`, 1),
		"a document carrying a command":           withExtraField(vectorWebServicePlanDocument, `"command":"/bin/sh"`),
		"a document carrying a volume":            withExtraField(vectorWebServicePlanDocument, `"volumes":["/etc:/etc"]`),
		"a document carrying a privilege":         withExtraField(vectorEntrypointPlanDocument, `"privileged":true`),
		"a document carrying a tag":               withExtraField(vectorEntrypointPlanDocument, `"tag":"latest"`),
		"a document carrying middleware headers":  withExtraField(vectorRoutePlanDocument, `"headers":{"X-Forwarded-For":"1.2.3.4"}`),
		"a document carrying a TLS certificate":   withExtraField(vectorRoutePlanDocument, `"tls_certificate":"-----BEGIN CERTIFICATE-----"`),
		"an empty document":                       "",
		"two values":                              vectorRoutePlanDocument + "{}",
		"an array of documents":                   "[" + vectorRoutePlanDocument + "]",
		"a truncated document":                    strings.TrimSuffix(vectorRoutePlanDocument, "}"),
		"an oversized document":                   strings.Replace(vectorRoutePlanDocument, vectorRouteHost, strings.Repeat("a", MaxPlanBytes), 1),
		"an oversized service document":           strings.Replace(vectorWebServicePlanDocument, BentoPDFImageReference, strings.Repeat("a", MaxPlanBytes), 1),
		"a document that is only its operation":   `{"operation":"publish_route"}`,
		"a document whose operation is a schema1": `{"operation":"deploy_oci_probe"}`,
	} {
		if _, err := DecodeV2([]byte(document)); err == nil {
			t.Fatalf("%s was accepted", name)
		}
	}
}

// TestSchemaOneAndSchemaTwoRefuseOneAnother keeps the older contract exactly
// where it was.
//
// A probe plan decodes, hashes and freezes as it always did, and neither decoder
// accepts a document of the other schema — the version is not a hint, it selects
// which closed contract the document is held against.
func TestSchemaOneAndSchemaTwoRefuseOneAnother(t *testing.T) {
	t.Parallel()
	for name, document := range map[string]string{
		"a service plan":     vectorWebServicePlanDocument,
		"an entrypoint plan": vectorEntrypointPlanDocument,
		"a route plan":       vectorRoutePlanDocument,
	} {
		if _, err := Decode([]byte(document)); err == nil {
			t.Fatalf("the schema 1 decoder accepted %s", name)
		}
	}
	if _, err := DecodeV2([]byte(vectorPlanDocument)); err == nil {
		t.Fatal("the schema 2 decoder accepted a probe plan")
	}
	if TranscriptDomain == TranscriptDomainV2 {
		t.Fatal("the two schemas share a transcript domain")
	}
	if SchemaVersion == SchemaVersionV2 {
		t.Fatal("the two schemas share a version")
	}
}

// TestASchemaTwoPlanSurvivesTransportAndReturnsTheSameBytes states the exact
// limit of what a transport may do: reshape the JSON, and only that.
func TestASchemaTwoPlanSurvivesTransportAndReturnsTheSameBytes(t *testing.T) {
	t.Parallel()
	for name, subject := range map[string]struct {
		canonical string
		reshaped  string
		digest    string
	}{
		"web service": {
			canonical: vectorWebServicePlanDocument,
			digest:    vectorWebServicePlanSHA256,
			reshaped: fmt.Sprintf(`{
  "local_port": %d,
  "image_digest": %q,
  "image_reference": %q,
  "service_profile": %q,
  "operation": %q,
  "machine_id": %q,
  "infrastructure_id": %q,
  "schema_version": 2
}`, vectorLocalPort, BentoPDFImageDigest, BentoPDFImageReference, vectorServiceProfile,
				OperationDeployWebService, vectorMachine, vectorInfrastructure),
		},
		"entrypoint": {
			canonical: vectorEntrypointPlanDocument,
			digest:    vectorEntrypointPlanSHA256,
			reshaped: fmt.Sprintf(`{
  "image_digest": %q,
  "image_reference": %q,
  "operation": %q,
  "machine_id": %q,
  "infrastructure_id": %q,
  "schema_version": 2
}`, EntrypointImageDigest, EntrypointImageReference,
				OperationDeployEntrypoint, vectorMachine, vectorInfrastructure),
		},
		"route": {
			canonical: vectorRoutePlanDocument,
			digest:    vectorRoutePlanSHA256,
			reshaped: fmt.Sprintf(`{
  "backend_port": %d,
  "route_host": %q,
  "operation": %q,
  "machine_id": %q,
  "infrastructure_id": %q,
  "schema_version": 2
}`, vectorBackendPort, vectorRouteHost,
				OperationPublishRoute, vectorMachine, vectorInfrastructure),
		},
	} {
		decoded, err := DecodeV2([]byte(subject.canonical))
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

		reordered, err := DecodeV2([]byte(subject.reshaped))
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

// TestTheRollbackOfASchemaTwoPairIsTheOtherPairItself is what makes a rollback a
// plan rather than a promise, in each of the three groups: removal for a
// deployment, redeployment for a removal, retire_route for publish_route.
func TestTheRollbackOfASchemaTwoPairIsTheOtherPairItself(t *testing.T) {
	t.Parallel()
	for name, subject := range map[string]struct {
		forward func() (V2Pair, error)
		reverse func() (V2Pair, error)
	}{
		"web service": {
			forward: func() (V2Pair, error) {
				return BuildWebServicePair(OperationDeployWebService, vectorInfrastructure,
					vectorMachine, vectorServiceProfile, vectorLocalPort)
			},
			reverse: func() (V2Pair, error) {
				return BuildWebServicePair(OperationRemoveWebService, vectorInfrastructure,
					vectorMachine, vectorServiceProfile, vectorLocalPort)
			},
		},
		"entrypoint": {
			forward: func() (V2Pair, error) {
				return BuildEntrypointPair(OperationDeployEntrypoint, vectorInfrastructure, vectorMachine)
			},
			reverse: func() (V2Pair, error) {
				return BuildEntrypointPair(OperationRemoveEntrypoint, vectorInfrastructure, vectorMachine)
			},
		},
		"route": {
			forward: func() (V2Pair, error) {
				return BuildRoutePair(OperationPublishRoute, vectorInfrastructure,
					vectorMachine, vectorRouteHost, vectorBackendPort)
			},
			reverse: func() (V2Pair, error) {
				return BuildRoutePair(OperationRetireRoute, vectorInfrastructure,
					vectorMachine, vectorRouteHost, vectorBackendPort)
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

// TestARollbackOfSchemaTwoIsRecognisedOnlyWhenItUndoesExactlyThePlan is what a
// machine asks before acting: the document it was handed as an undoing has to be
// one it could apply to return to the state it is about to leave.
func TestARollbackOfSchemaTwoIsRecognisedOnlyWhenItUndoesExactlyThePlan(t *testing.T) {
	t.Parallel()
	service, err := BuildWebServicePair(OperationDeployWebService, vectorInfrastructure,
		vectorMachine, vectorServiceProfile, vectorLocalPort)
	if err != nil {
		t.Fatal(err)
	}
	route, err := BuildRoutePair(OperationPublishRoute, vectorInfrastructure,
		vectorMachine, vectorRouteHost, vectorBackendPort)
	if err != nil {
		t.Fatal(err)
	}
	entrypoint, err := BuildEntrypointPair(OperationDeployEntrypoint, vectorInfrastructure, vectorMachine)
	if err != nil {
		t.Fatal(err)
	}

	// A document of another operation group is never an undoing, whatever it
	// names: the two are not the same plan written differently.
	if route.Rollback.IsExactInverseOf(service.Plan) || service.Rollback.IsExactInverseOf(route.Plan) {
		t.Fatal("a document of another operation group was read as an undoing")
	}
	if entrypoint.Rollback.IsExactInverseOf(service.Plan) {
		t.Fatal("an entrypoint removal was read as undoing a service deployment")
	}

	for name, forge := range map[string]func(*WebServiceDocument){
		"another machine":        func(d *WebServiceDocument) { d.MachineID = "lab-machine-2" },
		"another infrastructure": func(d *WebServiceDocument) { d.InfrastructureID = otherInfrastructure },
		"another port":           func(d *WebServiceDocument) { d.LocalPort = vectorLocalPort + 1 },
		"another profile":        func(d *WebServiceDocument) { d.ServiceProfile = "bentopdf-simple" },
		"another image":          func(d *WebServiceDocument) { d.ImageReference = EntrypointImageReference },
		"another digest":         func(d *WebServiceDocument) { d.ImageDigest = otherPinnedDigest },
		"the same operation":     func(d *WebServiceDocument) { d.Operation = OperationDeployWebService },
		"an unknown operation":   func(d *WebServiceDocument) { d.Operation = "install_container" },
	} {
		forged, ok := service.Rollback.(WebServiceDocument)
		if !ok {
			t.Fatal("the rollback of a service pair is not a service document")
		}
		forge(&forged)
		if forged.IsExactInverseOf(service.Plan) {
			t.Fatalf("a rollback naming %s was read as undoing the plan", name)
		}
	}

	for name, forge := range map[string]func(*RouteDocument){
		"another host":         func(d *RouteDocument) { d.RouteHost = "other.lab.your-cloud.test" },
		"another backend port": func(d *RouteDocument) { d.BackendPort = vectorBackendPort + 1 },
		"the same operation":   func(d *RouteDocument) { d.Operation = OperationPublishRoute },
		"an unknown operation": func(d *RouteDocument) { d.Operation = "publish_ingress" },
	} {
		forged, ok := route.Rollback.(RouteDocument)
		if !ok {
			t.Fatal("the rollback of a route pair is not a route document")
		}
		forge(&forged)
		if forged.IsExactInverseOf(route.Plan) {
			t.Fatalf("a rollback naming %s was read as undoing the route", name)
		}
	}
}

func TestSchemaTwoBuildersRefuseEveryInstanceOutsideTheContract(t *testing.T) {
	t.Parallel()
	for _, port := range []int{MinLocalPort, MaxLocalPort} {
		if _, err := BuildWebServicePair(OperationDeployWebService, vectorInfrastructure,
			vectorMachine, vectorServiceProfile, port); err != nil {
			t.Fatalf("the bound %d of the port range must build: %v", port, err)
		}
	}
	if _, err := BuildRoutePair(OperationRetireRoute, vectorInfrastructure,
		vectorMachine, "abc", MinBackendPort); err != nil {
		t.Fatalf("the bounds of the route contract must build: %v", err)
	}

	for name, build := range map[string]func() (V2Pair, error){
		"a service pair on an unknown operation": func() (V2Pair, error) {
			return BuildWebServicePair("install_container", vectorInfrastructure,
				vectorMachine, vectorServiceProfile, vectorLocalPort)
		},
		"a service pair on the probe operation": func() (V2Pair, error) {
			return BuildWebServicePair(OperationDeployOCIProbe, vectorInfrastructure,
				vectorMachine, vectorServiceProfile, vectorLocalPort)
		},
		"a service pair on a route operation": func() (V2Pair, error) {
			return BuildWebServicePair(OperationPublishRoute, vectorInfrastructure,
				vectorMachine, vectorServiceProfile, vectorLocalPort)
		},
		"a service pair on an unknown profile": func() (V2Pair, error) {
			return BuildWebServicePair(OperationDeployWebService, vectorInfrastructure,
				vectorMachine, "bentopdf-simple", vectorLocalPort)
		},
		"a service pair without a profile": func() (V2Pair, error) {
			return BuildWebServicePair(OperationDeployWebService, vectorInfrastructure,
				vectorMachine, "", vectorLocalPort)
		},
		"a service pair on a privileged port": func() (V2Pair, error) {
			return BuildWebServicePair(OperationDeployWebService, vectorInfrastructure,
				vectorMachine, vectorServiceProfile, 443)
		},
		"a service pair on a malformed machine": func() (V2Pair, error) {
			return BuildWebServicePair(OperationDeployWebService, vectorInfrastructure,
				"LAB", vectorServiceProfile, vectorLocalPort)
		},
		"a service pair on a malformed infrastructure": func() (V2Pair, error) {
			return BuildWebServicePair(OperationDeployWebService, "not-a-uuid",
				vectorMachine, vectorServiceProfile, vectorLocalPort)
		},
		"an entrypoint pair on a service operation": func() (V2Pair, error) {
			return BuildEntrypointPair(OperationDeployWebService, vectorInfrastructure, vectorMachine)
		},
		"an entrypoint pair on the read-only operation of the previous palier": func() (V2Pair, error) {
			return BuildEntrypointPair("diagnose_protocol_read_only", vectorInfrastructure, vectorMachine)
		},
		"an entrypoint pair without an operation": func() (V2Pair, error) {
			return BuildEntrypointPair("", vectorInfrastructure, vectorMachine)
		},
		"a route pair on an entrypoint operation": func() (V2Pair, error) {
			return BuildRoutePair(OperationDeployEntrypoint, vectorInfrastructure,
				vectorMachine, vectorRouteHost, vectorBackendPort)
		},
		"a route pair on a wildcard host": func() (V2Pair, error) {
			return BuildRoutePair(OperationPublishRoute, vectorInfrastructure,
				vectorMachine, "*.lab.your-cloud.test", vectorBackendPort)
		},
		"a route pair without a host": func() (V2Pair, error) {
			return BuildRoutePair(OperationPublishRoute, vectorInfrastructure,
				vectorMachine, "", vectorBackendPort)
		},
		"a route pair on a privileged backend": func() (V2Pair, error) {
			return BuildRoutePair(OperationPublishRoute, vectorInfrastructure,
				vectorMachine, vectorRouteHost, 443)
		},
		"a route pair beyond the backend range": func() (V2Pair, error) {
			return BuildRoutePair(OperationPublishRoute, vectorInfrastructure,
				vectorMachine, vectorRouteHost, MaxBackendPort+1)
		},
	} {
		if _, err := build(); err == nil {
			t.Fatalf("%s built a pair", name)
		}
	}

	// An empty pair freezes nothing rather than freezing a zero document.
	if _, err := (V2Pair{}).Freeze(); err == nil {
		t.Fatal("an empty pair was frozen")
	}
}

// TestTheImagesOfThisPalierArePinnedByDigestAlone keeps the decisions of the
// contract testable rather than merely written: one profile, one image per
// pinned role, no second truth beside a digest, and an undoing for every
// operation.
//
// The human versions of these images — the tags a release note names — appear
// nowhere in this package on purpose. A tag in the source would be a second,
// movable identity beside the digest, and the digest is the identity.
func TestTheImagesOfThisPalierArePinnedByDigestAlone(t *testing.T) {
	t.Parallel()
	for name, reference := range map[string]string{
		"the service image":    BentoPDFImageReference,
		"the entrypoint image": EntrypointImageReference,
	} {
		if strings.ContainsAny(reference, ":@") {
			t.Fatalf("%s carries a tag or a digest: %s", name, reference)
		}
		if !strings.Contains(reference, "/") {
			t.Fatalf("%s names no registry: %s", name, reference)
		}
	}
	for name, digest := range map[string]string{
		"the service digest":    BentoPDFImageDigest,
		"the entrypoint digest": EntrypointImageDigest,
	} {
		if !canonicalOCIDigest.MatchString(digest) {
			t.Fatalf("%s is not canonical: %s", name, digest)
		}
	}
	if BentoPDFImageDigest == EntrypointImageDigest {
		t.Fatal("the two pinned images share a digest")
	}

	if len(profileImage) != 1 {
		t.Fatalf("this palier describes exactly one service profile, not %d", len(profileImage))
	}
	if _, known := profileImage[ServiceProfileBentoPDF]; !known {
		t.Fatal("the one service profile of this palier is not the one it names")
	}
	if len(inverseOperationV2) != 6 || len(operationGroups) != 6 {
		t.Fatalf("schema 2 describes exactly six operations, not %d and %d",
			len(inverseOperationV2), len(operationGroups))
	}
	for operation, inverse := range inverseOperationV2 {
		if inverseOperationV2[inverse] != operation {
			t.Fatalf("operation %q is not undone by an operation that redoes it", operation)
		}
		if operationGroups[operation] == 0 {
			t.Fatalf("operation %q carries no closed field list", operation)
		}
		if operationGroups[inverse] != operationGroups[operation] {
			t.Fatalf("operation %q and its undoing do not carry the same fields", operation)
		}
	}
	if _, borrowed := operationGroups[OperationDeployOCIProbe]; borrowed {
		t.Fatal("a schema 1 operation carries a schema 2 field list")
	}
}

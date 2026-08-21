// Package plan gives the two digests an approval signs their first real
// content: a closed description of a state, and the complete second document
// that undoes it.
//
// The approval envelope signs plan_sha256 and rollback_sha256 without saying
// what they cover. A plan is what they cover here. It is never a script: its
// field list is closed, and none of its fields can carry a command, a path, a
// playbook, an inventory, a volume, a network or a privilege. A document that
// tries is refused by the strict decoding before any of its content is read,
// which is the strongest form the refusal can take — the refusal does not
// depend on understanding what was smuggled in.
//
// Nothing in this package signs anything. The Controller that builds a plan
// holds no approval key: it freezes bytes and transports them. Everything a
// plan means is re-derived on the machine that will act on it, from that
// machine's own anchors, exactly as for the envelope that names its digest.
//
// The transcript below is the counterpart of the one written on the App
// side. The two are held against one another by deterministic vectors on both
// sides rather than by reading, because a canonical encoding that exists in two
// implementations is only canonical while the two agree byte for byte.
package plan

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/ldesfontaine/your-cloud/internal/strictjson"
)

const (
	// SchemaVersion is the one plan version this palier reads and builds.
	SchemaVersion = 1

	// TranscriptDomain separates a plan digest from every other transcript of
	// the product. Its terminating NUL cannot appear in any textual field, so
	// no prefix of one transcript is a prefix of another.
	TranscriptDomain = "your-cloud/oci-plan.v1\x00"

	// DigestBytes is the length of the decoded image digest and of the plan
	// digest the envelope names.
	DigestBytes = 32

	// MaxPlanBytes bounds a plan document before it is parsed. A plan is a
	// fixed set of bounded fields; this is the size they reach with room for
	// the reindentation a transport is allowed to apply.
	MaxPlanBytes = 4096

	// OperationDeployOCIProbe asks for the probe to be present on exactly one
	// machine, at exactly one local port.
	OperationDeployOCIProbe = "deploy_oci_probe"
	// OperationRemoveOCIProbe asks for that exact instance to be absent. It
	// carries the same fields as the deployment because a removal names an
	// instance, never "whatever is running there".
	OperationRemoveOCIProbe = "remove_oci_probe"

	// ProbeImageReference is the one registry, repository and image this palier
	// accepts. It carries no tag: a tag would be a second, movable truth beside
	// the digest, and the digest is the identity.
	ProbeImageReference = "docker.io/traefik/whoami"

	// ProbeImageDigest pins the manifest list this palier accepts. Widening the
	// accepted images is a decision of a later palier, not a generalisation of
	// this one, so the value is compared for equality rather than parsed into a
	// policy.
	ProbeImageDigest = "sha256:200689790a0a0ea48ca45992e0450bc26ccab5307375b41c84dfc4f2475937ab"

	// MinLocalPort and MaxLocalPort bound the loopback port the probe listens
	// on. The address itself is a constant of the contract and not a field: no
	// approvable value can expose the probe beyond its own machine.
	MinLocalPort = 1024
	MaxLocalPort = 65535
)

var (
	canonicalUUIDv4    = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	canonicalMachine   = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{2,62}$`)
	canonicalOCIDigest = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

	// inverseOperation is at once the closed list of operations this palier
	// describes and the operation that undoes each of them. Holding both in one
	// declaration is what makes an operation without an undoing impossible to
	// add here by accident.
	inverseOperation = map[string]string{
		OperationDeployOCIProbe: OperationRemoveOCIProbe,
		OperationRemoveOCIProbe: OperationDeployOCIProbe,
	}

	errMalformedImageDigest = errors.New("plan image_digest is malformed")
)

// Document is the whole plan. The declaration order below is the canonical
// encoding order and the transcript order at once, and no field of a plan lives
// outside it.
type Document struct {
	SchemaVersion    int    `json:"schema_version"`
	InfrastructureID string `json:"infrastructure_id"`
	MachineID        string `json:"machine_id"`
	Operation        string `json:"operation"`
	ImageReference   string `json:"image_reference"`
	ImageDigest      string `json:"image_digest"`
	LocalPort        int    `json:"local_port"`
}

// Pair is one plan and the complete document that undoes it.
//
// The rollback is a plan in its own right, read, displayed, approved and
// verified like any other. It is never an implicit promise attached to the
// first document, because a promise no one can hash is a promise no one can
// refuse.
type Pair struct {
	Plan     Document
	Rollback Document
}

// Frozen is the transportable form of a pair: the two canonical documents and
// the two digests an approval envelope names as plan_sha256 and
// rollback_sha256.
type Frozen struct {
	PlanDocument     []byte
	PlanSHA256       string
	RollbackDocument []byte
	RollbackSHA256   string
}

// Decode accepts one bounded, strict, fully validated plan document.
//
// It never returns a partially checked plan: a caller that holds one may assume
// every field is inside the bounds of the contract, which is what lets the
// decisions that follow be about authority rather than about shape.
func Decode(document []byte) (*Document, error) {
	if len(document) == 0 || len(document) > MaxPlanBytes {
		return nil, fmt.Errorf("plan document must contain 1..%d bytes", MaxPlanBytes)
	}
	var parsed Document
	if err := strictDecodePlan(document, &parsed); err != nil {
		return nil, err
	}
	if err := parsed.Validate(); err != nil {
		return nil, err
	}
	return &parsed, nil
}

// Validate holds a plan against the whole contract of the palier, image
// included.
//
// The image is checked for equality against the one pinned probe rather than
// against a policy, because this palier accepts exactly one probe and nothing
// else. A plan naming another registry, another repository or another digest is
// not a narrower or a wider plan: it is one this palier does not build and does
// not recognise.
func (document *Document) Validate() error {
	if document.SchemaVersion != SchemaVersion {
		return errors.New("plan schema version is unsupported")
	}
	if !canonicalUUIDv4.MatchString(document.InfrastructureID) {
		return errors.New("plan infrastructure_id must be a canonical lower-case UUIDv4")
	}
	if !canonicalMachine.MatchString(document.MachineID) {
		return errors.New("plan machine_id is malformed")
	}
	if _, known := inverseOperation[document.Operation]; !known {
		return fmt.Errorf("plan operation %q is not one this palier describes", document.Operation)
	}
	if document.ImageReference != ProbeImageReference {
		return errors.New("plan image_reference is not the pinned probe of this palier")
	}
	// The shape is required before the pin so that the transcript may rely on
	// decoding exactly 32 bytes out of the field, and so that a malformed
	// digest and an unpinned one remain two distinct refusals.
	if !canonicalOCIDigest.MatchString(document.ImageDigest) {
		return errMalformedImageDigest
	}
	if document.ImageDigest != ProbeImageDigest {
		return errors.New("plan image_digest is not the pinned probe of this palier")
	}
	if document.LocalPort < MinLocalPort || document.LocalPort > MaxLocalPort {
		return fmt.Errorf("plan local_port must be within %d..%d", MinLocalPort, MaxLocalPort)
	}
	return nil
}

// IsExactInverseOf reports whether this document undoes the other one entirely:
// the opposite operation on the same instance, differing in nothing else.
//
// A machine asks this before acting so that the rollback it received is a
// document it could actually apply to return to the state it is leaving. A
// rollback naming another machine, another port or another image would be a
// second plan rather than an undoing, and a human who approved the pair would
// have approved something the machine cannot honour.
func (document *Document) IsExactInverseOf(other *Document) bool {
	if document == nil || other == nil {
		return false
	}
	inverse, known := inverseOperation[other.Operation]
	if !known {
		return false
	}
	expected := *other
	expected.Operation = inverse
	return *document == expected
}

// Encode renders the one canonical encoding of a plan for transport.
//
// A transport may reindent or reorder what it carries without changing the plan
// — the digest is rebuilt from the fields, not from the bytes — but the
// Controller emits exactly one spelling, so that the document a human is shown,
// the document an Auxiliary receives and the document a digest was taken over
// are the same bytes rather than three encodings that happen to agree.
func (document *Document) Encode() ([]byte, error) {
	if err := document.Validate(); err != nil {
		return nil, err
	}
	return encodeCanonicalPlan(document)
}

// strictDecodePlan is the one strict decoding every schema of this package goes
// through, so that no schema can own a second way of reading its own bytes — a
// looser one above all.
func strictDecodePlan(document []byte, shape any) error {
	if err := strictjson.Decode(document, shape); err != nil {
		return fmt.Errorf("decode plan: %w", err)
	}
	return nil
}

// encodeCanonicalPlan renders one validated document as the one spelling the
// Controller emits, and is the one place any schema does so.
//
// The bound is required again after the rendering rather than trusted from the
// fields: a document that validates and still does not fit is refused rather
// than transported, whatever its schema.
func encodeCanonicalPlan(document any) ([]byte, error) {
	buffer := &bytes.Buffer{}
	encoder := json.NewEncoder(buffer)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(document); err != nil {
		return nil, fmt.Errorf("encode plan: %w", err)
	}
	encoded := bytes.TrimSuffix(buffer.Bytes(), []byte("\n"))
	if len(encoded) == 0 || len(encoded) > MaxPlanBytes {
		return nil, fmt.Errorf("plan document must contain 1..%d bytes", MaxPlanBytes)
	}
	return encoded, nil
}

// Transcript rebuilds the exact bytes a plan digest is taken over.
//
// It is built from the parsed fields and never from a received document, so two
// implementations that read the same plan produce the same digest, a transport
// that reshapes the JSON transports the same plan, and a transport that changes
// one value transports a plan whose digest no longer matches the approval that
// named it.
func (document *Document) Transcript() ([]byte, error) {
	if err := document.Validate(); err != nil {
		return nil, err
	}
	image, err := decodeOCIDigest(document.ImageDigest)
	if err != nil {
		return nil, err
	}
	transcript := make([]byte, 0, len(TranscriptDomain)+192)
	transcript = append(transcript, TranscriptDomain...)
	transcript = append(transcript, byte(document.SchemaVersion))
	transcript = appendField(transcript, []byte(document.InfrastructureID))
	transcript = appendField(transcript, []byte(document.MachineID))
	transcript = appendField(transcript, []byte(document.Operation))
	transcript = appendField(transcript, []byte(document.ImageReference))
	transcript = appendField(transcript, image)
	transcript = appendUint32(transcript, uint32(document.LocalPort))
	return transcript, nil
}

// SHA256 is the lower-case hexadecimal value an envelope names as plan_sha256
// or rollback_sha256, in the exact spelling that envelope requires.
func (document *Document) SHA256() (string, error) { return digestOf(document) }

// BuildPair freezes one operation on one instance together with the complete
// document that undoes it.
//
// The two documents differ by their operation and by nothing else: the rollback
// of a deployment removes that exact instance, and the rollback of a removal
// redeploys that exact instance. A caller cannot ask for a rollback that
// targets another machine, another port or another image, because it never
// supplies one.
func BuildPair(operation, infrastructureID, machineID string, localPort int) (Pair, error) {
	inverse, known := inverseOperation[operation]
	if !known {
		return Pair{}, fmt.Errorf("plan operation %q is not one this palier builds", operation)
	}
	subject := Document{
		SchemaVersion:    SchemaVersion,
		InfrastructureID: infrastructureID,
		MachineID:        machineID,
		Operation:        operation,
		ImageReference:   ProbeImageReference,
		ImageDigest:      ProbeImageDigest,
		LocalPort:        localPort,
	}
	if err := subject.Validate(); err != nil {
		return Pair{}, err
	}
	rollback := subject
	rollback.Operation = inverse
	if err := rollback.Validate(); err != nil {
		return Pair{}, err
	}
	return Pair{Plan: subject, Rollback: rollback}, nil
}

// Freeze renders a pair once and keeps the documents and their digests
// together, so that no caller can transport one document beside the digest of
// another.
func (pair Pair) Freeze() (Frozen, error) { return freeze(&pair.Plan, &pair.Rollback) }

// hashedDocument is what freezing a pair requires of a document, whatever its
// schema: the one canonical spelling of its bytes, and the digest an envelope
// names. Both schemas answer it, so neither owns a second way of being frozen.
type hashedDocument interface {
	Encode() ([]byte, error)
	SHA256() (string, error)
}

func freeze(planDocument, rollbackDocument hashedDocument) (Frozen, error) {
	encodedPlan, err := planDocument.Encode()
	if err != nil {
		return Frozen{}, err
	}
	planDigest, err := planDocument.SHA256()
	if err != nil {
		return Frozen{}, err
	}
	encodedRollback, err := rollbackDocument.Encode()
	if err != nil {
		return Frozen{}, err
	}
	rollbackDigest, err := rollbackDocument.SHA256()
	if err != nil {
		return Frozen{}, err
	}
	return Frozen{
		PlanDocument:     encodedPlan,
		PlanSHA256:       planDigest,
		RollbackDocument: encodedRollback,
		RollbackSHA256:   rollbackDigest,
	}, nil
}

// digestOf is the one place a plan digest is taken, so that no schema can hash
// its transcript by a second procedure.
func digestOf(document interface{ Transcript() ([]byte, error) }) (string, error) {
	transcript, err := document.Transcript()
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(transcript)
	return hex.EncodeToString(digest[:]), nil
}

// decodeOCIDigest turns the textual field into the 32 bytes the transcript
// carries, and refuses everything else.
func decodeOCIDigest(value string) ([]byte, error) {
	decoded, err := hex.DecodeString(strings.TrimPrefix(value, "sha256:"))
	if err != nil || len(decoded) != DigestBytes {
		return nil, errMalformedImageDigest
	}
	return decoded, nil
}

func appendField(buffer []byte, value []byte) []byte {
	buffer = appendUint32(buffer, uint32(len(value)))
	return append(buffer, value...)
}

func appendUint32(buffer []byte, value uint32) []byte {
	var encoded [4]byte
	binary.BigEndian.PutUint32(encoded[:], value)
	return append(buffer, encoded[:]...)
}

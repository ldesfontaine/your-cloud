package plan

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/ldesfontaine/your-cloud/internal/strictjson"
)

// Schema 2 keeps every procedure of schema 1 — one bounded strict JSON
// document, one domain-separated binary transcript, a rollback that is a
// complete inverse document, a pair frozen by the Controller — and adds the
// four operations of the public profile. Schema 1 is not reopened by any of it:
// a probe plan decodes, hashes and freezes exactly as before, and a document of
// either schema is refused by the decoder of the other.
//
// The transcript is laid out per operation group. The fields a group does not
// have are simply not present rather than written empty, and the operation
// string inside the transcript is what tells the groups apart:
//
//	domaine  "your-cloud/oci-plan.v2\0"
//	puis     schema_version   sur 1 octet
//	         infrastructure_id, machine_id, operation
//	                                     en champs préfixés par longueur uint32
//	puis, selon l'opération :
//	  deploy_web_service / remove_web_service
//	         service_profile, image_reference  en champs préfixés
//	         image_digest (32 octets décodés)  en champ préfixé
//	         local_port                        en uint32 big-endian
//	  deploy_entrypoint / remove_entrypoint
//	         image_reference                   en champ préfixé
//	         image_digest (32 octets décodés)  en champ préfixé
//	  publish_route / retire_route
//	         route_host                        en champ préfixé
//	         backend_port                      en uint32 big-endian
//
// The layout is unambiguous across the three groups without a group tag,
// because everything before the operation is at a determined offset: the domain
// and the version are fixed, and each of the two fields that follow announces
// its own length. A reader that has consumed the operation therefore knows
// which of the three tails it is looking at, so no two documents of different
// groups can produce the same bytes.
const (
	// SchemaVersionV2 is the second plan version, and the only one that
	// describes services, entrypoints and routes.
	SchemaVersionV2 = 2

	// TranscriptDomainV2 separates a schema 2 digest from a schema 1 digest and
	// from every other transcript of the product. Its terminating NUL cannot
	// appear in any textual field, so no prefix of one transcript is a prefix of
	// another.
	TranscriptDomainV2 = "your-cloud/oci-plan.v2\x00"

	// OperationDeployWebService asks for one managed web service to be present
	// on exactly one machine, at exactly one loopback port, and
	// OperationRemoveWebService for that exact instance to be absent.
	OperationDeployWebService = "deploy_web_service"
	OperationRemoveWebService = "remove_web_service"

	// OperationDeployEntrypoint asks for the public entrypoint to exist on this
	// machine, and OperationRemoveEntrypoint for it to be gone. Neither carries
	// a port or a host: the public ports, the listening addresses and the file
	// provider directory are constants of the contract, and an entrypoint has
	// nothing approvable beyond its existence and its image.
	OperationDeployEntrypoint = "deploy_entrypoint"
	OperationRemoveEntrypoint = "remove_entrypoint"

	// OperationPublishRoute asks for one declared name to reach one managed
	// service through the entrypoint, and OperationRetireRoute for that name to
	// stop being served. Retiring a route removes the route and nothing else:
	// the service it named keeps running.
	OperationPublishRoute = "publish_route"
	OperationRetireRoute  = "retire_route"

	// ServiceProfileBentoPDF is the one service profile this palier describes.
	// The profile decides everything the plan does not state — account, unit
	// file, isolation headers — so an unknown profile is refused before the rest
	// of the document is read. Widening the list is a decision of a later
	// palier.
	ServiceProfileBentoPDF = "bentopdf"

	// BentoPDFImageReference and BentoPDFImageDigest pin the one image the
	// bentopdf profile may name. As for the probe, the reference carries no tag:
	// a tag is a human indication, the digest is the executable identity, and an
	// update is a new plan whose digest differs rather than a silent mutation.
	BentoPDFImageReference = "ghcr.io/alam00000/bentopdf"
	BentoPDFImageDigest    = "sha256:a4ed090f29823da5e296e2c2f8603664da71676156ea47c3f186cc73eec38db0"

	// EntrypointImageReference and EntrypointImageDigest pin the one image an
	// entrypoint plan may name, under the same rule.
	EntrypointImageReference = "docker.io/library/traefik"
	EntrypointImageDigest    = "sha256:9c3b91d5fb7770853ca5c1124a23c34bf2d9b47ffaebeab2614cbaf410dcb2ac"

	// MinRouteHostBytes and MaxRouteHostBytes bound the declared name a route
	// serves. There is no wildcard inside those bounds: a route names one host,
	// and a name nobody declared receives the generic refusal of the entrypoint
	// rather than an application route.
	MinRouteHostBytes = 3
	MaxRouteHostBytes = 253

	// MinBackendPort and MaxBackendPort repeat the loopback range of the service
	// side, because a route may only name a port a managed service of the same
	// machine could be listening on.
	MinBackendPort = MinLocalPort
	MaxBackendPort = MaxLocalPort
)

// operationGroup is which of the three closed field lists an operation carries.
type operationGroup int

const (
	groupWebService operationGroup = iota + 1
	groupEntrypoint
	groupRoute
)

// pinnedImage is one registry-qualified reference and the digest that is the
// executable identity behind it. The two always travel together so that no
// declaration can pin a digest for one repository and a reference for another.
type pinnedImage struct {
	reference string
	digest    string
}

var (
	// canonicalRouteHost bounds the declared name a route serves: lower-case
	// letters, digits, hyphens and dots, three to two hundred fifty-three
	// characters, opening and closing on a letter or a digit. Consecutive
	// hyphens stay accepted because a punycode label carries them; consecutive
	// dots do not, and are refused beside this expression.
	canonicalRouteHost = regexp.MustCompile(fmt.Sprintf(`^[a-z0-9][a-z0-9.-]{%d,%d}[a-z0-9]$`,
		MinRouteHostBytes-2, MaxRouteHostBytes-2))

	// inverseOperationV2 is at once the closed list of operations schema 2
	// describes and the operation that undoes each of them. Holding both in one
	// declaration is what makes an operation without an undoing impossible to
	// add here by accident.
	inverseOperationV2 = map[string]string{
		OperationDeployWebService: OperationRemoveWebService,
		OperationRemoveWebService: OperationDeployWebService,
		OperationDeployEntrypoint: OperationRemoveEntrypoint,
		OperationRemoveEntrypoint: OperationDeployEntrypoint,
		OperationPublishRoute:     OperationRetireRoute,
		OperationRetireRoute:      OperationPublishRoute,
	}

	// operationGroups says which closed field list each operation carries. It is
	// the whole of the discriminator: an operation absent from this table has no
	// document shape, and is refused before any field of the document is read.
	operationGroups = map[string]operationGroup{
		OperationDeployWebService: groupWebService,
		OperationRemoveWebService: groupWebService,
		OperationDeployEntrypoint: groupEntrypoint,
		OperationRemoveEntrypoint: groupEntrypoint,
		OperationPublishRoute:     groupRoute,
		OperationRetireRoute:      groupRoute,
	}

	// profileImage is at once the closed list of service profiles and the one
	// image each of them may name. A profile the table does not hold is refused
	// before its image is compared, so an unknown profile can never borrow the
	// pin of a known one.
	profileImage = map[string]pinnedImage{
		ServiceProfileBentoPDF: {reference: BentoPDFImageReference, digest: BentoPDFImageDigest},
	}

	// entrypointImage is the single pin of the entrypoint, which has no profile
	// to choose from: there is one entrypoint and one image for it.
	entrypointImage = pinnedImage{reference: EntrypointImageReference, digest: EntrypointImageDigest}
)

// Target is the one infrastructure and the one machine a schema 2 document
// names. An Auxiliary holds it against its own anchors before reading anything
// else the document says.
type Target struct {
	InfrastructureID string
	MachineID        string
}

// V2Document is one plan of schema 2, whatever its operation group.
//
// The interface is closed to the three shapes declared below: its unexported
// method cannot be implemented outside this package, so a fourth field list is a
// decision taken here — beside the transcript it would need and beside the
// inverse it must have — rather than a type another package could hand to a
// Controller.
type V2Document interface {
	// Validate holds the document against the whole contract of the palier,
	// profile and pinned image included.
	Validate() error
	// Encode renders the one canonical encoding of the document for transport.
	Encode() ([]byte, error)
	// Transcript rebuilds the exact bytes the digest is taken over.
	Transcript() ([]byte, error)
	// SHA256 is the lower-case hexadecimal value an envelope names as
	// plan_sha256 or rollback_sha256.
	SHA256() (string, error)
	// OperationName is the state the document asks for.
	OperationName() string
	// Target names the one machine and the one infrastructure the document aims
	// at, and nothing else.
	Target() Target
	// IsExactInverseOf reports whether this document undoes the other one
	// entirely: the opposite operation on the same instance, differing in
	// nothing else.
	IsExactInverseOf(other V2Document) bool

	inverse() (V2Document, bool)
}

// WebServiceDocument is the plan of one managed web service: one profile, the
// image that profile pins, and one loopback port on one machine.
//
// The declaration order below is the canonical encoding order and the transcript
// order at once, and no field of a web service plan lives outside it.
type WebServiceDocument struct {
	SchemaVersion    int    `json:"schema_version"`
	InfrastructureID string `json:"infrastructure_id"`
	MachineID        string `json:"machine_id"`
	Operation        string `json:"operation"`
	ServiceProfile   string `json:"service_profile"`
	ImageReference   string `json:"image_reference"`
	ImageDigest      string `json:"image_digest"`
	LocalPort        int    `json:"local_port"`
}

// EntrypointDocument is the plan of the public entrypoint: its existence and its
// image, and deliberately nothing else.
//
// It carries neither port nor host. The public ports, the listening addresses
// and the file provider directory are constants of the contract, so a field for
// any of them would be an approvable value that decides nothing.
type EntrypointDocument struct {
	SchemaVersion    int    `json:"schema_version"`
	InfrastructureID string `json:"infrastructure_id"`
	MachineID        string `json:"machine_id"`
	Operation        string `json:"operation"`
	ImageReference   string `json:"image_reference"`
	ImageDigest      string `json:"image_digest"`
}

// RouteDocument is the plan of one published name: the host the entrypoint
// serves and the loopback port of the managed service behind it.
//
// It carries no image. A route publishes a service that another plan deployed;
// naming an image here would let a route describe a deployment nobody approved
// as one.
type RouteDocument struct {
	SchemaVersion    int    `json:"schema_version"`
	InfrastructureID string `json:"infrastructure_id"`
	MachineID        string `json:"machine_id"`
	Operation        string `json:"operation"`
	RouteHost        string `json:"route_host"`
	BackendPort      int    `json:"backend_port"`
}

// V2Pair is one schema 2 plan and the complete document that undoes it.
//
// The rollback is a plan in its own right, read, displayed, approved and
// verified like any other: removal for a deployment, redeployment for a removal,
// retire_route for publish_route.
type V2Pair struct {
	Plan     V2Document
	Rollback V2Document
}

// DecodeV2 accepts one bounded, strict, fully validated schema 2 document.
//
// It never returns a partially checked plan: a caller that holds one may assume
// every field is inside the bounds of the contract, and that the fields it holds
// are exactly the ones its operation declares — no more, and none borrowed from
// another operation.
func DecodeV2(document []byte) (V2Document, error) {
	if len(document) == 0 || len(document) > MaxPlanBytes {
		return nil, fmt.Errorf("plan document must contain 1..%d bytes", MaxPlanBytes)
	}
	operation, err := declaredOperation(document)
	if err != nil {
		return nil, err
	}
	var parsed V2Document
	switch operationGroups[operation] {
	case groupWebService:
		var shape WebServiceDocument
		if err := strictjson.Decode(document, &shape); err != nil {
			return nil, fmt.Errorf("decode plan: %w", err)
		}
		parsed = shape
	case groupEntrypoint:
		var shape EntrypointDocument
		if err := strictjson.Decode(document, &shape); err != nil {
			return nil, fmt.Errorf("decode plan: %w", err)
		}
		parsed = shape
	case groupRoute:
		var shape RouteDocument
		if err := strictjson.Decode(document, &shape); err != nil {
			return nil, fmt.Errorf("decode plan: %w", err)
		}
		parsed = shape
	default:
		return nil, fmt.Errorf("plan operation %q is not one this palier describes", operation)
	}
	if err := parsed.Validate(); err != nil {
		return nil, err
	}
	return parsed, nil
}

// declaredOperation reads only the operation field, and decides which closed
// schema the document will be held against from it alone.
//
// It is the same principle as the discriminator of the Auxiliary's input: the
// shape is read in the document rather than guessed by trying each schema in
// turn. That is what keeps the three field lists from covering for one another —
// a route document carrying image_digest is an unknown field of the route
// schema, refused before its value is read, instead of being retried as a web
// service plan that happens to be missing a port. Nothing is decided here: this
// pass selects a schema, and the strict decoding that follows is the whole of
// the authority.
func declaredOperation(document []byte) (string, error) {
	var fields map[string]json.RawMessage
	if err := strictjson.Decode(document, &fields); err != nil {
		return "", fmt.Errorf("decode plan: %w", err)
	}
	raw, declared := fields["operation"]
	if !declared {
		return "", errors.New("plan declares no operation")
	}
	var operation string
	if err := json.Unmarshal(raw, &operation); err != nil {
		return "", errors.New("plan operation must be a string")
	}
	return operation, nil
}

// BuildWebServicePair freezes one operation on one service instance together
// with the complete document that undoes it.
//
// The caller chooses the profile and is refused when the profile is not one this
// palier describes; it never chooses the image, because the profile pins it.
func BuildWebServicePair(operation, infrastructureID, machineID, serviceProfile string, localPort int) (V2Pair, error) {
	image, known := profileImage[serviceProfile]
	if !known {
		return V2Pair{}, fmt.Errorf("plan service_profile %q is not one this palier builds", serviceProfile)
	}
	return buildV2Pair(WebServiceDocument{
		SchemaVersion:    SchemaVersionV2,
		InfrastructureID: infrastructureID,
		MachineID:        machineID,
		Operation:        operation,
		ServiceProfile:   serviceProfile,
		ImageReference:   image.reference,
		ImageDigest:      image.digest,
		LocalPort:        localPort,
	})
}

// BuildEntrypointPair freezes the existence of the entrypoint on one machine
// together with its removal. There is nothing else to choose.
func BuildEntrypointPair(operation, infrastructureID, machineID string) (V2Pair, error) {
	return buildV2Pair(EntrypointDocument{
		SchemaVersion:    SchemaVersionV2,
		InfrastructureID: infrastructureID,
		MachineID:        machineID,
		Operation:        operation,
		ImageReference:   entrypointImage.reference,
		ImageDigest:      entrypointImage.digest,
	})
}

// BuildRoutePair freezes one published name together with its retirement.
func BuildRoutePair(operation, infrastructureID, machineID, routeHost string, backendPort int) (V2Pair, error) {
	return buildV2Pair(RouteDocument{
		SchemaVersion:    SchemaVersionV2,
		InfrastructureID: infrastructureID,
		MachineID:        machineID,
		Operation:        operation,
		RouteHost:        routeHost,
		BackendPort:      backendPort,
	})
}

// buildV2Pair holds both directions against the contract before either exists.
//
// The two documents differ by their operation and by nothing else, and a caller
// cannot ask for a rollback that targets another instance because it never
// supplies one.
func buildV2Pair(subject V2Document) (V2Pair, error) {
	if err := subject.Validate(); err != nil {
		return V2Pair{}, err
	}
	rollback, known := subject.inverse()
	if !known {
		// Unreachable while Validate refuses every operation outside the closed
		// table, and kept as a refusal so that a disagreement between the two
		// declarations builds nothing rather than something.
		return V2Pair{}, fmt.Errorf("plan operation %q is not one this palier builds", subject.OperationName())
	}
	if err := rollback.Validate(); err != nil {
		return V2Pair{}, err
	}
	return V2Pair{Plan: subject, Rollback: rollback}, nil
}

// Freeze renders a pair once and keeps the documents and their digests together,
// so that no caller can transport one document beside the digest of another.
func (pair V2Pair) Freeze() (Frozen, error) {
	if pair.Plan == nil || pair.Rollback == nil {
		return Frozen{}, errors.New("a frozen pair holds two documents")
	}
	return freeze(pair.Plan, pair.Rollback)
}

// Validate holds a web service plan against the whole contract of the palier.
//
// The image is checked for equality against the pin of the declared profile
// rather than against a policy: a plan naming another registry, another
// repository or another digest is not a narrower or a wider plan, it is one this
// palier does not build and does not recognise.
func (document WebServiceDocument) Validate() error {
	if err := validateV2Head(document.SchemaVersion, document.InfrastructureID,
		document.MachineID, document.Operation, groupWebService); err != nil {
		return err
	}
	image, known := profileImage[document.ServiceProfile]
	if !known {
		return fmt.Errorf("plan service_profile %q is not one this palier describes", document.ServiceProfile)
	}
	if err := validatePinnedImage(document.ImageReference, document.ImageDigest, image); err != nil {
		return err
	}
	if document.LocalPort < MinLocalPort || document.LocalPort > MaxLocalPort {
		return fmt.Errorf("plan local_port must be within %d..%d", MinLocalPort, MaxLocalPort)
	}
	return nil
}

// Validate holds an entrypoint plan against the whole contract of the palier.
func (document EntrypointDocument) Validate() error {
	if err := validateV2Head(document.SchemaVersion, document.InfrastructureID,
		document.MachineID, document.Operation, groupEntrypoint); err != nil {
		return err
	}
	return validatePinnedImage(document.ImageReference, document.ImageDigest, entrypointImage)
}

// Validate holds a route plan against the whole contract of the palier.
func (document RouteDocument) Validate() error {
	if err := validateV2Head(document.SchemaVersion, document.InfrastructureID,
		document.MachineID, document.Operation, groupRoute); err != nil {
		return err
	}
	if err := validateRouteHost(document.RouteHost); err != nil {
		return err
	}
	if document.BackendPort < MinBackendPort || document.BackendPort > MaxBackendPort {
		return fmt.Errorf("plan backend_port must be within %d..%d", MinBackendPort, MaxBackendPort)
	}
	return nil
}

// Transcript rebuilds the exact bytes a web service plan digest is taken over,
// in the layout documented at the head of this file.
func (document WebServiceDocument) Transcript() ([]byte, error) {
	if err := document.Validate(); err != nil {
		return nil, err
	}
	image, err := decodeOCIDigest(document.ImageDigest)
	if err != nil {
		return nil, err
	}
	transcript := appendV2Head(document.SchemaVersion, document.InfrastructureID,
		document.MachineID, document.Operation)
	transcript = appendField(transcript, []byte(document.ServiceProfile))
	transcript = appendField(transcript, []byte(document.ImageReference))
	transcript = appendField(transcript, image)
	return appendUint32(transcript, uint32(document.LocalPort)), nil
}

// Transcript rebuilds the exact bytes an entrypoint plan digest is taken over.
func (document EntrypointDocument) Transcript() ([]byte, error) {
	if err := document.Validate(); err != nil {
		return nil, err
	}
	image, err := decodeOCIDigest(document.ImageDigest)
	if err != nil {
		return nil, err
	}
	transcript := appendV2Head(document.SchemaVersion, document.InfrastructureID,
		document.MachineID, document.Operation)
	transcript = appendField(transcript, []byte(document.ImageReference))
	return appendField(transcript, image), nil
}

// Transcript rebuilds the exact bytes a route plan digest is taken over.
func (document RouteDocument) Transcript() ([]byte, error) {
	if err := document.Validate(); err != nil {
		return nil, err
	}
	transcript := appendV2Head(document.SchemaVersion, document.InfrastructureID,
		document.MachineID, document.Operation)
	transcript = appendField(transcript, []byte(document.RouteHost))
	return appendUint32(transcript, uint32(document.BackendPort)), nil
}

func (document WebServiceDocument) Encode() ([]byte, error) { return encodeV2(document) }
func (document EntrypointDocument) Encode() ([]byte, error) { return encodeV2(document) }
func (document RouteDocument) Encode() ([]byte, error)      { return encodeV2(document) }

func (document WebServiceDocument) SHA256() (string, error) { return digestOf(document) }
func (document EntrypointDocument) SHA256() (string, error) { return digestOf(document) }
func (document RouteDocument) SHA256() (string, error)      { return digestOf(document) }

func (document WebServiceDocument) OperationName() string { return document.Operation }
func (document EntrypointDocument) OperationName() string { return document.Operation }
func (document RouteDocument) OperationName() string      { return document.Operation }

func (document WebServiceDocument) Target() Target {
	return Target{InfrastructureID: document.InfrastructureID, MachineID: document.MachineID}
}

func (document EntrypointDocument) Target() Target {
	return Target{InfrastructureID: document.InfrastructureID, MachineID: document.MachineID}
}

func (document RouteDocument) Target() Target {
	return Target{InfrastructureID: document.InfrastructureID, MachineID: document.MachineID}
}

func (document WebServiceDocument) IsExactInverseOf(other V2Document) bool {
	return isExactInverseV2(document, other)
}

func (document EntrypointDocument) IsExactInverseOf(other V2Document) bool {
	return isExactInverseV2(document, other)
}

func (document RouteDocument) IsExactInverseOf(other V2Document) bool {
	return isExactInverseV2(document, other)
}

func (document WebServiceDocument) inverse() (V2Document, bool) {
	inverted, known := inverseOperationV2[document.Operation]
	if !known {
		return nil, false
	}
	document.Operation = inverted
	return document, true
}

func (document EntrypointDocument) inverse() (V2Document, bool) {
	inverted, known := inverseOperationV2[document.Operation]
	if !known {
		return nil, false
	}
	document.Operation = inverted
	return document, true
}

func (document RouteDocument) inverse() (V2Document, bool) {
	inverted, known := inverseOperationV2[document.Operation]
	if !known {
		return nil, false
	}
	document.Operation = inverted
	return document, true
}

// isExactInverseV2 is what a machine asks before acting: the document it was
// handed as an undoing has to be one it could apply to return to the state it is
// about to leave.
//
// The two documents are compared whole, so a rollback naming another machine,
// another port, another profile or another operation group is a second plan
// rather than an undoing, and is refused as one.
func isExactInverseV2(document, other V2Document) bool {
	if document == nil || other == nil {
		return false
	}
	expected, known := other.inverse()
	if !known {
		return false
	}
	return document == expected
}

// validateV2Head holds the four fields every schema 2 document carries, and
// refuses an operation that does not belong to the shape it was decoded into.
//
// The last check is what makes the discriminator binding in both directions: a
// document whose operation belongs to another group is refused even when a
// caller built the value in Go rather than decoding it.
func validateV2Head(schemaVersion int, infrastructureID, machineID, operation string, group operationGroup) error {
	if schemaVersion != SchemaVersionV2 {
		return errors.New("plan schema version is unsupported")
	}
	if !canonicalUUIDv4.MatchString(infrastructureID) {
		return errors.New("plan infrastructure_id must be a canonical lower-case UUIDv4")
	}
	if !canonicalMachine.MatchString(machineID) {
		return errors.New("plan machine_id is malformed")
	}
	if operationGroups[operation] != group {
		return fmt.Errorf("plan operation %q does not carry the fields this document holds", operation)
	}
	return nil
}

// validatePinnedImage requires the exact couple the contract pins.
//
// The shape of the digest is required before the pin so that the transcript may
// rely on decoding exactly 32 bytes out of the field, and so that a malformed
// digest and an unpinned one remain two distinct refusals.
func validatePinnedImage(reference, digest string, pinned pinnedImage) error {
	if reference != pinned.reference {
		return errors.New("plan image_reference is not the pinned image of this palier")
	}
	if !canonicalOCIDigest.MatchString(digest) {
		return errMalformedImageDigest
	}
	if digest != pinned.digest {
		return errors.New("plan image_digest is not the pinned image of this palier")
	}
	return nil
}

// validateRouteHost bounds the one name a route serves.
//
// The closed character set is what removes the wildcard, the upper-case
// spelling and every separator a host name has no business carrying; the two
// checks around it remove the empty label and the name that opens or closes on a
// separator. A host outside these bounds never reaches a fragment of the
// entrypoint, so the entrypoint never has to decide what such a name means.
func validateRouteHost(host string) error {
	if !canonicalRouteHost.MatchString(host) {
		return fmt.Errorf(
			"plan route_host must be %d..%d lower-case letters, digits, hyphens and dots opening and closing on a letter or a digit",
			MinRouteHostBytes, MaxRouteHostBytes,
		)
	}
	if strings.Contains(host, "..") {
		return errors.New("plan route_host must not carry an empty label")
	}
	return nil
}

// encodeV2 renders the one canonical encoding of a schema 2 document.
//
// A transport may reindent or reorder what it carries without changing the plan
// — the digest is rebuilt from the fields, not from the bytes — but the
// Controller emits exactly one spelling, so that the document a human is shown,
// the document an Auxiliary receives and the document a digest was taken over
// are the same bytes rather than three encodings that happen to agree.
func encodeV2(document V2Document) ([]byte, error) {
	if err := document.Validate(); err != nil {
		return nil, err
	}
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

func appendV2Head(schemaVersion int, infrastructureID, machineID, operation string) []byte {
	transcript := make([]byte, 0, len(TranscriptDomainV2)+192)
	transcript = append(transcript, TranscriptDomainV2...)
	transcript = append(transcript, byte(schemaVersion))
	transcript = appendField(transcript, []byte(infrastructureID))
	transcript = appendField(transcript, []byte(machineID))
	return appendField(transcript, []byte(operation))
}

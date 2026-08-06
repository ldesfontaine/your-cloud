package plan

import (
	"encoding/base64"
	"errors"
	"fmt"
)

// Schema 3 keeps every procedure of the two schemas before it — one bounded
// strict JSON document, one domain-separated binary transcript, a rollback that
// is a complete inverse document, a pair frozen by the Controller — and adds the
// six operations of the private passage. Neither older schema is reopened by any
// of it: a probe plan and a public profile plan decode, hash and freeze exactly
// as before, and a document of any one schema is refused by the decoders of the
// other two.
//
// The transcript is laid out per operation group, as in schema 2. The fields a
// group does not have are simply not present rather than written empty, and the
// operation string inside the transcript is what tells the groups apart:
//
//	domaine  "your-cloud/oci-plan.v3\0"
//	puis     schema_version   sur 1 octet
//	         infrastructure_id, machine_id, operation
//	                                     en champs préfixés par longueur uint32
//	puis, selon l'opération :
//	  prepare_link / withdraw_link
//	         link_role                         en champ préfixé
//	  attach_link_peer / detach_link_peer
//	         peer_public_key (32 octets décodés) en champ préfixé
//	         service_port                      en uint32 big-endian
//	  join_link_peer / leave_link_peer
//	         peer_public_key (32 octets décodés) en champ préfixé
//	         peer_endpoint_host                en champ préfixé
//	         service_port                      en uint32 big-endian
//
// The public key travels decoded, exactly as an image digest does in the two
// older schemas: the textual field is one spelling of thirty-two bytes, and the
// bytes are what the digest is taken over. That is also why the field's
// canonicity is required before the transcript is built — a key with a second
// accepted spelling would be a key with two digests.
//
// The layout is unambiguous across the three groups without a group tag, for the
// same reason it is in schema 2: everything before the operation is at a
// determined offset, so a reader that has consumed the operation knows which of
// the three tails it is looking at.
const (
	// SchemaVersionV3 is the third plan version, and the only one that describes
	// the private passage between two enrolled machines.
	SchemaVersionV3 = 3

	// TranscriptDomainV3 separates a schema 3 digest from the digests of the two
	// older schemas and from every other transcript of the product. Its
	// terminating NUL cannot appear in any textual field, so no prefix of one
	// transcript is a prefix of another.
	TranscriptDomainV3 = "your-cloud/oci-plan.v3\x00"

	// OperationPrepareLink asks for this machine to hold the closed interface of
	// the passage in one role — its keys generated on it and never leaving it —
	// and OperationWithdrawLink for that interface and those keys to be gone.
	// Neither carries a peer: preparing is what a machine does alone.
	OperationPrepareLink  = "prepare_link"
	OperationWithdrawLink = "withdraw_link"

	// OperationAttachLinkPeer asks the listener to hold exactly one peer and the
	// bounds that peer's traffic is allowed inside, and OperationDetachLinkPeer
	// for that peer and those bounds to be gone. The listener has no endpoint to
	// reach: the initiator is the side that goes out, so the field does not exist
	// here rather than travelling empty.
	OperationAttachLinkPeer = "attach_link_peer"
	OperationDetachLinkPeer = "detach_link_peer"

	// OperationJoinLinkPeer asks the initiator to reach exactly one endpoint and
	// hold the same bounds from its own side, and OperationLeaveLinkPeer for the
	// junction to be gone. The endpoint host is a field because only the
	// initiator has one; the endpoint port is not, because it is the listening
	// port of the contract.
	OperationJoinLinkPeer  = "join_link_peer"
	OperationLeaveLinkPeer = "leave_link_peer"

	// LinkRoleListener is the side that listens on the port of the contract, and
	// LinkRoleInitiator the side that goes out and keeps the tunnel alive. The
	// list is closed to these two: the role decides the constants of the
	// scenario, and no field of a plan reopens any of them.
	LinkRoleListener  = "listener"
	LinkRoleInitiator = "initiator"

	// PeerPublicKeyBytes is what a peer public key decodes to, and
	// PeerPublicKeyChars the one length its canonical standard base64 spelling
	// has. Both are required, so a value that decodes to the right bytes through
	// another spelling is refused rather than accepted twice.
	PeerPublicKeyBytes = 32
	PeerPublicKeyChars = 44

	// MinServicePort and MaxServicePort repeat the loopback range of the two
	// older schemas, because the one port a passage carries may only be a port a
	// managed service of the joined machine could be listening on.
	MinServicePort = MinLocalPort
	MaxServicePort = MaxLocalPort
)

// linkOperationGroup is which of the three closed field lists a schema 3
// operation carries. It is its own type rather than a continuation of schema 2's
// so that no operation of one schema can ever name a group of the other.
type linkOperationGroup int

const (
	groupLink linkOperationGroup = iota + 1
	groupListenerPeer
	groupInitiatorPeer
)

var (
	// inverseOperationV3 is at once the closed list of operations schema 3
	// describes and the operation that undoes each of them. Holding both in one
	// declaration is what makes an operation without an undoing impossible to add
	// here by accident.
	inverseOperationV3 = map[string]string{
		OperationPrepareLink:    OperationWithdrawLink,
		OperationWithdrawLink:   OperationPrepareLink,
		OperationAttachLinkPeer: OperationDetachLinkPeer,
		OperationDetachLinkPeer: OperationAttachLinkPeer,
		OperationJoinLinkPeer:   OperationLeaveLinkPeer,
		OperationLeaveLinkPeer:  OperationJoinLinkPeer,
	}

	// linkOperationGroups says which closed field list each operation carries. It
	// is the whole of the discriminator: an operation absent from this table has
	// no document shape, and is refused before any field of the document is read.
	linkOperationGroups = map[string]linkOperationGroup{
		OperationPrepareLink:    groupLink,
		OperationWithdrawLink:   groupLink,
		OperationAttachLinkPeer: groupListenerPeer,
		OperationDetachLinkPeer: groupListenerPeer,
		OperationJoinLinkPeer:   groupInitiatorPeer,
		OperationLeaveLinkPeer:  groupInitiatorPeer,
	}

	// linkRoles is the closed list of roles a link plan may name. A role outside
	// it is refused before the rest of the document counts, because the role is
	// what decides every constant the plan does not state.
	linkRoles = map[string]struct{}{
		LinkRoleListener:  {},
		LinkRoleInitiator: {},
	}

	errMalformedPeerPublicKey = fmt.Errorf(
		"plan peer_public_key must be canonical standard base64 of %d characters decoding to exactly %d bytes",
		PeerPublicKeyChars, PeerPublicKeyBytes)
)

// V3Document is one plan of schema 3, whatever its operation group.
//
// The interface is closed to the three shapes declared below: its unexported
// method cannot be implemented outside this package, so a fourth field list is a
// decision taken here — beside the transcript it would need and beside the
// inverse it must have — rather than a type another package could hand to a
// Controller.
type V3Document interface {
	// Validate holds the document against the whole contract of the palier, the
	// closed role list and the canonicity of the peer key included.
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
	IsExactInverseOf(other V3Document) bool

	inverse() (V3Document, bool)
}

// LinkDocument is the plan of one machine's own side of the passage: the closed
// interface and the keys that never leave it, in exactly one role.
//
// It names no peer. Preparing is what a machine does alone, and a field for the
// other machine here would be an approvable value that decides nothing until a
// junction plan names it.
//
// The declaration order below is the canonical encoding order and the transcript
// order at once, and no field of a link plan lives outside it.
type LinkDocument struct {
	SchemaVersion    int    `json:"schema_version"`
	InfrastructureID string `json:"infrastructure_id"`
	MachineID        string `json:"machine_id"`
	Operation        string `json:"operation"`
	LinkRole         string `json:"link_role"`
}

// ListenerPeerDocument is the plan of the listener's junction: exactly one peer,
// named by the public key that peer's own preparation reported, and the one port
// the passage will carry.
//
// It carries no endpoint. The listener does not go out, so an endpoint field
// here would be a value nothing reads — and a field of the other group is an
// unknown field, refused before its value is read.
type ListenerPeerDocument struct {
	SchemaVersion    int    `json:"schema_version"`
	InfrastructureID string `json:"infrastructure_id"`
	MachineID        string `json:"machine_id"`
	Operation        string `json:"operation"`
	PeerPublicKey    string `json:"peer_public_key"`
	ServicePort      int    `json:"service_port"`
}

// InitiatorPeerDocument is the plan of the initiator's junction: the same peer
// key and the same port, plus the one host it reaches to establish the tunnel.
//
// The endpoint port is deliberately absent: it is the listening port of the
// contract, a constant the role decides, and a field for it would be an
// approvable value that may only hold one value.
type InitiatorPeerDocument struct {
	SchemaVersion    int    `json:"schema_version"`
	InfrastructureID string `json:"infrastructure_id"`
	MachineID        string `json:"machine_id"`
	Operation        string `json:"operation"`
	PeerPublicKey    string `json:"peer_public_key"`
	PeerEndpointHost string `json:"peer_endpoint_host"`
	ServicePort      int    `json:"service_port"`
}

// V3Pair is one schema 3 plan and the complete document that undoes it.
//
// The rollback is a plan in its own right, read, displayed, approved and
// verified like any other: withdraw_link for prepare_link, detach_link_peer for
// attach_link_peer, leave_link_peer for join_link_peer.
type V3Pair struct {
	Plan     V3Document
	Rollback V3Document
}

// DecodeV3 accepts one bounded, strict, fully validated schema 3 document.
//
// It never returns a partially checked plan: a caller that holds one may assume
// every field is inside the bounds of the contract, and that the fields it holds
// are exactly the ones its operation declares — no more, and none borrowed from
// another operation or from another schema.
func DecodeV3(document []byte) (V3Document, error) {
	if len(document) == 0 || len(document) > MaxPlanBytes {
		return nil, fmt.Errorf("plan document must contain 1..%d bytes", MaxPlanBytes)
	}
	// The discriminator pre-pass is the very one schema 2 uses, because the
	// question it answers is the same one: which closed field list this document
	// will be held against, read in the document rather than guessed by trying
	// each shape in turn.
	operation, err := declaredOperation(document)
	if err != nil {
		return nil, err
	}
	var parsed V3Document
	switch linkOperationGroups[operation] {
	case groupLink:
		var shape LinkDocument
		if err := strictDecodePlan(document, &shape); err != nil {
			return nil, err
		}
		parsed = shape
	case groupListenerPeer:
		var shape ListenerPeerDocument
		if err := strictDecodePlan(document, &shape); err != nil {
			return nil, err
		}
		parsed = shape
	case groupInitiatorPeer:
		var shape InitiatorPeerDocument
		if err := strictDecodePlan(document, &shape); err != nil {
			return nil, err
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

// BuildLinkPair freezes one machine's own side of the passage together with its
// withdrawal. The caller chooses the role and nothing else: everything the role
// decides is a constant of the contract.
func BuildLinkPair(operation, infrastructureID, machineID, linkRole string) (V3Pair, error) {
	return buildV3Pair(LinkDocument{
		SchemaVersion:    SchemaVersionV3,
		InfrastructureID: infrastructureID,
		MachineID:        machineID,
		Operation:        operation,
		LinkRole:         linkRole,
	})
}

// BuildListenerPeerPair freezes the listener's junction together with its
// detachment.
//
// The peer key is an observation the other machine's preparation reported: the
// Controller carries it, the human reads it in the plan, and this package holds
// it against exactly the canonicity the document validation requires — so a key
// that could not appear in a plan cannot be built into one either.
func BuildListenerPeerPair(operation, infrastructureID, machineID, peerPublicKey string, servicePort int) (V3Pair, error) {
	return buildV3Pair(ListenerPeerDocument{
		SchemaVersion:    SchemaVersionV3,
		InfrastructureID: infrastructureID,
		MachineID:        machineID,
		Operation:        operation,
		PeerPublicKey:    peerPublicKey,
		ServicePort:      servicePort,
	})
}

// BuildInitiatorPeerPair freezes the initiator's junction together with its
// departure, under the same rule for the peer key and for the endpoint host.
func BuildInitiatorPeerPair(operation, infrastructureID, machineID, peerPublicKey, peerEndpointHost string, servicePort int) (V3Pair, error) {
	return buildV3Pair(InitiatorPeerDocument{
		SchemaVersion:    SchemaVersionV3,
		InfrastructureID: infrastructureID,
		MachineID:        machineID,
		Operation:        operation,
		PeerPublicKey:    peerPublicKey,
		PeerEndpointHost: peerEndpointHost,
		ServicePort:      servicePort,
	})
}

// buildV3Pair holds both directions against the contract before either exists.
//
// The two documents differ by their operation and by nothing else, and a caller
// cannot ask for a rollback that targets another peer, another endpoint or
// another port because it never supplies one.
func buildV3Pair(subject V3Document) (V3Pair, error) {
	if err := subject.Validate(); err != nil {
		return V3Pair{}, err
	}
	rollback, known := subject.inverse()
	if !known {
		// Unreachable while Validate refuses every operation outside the closed
		// table, and kept as a refusal so that a disagreement between the two
		// declarations builds nothing rather than something.
		return V3Pair{}, fmt.Errorf("plan operation %q is not one this palier builds", subject.OperationName())
	}
	if err := rollback.Validate(); err != nil {
		return V3Pair{}, err
	}
	return V3Pair{Plan: subject, Rollback: rollback}, nil
}

// Freeze renders a pair once and keeps the documents and their digests together,
// so that no caller can transport one document beside the digest of another.
func (pair V3Pair) Freeze() (Frozen, error) {
	if pair.Plan == nil || pair.Rollback == nil {
		return Frozen{}, errors.New("a frozen pair holds two documents")
	}
	return freeze(pair.Plan, pair.Rollback)
}

// Validate holds a link plan against the whole contract of the palier.
func (document LinkDocument) Validate() error {
	if err := validateV3Head(document.SchemaVersion, document.InfrastructureID,
		document.MachineID, document.Operation, groupLink); err != nil {
		return err
	}
	if _, known := linkRoles[document.LinkRole]; !known {
		return fmt.Errorf("plan link_role %q is not one this palier describes", document.LinkRole)
	}
	return nil
}

// Validate holds a listener junction plan against the whole contract of the
// palier.
func (document ListenerPeerDocument) Validate() error {
	if err := validateV3Head(document.SchemaVersion, document.InfrastructureID,
		document.MachineID, document.Operation, groupListenerPeer); err != nil {
		return err
	}
	if _, err := decodePeerPublicKey(document.PeerPublicKey); err != nil {
		return err
	}
	return validateServicePort(document.ServicePort)
}

// Validate holds an initiator junction plan against the whole contract of the
// palier.
func (document InitiatorPeerDocument) Validate() error {
	if err := validateV3Head(document.SchemaVersion, document.InfrastructureID,
		document.MachineID, document.Operation, groupInitiatorPeer); err != nil {
		return err
	}
	if _, err := decodePeerPublicKey(document.PeerPublicKey); err != nil {
		return err
	}
	if err := validateHostBound("peer_endpoint_host", document.PeerEndpointHost); err != nil {
		return err
	}
	return validateServicePort(document.ServicePort)
}

// Transcript rebuilds the exact bytes a link plan digest is taken over, in the
// layout documented at the head of this file.
func (document LinkDocument) Transcript() ([]byte, error) {
	if err := document.Validate(); err != nil {
		return nil, err
	}
	transcript := appendV3Head(document.SchemaVersion, document.InfrastructureID,
		document.MachineID, document.Operation)
	return appendField(transcript, []byte(document.LinkRole)), nil
}

// Transcript rebuilds the exact bytes a listener junction digest is taken over.
func (document ListenerPeerDocument) Transcript() ([]byte, error) {
	if err := document.Validate(); err != nil {
		return nil, err
	}
	key, err := decodePeerPublicKey(document.PeerPublicKey)
	if err != nil {
		return nil, err
	}
	transcript := appendV3Head(document.SchemaVersion, document.InfrastructureID,
		document.MachineID, document.Operation)
	transcript = appendField(transcript, key)
	return appendUint32(transcript, uint32(document.ServicePort)), nil
}

// Transcript rebuilds the exact bytes an initiator junction digest is taken
// over.
func (document InitiatorPeerDocument) Transcript() ([]byte, error) {
	if err := document.Validate(); err != nil {
		return nil, err
	}
	key, err := decodePeerPublicKey(document.PeerPublicKey)
	if err != nil {
		return nil, err
	}
	transcript := appendV3Head(document.SchemaVersion, document.InfrastructureID,
		document.MachineID, document.Operation)
	transcript = appendField(transcript, key)
	transcript = appendField(transcript, []byte(document.PeerEndpointHost))
	return appendUint32(transcript, uint32(document.ServicePort)), nil
}

func (document LinkDocument) Encode() ([]byte, error)          { return encodeV3(document) }
func (document ListenerPeerDocument) Encode() ([]byte, error)  { return encodeV3(document) }
func (document InitiatorPeerDocument) Encode() ([]byte, error) { return encodeV3(document) }

func (document LinkDocument) SHA256() (string, error)          { return digestOf(document) }
func (document ListenerPeerDocument) SHA256() (string, error)  { return digestOf(document) }
func (document InitiatorPeerDocument) SHA256() (string, error) { return digestOf(document) }

func (document LinkDocument) OperationName() string          { return document.Operation }
func (document ListenerPeerDocument) OperationName() string  { return document.Operation }
func (document InitiatorPeerDocument) OperationName() string { return document.Operation }

func (document LinkDocument) Target() Target {
	return Target{InfrastructureID: document.InfrastructureID, MachineID: document.MachineID}
}

func (document ListenerPeerDocument) Target() Target {
	return Target{InfrastructureID: document.InfrastructureID, MachineID: document.MachineID}
}

func (document InitiatorPeerDocument) Target() Target {
	return Target{InfrastructureID: document.InfrastructureID, MachineID: document.MachineID}
}

func (document LinkDocument) IsExactInverseOf(other V3Document) bool {
	return isExactInverseV3(document, other)
}

func (document ListenerPeerDocument) IsExactInverseOf(other V3Document) bool {
	return isExactInverseV3(document, other)
}

func (document InitiatorPeerDocument) IsExactInverseOf(other V3Document) bool {
	return isExactInverseV3(document, other)
}

func (document LinkDocument) inverse() (V3Document, bool) {
	inverted, known := inverseOperationV3[document.Operation]
	if !known {
		return nil, false
	}
	document.Operation = inverted
	return document, true
}

func (document ListenerPeerDocument) inverse() (V3Document, bool) {
	inverted, known := inverseOperationV3[document.Operation]
	if !known {
		return nil, false
	}
	document.Operation = inverted
	return document, true
}

func (document InitiatorPeerDocument) inverse() (V3Document, bool) {
	inverted, known := inverseOperationV3[document.Operation]
	if !known {
		return nil, false
	}
	document.Operation = inverted
	return document, true
}

// isExactInverseV3 is what a machine asks before acting: the document it was
// handed as an undoing has to be one it could apply to return to the state it is
// about to leave.
//
// The two documents are compared whole, so a rollback naming another machine,
// another peer, another endpoint, another port or another operation group is a
// second plan rather than an undoing, and is refused as one.
func isExactInverseV3(document, other V3Document) bool {
	if document == nil || other == nil {
		return false
	}
	expected, known := other.inverse()
	if !known {
		return false
	}
	return document == expected
}

// validateV3Head holds the four fields every schema 3 document carries, and
// refuses an operation that does not belong to the shape it was decoded into.
//
// The last check is what makes the discriminator binding in both directions: a
// document whose operation belongs to another group — or to another schema — is
// refused even when a caller built the value in Go rather than decoding it.
func validateV3Head(schemaVersion int, infrastructureID, machineID, operation string, group linkOperationGroup) error {
	if schemaVersion != SchemaVersionV3 {
		return errors.New("plan schema version is unsupported")
	}
	if !canonicalUUIDv4.MatchString(infrastructureID) {
		return errors.New("plan infrastructure_id must be a canonical lower-case UUIDv4")
	}
	if !canonicalMachine.MatchString(machineID) {
		return errors.New("plan machine_id is malformed")
	}
	if linkOperationGroups[operation] != group {
		return fmt.Errorf("plan operation %q does not carry the fields this document holds", operation)
	}
	return nil
}

func validateServicePort(port int) error {
	if port < MinServicePort || port > MaxServicePort {
		return fmt.Errorf("plan service_port must be within %d..%d", MinServicePort, MaxServicePort)
	}
	return nil
}

// decodePeerPublicKey turns the textual field into the thirty-two bytes the
// transcript carries, and refuses every other spelling of the same key.
//
// The three requirements are held together on purpose. The length removes the
// shorter and longer strings a decoder might otherwise accept; the decoding
// removes the alphabets and the paddings that are not this one; and the
// re-encoding removes what remains — the trailing bits a peer key has no room
// for, which decode without complaint and would give the same key a second
// spelling and therefore a second digest.
func decodePeerPublicKey(value string) ([]byte, error) {
	if len(value) != PeerPublicKeyChars {
		return nil, errMalformedPeerPublicKey
	}
	decoded, err := base64.StdEncoding.DecodeString(value)
	if err != nil || len(decoded) != PeerPublicKeyBytes {
		return nil, errMalformedPeerPublicKey
	}
	if base64.StdEncoding.EncodeToString(decoded) != value {
		return nil, errMalformedPeerPublicKey
	}
	return decoded, nil
}

// encodeV3 renders the one canonical encoding of a schema 3 document.
//
// A transport may reindent or reorder what it carries without changing the plan
// — the digest is rebuilt from the fields, not from the bytes — but the
// Controller emits exactly one spelling, so that the document a human is shown,
// the document an Auxiliary receives and the document a digest was taken over
// are the same bytes rather than three encodings that happen to agree.
func encodeV3(document V3Document) ([]byte, error) {
	if err := document.Validate(); err != nil {
		return nil, err
	}
	return encodeCanonicalPlan(document)
}

func appendV3Head(schemaVersion int, infrastructureID, machineID, operation string) []byte {
	transcript := make([]byte, 0, len(TranscriptDomainV3)+192)
	transcript = append(transcript, TranscriptDomainV3...)
	transcript = append(transcript, byte(schemaVersion))
	transcript = appendField(transcript, []byte(infrastructureID))
	transcript = appendField(transcript, []byte(machineID))
	return appendField(transcript, []byte(operation))
}

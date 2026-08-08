package plan

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/ldesfontaine/your-cloud/internal/servicedefinition"
	"github.com/ldesfontaine/your-cloud/internal/strictjson"
)

// Schema 2 keeps every procedure of schema 1 — one bounded strict JSON
// document, one domain-separated binary transcript, a rollback that is a
// complete inverse document, a pair frozen by the Controller — and describes the
// operations of the public profile, of the private one and of the third door,
// where a service is described by a definition its user wrote rather than by a
// profile the product pins. Schema 1 is not reopened by any of it: a probe plan
// decodes, hashes and freezes exactly as before, and a document of either schema
// is refused by the decoder of the other.
//
// The third door is why this file reads the definition package, and it reads it
// in one direction only: a plan names a definition by its slug and its digest, so
// the grammar of those two values is stated where the definition owns it rather
// than spelled a second time here. Nothing of the definition package knows this
// one, and nothing here reads a definition's content — a plan pins bytes it never
// opens, and holding a plan against the document it pins is one named function
// with the definition passed to it.
//
// The transcript is laid out per operation group. The fields a group does not
// have are simply not present rather than written empty — a field one group's own
// documents may or may not carry is a different matter, stated below — and the
// operation string inside the transcript is what tells the groups apart:
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
//	  deploy_private_service / remove_private_service
//	         service_profile, image_reference  en champs préfixés
//	         image_digest (32 octets décodés)  en champ préfixé
//	         local_port                        en uint32 big-endian
//	         origin_host                       en champ préfixé
//	  publish_link_route / retire_link_route
//	         route_host                        en champ préfixé
//	         backend_port                      en uint32 big-endian
//	  snapshot_service / discard_snapshot
//	         service_profile, snapshot_slot    en champs préfixés
//	  restore_service
//	         service_profile, snapshot_slot    en champs préfixés
//	  deploy_user_service / remove_user_service
//	         definition_slug                   en champ préfixé
//	         definition_digest                 en champ préfixé (32 octets décodés)
//	         image_reference                   en champ préfixé
//	         image_digest                      en champ préfixé (32 octets décodés)
//	         local_port                        en uint32 big-endian
//	         origin_host                       en champ préfixé, vide s'il est absent
//
// The layout is unambiguous across the groups without a group tag, because
// everything before the operation is at a determined offset: the domain and the
// version are fixed, and each of the two fields that follow announces its own
// length. A reader that has consumed the operation therefore knows which of the
// tails it is looking at, so no two documents of different groups can produce the
// same bytes.
//
// Three pairs of groups carry the same tail shape — a route and a link route
// name a host and a port, a snapshot and a restore name a profile and a slot —
// and they are still six distinct digests, because the operation string is inside
// the hashed bytes at a determined offset. That is exactly what the operation is
// there for: two documents that describe different states never hash the same,
// even when the values they carry are spelled identically. A test pins that
// property at the level of the vectors rather than leaving it to be read here.
//
// The user service group is the one group carrying a field that is present on
// some of its documents and absent on others, and the layout writes it anyway:
// origin_host is always a length-prefixed field, of length zero when the
// definition does not interpolate the origin. Writing it always is what keeps the
// tail unambiguous — a field the reader may or may not find would make the end of
// the transcript depend on a rule the bytes do not carry — and it is the decision
// the definition's own lists already took, where an empty list is written as a
// count of zero rather than left out. The empty spelling is unmistakable because
// no origin the contract accepts is the empty string: a plan carrying no origin
// and a plan carrying an origin are two lengths and two digests, never two
// readings of the same bytes. The canonical JSON follows the same rule and always
// renders the field, so a document that omitted it and one that spelled it empty
// are one plan with one digest and one canonical spelling — exactly as a
// definition that left a list out and one that declared it empty are one
// definition.
//
// definition_digest travels as its 32 decoded bytes in a length-prefixed field,
// as image_digest does. It is the digest of the frozen definition the plan pins,
// taken over the definition's own transcript under its own domain, so nothing of
// the two documents' bounds can ever be read through the other's.
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

	// OperationDeployPrivateService asks for one managed service whose data
	// outlives its container to be present on exactly one machine, at exactly one
	// loopback port and under exactly one origin, and
	// OperationRemovePrivateService for that exact instance to be absent.
	//
	// It is a second door rather than a widening of the first. A profile whose
	// data survives the container carries a persistent volume, a closed
	// environment and an egress table that the stateless sheet does not have and
	// must never grow, so the two lists of profiles are closed against one
	// another in both directions.
	OperationDeployPrivateService = "deploy_private_service"
	OperationRemovePrivateService = "remove_private_service"

	// OperationPublishLinkRoute asks for one declared name to reach one managed
	// service through the entrypoint and the private passage, and
	// OperationRetireLinkRoute for that name to stop being served.
	//
	// It carries the fields of publish_route and describes another state: the
	// backend of a link route is the constant peer of the tunnel rather than this
	// machine's own loopback, and its presence rule is a junction the passage
	// bounds. The two operations are therefore never interchangeable, and their
	// digests differ because the operation is inside the hashed bytes.
	OperationPublishLinkRoute = "publish_link_route"
	OperationRetireLinkRoute  = "retire_link_route"

	// OperationSnapshotService asks for the data of one private service to be
	// archived under exactly one named slot, and OperationDiscardSnapshot for
	// that archive to be gone. A snapshot stops and restarts the service, so it
	// mutates the machine as much as a deployment does.
	OperationSnapshotService = "snapshot_service"
	OperationDiscardSnapshot = "discard_snapshot"

	// OperationRestoreService asks for the data of one private service to become
	// what one named slot holds. It is the one operation of this schema whose
	// undoing is itself: the flow writes the current state into the reserved slot
	// before replacing anything, so the document that returns is a restore naming
	// that reserved slot.
	OperationRestoreService = "restore_service"

	// OperationDeployUserService asks for one service described by a definition
	// its user wrote to be present on exactly one machine, at exactly one loopback
	// port, and OperationRemoveUserService for that exact instance to be absent.
	//
	// It is a third door rather than a widening of the second, for the reason the
	// second was not a widening of the first: nothing about this service is a
	// constant of the product. The account, the home, the volumes, the environment
	// and the secret names are derived from a definition the Controller froze and
	// the plan pins by digest, so the two documents name a definition where the
	// other doors name a profile — and neither list of profiles can ever answer to
	// a definition's slug, because those slugs are reserved against exactly the
	// four names the product already owns.
	OperationDeployUserService = "deploy_user_service"
	OperationRemoveUserService = "remove_user_service"

	// ServiceProfileBentoPDF is the one profile of the stateless door. The
	// profile decides everything the plan does not state — account, unit file,
	// isolation headers — so an unknown profile is refused before the rest of the
	// document is read.
	ServiceProfileBentoPDF = "bentopdf"

	// ServiceProfileVaultwarden is the one profile of the private door: the first
	// profile of the product whose data outlives its container. It decides its
	// persistent volume, its closed environment lines and its egress table, none
	// of which any field of a plan can name or move.
	ServiceProfileVaultwarden = "vaultwarden"

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

	// VaultwardenImageReference and VaultwardenImageDigest pin the one image the
	// vaultwarden profile may name, under the same rule again. The digest is the
	// manifest list of the contract: it resolves to one image per architecture,
	// which is what lets a later proof change machine without changing profile,
	// and it is compared for equality rather than parsed into a policy.
	VaultwardenImageReference = "docker.io/vaultwarden/server"
	VaultwardenImageDigest    = "sha256:ebdfe70701c60ac0c28c697e787cea767d7972940b786037b29fe0d507f821e8"

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

	// MinSnapshotSlotBytes and MaxSnapshotSlotBytes bound the label one archive
	// is named by. The slot is the only part of an archive's path a human
	// chooses, so it is bounded to what a single directory entry can be: no
	// separator, no dot, no upper case, nothing that could climb out of the
	// directory the profile owns.
	MinSnapshotSlotBytes = 1
	MaxSnapshotSlotBytes = 32

	// ReservedSnapshotSlot belongs to the return mechanism and to nothing else.
	//
	// A snapshot may not write it and a discard may not destroy it: it holds the
	// state a restore was about to replace, and it is the one slot the Auxiliary
	// itself is allowed to overwrite. It appears in exactly one document of the
	// product — the signed rollback of a restore, built below — and no forward
	// plan a human submits can name it.
	ReservedSnapshotSlot = "previous"
)

// operationGroup is which of the closed field lists an operation carries.
type operationGroup int

const (
	groupWebService operationGroup = iota + 1
	groupEntrypoint
	groupRoute
	groupPrivateService
	groupLinkRoute
	groupSnapshot
	groupRestore
	groupUserService
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

	// canonicalDefinitionDigest is the one spelling a plan may name a frozen
	// definition by: thirty-two bytes written as lower-case hexadecimal, bare.
	//
	// It carries no `sha256:` prefix, and that is not an oversight beside
	// image_digest: an image digest is an OCI reference whose algorithm is part of
	// the value the registry answers to, while a definition digest is this
	// product's own SHA-256 over its own transcript, spelled exactly as the
	// approval envelope spells the digests it signs. Two spellings of one value
	// would be two names for one revision, and every freeze, every plan and every
	// lookup of a definition is keyed on that name.
	canonicalDefinitionDigest = regexp.MustCompile(`^[0-9a-f]{64}$`)

	// canonicalSnapshotSlot bounds the label one archive is named by: lower-case
	// letters, digits and hyphens, one to thirty-two characters, opening on a
	// letter or a digit. There is no dot and no separator inside those bounds, so
	// a slot is always exactly one name inside the directory its profile owns and
	// never a path a plan could climb out of.
	canonicalSnapshotSlot = regexp.MustCompile(fmt.Sprintf(`^[a-z0-9][a-z0-9-]{0,%d}$`,
		MaxSnapshotSlotBytes-1))

	// inverseOperationV2 is at once the closed list of operations schema 2
	// describes and the operation that undoes each of them. Holding both in one
	// declaration is what makes an operation without an undoing impossible to
	// add here by accident.
	//
	// The restore is the one entry that names itself, and it is the one entry
	// this table does not fully describe: what changes between a restore and its
	// undoing is the slot, not the operation. RestoreDocument's own inverse
	// states that, and this table says the only thing it can — that the document
	// which returns from a restore is a restore.
	inverseOperationV2 = map[string]string{
		OperationDeployWebService:     OperationRemoveWebService,
		OperationRemoveWebService:     OperationDeployWebService,
		OperationDeployEntrypoint:     OperationRemoveEntrypoint,
		OperationRemoveEntrypoint:     OperationDeployEntrypoint,
		OperationPublishRoute:         OperationRetireRoute,
		OperationRetireRoute:          OperationPublishRoute,
		OperationDeployPrivateService: OperationRemovePrivateService,
		OperationRemovePrivateService: OperationDeployPrivateService,
		OperationPublishLinkRoute:     OperationRetireLinkRoute,
		OperationRetireLinkRoute:      OperationPublishLinkRoute,
		OperationSnapshotService:      OperationDiscardSnapshot,
		OperationDiscardSnapshot:      OperationSnapshotService,
		OperationRestoreService:       OperationRestoreService,
		OperationDeployUserService:    OperationRemoveUserService,
		OperationRemoveUserService:    OperationDeployUserService,
	}

	// operationGroups says which closed field list each operation carries. It is
	// the whole of the discriminator: an operation absent from this table has no
	// document shape, and is refused before any field of the document is read.
	operationGroups = map[string]operationGroup{
		OperationDeployWebService:     groupWebService,
		OperationRemoveWebService:     groupWebService,
		OperationDeployEntrypoint:     groupEntrypoint,
		OperationRemoveEntrypoint:     groupEntrypoint,
		OperationPublishRoute:         groupRoute,
		OperationRetireRoute:          groupRoute,
		OperationDeployPrivateService: groupPrivateService,
		OperationRemovePrivateService: groupPrivateService,
		OperationPublishLinkRoute:     groupLinkRoute,
		OperationRetireLinkRoute:      groupLinkRoute,
		OperationSnapshotService:      groupSnapshot,
		OperationDiscardSnapshot:      groupSnapshot,
		OperationRestoreService:       groupRestore,
		OperationDeployUserService:    groupUserService,
		OperationRemoveUserService:    groupUserService,
	}

	// profileImage and privateProfileImage are the two closed lists of service
	// profiles, one per door, and the one image each profile may name. A profile
	// a table does not hold is refused before its image is compared, so an
	// unknown profile can never borrow the pin of a known one.
	//
	// They are two tables rather than one table and a flag because the refusal
	// has to run in both directions: a data-bearing service does not pass through
	// the stateless door, and a stateless service does not pass through the
	// private one. A single list would make each of those a comparison someone
	// has to remember to write; two lists make them the same lookup that already
	// refuses an unknown name.
	profileImage = map[string]pinnedImage{
		ServiceProfileBentoPDF: {reference: BentoPDFImageReference, digest: BentoPDFImageDigest},
	}

	privateProfileImage = map[string]pinnedImage{
		ServiceProfileVaultwarden: {reference: VaultwardenImageReference, digest: VaultwardenImageDigest},
	}

	// entrypointImage is the single pin of the entrypoint, which has no profile
	// to choose from: there is one entrypoint and one image for it.
	entrypointImage = pinnedImage{reference: EntrypointImageReference, digest: EntrypointImageDigest}

	errReservedSnapshotSlot = fmt.Errorf(
		"plan snapshot_slot %q belongs to the return mechanism and no plan may name it",
		ReservedSnapshotSlot)
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
// The interface is closed to the shapes declared below: its unexported method
// cannot be implemented outside this package, so a further field list is a
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

// PrivateServiceDocument is the plan of one managed service whose data outlives
// its container: one profile, the image that profile pins, one loopback port on
// one machine, and the one origin the instance will answer under.
//
// The origin is a field because it binds the service to the route that will
// publish it: the instance only works correctly under that name, and the name is
// therefore under the eyes of the human who approves the deployment. It is not a
// route: publishing is a separate, optional plan, and a private service deployed
// without one lives on its own machine's loopback for as long as its owner wants.
//
// The volume, the environment lines and the egress table have no field here and
// none anywhere else. They are the profile's, exactly as the account and the
// sheet are, and the rule of the stateless sheets is unchanged: no plan of this
// product describes a path a machine will write to.
//
// The declaration order below is the canonical encoding order and the transcript
// order at once, and no field of a private service plan lives outside it.
type PrivateServiceDocument struct {
	SchemaVersion    int    `json:"schema_version"`
	InfrastructureID string `json:"infrastructure_id"`
	MachineID        string `json:"machine_id"`
	Operation        string `json:"operation"`
	ServiceProfile   string `json:"service_profile"`
	ImageReference   string `json:"image_reference"`
	ImageDigest      string `json:"image_digest"`
	LocalPort        int    `json:"local_port"`
	OriginHost       string `json:"origin_host"`
}

// LinkRouteDocument is the plan of one published name served through the private
// passage: the host the entrypoint serves and the port the tunnel carries.
//
// It carries the same two fields as a route of the public profile and describes
// another state, which is why it is another shape rather than a flag on that one.
// Its backend is the constant peer of the tunnel and never an address a plan
// names, so there is no field for one; and the port it names is required, on the
// machine that will act, to be the port an approved junction already bounds.
type LinkRouteDocument struct {
	SchemaVersion    int    `json:"schema_version"`
	InfrastructureID string `json:"infrastructure_id"`
	MachineID        string `json:"machine_id"`
	Operation        string `json:"operation"`
	RouteHost        string `json:"route_host"`
	BackendPort      int    `json:"backend_port"`
}

// SnapshotDocument is the plan of one archive of one private service's data:
// which profile, and the one named slot the archive is written to or destroyed
// from.
//
// It carries no path and no digest. The directory belongs to the profile, the
// file name is the slot, and the digest of the archive is a fact the report
// carries afterwards rather than a value a human could approve in advance.
type SnapshotDocument struct {
	SchemaVersion    int    `json:"schema_version"`
	InfrastructureID string `json:"infrastructure_id"`
	MachineID        string `json:"machine_id"`
	Operation        string `json:"operation"`
	ServiceProfile   string `json:"service_profile"`
	SnapshotSlot     string `json:"snapshot_slot"`
}

// RestoreDocument is the plan of one return: which profile, and the one named
// slot whose archive becomes the service's data.
//
// It carries exactly the fields a snapshot carries and it is a separate shape,
// because what differs between the two is not a field but an undoing. A
// snapshot is undone by destroying the archive it wrote; a restore is undone by
// another restore, naming the reserved slot the flow has just written the
// replaced state into. Two shapes is how that difference is stated once instead
// of being decided by a branch every time an inverse is needed.
type RestoreDocument struct {
	SchemaVersion    int    `json:"schema_version"`
	InfrastructureID string `json:"infrastructure_id"`
	MachineID        string `json:"machine_id"`
	Operation        string `json:"operation"`
	ServiceProfile   string `json:"service_profile"`
	SnapshotSlot     string `json:"snapshot_slot"`
}

// UserServiceDocument is the plan of one service the product does not know: the
// definition it runs, the revision of that definition, the image of this
// instance, one loopback port on one machine, and the origin the instance answers
// under when — and only when — its definition consumes one.
//
// It names a definition where the two other service shapes name a profile. A
// profile decides everything its plan does not state and is a constant of the
// product; a definition decides the same things and is a document its user wrote,
// frozen by the Controller and pinned here by definition_digest. The two are the
// same idea under two authorities, which is why this is a third shape rather than
// a profile whose name happens to be free-form: the fields differ, so the closed
// field lists differ.
//
// image_reference is here and decides nothing. It must be exactly the repository
// of the pinned definition — the human approves an origin and an executable
// identity under their eyes — and image_digest is the identity of this instance,
// which is the one thing about a user service that a revision does not fix: an
// update is a new plan whose digest differs, never a silent mutation.
//
// origin_host is present exactly when the pinned definition interpolates it. A
// definition that names {origin_host} makes the origin a value the container
// receives, so the human approves a service that only works correctly under that
// name and the name is under their eyes; a definition that does not interpolate
// it makes the field refused, because an approved value no line consumes would be
// an intention without a consequence. Neither half of that rule can be held here
// — validating a plan reads no definition — so it lives in
// RequireDefinitionAgreement, held at construction by the Controller and re-held
// by the Auxiliary with the definition in hand.
//
// The volumes, the tmpfs, the environment lines, the secret names, the account
// and the home have no field here and none anywhere else. They are the
// definition's, and everything touching the machine is derived from its slug by
// the Auxiliary: the rule of the delivered profiles, unchanged, over a document
// whose author is the user rather than the product.
//
// The declaration order below is the canonical encoding order and the transcript
// order at once, and no field of a user service plan lives outside it.
type UserServiceDocument struct {
	SchemaVersion    int    `json:"schema_version"`
	InfrastructureID string `json:"infrastructure_id"`
	MachineID        string `json:"machine_id"`
	Operation        string `json:"operation"`
	DefinitionSlug   string `json:"definition_slug"`
	DefinitionDigest string `json:"definition_digest"`
	ImageReference   string `json:"image_reference"`
	ImageDigest      string `json:"image_digest"`
	LocalPort        int    `json:"local_port"`
	OriginHost       string `json:"origin_host"`
}

// V2Pair is one schema 2 plan and the complete document that undoes it.
//
// The rollback is a plan in its own right, read, displayed, approved and
// verified like any other: removal for a deployment, redeployment for a removal,
// retire_route for publish_route, discard_snapshot for snapshot_service — and,
// for a restore, a second restore naming the reserved slot.
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
		if err := strictDecodePlan(document, &shape); err != nil {
			return nil, err
		}
		parsed = shape
	case groupEntrypoint:
		var shape EntrypointDocument
		if err := strictDecodePlan(document, &shape); err != nil {
			return nil, err
		}
		parsed = shape
	case groupRoute:
		var shape RouteDocument
		if err := strictDecodePlan(document, &shape); err != nil {
			return nil, err
		}
		parsed = shape
	case groupPrivateService:
		var shape PrivateServiceDocument
		if err := strictDecodePlan(document, &shape); err != nil {
			return nil, err
		}
		parsed = shape
	case groupLinkRoute:
		var shape LinkRouteDocument
		if err := strictDecodePlan(document, &shape); err != nil {
			return nil, err
		}
		parsed = shape
	case groupSnapshot:
		var shape SnapshotDocument
		if err := strictDecodePlan(document, &shape); err != nil {
			return nil, err
		}
		parsed = shape
	case groupRestore:
		var shape RestoreDocument
		if err := strictDecodePlan(document, &shape); err != nil {
			return nil, err
		}
		parsed = shape
	case groupUserService:
		var shape UserServiceDocument
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

// declaredOperation reads only the operation field, and decides which closed
// schema the document will be held against from it alone.
//
// It is the same principle as the discriminator of the Auxiliary's input: the
// shape is read in the document rather than guessed by trying each schema in
// turn. That is what keeps the closed field lists from covering for one another —
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

// BuildPrivateServicePair freezes one operation on one data-bearing service
// instance together with the complete document that undoes it.
//
// The caller chooses the profile and is refused when the profile is not one the
// private door describes — the stateless profile of the previous palier included.
// It never chooses the image, because the profile pins it.
func BuildPrivateServicePair(operation, infrastructureID, machineID, serviceProfile string,
	localPort int, originHost string) (V2Pair, error) {
	image, known := privateProfileImage[serviceProfile]
	if !known {
		return V2Pair{}, fmt.Errorf("plan service_profile %q is not one this palier builds behind the private door", serviceProfile)
	}
	return buildV2Pair(PrivateServiceDocument{
		SchemaVersion:    SchemaVersionV2,
		InfrastructureID: infrastructureID,
		MachineID:        machineID,
		Operation:        operation,
		ServiceProfile:   serviceProfile,
		ImageReference:   image.reference,
		ImageDigest:      image.digest,
		LocalPort:        localPort,
		OriginHost:       originHost,
	})
}

// BuildLinkRoutePair freezes one name published through the passage together
// with its retirement.
func BuildLinkRoutePair(operation, infrastructureID, machineID, routeHost string, backendPort int) (V2Pair, error) {
	return buildV2Pair(LinkRouteDocument{
		SchemaVersion:    SchemaVersionV2,
		InfrastructureID: infrastructureID,
		MachineID:        machineID,
		Operation:        operation,
		RouteHost:        routeHost,
		BackendPort:      backendPort,
	})
}

// BuildSnapshotPair freezes one archive together with its destruction, or one
// destruction together with an archive.
//
// The second direction is the asymmetry the contract names rather than hides:
// the rollback of a discard is a snapshot of the same slot, and what it will
// archive is the state the machine holds when it runs — not the archive that was
// destroyed, which nothing can bring back. The Console says so in those words;
// this builder only builds the document.
//
// The reserved slot is refused here as it is refused by validation, in both
// directions: it is not a slot a plan names.
func BuildSnapshotPair(operation, infrastructureID, machineID, serviceProfile, snapshotSlot string) (V2Pair, error) {
	if err := validateArchivedProfile(serviceProfile); err != nil {
		return V2Pair{}, err
	}
	return buildV2Pair(SnapshotDocument{
		SchemaVersion:    SchemaVersionV2,
		InfrastructureID: infrastructureID,
		MachineID:        machineID,
		Operation:        operation,
		ServiceProfile:   serviceProfile,
		SnapshotSlot:     snapshotSlot,
	})
}

// BuildRestorePair freezes one return together with the document that returns
// from it.
//
// There is no operation to choose: a restore has one direction. Its rollback is a
// restore naming the reserved slot, which is the one document of the product
// where that slot appears — the flow writes the state it is about to replace
// there before replacing anything, so the returning document restores exactly
// what was left behind. A caller that named the reserved slot as the forward
// direction is refused: that document would undo itself, and a pair whose two
// halves are one document is not a pair.
func BuildRestorePair(infrastructureID, machineID, serviceProfile, snapshotSlot string) (V2Pair, error) {
	if err := validateArchivedProfile(serviceProfile); err != nil {
		return V2Pair{}, err
	}
	if snapshotSlot == ReservedSnapshotSlot {
		return V2Pair{}, errReservedSnapshotSlot
	}
	return buildV2Pair(RestoreDocument{
		SchemaVersion:    SchemaVersionV2,
		InfrastructureID: infrastructureID,
		MachineID:        machineID,
		Operation:        OperationRestoreService,
		ServiceProfile:   serviceProfile,
		SnapshotSlot:     snapshotSlot,
	})
}

// BuildUserServicePair freezes one operation on one instance of a user service
// together with the complete document that undoes it.
//
// The definition is passed whole rather than by name, because three of the plan's
// fields are read out of it and never chosen by the caller: the slug, the digest
// of the revision, and the repository the images come from. A caller that could
// name them could pin one revision while displaying another, or aim a plan at a
// repository the definition never mentioned — and the human reading the plan
// would have no way to tell.
//
// What the caller does choose is the instance: which image digest runs, on which
// port, and under which origin. The digest is the one thing a revision
// deliberately does not fix, and the origin is required to be present exactly
// when the definition consumes it, which is checked here with the definition in
// hand.
func BuildUserServicePair(operation, infrastructureID, machineID string,
	definition servicedefinition.Document, imageDigest string, localPort int, originHost string) (V2Pair, error) {
	digest, err := definition.SHA256()
	if err != nil {
		return V2Pair{}, fmt.Errorf("plan definition_digest: %w", err)
	}
	subject := UserServiceDocument{
		SchemaVersion:    SchemaVersionV2,
		InfrastructureID: infrastructureID,
		MachineID:        machineID,
		Operation:        operation,
		DefinitionSlug:   definition.Slug,
		DefinitionDigest: digest,
		ImageReference:   definition.ImageRepository,
		ImageDigest:      imageDigest,
		LocalPort:        localPort,
		OriginHost:       originHost,
	}
	if err := RequireDefinitionAgreement(subject, definition); err != nil {
		return V2Pair{}, err
	}
	return buildV2Pair(subject)
}

// RequireDefinitionAgreement holds one user service plan against the definition
// it pins, and is the whole of what a plan cannot decide about itself.
//
// Validating a plan is an offline act: it reads one document and no other, so it
// can say that origin_host is a well-formed host or absent, and it cannot say
// whether this definition consumes one. The contract answers that by naming where
// the rule lives instead — held at construction by the Controller, which has just
// looked the definition up, and re-held by the Auxiliary, which receives the
// definition's bytes beside the signed pair and re-derives everything locally
// rather than trusting the Controller that carried it. This function is that one
// rule, written once so the two callers cannot come to disagree.
//
// The digest is re-derived from the definition rather than compared as a string
// against what accompanied it: that is what makes "this plan pins these exact
// bytes" a property of the document rather than a promise of whoever handed the
// two over together.
func RequireDefinitionAgreement(document UserServiceDocument, definition servicedefinition.Document) error {
	if err := document.Validate(); err != nil {
		return err
	}
	digest, err := definition.SHA256()
	if err != nil {
		return fmt.Errorf("plan definition_digest: %w", err)
	}
	if document.DefinitionDigest != digest {
		return errors.New("plan definition_digest is not the digest of the definition it travels with")
	}
	if document.DefinitionSlug != definition.Slug {
		return fmt.Errorf("plan definition_slug %q is not the slug the pinned definition declares",
			document.DefinitionSlug)
	}
	// The repository is the definition's and the digest is the instance's. The
	// equality is the same rule the delivered profiles hold against their pins,
	// read against a document a user wrote instead of against a constant of the
	// product.
	if document.ImageReference != definition.ImageRepository {
		return errors.New("plan image_reference is not the repository the pinned definition names")
	}
	if definition.InterpolatesOriginHost() {
		if document.OriginHost == "" {
			return errors.New(
				"plan origin_host is required because the pinned definition interpolates the origin")
		}
		return nil
	}
	if document.OriginHost != "" {
		return errors.New(
			"plan origin_host is refused because no line of the pinned definition consumes the origin")
	}
	return nil
}

// buildV2Pair holds both directions against the contract before either exists.
//
// The two documents differ by their operation — or, for a restore, by the one
// slot the return mechanism owns — and by nothing else, and a caller cannot ask
// for a rollback that targets another instance because it never supplies one.
//
// The last refusal is the one that keeps a self-undoing document from being
// frozen as a pair: two identical documents carry one digest twice, so a human
// would be approving the same plan as its own rollback.
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
	if rollback == subject {
		return V2Pair{}, errors.New("a plan and its rollback must be two documents")
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

// Validate holds a private service plan against the whole contract of the
// palier.
//
// The profile is looked up in the private door's own list, so the stateless
// profile of the previous palier is refused here exactly as an invented name
// would be: a service without persistent data has nothing to do behind a door
// whose sheet declares a volume, and the refusal says so before the image is
// even compared.
func (document PrivateServiceDocument) Validate() error {
	if err := validateV2Head(document.SchemaVersion, document.InfrastructureID,
		document.MachineID, document.Operation, groupPrivateService); err != nil {
		return err
	}
	image, known := privateProfileImage[document.ServiceProfile]
	if !known {
		return fmt.Errorf("plan service_profile %q is not one this palier describes behind the private door", document.ServiceProfile)
	}
	if err := validatePinnedImage(document.ImageReference, document.ImageDigest, image); err != nil {
		return err
	}
	if document.LocalPort < MinLocalPort || document.LocalPort > MaxLocalPort {
		return fmt.Errorf("plan local_port must be within %d..%d", MinLocalPort, MaxLocalPort)
	}
	return validateHostBound("origin_host", document.OriginHost)
}

// Validate holds a link route plan against the whole contract of the palier. It
// is the route contract read again over the other operation: the bound of a name
// and the bound of a port do not change because the traffic behind them takes
// the passage.
func (document LinkRouteDocument) Validate() error {
	if err := validateV2Head(document.SchemaVersion, document.InfrastructureID,
		document.MachineID, document.Operation, groupLinkRoute); err != nil {
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

// Validate holds a snapshot plan against the whole contract of the palier.
//
// The reserved slot is refused here rather than only in the builder, because a
// document is what a machine acts on: a snapshot writing over the return
// mechanism's slot, or a discard destroying it, would be a plan that removes the
// possibility of returning — and it must be refused whoever wrote the bytes.
func (document SnapshotDocument) Validate() error {
	if err := validateV2Head(document.SchemaVersion, document.InfrastructureID,
		document.MachineID, document.Operation, groupSnapshot); err != nil {
		return err
	}
	if err := validateArchivedProfile(document.ServiceProfile); err != nil {
		return err
	}
	if err := validateSnapshotSlot(document.SnapshotSlot); err != nil {
		return err
	}
	if document.SnapshotSlot == ReservedSnapshotSlot {
		return errReservedSnapshotSlot
	}
	return nil
}

// Validate holds a restore plan against the whole contract of the palier.
//
// It is the one place the reserved slot is accepted, and it has to be: the signed
// rollback of a restore is a restore naming that slot, and a rollback is a plan
// in its own right — displayed, hashed, transported and decoded like any other.
// What keeps a human from submitting one as a forward direction is the builder,
// which is the only thing in the product that writes that document.
func (document RestoreDocument) Validate() error {
	if err := validateV2Head(document.SchemaVersion, document.InfrastructureID,
		document.MachineID, document.Operation, groupRestore); err != nil {
		return err
	}
	if err := validateArchivedProfile(document.ServiceProfile); err != nil {
		return err
	}
	return validateSnapshotSlot(document.SnapshotSlot)
}

// Validate holds a user service plan against everything one document can be held
// against on its own.
//
// Three of its fields name a definition this package cannot read: the slug, the
// revision and the repository. What is required here is therefore their shape —
// the slug grammar the definition package owns, reserved names included, so a
// plan can never name a definition that could not exist; the one spelling of a
// revision's digest; and the repository rule, which is where the tag is refused
// on this side too. Whether they are the shape of the definition actually frozen
// under that digest is RequireDefinitionAgreement's, with the definition in hand.
//
// origin_host is accepted in both of its forms and refused in neither. That is
// not a weaker rule than the contract's, it is the same rule read where it can be
// read: presence is required exactly when the definition interpolates, and a
// document alone knows nothing of the definition. A plan reaching a machine has
// been through the agreement check twice by then — once at the Controller that
// built it, once at the Auxiliary that received the definition beside it.
func (document UserServiceDocument) Validate() error {
	if err := validateV2Head(document.SchemaVersion, document.InfrastructureID,
		document.MachineID, document.Operation, groupUserService); err != nil {
		return err
	}
	if err := servicedefinition.ValidateSlug(document.DefinitionSlug); err != nil {
		return fmt.Errorf("plan definition_slug: %w", err)
	}
	if !canonicalDefinitionDigest.MatchString(document.DefinitionDigest) {
		return errors.New("plan definition_digest must be lower-case hexadecimal SHA-256")
	}
	if err := servicedefinition.ValidateImageRepository(document.ImageReference); err != nil {
		return fmt.Errorf("plan image_reference: %w", err)
	}
	// The shape of the image digest is required as it is everywhere else, so that
	// the transcript may rely on decoding exactly 32 bytes out of the field. There
	// is no pin to compare it to: which image runs is what a plan of this door
	// says, and the definition only says where images come from.
	if !canonicalOCIDigest.MatchString(document.ImageDigest) {
		return errMalformedImageDigest
	}
	if document.LocalPort < MinLocalPort || document.LocalPort > MaxLocalPort {
		return fmt.Errorf("plan local_port must be within %d..%d", MinLocalPort, MaxLocalPort)
	}
	if document.OriginHost == "" {
		return nil
	}
	return validateHostBound("origin_host", document.OriginHost)
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

// Transcript rebuilds the exact bytes a private service plan digest is taken
// over. The origin follows the port rather than the profile: the layout is the
// stateless one with exactly one field appended, so a reader holds the two side
// by side and sees what the private door adds.
func (document PrivateServiceDocument) Transcript() ([]byte, error) {
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
	transcript = appendUint32(transcript, uint32(document.LocalPort))
	return appendField(transcript, []byte(document.OriginHost)), nil
}

// Transcript rebuilds the exact bytes a link route plan digest is taken over.
//
// The tail is byte for byte the tail of a route of the public profile, and the
// two digests differ anyway, because the operation is inside the hashed bytes
// ahead of it. That is the whole reason the operation travels in the transcript
// at all.
func (document LinkRouteDocument) Transcript() ([]byte, error) {
	if err := document.Validate(); err != nil {
		return nil, err
	}
	transcript := appendV2Head(document.SchemaVersion, document.InfrastructureID,
		document.MachineID, document.Operation)
	transcript = appendField(transcript, []byte(document.RouteHost))
	return appendUint32(transcript, uint32(document.BackendPort)), nil
}

// Transcript rebuilds the exact bytes a snapshot plan digest is taken over.
func (document SnapshotDocument) Transcript() ([]byte, error) {
	if err := document.Validate(); err != nil {
		return nil, err
	}
	transcript := appendV2Head(document.SchemaVersion, document.InfrastructureID,
		document.MachineID, document.Operation)
	transcript = appendField(transcript, []byte(document.ServiceProfile))
	return appendField(transcript, []byte(document.SnapshotSlot)), nil
}

// Transcript rebuilds the exact bytes a restore plan digest is taken over. It is
// the snapshot tail again, under the other operation.
func (document RestoreDocument) Transcript() ([]byte, error) {
	if err := document.Validate(); err != nil {
		return nil, err
	}
	transcript := appendV2Head(document.SchemaVersion, document.InfrastructureID,
		document.MachineID, document.Operation)
	transcript = appendField(transcript, []byte(document.ServiceProfile))
	return appendField(transcript, []byte(document.SnapshotSlot)), nil
}

// Transcript rebuilds the exact bytes a user service plan digest is taken over.
//
// The tail is the private door's with the profile replaced by the two fields that
// name a definition, so a reader holds the two side by side and sees what the
// third door changes: a plan of this door pins a document instead of naming a
// constant. The origin closes the tail as it does there, and it is written even
// when it is absent — a length of zero — so that the end of the transcript never
// depends on a rule the bytes do not carry.
func (document UserServiceDocument) Transcript() ([]byte, error) {
	if err := document.Validate(); err != nil {
		return nil, err
	}
	definition, err := decodeDefinitionDigest(document.DefinitionDigest)
	if err != nil {
		return nil, err
	}
	image, err := decodeOCIDigest(document.ImageDigest)
	if err != nil {
		return nil, err
	}
	transcript := appendV2Head(document.SchemaVersion, document.InfrastructureID,
		document.MachineID, document.Operation)
	transcript = appendField(transcript, []byte(document.DefinitionSlug))
	transcript = appendField(transcript, definition)
	transcript = appendField(transcript, []byte(document.ImageReference))
	transcript = appendField(transcript, image)
	transcript = appendUint32(transcript, uint32(document.LocalPort))
	return appendField(transcript, []byte(document.OriginHost)), nil
}

func (document WebServiceDocument) Encode() ([]byte, error)     { return encodeV2(document) }
func (document EntrypointDocument) Encode() ([]byte, error)     { return encodeV2(document) }
func (document RouteDocument) Encode() ([]byte, error)          { return encodeV2(document) }
func (document PrivateServiceDocument) Encode() ([]byte, error) { return encodeV2(document) }
func (document LinkRouteDocument) Encode() ([]byte, error)      { return encodeV2(document) }
func (document SnapshotDocument) Encode() ([]byte, error)       { return encodeV2(document) }
func (document RestoreDocument) Encode() ([]byte, error)        { return encodeV2(document) }
func (document UserServiceDocument) Encode() ([]byte, error)    { return encodeV2(document) }

func (document WebServiceDocument) SHA256() (string, error)     { return digestOf(document) }
func (document EntrypointDocument) SHA256() (string, error)     { return digestOf(document) }
func (document RouteDocument) SHA256() (string, error)          { return digestOf(document) }
func (document PrivateServiceDocument) SHA256() (string, error) { return digestOf(document) }
func (document LinkRouteDocument) SHA256() (string, error)      { return digestOf(document) }
func (document SnapshotDocument) SHA256() (string, error)       { return digestOf(document) }
func (document RestoreDocument) SHA256() (string, error)        { return digestOf(document) }
func (document UserServiceDocument) SHA256() (string, error)    { return digestOf(document) }

func (document WebServiceDocument) OperationName() string     { return document.Operation }
func (document EntrypointDocument) OperationName() string     { return document.Operation }
func (document RouteDocument) OperationName() string          { return document.Operation }
func (document PrivateServiceDocument) OperationName() string { return document.Operation }
func (document LinkRouteDocument) OperationName() string      { return document.Operation }
func (document SnapshotDocument) OperationName() string       { return document.Operation }
func (document RestoreDocument) OperationName() string        { return document.Operation }
func (document UserServiceDocument) OperationName() string    { return document.Operation }

func (document WebServiceDocument) Target() Target {
	return Target{InfrastructureID: document.InfrastructureID, MachineID: document.MachineID}
}

func (document EntrypointDocument) Target() Target {
	return Target{InfrastructureID: document.InfrastructureID, MachineID: document.MachineID}
}

func (document RouteDocument) Target() Target {
	return Target{InfrastructureID: document.InfrastructureID, MachineID: document.MachineID}
}

func (document PrivateServiceDocument) Target() Target {
	return Target{InfrastructureID: document.InfrastructureID, MachineID: document.MachineID}
}

func (document LinkRouteDocument) Target() Target {
	return Target{InfrastructureID: document.InfrastructureID, MachineID: document.MachineID}
}

func (document SnapshotDocument) Target() Target {
	return Target{InfrastructureID: document.InfrastructureID, MachineID: document.MachineID}
}

func (document RestoreDocument) Target() Target {
	return Target{InfrastructureID: document.InfrastructureID, MachineID: document.MachineID}
}

func (document UserServiceDocument) Target() Target {
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

func (document PrivateServiceDocument) IsExactInverseOf(other V2Document) bool {
	return isExactInverseV2(document, other)
}

func (document LinkRouteDocument) IsExactInverseOf(other V2Document) bool {
	return isExactInverseV2(document, other)
}

func (document SnapshotDocument) IsExactInverseOf(other V2Document) bool {
	return isExactInverseV2(document, other)
}

func (document RestoreDocument) IsExactInverseOf(other V2Document) bool {
	return isExactInverseV2(document, other)
}

func (document UserServiceDocument) IsExactInverseOf(other V2Document) bool {
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

func (document PrivateServiceDocument) inverse() (V2Document, bool) {
	inverted, known := inverseOperationV2[document.Operation]
	if !known {
		return nil, false
	}
	document.Operation = inverted
	return document, true
}

func (document LinkRouteDocument) inverse() (V2Document, bool) {
	inverted, known := inverseOperationV2[document.Operation]
	if !known {
		return nil, false
	}
	document.Operation = inverted
	return document, true
}

func (document SnapshotDocument) inverse() (V2Document, bool) {
	inverted, known := inverseOperationV2[document.Operation]
	if !known {
		return nil, false
	}
	document.Operation = inverted
	return document, true
}

func (document UserServiceDocument) inverse() (V2Document, bool) {
	inverted, known := inverseOperationV2[document.Operation]
	if !known {
		return nil, false
	}
	document.Operation = inverted
	return document, true
}

// inverse is the one undoing of this schema that moves a field instead of the
// operation.
//
// The document that returns from a restore is a restore of the reserved slot,
// because the flow writes the state it is about to replace there before replacing
// anything. That is why the reserved slot has to be a value this package accepts
// in a restore document and refuses everywhere else: it is not a slot a human
// names, it is the slot the mechanism owns.
//
// A restore already naming the reserved slot is its own undoing, which is
// honest — running it twice returns the machine where it started — and it is
// also why buildV2Pair refuses to freeze a pair whose two documents are one.
func (document RestoreDocument) inverse() (V2Document, bool) {
	if operationGroups[document.Operation] != groupRestore {
		return nil, false
	}
	document.SnapshotSlot = ReservedSnapshotSlot
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
func validateRouteHost(host string) error { return validateHostBound("route_host", host) }

// validateArchivedProfile requires a name whose data is worth archiving: a
// profile of the private door's own closed list, or the slug of a user service
// definition.
//
// The two readings share one field and stay unambiguous, because the four names
// the product owns are exactly the four a definition may not take. A name is
// therefore found in the closed list or it is a slug — never both, and never a
// comparison someone has to remember to write.
//
// A stateless profile is refused here and not merely unsupported: it is a
// reserved name the closed list does not hold, so it is neither a data-bearing
// profile nor a possible slug. It owns no persistent volume, an archive of it
// would be an archive of nothing, and a plan that could ask for one would be a
// plan whose report could never be honest.
//
// What a slug is admitted as here is exactly a well-formed name, and nothing
// more. This package reads no definition and no machine, so whether a service by
// that name was ever deployed, and whether its definition declares a volume at
// all, are facts the Auxiliary reads on the machine before any effect — a home
// without a volumes directory is a refusal, as the contract says.
func validateArchivedProfile(profile string) error {
	if _, known := privateProfileImage[profile]; known {
		return nil
	}
	if err := servicedefinition.ValidateSlug(profile); err != nil {
		return fmt.Errorf("plan service_profile %q holds no data this palier archives: %w", profile, err)
	}
	return nil
}

// decodeDefinitionDigest turns the textual field into the 32 bytes the transcript
// carries, and refuses everything else.
//
// It is a second function beside decodeOCIDigest rather than a shared one,
// because the two fields are two spellings of two different things: an OCI digest
// announces its algorithm to a registry, a definition digest is this product's
// own SHA-256 over its own transcript. A single decoder would be a place where
// one spelling could start being accepted for the other.
func decodeDefinitionDigest(value string) ([]byte, error) {
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != DigestBytes {
		return nil, errors.New("plan definition_digest is malformed")
	}
	return decoded, nil
}

// validateSnapshotSlot bounds the one label an archive is named by.
//
// The closed character set is what removes the separator, the dot, the upper-case
// spelling and everything else a file name inside a directory the profile owns
// has no business carrying: a slot cannot climb, cannot hide and cannot be two
// spellings of the same archive. Whether the reserved slot is one this document
// may name is decided by the document's own group, not here.
func validateSnapshotSlot(slot string) error {
	if !canonicalSnapshotSlot.MatchString(slot) {
		return fmt.Errorf(
			"plan snapshot_slot must be %d..%d lower-case letters, digits and hyphens opening on a letter or a digit",
			MinSnapshotSlotBytes, MaxSnapshotSlotBytes,
		)
	}
	return nil
}

// validateHostBound is that one bound, named by the field it is being applied
// to. Schema 3's peer_endpoint_host reuses it rather than restating it: the two
// fields name a host the same way, and a second expression that agreed with this
// one today would be a second expression to keep agreeing with it.
func validateHostBound(field, host string) error {
	if !canonicalRouteHost.MatchString(host) {
		return fmt.Errorf(
			"plan %s must be %d..%d lower-case letters, digits, hyphens and dots opening and closing on a letter or a digit",
			field, MinRouteHostBytes, MaxRouteHostBytes,
		)
	}
	if strings.Contains(host, "..") {
		return fmt.Errorf("plan %s must not carry an empty label", field)
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
	return encodeCanonicalPlan(document)
}

func appendV2Head(schemaVersion int, infrastructureID, machineID, operation string) []byte {
	transcript := make([]byte, 0, len(TranscriptDomainV2)+192)
	transcript = append(transcript, TranscriptDomainV2...)
	transcript = append(transcript, byte(schemaVersion))
	transcript = appendField(transcript, []byte(infrastructureID))
	transcript = appendField(transcript, []byte(machineID))
	return appendField(transcript, []byte(operation))
}

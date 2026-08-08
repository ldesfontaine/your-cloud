// Synthetic LAB fixture of the user service proof. It stands in for the four
// authorities this palier separates and holds none of them for real:
//
//   - the Controller, for the two things `v0.1.1` adds to it — freezing a
//     definition and reading it back, and building the pair of a plan that pins
//     one — plus the seven pairs the reference scenario of `v0.1.0` still needs;
//   - the Console, which shows a pair to a human and signs the envelope naming
//     their two digests;
//   - the certificate authority of the declared names, which no plan describes
//     and which the Auxiliary never writes into;
//   - the **origin of the image**, which is the one authority this palier could
//     not borrow from anywhere: the third door pulls an image by digest from a
//     registry, the LAB holds none, and no image of a third party may enter this
//     proof. So the origin is built here, out of the synthetic application's own
//     binary, and served here over the run's own TLS.
//
// The halves come from deliberately different sources, exactly as
// tests/lab/v0.1.0/{oci-plan,public-profile,private-passage,private-service}/_fixture do:
//
//   - the definitions are built as Go values and rendered by the product's own
//     `servicedefinition.Document.Encode`, so the canonical bytes a machine
//     receives are the bytes a Controller would have frozen and not a second
//     spelling invented by a test;
//   - freezing and reading back go through the product's own
//     `controller.ServiceDefinitionStore`, so "relire une définition gelée rend
//     ses octets exacts" is the product's own store answering and not this
//     program remembering;
//   - the plan documents come from `internal/plan`'s builders — including
//     `BuildUserServicePair`, which holds the plan against the definition it
//     pins at construction, exactly as the Controller's route does;
//   - the envelope transcript is rebuilt by hand below, so the signature this
//     fixture produces is not verified by the lines that produced it;
//   - the authority and the image are Go's own x509, archive/tar and
//     net/http, and share nothing with the product at all.
//
// What this fixture is **not** is the Controller's HTTP surface. It opens no
// listener for a Console, mints no session and presents no client certificate:
// the three routes of `v0.1.1` are held by their own Go tests, and what this
// proof exercises is the engine on machines. The report says so.
//
// The seed is synthetic and the key material lives only as long as the run.
// Interoperability with the real Console is proven by the pinned cross-language
// vectors, never by this program.
package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ldesfontaine/your-cloud/internal/controller"
	"github.com/ldesfontaine/your-cloud/internal/plan"
	"github.com/ldesfontaine/your-cloud/internal/servicedefinition"
)

// ---------------------------------------------------------------------------
// The definitions this proof writes.
//
// They are Go values rather than JSON files for one reason: what must be frozen
// is a document the product's own encoder rendered, so that the bytes this proof
// hands a machine are the bytes a Controller would have. A file of JSON in this
// directory would be a second canonical spelling, and the first day the encoder
// changed, the proof would be judging the file.
//
// Six of the ten below can never be frozen at all, and that is what they exist
// for: each carries exactly one thing the contract refuses, so the refusal it
// draws is about that thing and never about a second mistake beside it.
// ---------------------------------------------------------------------------

const (
	// applicationSlug is the service whose whole life this proof follows, and
	// edgeSlug is the second one — deployed on the other machine, keeping nothing,
	// published by a local route instead of by the passage.
	//
	// Two slugs rather than one is not decoration: it is what makes "two distinct
	// slugs are two distinct accounts by construction" a fact of a machine, what
	// gives the confinement table more than one block to render, and what lets the
	// two kinds of route this palier opens to the third door both be exercised.
	applicationSlug = "labapp"
	edgeSlug        = "labedge"
	// plainSlug is a service whose definition interpolates no origin. It is frozen
	// and never deployed: it exists so that a plan carrying an origin no line
	// consumes can be presented to a machine.
	plainSlug = "labplain"

	// defaultRepository is where the images of this proof come from. The host
	// carries a dot, which is what the contract requires of a repository, and it
	// resolves to the machine this run's own origin is served from — never to
	// anything of the real world.
	defaultRepository = "registry.lab.your-cloud.test/lab/synthetic-app"

	// applicationContent is the payload the application writes into its content
	// volume the first time it starts. It is spelled here so that the corruption
	// and the return of this proof compare against one constant.
	applicationContent = "your-cloud lab synthetic content, revision one"
)

// definitionOf renders one named definition over the repository this run serves.
func definitionOf(name, repository string) (servicedefinition.Document, error) {
	switch name {
	// The service under proof: two volumes that do not overlap, one tmpfs the
	// image refuses to start without, an environment that interpolates the origin,
	// one generated value, and a container port below 1024 so that the sheet must
	// derive the namespace-scoped low-port sysctl.
	case "application":
		return servicedefinition.Document{
			SchemaVersion:   servicedefinition.SchemaVersion,
			Slug:            applicationSlug,
			ImageRepository: repository,
			ContainerPort:   80,
			Volumes:         []string{"/srv/state", "/srv/content"},
			Tmpfs:           []string{"/scratch"},
			Environment: []string{
				"YC_LAB_SLUG=" + applicationSlug,
				"YC_LAB_LISTEN_PORT=80",
				"YC_LAB_ORIGIN=https://{origin_host}",
				"YC_LAB_SCRATCH_DIR=/scratch",
				"YC_LAB_STATE_DIR=/srv/state",
				"YC_LAB_CONTENT_DIR=/srv/content",
				"YC_LAB_CONTENT=" + applicationContent,
			},
			SecretKeys: []string{"YC_LAB_TOKEN"},
		}, nil

	// A second revision of that same service whose author forgot that their image
	// listens below 1024. Everything else is identical, and the one changed field
	// takes the low-port sysctl out of the sheet — so the container cannot bind and
	// the deployment is a controlled failure with its approved rollback. It is the
	// contract's "une image qui ne démarre pas sous les contrôles est un échec
	// contrôlé, jamais un assouplissement", produced rather than asserted.
	case "application-undeclared-low-port":
		document, err := definitionOf("application", repository)
		if err != nil {
			return servicedefinition.Document{}, err
		}
		document.ContainerPort = 8080
		return document, nil

	// The second service: no volume at all, therefore nothing to archive and no
	// durable root; no secret, therefore no EnvironmentFile line; a container port
	// above 1024, therefore no low-port sysctl. It is the absence side of every
	// derivation the service above exercises by presence.
	case "edge":
		return servicedefinition.Document{
			SchemaVersion:   servicedefinition.SchemaVersion,
			Slug:            edgeSlug,
			ImageRepository: repository,
			ContainerPort:   8080,
			Tmpfs:           []string{"/scratch"},
			Environment: []string{
				"YC_LAB_SLUG=" + edgeSlug,
				"YC_LAB_LISTEN_PORT=8080",
				"YC_LAB_ORIGIN=https://{origin_host}",
				"YC_LAB_SCRATCH_DIR=/scratch",
			},
		}, nil

	// A definition no line of which consumes an origin. It is frozen and never
	// deployed: what it exists for is a plan that approves an origin anyway.
	case "plain":
		return servicedefinition.Document{
			SchemaVersion:   servicedefinition.SchemaVersion,
			Slug:            plainSlug,
			ImageRepository: repository,
			ContainerPort:   8080,
			Tmpfs:           []string{"/scratch"},
			Environment: []string{
				"YC_LAB_SLUG=" + plainSlug,
				"YC_LAB_LISTEN_PORT=8080",
				"YC_LAB_SCRATCH_DIR=/scratch",
			},
		}, nil

	// The six the contract refuses, one refused thing each.
	case "tagged-repository":
		document, err := definitionOf("edge", repository)
		if err != nil {
			return servicedefinition.Document{}, err
		}
		document.ImageRepository = repository + ":v1"
		return document, nil
	case "pinned-repository":
		document, err := definitionOf("edge", repository)
		if err != nil {
			return servicedefinition.Document{}, err
		}
		document.ImageRepository = repository +
			"@sha256:0000000000000000000000000000000000000000000000000000000000000000"
		return document, nil
	case "reserved-slug":
		document, err := definitionOf("edge", repository)
		if err != nil {
			return servicedefinition.Document{}, err
		}
		document.Slug = "vaultwarden"
		return document, nil
	case "host-path":
		document, err := definitionOf("application", repository)
		if err != nil {
			return servicedefinition.Document{}, err
		}
		// The mount specification a human pastes out of a `docker run` line. The
		// separator is not in the character set of a container path and no escape
		// exists, so what is refused is the attempt to name the host side at all.
		document.Volumes = []string{"/var/lib/your-cloud-user-labapp:/srv/state"}
		return document, nil
	case "overlapping-mounts":
		document, err := definitionOf("application", repository)
		if err != nil {
			return servicedefinition.Document{}, err
		}
		document.Volumes = []string{"/srv/state", "/srv/state/inner"}
		return document, nil
	case "stray-brace":
		document, err := definitionOf("edge", repository)
		if err != nil {
			return servicedefinition.Document{}, err
		}
		document.Environment = append(document.Environment, "YC_LAB_TEMPLATE={machine_id}")
		return document, nil
	}
	return servicedefinition.Document{}, fmt.Errorf("this fixture writes no definition named %q", name)
}

// ---------------------------------------------------------------------------
// The hostile documents this fixture is able to present.
//
// Every one of them is a document a Controller could physically transport and no
// human ever approved. The refusals this proof cares most about are not in this
// list: a definition the contract refuses is one nobody can freeze, and that is
// constated where it happens rather than carried to a machine.
// ---------------------------------------------------------------------------

const (
	hostileNone             = "none"
	hostileAlteredPlan      = "altered-plan"
	hostileApprovedMismatch = "mismatched-rollback"
	// hostileAlteredDefinition changes one byte of the definition **after** the
	// plan pinned it. The plan is perfectly valid, the envelope names the digests
	// of documents a human could have read, and what no longer holds is the one
	// thing the Auxiliary rebuilds for itself: the digest of the bytes it was
	// handed.
	hostileAlteredDefinition = "altered-definition"
	// hostileNoDefinition sends a user service plan with no definition beside it.
	hostileNoDefinition = "no-definition"
	// hostileForeignRepository names, in the plan, a repository the pinned
	// definition does not name. It cannot be built by BuildUserServicePair — the
	// agreement check refuses it at construction, which is itself a constat — so
	// the pair is assembled from the exported document type below.
	hostileForeignRepository = "foreign-repository"
	// hostileUnconsumedOrigin approves an origin no line of the pinned definition
	// interpolates, and hostileMissingOrigin approves none where a line does.
	hostileUnconsumedOrigin = "unconsumed-origin"
	hostileMissingOrigin    = "missing-origin"
)

func field(buffer []byte, value []byte) []byte {
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(value)))
	return append(append(buffer, length[:]...), value...)
}

func be64(buffer []byte, value uint64) []byte {
	var encoded [8]byte
	binary.BigEndian.PutUint64(encoded[:], value)
	return append(buffer, encoded[:]...)
}

func be32(buffer []byte, value uint32) []byte {
	var encoded [4]byte
	binary.BigEndian.PutUint32(encoded[:], value)
	return append(buffer, encoded[:]...)
}

func main() {
	seedByte := flag.Int("seed", 1, "synthetic seed byte")
	epoch := flag.Uint64("epoch", 1, "approval epoch")
	sequence := flag.Uint64("sequence", 1, "approval sequence")
	infrastructure := flag.String("infrastructure", "8f14e45f-ceea-4167-a8b1-1f7bd0a0f4c2", "infrastructure id")
	controllerID := flag.String("controller", "3f2504e0-4f89-41d3-9a0c-0305e82c3301", "controller id")
	machine := flag.String("machine", "lab-machine-1", "machine id")
	operation := flag.String("operation", plan.OperationDeployUserService, "plan operation")
	profile := flag.String("profile", plan.ServiceProfileVaultwarden, "service profile")
	port := flag.Int("port", 18310, "the loopback port a service plan names")
	originHost := flag.String("origin-host", "", "the origin a service answers under")
	routeHost := flag.String("route-host", "", "the declared name a route serves")
	backendPort := flag.Int("backend-port", 18310, "the port a route names behind it")
	snapshotSlot := flag.String("snapshot-slot", "", "the named archive an archive plan acts on")
	linkRole := flag.String("link-role", plan.LinkRoleListener, "the side of the passage this plan is for")
	peerPublicKey := flag.String("peer-public-key", "", "the public key the other machine's preparation reported")
	peerEndpointHost := flag.String("peer-endpoint-host", "", "the host the initiator reaches")
	servicePort := flag.Int("service-port", 18310, "the one port the passage carries")
	lifetime := flag.Uint64("lifetime", 900, "lifetime seconds")
	age := flag.Int64("age", 0, "seconds to subtract from the issue time")
	anchorOnly := flag.Bool("anchor", false, "emit the anchor instead of an approval")
	hostile := flag.String("hostile", hostileNone, "the hostile document to present")

	definitionName := flag.String("definition", "", "the named definition a user service plan pins")
	repository := flag.String("image-repository", defaultRepository, "where the images of this proof come from")
	imageDigest := flag.String("image-digest", "", "the digest of the instance a user service plan deploys")
	storeDirectory := flag.String("store", "", "the Controller's private state directory")
	freeze := flag.Bool("freeze", false, "freeze the named definition and report what the store did")
	list := flag.Bool("list", false, "read every frozen definition back, exactly as the store holds it")
	emit := flag.Bool("emit", false, "render the named definition's canonical bytes without freezing it")
	altered := flag.Bool("altered", false, "render that definition with one byte changed")
	carryBeside := flag.String("definition-beside", "",
		"carry the named definition beside a plan of another door")

	authority := flag.Bool("authority", false, "create the synthetic certificate authority")
	issue := flag.Bool("issue", false, "issue a certificate for -route-host under that authority")
	authorityDirectory := flag.String("authority-directory", "", "where the synthetic authority lives")
	out := flag.String("out", "", "where an issued certificate, or a built image, is written")

	buildImage := flag.Bool("image-build", false, "build the synthetic application's image")
	binary := flag.String("binary", "", "the static application binary the image carries")
	origin := flag.Bool("origin", false, "serve the built image as an OCI distribution origin")
	originRoot := flag.String("origin-root", "", "the built image this origin serves")
	originListen := flag.String("origin-listen", ":443", "where this origin listens")
	originCertificate := flag.String("origin-certificate", "", "the certificate this origin presents")
	originKey := flag.String("origin-key", "", "the key of that certificate")

	attest := flag.Bool("attest", false, "print the attestation of a generated value, never the value")
	secretFile := flag.String("secret-file", "", "the file holding that generated value")
	flag.Parse()

	switch {
	case *authority:
		exitOn(createAuthority(*authorityDirectory), "create the synthetic authority")
		return
	case *issue:
		exitOn(issueCertificate(*authorityDirectory, *out, *routeHost),
			"issue the certificate of "+*routeHost)
		return
	case *buildImage:
		exitOn(buildApplicationImage(*binary, *out), "build the synthetic application's image")
		return
	case *origin:
		exitOn(serveOrigin(*originRoot, *repository, *originListen, *originCertificate, *originKey),
			"serve the synthetic origin")
		return
	case *attest:
		exitOn(printAttestation(*secretFile), "attest the generated value")
		return
	case *emit:
		exitOn(emitDefinition(*definitionName, *repository, *altered), "render the definition")
		return
	case *freeze:
		exitOn(freezeDefinition(*storeDirectory, *controllerID, *infrastructure,
			*definitionName, *repository), "freeze the definition")
		return
	case *list:
		exitOn(listDefinitions(*storeDirectory, *controllerID, *infrastructure),
			"read the frozen definitions back")
		return
	}

	seed := make([]byte, ed25519.SeedSize)
	for index := range seed {
		seed[index] = byte(*seedByte)
	}
	private := ed25519.NewKeyFromSeed(seed)
	public := private.Public().(ed25519.PublicKey)
	publicB64 := base64.RawURLEncoding.EncodeToString(public)

	if *anchorOnly {
		fmt.Printf("{\"schema_version\":1,\"infrastructure_id\":%q,\"machine_id\":%q,\"approval_epoch\":%d,\"approval_public_key\":%q}\n",
			*infrastructure, *machine, *epoch, publicB64)
		return
	}

	// The definition this plan pins, read out of the Controller's own store rather
	// than rebuilt here. A plan of the third door names a revision, and a fixture
	// that rebuilt the document instead of reading it back would be pinning
	// something nobody froze.
	var pinned servicedefinition.Document
	var carried []byte
	if *definitionName != "" {
		held, err := heldDefinition(*storeDirectory, *controllerID, *infrastructure,
			*definitionName, *repository)
		if err != nil {
			fmt.Fprintf(os.Stderr, "read the frozen definition %s: %v\n", *definitionName, err)
			os.Exit(1)
		}
		pinned = held
		encoded, err := held.Encode()
		if err != nil {
			fmt.Fprintf(os.Stderr, "carry the frozen definition: %v\n", err)
			os.Exit(1)
		}
		carried = encoded
	}

	frozen, err := freezePair(*operation, *infrastructure, *machine, *profile, *port,
		*originHost, *routeHost, *backendPort, *snapshotSlot,
		*linkRole, *peerPublicKey, *peerEndpointHost, *servicePort,
		pinned, *imageDigest, *hostile, *repository)
	if err != nil {
		fmt.Fprintf(os.Stderr, "freeze the approved pair: %v\n", err)
		os.Exit(1)
	}

	planDocument := string(frozen.PlanDocument)
	rollbackDocument := string(frozen.RollbackDocument)
	planDigest := frozen.PlanSHA256
	rollbackDigest := frozen.RollbackSHA256

	// A definition may be carried beside a plan of another door, and that is a
	// hostile presentation in its own right: the Auxiliary refuses it before any
	// effect, because a document nothing in the run reads is a document nobody
	// verified.
	if *carryBeside != "" {
		held, err := heldDefinition(*storeDirectory, *controllerID, *infrastructure,
			*carryBeside, *repository)
		if err != nil {
			fmt.Fprintf(os.Stderr, "read the definition to carry beside: %v\n", err)
			os.Exit(1)
		}
		encoded, err := held.Encode()
		if err != nil {
			fmt.Fprintf(os.Stderr, "carry that definition: %v\n", err)
			os.Exit(1)
		}
		carried = encoded
	}

	switch *hostile {
	case hostileNone, hostileForeignRepository, hostileUnconsumedOrigin, hostileMissingOrigin:
	case hostileAlteredPlan:
		planDocument = strings.Replace(planDocument, *machine, alterLast(*machine), 1)
	case hostileApprovedMismatch:
		other, err := freezePair(*operation, *infrastructure, *machine, *profile, *port+1,
			*originHost, *routeHost, *backendPort+1, *snapshotSlot,
			*linkRole, *peerPublicKey, *peerEndpointHost, *servicePort+1,
			pinned, *imageDigest, hostileNone, *repository)
		if err != nil {
			fmt.Fprintf(os.Stderr, "freeze the mismatched rollback: %v\n", err)
			os.Exit(1)
		}
		rollbackDocument = string(other.RollbackDocument)
		rollbackDigest = other.RollbackSHA256
	case hostileAlteredDefinition:
		// One byte of the transported definition, changed by a Controller after a
		// human read the plan that pins it. The document still decodes and still
		// validates; what it no longer does is hash to the digest the plan names.
		altered, err := alterDefinition(carried)
		if err != nil {
			fmt.Fprintf(os.Stderr, "alter the carried definition: %v\n", err)
			os.Exit(1)
		}
		carried = altered
	case hostileNoDefinition:
		carried = nil
	default:
		fmt.Fprintf(os.Stderr, "unknown hostile document %q\n", *hostile)
		os.Exit(2)
	}

	issued := uint64(time.Now().UTC().Unix() - *age)
	expires := issued + *lifetime

	transcript := []byte("your-cloud/approval-envelope.v1\x00")
	transcript = append(transcript, 1)
	transcript = field(transcript, []byte(*infrastructure))
	transcript = field(transcript, []byte(*machine))
	transcript = be64(transcript, *epoch)
	transcript = be64(transcript, *sequence)
	transcript = field(transcript, []byte(*operation))
	transcript = field(transcript, mustDecodeDigest(planDigest))
	transcript = field(transcript, mustDecodeDigest(rollbackDigest))
	privileges := []string{"mutate_local_state", "read_local_state"}
	transcript = be32(transcript, uint32(len(privileges)))
	for _, privilege := range privileges {
		transcript = field(transcript, []byte(privilege))
	}
	transcript = be64(transcript, issued)
	transcript = be64(transcript, expires)
	transcript = field(transcript, public)

	signature := base64.RawURLEncoding.EncodeToString(ed25519.Sign(private, transcript))
	envelope := fmt.Sprintf(
		"{\"envelope\":{\"schema_version\":1,\"infrastructure_id\":%q,\"machine_id\":%q,\"approval_epoch\":%d,\"sequence\":%d,\"operation\":%q,\"plan_sha256\":%q,\"rollback_sha256\":%q,\"privileges\":[%q,%q],\"issued_at_unix_seconds\":%d,\"expires_at_unix_seconds\":%d,\"approval_public_key\":%q},\"signature\":%q}",
		*infrastructure, *machine, *epoch, *sequence, *operation,
		planDigest, rollbackDigest,
		privileges[0], privileges[1], issued, expires, publicB64, signature,
	)

	planField := mustMarshal(planDocument, "carry the plan")
	rollbackField := mustMarshal(rollbackDocument, "carry the rollback")
	if len(carried) == 0 {
		fmt.Printf("{\"signed_approval\":%s,\"plan\":%s,\"rollback\":%s}\n",
			envelope, planField, rollbackField)
		return
	}
	definitionField := mustMarshal(string(carried), "carry the definition")
	fmt.Printf("{\"signed_approval\":%s,\"plan\":%s,\"rollback\":%s,\"definition\":%s}\n",
		envelope, planField, rollbackField, definitionField)
}

func exitOn(err error, what string) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", what, err)
		os.Exit(1)
	}
}

func mustMarshal(value, what string) []byte {
	encoded, err := json.Marshal(value)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", what, err)
		os.Exit(1)
	}
	return encoded
}

// ---------------------------------------------------------------------------
// The Controller's two new acts: freezing a definition, and reading it back.
// ---------------------------------------------------------------------------

func openStore(directory, controllerID, infrastructureID string) (*controller.ServiceDefinitionStore, error) {
	if directory == "" {
		return nil, fmt.Errorf("a definition store needs a directory to live in")
	}
	return controller.OpenServiceDefinitionStore(directory, controllerID, infrastructureID)
}

// emitDefinition renders one definition's canonical bytes and its digest without
// freezing anything, so that a step can show a human what is about to be frozen —
// and so that a definition the contract refuses is refused *here*, by the
// product's own encoder, before any store is opened.
func emitDefinition(name, repository string, altered bool) error {
	document, err := definitionOf(name, repository)
	if err != nil {
		return err
	}
	encoded, err := document.Encode()
	if err != nil {
		return err
	}
	// One byte of an inert value changed, and the document read back through the
	// product's own decoder rather than patched in place: what is printed is the
	// digest of a definition that is still entirely inside the contract and differs
	// from the original by a single character.
	if altered {
		changed, err := alterDefinition(encoded)
		if err != nil {
			return err
		}
		document, err = servicedefinition.Decode(changed)
		if err != nil {
			return err
		}
		encoded = changed
	}
	digest, err := document.SHA256()
	if err != nil {
		return err
	}
	fmt.Printf("DEFINITION_SLUG=%s\n", document.Slug)
	fmt.Printf("DEFINITION_DIGEST=%s\n", digest)
	fmt.Printf("DEFINITION_BYTES=%d\n", len(encoded))
	fmt.Printf("DEFINITION_DOCUMENT=%s\n", encoded)
	return nil
}

func freezeDefinition(directory, controllerID, infrastructureID, name, repository string) error {
	document, err := definitionOf(name, repository)
	if err != nil {
		return err
	}
	encoded, err := document.Encode()
	if err != nil {
		return err
	}
	digest, err := document.SHA256()
	if err != nil {
		return err
	}
	store, err := openStore(directory, controllerID, infrastructureID)
	if err != nil {
		return err
	}
	frozen, revision, created, err := store.Freeze(encoded, digest, time.Now().UTC())
	if err != nil {
		return err
	}
	fmt.Printf("DEFINITION_SLUG=%s\n", frozen.Slug)
	fmt.Printf("DEFINITION_DIGEST=%s\n", frozen.Digest)
	fmt.Printf("DEFINITION_REVISION=%d\n", revision)
	fmt.Printf("DEFINITION_CREATED=%t\n", created)
	fmt.Printf("DEFINITION_BYTES=%d\n", len(frozen.Document))
	fmt.Printf("DEFINITION_DOCUMENT=%s\n", frozen.Document)
	return nil
}

// listDefinitions reads every revision back through the very projection the
// Controller's own GET serves, and prints each one's exact frozen bytes.
func listDefinitions(directory, controllerID, infrastructureID string) error {
	store, err := openStore(directory, controllerID, infrastructureID)
	if err != nil {
		return err
	}
	view, err := controller.ProjectServiceDefinitions(store.Snapshot())
	if err != nil {
		return err
	}
	fmt.Printf("DEFINITION_REVISION=%d\n", view.DefinitionRevision)
	fmt.Printf("DEFINITION_COUNT=%d\n", len(view.Definitions))
	for _, entry := range view.Definitions {
		fmt.Printf("DEFINITION_ENTRY=%s %s %d\n",
			entry.Slug, entry.DefinitionSHA256, len(entry.DefinitionDocument))
		fmt.Printf("DEFINITION_HELD=%s %s\n", entry.DefinitionSHA256, entry.DefinitionDocument)
	}
	return nil
}

// heldDefinition is the lookup a plan route performs: the pair (slug, digest)
// this Controller froze, and nothing rebuilt.
func heldDefinition(directory, controllerID, infrastructureID, name, repository string) (
	servicedefinition.Document, error,
) {
	wanted, err := definitionOf(name, repository)
	if err != nil {
		return servicedefinition.Document{}, err
	}
	digest, err := wanted.SHA256()
	if err != nil {
		return servicedefinition.Document{}, err
	}
	store, err := openStore(directory, controllerID, infrastructureID)
	if err != nil {
		return servicedefinition.Document{}, err
	}
	held, frozen := store.FrozenDefinition(wanted.Slug, digest)
	if !frozen {
		return servicedefinition.Document{}, fmt.Errorf(
			"this Controller froze no revision %s of %s", digest, wanted.Slug)
	}
	return held, nil
}

// alterDefinition changes exactly one byte of a carried definition and leaves a
// document that still decodes: the last character of the content payload, which
// is an inert environment value.
func alterDefinition(carried []byte) ([]byte, error) {
	altered := bytes.Replace(carried,
		[]byte(applicationContent), []byte(alterLast(applicationContent)), 1)
	if bytes.Equal(altered, carried) {
		return nil, fmt.Errorf("this definition carries nothing this fixture knows how to alter")
	}
	return altered, nil
}

// ---------------------------------------------------------------------------
// The pairs.
// ---------------------------------------------------------------------------

func freezePair(operation, infrastructure, machine, profile string, port int,
	originHost, routeHost string, backendPort int, snapshotSlot string,
	linkRole, peerPublicKey, peerEndpointHost string, servicePort int,
	definition servicedefinition.Document, imageDigest, hostile, repository string,
) (plan.Frozen, error) {
	switch operation {
	case plan.OperationDeployWebService, plan.OperationRemoveWebService:
		pair, err := plan.BuildWebServicePair(operation, infrastructure, machine, profile, port)
		if err != nil {
			return plan.Frozen{}, err
		}
		return pair.Freeze()
	case plan.OperationDeployEntrypoint, plan.OperationRemoveEntrypoint:
		pair, err := plan.BuildEntrypointPair(operation, infrastructure, machine)
		if err != nil {
			return plan.Frozen{}, err
		}
		return pair.Freeze()
	case plan.OperationPublishRoute, plan.OperationRetireRoute:
		pair, err := plan.BuildRoutePair(operation, infrastructure, machine, routeHost, backendPort)
		if err != nil {
			return plan.Frozen{}, err
		}
		return pair.Freeze()
	case plan.OperationDeployPrivateService, plan.OperationRemovePrivateService:
		pair, err := plan.BuildPrivateServicePair(operation, infrastructure, machine, profile, port, originHost)
		if err != nil {
			return plan.Frozen{}, err
		}
		return pair.Freeze()
	case plan.OperationPublishLinkRoute, plan.OperationRetireLinkRoute:
		pair, err := plan.BuildLinkRoutePair(operation, infrastructure, machine, routeHost, backendPort)
		if err != nil {
			return plan.Frozen{}, err
		}
		return pair.Freeze()
	case plan.OperationSnapshotService, plan.OperationDiscardSnapshot:
		pair, err := plan.BuildSnapshotPair(operation, infrastructure, machine, profile, snapshotSlot)
		if err != nil {
			return plan.Frozen{}, err
		}
		return pair.Freeze()
	case plan.OperationRestoreService:
		pair, err := plan.BuildRestorePair(infrastructure, machine, profile, snapshotSlot)
		if err != nil {
			return plan.Frozen{}, err
		}
		return pair.Freeze()
	case plan.OperationPrepareLink, plan.OperationWithdrawLink:
		pair, err := plan.BuildLinkPair(operation, infrastructure, machine, linkRole)
		if err != nil {
			return plan.Frozen{}, err
		}
		return pair.Freeze()
	case plan.OperationAttachLinkPeer, plan.OperationDetachLinkPeer:
		pair, err := plan.BuildListenerPeerPair(operation, infrastructure, machine, peerPublicKey, servicePort)
		if err != nil {
			return plan.Frozen{}, err
		}
		return pair.Freeze()
	case plan.OperationJoinLinkPeer, plan.OperationLeaveLinkPeer:
		pair, err := plan.BuildInitiatorPeerPair(operation, infrastructure, machine,
			peerPublicKey, peerEndpointHost, servicePort)
		if err != nil {
			return plan.Frozen{}, err
		}
		return pair.Freeze()
	case plan.OperationDeployUserService, plan.OperationRemoveUserService:
		return userServicePair(operation, infrastructure, machine, definition,
			imageDigest, port, originHost, hostile, repository)
	default:
		return plan.Frozen{}, fmt.Errorf("the fixture builds no pair for the operation %q", operation)
	}
}

// userServicePair freezes the third door's pair the way a Controller does — and,
// for three hostile presentations, the way a Controller that is *not* this
// package would.
//
// The honest path goes through BuildUserServicePair, which holds the plan against
// the definition it pins at construction. The three hostile ones cannot: the very
// check that makes them hostile is the one that refuses to build them, which is a
// constat of this proof rather than an inconvenience. They are assembled from the
// exported document type instead, encoded and digested by the product's own
// canonical encoder — so the machine receives a document that is valid in every
// way except the agreement it was never held against.
func userServicePair(operation, infrastructure, machine string,
	definition servicedefinition.Document, imageDigest string, port int,
	originHost, hostile, repository string,
) (plan.Frozen, error) {
	if definition.Slug == "" {
		return plan.Frozen{}, fmt.Errorf("a user service plan needs the definition it pins")
	}
	switch hostile {
	case hostileForeignRepository, hostileUnconsumedOrigin, hostileMissingOrigin:
	default:
		pair, err := plan.BuildUserServicePair(operation, infrastructure, machine,
			definition, imageDigest, port, originHost)
		if err != nil {
			return plan.Frozen{}, err
		}
		return pair.Freeze()
	}

	digest, err := definition.SHA256()
	if err != nil {
		return plan.Frozen{}, err
	}
	subject := plan.UserServiceDocument{
		SchemaVersion:    plan.SchemaVersionV2,
		InfrastructureID: infrastructure,
		MachineID:        machine,
		Operation:        operation,
		DefinitionSlug:   definition.Slug,
		DefinitionDigest: digest,
		ImageReference:   definition.ImageRepository,
		ImageDigest:      imageDigest,
		LocalPort:        port,
		OriginHost:       originHost,
	}
	switch hostile {
	case hostileForeignRepository:
		subject.ImageReference = "other." + repository
	case hostileUnconsumedOrigin:
		// The definition consumes no origin and this plan approves one anyway.
	case hostileMissingOrigin:
		subject.OriginHost = ""
	}
	undoing := subject
	switch operation {
	case plan.OperationDeployUserService:
		undoing.Operation = plan.OperationRemoveUserService
	default:
		undoing.Operation = plan.OperationDeployUserService
	}
	return freezeHandBuiltPair(subject, undoing)
}

// freezeHandBuiltPair renders and digests a pair this fixture assembled itself,
// through the product's own encoder and transcript. Nothing of the canonical form
// is spelled a second time here: what is bypassed is the *builder*, which is
// exactly the check under proof, and never the encoding.
func freezeHandBuiltPair(subject, undoing plan.UserServiceDocument) (plan.Frozen, error) {
	planDocument, err := subject.Encode()
	if err != nil {
		return plan.Frozen{}, err
	}
	planDigest, err := subject.SHA256()
	if err != nil {
		return plan.Frozen{}, err
	}
	rollbackDocument, err := undoing.Encode()
	if err != nil {
		return plan.Frozen{}, err
	}
	rollbackDigest, err := undoing.SHA256()
	if err != nil {
		return plan.Frozen{}, err
	}
	return plan.Frozen{
		PlanDocument:     planDocument,
		PlanSHA256:       planDigest,
		RollbackDocument: rollbackDocument,
		RollbackSHA256:   rollbackDigest,
	}, nil
}

func alterLast(value string) string {
	if value == "" {
		return "x"
	}
	last := value[len(value)-1]
	replacement := byte('2')
	if last == '2' {
		replacement = '3'
	}
	return value[:len(value)-1] + string(replacement)
}

func mustDecodeDigest(value string) []byte {
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != plan.DigestBytes {
		fmt.Fprintf(os.Stderr, "the frozen pair named a malformed digest\n")
		os.Exit(1)
	}
	return decoded
}

// ---------------------------------------------------------------------------
// The attestation of a generated value.
//
// It reads a value the machine generated and prints a keyed digest over one fixed
// message — the very computation the application performs inside its container.
// The value never reaches an argument vector, a log or this program's output, and
// comparing the two digests is what makes "the container received exactly the
// value this machine generated" a comparison.
// ---------------------------------------------------------------------------

const attestationMessage = "your-cloud/lab-user-service-attestation.v1"

func printAttestation(path string) error {
	if path == "" {
		return fmt.Errorf("an attestation needs the file the value lives in")
	}
	value, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	mac := hmac.New(sha256.New, bytes.TrimSpace(value))
	mac.Write([]byte(attestationMessage))
	fmt.Printf("ATTESTATION=attested:%s\n", hex.EncodeToString(mac.Sum(nil)))
	return nil
}

// ---------------------------------------------------------------------------
// The origin of the image.
//
// No registry exists in this LAB and no image of a third party may enter this
// proof, so the image the third door pulls is built here out of the synthetic
// application's own static binary, and served here.
//
// What is served is the read half of the OCI distribution API and nothing else:
// the version check, one manifest by digest, and the blobs that manifest names.
// There is no upload, no catalogue, no tag listing and — deliberately — **no tag
// at all**: this origin cannot answer a reference that is not a digest, which is
// the contract's "un tag n'est une identité nulle part dans ce produit" made into
// a property of the origin rather than a rule somebody has to respect.
//
// What this arrangement does not prove is named in the report: it is a static
// tree behind an HTTPS server of this proof's own, not a registry implementation,
// so nothing here establishes how the product behaves against one. What it does
// establish is that the fetch is a real fetch — a rootless engine, over the
// network, to another machine, by digest, against the run's own authority — and
// that a machine whose account is confined can no longer perform it.
// ---------------------------------------------------------------------------

const (
	manifestMediaType = "application/vnd.oci.image.manifest.v1+json"
	configMediaType   = "application/vnd.oci.image.config.v1+json"
	layerMediaType    = "application/vnd.oci.image.layer.v1.tar+gzip"

	manifestFileName = "manifest.json"
	digestFileName   = "manifest.digest"
)

type descriptor struct {
	MediaType string `json:"mediaType"`
	Digest    string `json:"digest"`
	Size      int64  `json:"size"`
}

type imageManifest struct {
	SchemaVersion int          `json:"schemaVersion"`
	MediaType     string       `json:"mediaType"`
	Config        descriptor   `json:"config"`
	Layers        []descriptor `json:"layers"`
}

type imageRootFS struct {
	Type    string   `json:"type"`
	DiffIDs []string `json:"diff_ids"`
}

type imageConfiguration struct {
	Entrypoint []string `json:"Entrypoint"`
	WorkingDir string   `json:"WorkingDir"`
}

type imageConfigurationDocument struct {
	Architecture string             `json:"architecture"`
	OS           string             `json:"os"`
	Config       imageConfiguration `json:"config"`
	RootFS       imageRootFS        `json:"rootfs"`
}

// buildApplicationImage lays one static binary out as an image an engine can
// pull. Everything about it is deterministic — no creation date, no history, a
// tar whose entries carry a fixed time — so that two builds of one binary produce
// one digest and a reader can hold the digest the proof pins against the tree it
// serves.
func buildApplicationImage(binaryPath, directory string) error {
	if binaryPath == "" || directory == "" {
		return fmt.Errorf("building an image needs the application binary and an output directory")
	}
	content, err := os.ReadFile(binaryPath)
	if err != nil {
		return err
	}
	blobs := filepath.Join(directory, "blobs", "sha256")
	if err := os.MkdirAll(blobs, 0o755); err != nil {
		return err
	}

	layer, diffID, err := applicationLayer(content)
	if err != nil {
		return err
	}
	layerDigest, err := writeBlob(blobs, layer)
	if err != nil {
		return err
	}

	configuration, err := json.Marshal(imageConfigurationDocument{
		Architecture: "amd64",
		OS:           "linux",
		Config: imageConfiguration{
			Entrypoint: []string{"/app/synthetic"},
			WorkingDir: "/",
		},
		RootFS: imageRootFS{Type: "layers", DiffIDs: []string{diffID}},
	})
	if err != nil {
		return err
	}
	configDigest, err := writeBlob(blobs, configuration)
	if err != nil {
		return err
	}

	manifest, err := json.Marshal(imageManifest{
		SchemaVersion: 2,
		MediaType:     manifestMediaType,
		Config: descriptor{
			MediaType: configMediaType, Digest: configDigest, Size: int64(len(configuration)),
		},
		Layers: []descriptor{
			{MediaType: layerMediaType, Digest: layerDigest, Size: int64(len(layer))},
		},
	})
	if err != nil {
		return err
	}
	manifestDigest := digestOf(manifest)
	if err := os.WriteFile(filepath.Join(directory, manifestFileName), manifest, 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(directory, digestFileName),
		[]byte(manifestDigest+"\n"), 0o644); err != nil {
		return err
	}
	fmt.Printf("IMAGE_DIGEST=%s\n", manifestDigest)
	fmt.Printf("IMAGE_MANIFEST_BYTES=%d\n", len(manifest))
	fmt.Printf("IMAGE_LAYER_BYTES=%d\n", len(layer))
	return nil
}

// applicationLayer is the whole filesystem of this image: the binary, and the
// three empty directories its mounts are attached to.
//
// The mount points are in the layer rather than left to the engine on purpose. A
// container whose filesystem is read-only cannot have a directory created inside
// it, and an image whose author did not provide the directories their own
// definition declares would be an image whose failures belong to the image. This
// one provides them, which is what makes every failure this proof produces a
// failure of the thing it is about.
func applicationLayer(binary []byte) ([]byte, string, error) {
	uncompressed := &bytes.Buffer{}
	writer := tar.NewWriter(uncompressed)
	fixed := time.Unix(0, 0).UTC()
	for _, directory := range []string{"app/", "srv/", "srv/state/", "srv/content/", "scratch/"} {
		if err := writer.WriteHeader(&tar.Header{
			Typeflag: tar.TypeDir, Name: directory, Mode: 0o755, ModTime: fixed,
		}); err != nil {
			return nil, "", err
		}
	}
	if err := writer.WriteHeader(&tar.Header{
		Typeflag: tar.TypeReg, Name: "app/synthetic",
		Mode: 0o755, Size: int64(len(binary)), ModTime: fixed,
	}); err != nil {
		return nil, "", err
	}
	if _, err := writer.Write(binary); err != nil {
		return nil, "", err
	}
	if err := writer.Close(); err != nil {
		return nil, "", err
	}
	diffID := digestOf(uncompressed.Bytes())

	compressed := &bytes.Buffer{}
	zipper, err := gzip.NewWriterLevel(compressed, gzip.BestCompression)
	if err != nil {
		return nil, "", err
	}
	if _, err := zipper.Write(uncompressed.Bytes()); err != nil {
		return nil, "", err
	}
	if err := zipper.Close(); err != nil {
		return nil, "", err
	}
	return compressed.Bytes(), diffID, nil
}

func writeBlob(directory string, content []byte) (string, error) {
	digest := digestOf(content)
	path := filepath.Join(directory, strings.TrimPrefix(digest, "sha256:"))
	if err := os.WriteFile(path, content, 0o644); err != nil {
		return "", err
	}
	return digest, nil
}

func digestOf(content []byte) string {
	sum := sha256.Sum256(content)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// serveOrigin answers the read half of the distribution API for exactly one
// repository and exactly one manifest, over the run's own TLS.
func serveOrigin(root, repository, listen, certificate, key string) error {
	if root == "" || repository == "" || certificate == "" || key == "" {
		return fmt.Errorf("an origin needs a built image, a repository, a certificate and a key")
	}
	_, path, qualified := strings.Cut(repository, "/")
	if !qualified {
		return fmt.Errorf("the repository %q names no path", repository)
	}
	manifest, err := os.ReadFile(filepath.Join(root, manifestFileName))
	if err != nil {
		return err
	}
	manifestDigest := strings.TrimSpace(string(mustRead(filepath.Join(root, digestFileName))))
	blobs := filepath.Join(root, "blobs", "sha256")

	handler := http.NewServeMux()
	handler.HandleFunc("/v2/", func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Docker-Distribution-API-Version", "registry/2.0")
		if request.URL.Path == "/v2/" {
			response.Header().Set("Content-Type", "application/json")
			fmt.Fprint(response, "{}")
			return
		}
		manifestPrefix := "/v2/" + path + "/manifests/"
		blobPrefix := "/v2/" + path + "/blobs/"
		switch {
		case strings.HasPrefix(request.URL.Path, manifestPrefix):
			reference := strings.TrimPrefix(request.URL.Path, manifestPrefix)
			// A reference that is not the digest this origin holds is answered as
			// absent, and a tag is exactly such a reference: nothing here resolves a
			// name to an image.
			if reference != manifestDigest {
				notFound(response, "MANIFEST_UNKNOWN")
				return
			}
			response.Header().Set("Content-Type", manifestMediaType)
			response.Header().Set("Docker-Content-Digest", manifestDigest)
			writeBody(response, request, manifest)
		case strings.HasPrefix(request.URL.Path, blobPrefix):
			reference := strings.TrimPrefix(request.URL.Path, blobPrefix)
			if !strings.HasPrefix(reference, "sha256:") || strings.ContainsAny(reference, "/.") {
				notFound(response, "BLOB_UNKNOWN")
				return
			}
			content, err := os.ReadFile(filepath.Join(blobs, strings.TrimPrefix(reference, "sha256:")))
			if err != nil {
				notFound(response, "BLOB_UNKNOWN")
				return
			}
			response.Header().Set("Content-Type", "application/octet-stream")
			response.Header().Set("Docker-Content-Digest", reference)
			writeBody(response, request, content)
		default:
			notFound(response, "NAME_UNKNOWN")
		}
	})
	server := &http.Server{
		Addr:              listen,
		Handler:           handler,
		ReadHeaderTimeout: 15 * time.Second,
	}
	return server.ListenAndServeTLS(certificate, key)
}

func writeBody(response http.ResponseWriter, request *http.Request, content []byte) {
	response.Header().Set("Content-Length", fmt.Sprintf("%d", len(content)))
	response.WriteHeader(http.StatusOK)
	if request.Method == http.MethodHead {
		return
	}
	response.Write(content)
}

func notFound(response http.ResponseWriter, code string) {
	response.Header().Set("Content-Type", "application/json")
	response.WriteHeader(http.StatusNotFound)
	fmt.Fprintf(response, `{"errors":[{"code":%q,"message":"this origin serves one image by digest"}]}`, code)
}

func mustRead(path string) []byte {
	content, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read %s: %v\n", path, err)
		os.Exit(1)
	}
	return content
}

// ---------------------------------------------------------------------------
// The synthetic certificate authority of the declared names and of the origin.
//
// The contract puts it in the proof rather than in the product: no plan describes
// a certificate, and the Auxiliary never writes into the directory it reads them
// from. What differs from the private profile's proof is that one of the names
// this authority signs is not a declared name of the product at all — it is the
// origin the images come from, which the LAB owns and the product only pulls
// from.
// ---------------------------------------------------------------------------

const (
	authorityCertificateFile = "authority.crt"
	authorityKeyFile         = "authority.key"
	certificateLifetime      = 24 * time.Hour
	keyBits                  = 2048
)

func createAuthority(directory string) error {
	if directory == "" {
		return fmt.Errorf("an authority needs a directory to live in")
	}
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return err
	}
	key, err := rsa.GenerateKey(rand.Reader, keyBits)
	if err != nil {
		return err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return err
	}
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "your-cloud LAB user service authority"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(certificateLifetime),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
	encoded, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return err
	}
	if err := writePEM(filepath.Join(directory, authorityCertificateFile), "CERTIFICATE", encoded, 0o644); err != nil {
		return err
	}
	encodedKey, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	return writePEM(filepath.Join(directory, authorityKeyFile), "PRIVATE KEY", encodedKey, 0o600)
}

func issueCertificate(authorityDirectory, out, host string) error {
	if authorityDirectory == "" || out == "" || host == "" {
		return fmt.Errorf("issuing needs an authority, an output directory and a name")
	}
	authorityCertificate, authorityKey, err := readAuthority(authorityDirectory)
	if err != nil {
		return err
	}
	key, err := rsa.GenerateKey(rand.Reader, keyBits)
	if err != nil {
		return err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return err
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: host},
		DNSNames:     []string{host},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(certificateLifetime),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	encoded, err := x509.CreateCertificate(rand.Reader, template, authorityCertificate,
		&key.PublicKey, authorityKey)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(out, 0o700); err != nil {
		return err
	}
	if err := writePEM(filepath.Join(out, host+".crt"), "CERTIFICATE", encoded, 0o644); err != nil {
		return err
	}
	encodedKey, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	return writePEM(filepath.Join(out, host+".key"), "PRIVATE KEY", encodedKey, 0o600)
}

func readAuthority(directory string) (*x509.Certificate, *rsa.PrivateKey, error) {
	certificateBytes, err := os.ReadFile(filepath.Join(directory, authorityCertificateFile))
	if err != nil {
		return nil, nil, err
	}
	keyBytes, err := os.ReadFile(filepath.Join(directory, authorityKeyFile))
	if err != nil {
		return nil, nil, err
	}
	certificateBlock, _ := pem.Decode(certificateBytes)
	keyBlock, _ := pem.Decode(keyBytes)
	if certificateBlock == nil || keyBlock == nil {
		return nil, nil, fmt.Errorf("the synthetic authority is not readable as PEM")
	}
	certificate, err := x509.ParseCertificate(certificateBlock.Bytes)
	if err != nil {
		return nil, nil, err
	}
	parsed, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, nil, err
	}
	key, isRSA := parsed.(*rsa.PrivateKey)
	if !isRSA {
		return nil, nil, fmt.Errorf("the synthetic authority does not hold an RSA key")
	}
	return certificate, key, nil
}

func writePEM(path, blockType string, content []byte, mode os.FileMode) error {
	encoded := pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: content})
	if encoded == nil {
		return fmt.Errorf("encode %s", blockType)
	}
	return os.WriteFile(path, encoded, mode)
}

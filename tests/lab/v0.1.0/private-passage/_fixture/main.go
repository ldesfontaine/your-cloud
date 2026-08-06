// Synthetic LAB fixture of the private passage proof. It stands in for the two
// authorities this palier separates and holds neither of them for real:
//
//   - the Controller, which freezes a plan and its rollback — here for three
//     schemas at once, because a passage bounds a service the older schemas
//     deploy;
//   - the Console, which shows the pair to a human and signs the envelope naming
//     their two digests.
//
// The two halves are built from two different sources on purpose, exactly as
// tests/lab/v0.1.0/oci-plan/_fixture and tests/lab/v0.1.0/public-profile/_fixture
// do:
//
//   - the plan documents come from the product's own internal/plan builders, so
//     the bytes an Auxiliary receives here are the canonical bytes a Controller
//     would have frozen and not a second spelling invented by a test;
//   - the envelope transcript is rebuilt by hand below, so the signature this
//     fixture produces is not verified by the same lines that produced it.
//
// One value of this fixture is not chosen by anybody and that is the whole point
// of the palier: `-peer-public-key` is an *observation*. The other machine's
// preparation reported it, the harness read it out of that report, and it enters
// the junction plan of this machine as a literal a human could have read. This
// program never generates a key, never holds a private one and could not: the
// private half of a passage key is born on its machine and never leaves it.
//
// The seed is synthetic and the key material lives only as long as the run.
// Interoperability with the real Console is proven by the pinned cross-language
// vector, never by this program.
package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/ldesfontaine/your-cloud/internal/plan"
)

// The hostile documents this fixture is able to present. Each one is a document
// a Controller could physically transport and no human ever approved.
//
// The refusals this proof cares most about are not in this list at all, and that
// is deliberate: a junction naming a port no managed service publishes, a
// junction on a machine holding no prepared passage, and a withdrawal while a
// junction still stands are *honest* documents, signed as they stand, that the
// machine refuses because of what the machine holds. They are asked for with no
// hostile flag.
const (
	hostileNone             = "none"
	hostileAlteredPlan      = "altered-plan"
	hostileApprovedMismatch = "mismatched-rollback"
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
	machine := flag.String("machine", "lab-machine-1", "machine id")
	operation := flag.String("operation", plan.OperationPrepareLink, "plan operation")
	profile := flag.String("profile", plan.ServiceProfileBentoPDF, "service profile")
	port := flag.Int("port", 18080, "loopback port a schema 1 or schema 2 plan names")
	linkRole := flag.String("link-role", plan.LinkRoleListener, "the side of the passage this plan is for")
	peerPublicKey := flag.String("peer-public-key", "", "the public key the other machine's preparation reported")
	peerEndpointHost := flag.String("peer-endpoint-host", "", "the host the initiator reaches")
	servicePort := flag.Int("service-port", 18180, "the one port the passage carries")
	lifetime := flag.Uint64("lifetime", 900, "lifetime seconds")
	age := flag.Int64("age", 0, "seconds to subtract from the issue time")
	anchorOnly := flag.Bool("anchor", false, "emit the anchor instead of an approval")
	bare := flag.Bool("bare", false, "emit the envelope alone, without its two documents")
	hostile := flag.String("hostile", hostileNone, "the hostile document to present")
	flag.Parse()

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

	// The honest pair, built by the product. Everything a hostile presentation
	// changes below is changed *after* this, so the envelope always names the
	// digests of documents a human could have read.
	frozen, err := freezePair(*operation, *infrastructure, *machine, *profile, *port,
		*linkRole, *peerPublicKey, *peerEndpointHost, *servicePort)
	if err != nil {
		fmt.Fprintf(os.Stderr, "freeze the approved pair: %v\n", err)
		os.Exit(1)
	}

	planDocument := string(frozen.PlanDocument)
	rollbackDocument := string(frozen.RollbackDocument)
	planDigest := frozen.PlanSHA256
	rollbackDigest := frozen.RollbackSHA256
	switch *hostile {
	case hostileNone:
	case hostileAlteredPlan:
		// One byte of the transported document, changed by a Controller after a
		// human read it. It still parses and still validates; what it no longer
		// does is hash to the digest the envelope names.
		planDocument = strings.Replace(planDocument, *machine, alterLast(*machine), 1)
	case hostileApprovedMismatch:
		// The one hostile case a human really signed: a Controller froze a plan
		// beside a rollback that undoes another instance, and the Console signed
		// both digests. Every check upstream of the pair passes, and the refusal
		// has to come from the pair itself.
		other, err := freezePair(*operation, *infrastructure, *machine, *profile, *port+1,
			*linkRole, *peerPublicKey, *peerEndpointHost, *servicePort+1)
		if err != nil {
			fmt.Fprintf(os.Stderr, "freeze the mismatched rollback: %v\n", err)
			os.Exit(1)
		}
		rollbackDocument = string(other.RollbackDocument)
		rollbackDigest = other.RollbackSHA256
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
	// The two privileges of a mutating operation, in the strictly increasing
	// order the envelope requires. Every operation of the passage carries exactly
	// these two, as every mutating operation of the two older schemas does.
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

	if *bare {
		fmt.Println(envelope)
		return
	}

	// The one transport form the contract describes: the two documents travel as
	// JSON strings carrying their exact canonical bytes, so the machine hashes
	// what it was given rather than what it understood.
	planField, err := json.Marshal(planDocument)
	if err != nil {
		fmt.Fprintf(os.Stderr, "carry the plan: %v\n", err)
		os.Exit(1)
	}
	rollbackField, err := json.Marshal(rollbackDocument)
	if err != nil {
		fmt.Fprintf(os.Stderr, "carry the rollback: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("{\"signed_approval\":%s,\"plan\":%s,\"rollback\":%s}\n",
		envelope, planField, rollbackField)
}

// freezePair asks the product's own builder for the pair of the operation named,
// and refuses to guess which of the five shapes an unknown operation would be.
//
// The builders are separate in the product because the field lists are closed
// and share nothing; they are separate here for the same reason, so that a peer
// key can never end up inside a probe document and a service port can never end
// up where a loopback port belongs.
func freezePair(operation, infrastructure, machine, profile string, port int,
	linkRole, peerPublicKey, peerEndpointHost string, servicePort int) (plan.Frozen, error) {
	switch operation {
	case plan.OperationDeployOCIProbe, plan.OperationRemoveOCIProbe:
		pair, err := plan.BuildPair(operation, infrastructure, machine, port)
		if err != nil {
			return plan.Frozen{}, err
		}
		return pair.Freeze()
	case plan.OperationDeployWebService, plan.OperationRemoveWebService:
		pair, err := plan.BuildWebServicePair(operation, infrastructure, machine, profile, port)
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
	default:
		return plan.Frozen{}, fmt.Errorf("the fixture builds no pair for the operation %q", operation)
	}
}

// alterLast changes the last character of a value without leaving the shape its
// own validation requires, so that the refusal drawn is the digest comparison
// and never a malformed field.
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

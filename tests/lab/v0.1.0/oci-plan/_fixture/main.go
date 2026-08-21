// Synthetic LAB fixture. It stands in for the two authorities this palier
// separates and holds neither of them for real: the Controller, which freezes a
// plan and its rollback, and the App, which shows them to a human and signs
// the envelope naming their two digests.
//
// Two halves, two different sources on purpose:
//
//   - the plan documents come from the product's own internal/plan builder, so
//     the bytes an Auxiliary receives here are the canonical bytes a Controller
//     would have frozen and not a second spelling invented by a test;
//   - the envelope transcript is rebuilt by hand below, exactly as
//     tests/lab/v0.1.0/signed-approval/_signer does, so the signature this
//     fixture produces is not verified by the same lines that produced it.
//
// The seed is synthetic and the key material lives only as long as the run.
// Interoperability with the real App is proven by the pinned cross-language
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
// a Controller could physically transport and no human ever approved; the names
// are the ones the harness prints beside the refusal each is supposed to draw.
const (
	hostileNone            = "none"
	hostileAlteredPlan     = "altered-plan"
	hostileTaggedReference = "tagged-reference"
	hostileForeignRegistry = "foreign-registry"
	hostilePortOutOfRange  = "port-out-of-range"
	hostileSmuggledVolume  = "smuggled-volume"
	// hostileApprovedMismatch is the one hostile case a human really signed: a
	// Controller froze a plan beside a rollback that undoes another instance,
	// and the App signed both digests. Every check upstream of the pair
	// passes, and the refusal has to come from the pair itself.
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
	operation := flag.String("operation", plan.OperationDeployOCIProbe, "plan operation")
	port := flag.Int("port", 18080, "local port the probe answers on")
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
	pair, err := plan.BuildPair(*operation, *infrastructure, *machine, *port)
	if err != nil {
		fmt.Fprintf(os.Stderr, "build the approved pair: %v\n", err)
		os.Exit(1)
	}
	frozen, err := pair.Freeze()
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
	case hostileTaggedReference:
		planDocument = rewriteField(planDocument, "image_reference", plan.ProbeImageReference+":v1.11.0")
	case hostileForeignRegistry:
		planDocument = rewriteField(planDocument, "image_reference", "registry.invalid/traefik/whoami")
	case hostilePortOutOfRange:
		planDocument = rewriteNumber(planDocument, "local_port", 80)
	case hostileSmuggledVolume:
		planDocument = strings.TrimSuffix(planDocument, "}") + `,"volume":"/etc:/etc:ro"}`
	case hostileApprovedMismatch:
		other, err := plan.BuildPair(*operation, *infrastructure, *machine, *port+1)
		if err != nil {
			fmt.Fprintf(os.Stderr, "build the mismatched rollback: %v\n", err)
			os.Exit(1)
		}
		frozenOther, err := other.Freeze()
		if err != nil {
			fmt.Fprintf(os.Stderr, "freeze the mismatched rollback: %v\n", err)
			os.Exit(1)
		}
		rollbackDocument = string(frozenOther.RollbackDocument)
		rollbackDigest = frozenOther.RollbackSHA256
	default:
		fmt.Fprintf(os.Stderr, "unknown hostile document %q\n", *hostile)
		os.Exit(2)
	}

	envelopeOperation := *operation
	issued := uint64(time.Now().UTC().Unix() - *age)
	expires := issued + *lifetime

	transcript := []byte("your-cloud/approval-envelope.v1\x00")
	transcript = append(transcript, 1)
	transcript = field(transcript, []byte(*infrastructure))
	transcript = field(transcript, []byte(*machine))
	transcript = be64(transcript, *epoch)
	transcript = be64(transcript, *sequence)
	transcript = field(transcript, []byte(envelopeOperation))
	transcript = field(transcript, mustDecodeDigest(planDigest))
	transcript = field(transcript, mustDecodeDigest(rollbackDigest))
	// The two privileges of a mutating operation, in the strictly increasing
	// order the envelope requires. A different order is a different document.
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
		*infrastructure, *machine, *epoch, *sequence, envelopeOperation,
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

func rewriteField(document, name, value string) string {
	prefix := fmt.Sprintf("%q:", name)
	start := strings.Index(document, prefix)
	if start < 0 {
		fmt.Fprintf(os.Stderr, "the canonical plan carries no field %q\n", name)
		os.Exit(1)
	}
	rest := document[start+len(prefix):]
	end := strings.Index(rest[1:], `"`)
	if rest[0] != '"' || end < 0 {
		fmt.Fprintf(os.Stderr, "the field %q is not a string in the canonical plan\n", name)
		os.Exit(1)
	}
	return document[:start] + prefix + fmt.Sprintf("%q", value) + rest[end+2:]
}

func rewriteNumber(document, name string, value int) string {
	prefix := fmt.Sprintf("%q:", name)
	start := strings.Index(document, prefix)
	if start < 0 {
		fmt.Fprintf(os.Stderr, "the canonical plan carries no field %q\n", name)
		os.Exit(1)
	}
	rest := document[start+len(prefix):]
	end := 0
	for end < len(rest) && rest[end] >= '0' && rest[end] <= '9' {
		end++
	}
	if end == 0 {
		fmt.Fprintf(os.Stderr, "the field %q is not a number in the canonical plan\n", name)
		os.Exit(1)
	}
	return document[:start] + prefix + fmt.Sprintf("%d", value) + rest[end:]
}

func mustDecodeDigest(value string) []byte {
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != plan.DigestBytes {
		fmt.Fprintf(os.Stderr, "the frozen pair named a malformed digest\n")
		os.Exit(1)
	}
	return decoded
}

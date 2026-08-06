// Synthetic LAB fixture of the public profile proof. It stands in for the three
// authorities this palier separates and holds none of them for real:
//
//   - the Controller, which freezes a schema 2 plan and its rollback;
//   - the Console, which shows the pair to a human and signs the envelope naming
//     their two digests;
//   - the certificate authority of the declared names, which the contract says
//     belongs to the proof and never to the Auxiliary — no plan describes a
//     certificate, and the Auxiliary never writes into the directory it reads
//     them from.
//
// The first two halves are built from two different sources on purpose, exactly
// as tests/lab/v0.1.0/oci-plan/_fixture does:
//
//   - the plan documents come from the product's own internal/plan builder, so
//     the bytes an Auxiliary receives here are the canonical bytes a Controller
//     would have frozen and not a second spelling invented by a test;
//   - the envelope transcript is rebuilt by hand below, so the signature this
//     fixture produces is not verified by the same lines that produced it.
//
// The third half shares nothing with the product at all: it is Go's own x509,
// and the key material it mints lives only as long as the run's state directory.
// Interoperability with the real Console is proven by the pinned cross-language
// vector, never by this program.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
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
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ldesfontaine/your-cloud/internal/plan"
)

// The hostile documents this fixture is able to present. Each one is a document
// a Controller could physically transport and no human ever approved; the names
// are the ones the harness prints beside the refusal each is supposed to draw.
//
// The refusals this proof cares most about are not in this list at all, and that
// is the point: a route towards a port nothing manages and a removal of an entry
// that still publishes routes are *honest* documents, signed as they stand, that
// the machine refuses because of what the machine holds. They are asked for with
// no hostile flag.
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
	machine := flag.String("machine", "lab-vps", "machine id")
	operation := flag.String("operation", plan.OperationDeployWebService, "plan operation")
	profile := flag.String("profile", plan.ServiceProfileBentoPDF, "service profile")
	port := flag.Int("port", 18800, "loopback port the managed service publishes")
	routeHost := flag.String("route-host", "", "the declared name a route serves")
	backendPort := flag.Int("backend-port", 18800, "the loopback port a route names")
	lifetime := flag.Uint64("lifetime", 900, "lifetime seconds")
	age := flag.Int64("age", 0, "seconds to subtract from the issue time")
	anchorOnly := flag.Bool("anchor", false, "emit the anchor instead of an approval")
	bare := flag.Bool("bare", false, "emit the envelope alone, without its two documents")
	hostile := flag.String("hostile", hostileNone, "the hostile document to present")
	authority := flag.Bool("authority", false, "create the synthetic certificate authority")
	issue := flag.Bool("issue", false, "issue a certificate for -route-host under that authority")
	authorityDirectory := flag.String("authority-directory", "", "where the synthetic authority lives")
	out := flag.String("out", "", "where an issued certificate and key are written")
	flag.Parse()

	switch {
	case *authority:
		if err := createAuthority(*authorityDirectory); err != nil {
			fmt.Fprintf(os.Stderr, "create the synthetic authority: %v\n", err)
			os.Exit(1)
		}
		return
	case *issue:
		if err := issueCertificate(*authorityDirectory, *out, *routeHost); err != nil {
			fmt.Fprintf(os.Stderr, "issue the certificate of %s: %v\n", *routeHost, err)
			os.Exit(1)
		}
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

	// The honest pair, built by the product. Everything a hostile presentation
	// changes below is changed *after* this, so the envelope always names the
	// digests of documents a human could have read.
	pair, err := buildPair(*operation, *infrastructure, *machine, *profile, *port, *routeHost, *backendPort)
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
	case hostileApprovedMismatch:
		// The one hostile case a human really signed: a Controller froze a plan
		// beside a rollback that undoes another instance, and the Console signed
		// both digests. Every check upstream of the pair passes, and the refusal
		// has to come from the pair itself.
		other, err := buildPair(*operation, *infrastructure, *machine, *profile, *port+1, *routeHost, *backendPort+1)
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

// buildPair asks the product's own builder for the pair of the operation named,
// and refuses to guess which of the three shapes an unknown operation would be.
//
// The three builders are separate in the product because the three field lists
// are closed and share nothing; they are separate here for the same reason, so
// that a route argument can never end up inside a web service document.
func buildPair(operation, infrastructure, machine, profile string, port int, routeHost string, backendPort int) (plan.V2Pair, error) {
	switch operation {
	case plan.OperationDeployWebService, plan.OperationRemoveWebService:
		return plan.BuildWebServicePair(operation, infrastructure, machine, profile, port)
	case plan.OperationDeployEntrypoint, plan.OperationRemoveEntrypoint:
		return plan.BuildEntrypointPair(operation, infrastructure, machine)
	case plan.OperationPublishRoute, plan.OperationRetireRoute:
		return plan.BuildRoutePair(operation, infrastructure, machine, routeHost, backendPort)
	default:
		return plan.V2Pair{}, fmt.Errorf("the fixture builds no pair for the operation %q", operation)
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

// ---------------------------------------------------------------------------
// The synthetic certificate authority of the declared names.
//
// The contract puts it here rather than in the product on purpose: no plan
// describes a certificate, the Auxiliary never writes into the directory it
// reads them from, and a removal of the entrypoint therefore does not take them
// away. What the palier proves is HTTPS on a declared name inside the LAB, with
// the proof's own client pinning this authority — not a public issuance.
// ---------------------------------------------------------------------------

const (
	authorityCertificateFile = "authority.crt"
	authorityKeyFile         = "authority.key"
	// certificateLifetime is short because this material exists for one run. It
	// is still long enough that a slow proof cannot be failed by its own clock.
	certificateLifetime = 24 * time.Hour
	// keyBits is deliberate rather than incidental: the harness signs with RSA
	// so that a reader can hold the certificate against any client, and 2048 is
	// what a synthetic authority of a single run needs.
	keyBits = 2048
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
		Subject:               pkix.Name{CommonName: "your-cloud LAB synthetic authority"},
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
		return fmt.Errorf("issuing needs an authority, an output directory and a declared name")
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

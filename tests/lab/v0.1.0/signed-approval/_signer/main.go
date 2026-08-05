// Synthetic LAB fixture. It stands in for the Console core: same canonical
// transcript, same Ed25519 key handling, a synthetic seed and nothing else. The
// interoperability of this encoding with the real Console is proven separately
// by the pinned cross-language vector, not by this program.
package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"time"
)

func field(b []byte, v []byte) []byte {
	var l [4]byte
	binary.BigEndian.PutUint32(l[:], uint32(len(v)))
	return append(append(b, l[:]...), v...)
}
func be64(b []byte, v uint64) []byte {
	var e [8]byte
	binary.BigEndian.PutUint64(e[:], v)
	return append(b, e[:]...)
}

func main() {
	seedByte := flag.Int("seed", 1, "synthetic seed byte")
	epoch := flag.Uint64("epoch", 1, "approval epoch")
	sequence := flag.Uint64("sequence", 1, "approval sequence")
	infra := flag.String("infrastructure", "8f14e45f-ceea-4167-a8b1-1f7bd0a0f4c2", "infrastructure id")
	machine := flag.String("machine", "lab-machine-1", "machine id")
	privilege := flag.String("privilege", "read_local_state", "privilege")
	operation := flag.String("operation", "diagnose_protocol_read_only", "operation")
	lifetime := flag.Uint64("lifetime", 300, "lifetime seconds")
	// Backdates or postdates the issue time so a LAB run can present an
	// approval that really is expired, or not valid yet, at the instant the
	// Auxiliary reads its own clock.
	age := flag.Int64("age", 0, "seconds to subtract from the issue time")
	anchorOnly := flag.Bool("anchor", false, "emit the anchor instead of an approval")
	flag.Parse()

	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(*seedByte)
	}
	private := ed25519.NewKeyFromSeed(seed)
	public := private.Public().(ed25519.PublicKey)
	publicB64 := base64.RawURLEncoding.EncodeToString(public)

	if *anchorOnly {
		fmt.Printf("{\"schema_version\":1,\"infrastructure_id\":%q,\"machine_id\":%q,\"approval_epoch\":%d,\"approval_public_key\":%q}\n",
			*infra, *machine, *epoch, publicB64)
		return
	}

	plan := sha256.Sum256([]byte("diagnose protocol read only"))
	rollback := sha256.Sum256([]byte("no change to roll back"))
	issued := uint64(time.Now().UTC().Unix() - *age)
	expires := issued + *lifetime

	t := []byte("your-cloud/approval-envelope.v1\x00")
	t = append(t, 1)
	t = field(t, []byte(*infra))
	t = field(t, []byte(*machine))
	t = be64(t, *epoch)
	t = be64(t, *sequence)
	t = field(t, []byte(*operation))
	t = field(t, plan[:])
	t = field(t, rollback[:])
	var c [4]byte
	binary.BigEndian.PutUint32(c[:], 1)
	t = append(t, c[:]...)
	t = field(t, []byte(*privilege))
	t = be64(t, issued)
	t = be64(t, expires)
	t = field(t, public)

	signature := base64.RawURLEncoding.EncodeToString(ed25519.Sign(private, t))
	fmt.Fprintf(os.Stdout,
		"{\"envelope\":{\"schema_version\":1,\"infrastructure_id\":%q,\"machine_id\":%q,\"approval_epoch\":%d,\"sequence\":%d,\"operation\":%q,\"plan_sha256\":%q,\"rollback_sha256\":%q,\"privileges\":[%q],\"issued_at_unix_seconds\":%d,\"expires_at_unix_seconds\":%d,\"approval_public_key\":%q},\"signature\":%q}\n",
		*infra, *machine, *epoch, *sequence, *operation,
		hex.EncodeToString(plan[:]), hex.EncodeToString(rollback[:]),
		*privilege, issued, expires, publicB64, signature)
}

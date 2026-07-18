package relay

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/ldesfontaine/your-cloud/internal/securefile"
)

const (
	// CandidateManifestPath is intentionally fixed: a command-line argument
	// must not turn an arbitrary user-controlled file into Relay authority.
	CandidateManifestPath = "/etc/your-cloud/relay-candidate.json"
	maxCandidateBytes     = 256
)

type candidateManifest struct {
	Schema int
	Role   string
}

// LoadCandidate proves that root explicitly provisioned this machine before
// the Relay opens a socket. The marker grants no identity or privilege.
func LoadCandidate(path string) error {
	data, err := securefile.ReadRootOwned(path, maxCandidateBytes)
	if err != nil {
		return err
	}
	_, err = decodeCandidate(data)
	return err
}

func decodeCandidate(data []byte) (candidateManifest, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := openCandidateObject(decoder); err != nil {
		return candidateManifest{}, err
	}

	var manifest candidateManifest
	seen := make(map[string]struct{}, 2)
	for decoder.More() {
		if err := decodeCandidateField(decoder, &manifest, seen); err != nil {
			return candidateManifest{}, err
		}
	}
	if err := closeCandidateObject(decoder); err != nil {
		return candidateManifest{}, err
	}
	if len(seen) != 2 {
		return candidateManifest{}, errors.New("candidate manifest is missing a required field")
	}
	if manifest.Schema != 1 || manifest.Role != "relay-candidate" {
		return candidateManifest{}, errors.New("candidate manifest has an unsupported schema or role")
	}
	return manifest, nil
}

func openCandidateObject(decoder *json.Decoder) error {
	start, err := decoder.Token()
	if err != nil || start != json.Delim('{') {
		return errors.New("candidate manifest must be one JSON object")
	}
	return nil
}

func decodeCandidateField(decoder *json.Decoder, manifest *candidateManifest, seen map[string]struct{}) error {
	token, err := decoder.Token()
	if err != nil {
		return errors.New("candidate manifest contains an invalid field")
	}
	key, ok := token.(string)
	if !ok {
		return errors.New("candidate manifest field name is invalid")
	}
	if _, duplicate := seen[key]; duplicate {
		return fmt.Errorf("candidate manifest repeats field %q", key)
	}
	seen[key] = struct{}{}

	switch key {
	case "schema":
		err = decoder.Decode(&manifest.Schema)
	case "role":
		err = decoder.Decode(&manifest.Role)
	default:
		return fmt.Errorf("candidate manifest contains unknown field %q", key)
	}
	if err != nil {
		return fmt.Errorf("candidate manifest field %q is invalid", key)
	}
	return nil
}

func closeCandidateObject(decoder *json.Decoder) error {
	if end, err := decoder.Token(); err != nil || end != json.Delim('}') {
		return errors.New("candidate manifest is incomplete")
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return errors.New("candidate manifest must contain only one JSON object")
	}
	return nil
}

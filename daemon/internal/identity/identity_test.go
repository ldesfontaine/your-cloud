package identity

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"testing"

	telemetryv1 "github.com/lucas-desfontaine/your-cloud/protocole/gen/go"
)

func TestIdentityPersistsAndSignsExactPayload(t *testing.T) {
	dir := t.TempDir()
	first, err := LoadOrCreate(dir)
	if err != nil {
		t.Fatal(err)
	}
	second, err := LoadOrCreate(dir)
	if err != nil {
		t.Fatal(err)
	}
	if first.KeyID() != second.KeyID() {
		t.Fatal("identité non persistante")
	}
	publicRaw, err := base64.StdEncoding.DecodeString(first.PublicBase64())
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("etat exact")
	signature := first.Sign(telemetryv1.TelemetryStream_TELEMETRY_STREAM_STATE, payload)
	if !Verify(ed25519.PublicKey(publicRaw), telemetryv1.TelemetryStream_TELEMETRY_STREAM_STATE, payload, signature) {
		t.Fatal("signature refusée")
	}
	if Verify(ed25519.PublicKey(publicRaw), telemetryv1.TelemetryStream_TELEMETRY_STREAM_STATE, bytes.ReplaceAll(payload, []byte("exact"), []byte("modif")), signature) {
		t.Fatal("payload modifié accepté")
	}
	if Verify(ed25519.PublicKey(publicRaw), telemetryv1.TelemetryStream_TELEMETRY_STREAM_EVENT, payload, signature) {
		t.Fatal("changement de flux accepté")
	}
}

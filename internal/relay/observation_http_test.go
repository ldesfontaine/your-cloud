package relay

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ldesfontaine/your-cloud/internal/observation"
)

func TestObservationHandlerRechecksCertificateAndAcknowledgesDurableState(t *testing.T) {
	t.Parallel()
	store, err := OpenObservationStore(privateRelayDirectory(t))
	if err != nil {
		t.Fatal(err)
	}
	certificate := &x509.Certificate{Raw: []byte("client")}
	revoked := false
	handler, err := NewObservationHandler(store, func(received *x509.Certificate) (string, error) {
		if revoked || !bytes.Equal(received.Raw, certificate.Raw) {
			return "", io.EOF
		}
		return "lab-machine-1", nil
	})
	if err != nil {
		t.Fatal(err)
	}
	handler.now = func() time.Time { return time.Date(2026, 7, 18, 12, 1, 0, 0, time.UTC) }
	envelope := relayTestEnvelope(t, 1, nil)
	encoded, _ := envelope.Encode()

	response := postObservation(handler, certificate, encoded, "")
	if response.Code != http.StatusOK {
		t.Fatalf("valid observation refused: %d %s", response.Code, response.Body.String())
	}
	var ack observationAck
	if err := json.Unmarshal(response.Body.Bytes(), &ack); err != nil || ack.Sequence != 1 || ack.MachineID != "lab-machine-1" || ack.AlreadyPresent {
		t.Fatalf("unexpected acknowledgement: %#v %v", ack, err)
	}

	revoked = true
	response = postObservation(handler, certificate, encoded, "")
	if response.Code != http.StatusForbidden {
		t.Fatalf("revocation on reused certificate was not rechecked: %d", response.Code)
	}
}

func TestObservationHandlerRefusesHostileBoundary(t *testing.T) {
	t.Parallel()
	store, err := OpenObservationStore(privateRelayDirectory(t))
	if err != nil {
		t.Fatal(err)
	}
	certificate := &x509.Certificate{Raw: []byte("client")}
	handler, err := NewObservationHandler(store, func(*x509.Certificate) (string, error) {
		return "lab-machine-1", nil
	})
	if err != nil {
		t.Fatal(err)
	}
	envelope := relayTestEnvelope(t, 1, nil)
	encoded, _ := envelope.Encode()

	tests := []struct {
		name        string
		certificate *x509.Certificate
		body        []byte
		query       string
		contentType string
		want        int
	}{
		{name: "missing certificate", body: encoded, contentType: "application/json", want: http.StatusForbidden},
		{name: "query", certificate: certificate, body: encoded, query: "?free=true", contentType: "application/json", want: http.StatusBadRequest},
		{name: "wrong content type", certificate: certificate, body: encoded, contentType: "text/plain", want: http.StatusUnsupportedMediaType},
		{name: "unknown field", certificate: certificate, body: append(encoded[:len(encoded)-1], []byte(`,"command":"id"}`)...), contentType: "application/json", want: http.StatusUnprocessableEntity},
		{name: "too large", certificate: certificate, body: bytes.Repeat([]byte("x"), observation.MaxMessageBytes+1), contentType: "application/json", want: http.StatusRequestEntityTooLarge},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			response := postObservationWithType(handler, test.certificate, test.body, test.query, test.contentType)
			if response.Code != test.want {
				t.Fatalf("status=%d want=%d body=%s", response.Code, test.want, response.Body.String())
			}
		})
	}
}

func postObservation(handler http.Handler, certificate *x509.Certificate, body []byte, query string) *httptest.ResponseRecorder {
	return postObservationWithType(handler, certificate, body, query, "application/json")
}

func postObservationWithType(handler http.Handler, certificate *x509.Certificate, body []byte, query, contentType string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(http.MethodPost, "https://relay.observation.your-cloud.test/v0/observations"+query, bytes.NewReader(body))
	request.Header.Set("Content-Type", contentType)
	if certificate != nil {
		request.TLS.PeerCertificates = []*x509.Certificate{certificate}
	} else {
		request.TLS = nil
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

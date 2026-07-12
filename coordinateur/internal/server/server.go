package server

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/lucas-desfontaine/your-cloud/coordinateur/internal/config"
	"github.com/lucas-desfontaine/your-cloud/coordinateur/internal/registry"
	"github.com/lucas-desfontaine/your-cloud/coordinateur/internal/store"
	telemetryv1 "github.com/lucas-desfontaine/your-cloud/protocole/gen/go"
)

const (
	maxEnvelopeBytes = 256 * 1024
	maxPageBytes     = 1024 * 1024
	maxPageItems     = 64
)

var signatureDomain = []byte("your-cloud.telemetry.v1\x00")

type Server struct {
	config   config.Config
	registry *registry.Registry
	store    *store.Store
	http     *http.Server
}

func New(cfg config.Config, identities *registry.Registry, database *store.Store) (*Server, error) {
	tlsConfig, err := transportTLS(cfg)
	if err != nil {
		return nil, err
	}
	result := &Server{config: cfg, registry: identities, store: database}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/telemetry/{machine}", result.publish)
	mux.HandleFunc("GET /v1/state/{machine}", result.current)
	mux.HandleFunc("GET /v1/events/{machine}", result.events)
	result.http = &http.Server{
		Addr: cfg.ListenAddress, Handler: mux, TLSConfig: tlsConfig,
		ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second,
		WriteTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second,
		MaxHeaderBytes: 16 * 1024,
	}
	return result, nil
}

func transportTLS(cfg config.Config) (*tls.Config, error) {
	certificate, err := tls.LoadX509KeyPair(cfg.CertificateFile, cfg.PrivateKeyFile)
	if err != nil {
		return nil, fmt.Errorf("charger l'identité TLS du coordinateur: %w", err)
	}
	caPEM, err := os.ReadFile(cfg.ClientCAFile)
	if err != nil {
		return nil, fmt.Errorf("lire l'autorité cliente: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("autorité cliente PEM invalide")
	}
	return &tls.Config{
		MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{certificate},
		ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool,
		NextProtos: []string{"http/1.1"},
	}, nil
}

func (s *Server) Run() error {
	err := s.http.ListenAndServeTLS("", "")
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func (s *Server) Shutdown(ctx context.Context) error { return s.http.Shutdown(ctx) }

func clientName(request *http.Request) (string, bool) {
	if request.TLS == nil || len(request.TLS.PeerCertificates) < 1 {
		return "", false
	}
	name := request.TLS.PeerCertificates[0].Subject.CommonName
	return name, name != ""
}

func protobufResponse(writer http.ResponseWriter, status int, message proto.Message) {
	body, err := proto.MarshalOptions{Deterministic: true}.Marshal(message)
	if err != nil {
		http.Error(writer, "réponse indisponible", http.StatusInternalServerError)
		return
	}
	writer.Header().Set("Content-Type", "application/x-protobuf")
	writer.Header().Set("Content-Length", strconv.Itoa(len(body)))
	writer.WriteHeader(status)
	_, _ = writer.Write(body)
}

func (s *Server) publish(writer http.ResponseWriter, request *http.Request) {
	machineID := request.PathValue("machine")
	name, ok := clientName(request)
	if !ok || name != "daemon:"+machineID {
		http.Error(writer, "identité de transport refusée", http.StatusForbidden)
		return
	}
	request.Body = http.MaxBytesReader(writer, request.Body, maxEnvelopeBytes)
	body, err := io.ReadAll(request.Body)
	if err != nil || len(body) == 0 {
		http.Error(writer, "enveloppe absente ou trop grande", http.StatusRequestEntityTooLarge)
		return
	}
	keyID, public, ok := s.registry.Identity(machineID)
	if !ok {
		http.Error(writer, "machine non autorisée", http.StatusForbidden)
		return
	}
	envelope, sequence, observedAt, err := validateEnvelope(machineID, keyID, public, body)
	if err != nil {
		http.Error(writer, "enveloppe refusée", http.StatusUnprocessableEntity)
		return
	}
	already, err := s.store.Save(request.Context(), machineID, keyID, envelope.Stream, sequence, observedAt, body)
	if err != nil {
		http.Error(writer, "télémétrie non conservée", http.StatusConflict)
		return
	}
	protobufResponse(writer, http.StatusOK, &telemetryv1.PublishAck{
		SchemaVersion: 1, MachineId: machineID, Stream: envelope.Stream,
		Sequence: sequence, AlreadyPresent: already,
	})
}

func validateEnvelope(machineID, keyID string, public ed25519.PublicKey, body []byte) (*telemetryv1.SignedEnvelope, uint64, int64, error) {
	envelope := &telemetryv1.SignedEnvelope{}
	if err := proto.Unmarshal(body, envelope); err != nil {
		return nil, 0, 0, err
	}
	if envelope.SchemaVersion != 1 || envelope.KeyId != keyID || len(envelope.Payload) == 0 {
		return nil, 0, 0, fmt.Errorf("enveloppe incohérente")
	}
	signed := make([]byte, 0, len(signatureDomain)+1+len(envelope.Payload))
	signed = append(signed, signatureDomain...)
	signed = append(signed, byte(envelope.Stream))
	signed = append(signed, envelope.Payload...)
	if !ed25519.Verify(public, signed, envelope.Signature) {
		return nil, 0, 0, fmt.Errorf("signature invalide")
	}
	switch envelope.Stream {
	case telemetryv1.TelemetryStream_TELEMETRY_STREAM_STATE:
		message := &telemetryv1.MachineState{}
		if err := proto.Unmarshal(envelope.Payload, message); err != nil || message.SchemaVersion != 1 || message.MachineId != machineID || message.Sequence == 0 || len(message.Units) > 32 {
			return nil, 0, 0, fmt.Errorf("état invalide")
		}
		return envelope, message.Sequence, message.ObservedAtUnix, nil
	case telemetryv1.TelemetryStream_TELEMETRY_STREAM_EVENT:
		message := &telemetryv1.MachineEvent{}
		if err := proto.Unmarshal(envelope.Payload, message); err != nil || message.SchemaVersion != 1 || message.MachineId != machineID || message.Sequence == 0 || len(message.Kind) > 128 || len(message.Detail) > 1024 {
			return nil, 0, 0, fmt.Errorf("événement invalide")
		}
		return envelope, message.Sequence, message.ObservedAtUnix, nil
	default:
		return nil, 0, 0, fmt.Errorf("flux inconnu")
	}
}

func consoleAllowed(request *http.Request) bool {
	name, ok := clientName(request)
	return ok && strings.HasPrefix(name, "console:") && len(name) > len("console:")
}

func (s *Server) current(writer http.ResponseWriter, request *http.Request) {
	if !consoleAllowed(request) {
		http.Error(writer, "identité de lecture refusée", http.StatusForbidden)
		return
	}
	body, err := s.store.Current(request.Context(), request.PathValue("machine"))
	if errors.Is(err, sql.ErrNoRows) {
		http.Error(writer, "état absent", http.StatusNotFound)
		return
	}
	if err != nil {
		http.Error(writer, "état indisponible", http.StatusInternalServerError)
		return
	}
	writer.Header().Set("Content-Type", "application/x-protobuf")
	writer.Header().Set("Content-Length", strconv.Itoa(len(body)))
	writer.WriteHeader(http.StatusOK)
	_, _ = writer.Write(body)
}

func (s *Server) events(writer http.ResponseWriter, request *http.Request) {
	if !consoleAllowed(request) {
		http.Error(writer, "identité de lecture refusée", http.StatusForbidden)
		return
	}
	after, err := strconv.ParseUint(request.URL.Query().Get("after"), 10, 64)
	if request.URL.Query().Get("after") == "" {
		after, err = 0, nil
	}
	limit, limitErr := strconv.Atoi(request.URL.Query().Get("limit"))
	if request.URL.Query().Get("limit") == "" {
		limit, limitErr = maxPageItems, nil
	}
	if err != nil || limitErr != nil || limit < 1 || limit > maxPageItems {
		http.Error(writer, "pagination invalide", http.StatusBadRequest)
		return
	}
	encoded, next, hasMore, err := s.store.Events(request.Context(), request.PathValue("machine"), after, limit)
	if err != nil {
		http.Error(writer, "journal indisponible", http.StatusInternalServerError)
		return
	}
	page := &telemetryv1.EnvelopePage{SchemaVersion: 1, NextAfterSequence: next, HasMore: hasMore}
	size := 0
	for _, item := range encoded {
		if size+len(item) > maxPageBytes {
			page.HasMore = true
			break
		}
		envelope := &telemetryv1.SignedEnvelope{}
		if err := proto.Unmarshal(item, envelope); err != nil {
			http.Error(writer, "journal corrompu", http.StatusInternalServerError)
			return
		}
		page.Envelopes = append(page.Envelopes, envelope)
		size += len(item)
		var event telemetryv1.MachineEvent
		if err := proto.Unmarshal(envelope.Payload, &event); err == nil {
			page.NextAfterSequence = event.Sequence
		}
	}
	protobufResponse(writer, http.StatusOK, page)
}

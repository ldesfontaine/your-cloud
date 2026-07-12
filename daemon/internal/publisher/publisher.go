package publisher

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"strings"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/ldesfontaine/yourcloud/daemon/internal/config"
	"github.com/ldesfontaine/yourcloud/daemon/internal/store"
	telemetryv1 "github.com/ldesfontaine/yourcloud/protocole/gen/go"
)

const maxResponseBytes = 64 * 1024

type endpoint struct {
	url    string
	client *http.Client
}

// Publisher relaie la file locale vers les coordinateurs préautorisés.
type Publisher struct {
	machineID string
	endpoints []endpoint
	store     *store.Store
}

// New construit les clients mTLS des seuls coordinateurs déclarés.
func New(machineID string, coordinators []config.Coordinator, database *store.Store) (*Publisher, error) {
	result := &Publisher{machineID: machineID, store: database}
	for _, coordinator := range coordinators {
		certificate, err := tls.LoadX509KeyPair(coordinator.CertificateFile, coordinator.PrivateKeyFile)
		if err != nil {
			return nil, fmt.Errorf("charger l'identité mTLS du daemon: %w", err)
		}
		caPEM, err := os.ReadFile(coordinator.CAFile)
		if err != nil {
			return nil, fmt.Errorf("lire l'autorité du coordinateur: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPEM) {
			return nil, fmt.Errorf("autorité du coordinateur invalide")
		}
		transport := &http.Transport{
			TLSClientConfig:    &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: pool, Certificates: []tls.Certificate{certificate}},
			DisableCompression: true, MaxIdleConns: 2, MaxIdleConnsPerHost: 1,
			IdleConnTimeout: 30 * time.Second, TLSHandshakeTimeout: 5 * time.Second,
		}
		result.endpoints = append(result.endpoints, endpoint{
			url:    strings.TrimSuffix(coordinator.URL, "/") + "/v1/telemetry/" + machineID,
			client: &http.Client{Transport: transport, Timeout: 10 * time.Second},
		})
	}
	return result, nil
}

// Run republie avec une temporisation exponentielle bornée tant que le daemon vit.
func (p *Publisher) Run(ctx context.Context) {
	if len(p.endpoints) == 0 {
		return
	}
	delay := time.Duration(0)
	for {
		if delay > 0 {
			timer := time.NewTimer(jitter(delay))
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
			}
		}
		if err := p.publishAll(ctx); err != nil {
			if delay == 0 {
				delay = 5 * time.Second
			} else {
				delay *= 2
				if delay > 5*time.Minute {
					delay = 5 * time.Minute
				}
			}
			continue
		}
		delay = 60 * time.Second
	}
}

func jitter(delay time.Duration) time.Duration {
	bound := int64(delay / 5)
	if bound < 1 {
		return delay
	}
	value, err := rand.Int(rand.Reader, big.NewInt(bound+1))
	if err != nil {
		return delay
	}
	return delay + time.Duration(value.Int64())
}

// publishAll envoie toujours l'état courant avant les événements encore présents.
func (p *Publisher) publishAll(ctx context.Context) error {
	current, err := p.store.Current(ctx)
	if err != nil {
		return err
	}
	if _, err := p.publish(ctx, current); err != nil {
		return err
	}
	events, err := p.store.PendingEvents(ctx, 64)
	if err != nil {
		return err
	}
	for _, encoded := range events {
		ack, err := p.publish(ctx, encoded)
		if err != nil {
			return err
		}
		if err := p.store.AcknowledgeEvent(ctx, ack.Sequence); err != nil {
			return err
		}
	}
	return nil
}

// publish accepte uniquement un accusé Protobuf cohérent reçu par le canal mTLS.
func (p *Publisher) publish(ctx context.Context, encoded []byte) (*telemetryv1.PublishAck, error) {
	var last error
	for _, target := range p.endpoints {
		request, err := http.NewRequestWithContext(ctx, http.MethodPost, target.url, bytes.NewReader(encoded))
		if err != nil {
			return nil, err
		}
		request.Header.Set("Content-Type", "application/x-protobuf")
		response, err := target.client.Do(request)
		if err != nil {
			last = err
			continue
		}
		body, readErr := io.ReadAll(io.LimitReader(response.Body, maxResponseBytes+1))
		response.Body.Close()
		if readErr != nil || len(body) > maxResponseBytes || response.StatusCode != http.StatusOK {
			last = fmt.Errorf("accusé du coordinateur refusé")
			continue
		}
		ack := &telemetryv1.PublishAck{}
		if err := proto.Unmarshal(body, ack); err != nil || ack.SchemaVersion != 1 || ack.MachineId != p.machineID {
			last = fmt.Errorf("accusé Protobuf invalide")
			continue
		}
		envelope := &telemetryv1.SignedEnvelope{}
		if err := proto.Unmarshal(encoded, envelope); err != nil || ack.Stream != envelope.Stream {
			return nil, fmt.Errorf("accusé incohérent avec l'enveloppe")
		}
		var sequence uint64
		switch envelope.Stream {
		case telemetryv1.TelemetryStream_TELEMETRY_STREAM_STATE:
			message := &telemetryv1.MachineState{}
			if err := proto.Unmarshal(envelope.Payload, message); err != nil {
				return nil, err
			}
			sequence = message.Sequence
		case telemetryv1.TelemetryStream_TELEMETRY_STREAM_EVENT:
			message := &telemetryv1.MachineEvent{}
			if err := proto.Unmarshal(envelope.Payload, message); err != nil {
				return nil, err
			}
			sequence = message.Sequence
		default:
			return nil, fmt.Errorf("flux local inconnu")
		}
		if ack.Sequence != sequence {
			return nil, fmt.Errorf("séquence d'accusé incohérente")
		}
		return ack, nil
	}
	return nil, fmt.Errorf("aucun coordinateur n'a accusé la télémétrie: %w", last)
}

package daemon

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/ldesfontaine/your-cloud/internal/buffer"
	"github.com/ldesfontaine/your-cloud/internal/machineid"
	"github.com/ldesfontaine/your-cloud/internal/observation"
	"github.com/ldesfontaine/your-cloud/internal/strictjson"
)

const (
	// ApprovedRelayOrigin is the complete authenticated observation destination.
	ApprovedRelayOrigin = "https://relay.observation.your-cloud.test:8443"
	observationPath     = "/v0/observations"
	maxAckBytes         = 256
)

// Collector periodically records the fixed host-health profile locally, and
// beside it whatever the machine's own declared loopback targets did.
type Collector struct {
	machineID string
	buffer    *buffer.Buffer
	sources   observation.Sources
	external  ExternalReader
	interval  time.Duration
	now       func() time.Time
	logger    *log.Logger
}

// ExternalReader is the read-only adapter of `#107` as this package sees it: one
// function that answers what the declared loopback ports of this machine did,
// and that receives nothing with which to change anything.
//
// It is a parameter rather than a package this file reaches into, for the reason
// the three fixed sources are: the Daemon is the process that observes and
// reports, and what it may observe is decided at assembly rather than by the
// loop that runs every thirty seconds.
type ExternalReader func(context.Context) ([]observation.ExternalReading, error)

// NewCollector accepts no profile, path or collector parameter. The external
// reader may be absent, and a Daemon without one reports exactly what every
// Daemon reported before this palier.
func NewCollector(machineID string, localBuffer *buffer.Buffer, sources observation.Sources, external ExternalReader, logger *log.Logger) (*Collector, error) {
	if err := machineid.Validate(machineID); err != nil {
		return nil, err
	}
	if localBuffer == nil || sources.ReadFile == nil || sources.StatFS == nil || logger == nil {
		return nil, errors.New("collector requires a buffer, fixed sources and logger")
	}
	return &Collector{
		machineID: machineID, buffer: localBuffer, sources: sources, external: external,
		interval: observation.CollectionInterval, now: time.Now, logger: logger,
	}, nil
}

// CollectOnce records one typed state even when an individual collector fails.
//
// A declared-target reading that could not be taken is logged and dropped, and
// the host's own health is persisted regardless: an external element the product
// does not own may not take the observation of a machine down with it. The
// absence then ages honestly in the Controller's projection, which is the
// product's own way of saying "nobody looked recently".
func (collector *Collector) CollectOnce(ctx context.Context) error {
	health := observation.CollectHostHealth(collector.sources)
	var external []observation.ExternalReading
	if collector.external != nil {
		readings, err := collector.external(ctx)
		if err != nil {
			collector.logger.Printf("external reading unavailable: %v", err)
		} else {
			external = readings
		}
	}
	if _, err := collector.buffer.Enqueue(collector.machineID, health, external, collector.now()); err != nil {
		return fmt.Errorf("persist host health: %w", err)
	}
	return nil
}

// Run collects immediately, then at the fixed candidate cadence.
//
// That cadence is what makes an external reading usable at all: the product
// announces one ageing limit, ninety seconds, and a reading taken every thirty
// reaches the Relay three times inside it. A slower adapter would have rendered
// every external element permanently old, which is the cost `#105` asked this
// palier to either meet or admit.
func (collector *Collector) Run(ctx context.Context) {
	collector.collectAndLog(ctx)
	ticker := time.NewTicker(collector.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			collector.collectAndLog(ctx)
		}
	}
}

func (collector *Collector) collectAndLog(ctx context.Context) {
	if err := collector.CollectOnce(ctx); err != nil {
		collector.logger.Printf("observation collection unavailable: %v", err)
	}
}

// Publisher sends immutable queued observations and accepts exact durable acks.
type Publisher struct {
	machineID string
	endpoint  string
	buffer    *buffer.Buffer
	client    *http.Client
	logger    *log.Logger
	now       func() time.Time
	failing   bool
}

type durableAck struct {
	Schema         int    `json:"schema"`
	MachineID      string `json:"machine_id"`
	Sequence       uint64 `json:"sequence"`
	AlreadyPresent bool   `json:"already_present"`
}

// NewPublisher pins the complete approved origin before the first request.
func NewPublisher(machineID, relayOrigin string, localBuffer *buffer.Buffer, client *http.Client, logger *log.Logger) (*Publisher, error) {
	if err := machineid.Validate(machineID); err != nil {
		return nil, err
	}
	if relayOrigin != ApprovedRelayOrigin {
		return nil, fmt.Errorf("Relay origin must be exactly %s", ApprovedRelayOrigin)
	}
	parsed, err := url.Parse(relayOrigin)
	if err != nil || !isApprovedHTTPSOrigin(parsed) {
		return nil, errors.New("Relay origin is not a canonical HTTPS origin")
	}
	if localBuffer == nil || client == nil || logger == nil {
		return nil, errors.New("publisher requires a buffer, mTLS client and logger")
	}
	return &Publisher{
		machineID: machineID, endpoint: relayOrigin + observationPath,
		buffer: localBuffer, client: client, logger: logger, now: time.Now,
	}, nil
}

func isApprovedHTTPSOrigin(parsed *url.URL) bool {
	return parsed.Scheme == "https" && parsed.Hostname() == "relay.observation.your-cloud.test" && parsed.Port() == "8443" &&
		parsed.User == nil && parsed.Path == "" && parsed.RawPath == "" && parsed.RawQuery == "" &&
		!parsed.ForceQuery && parsed.Fragment == "" && parsed.Opaque == ""
}

// SendOnce sends only the oldest immutable record and removes it after an exact
// acknowledgement from the already authenticated Relay connection.
func (publisher *Publisher) SendOnce(ctx context.Context) error {
	encoded, sequence, err := publisher.buffer.Peek()
	if err != nil {
		return err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, publisher.endpoint, bytes.NewReader(encoded))
	if err != nil {
		return fmt.Errorf("create observation request: %w", err)
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := publisher.client.Do(request)
	if err != nil {
		return fmt.Errorf("send observation: %w", err)
	}
	defer response.Body.Close()
	ack, err := decodeDurableAck(response, publisher.machineID, sequence)
	if err != nil {
		return err
	}
	if err := publisher.buffer.Acknowledge(ack.Sequence, publisher.now()); err != nil {
		return fmt.Errorf("apply durable acknowledgement: %w", err)
	}
	if err := publisher.buffer.SetDeliveryState("available", publisher.now()); err != nil {
		return fmt.Errorf("persist delivery recovery: %w", err)
	}
	return nil
}

func decodeDurableAck(response *http.Response, machineID string, sequence uint64) (durableAck, error) {
	if response.StatusCode != http.StatusOK {
		problem, _ := io.ReadAll(io.LimitReader(response.Body, maxAckBytes+1))
		return durableAck{}, fmt.Errorf("Relay refused observation: status=%d body=%q", response.StatusCode, strings.TrimSpace(string(problem)))
	}
	mediaType, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return durableAck{}, errors.New("Relay acknowledgement has an unsupported Content-Type")
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maxAckBytes+1))
	if err != nil || len(body) == 0 || len(body) > maxAckBytes {
		return durableAck{}, errors.New("Relay acknowledgement is absent or too large")
	}
	var ack durableAck
	if err := strictjson.Decode(body, &ack); err != nil {
		return durableAck{}, errors.New("Relay acknowledgement does not match its schema")
	}
	if ack.Schema != 1 || ack.MachineID != machineID || ack.Sequence != sequence {
		return durableAck{}, errors.New("Relay acknowledgement does not match the pending observation")
	}
	return ack, nil
}

// Run drains immediately, uses bounded exponential backoff on failure and
// keeps collection independent from Relay availability.
func (publisher *Publisher) Run(ctx context.Context) {
	delay := time.Duration(0)
	for {
		if delay > 0 {
			timer := time.NewTimer(delay)
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
			}
		}
		err := publisher.SendOnce(ctx)
		switch {
		case errors.Is(err, context.Canceled):
			return
		case errors.Is(err, io.EOF):
			publisher.logRecovery()
			delay = time.Second
		case err != nil:
			publisher.logFailure(err)
			if stateErr := publisher.buffer.SetDeliveryState("unavailable", publisher.now()); stateErr != nil {
				publisher.logger.Printf("persist delivery failure state: %v", stateErr)
			}
			if delay < time.Second {
				delay = time.Second
			} else if delay < time.Minute {
				delay *= 2
				if delay > time.Minute {
					delay = time.Minute
				}
			}
		default:
			publisher.logRecovery()
			delay = 0
		}
	}
}

func (publisher *Publisher) logFailure(err error) {
	if publisher.failing {
		return
	}
	publisher.logger.Printf("observation delivery unavailable machine_id=%s: %v", publisher.machineID, err)
	publisher.failing = true
}

func (publisher *Publisher) logRecovery() {
	if !publisher.failing {
		return
	}
	publisher.logger.Printf("observation delivery recovered machine_id=%s", publisher.machineID)
	publisher.failing = false
}

func encodeAck(machineID string, sequence uint64, alreadyPresent bool) []byte {
	encoded, _ := json.Marshal(durableAck{Schema: 1, MachineID: machineID, Sequence: sequence, AlreadyPresent: alreadyPresent})
	return encoded
}

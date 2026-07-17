// Package daemon sends one bounded presence signal from an Agent to the Relay.
package daemon

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/ldesfontaine/your-cloud/internal/presence"
)

// Sender has no local observation authority. Its only source data is the
// configured synthetic machine ID, the binary version, and the current time.
type Sender struct {
	machineID  string
	endpoint   string
	interval   time.Duration
	httpClient *http.Client
	logger     *log.Logger
	now        func() time.Time
	failing    bool
}

// NewSender validates the fixed outbound destination before any request.
func NewSender(machineID, relayURL string, interval time.Duration, logger *log.Logger) (*Sender, error) {
	if err := presence.ValidateMachineID(machineID); err != nil {
		return nil, err
	}
	if interval <= 0 {
		return nil, errors.New("interval must be positive")
	}
	endpoint, err := presenceEndpoint(relayURL)
	if err != nil {
		return nil, err
	}

	return &Sender{
		machineID:  machineID,
		endpoint:   endpoint,
		interval:   interval,
		httpClient: &http.Client{Timeout: 2 * time.Second},
		logger:     logger,
		now:        time.Now,
	}, nil
}

func presenceEndpoint(relayURL string) (string, error) {
	parsedURL, err := url.Parse(relayURL)
	if err != nil || !isHTTPOrigin(parsedURL) {
		return "", errors.New("relay URL must be an HTTP origin without userinfo, path, query, or fragment")
	}
	return strings.TrimRight(relayURL, "/") + "/v0/presence", nil
}

func isHTTPOrigin(parsedURL *url.URL) bool {
	return parsedURL.Scheme == "http" &&
		parsedURL.Host != "" &&
		parsedURL.User == nil &&
		parsedURL.Path == "" &&
		parsedURL.RawPath == "" &&
		parsedURL.RawQuery == "" &&
		!parsedURL.ForceQuery &&
		parsedURL.Fragment == "" &&
		parsedURL.Opaque == ""
}

// SendOnce sends the complete v0.0.1 message and accepts only 204 from the
// configured Relay destination.
func (sender *Sender) SendOnce(ctx context.Context) error {
	request, err := sender.newPresenceRequest(ctx)
	if err != nil {
		return err
	}

	response, err := sender.httpClient.Do(request)
	if err != nil {
		return fmt.Errorf("send presence: %w", err)
	}
	defer response.Body.Close()
	return validateRelayResponse(response)
}

func (sender *Sender) newPresenceRequest(ctx context.Context) (*http.Request, error) {
	signal := presence.Signal{
		MachineID:     sender.machineID,
		DaemonVersion: presence.Version,
		SentAt:        sender.now().UTC().Format(time.RFC3339Nano),
	}
	body, err := json.Marshal(signal)
	if err != nil {
		return nil, fmt.Errorf("encode presence: %w", err)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, sender.endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("create presence request: %w", err)
	}
	request.Header.Set("Content-Type", "application/json")
	return request, nil
}

func validateRelayResponse(response *http.Response) error {
	if response.StatusCode != http.StatusNoContent {
		problem, _ := io.ReadAll(io.LimitReader(response.Body, 1024))
		return fmt.Errorf("relay refused presence: status=%d body=%q", response.StatusCode, strings.TrimSpace(string(problem)))
	}
	return nil
}

// Run sends immediately, then once per interval until systemd cancels the
// context. A transient Relay failure is logged and retried without crashing.
func (sender *Sender) Run(ctx context.Context) {
	sender.sendAndLog(ctx)
	ticker := time.NewTicker(sender.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			sender.sendAndLog(ctx)
		}
	}
}

func (sender *Sender) sendAndLog(ctx context.Context) {
	err := sender.SendOnce(ctx)
	switch {
	case errors.Is(err, context.Canceled):
		return
	case err != nil:
		sender.logFailure(err)
	default:
		sender.logRecovery()
	}
}

func (sender *Sender) logFailure(err error) {
	if sender.failing {
		return
	}
	sender.logger.Printf("presence unavailable machine_id=%s: %v", sender.machineID, err)
	sender.failing = true
}

func (sender *Sender) logRecovery() {
	if !sender.failing {
		return
	}
	sender.logger.Printf("presence recovered machine_id=%s", sender.machineID)
	sender.failing = false
}

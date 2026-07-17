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
	parsedURL, err := url.Parse(relayURL)
	if err != nil || parsedURL.Scheme != "http" || parsedURL.Host == "" ||
		parsedURL.User != nil || parsedURL.Path != "" || parsedURL.RawPath != "" ||
		parsedURL.RawQuery != "" || parsedURL.ForceQuery || parsedURL.Fragment != "" ||
		parsedURL.Opaque != "" {
		return nil, errors.New("relay URL must be an HTTP origin without userinfo, path, query, or fragment")
	}
	return &Sender{
		machineID:  machineID,
		endpoint:   strings.TrimRight(relayURL, "/") + "/v0/presence",
		interval:   interval,
		httpClient: &http.Client{Timeout: 2 * time.Second},
		logger:     logger,
		now:        time.Now,
	}, nil
}

// SendOnce sends the complete v0.0.1 message and accepts only 204 from the
// configured Relay destination.
func (sender *Sender) SendOnce(ctx context.Context) error {
	signal := presence.Signal{
		MachineID:     sender.machineID,
		DaemonVersion: presence.Version,
		SentAt:        sender.now().UTC().Format(time.RFC3339Nano),
	}
	body, err := json.Marshal(signal)
	if err != nil {
		return fmt.Errorf("encode presence: %w", err)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, sender.endpoint, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create presence request: %w", err)
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := sender.httpClient.Do(request)
	if err != nil {
		return fmt.Errorf("send presence: %w", err)
	}
	defer response.Body.Close()
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
	if err != nil && !errors.Is(err, context.Canceled) {
		if !sender.failing {
			sender.logger.Printf("presence unavailable machine_id=%s: %v", sender.machineID, err)
			sender.failing = true
		}
		return
	}
	if err == nil && sender.failing {
		sender.logger.Printf("presence recovered machine_id=%s", sender.machineID)
		sender.failing = false
	}
}

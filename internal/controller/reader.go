package controller

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ldesfontaine/your-cloud/internal/strictjson"
)

const (
	maxRelayErrorBytes = 1_024
	readerReuseWindow  = 5 * time.Second
)

var errRelayClock = errors.New("Relay clock is not trustworthy")

type clockSample struct {
	civil     time.Time
	monotonic time.Time
}

type relayProblem struct {
	SchemaVersion int    `json:"schema_version"`
	ErrorCode     string `json:"error_code"`
	RequestID     string `json:"request_id"`
}

type RelayReader struct {
	mu               sync.Mutex
	httpClient       *http.Client
	origin           string
	host             string
	controllerID     string
	infrastructureID string
	cache            *RelayCacheStore
	sample           func() clockSample
	inflight         chan struct{}
	inflightStarted  time.Time
	lastSuccess      time.Time
	lastNetworkStart time.Time
	nextRetry        time.Time
	failures         uint8
	lastStatus       RelayStatus
}

// DormantRelayReader est le lecteur d'une infrastructure dont le Relay
// n'existe pas encore — l'état VRAI d'une création, pas un mode dégradé.
//
// Il naît quand aucune ancre de Relay n'a été posée (le répertoire
// `relay-anchor` est vide), et il répond ce que le vocabulaire clos sait déjà
// dire : indisponible, sans instantané. Les portes qui exigent le Relay —
// l'attache d'une machine à l'inventaire en tête — refusent alors comme elles
// refuseraient une panne, ce qui est exact : rien ne répond, et rien ne
// répondra tant que le parcours qui pose un Relay n'aura pas déposé son
// ancre. Un redémarrage du service la prendra ; aucun credential n'est
// optionnel durablement (décision du 20 août 2026, motif NOPASSWD).
type DormantRelayReader struct{}

func (DormantRelayReader) Read(context.Context, time.Time) (*RelaySnapshot, RelayStatus, error) {
	return nil, RelayUnavailable, nil
}

func NewRelayReader(client *http.Client, originHost, controllerID, infrastructureID string, cache *RelayCacheStore) (*RelayReader, error) {
	if client == nil || cache == nil || originHost == "" || strings.ContainsAny(originHost, "/?#@") {
		return nil, errors.New("bounded Relay reader configuration is incomplete")
	}
	return &RelayReader{
		httpClient:       client,
		origin:           "https://" + originHost,
		host:             originHost,
		controllerID:     controllerID,
		infrastructureID: infrastructureID,
		cache:            cache,
		lastStatus:       RelayUnavailable,
		sample: func() clockSample {
			now := time.Now()
			return clockSample{civil: now.Round(0), monotonic: now}
		},
	}, nil
}

// Read shares compatible in-flight reads. freshAfter is zero for ordinary GET
// projection; a machine attachment supplies its post-authentication instant.
func (reader *RelayReader) Read(ctx context.Context, freshAfter time.Time) (*RelaySnapshot, RelayStatus, error) {
	for {
		now := reader.sample().monotonic
		reader.mu.Lock()
		if reader.canReuse(now, freshAfter) {
			status := reader.lastStatus
			reader.mu.Unlock()
			cached, err := reader.cache.Snapshot()
			return cached, status, err
		}
		if now.Before(reader.nextRetry) {
			status := reader.lastStatus
			reader.mu.Unlock()
			cached, cacheErr := reader.cache.Snapshot()
			if cacheErr != nil {
				cached = nil
			}
			return cached, status, errors.New("Relay backoff is active")
		}
		if reader.inflight != nil {
			pending := reader.inflight
			compatible := freshAfter.IsZero() || !reader.inflightStarted.Before(freshAfter)
			reader.mu.Unlock()
			select {
			case <-ctx.Done():
				return nil, RelayUnavailable, ctx.Err()
			case <-pending:
				if compatible {
					reader.mu.Lock()
					status := reader.lastStatus
					reader.mu.Unlock()
					cached, err := reader.cache.Snapshot()
					return cached, status, err
				}
				continue
			}
		}
		started := reader.sample().monotonic
		reader.inflight = make(chan struct{})
		reader.inflightStarted = started
		pending := reader.inflight
		reader.mu.Unlock()

		snapshot, status, err := reader.perform(ctx)
		reader.mu.Lock()
		reader.lastNetworkStart = started
		if err == nil {
			reader.failures = 0
			reader.nextRetry = time.Time{}
			reader.lastSuccess = reader.sample().monotonic
			reader.lastStatus = RelayAvailable
		} else {
			reader.failures++
			reader.nextRetry = reader.sample().monotonic.Add(reader.backoffDelay())
			reader.lastStatus = status
		}
		reader.inflight = nil
		close(pending)
		reader.mu.Unlock()
		if err != nil {
			cached, cacheErr := reader.cache.Snapshot()
			if cacheErr != nil {
				cached = nil
			}
			return cached, status, err
		}
		return snapshot, RelayAvailable, nil
	}
}

func (reader *RelayReader) canReuse(now, freshAfter time.Time) bool {
	if reader.lastStatus != RelayAvailable || reader.lastSuccess.IsZero() {
		return false
	}
	if freshAfter.IsZero() {
		return now.Sub(reader.lastSuccess) < readerReuseWindow
	}
	return !reader.lastNetworkStart.Before(freshAfter)
}

func (reader *RelayReader) perform(parent context.Context) (*RelaySnapshot, RelayStatus, error) {
	budget := 6 * time.Second
	if deadline, ok := parent.Deadline(); ok {
		remaining := time.Until(deadline) - 2*time.Second
		if remaining <= 0 {
			return nil, RelayUnavailable, errors.New("external request has no safe Relay budget")
		}
		if remaining < budget {
			budget = remaining
		}
	}
	ctx, cancel := context.WithTimeout(parent, budget)
	defer cancel()
	start := reader.sample()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, reader.origin+"/v0/snapshot", nil)
	if err != nil {
		return nil, RelayUnavailable, err
	}
	request.Host = reader.host
	request.Header.Set("Accept", "application/json")
	request.Header["User-Agent"] = nil
	response, err := reader.httpClient.Do(request)
	if err != nil {
		return nil, RelayUnavailable, err
	}
	defer response.Body.Close()
	end := reader.sample()
	if response.StatusCode != http.StatusOK {
		if err := validateRelayProblem(response); err != nil {
			return nil, RelayUnavailable, err
		}
		return nil, RelayUnavailable, errors.New("Relay refused the snapshot request")
	}
	if response.Header.Get("Content-Type") != "application/json" ||
		response.Header.Get("Cache-Control") != "no-store" ||
		response.Header.Get("Content-Encoding") != "" ||
		len(response.TransferEncoding) != 0 ||
		response.ContentLength < 0 ||
		response.ContentLength > maxRelaySnapshotBytes {
		return nil, RelayUnavailable, errors.New("Relay response envelope is invalid")
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maxRelaySnapshotBytes+1))
	if err != nil || len(body) > maxRelaySnapshotBytes || int64(len(body)) != response.ContentLength {
		return nil, RelayUnavailable, errors.New("Relay response body is truncated or outside its bound")
	}
	snapshot, err := DecodeRelaySnapshot(body, reader.controllerID, reader.infrastructureID)
	if err != nil {
		return nil, RelayUnavailable, err
	}
	if err := validateFreshness(start, end, snapshot); err != nil {
		if errors.Is(err, errRelayClock) {
			return nil, RelayClockUntrusted, err
		}
		return nil, RelayUnavailable, err
	}
	if err := reader.cache.Commit(snapshot); err != nil {
		return nil, RelayUnavailable, err
	}
	copy := cloneRelaySnapshot(snapshot)
	return &copy, RelayAvailable, nil
}

func validateFreshness(start, end clockSample, snapshot RelaySnapshot) error {
	monotonicDuration := end.monotonic.Sub(start.monotonic)
	wallDuration := end.civil.Sub(start.civil)
	if monotonicDuration < 0 || monotonicDuration > 6*time.Second || absoluteDuration(wallDuration-monotonicDuration) > time.Second {
		return errRelayClock
	}
	snapshotAt, err := parseCanonicalUTC(snapshot.SnapshotAt)
	if err != nil || snapshotAt.Before(end.civil.Add(-30*time.Second)) || snapshotAt.After(start.civil.Add(30*time.Second)) {
		return errRelayClock
	}
	return nil
}

func validateRelayProblem(response *http.Response) error {
	allowed := map[int]string{
		400: "invalid_request", 403: "reader_forbidden", 404: "route_not_found",
		405: "method_not_allowed", 406: "not_acceptable", 413: "request_too_large",
		415: "unsupported_media_type", 421: "origin_mismatch", 429: "rate_limited",
		431: "headers_too_large", 503: "snapshot_unavailable",
	}
	expected, exists := allowed[response.StatusCode]
	if !exists || response.Header.Get("Content-Type") != "application/json" ||
		response.Header.Get("Cache-Control") != "no-store" || len(response.TransferEncoding) != 0 ||
		response.ContentLength < 0 || response.ContentLength > maxRelayErrorBytes {
		return errors.New("Relay returned an unsupported error envelope")
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maxRelayErrorBytes+1))
	if err != nil || len(body) > maxRelayErrorBytes || int64(len(body)) != response.ContentLength {
		return errors.New("Relay error body is outside its bound")
	}
	var problem relayProblem
	if strictjson.Decode(body, &problem) != nil || problem.SchemaVersion != 1 || problem.ErrorCode != expected {
		return errors.New("Relay error document is invalid")
	}
	requestID, err := base64.RawURLEncoding.DecodeString(problem.RequestID)
	if err != nil || len(requestID) != 16 || base64.RawURLEncoding.EncodeToString(requestID) != problem.RequestID {
		return errors.New("Relay error request_id is invalid")
	}
	if response.StatusCode == http.StatusTooManyRequests {
		retry, err := strconv.Atoi(response.Header.Get("Retry-After"))
		if err != nil || retry < 1 || retry > 300 {
			return errors.New("Relay Retry-After is invalid")
		}
	} else if response.Header.Get("Retry-After") != "" {
		return errors.New("Relay added Retry-After to an unsupported status")
	}
	return nil
}

func (reader *RelayReader) backoffDelay() time.Duration {
	nominalSeconds := []uint8{1, 2, 4, 8, 16, 30}
	index := int(reader.failures) - 1
	if index < 0 {
		index = 0
	}
	if index >= len(nominalSeconds) {
		index = len(nominalSeconds) - 1
	}
	var random [1]byte
	percentage := uint8(100)
	if _, err := rand.Read(random[:]); err == nil {
		percentage = 80 + random[0]%21
	}
	return time.Duration(nominalSeconds[index]) * time.Second * time.Duration(percentage) / 100
}

func absoluteDuration(value time.Duration) time.Duration {
	if value < 0 {
		return -value
	}
	return value
}

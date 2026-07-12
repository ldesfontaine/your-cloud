package app

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/lucas-desfontaine/your-cloud/daemon/internal/collect"
	"github.com/lucas-desfontaine/your-cloud/daemon/internal/config"
	"github.com/lucas-desfontaine/your-cloud/daemon/internal/identity"
	"github.com/lucas-desfontaine/your-cloud/daemon/internal/publisher"
	"github.com/lucas-desfontaine/your-cloud/daemon/internal/store"
	telemetryv1 "github.com/lucas-desfontaine/your-cloud/protocole/gen/go"
)

const Version = "1.0.0-rc.2"

// App orchestre la collecte, la signature, la persistance et la publication.
type App struct {
	config    config.Config
	identity  *identity.Identity
	store     *store.Store
	publisher *publisher.Publisher
}

// Open assemble identité, stockage et publication sans démarrer la collecte.
func Open(cfg config.Config) (*App, error) {
	id, err := identity.LoadOrCreate(cfg.StateDir)
	if err != nil {
		return nil, err
	}
	database, err := store.Open(cfg.StateDir, cfg.QueueLimitBytes)
	if err != nil {
		return nil, err
	}
	transport, err := publisher.New(cfg.MachineID, cfg.Coordinators, database)
	if err != nil {
		database.Close()
		return nil, err
	}
	return &App{config: cfg, identity: id, store: database, publisher: transport}, nil
}

// Close libère le stockage durable du daemon.
func (a *App) Close() error { return a.store.Close() }

// envelope sérialise puis signe un payload sans représentation intermédiaire.
func (a *App) envelope(stream telemetryv1.TelemetryStream, message proto.Message) ([]byte, error) {
	payload, err := proto.MarshalOptions{Deterministic: true}.Marshal(message)
	if err != nil {
		return nil, fmt.Errorf("encoder le payload: %w", err)
	}
	envelope := &telemetryv1.SignedEnvelope{
		SchemaVersion: 1, KeyId: a.identity.KeyID(), Stream: stream,
		Payload: payload, Signature: a.identity.Sign(stream, payload),
	}
	return proto.MarshalOptions{Deterministic: true}.Marshal(envelope)
}

// significantDigest isole les champs dont un changement mérite un événement.
func significantDigest(state *telemetryv1.MachineState) (string, error) {
	view := struct {
		BootID string                   `json:"boot_id"`
		Kernel string                   `json:"kernel"`
		Reboot bool                     `json:"reboot"`
		Units  []*telemetryv1.UnitState `json:"units"`
	}{state.BootId, state.KernelRelease, state.SecurityRebootRequired, state.Units}
	data, err := json.Marshal(view)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:]), nil
}

// CollectOnce produit un nouvel état et journalise uniquement les changements significatifs.
func (a *App) CollectOnce(ctx context.Context) error {
	sequence, err := a.store.NextSequence(ctx, telemetryv1.TelemetryStream_TELEMETRY_STREAM_STATE)
	if err != nil {
		return err
	}
	state, err := collect.State(ctx, a.config.MachineID, Version, sequence, a.config.Units)
	if err != nil {
		return err
	}
	envelope, err := a.envelope(telemetryv1.TelemetryStream_TELEMETRY_STREAM_STATE, state)
	if err != nil {
		return err
	}
	if err := a.store.SaveCurrent(ctx, sequence, state.ObservedAtUnix, envelope); err != nil {
		return err
	}
	digest, err := significantDigest(state)
	if err != nil {
		return err
	}
	previous, err := a.store.SignificantDigest(ctx)
	if err != nil {
		return err
	}
	if digest != previous {
		kind := "observer-started"
		if previous != "" {
			kind = "machine-state-changed"
		}
		if err := a.enqueueEvent(ctx, kind, "changement significatif observé", 0, 0); err != nil {
			return err
		}
		if err := a.store.SetSignificantDigest(ctx, digest); err != nil {
			return err
		}
	}
	return nil
}

// enqueueEvent signe un événement et transforme tout débordement en lacune explicite.
func (a *App) enqueueEvent(ctx context.Context, kind, detail string, gapFrom, gapTo uint64) error {
	for attempts := 0; attempts < 3; attempts++ {
		sequence, err := a.store.NextSequence(ctx, telemetryv1.TelemetryStream_TELEMETRY_STREAM_EVENT)
		if err != nil {
			return err
		}
		event := &telemetryv1.MachineEvent{SchemaVersion: 1, MachineId: a.config.MachineID,
			Sequence: sequence, ObservedAtUnix: time.Now().UTC().Unix(), Kind: kind, Detail: detail,
			GapFromSequence: gapFrom, GapToSequence: gapTo}
		envelope, err := a.envelope(telemetryv1.TelemetryStream_TELEMETRY_STREAM_EVENT, event)
		if err != nil {
			return err
		}
		gap, err := a.store.EnqueueEvent(ctx, sequence, event.ObservedAtUnix, kind, envelope)
		if err != nil {
			return err
		}
		if gap == nil {
			return nil
		}
		kind, detail, gapFrom, gapTo = "telemetry-gap", "événements supprimés par la limite locale", gap.From, gap.To
	}
	return fmt.Errorf("impossible d'enregistrer un marqueur de lacune borné")
}

// Run collecte immédiatement puis poursuit collecte et publication jusqu'à l'arrêt.
func (a *App) Run(ctx context.Context) error {
	if err := a.CollectOnce(ctx); err != nil {
		return err
	}
	go a.publisher.Run(ctx)
	ticker := time.NewTicker(time.Duration(a.config.IntervalSeconds) * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			if err := a.CollectOnce(ctx); err != nil {
				return err
			}
		}
	}
}

// ExportCurrent encode l'enveloppe courante pour l'inspection ponctuelle par SSH.
func (a *App) ExportCurrent(ctx context.Context) (string, error) {
	value, err := a.store.Current(ctx)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(value), nil
}

// PublicIdentity expose les seules données nécessaires à l'approbation par la console.
func (a *App) PublicIdentity() map[string]string {
	return map[string]string{"algorithm": "Ed25519", "key_id": a.identity.KeyID(), "public_key": a.identity.PublicBase64()}
}

// DatabaseUsage retourne le bornage et l'occupation de la file locale.
func (a *App) DatabaseUsage(ctx context.Context) (map[string]int64, error) {
	pages, pageSize, err := a.store.PageUsage(ctx)
	if err != nil {
		return nil, err
	}
	return map[string]int64{"page_count": pages, "page_size": pageSize, "bytes": pages * pageSize, "limit_bytes": a.config.QueueLimitBytes}, nil
}

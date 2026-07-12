package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"strconv"

	telemetryv1 "github.com/lucas-desfontaine/your-cloud/protocole/gen/go"
	_ "modernc.org/sqlite"
)

// Store conserve l'état courant et la file bornée d'événements du daemon.
type Store struct {
	db          *sql.DB
	eventBudget int64
}

// Gap décrit une plage d'événements supprimés par la limite locale.
type Gap struct {
	From uint64
	To   uint64
}

// Open initialise la file SQLite avec durabilité forte et limite dure de pages.
func Open(stateDir string, limitBytes int64) (*Store, error) {
	path := filepath.Join(stateDir, "telemetry.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("ouvrir SQLite: %w", err)
	}
	db.SetMaxOpenConns(1)
	pageLimit := limitBytes / 4096
	if pageLimit < 32 {
		pageLimit = 32
	}
	pragmas := []string{
		"PRAGMA journal_mode=DELETE",
		"PRAGMA synchronous=FULL",
		"PRAGMA foreign_keys=ON",
		"PRAGMA busy_timeout=5000",
		fmt.Sprintf("PRAGMA max_page_count=%d", pageLimit),
	}
	for _, statement := range pragmas {
		if _, err := db.Exec(statement); err != nil {
			db.Close()
			return nil, fmt.Errorf("configurer SQLite: %w", err)
		}
	}
	schema := `
CREATE TABLE IF NOT EXISTS meta (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
) WITHOUT ROWID;
INSERT OR IGNORE INTO meta(key, value) VALUES
  ('state_sequence', '0'), ('event_sequence', '0'), ('significant_digest', '');
CREATE TABLE IF NOT EXISTS current_state (
  singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
  sequence INTEGER NOT NULL,
  observed_at INTEGER NOT NULL,
  envelope BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS events (
  sequence INTEGER PRIMARY KEY,
  observed_at INTEGER NOT NULL,
  kind TEXT NOT NULL,
  envelope BLOB NOT NULL
);`
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("initialiser SQLite: %w", err)
	}
	return &Store{db: db, eventBudget: limitBytes / 2}, nil
}

// Close ferme la base locale du daemon.
func (s *Store) Close() error { return s.db.Close() }

// NextSequence avance atomiquement la séquence persistante d'un flux.
func (s *Store) NextSequence(ctx context.Context, stream telemetryv1.TelemetryStream) (uint64, error) {
	key := ""
	switch stream {
	case telemetryv1.TelemetryStream_TELEMETRY_STREAM_STATE:
		key = "state_sequence"
	case telemetryv1.TelemetryStream_TELEMETRY_STREAM_EVENT:
		key = "event_sequence"
	default:
		return 0, fmt.Errorf("flux de séquence invalide")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	var raw string
	if err := tx.QueryRowContext(ctx, "SELECT value FROM meta WHERE key = ?", key).Scan(&raw); err != nil {
		return 0, err
	}
	current, err := strconv.ParseUint(raw, 10, 64)
	if err != nil || current == ^uint64(0) {
		return 0, fmt.Errorf("séquence persistante invalide")
	}
	next := current + 1
	if _, err := tx.ExecContext(ctx, "UPDATE meta SET value = ? WHERE key = ?", strconv.FormatUint(next, 10), key); err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return next, nil
}

// SaveCurrent remplace l'état courant sans alimenter le journal périodique.
func (s *Store) SaveCurrent(ctx context.Context, sequence uint64, observedAt int64, envelope []byte) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO current_state(singleton, sequence, observed_at, envelope)
VALUES(1, ?, ?, ?) ON CONFLICT(singleton) DO UPDATE SET sequence=excluded.sequence,
observed_at=excluded.observed_at, envelope=excluded.envelope`, sequence, observedAt, envelope)
	if err != nil {
		return fmt.Errorf("enregistrer l'état courant: %w", err)
	}
	return nil
}

// Current retourne l'enveloppe d'état la plus récente à publier en priorité.
func (s *Store) Current(ctx context.Context) ([]byte, error) {
	var envelope []byte
	if err := s.db.QueryRowContext(ctx, "SELECT envelope FROM current_state WHERE singleton = 1").Scan(&envelope); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("aucun état collecté")
		}
		return nil, fmt.Errorf("lire l'état courant: %w", err)
	}
	return envelope, nil
}

// PendingEvents retourne une page ordonnée des événements encore non confirmés.
func (s *Store) PendingEvents(ctx context.Context, limit int) ([][]byte, error) {
	if limit < 1 || limit > 64 {
		return nil, fmt.Errorf("limite d'événements invalide")
	}
	rows, err := s.db.QueryContext(ctx, "SELECT envelope FROM events ORDER BY sequence LIMIT ?", limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result [][]byte
	for rows.Next() {
		var envelope []byte
		if err := rows.Scan(&envelope); err != nil {
			return nil, err
		}
		result = append(result, envelope)
	}
	return result, rows.Err()
}

// AcknowledgeEvent purge uniquement l'événement confirmé par un coordinateur.
func (s *Store) AcknowledgeEvent(ctx context.Context, sequence uint64) error {
	result, err := s.db.ExecContext(ctx, "DELETE FROM events WHERE sequence = ?", sequence)
	if err != nil {
		return fmt.Errorf("purger l'événement confirmé: %w", err)
	}
	deleted, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if deleted != 1 {
		return fmt.Errorf("événement confirmé absent: %d", sequence)
	}
	return nil
}

// SignificantDigest retourne l'empreinte du dernier état significatif observé.
func (s *Store) SignificantDigest(ctx context.Context) (string, error) {
	var digest string
	if err := s.db.QueryRowContext(ctx, "SELECT value FROM meta WHERE key = 'significant_digest'").Scan(&digest); err != nil {
		return "", err
	}
	return digest, nil
}

// SetSignificantDigest mémorise l'état significatif après création de son événement.
func (s *Store) SetSignificantDigest(ctx context.Context, digest string) error {
	_, err := s.db.ExecContext(ctx, "UPDATE meta SET value = ? WHERE key = 'significant_digest'", digest)
	return err
}

// EnqueueEvent ajoute un événement et signale toute plage supprimée par débordement.
func (s *Store) EnqueueEvent(ctx context.Context, sequence uint64, observedAt int64, kind string, envelope []byte) (*Gap, error) {
	if int64(len(envelope)) > s.eventBudget/2 {
		return nil, fmt.Errorf("événement trop grand pour la file bornée")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, "INSERT INTO events(sequence, observed_at, kind, envelope) VALUES(?, ?, ?, ?)", sequence, observedAt, kind, envelope); err != nil {
		return nil, err
	}
	var total int64
	if err := tx.QueryRowContext(ctx, "SELECT COALESCE(SUM(length(envelope)), 0) FROM events").Scan(&total); err != nil {
		return nil, err
	}
	var gap *Gap
	for total > s.eventBudget {
		var oldest uint64
		var size int64
		if err := tx.QueryRowContext(ctx, "SELECT sequence, length(envelope) FROM events ORDER BY sequence LIMIT 1").Scan(&oldest, &size); err != nil {
			return nil, err
		}
		if _, err := tx.ExecContext(ctx, "DELETE FROM events WHERE sequence = ?", oldest); err != nil {
			return nil, err
		}
		if gap == nil {
			gap = &Gap{From: oldest, To: oldest}
		} else {
			gap.To = oldest
		}
		total -= size
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return gap, nil
}

// PageUsage mesure l'espace SQLite alloué sans lire le contenu des événements.
func (s *Store) PageUsage(ctx context.Context) (int64, int64, error) {
	var pages, size int64
	if err := s.db.QueryRowContext(ctx, "PRAGMA page_count").Scan(&pages); err != nil {
		return 0, 0, err
	}
	if err := s.db.QueryRowContext(ctx, "PRAGMA page_size").Scan(&size); err != nil {
		return 0, 0, err
	}
	return pages, size, nil
}

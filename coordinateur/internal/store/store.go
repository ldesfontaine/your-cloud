package store

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"time"

	telemetryv1 "github.com/ldesfontaine/your-cloud/protocole/gen/go"
	_ "modernc.org/sqlite"
)

// Store conserve l'état courant et l'historique borné reçu des machines.
type Store struct {
	db            *sql.DB
	retentionDays int
}

// Open initialise la base dérivée avec rétention et limite dure de pages.
func Open(stateDir string, limitBytes int64, retentionDays int) (*Store, error) {
	db, err := sql.Open("sqlite", filepath.Join(stateDir, "telemetry.db"))
	if err != nil {
		return nil, fmt.Errorf("ouvrir SQLite: %w", err)
	}
	db.SetMaxOpenConns(1)
	pageLimit := limitBytes / 4096
	pragmas := []string{
		"PRAGMA journal_mode=DELETE", "PRAGMA synchronous=FULL",
		"PRAGMA foreign_keys=ON", "PRAGMA busy_timeout=5000",
		fmt.Sprintf("PRAGMA max_page_count=%d", pageLimit),
	}
	for _, statement := range pragmas {
		if _, err := db.Exec(statement); err != nil {
			db.Close()
			return nil, fmt.Errorf("configurer SQLite: %w", err)
		}
	}
	schema := `
CREATE TABLE IF NOT EXISTS current_states (
  machine_id TEXT PRIMARY KEY,
  key_id TEXT NOT NULL,
  sequence INTEGER NOT NULL,
  observed_at INTEGER NOT NULL,
  envelope BLOB NOT NULL
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS events (
  machine_id TEXT NOT NULL,
  sequence INTEGER NOT NULL,
  key_id TEXT NOT NULL,
  observed_at INTEGER NOT NULL,
  envelope BLOB NOT NULL,
  PRIMARY KEY(machine_id, sequence)
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS events_observed_at ON events(observed_at);`
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("initialiser SQLite: %w", err)
	}
	return &Store{db: db, retentionDays: retentionDays}, nil
}

// Close ferme la base locale du coordinateur.
func (s *Store) Close() error { return s.db.Close() }

// Save rend une publication durable et idempotente avant tout accusé.
func (s *Store) Save(ctx context.Context, machineID, keyID string, stream telemetryv1.TelemetryStream, sequence uint64, observedAt int64, envelope []byte) (bool, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	cutoff := time.Now().UTC().AddDate(0, 0, -s.retentionDays).Unix()
	if _, err := tx.ExecContext(ctx, "DELETE FROM events WHERE observed_at < ?", cutoff); err != nil {
		return false, err
	}
	already := false
	switch stream {
	case telemetryv1.TelemetryStream_TELEMETRY_STREAM_STATE:
		var existingSequence uint64
		var existing []byte
		err := tx.QueryRowContext(ctx, "SELECT sequence, envelope FROM current_states WHERE machine_id = ?", machineID).Scan(&existingSequence, &existing)
		if err == nil {
			if sequence < existingSequence {
				return false, fmt.Errorf("séquence d'état en retour arrière")
			}
			if sequence == existingSequence {
				if !bytes.Equal(existing, envelope) {
					return false, fmt.Errorf("collision de séquence d'état")
				}
				already = true
				break
			}
		} else if !errors.Is(err, sql.ErrNoRows) {
			return false, err
		}
		if !already {
			_, err = tx.ExecContext(ctx, `INSERT INTO current_states(machine_id,key_id,sequence,observed_at,envelope)
VALUES(?,?,?,?,?) ON CONFLICT(machine_id) DO UPDATE SET key_id=excluded.key_id,
sequence=excluded.sequence,observed_at=excluded.observed_at,envelope=excluded.envelope`, machineID, keyID, sequence, observedAt, envelope)
		}
	case telemetryv1.TelemetryStream_TELEMETRY_STREAM_EVENT:
		var existing []byte
		err := tx.QueryRowContext(ctx, "SELECT envelope FROM events WHERE machine_id = ? AND sequence = ?", machineID, sequence).Scan(&existing)
		if err == nil {
			if !bytes.Equal(existing, envelope) {
				return false, fmt.Errorf("collision de séquence d'événement")
			}
			already = true
		} else if !errors.Is(err, sql.ErrNoRows) {
			return false, err
		} else {
			_, err = tx.ExecContext(ctx, "INSERT INTO events(machine_id,key_id,sequence,observed_at,envelope) VALUES(?,?,?,?,?)", machineID, keyID, sequence, observedAt, envelope)
		}
	default:
		return false, fmt.Errorf("flux inconnu")
	}
	if err != nil {
		return false, err
	}
	if err := tx.Commit(); err != nil {
		return false, err
	}
	return already, nil
}

// Current retourne l'enveloppe originale du dernier état d'une machine.
func (s *Store) Current(ctx context.Context, machineID string) ([]byte, error) {
	var envelope []byte
	if err := s.db.QueryRowContext(ctx, "SELECT envelope FROM current_states WHERE machine_id = ?", machineID).Scan(&envelope); err != nil {
		return nil, err
	}
	return envelope, nil
}

// Events retourne une page ordonnée et indique explicitement s'il reste des données.
func (s *Store) Events(ctx context.Context, machineID string, after uint64, limit int) ([][]byte, uint64, bool, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT sequence,envelope FROM events WHERE machine_id = ? AND sequence > ? ORDER BY sequence LIMIT ?", machineID, after, limit+1)
	if err != nil {
		return nil, 0, false, err
	}
	defer rows.Close()
	var envelopes [][]byte
	var sequences []uint64
	next := after
	for rows.Next() {
		var sequence uint64
		var envelope []byte
		if err := rows.Scan(&sequence, &envelope); err != nil {
			return nil, 0, false, err
		}
		envelopes = append(envelopes, envelope)
		sequences = append(sequences, sequence)
		next = sequence
	}
	if err := rows.Err(); err != nil {
		return nil, 0, false, err
	}
	hasMore := len(envelopes) > limit
	if hasMore {
		envelopes = envelopes[:limit]
		next = sequences[limit-1]
	}
	return envelopes, next, hasMore, nil
}

// PageUsage mesure l'occupation SQLite sans exposer la télémétrie conservée.
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

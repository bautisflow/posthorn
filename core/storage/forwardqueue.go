package storage

import (
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// Forward queue for lifecycle-event callbacks (FR84). Same sync-first
// posture as the mail queue: the inline forward attempt happens in the
// event handler; only transient/rate-limited failures land here, and
// the forwarder worker replays them on the shared RetryBackoff ladder.
//
// Unlike mail, an event that exhausts its ladder is deleted (with a
// log), not dead-lettered to a table — events are telemetry about mail,
// not mail; the submission log still holds the underlying truth.

// PendingForward is one queued callback delivery. Payload is the exact
// normalized-event JSON to POST; the webhook URL and secret are
// resolved from config at send time so secrets never persist (NFR29).
type PendingForward struct {
	ID       int64
	Endpoint string
	Payload  []byte
	Attempt  int
}

// EnqueueForward stores a callback for background retry, due after the
// first backoff step.
func (s *Store) EnqueueForward(endpoint string, payload []byte, now time.Time) error {
	_, err := s.db.Exec(`
		INSERT INTO lifecycle_queue (endpoint, payload, attempt, next_attempt_at)
		VALUES (?, ?, 0, ?)`,
		endpoint, payload, now.Add(RetryBackoff[0]).Unix())
	if err != nil {
		return fmt.Errorf("storage: enqueue forward: %w", err)
	}
	return nil
}

// ClaimDueForwards returns up to limit due callbacks. Rows stay in the
// table until RecordForwardOutcome removes or reschedules them, so a
// crash mid-forward re-delivers (at-least-once, same as mail).
func (s *Store) ClaimDueForwards(now time.Time, limit int) ([]PendingForward, error) {
	rows, err := s.db.Query(`
		SELECT id, endpoint, payload, attempt FROM lifecycle_queue
		WHERE next_attempt_at <= ?
		ORDER BY next_attempt_at LIMIT ?`, now.Unix(), limit)
	if err != nil {
		return nil, fmt.Errorf("storage: claim forwards: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []PendingForward
	for rows.Next() {
		var p PendingForward
		if err := rows.Scan(&p.ID, &p.Endpoint, &p.Payload, &p.Attempt); err != nil {
			return nil, fmt.Errorf("storage: claim forwards: %w", err)
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// RecordForwardOutcome finalizes an attempt: success or terminal
// failure removes the row; a retryable failure bumps the attempt and
// reschedules, deleting (dropped=true) once the ladder is exhausted.
func (s *Store) RecordForwardOutcome(id int64, retryable bool, now time.Time) (dropped bool, err error) {
	if !retryable {
		_, err := s.db.Exec(`DELETE FROM lifecycle_queue WHERE id = ?`, id)
		if err != nil {
			return false, fmt.Errorf("storage: forward outcome: %w", err)
		}
		return false, nil
	}
	var attempt int
	err = s.db.QueryRow(`SELECT attempt FROM lifecycle_queue WHERE id = ?`, id).Scan(&attempt)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("storage: forward outcome: %w", err)
	}
	attempt++
	if attempt >= MaxAttempts {
		if _, err := s.db.Exec(`DELETE FROM lifecycle_queue WHERE id = ?`, id); err != nil {
			return false, fmt.Errorf("storage: forward outcome: %w", err)
		}
		return true, nil
	}
	_, err = s.db.Exec(`
		UPDATE lifecycle_queue SET attempt = ?, next_attempt_at = ? WHERE id = ?`,
		attempt, now.Add(RetryBackoff[attempt]).Unix(), id)
	if err != nil {
		return false, fmt.Errorf("storage: forward outcome: %w", err)
	}
	return false, nil
}

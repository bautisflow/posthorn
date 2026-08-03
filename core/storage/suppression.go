package storage

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Suppression reasons (ADR-23). Bounce and complaint rows are written
// by the lifecycle ingester (FR85); manual rows come from the
// `posthorn suppressions` CLI (FR87). All shipped reasons are global —
// per-endpoint scoping is reserved for future unsubscribe-class
// reasons.
const (
	ReasonHardBounce    = "hard_bounce"
	ReasonSpamComplaint = "spam_complaint"
	ReasonManual        = "manual"
)

// Suppression is one row of the suppression list. Rows are exempt from
// retention pruning by design: forgetting a bounce defeats the feature
// (ADR-23). Erasure is the CLI's remove command.
type Suppression struct {
	Email          string
	Reason         string
	SourceEndpoint string
	CreatedAt      time.Time
}

// normalizeEmail lower-cases for storage and lookup — suppression must
// not be dodged by case variance.
func normalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

// AddSuppression inserts a row. Idempotent per (email, reason): the
// first observation wins and keeps its timestamp.
func (s *Store) AddSuppression(email, reason, sourceEndpoint string, at time.Time) error {
	email = normalizeEmail(email)
	if email == "" {
		return fmt.Errorf("storage: suppression email is empty")
	}
	_, err := s.db.Exec(`
		INSERT INTO suppressions (email, reason, source_endpoint, created_at)
		VALUES (?, ?, ?, ?)
		ON CONFLICT(email, reason) DO NOTHING`,
		email, reason, sourceEndpoint, at.Unix())
	if err != nil {
		return fmt.Errorf("storage: add suppression: %w", err)
	}
	return nil
}

// SuppressionFor reports whether email is suppressed under any reason
// (all shipped reasons are global). With multiple rows the earliest wins
// for reporting.
func (s *Store) SuppressionFor(email string) (Suppression, bool, error) {
	row := s.db.QueryRow(`
		SELECT email, reason, source_endpoint, created_at
		FROM suppressions WHERE email = ?
		ORDER BY created_at, reason LIMIT 1`, normalizeEmail(email))
	var sup Suppression
	var createdAt int64
	err := row.Scan(&sup.Email, &sup.Reason, &sup.SourceEndpoint, &createdAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Suppression{}, false, nil
		}
		return Suppression{}, false, fmt.Errorf("storage: suppression lookup: %w", err)
	}
	sup.CreatedAt = time.Unix(createdAt, 0).UTC()
	return sup, true, nil
}

// RemoveSuppression deletes every reason-row for email (the CLI's
// remove / GDPR-erasure path, FR87). Returns rows removed.
func (s *Store) RemoveSuppression(email string) (int64, error) {
	res, err := s.db.Exec(`DELETE FROM suppressions WHERE email = ?`, normalizeEmail(email))
	if err != nil {
		return 0, fmt.Errorf("storage: remove suppression: %w", err)
	}
	n, _ := res.RowsAffected()
	return n, nil
}

// ListSuppressions returns rows ordered oldest-first, up to limit.
func (s *Store) ListSuppressions(limit int) ([]Suppression, error) {
	rows, err := s.db.Query(`
		SELECT email, reason, source_endpoint, created_at
		FROM suppressions ORDER BY created_at, email LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("storage: list suppressions: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []Suppression
	for rows.Next() {
		var sup Suppression
		var createdAt int64
		if err := rows.Scan(&sup.Email, &sup.Reason, &sup.SourceEndpoint, &createdAt); err != nil {
			return nil, fmt.Errorf("storage: list suppressions: %w", err)
		}
		sup.CreatedAt = time.Unix(createdAt, 0).UTC()
		out = append(out, sup)
	}
	return out, rows.Err()
}

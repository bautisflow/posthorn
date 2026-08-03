package storage

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"
)

// idemRecord is the serialized form of a cached idempotent response.
// Body round-trips through JSON's base64 []byte encoding.
type idemRecord struct {
	Status      int    `json:"status"`
	ContentType string `json:"content_type"`
	Body        []byte `json:"body"`
}

// PutIdempotent stores a response under (key, endpoint) until expiresAt
// (FR81). Same-key overwrites are last-write-wins — the caller already
// serialized via the in-flight claim.
func (s *Store) PutIdempotent(key, endpoint string, status int, contentType string, body []byte, expiresAt time.Time) error {
	blob, err := json.Marshal(idemRecord{Status: status, ContentType: contentType, Body: body})
	if err != nil {
		return fmt.Errorf("storage: marshal idempotent response: %w", err)
	}
	_, err = s.db.Exec(`
		INSERT INTO idempotency (key, endpoint, response, expires_at)
		VALUES (?, ?, ?, ?)
		ON CONFLICT(key, endpoint) DO UPDATE SET
		  response = excluded.response, expires_at = excluded.expires_at`,
		key, endpoint, blob, expiresAt.Unix())
	if err != nil {
		return fmt.Errorf("storage: put idempotent: %w", err)
	}
	return nil
}

// GetIdempotent fetches a TTL-valid cached response. Expired rows are
// misses (background pruning removes them; correctness doesn't depend
// on the pruner's timing).
func (s *Store) GetIdempotent(key, endpoint string, now time.Time) (status int, contentType string, body []byte, ok bool, err error) {
	var blob []byte
	var expiresAt int64
	row := s.db.QueryRow(
		`SELECT response, expires_at FROM idempotency WHERE key = ? AND endpoint = ?`,
		key, endpoint)
	if err := row.Scan(&blob, &expiresAt); err != nil {
		if err == sql.ErrNoRows {
			return 0, "", nil, false, nil
		}
		return 0, "", nil, false, fmt.Errorf("storage: get idempotent: %w", err)
	}
	if now.Unix() >= expiresAt {
		return 0, "", nil, false, nil
	}
	var rec idemRecord
	if err := json.Unmarshal(blob, &rec); err != nil {
		return 0, "", nil, false, fmt.Errorf("storage: decode idempotent response: %w", err)
	}
	return rec.Status, rec.ContentType, rec.Body, true, nil
}

// PruneIdempotency deletes expired rows (FR81 background cleanup).
func (s *Store) PruneIdempotency(now time.Time) (int64, error) {
	res, err := s.db.Exec(`DELETE FROM idempotency WHERE expires_at <= ?`, now.Unix())
	if err != nil {
		return 0, fmt.Errorf("storage: prune idempotency: %w", err)
	}
	n, _ := res.RowsAffected()
	return n, nil
}

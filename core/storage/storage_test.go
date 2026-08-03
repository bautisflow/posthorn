package storage

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var t0 = time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)

func memStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(Config{InMemory: true})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func sampleSubmission(id, status string) Submission {
	return Submission{
		ID:        id,
		Endpoint:  "/contact",
		Transport: "postmark",
		From:      "noreply@example.com",
		ToAddrs:   []string{"a@example.com", "b@example.com"},
		ReplyTo:   "jane@example.com",
		Subject:   "Hello",
		BodyText:  "text part",
		BodyHTML:  "<p>html part</p>",
		Fields:    map[string][]string{"name": {"Jane"}, "tags": {"x", "y"}},
		ClientIP:  "203.0.113.9",
		Status:    status,
		CreatedAt: t0,
	}
}

func TestOpen_RequiresPathOrMemory(t *testing.T) {
	if _, err := Open(Config{}); err == nil {
		t.Fatal("expected error for empty path without in_memory")
	}
}

func TestRecordAndGet_RoundTrip(t *testing.T) {
	s := memStore(t)
	want := sampleSubmission("sub-1", StatusSending)
	if err := s.RecordSubmission(want); err != nil {
		t.Fatalf("RecordSubmission: %v", err)
	}
	got, ok, err := s.GetSubmission("sub-1")
	if err != nil || !ok {
		t.Fatalf("GetSubmission: ok=%v err=%v", ok, err)
	}
	if got.BodyHTML != want.BodyHTML || got.BodyText != want.BodyText {
		t.Errorf("bodies = %q / %q", got.BodyText, got.BodyHTML)
	}
	if len(got.ToAddrs) != 2 || got.ToAddrs[1] != "b@example.com" {
		t.Errorf("ToAddrs = %v", got.ToAddrs)
	}
	if got.Fields["tags"][1] != "y" {
		t.Errorf("Fields = %v", got.Fields)
	}
	if !got.CreatedAt.Equal(t0) {
		t.Errorf("CreatedAt = %v", got.CreatedAt)
	}
	if !got.SentAt.IsZero() {
		t.Errorf("SentAt should be zero, got %v", got.SentAt)
	}
	if got.ClientIP != "203.0.113.9" {
		t.Errorf("ClientIP = %q", got.ClientIP)
	}
}

func TestMarkSent_SetsStatusAndTimestamp(t *testing.T) {
	s := memStore(t)
	if err := s.RecordSubmission(sampleSubmission("sub-1", StatusSending)); err != nil {
		t.Fatal(err)
	}
	sentAt := t0.Add(2 * time.Second)
	if err := s.MarkSent("sub-1", "pm-msg-123", sentAt); err != nil {
		t.Fatalf("MarkSent: %v", err)
	}
	got, _, _ := s.GetSubmission("sub-1")
	if got.Status != StatusSent {
		t.Errorf("Status = %q", got.Status)
	}
	if got.TransportMessageID != "pm-msg-123" {
		t.Errorf("TransportMessageID = %q", got.TransportMessageID)
	}
	if !got.SentAt.Equal(sentAt) {
		t.Errorf("SentAt = %v", got.SentAt)
	}
}

func TestMarkStatus_RecordsError(t *testing.T) {
	s := memStore(t)
	if err := s.RecordSubmission(sampleSubmission("sub-1", StatusSending)); err != nil {
		t.Fatal(err)
	}
	if err := s.MarkStatus("sub-1", StatusFailed, "postmark 422"); err != nil {
		t.Fatalf("MarkStatus: %v", err)
	}
	got, _, _ := s.GetSubmission("sub-1")
	if got.Status != StatusFailed || got.LastError != "postmark 422" {
		t.Errorf("got %q / %q", got.Status, got.LastError)
	}
}

func TestFindByMessageID(t *testing.T) {
	s := memStore(t)
	sub := sampleSubmission("sub-1", StatusSending)
	if err := s.RecordSubmission(sub); err != nil {
		t.Fatal(err)
	}
	if err := s.MarkSent("sub-1", "pm-msg-123", t0); err != nil {
		t.Fatal(err)
	}
	got, ok, err := s.FindByMessageID("pm-msg-123")
	if err != nil || !ok {
		t.Fatalf("FindByMessageID: ok=%v err=%v", ok, err)
	}
	if got.ID != "sub-1" {
		t.Errorf("ID = %q", got.ID)
	}
	if _, ok, _ := s.FindByMessageID("unknown"); ok {
		t.Error("unknown message ID should not resolve")
	}
	if _, ok, _ := s.FindByMessageID(""); ok {
		t.Error("empty message ID must never resolve")
	}
}

func TestOpen_FileReopen_MigrationsIdempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "posthorn.db")

	s1, err := Open(Config{Path: path})
	if err != nil {
		t.Fatalf("first Open: %v", err)
	}
	if err := s1.RecordSubmission(sampleSubmission("sub-1", StatusSent)); err != nil {
		t.Fatal(err)
	}
	_ = s1.Close()

	s2, err := Open(Config{Path: path})
	if err != nil {
		t.Fatalf("second Open: %v", err)
	}
	defer func() { _ = s2.Close() }()

	got, ok, err := s2.GetSubmission("sub-1")
	if err != nil || !ok {
		t.Fatalf("data lost across reopen: ok=%v err=%v", ok, err)
	}
	if got.Subject != "Hello" {
		t.Errorf("Subject = %q", got.Subject)
	}

	var version int
	if err := s2.db.QueryRow("PRAGMA user_version").Scan(&version); err != nil {
		t.Fatal(err)
	}
	if version != schemaVersion {
		t.Errorf("user_version = %d, want %d", version, schemaVersion)
	}
}

func TestOpen_RefusesNewerSchema(t *testing.T) {
	path := filepath.Join(t.TempDir(), "posthorn.db")
	s, err := Open(Config{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec("PRAGMA user_version = 99"); err != nil {
		t.Fatal(err)
	}
	_ = s.Close()

	if _, err := Open(Config{Path: path}); err == nil || !strings.Contains(err.Error(), "newer") {
		t.Fatalf("expected newer-schema refusal, got %v", err)
	}
}

func TestOpen_RecoversInFlightToQueue(t *testing.T) {
	path := filepath.Join(t.TempDir(), "posthorn.db")
	s, err := Open(Config{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	// Simulate a crash mid-send: row committed as "sending", process dies.
	if err := s.RecordSubmission(sampleSubmission("sub-crash", StatusSending)); err != nil {
		t.Fatal(err)
	}
	_ = s.Close()

	s2, err := Open(Config{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s2.Close() }()

	got, _, _ := s2.GetSubmission("sub-crash")
	if got.Status != StatusQueued {
		t.Errorf("crashed in-flight row: status = %q, want %q (NFR28 at-least-once)", got.Status, StatusQueued)
	}
	var n int
	if err := s2.db.QueryRow(
		`SELECT COUNT(*) FROM retry_queue WHERE submission_id = ?`, "sub-crash").Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Errorf("retry_queue rows = %d, want 1", n)
	}
}

func TestPrune_KeepsPendingAndRecent(t *testing.T) {
	s := memStore(t)
	old := sampleSubmission("old-sent", StatusSent)
	old.CreatedAt = t0.Add(-40 * 24 * time.Hour)
	oldQueued := sampleSubmission("old-queued", StatusQueued)
	oldQueued.CreatedAt = t0.Add(-40 * 24 * time.Hour)
	fresh := sampleSubmission("fresh", StatusSent)
	for _, sub := range []Submission{old, oldQueued, fresh} {
		if err := s.RecordSubmission(sub); err != nil {
			t.Fatal(err)
		}
	}

	n, err := s.Prune(t0.Add(-30 * 24 * time.Hour))
	if err != nil {
		t.Fatalf("Prune: %v", err)
	}
	if n != 1 {
		t.Errorf("pruned = %d, want 1", n)
	}
	if _, ok, _ := s.GetSubmission("old-sent"); ok {
		t.Error("old sent row survived prune")
	}
	if _, ok, _ := s.GetSubmission("old-queued"); !ok {
		t.Error("pending queued row must survive prune regardless of age")
	}
	if _, ok, _ := s.GetSubmission("fresh"); !ok {
		t.Error("recent row must survive prune")
	}
}

func TestProbe_WritesCanary(t *testing.T) {
	s := memStore(t)
	if err := s.Probe(t0); err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if err := s.Probe(t0.Add(time.Minute)); err != nil {
		t.Fatalf("second Probe: %v", err)
	}
	var at int64
	if err := s.db.QueryRow(`SELECT at FROM canary WHERE id = 1`).Scan(&at); err != nil {
		t.Fatal(err)
	}
	if at != t0.Add(time.Minute).Unix() {
		t.Errorf("canary at = %d", at)
	}
}

func TestProbe_FailsAfterClose(t *testing.T) {
	s, err := Open(Config{InMemory: true})
	if err != nil {
		t.Fatal(err)
	}
	_ = s.Close()
	if err := s.Probe(t0); err == nil {
		t.Fatal("Probe on closed store should error (degrade signal)")
	}
}

func TestMaxSize_CapsGrowthButStaysOperable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "capped.db")
	s, err := Open(Config{Path: path, MaxSize: 256 * 1024}) // 256KB cap
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()

	big := strings.Repeat("x", 8*1024)
	var hitCap bool
	for i := 0; i < 1000; i++ {
		sub := sampleSubmission(fmt.Sprintf("sub-%04d", i), StatusSent)
		sub.BodyText = big
		if err := s.RecordSubmission(sub); err != nil {
			hitCap = true
			break
		}
	}
	if !hitCap {
		t.Fatal("256KB cap never enforced across 8MB of inserts (FR79)")
	}

	// The whole point of the cap: pruning must still work at the cap,
	// and after pruning the store accepts writes again.
	if _, err := s.Prune(t0.Add(24 * time.Hour)); err != nil {
		t.Fatalf("Prune at cap: %v", err)
	}
	if err := s.RecordSubmission(sampleSubmission("after-prune", StatusSent)); err != nil {
		t.Fatalf("insert after prune: %v", err)
	}
}

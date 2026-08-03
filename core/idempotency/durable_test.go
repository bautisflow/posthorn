package idempotency

import (
	"errors"
	"io"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"github.com/craigmccaskill/posthorn/storage"
)

func testGate(t *testing.T, cfg storage.Config) *storage.Gate {
	t.Helper()
	st, err := storage.Open(cfg)
	if err != nil {
		t.Fatalf("storage.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return storage.NewGate(st, slog.New(slog.NewTextHandler(io.Discard, nil)))
}

func TestDurable_StoreThenLookup_ByteIdentical(t *testing.T) {
	g := testGate(t, storage.Config{InMemory: true})
	d := NewDurable(g, "/api/x", time.Hour)

	if !d.ClaimInFlight("k1") {
		t.Fatal("claim refused on empty cache")
	}
	d.Store("k1", Response{Status: 200, ContentType: "application/json", Body: []byte(`{"status":"ok","submission_id":"abc"}`)})

	resp, inflight := d.Lookup("k1")
	if inflight {
		t.Fatal("in-flight after Store")
	}
	if resp == nil {
		t.Fatal("miss after Store")
	}
	if resp.Status != 200 || resp.ContentType != "application/json" ||
		string(resp.Body) != `{"status":"ok","submission_id":"abc"}` {
		t.Errorf("replay not byte-identical: %+v", resp)
	}
}

func TestDurable_SurvivesRestart(t *testing.T) {
	// The FR81 acceptance: a response cached before a restart replays
	// after it.
	path := filepath.Join(t.TempDir(), "posthorn.db")
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	st1, err := storage.Open(storage.Config{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	d1 := NewDurable(storage.NewGate(st1, logger), "/api/x", time.Hour)
	d1.Store("k1", Response{Status: 202, ContentType: "application/json", Body: []byte(`{"status":"queued"}`)})
	_ = st1.Close()

	st2, err := storage.Open(storage.Config{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st2.Close() }()
	d2 := NewDurable(storage.NewGate(st2, logger), "/api/x", time.Hour)

	resp, _ := d2.Lookup("k1")
	if resp == nil {
		t.Fatal("cached response lost across restart")
	}
	// NFR20: a queued 202 replays as that 202, even post-restart.
	if resp.Status != 202 || string(resp.Body) != `{"status":"queued"}` {
		t.Errorf("replay = %+v", resp)
	}
}

func TestDurable_PerEndpointScoping(t *testing.T) {
	g := testGate(t, storage.Config{InMemory: true})
	a := NewDurable(g, "/api/a", time.Hour)
	b := NewDurable(g, "/api/b", time.Hour)

	a.Store("k1", Response{Status: 200, Body: []byte("a")})
	if resp, _ := b.Lookup("k1"); resp != nil {
		t.Fatal("key leaked across endpoints (FR41)")
	}
}

func TestDurable_InFlight409Semantics(t *testing.T) {
	g := testGate(t, storage.Config{InMemory: true})
	d := NewDurable(g, "/api/x", time.Hour)

	if !d.ClaimInFlight("k1") {
		t.Fatal("first claim refused")
	}
	if d.ClaimInFlight("k1") {
		t.Fatal("second claim succeeded while in flight (ADR-9)")
	}
	if _, inflight := d.Lookup("k1"); !inflight {
		t.Fatal("Lookup should report in-flight")
	}
	d.Abandon("k1")
	if !d.ClaimInFlight("k1") {
		t.Fatal("claim refused after Abandon")
	}
}

func TestDurable_ClaimRefusedWhenStored(t *testing.T) {
	g := testGate(t, storage.Config{InMemory: true})
	d := NewDurable(g, "/api/x", time.Hour)
	d.Store("k1", Response{Status: 200, Body: []byte("x")})
	if d.ClaimInFlight("k1") {
		t.Fatal("claim must be refused for a completed key (caller re-Lookups)")
	}
}

func TestDurable_TTLExpiryIsAMiss(t *testing.T) {
	g := testGate(t, storage.Config{InMemory: true})
	d := NewDurable(g, "/api/x", time.Hour)
	base := time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)
	d.now = func() time.Time { return base }
	d.Store("k1", Response{Status: 200, Body: []byte("x")})

	d.now = func() time.Time { return base.Add(2 * time.Hour) }
	if resp, _ := d.Lookup("k1"); resp != nil {
		t.Fatal("expired entry replayed")
	}
	if !d.ClaimInFlight("k1") {
		t.Fatal("claim refused for expired entry")
	}
}

func TestDurable_DegradedGate_FailsOpen(t *testing.T) {
	g := testGate(t, storage.Config{InMemory: true})
	d := NewDurable(g, "/api/x", time.Hour)
	d.Store("k1", Response{Status: 200, Body: []byte("x")})

	g.ReportError(errors.New("disk full"))

	// Miss (fresh send) rather than error — mail first (NFR27). The
	// documented cost: retried keys may double-send during an outage.
	if resp, _ := d.Lookup("k1"); resp != nil {
		t.Fatal("degraded lookup should miss")
	}
	if !d.ClaimInFlight("k1") {
		t.Fatal("claim should succeed while degraded")
	}
	d.Store("k1", Response{Status: 200, Body: []byte("y")}) // must not panic
}

func TestDurable_PruneRemovesExpired(t *testing.T) {
	g := testGate(t, storage.Config{InMemory: true})
	d := NewDurable(g, "/api/x", time.Minute)
	base := time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)
	d.now = func() time.Time { return base }
	d.Store("k1", Response{Status: 200, Body: []byte("x")})

	n, err := g.Store().PruneIdempotency(base.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Errorf("pruned = %d", n)
	}
}

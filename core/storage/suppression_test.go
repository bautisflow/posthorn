package storage

import (
	"testing"
	"time"
)

func TestSuppression_AddLookupRemove(t *testing.T) {
	s := memStore(t)
	if err := s.AddSuppression("Bounced@Example.COM", ReasonHardBounce, "/contact", t0); err != nil {
		t.Fatalf("AddSuppression: %v", err)
	}

	// Lookup is case-insensitive both directions.
	sup, ok, err := s.SuppressionFor("bounced@example.com")
	if err != nil || !ok {
		t.Fatalf("SuppressionFor: ok=%v err=%v", ok, err)
	}
	if sup.Reason != ReasonHardBounce || sup.SourceEndpoint != "/contact" {
		t.Errorf("sup = %+v", sup)
	}
	if _, ok, _ := s.SuppressionFor("BOUNCED@example.com"); !ok {
		t.Error("case-variant lookup missed")
	}
	if _, ok, _ := s.SuppressionFor("clean@example.com"); ok {
		t.Error("clean address reported suppressed")
	}

	n, err := s.RemoveSuppression("BOUNCED@EXAMPLE.COM")
	if err != nil || n != 1 {
		t.Fatalf("RemoveSuppression: n=%d err=%v", n, err)
	}
	if _, ok, _ := s.SuppressionFor("bounced@example.com"); ok {
		t.Error("still suppressed after remove")
	}
}

func TestSuppression_IdempotentPerReason_RemoveClearsAll(t *testing.T) {
	s := memStore(t)
	if err := s.AddSuppression("x@example.com", ReasonHardBounce, "/a", t0); err != nil {
		t.Fatal(err)
	}
	// Same (email, reason) again: first observation wins, no error.
	if err := s.AddSuppression("x@example.com", ReasonHardBounce, "/b", t0.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	// A second reason coexists.
	if err := s.AddSuppression("x@example.com", ReasonSpamComplaint, "/a", t0.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}

	list, err := s.ListSuppressions(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 2 {
		t.Fatalf("rows = %d, want 2", len(list))
	}
	if list[0].SourceEndpoint != "/a" || !list[0].CreatedAt.Equal(t0) {
		t.Errorf("first row lost first-observation data: %+v", list[0])
	}

	n, _ := s.RemoveSuppression("x@example.com")
	if n != 2 {
		t.Errorf("remove cleared %d rows, want 2 (all reasons)", n)
	}
}

func TestSuppression_ExemptFromPrune(t *testing.T) {
	s := memStore(t)
	old := t0.Add(-400 * 24 * time.Hour)
	if err := s.AddSuppression("x@example.com", ReasonHardBounce, "/a", old); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Prune(t0); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := s.SuppressionFor("x@example.com"); !ok {
		t.Fatal("suppression pruned — rows must be retention-exempt (ADR-23)")
	}
}

func TestForwardQueue_LadderAndDrop(t *testing.T) {
	s := memStore(t)
	payload := []byte(`{"event":"delivered"}`)
	if err := s.EnqueueForward("/contact", payload, t0); err != nil {
		t.Fatalf("EnqueueForward: %v", err)
	}

	// Not due before the first backoff.
	if due, _ := s.ClaimDueForwards(t0.Add(RetryBackoff[0]-time.Second), 10); len(due) != 0 {
		t.Fatalf("due early: %d", len(due))
	}
	due, err := s.ClaimDueForwards(t0.Add(RetryBackoff[0]+time.Second), 10)
	if err != nil || len(due) != 1 {
		t.Fatalf("due = %d err=%v", len(due), err)
	}
	if string(due[0].Payload) != string(payload) || due[0].Endpoint != "/contact" {
		t.Errorf("claimed = %+v", due[0])
	}

	// Ladder through retryable failures until dropped.
	id := due[0].ID
	var droppedAt int
	for i := 1; i <= MaxAttempts; i++ {
		dropped, err := s.RecordForwardOutcome(id, true, t0)
		if err != nil {
			t.Fatalf("attempt %d: %v", i, err)
		}
		if dropped {
			droppedAt = i
			break
		}
	}
	if droppedAt != MaxAttempts {
		t.Fatalf("dropped at attempt %d, want %d", droppedAt, MaxAttempts)
	}
	if due, _ := s.ClaimDueForwards(t0.Add(365*24*time.Hour), 10); len(due) != 0 {
		t.Errorf("row survived drop: %d", len(due))
	}
}

func TestForwardQueue_SuccessRemoves(t *testing.T) {
	s := memStore(t)
	if err := s.EnqueueForward("/contact", []byte("{}"), t0); err != nil {
		t.Fatal(err)
	}
	due, _ := s.ClaimDueForwards(t0.Add(time.Hour), 10)
	if len(due) != 1 {
		t.Fatal("nothing due")
	}
	if _, err := s.RecordForwardOutcome(due[0].ID, false, t0); err != nil {
		t.Fatal(err)
	}
	if due, _ := s.ClaimDueForwards(t0.Add(365*24*time.Hour), 10); len(due) != 0 {
		t.Errorf("row survived success: %d", len(due))
	}
}

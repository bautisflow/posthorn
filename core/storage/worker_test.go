package storage

import (
	"context"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/craigmccaskill/posthorn/transport"
)

type fakeSender struct {
	mu    sync.Mutex
	calls []transport.Message
	errs  []error // consumed in order; nil = success
}

func (f *fakeSender) send(_ context.Context, _ string, msg transport.Message) (transport.SendResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, msg)
	if len(f.errs) > 0 {
		err := f.errs[0]
		f.errs = f.errs[1:]
		if err != nil {
			return transport.SendResult{}, err
		}
	}
	return transport.SendResult{MessageID: "msg-ok"}, nil
}

func newWorker(s *Store, f *fakeSender, now time.Time) *Worker {
	return &Worker{
		Store:  s,
		Send:   f.send,
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Now:    func() time.Time { return now },
	}
}

func enqueueSample(t *testing.T, s *Store, id string) {
	t.Helper()
	if err := s.RecordSubmission(sampleSubmission(id, StatusSending)); err != nil {
		t.Fatal(err)
	}
	if err := s.Enqueue(id, t0); err != nil {
		t.Fatal(err)
	}
}

func TestWorker_SendsDueEntryAndMarksSent(t *testing.T) {
	s := memStore(t)
	enqueueSample(t, s, "sub-1")
	f := &fakeSender{}
	w := newWorker(s, f, t0.Add(time.Hour))

	var sent []string
	w.ProcessDue(context.Background(), Hooks{OnSent: func(ep string) { sent = append(sent, ep) }})

	if len(f.calls) != 1 {
		t.Fatalf("send calls = %d", len(f.calls))
	}
	msg := f.calls[0]
	if msg.BodyHTML != "<p>html part</p>" || msg.BodyText != "text part" || len(msg.To) != 2 {
		t.Errorf("replayed message lost content: %+v", msg)
	}
	got, _, _ := s.GetSubmission("sub-1")
	if got.Status != StatusSent || got.TransportMessageID != "msg-ok" {
		t.Errorf("status=%q msgid=%q", got.Status, got.TransportMessageID)
	}
	if n, _ := s.QueueDepth(); n != 0 {
		t.Errorf("queue depth = %d", n)
	}
	if len(sent) != 1 || sent[0] != "/contact" {
		t.Errorf("OnSent hooks = %v", sent)
	}
}

func TestWorker_NothingDue_NoSends(t *testing.T) {
	s := memStore(t)
	enqueueSample(t, s, "sub-1")
	f := &fakeSender{}
	w := newWorker(s, f, t0) // before first backoff elapses

	w.ProcessDue(context.Background(), Hooks{})
	if len(f.calls) != 0 {
		t.Errorf("sent %d messages before due time", len(f.calls))
	}
}

func TestWorker_TransientFailure_Reladders(t *testing.T) {
	s := memStore(t)
	enqueueSample(t, s, "sub-1")
	f := &fakeSender{errs: []error{
		&transport.TransportError{Class: transport.ErrTransient, Message: "upstream 503"},
	}}
	w := newWorker(s, f, t0.Add(time.Hour))

	var retried int
	w.ProcessDue(context.Background(), Hooks{OnRetryAgain: func(string) { retried++ }})

	got, _, _ := s.GetSubmission("sub-1")
	if got.Status != StatusQueued {
		t.Errorf("status = %q, want queued", got.Status)
	}
	if n, _ := s.QueueDepth(); n != 1 {
		t.Errorf("queue depth = %d", n)
	}
	if retried != 1 {
		t.Errorf("OnRetryAgain = %d", retried)
	}
}

func TestWorker_RateLimitedFailure_Reladders(t *testing.T) {
	s := memStore(t)
	enqueueSample(t, s, "sub-1")
	f := &fakeSender{errs: []error{
		&transport.TransportError{Class: transport.ErrRateLimited, Status: 429, Message: "slow down"},
	}}
	w := newWorker(s, f, t0.Add(time.Hour))
	w.ProcessDue(context.Background(), Hooks{})

	got, _, _ := s.GetSubmission("sub-1")
	if got.Status != StatusQueued {
		t.Errorf("status = %q, want queued", got.Status)
	}
}

func TestWorker_TerminalFailure_DeadLettersImmediately(t *testing.T) {
	s := memStore(t)
	enqueueSample(t, s, "sub-1")
	f := &fakeSender{errs: []error{
		&transport.TransportError{Class: transport.ErrTerminal, Status: 422, Message: "bad address"},
	}}
	w := newWorker(s, f, t0.Add(time.Hour))

	var dead int
	w.ProcessDue(context.Background(), Hooks{OnDeadLetter: func(string) { dead++ }})

	got, _, _ := s.GetSubmission("sub-1")
	if got.Status != StatusFailed {
		t.Errorf("status = %q, want failed (terminal must not ladder)", got.Status)
	}
	if n, _ := s.QueueDepth(); n != 0 {
		t.Errorf("queue depth = %d", n)
	}
	if dead != 1 {
		t.Errorf("OnDeadLetter = %d", dead)
	}
}

func TestWorker_NonTransportError_TreatedTerminal(t *testing.T) {
	s := memStore(t)
	enqueueSample(t, s, "sub-1")
	f := &fakeSender{errs: []error{context.DeadlineExceeded}}
	w := newWorker(s, f, t0.Add(time.Hour))
	w.ProcessDue(context.Background(), Hooks{})

	got, _, _ := s.GetSubmission("sub-1")
	if got.Status != StatusFailed {
		t.Errorf("status = %q — a bare error is a contract bug and must dead-letter, not loop", got.Status)
	}
}

func TestWorker_ExhaustsLadderThenDeadLetters(t *testing.T) {
	s := memStore(t)
	enqueueSample(t, s, "sub-1")

	transient := func() error {
		return &transport.TransportError{Class: transport.ErrTransient, Message: "e"}
	}
	f := &fakeSender{}
	for i := 0; i < MaxAttempts; i++ {
		f.errs = append(f.errs, transient())
	}

	now := t0.Add(time.Hour)
	var dead int
	hooks := Hooks{OnDeadLetter: func(string) { dead++ }}
	for i := 0; i < MaxAttempts; i++ {
		w := newWorker(s, f, now)
		w.ProcessDue(context.Background(), hooks)
		now = now.Add(RetryBackoff[len(RetryBackoff)-1] + time.Hour)
	}

	if len(f.calls) != MaxAttempts {
		t.Fatalf("send calls = %d, want %d", len(f.calls), MaxAttempts)
	}
	got, _, _ := s.GetSubmission("sub-1")
	if got.Status != StatusFailed {
		t.Errorf("status = %q after ladder exhaustion", got.Status)
	}
	if dead != 1 {
		t.Errorf("OnDeadLetter = %d", dead)
	}
}

func TestWorker_RunStopsOnCancel(t *testing.T) {
	s := memStore(t)
	f := &fakeSender{}
	w := newWorker(s, f, t0)
	w.Interval = 5 * time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		w.Run(ctx, Hooks{})
		close(done)
	}()
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("worker did not stop on context cancel")
	}
}

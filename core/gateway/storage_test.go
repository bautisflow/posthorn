package gateway_test

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/craigmccaskill/posthorn/config"
	"github.com/craigmccaskill/posthorn/gateway"
	"github.com/craigmccaskill/posthorn/storage"
	"github.com/craigmccaskill/posthorn/transport"
)

// FR77/FR78 wiring: the handler records submissions pre-send, finalizes
// them on outcome, and moves transient exhaustion to the queue with the
// 202 contract. Without an attached gate every test in handler_test.go
// already proves v1.x behavior is untouched.

func newGate(t *testing.T) *storage.Gate {
	t.Helper()
	st, err := storage.Open(storage.Config{InMemory: true})
	if err != nil {
		t.Fatalf("storage.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return storage.NewGate(st, slog.New(slog.NewTextHandler(io.Discard, nil)))
}

func transientErr() error {
	return &transport.TransportError{Class: transport.ErrTransient, Message: "upstream 503"}
}

func terminalErr() error {
	return &transport.TransportError{Class: transport.ErrTerminal, Status: 422, Message: "bad address"}
}

func TestStorage_SuccessfulSend_RecordsSentRow(t *testing.T) {
	tr := &recordingTransport{sendResult: transport.SendResult{MessageID: "pm-1"}}
	h := newTestHandler(t, tr)
	gate := newGate(t)
	h.AttachStorage(gate)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, urlencodedRequest("email=a@b.com&message=hi"))
	if rec.Code != 200 {
		t.Fatalf("status = %d", rec.Code)
	}

	var resp struct {
		SubmissionID string `json:"submission_id"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	sub, ok, err := gate.Store().GetSubmission(resp.SubmissionID)
	if err != nil || !ok {
		t.Fatalf("submission row missing: ok=%v err=%v", ok, err)
	}
	if sub.Status != storage.StatusSent {
		t.Errorf("status = %q", sub.Status)
	}
	if sub.TransportMessageID != "pm-1" {
		t.Errorf("transport_message_id = %q", sub.TransportMessageID)
	}
	if sub.Endpoint != "/test" || len(sub.ToAddrs) != 1 {
		t.Errorf("row = %+v", sub)
	}
	if sub.Fields["message"][0] != "hi" {
		t.Errorf("fields = %v", sub.Fields)
	}
}

func TestStorage_TransientExhaustion_QueuesWith202(t *testing.T) {
	restore := gateway.SetRetryDelaysForTest(time.Millisecond, time.Millisecond, 10*time.Second)
	defer restore()

	tr := &recordingTransport{sendErr: transientErr()}
	h, err := gateway.New(apiModeConfig("valid-key"), tr)
	if err != nil {
		t.Fatal(err)
	}
	gate := newGate(t)
	h.AttachStorage(gate)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, apiRequest(`{"email":"a@b.com","message":"hi"}`, "valid-key"))

	if rec.Code != 202 {
		t.Fatalf("status = %d, want 202 (FR78 queued contract); body=%s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Status       string `json:"status"`
		SubmissionID string `json:"submission_id"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Status != "queued" || resp.SubmissionID == "" {
		t.Fatalf("body = %+v", resp)
	}

	sub, ok, _ := gate.Store().GetSubmission(resp.SubmissionID)
	if !ok || sub.Status != storage.StatusQueued {
		t.Errorf("row status = %q ok=%v", sub.Status, ok)
	}
	if n, _ := gate.Store().QueueDepth(); n != 1 {
		t.Errorf("queue depth = %d", n)
	}
}

func TestStorage_FormMode_TransientExhaustion_QueuesWithSuccessShape(t *testing.T) {
	restore := gateway.SetRetryDelaysForTest(time.Millisecond, time.Millisecond, 10*time.Second)
	defer restore()

	tr := &recordingTransport{sendErr: transientErr()}
	h := newTestHandler(t, tr)
	gate := newGate(t)
	h.AttachStorage(gate)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, urlencodedRequest("email=a@b.com&message=hi"))

	if rec.Code != 200 {
		t.Fatalf("status = %d (form-mode queued follows the success shape)", rec.Code)
	}
	var resp struct {
		Status string `json:"status"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp.Status != "queued" {
		t.Errorf("status field = %q", resp.Status)
	}
	if n, _ := gate.Store().QueueDepth(); n != 1 {
		t.Errorf("queue depth = %d", n)
	}
}

func TestStorage_TerminalFailure_MarksFailedNo202(t *testing.T) {
	tr := &recordingTransport{sendErr: terminalErr()}
	h := newTestHandler(t, tr)
	gate := newGate(t)
	h.AttachStorage(gate)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, urlencodedRequest("email=a@b.com&message=hi"))

	if rec.Code != 502 {
		t.Fatalf("status = %d, want 502 (terminal never queues)", rec.Code)
	}
	if n, _ := gate.Store().QueueDepth(); n != 0 {
		t.Errorf("queue depth = %d", n)
	}
	sub := findOnlySubmission(t, gate.Store())
	if sub.Status != storage.StatusFailed {
		t.Errorf("status = %q, want failed", sub.Status)
	}
	if sub.LastError == "" {
		t.Error("last_error empty on terminal failure")
	}
}

func TestStorage_LogFailedFalse_MetadataOnlyAndNoQueue(t *testing.T) {
	restore := gateway.SetRetryDelaysForTest(time.Millisecond, time.Millisecond, 10*time.Second)
	defer restore()

	lf := false
	cfg := config.EndpointConfig{
		Path:                 "/test",
		To:                   []string{"to@example.com"},
		From:                 "from@example.com",
		Subject:              "Subject {{.message}}",
		Body:                 "Body {{.message}}",
		LogFailedSubmissions: &lf,
	}
	tr := &recordingTransport{sendErr: transientErr()}
	h, err := gateway.New(cfg, tr)
	if err != nil {
		t.Fatal(err)
	}
	gate := newGate(t)
	h.AttachStorage(gate)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, urlencodedRequest("email=a@b.com&message=secret"))

	if rec.Code != 502 {
		t.Fatalf("status = %d — LFS=false endpoints must not queue (ADR-21)", rec.Code)
	}
	if n, _ := gate.Store().QueueDepth(); n != 0 {
		t.Errorf("queue depth = %d", n)
	}
	// Row exists but carries no submitter content.
	sub := findOnlySubmission(t, gate.Store())
	if sub.Subject != "" || sub.BodyText != "" || len(sub.Fields) != 0 || len(sub.ToAddrs) != 0 {
		t.Errorf("metadata-only row leaked content: %+v", sub)
	}
	if sub.Endpoint != "/test" || sub.Status != storage.StatusFailed {
		t.Errorf("metadata row = %+v", sub)
	}
}

func TestStorage_StripClientIP_OmitsIPFromRow(t *testing.T) {
	cfg := config.EndpointConfig{
		Path:          "/test",
		To:            []string{"to@example.com"},
		From:          "from@example.com",
		Subject:       "S",
		Body:          "B",
		StripClientIP: true,
	}
	tr := &recordingTransport{}
	h, err := gateway.New(cfg, tr)
	if err != nil {
		t.Fatal(err)
	}
	gate := newGate(t)
	h.AttachStorage(gate)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, urlencodedRequest("email=a@b.com&message=hi"))
	if rec.Code != 200 {
		t.Fatalf("status = %d", rec.Code)
	}
	sub := findOnlySubmission(t, gate.Store())
	if sub.ClientIP != "" {
		t.Errorf("ClientIP = %q, want empty under strip_client_ip", sub.ClientIP)
	}
}

func TestStorage_DegradedGate_FallsBackToV1Behavior(t *testing.T) {
	restore := gateway.SetRetryDelaysForTest(time.Millisecond, time.Millisecond, 10*time.Second)
	defer restore()

	tr := &recordingTransport{sendErr: transientErr()}
	h := newTestHandler(t, tr)
	gate := newGate(t)
	gate.ReportError(errors.New("disk full"))
	h.AttachStorage(gate)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, urlencodedRequest("email=a@b.com&message=hi"))

	if rec.Code != 502 {
		t.Fatalf("status = %d — degraded storage must behave like v1.x (NFR27)", rec.Code)
	}
	if n, _ := gate.Store().QueueDepth(); n != 0 {
		t.Errorf("queue depth = %d while degraded", n)
	}
}

func TestStorage_DryRun_RecordsNothing(t *testing.T) {
	cfg := config.EndpointConfig{
		Path:    "/test",
		To:      []string{"to@example.com"},
		From:    "from@example.com",
		Subject: "S",
		Body:    "B",
		DryRun:  true,
	}
	tr := &recordingTransport{}
	h, err := gateway.New(cfg, tr)
	if err != nil {
		t.Fatal(err)
	}
	gate := newGate(t)
	h.AttachStorage(gate)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, urlencodedRequest("email=a@b.com&message=hi"))
	if rec.Code != 200 {
		t.Fatalf("status = %d", rec.Code)
	}
	assertNoSubmissions(t, gate.Store())
}

func TestStorage_DurableIdempotency_ReplaysAcrossRestart(t *testing.T) {
	// FR81 end-to-end: an api-mode response cached under an
	// Idempotency-Key before a process restart replays byte-identically
	// after it, with no second send.
	path := t.TempDir() + "/posthorn.db"
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	st1, err := storage.Open(storage.Config{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	tr1 := &recordingTransport{sendResult: transport.SendResult{MessageID: "pm-1"}}
	h1, err := gateway.New(apiModeConfig("valid-key"), tr1)
	if err != nil {
		t.Fatal(err)
	}
	h1.AttachStorage(storage.NewGate(st1, logger))

	req := apiRequest(`{"email":"a@b.com","message":"hi"}`, "valid-key")
	req.Header.Set("Idempotency-Key", "order-42")
	rec1 := httptest.NewRecorder()
	h1.ServeHTTP(rec1, req)
	if rec1.Code != 200 {
		t.Fatalf("first request: %d %s", rec1.Code, rec1.Body.String())
	}
	if len(tr1.sent) != 1 {
		t.Fatalf("first request sends = %d", len(tr1.sent))
	}
	_ = st1.Close() // "restart"

	st2, err := storage.Open(storage.Config{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st2.Close() })
	tr2 := &recordingTransport{}
	h2, err := gateway.New(apiModeConfig("valid-key"), tr2)
	if err != nil {
		t.Fatal(err)
	}
	h2.AttachStorage(storage.NewGate(st2, logger))

	req2 := apiRequest(`{"email":"a@b.com","message":"hi"}`, "valid-key")
	req2.Header.Set("Idempotency-Key", "order-42")
	rec2 := httptest.NewRecorder()
	h2.ServeHTTP(rec2, req2)

	if len(tr2.sent) != 0 {
		t.Fatalf("replay after restart re-sent mail (%d sends)", len(tr2.sent))
	}
	if rec2.Code != rec1.Code {
		t.Errorf("replay status = %d, want %d", rec2.Code, rec1.Code)
	}
	if rec2.Body.String() != rec1.Body.String() {
		t.Errorf("replay not byte-identical (NFR20):\n first: %s\nreplay: %s", rec1.Body.String(), rec2.Body.String())
	}
}

// findOnlySubmission asserts exactly one row exists and returns it.
func findOnlySubmission(t *testing.T, st *storage.Store) storage.Submission {
	t.Helper()
	subs, err := st.ListSubmissions(10)
	if err != nil {
		t.Fatalf("ListSubmissions: %v", err)
	}
	if len(subs) != 1 {
		t.Fatalf("submissions = %d, want 1", len(subs))
	}
	return subs[0]
}

func assertNoSubmissions(t *testing.T, st *storage.Store) {
	t.Helper()
	subs, err := st.ListSubmissions(10)
	if err != nil {
		t.Fatalf("ListSubmissions: %v", err)
	}
	if len(subs) != 0 {
		t.Fatalf("submissions = %d, want 0", len(subs))
	}
}

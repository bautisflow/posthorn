package gateway_test

import (
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/craigmccaskill/posthorn/config"
	"github.com/craigmccaskill/posthorn/gateway"
	"github.com/craigmccaskill/posthorn/storage"
)

// FR86: send-time suppression. The response contract is "2xx =
// terminally handled; the body names the outcome".

func multiRecipientHandler(t *testing.T, tr *recordingTransport) *gateway.Handler {
	t.Helper()
	cfg := config.EndpointConfig{
		Path:    "/test",
		To:      []string{"clean@example.com", "bounced@example.com"},
		From:    "from@example.com",
		Subject: "S",
		Body:    "B",
	}
	h, err := gateway.New(cfg, tr)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func TestSuppression_AllSuppressed_200SuppressedNoSend(t *testing.T) {
	tr := &recordingTransport{}
	h := newTestHandler(t, tr) // single recipient to@example.com
	gate := newGate(t)
	if err := gate.Store().AddSuppression("to@example.com", storage.ReasonHardBounce, "/test", time.Now()); err != nil {
		t.Fatal(err)
	}
	h.AttachStorage(gate)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, urlencodedRequest("email=a@b.com&message=hi"))

	if rec.Code != 200 {
		t.Fatalf("status = %d, want 200 (terminally handled, never retryable)", rec.Code)
	}
	var resp struct {
		Status     string            `json:"status"`
		Suppressed map[string]string `json:"suppressed"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Status != "suppressed" {
		t.Errorf("status field = %q", resp.Status)
	}
	if resp.Suppressed["to@example.com"] != storage.ReasonHardBounce {
		t.Errorf("suppressed map = %v", resp.Suppressed)
	}
	if len(tr.sent) != 0 {
		t.Fatalf("suppressed submission sent mail (%d sends)", len(tr.sent))
	}
	// The submission log records the refusal.
	subs, err := gate.Store().ListSubmissions(10)
	if err != nil || len(subs) != 1 {
		t.Fatalf("submissions = %d err=%v", len(subs), err)
	}
	if subs[0].Status != storage.StatusSuppressed {
		t.Errorf("row status = %q", subs[0].Status)
	}
}

func TestSuppression_Mixed_SendsRemainderReportsSuppressed(t *testing.T) {
	tr := &recordingTransport{}
	h := multiRecipientHandler(t, tr)
	gate := newGate(t)
	if err := gate.Store().AddSuppression("bounced@example.com", storage.ReasonSpamComplaint, "/x", time.Now()); err != nil {
		t.Fatal(err)
	}
	h.AttachStorage(gate)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, urlencodedRequest("email=a@b.com&message=hi"))

	if rec.Code != 200 {
		t.Fatalf("status = %d", rec.Code)
	}
	if len(tr.sent) != 1 {
		t.Fatalf("sends = %d", len(tr.sent))
	}
	if len(tr.sent[0].To) != 1 || tr.sent[0].To[0] != "clean@example.com" {
		t.Errorf("sent To = %v, want only the clean recipient", tr.sent[0].To)
	}
	var resp struct {
		Status     string            `json:"status"`
		Suppressed map[string]string `json:"suppressed"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Status != "ok" {
		t.Errorf("status field = %q (mail did send)", resp.Status)
	}
	if resp.Suppressed["bounced@example.com"] != storage.ReasonSpamComplaint {
		t.Errorf("suppressed map = %v", resp.Suppressed)
	}
}

func TestSuppression_CaseInsensitiveAtSendTime(t *testing.T) {
	tr := &recordingTransport{}
	h := newTestHandler(t, tr) // recipient to@example.com
	gate := newGate(t)
	if err := gate.Store().AddSuppression("TO@EXAMPLE.COM", storage.ReasonManual, "", time.Now()); err != nil {
		t.Fatal(err)
	}
	h.AttachStorage(gate)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, urlencodedRequest("email=a@b.com&message=hi"))
	if len(tr.sent) != 0 {
		t.Fatal("case-variant suppression dodged at send time")
	}
	_ = rec
}

func TestSuppression_NoStorage_V1Behavior(t *testing.T) {
	tr := &recordingTransport{}
	h := newTestHandler(t, tr) // no AttachStorage at all

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, urlencodedRequest("email=a@b.com&message=hi"))
	if rec.Code != 200 || len(tr.sent) != 1 {
		t.Fatalf("status=%d sends=%d", rec.Code, len(tr.sent))
	}
	// v1.x byte-shape: no suppressed key in the body.
	var raw map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &raw)
	if _, present := raw["suppressed"]; present {
		t.Error("suppressed key present on storage-less deployment")
	}
}

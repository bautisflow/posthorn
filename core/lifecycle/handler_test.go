package lifecycle

import (
	"bytes"
	"context"
	"crypto/hmac"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/craigmccaskill/posthorn/storage"
)

const (
	testUser   = "pm-hook"
	testPass   = "hook-password-sentinel"
	testSecret = "webhook-secret-sentinel-16bytes"
)

// receiver captures forwarded callbacks for assertion.
type receiver struct {
	srv *httptest.Server

	mu       sync.Mutex
	bodies   [][]byte
	sigs     []string
	statuses []int // scripted responses; empty = always 200
}

func newReceiver(t *testing.T) *receiver {
	t.Helper()
	rc := &receiver{}
	rc.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		rc.mu.Lock()
		rc.bodies = append(rc.bodies, body)
		rc.sigs = append(rc.sigs, r.Header.Get(SignatureHeader))
		status := http.StatusOK
		if len(rc.statuses) > 0 {
			status = rc.statuses[0]
			rc.statuses = rc.statuses[1:]
		}
		rc.mu.Unlock()
		w.WriteHeader(status)
	}))
	t.Cleanup(rc.srv.Close)
	return rc
}

func (rc *receiver) received() ([][]byte, []string) {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	return append([][]byte(nil), rc.bodies...), append([]string(nil), rc.sigs...)
}

type fixture struct {
	handler  *Handler
	fwd      *Forwarder
	gate     *storage.Gate
	logs     *bytes.Buffer
	outcomes []string
	mu       sync.Mutex
}

func newFixture(t *testing.T, webhooks map[string]Webhook) *fixture {
	t.Helper()
	st, err := storage.Open(storage.Config{InMemory: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })

	logs := &bytes.Buffer{}
	logger := slog.New(slog.NewJSONHandler(logs, nil))
	gate := storage.NewGate(st, logger)

	fx := &fixture{gate: gate, logs: logs}
	fx.fwd = &Forwarder{
		Webhooks: webhooks,
		Gate:     gate,
		Logger:   logger,
		Now:      func() time.Time { return t0 },
		OnResult: func(endpoint, outcome string) {
			fx.mu.Lock()
			fx.outcomes = append(fx.outcomes, endpoint+":"+outcome)
			fx.mu.Unlock()
		},
	}
	h, err := NewHandler(testUser, testPass, gate, fx.fwd, logger, nil)
	if err != nil {
		t.Fatal(err)
	}
	h.now = func() time.Time { return t0 }
	fx.handler = h
	return fx
}

// seedSubmission records a sent submission with the given message ID so
// events can correlate.
func (fx *fixture) seedSubmission(t *testing.T, id, endpoint, msgID string) {
	t.Helper()
	err := fx.gate.Store().RecordSubmission(storage.Submission{
		ID: id, Endpoint: endpoint, Status: storage.StatusSending, CreatedAt: t0,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := fx.gate.Store().MarkSent(id, msgID, t0); err != nil {
		t.Fatal(err)
	}
}

func post(fx *fixture, body string, auth bool) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/events/postmark", strings.NewReader(body))
	req.RemoteAddr = "203.0.113.7:44444"
	if auth {
		req.SetBasicAuth(testUser, testPass)
	}
	rec := httptest.NewRecorder()
	fx.handler.ServeHTTP(rec, req)
	return rec
}

func TestHandler_RequiresAuth(t *testing.T) {
	fx := newFixture(t, nil)
	if rec := post(fx, `{"RecordType":"Delivery"}`, false); rec.Code != http.StatusUnauthorized {
		t.Errorf("no-auth status = %d, want 401 (fail-closed)", rec.Code)
	}

	req := httptest.NewRequest(http.MethodPost, "/events/postmark", strings.NewReader("{}"))
	req.RemoteAddr = "203.0.113.7:44444"
	req.SetBasicAuth(testUser, "wrong-password")
	rec := httptest.NewRecorder()
	fx.handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("wrong-password status = %d, want 401", rec.Code)
	}
}

func TestHandler_MethodNotAllowed(t *testing.T) {
	fx := newFixture(t, nil)
	req := httptest.NewRequest(http.MethodGet, "/events/postmark", nil)
	rec := httptest.NewRecorder()
	fx.handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET status = %d", rec.Code)
	}
}

func TestHandler_UnmatchedEvent_200NoForward(t *testing.T) {
	rc := newReceiver(t)
	fx := newFixture(t, map[string]Webhook{"/contact": {URL: rc.srv.URL, Secret: testSecret}})

	rec := post(fx, `{"RecordType":"Delivery","MessageID":"unknown-id","Recipient":"a@b.com"}`, true)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (no retry storms)", rec.Code)
	}
	if bodies, _ := rc.received(); len(bodies) != 0 {
		t.Errorf("unmatched event forwarded %d times", len(bodies))
	}
	if !strings.Contains(fx.logs.String(), "lifecycle_event_unmatched") {
		t.Error("unmatched drop not logged")
	}
}

func TestHandler_MalformedBody_200Logged(t *testing.T) {
	fx := newFixture(t, nil)
	rec := post(fx, "not json at all", true)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if !strings.Contains(fx.logs.String(), "lifecycle_event_malformed") {
		t.Error("malformed drop not logged")
	}
}

func TestHandler_MatchedDelivery_ForwardsSignedNormalizedEvent(t *testing.T) {
	rc := newReceiver(t)
	fx := newFixture(t, map[string]Webhook{"/contact": {URL: rc.srv.URL, Secret: testSecret}})
	fx.seedSubmission(t, "sub-1", "/contact", "pm-msg-1")

	rec := post(fx, `{"RecordType":"Delivery","MessageID":"pm-msg-1","Recipient":"a@b.com","DeliveredAt":"2026-08-02T10:00:00Z"}`, true)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}

	bodies, sigs := rc.received()
	if len(bodies) != 1 {
		t.Fatalf("forwards = %d", len(bodies))
	}
	var ev Event
	if err := json.Unmarshal(bodies[0], &ev); err != nil {
		t.Fatalf("forwarded body not an Event: %v", err)
	}
	if ev.Event != EventDelivered || ev.SubmissionID != "sub-1" || ev.Endpoint != "/contact" || ev.Recipient != "a@b.com" {
		t.Errorf("event = %+v", ev)
	}
	if ev.Provider != "postmark" || len(ev.ProviderData) == 0 {
		t.Errorf("provider fields = %q / %d bytes", ev.Provider, len(ev.ProviderData))
	}
	// FR84: signature verifies against the exact body bytes.
	if !hmac.Equal([]byte(sigs[0]), []byte(Sign(bodies[0], testSecret))) {
		t.Errorf("signature mismatch: %q", sigs[0])
	}
}

func TestHandler_HardBounce_SuppressesAndForwards(t *testing.T) {
	rc := newReceiver(t)
	fx := newFixture(t, map[string]Webhook{"/contact": {URL: rc.srv.URL, Secret: testSecret}})
	fx.seedSubmission(t, "sub-1", "/contact", "pm-msg-1")

	post(fx, `{"RecordType":"Bounce","Type":"HardBounce","MessageID":"pm-msg-1","Email":"Bounced@Example.com"}`, true)

	sup, ok, err := fx.gate.Store().SuppressionFor("bounced@example.com")
	if err != nil || !ok {
		t.Fatalf("suppression missing: ok=%v err=%v", ok, err)
	}
	if sup.Reason != storage.ReasonHardBounce || sup.SourceEndpoint != "/contact" {
		t.Errorf("suppression = %+v", sup)
	}
	if bodies, _ := rc.received(); len(bodies) != 1 {
		t.Errorf("forwards = %d (suppression and callback both fire)", len(bodies))
	}
}

func TestHandler_SpamComplaint_Suppresses(t *testing.T) {
	fx := newFixture(t, nil)
	fx.seedSubmission(t, "sub-1", "/contact", "pm-msg-1")

	post(fx, `{"RecordType":"SpamComplaint","MessageID":"pm-msg-1","Email":"c@example.com"}`, true)

	sup, ok, _ := fx.gate.Store().SuppressionFor("c@example.com")
	if !ok || sup.Reason != storage.ReasonSpamComplaint {
		t.Fatalf("suppression = %+v ok=%v", sup, ok)
	}
}

func TestHandler_SoftBounce_DoesNotSuppress(t *testing.T) {
	fx := newFixture(t, nil)
	fx.seedSubmission(t, "sub-1", "/contact", "pm-msg-1")

	post(fx, `{"RecordType":"Bounce","Type":"SoftBounce","MessageID":"pm-msg-1","Email":"s@example.com"}`, true)

	if _, ok, _ := fx.gate.Store().SuppressionFor("s@example.com"); ok {
		t.Fatal("soft bounce suppressed — only hard bounces and complaints may (FR85)")
	}
}

func TestHandler_EndpointWithoutWebhook_ProcessesWithoutForward(t *testing.T) {
	fx := newFixture(t, map[string]Webhook{"/other": {URL: "http://127.0.0.1:0", Secret: testSecret}})
	fx.seedSubmission(t, "sub-1", "/contact", "pm-msg-1")

	rec := post(fx, `{"RecordType":"Bounce","Type":"HardBounce","MessageID":"pm-msg-1","Email":"x@example.com"}`, true)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if _, ok, _ := fx.gate.Store().SuppressionFor("x@example.com"); !ok {
		t.Fatal("suppression must not depend on a webhook being configured")
	}
}

func TestForwarder_5xx_QueuesThenReplays(t *testing.T) {
	rc := newReceiver(t)
	rc.statuses = []int{503} // first attempt fails transiently
	fx := newFixture(t, map[string]Webhook{"/contact": {URL: rc.srv.URL, Secret: testSecret}})
	fx.seedSubmission(t, "sub-1", "/contact", "pm-msg-1")

	post(fx, `{"RecordType":"Delivery","MessageID":"pm-msg-1","Recipient":"a@b.com"}`, true)

	fx.mu.Lock()
	outcomes := append([]string(nil), fx.outcomes...)
	fx.mu.Unlock()
	if len(outcomes) != 1 || outcomes[0] != "/contact:queued" {
		t.Fatalf("outcomes = %v", outcomes)
	}

	// Drive the queue worker past the first backoff; receiver now 200s.
	fx.fwd.Now = func() time.Time { return t0.Add(storage.RetryBackoff[0] + time.Second) }
	fx.fwd.ProcessDue(context.Background())

	bodies, sigs := rc.received()
	if len(bodies) != 2 {
		t.Fatalf("attempts = %d, want 2 (inline + replay)", len(bodies))
	}
	if string(bodies[0]) != string(bodies[1]) {
		t.Error("replayed payload differs from original")
	}
	if sigs[1] != Sign(bodies[1], testSecret) {
		t.Error("replay signature invalid")
	}
}

func TestForwarder_4xx_DroppedNotQueued(t *testing.T) {
	rc := newReceiver(t)
	rc.statuses = []int{400}
	fx := newFixture(t, map[string]Webhook{"/contact": {URL: rc.srv.URL, Secret: testSecret}})
	fx.seedSubmission(t, "sub-1", "/contact", "pm-msg-1")

	post(fx, `{"RecordType":"Delivery","MessageID":"pm-msg-1","Recipient":"a@b.com"}`, true)

	fx.mu.Lock()
	outcomes := append([]string(nil), fx.outcomes...)
	fx.mu.Unlock()
	if len(outcomes) != 1 || outcomes[0] != "/contact:dropped" {
		t.Fatalf("outcomes = %v", outcomes)
	}
	if due, _ := fx.gate.Store().ClaimDueForwards(t0.Add(24*time.Hour), 10); len(due) != 0 {
		t.Errorf("terminal failure queued: %d", len(due))
	}
}

// NFR29: neither the webhook secret nor the basic-auth password may
// appear in logs, even on failure paths.
func TestLifecycle_SecretsNeverLogged(t *testing.T) {
	rc := newReceiver(t)
	rc.statuses = []int{500, 400}
	fx := newFixture(t, map[string]Webhook{"/contact": {URL: rc.srv.URL, Secret: testSecret}})
	fx.seedSubmission(t, "sub-1", "/contact", "pm-msg-1")

	// Failure paths: auth failure, forward transient, forward terminal.
	post(fx, "{}", false)
	post(fx, `{"RecordType":"Delivery","MessageID":"pm-msg-1"}`, true)
	post(fx, `{"RecordType":"Delivery","MessageID":"pm-msg-1"}`, true)

	logged := fx.logs.String()
	if strings.Contains(logged, testSecret) {
		t.Error("webhook secret appeared in logs")
	}
	if strings.Contains(logged, testPass) {
		t.Error("basic-auth password appeared in logs")
	}
}

func TestHandler_RateLimit(t *testing.T) {
	fx := newFixture(t, nil)
	var got429 bool
	for i := 0; i < 120; i++ {
		if rec := post(fx, "not json", true); rec.Code == http.StatusTooManyRequests {
			got429 = true
			break
		}
	}
	if !got429 {
		t.Error("no 429 across 120 rapid posts from one IP")
	}
}

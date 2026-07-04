package providertest_test

// Reference slice for issue #76: an ingress→egress e2e that drives a
// real HTTP form submission through the real gateway handler and the
// real Postmark transport into a CaptureServer, then asserts the wire
// shape the provider actually received. The transport-unit tests verify
// the transport in isolation from a hand-built Message; this verifies
// the transport.Message SEAM — that a form field, run through template
// rendering and JSON encoding, reaches the provider correctly and
// injection-safe. The architecture audit flagged this seam as "trusted,
// not verified end-to-end"; this is the verification.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/craigmccaskill/posthorn/config"
	"github.com/craigmccaskill/posthorn/gateway"
	"github.com/craigmccaskill/posthorn/providertest"
	"github.com/craigmccaskill/posthorn/transport"
)

// postmarkWire is the subset of the Postmark request body we assert on.
type postmarkWire struct {
	From     string
	To       string
	Subject  string
	TextBody string
}

// newPostmarkFormHandler builds a form-mode endpoint whose Subject is
// templated from the submitter-controlled `name` field and whose
// transport is a real Postmark client pointed at the capture server.
func newPostmarkFormHandler(t *testing.T, captureURL string) *gateway.Handler {
	t.Helper()
	cfg := config.EndpointConfig{
		Path:     "/contact",
		To:       []string{"ops@example.com"},
		From:     "Posthorn <noreply@example.com>",
		Subject:  "Contact from {{.name}}",
		Body:     "{{.message}}",
		Required: []string{"name", "message"},
	}
	h, err := gateway.New(cfg, transport.NewPostmarkTransport("test-key", captureURL))
	if err != nil {
		t.Fatalf("gateway.New: %v", err)
	}
	return h
}

func formPOST(body string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/contact", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return r
}

func TestE2E_Postmark_FormToWire_HappyPath(t *testing.T) {
	cs := providertest.NewCaptureServer(t, http.StatusOK, `{"ErrorCode":0,"Message":"OK","MessageID":"m-1"}`)
	h := newPostmarkFormHandler(t, cs.URL)

	form := url.Values{"name": {"Alice"}, "message": {"Hello there"}}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, formPOST(form.Encode()))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	req, ok := cs.Last()
	if !ok {
		t.Fatal("Postmark transport made no request")
	}
	var w postmarkWire
	if err := json.Unmarshal(req.Body, &w); err != nil {
		t.Fatalf("captured body is not valid JSON: %v\n%s", err, req.Body)
	}
	if w.From != "Posthorn <noreply@example.com>" {
		t.Errorf("From = %q", w.From)
	}
	if w.To != "ops@example.com" {
		t.Errorf("To = %q", w.To)
	}
	if w.Subject != "Contact from Alice" {
		t.Errorf("Subject = %q, want template-rendered value", w.Subject)
	}
	if w.TextBody != "Hello there" {
		t.Errorf("TextBody = %q", w.TextBody)
	}
	// The submitter's api key must never reach the provider in a form we
	// didn't intend, but more importantly the auth header must be set.
	if got := req.Header.Get("X-Postmark-Server-Token"); got != "test-key" {
		t.Errorf("auth header = %q, want the server token", got)
	}
}

func TestE2E_Postmark_FormToWire_InjectionSafe(t *testing.T) {
	// Each nasty value goes into the templated Subject via the `name`
	// field. The provider must receive it as an inert JSON string — the
	// body must still parse, Subject must equal the payload verbatim, and
	// no CR/LF may appear raw in the serialized body (JSON encodes them
	// as \r \n escapes, so a bare 0x0D/0x0A in the wire bytes would mean
	// a smuggled header line).
	for _, payload := range providertest.InjectionValues() {
		t.Run(sanitizeName(payload), func(t *testing.T) {
			cs := providertest.NewCaptureServer(t, http.StatusOK, `{"ErrorCode":0,"MessageID":"m"}`)
			h := newPostmarkFormHandler(t, cs.URL)

			form := url.Values{"name": {payload}, "message": {"body"}}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, formPOST(form.Encode()))
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
			}

			req, ok := cs.Last()
			if !ok {
				t.Fatal("no request captured")
			}
			var w postmarkWire
			if err := json.Unmarshal(req.Body, &w); err != nil {
				t.Fatalf("captured body not valid JSON (encoding broke): %v\n%s", err, req.Body)
			}
			if w.Subject != "Contact from "+payload {
				t.Errorf("Subject = %q, want the payload rendered verbatim as data", w.Subject)
			}
			// Bare CR or LF in the raw JSON body means the payload escaped
			// its string context — a header-injection.
			if i := indexAnyByte(req.Body, '\r', '\n'); i >= 0 {
				t.Errorf("raw CR/LF at byte %d in serialized body — injection not neutralized:\n%q", i, req.Body)
			}
		})
	}
}

// indexAnyByte returns the first index of any of the given bytes, or -1.
func indexAnyByte(b []byte, targets ...byte) int {
	for i, c := range b {
		for _, tgt := range targets {
			if c == tgt {
				return i
			}
		}
	}
	return -1
}

// sanitizeName makes a subtest name from a payload without CR/LF.
func sanitizeName(s string) string {
	r := strings.NewReplacer("\r", "<CR>", "\n", "<LF>", " ", "_")
	name := r.Replace(s)
	if len(name) > 40 {
		name = name[:40]
	}
	return name
}

package transport

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

const webhookTestSecret = "webhook-secret-sentinel-16b"

func webhookMessage() Message {
	return Message{
		From:         "noreply@example.com",
		To:           []string{"ops@example.com"},
		ReplyTo:      "jane@example.com",
		Subject:      "Contact from Jane",
		BodyText:     "rendered text",
		BodyHTML:     "<p>rendered html</p>",
		SubmissionID: "sub-42",
		Fields:       map[string][]string{"name": {"Jane"}, "message": {"hi there"}},
	}
}

func TestWebhook_Success_PayloadShape(t *testing.T) {
	cs := newCaptureServer(t, http.StatusOK, `{}`)
	tp := NewWebhookTransport(cs.URL, webhookTestSecret, map[string]string{"X-Team": "infra"})

	if _, err := tp.Send(context.Background(), webhookMessage()); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if cs.method != http.MethodPost {
		t.Errorf("method = %q", cs.method)
	}
	if got := cs.headers.Get("Content-Type"); got != "application/json" {
		t.Errorf("Content-Type = %q", got)
	}
	if got := cs.headers.Get("X-Team"); got != "infra" {
		t.Errorf("custom header = %q", got)
	}

	var p map[string]any
	if err := json.Unmarshal(cs.body, &p); err != nil {
		t.Fatalf("payload not JSON: %v", err)
	}
	if p["submission_id"] != "sub-42" || p["from"] != "noreply@example.com" || p["subject"] != "Contact from Jane" {
		t.Errorf("payload = %v", p)
	}
	if p["body_text"] != "rendered text" || p["body_html"] != "<p>rendered html</p>" {
		t.Errorf("bodies = %v / %v", p["body_text"], p["body_html"])
	}
	fields := p["fields"].(map[string]any)
	if fields["name"].([]any)[0] != "Jane" {
		t.Errorf("fields = %v", fields)
	}
}

func TestWebhook_SignatureVerifies(t *testing.T) {
	cs := newCaptureServer(t, http.StatusOK, `{}`)
	tp := NewWebhookTransport(cs.URL, webhookTestSecret, nil)

	if _, err := tp.Send(context.Background(), webhookMessage()); err != nil {
		t.Fatalf("Send: %v", err)
	}
	mac := hmac.New(sha256.New, []byte(webhookTestSecret))
	mac.Write(cs.body)
	want := "sha256=" + hex.EncodeToString(mac.Sum(nil))
	if got := cs.headers.Get(WebhookSignatureHeader); !hmac.Equal([]byte(got), []byte(want)) {
		t.Errorf("signature = %q, want %q", got, want)
	}
}

func TestWebhook_StatusMapping(t *testing.T) {
	cases := []struct {
		status    int
		wantClass ErrorClass
	}{
		{202, ErrorClass(-1)}, // success sentinel
		{429, ErrRateLimited},
		{500, ErrTransient},
		{503, ErrTransient},
		{400, ErrTerminal},
		{404, ErrTerminal},
	}
	for _, tc := range cases {
		cs := newCaptureServer(t, tc.status, `{}`)
		tp := NewWebhookTransport(cs.URL, webhookTestSecret, nil)
		_, err := tp.Send(context.Background(), webhookMessage())
		if tc.wantClass == ErrorClass(-1) {
			if err != nil {
				t.Errorf("status %d: unexpected error %v", tc.status, err)
			}
			continue
		}
		var terr *TransportError
		if err == nil || !errorsAs(err, &terr) {
			t.Errorf("status %d: err = %v, want TransportError", tc.status, err)
			continue
		}
		if terr.Class != tc.wantClass {
			t.Errorf("status %d: class = %v, want %v", tc.status, terr.Class, tc.wantClass)
		}
	}
}

func TestWebhook_NetworkError_Transient(t *testing.T) {
	tp := NewWebhookTransport("http://127.0.0.1:1", webhookTestSecret, nil)
	_, err := tp.Send(context.Background(), webhookMessage())
	var terr *TransportError
	if err == nil || !errorsAs(err, &terr) || terr.Class != ErrTransient {
		t.Fatalf("err = %v, want transient TransportError", err)
	}
}

// NFR3/NFR29: the secret must never surface in error strings (the only
// operator-visible output this package produces).
func TestWebhook_SecretNotInErrors(t *testing.T) {
	for _, tp := range []*WebhookTransport{
		NewWebhookTransport("http://127.0.0.1:1", webhookTestSecret, nil),
	} {
		_, err := tp.Send(context.Background(), webhookMessage())
		if err == nil {
			t.Fatal("expected error")
		}
		if strings.Contains(err.Error(), webhookTestSecret) {
			t.Errorf("secret leaked into error: %v", err)
		}
	}
	cs := newCaptureServer(t, http.StatusBadRequest, `{}`)
	tp := NewWebhookTransport(cs.URL, webhookTestSecret, nil)
	_, err := tp.Send(context.Background(), webhookMessage())
	if err == nil || strings.Contains(err.Error(), webhookTestSecret) {
		t.Errorf("secret leaked into error: %v", err)
	}
}

func TestWebhook_RegistrySettings(t *testing.T) {
	cases := []struct {
		name     string
		settings map[string]any
		wantErr  string
	}{
		{"valid", map[string]any{"url": "https://x.example/hook", "secret": "0123456789abcdef"}, ""},
		{"valid with headers", map[string]any{"url": "https://x.example/hook", "secret": "0123456789abcdef", "headers": map[string]any{"X-Team": "a"}}, ""},
		{"missing url", map[string]any{"secret": "0123456789abcdef"}, "settings.url"},
		{"relative url", map[string]any{"url": "/hook", "secret": "0123456789abcdef"}, "absolute http(s)"},
		{"short secret", map[string]any{"url": "https://x.example/h", "secret": "short"}, "at least 16 bytes"},
		{"reserved signature header", map[string]any{"url": "https://x.example/h", "secret": "0123456789abcdef", "headers": map[string]any{"x-posthorn-signature": "spoof"}}, "reserved"},
		{"reserved content type", map[string]any{"url": "https://x.example/h", "secret": "0123456789abcdef", "headers": map[string]any{"content-type": "text/plain"}}, "reserved"},
		{"non-string header", map[string]any{"url": "https://x.example/h", "secret": "0123456789abcdef", "headers": map[string]any{"X-N": 42}}, "must be a string"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateWebhookSettings(tc.settings)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if _, err := buildWebhookFromSettings(tc.settings); err != nil {
					t.Fatalf("build: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("err = %v, want containing %q", err, tc.wantErr)
			}
		})
	}
}

func TestWebhook_RegistryLookup(t *testing.T) {
	reg, ok := Lookup("webhook")
	if !ok {
		t.Fatal("webhook not registered")
	}
	tp, err := reg.Build(map[string]any{"url": "https://x.example/hook", "secret": "0123456789abcdef"})
	if err != nil || tp == nil {
		t.Fatalf("Build: %v", err)
	}
}

// Guardrail (FR89/ADR-24): mail transports ignore SubmissionID and
// Fields — wire bytes identical with and without them. Text-only
// message so SMTP-out DATA is deterministic.
func TestMailTransports_IgnoreFieldsAndSubmissionID(t *testing.T) {
	plain := Message{
		From: "a@example.com", To: []string{"b@example.com"},
		Subject: "S", BodyText: "body",
	}
	loaded := plain
	loaded.SubmissionID = "sub-99"
	loaded.Fields = map[string][]string{"secret_field": {"leak-canary-value"}}

	builders := []struct {
		name string
		make func(baseURL string) Transport
		resp string
	}{
		{"postmark", func(u string) Transport { return NewPostmarkTransport("k", u) }, `{}`},
		{"resend", func(u string) Transport { return NewResendTransport("k", u) }, `{"id":"x"}`},
		{"mailgun", func(u string) Transport { return NewMailgunTransport("k", "d.example", u) }, `{"id":"x"}`},
		{"ses", func(u string) Transport { return NewSESTransport("AKID", "sec", "us-east-1", u) }, `{"MessageId":"x"}`},
	}
	for _, b := range builders {
		t.Run(b.name, func(t *testing.T) {
			cs1 := newCaptureServer(t, http.StatusOK, b.resp)
			if _, err := b.make(cs1.URL).Send(context.Background(), plain); err != nil {
				t.Fatalf("plain Send: %v", err)
			}
			cs2 := newCaptureServer(t, http.StatusOK, b.resp)
			if _, err := b.make(cs2.URL).Send(context.Background(), loaded); err != nil {
				t.Fatalf("loaded Send: %v", err)
			}
			body1, body2 := normalizeMultipartBoundary(cs1), normalizeMultipartBoundary(cs2)
			if body1 != body2 {
				t.Errorf("wire bytes differ when Fields/SubmissionID set:\n plain: %s\nloaded: %s", body1, body2)
			}
			if strings.Contains(string(cs2.body), "leak-canary-value") {
				t.Errorf("Fields leaked onto the %s wire", b.name)
			}
		})
	}
}

// normalizeMultipartBoundary strips the random multipart boundary from
// Mailgun captures so two requests are comparable.
func normalizeMultipartBoundary(cs *captureServer) string {
	ct := cs.headers.Get("Content-Type")
	const marker = "boundary="
	i := strings.Index(ct, marker)
	if i < 0 {
		return string(cs.body)
	}
	boundary := ct[i+len(marker):]
	return strings.ReplaceAll(string(cs.body), boundary, "BOUNDARY")
}

// errorsAs is a tiny local alias to keep the table test readable.
func errorsAs(err error, target **TransportError) bool {
	t, ok := err.(*TransportError)
	if ok {
		*target = t
	}
	return ok
}

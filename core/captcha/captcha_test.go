package captcha

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func fakeTurnstile(t *testing.T, success bool) *httptest.Server {
	t.Helper()
	body := `{"success":false,"error-codes":["invalid-input-response"]}`
	if success {
		body = `{"success":true}`
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestVerify_Success(t *testing.T) {
	srv := fakeTurnstile(t, true)
	v, _ := New(Config{BaseURL: srv.URL, Secret: "s"})
	if err := v.Verify(context.Background(), "good-token", "203.0.113.1"); err != nil {
		t.Errorf("want nil for accepted token, got %v", err)
	}
}

func TestVerify_Rejected(t *testing.T) {
	srv := fakeTurnstile(t, false)
	v, _ := New(Config{BaseURL: srv.URL, Secret: "s"})
	if err := v.Verify(context.Background(), "bad-token", ""); !errors.Is(err, ErrFailed) {
		t.Errorf("want ErrFailed for rejected token, got %v", err)
	}
}

func TestVerify_EmptyToken_FailsWithoutNetwork(t *testing.T) {
	// A closed server proves no request is made for an empty token.
	srv := fakeTurnstile(t, true)
	base := srv.URL
	srv.Close()
	v, _ := New(Config{BaseURL: base, Secret: "s", Timeout: 200 * time.Millisecond})
	if err := v.Verify(context.Background(), "  ", ""); !errors.Is(err, ErrFailed) {
		t.Errorf("empty token should be ErrFailed without a round-trip, got %v", err)
	}
}

func TestVerify_ProviderError(t *testing.T) {
	srv := fakeTurnstile(t, true)
	base := srv.URL
	srv.Close() // requests now fail
	v, _ := New(Config{BaseURL: base, Secret: "s", Timeout: 200 * time.Millisecond})
	err := v.Verify(context.Background(), "token", "")
	if err == nil || errors.Is(err, ErrFailed) {
		t.Errorf("provider error should be a non-ErrFailed error, got %v", err)
	}
}

func TestNew_RequiresSecret(t *testing.T) {
	if _, err := New(Config{}); err == nil {
		t.Error("New should require a secret")
	}
}

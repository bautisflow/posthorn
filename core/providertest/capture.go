// Package providertest is the shared harness for exercising Posthorn's
// egress against provider APIs. It has two modes that run the SAME
// assertions:
//
//   - Hermetic (default): a CaptureServer stands in for the provider,
//     recording the exact bytes Posthorn sends so tests can assert the
//     wire shape (auth, body encoding, header-injection safety) with no
//     network and no credentials. Safe on every PR, including forks.
//   - Live (build tag `integration`): the transport points at the real
//     provider endpoint using credentials supplied by the environment,
//     against non-delivering targets (Postmark's public test token, SES
//     simulator addresses, etc.). Gated to protected CI / local runs.
//
// This package is imported only by tests. It lives outside `_test.go`
// so both the transport-level and the ingress→egress e2e tests can
// share one CaptureServer and one assertion battery (issue #76).
package providertest

import (
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

// CaptureServer is an httptest.Server that records every request it
// receives and replies with a fixed status + body. Concurrency-safe so
// an ingress under test can be driven from multiple goroutines.
type CaptureServer struct {
	*httptest.Server

	mu       sync.Mutex
	requests []CapturedRequest
	status   int
	respBody string
}

// CapturedRequest is one recorded request's wire-observable surface.
type CapturedRequest struct {
	Method string
	Path   string
	Header http.Header
	Body   []byte
}

// NewCaptureServer starts a server that answers every request with the
// given status and body, and shuts down on test cleanup.
func NewCaptureServer(t *testing.T, status int, respBody string) *CaptureServer {
	t.Helper()
	cs := &CaptureServer{status: status, respBody: respBody}
	cs.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		cs.mu.Lock()
		cs.requests = append(cs.requests, CapturedRequest{
			Method: r.Method,
			Path:   r.URL.Path,
			Header: r.Header.Clone(),
			Body:   body,
		})
		cs.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(cs.status)
		_, _ = w.Write([]byte(cs.respBody))
	}))
	t.Cleanup(cs.Close)
	return cs
}

// Requests returns a copy of everything captured so far.
func (cs *CaptureServer) Requests() []CapturedRequest {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	out := make([]CapturedRequest, len(cs.requests))
	copy(out, cs.requests)
	return out
}

// Last returns the most recent captured request and whether one exists.
func (cs *CaptureServer) Last() (CapturedRequest, bool) {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	if len(cs.requests) == 0 {
		return CapturedRequest{}, false
	}
	return cs.requests[len(cs.requests)-1], true
}

// Count returns how many requests have been captured.
func (cs *CaptureServer) Count() int {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	return len(cs.requests)
}

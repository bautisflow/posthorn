package gateway

import (
	"time"

	"github.com/craigmccaskill/posthorn/transport"
)

// SetRetryDelaysForTest swaps the retry/timeout variables to short
// values for tests, returning a function that restores them. The retry
// delays live in the transport package since the FR19-22 policy moved
// to transport.SendWithRetry (issue #59); requestTimeout stays here.
//
// Compiled only with _test.go files. External (gateway_test package)
// tests use this rather than reaching into unexported state directly.
func SetRetryDelaysForTest(transient, rateLimited, requestTO time.Duration) func() {
	oldT, oldR, oldTo := transport.TransientRetryDelay, transport.RateLimitedRetryDelay, requestTimeout
	transport.TransientRetryDelay = transient
	transport.RateLimitedRetryDelay = rateLimited
	requestTimeout = requestTO
	return func() {
		transport.TransientRetryDelay = oldT
		transport.RateLimitedRetryDelay = oldR
		requestTimeout = oldTo
	}
}

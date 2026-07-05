// Package captcha verifies a Cloudflare Turnstile response token — the
// escalation tier of the spam ladder (#33). Reputation (#44) and
// proof-of-browser (#45) stop bots that reuse identities or don't run
// JavaScript; Turnstile is the backstop for the ones that do render the
// page and execute a real browser. It's opt-in per endpoint because it
// adds a third-party dependency and a visible widget.
package captcha

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// defaultBaseURL is Cloudflare Turnstile's siteverify endpoint.
const defaultBaseURL = "https://challenges.cloudflare.com/turnstile/v0/siteverify"

// ErrFailed means the provider verified the token and rejected it (a
// bad, missing, or already-used response). Distinct from a transport or
// provider error, which the caller handles per its fail-open policy.
var ErrFailed = errors.New("captcha: token rejected by provider")

// Config configures a Verifier.
type Config struct {
	BaseURL string // "" → Cloudflare's public siteverify
	Secret  string // Turnstile secret key
	Timeout time.Duration
}

// Verifier verifies Turnstile tokens against the provider.
type Verifier struct {
	baseURL string
	secret  string
	http    *http.Client
}

// New builds a Verifier.
func New(cfg Config) (*Verifier, error) {
	if cfg.Secret == "" {
		return nil, errors.New("captcha: secret is required")
	}
	base := cfg.BaseURL
	if base == "" {
		base = defaultBaseURL
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	return &Verifier{baseURL: base, secret: cfg.Secret, http: &http.Client{Timeout: timeout}}, nil
}

type siteverifyResponse struct {
	Success bool `json:"success"`
}

// Verify submits the response token to the provider. Returns nil when
// the provider accepts it, ErrFailed when the provider rejects it, or a
// wrapped transport/provider error otherwise (the caller decides whether
// to fail open or closed).
func (v *Verifier) Verify(ctx context.Context, token, remoteIP string) error {
	if strings.TrimSpace(token) == "" {
		// No token at all is a definite failure, not a provider error —
		// no point spending a network round-trip on it.
		return ErrFailed
	}
	form := url.Values{"secret": {v.secret}, "response": {token}}
	if remoteIP != "" {
		form.Set("remoteip", remoteIP)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, v.baseURL, strings.NewReader(form.Encode()))
	if err != nil {
		return fmt.Errorf("captcha: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := v.http.Do(req)
	if err != nil {
		return fmt.Errorf("captcha: provider request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("captcha: provider status %d", resp.StatusCode)
	}

	var sv siteverifyResponse
	if err := json.NewDecoder(resp.Body).Decode(&sv); err != nil {
		return fmt.Errorf("captcha: decode response: %w", err)
	}
	if !sv.Success {
		return ErrFailed
	}
	return nil
}

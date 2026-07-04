// Package reputation checks a submitter's email and IP against a
// reputation provider (StopForumSpam) so form-mode endpoints can reject
// known form-spam identities. It targets the observed spam pattern:
// distributed reply-bait from burner addresses, where the content varies
// by language and shape but the sender identity and source IP are what
// repeats and what public databases already catalog.
//
// The check is content-agnostic (it never looks at the message), caches
// results in a bounded LRU, and fails open by default — a provider
// outage must never block legitimate mail.
package reputation

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"

	lru "github.com/hashicorp/golang-lru/v2"
)

// defaultBaseURL is StopForumSpam's public lookup API. No key required.
const defaultBaseURL = "https://api.stopforumspam.org/api"

// Config configures a Checker. Zero values get sensible defaults in New.
type Config struct {
	BaseURL    string        // "" → StopForumSpam public API
	CheckEmail bool          // look up the submitter email
	CheckIP    bool          // look up the client IP
	Threshold  float64       // block when a looked-up field's confidence ≥ this (0–100)
	FailOpen   bool          // provider error → allow (true) or block (false)
	Timeout    time.Duration // per-lookup HTTP timeout
	CacheSize  int           // LRU capacity
	CacheTTL   time.Duration // how long a lookup result is reused
}

// Checker performs cached reputation lookups.
type Checker struct {
	baseURL    string
	checkEmail bool
	checkIP    bool
	threshold  float64
	failOpen   bool
	http       *http.Client
	cache      *lru.Cache[string, cachedResult]
	ttl        time.Duration
	now        func() time.Time
}

// Result is the outcome of a reputation check.
type Result struct {
	Blocked bool
	Reason  string // operator-facing detail; never contains submitter content beyond the matched field
	// FailedOpen is true when a provider error was suppressed (FailOpen).
	// The handler meters this so a sustained outage's silent-bypass
	// window is visible.
	FailedOpen bool
}

type cachedResult struct {
	result  Result
	expires time.Time
}

// New builds a Checker from cfg.
func New(cfg Config) (*Checker, error) {
	if !cfg.CheckEmail && !cfg.CheckIP {
		return nil, fmt.Errorf("reputation: at least one of email/ip must be checked")
	}
	base := cfg.BaseURL
	if base == "" {
		base = defaultBaseURL
	}
	size := cfg.CacheSize
	if size <= 0 {
		size = 10000
	}
	cache, err := lru.New[string, cachedResult](size)
	if err != nil {
		return nil, fmt.Errorf("reputation: cache: %w", err)
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	ttl := cfg.CacheTTL
	if ttl <= 0 {
		ttl = time.Hour
	}
	return &Checker{
		baseURL:    base,
		checkEmail: cfg.CheckEmail,
		checkIP:    cfg.CheckIP,
		threshold:  cfg.Threshold,
		failOpen:   cfg.FailOpen,
		http:       &http.Client{Timeout: timeout},
		cache:      cache,
		ttl:        ttl,
		now:        time.Now,
	}, nil
}

// sfsResponse is the subset of the StopForumSpam JSON we read.
type sfsResponse struct {
	Success int      `json:"success"`
	Email   sfsField `json:"email"`
	IP      sfsField `json:"ip"`
}

type sfsField struct {
	Appears    int     `json:"appears"`
	Confidence float64 `json:"confidence"`
}

// Check looks up email and/or ip and returns whether the submission
// should be blocked. Cached results are reused within the TTL. On a
// provider or decode error the result honors FailOpen.
func (c *Checker) Check(ctx context.Context, email, ip string) Result {
	key := email + "|" + ip
	if cr, ok := c.cache.Get(key); ok && c.now().Before(cr.expires) {
		return cr.result
	}

	res, err := c.lookup(ctx, email, ip)
	if err != nil {
		if c.failOpen {
			return Result{Blocked: false, FailedOpen: true, Reason: err.Error()}
		}
		return Result{Blocked: true, Reason: "reputation provider error (fail-closed): " + err.Error()}
	}

	c.cache.Add(key, cachedResult{result: res, expires: c.now().Add(c.ttl)})
	return res
}

func (c *Checker) lookup(ctx context.Context, email, ip string) (Result, error) {
	q := url.Values{"json": {""}}
	if c.checkEmail && email != "" {
		q.Set("email", email)
	}
	if c.checkIP && ip != "" {
		q.Set("ip", ip)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"?"+q.Encode(), nil)
	if err != nil {
		return Result{}, fmt.Errorf("build request: %w", err)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return Result{}, fmt.Errorf("provider request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return Result{}, fmt.Errorf("provider status %d", resp.StatusCode)
	}

	var sr sfsResponse
	if err := json.NewDecoder(resp.Body).Decode(&sr); err != nil {
		return Result{}, fmt.Errorf("decode response: %w", err)
	}

	if c.checkEmail && email != "" && sr.Email.Appears == 1 && sr.Email.Confidence >= c.threshold {
		return Result{Blocked: true, Reason: fmt.Sprintf("email reputation confidence %.0f ≥ %.0f", sr.Email.Confidence, c.threshold)}, nil
	}
	if c.checkIP && ip != "" && sr.IP.Appears == 1 && sr.IP.Confidence >= c.threshold {
		return Result{Blocked: true, Reason: fmt.Sprintf("ip reputation confidence %.0f ≥ %.0f", sr.IP.Confidence, c.threshold)}, nil
	}
	return Result{Blocked: false}, nil
}

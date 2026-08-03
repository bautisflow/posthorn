package metrics

import "time"

// LatencyBuckets is the histogram bucket set Posthorn uses for send
// latency. Covers sub-millisecond to 10s in a power-of-roughly-5 spacing
// that maps cleanly to the operator-meaningful regions (idempotent
// replay → ~ms; happy-path Postmark → ~300ms; retry → ~1s; near-timeout
// → ~5s; hard-timeout boundary → 10s).
var LatencyBuckets = []float64{0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1, 5, 10}

// Recorder is the typed entry point Posthorn's gateway and cmd/posthorn
// call to record metrics. Each method names the event semantically; the
// concrete metric storage (counters/histograms) is hidden so future
// metrics additions don't require gateway-side code changes.
//
// A nil *Recorder is a no-op — gateway code can call Recorder methods
// without an enabling-condition check; tests that don't care about
// metrics pass nil.
type Recorder struct {
	submitted        *Counter
	sent             *Counter
	failed           *Counter
	rateLimited      *Counter
	authFailed       *Counter
	spamBlocked      *Counter
	checkFailedOpen  *Counter
	validationFailed *Counter
	idempotentReplay *Counter
	sendLatency      *Histogram

	// v2.0 storage surface (FR78, FR80).
	queued           *Counter
	queueSent        *Counter
	queueRetried     *Counter
	queueDeadLetter  *Counter
	storageHealthy   *Gauge
	retryQueueDepth  *Gauge
}

// NewRecorder constructs a Recorder backed by counters and histograms
// registered with reg. Call once per Posthorn process.
func NewRecorder(reg *Registry) *Recorder {
	r := &Recorder{
		submitted: NewCounter(
			"posthorn_submissions_received_total",
			"Submissions accepted past the body-parse stage, before transport.Send.",
			[]string{"endpoint"},
		),
		sent: NewCounter(
			"posthorn_submissions_sent_total",
			"Submissions successfully delivered to the upstream transport.",
			[]string{"endpoint", "transport"},
		),
		failed: NewCounter(
			"posthorn_submissions_failed_total",
			"Submissions that reached transport.Send but failed terminally (no retry, 502 to client).",
			[]string{"endpoint", "transport", "error_class"},
		),
		rateLimited: NewCounter(
			"posthorn_rate_limited_total",
			"Submissions rejected at the rate-limit gate (HTTP 429).",
			[]string{"endpoint"},
		),
		authFailed: NewCounter(
			"posthorn_auth_failed_total",
			"API-mode submissions rejected with HTTP 401 (missing or invalid Bearer token).",
			[]string{"endpoint"},
		),
		spamBlocked: NewCounter(
			"posthorn_spam_blocked_total",
			"Form-mode submissions rejected by spam defenses (honeypot/origin silent-200; csrf/reputation 403).",
			[]string{"endpoint", "kind"},
		),
		checkFailedOpen: NewCounter(
			"posthorn_check_failed_open_total",
			"Spam checks whose provider errored and were allowed through (fail-open). A rising rate is a silent-bypass window. check is \"reputation\" or \"captcha\".",
			[]string{"endpoint", "check"},
		),
		validationFailed: NewCounter(
			"posthorn_validation_failed_total",
			"Submissions rejected with HTTP 422 for missing required fields or malformed email.",
			[]string{"endpoint"},
		),
		idempotentReplay: NewCounter(
			"posthorn_idempotent_replay_total",
			"API-mode requests served from the idempotency cache without re-sending.",
			[]string{"endpoint"},
		),
		sendLatency: NewHistogram(
			"posthorn_send_latency_seconds",
			"Wall-clock latency of transport.Send, including any retries.",
			LatencyBuckets,
			[]string{"endpoint", "transport"},
		),
		queued: NewCounter(
			"posthorn_submissions_queued_total",
			"Submissions whose inline retries exhausted transiently and entered the background retry queue (202 to api-mode callers).",
			[]string{"endpoint", "transport"},
		),
		queueSent: NewCounter(
			"posthorn_queue_sent_total",
			"Queued submissions delivered by a background retry.",
			[]string{"endpoint"},
		),
		queueRetried: NewCounter(
			"posthorn_queue_retries_total",
			"Background retry attempts that failed transiently and rescheduled.",
			[]string{"endpoint"},
		),
		queueDeadLetter: NewCounter(
			"posthorn_queue_dead_lettered_total",
			"Queued submissions abandoned as failed (terminal error or attempts exhausted).",
			[]string{"endpoint"},
		),
		storageHealthy: NewGauge(
			"posthorn_storage_healthy",
			"1 when the storage canary write succeeds, 0 while degraded (mail still flows synchronously; nothing persists).",
			nil,
		),
		retryQueueDepth: NewGauge(
			"posthorn_retry_queue_depth",
			"Submissions currently waiting in (or claimed from) the retry queue.",
			nil,
		),
	}
	reg.Register(r.submitted)
	reg.Register(r.sent)
	reg.Register(r.failed)
	reg.Register(r.rateLimited)
	reg.Register(r.authFailed)
	reg.Register(r.spamBlocked)
	reg.Register(r.checkFailedOpen)
	reg.Register(r.validationFailed)
	reg.Register(r.idempotentReplay)
	reg.Register(r.sendLatency)
	reg.Register(r.queued)
	reg.Register(r.queueSent)
	reg.Register(r.queueRetried)
	reg.Register(r.queueDeadLetter)
	reg.Register(r.storageHealthy)
	reg.Register(r.retryQueueDepth)
	return r
}

// Submitted records a submission that passed body parse + validation
// and is about to enter the transport. Called once per request before
// transport.Send.
func (r *Recorder) Submitted(endpoint string) {
	if r == nil {
		return
	}
	r.submitted.Inc(endpoint)
}

// Sent records a successful upstream delivery and observes the latency.
func (r *Recorder) Sent(endpoint, transport string, latency time.Duration) {
	if r == nil {
		return
	}
	r.sent.Inc(endpoint, transport)
	r.sendLatency.Observe(latency.Seconds(), endpoint, transport)
}

// Failed records a terminal transport failure (no retry, 502 to client).
// errorClass is the ErrorClass.String() value ("transient" / "rate_limited"
// / "terminal" / "unknown").
func (r *Recorder) Failed(endpoint, transport, errorClass string) {
	if r == nil {
		return
	}
	r.failed.Inc(endpoint, transport, errorClass)
}

// RateLimited records a 429 response at the rate-limit gate.
func (r *Recorder) RateLimited(endpoint string) {
	if r == nil {
		return
	}
	r.rateLimited.Inc(endpoint)
}

// AuthFailed records a 401 response from the API-mode auth check.
func (r *Recorder) AuthFailed(endpoint string) {
	if r == nil {
		return
	}
	r.authFailed.Inc(endpoint)
}

// SpamBlocked records a spam-check rejection. kind is "honeypot",
// "origin", "csrf", or "reputation" — an operator-facing enum, never
// submitter content (NFR24).
func (r *Recorder) SpamBlocked(endpoint, kind string) {
	if r == nil {
		return
	}
	r.spamBlocked.Inc(endpoint, kind)
}

// CheckFailedOpen records a spam check whose provider errored and was
// allowed through (fail-open) — a silent-bypass signal. check is the
// operator-facing check name ("reputation", "captcha"), never submitter
// content (NFR24).
func (r *Recorder) CheckFailedOpen(endpoint, check string) {
	if r == nil {
		return
	}
	r.checkFailedOpen.Inc(endpoint, check)
}

// ValidationFailed records a 422 response for required-fields or
// email-format failure.
func (r *Recorder) ValidationFailed(endpoint string) {
	if r == nil {
		return
	}
	r.validationFailed.Inc(endpoint)
}

// IdempotentReplay records a cache-hit replay (no transport send).
func (r *Recorder) IdempotentReplay(endpoint string) {
	if r == nil {
		return
	}
	r.idempotentReplay.Inc(endpoint)
}

// Queued records a submission entering the background retry queue after
// exhausting inline retries (FR78).
func (r *Recorder) Queued(endpoint, transport string) {
	if r == nil {
		return
	}
	r.queued.Inc(endpoint, transport)
}

// QueueSent records a background retry that delivered.
func (r *Recorder) QueueSent(endpoint string) {
	if r == nil {
		return
	}
	r.queueSent.Inc(endpoint)
}

// QueueRetried records a background retry that failed transiently and
// rescheduled.
func (r *Recorder) QueueRetried(endpoint string) {
	if r == nil {
		return
	}
	r.queueRetried.Inc(endpoint)
}

// QueueDeadLettered records a queued submission abandoned as failed.
func (r *Recorder) QueueDeadLettered(endpoint string) {
	if r == nil {
		return
	}
	r.queueDeadLetter.Inc(endpoint)
}

// SetStorageHealthy flips the FR80 canary gauge.
func (r *Recorder) SetStorageHealthy(healthy bool) {
	if r == nil {
		return
	}
	v := 0.0
	if healthy {
		v = 1
	}
	r.storageHealthy.Set(v)
}

// SetQueueDepth publishes the current retry-queue depth.
func (r *Recorder) SetQueueDepth(n int) {
	if r == nil {
		return
	}
	r.retryQueueDepth.Set(float64(n))
}

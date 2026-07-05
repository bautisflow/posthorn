package spam

// Verdict is a spam check's decision plus everything the handler needs to
// render the outcome: the response shape, the log line, and the metric
// label. Collecting these into one value lets the gateway apply a single
// mapping (log + metric + response) for every check instead of a bespoke
// inline block per check — so adding a check is a new builder entry, not
// another branch in ServeHTTP.
//
// The zero Verdict means "not blocked; continue the pipeline."
type Verdict struct {
	// Blocked is false for a passing check. When false, all other fields
	// are ignored.
	Blocked bool

	// Silent selects the response when Blocked. true → accept-and-discard
	// with a 200 in the success body shape (the honeypot behavior, so a
	// bot can't distinguish rejection from success). false → reject with
	// Status.
	Silent bool

	// Status is the HTTP status for a non-silent block. Zero means 403.
	Status int

	// Kind is the operator-facing check name — the metrics label and the
	// log "kind" field. Never submitter content (NFR24). E.g. "origin",
	// "honeypot", "csrf".
	Kind string

	// Event is the structured-log message. Empty means "spam_blocked".
	// The CSRF check sets "csrf_rejected" to preserve its distinct event.
	Event string

	// Reason is optional log detail (the specific check that fired).
	Reason string

	// FailedOpen marks a non-blocking verdict from a check whose provider
	// errored and was configured to fail open (reputation). The submission
	// continues, but the handler logs and meters it so a sustained-outage
	// bypass window is visible. Ignored when Blocked is true.
	FailedOpen bool
}

// Blocks constructs a hard-reject Verdict (403 unless Status is set later).
func Blocks(kind string) Verdict { return Verdict{Blocked: true, Kind: kind} }

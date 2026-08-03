// Package lifecycle ingests provider delivery events and forwards them
// to the originating caller (FR82-FR85, ADR-22).
//
// v2.0 speaks one provider dialect — Postmark — behind a
// provider-agnostic normalized event shape. The normalized fields are
// the forward contract; the raw provider payload rides along as
// explicitly best-effort provider_data. Additional providers slot in as
// new normalizers behind the same shape.
package lifecycle

import (
	"encoding/json"
	"fmt"
	"time"
)

// Event kinds (FR83). Label-safe operator-facing enum (NFR30) — never
// derived from payload content outside this fixed set.
const (
	EventDelivered     = "delivered"
	EventHardBounce    = "hard_bounce"
	EventSoftBounce    = "soft_bounce"
	EventSpamComplaint = "spam_complaint"
	EventOpened        = "opened"
	EventClicked       = "clicked"
	EventOther         = "other"
)

// Event is the normalized shape (FR83) — both what Posthorn forwards to
// webhook_url and the only contract consumers should couple to.
type Event struct {
	// Event is one of the Event* constants.
	Event string `json:"event"`

	// SubmissionID is Posthorn's submission UUID, correlated from the
	// provider message ID via the submission log. The stable join key
	// for callers who recorded submission IDs at send time.
	SubmissionID string `json:"submission_id"`

	// Endpoint is the originating endpoint path ("/contact",
	// "smtp_listener").
	Endpoint string `json:"endpoint"`

	// Recipient is the affected address, when the provider names one.
	Recipient string `json:"recipient,omitempty"`

	// Timestamp is the provider's event time, best-effort; ingestion
	// time when the provider omits or mangles it.
	Timestamp time.Time `json:"timestamp"`

	// Provider names the source dialect ("postmark").
	Provider string `json:"provider"`

	// ProviderData is the raw provider payload, passed through
	// best-effort. Consumers coupling to it are on their own (ADR-22);
	// the normalized fields above are the API.
	ProviderData json.RawMessage `json:"provider_data,omitempty"`
}

// postmarkEvent captures the fields Posthorn reads from Postmark's
// webhook payloads. Postmark spreads the recipient and timestamp across
// differently-named fields per RecordType; all candidates are listed
// and coalesced.
type postmarkEvent struct {
	RecordType string `json:"RecordType"`
	Type       string `json:"Type"` // bounce subtype (HardBounce, SoftBounce, Transient, ...)
	MessageID  string `json:"MessageID"`

	Email     string `json:"Email"`     // Bounce, SpamComplaint
	Recipient string `json:"Recipient"` // Delivery, Open, Click

	DeliveredAt string `json:"DeliveredAt"`
	BouncedAt   string `json:"BouncedAt"`
	ReceivedAt  string `json:"ReceivedAt"`
}

// hardBounceTypes are the Postmark bounce subtypes that indicate the
// mailbox is durably undeliverable — the FR85 auto-suppress set.
// Everything else bounce-shaped (SoftBounce, Transient, DnsError, ...)
// normalizes to soft_bounce and does not suppress.
var hardBounceTypes = map[string]bool{
	"HardBounce":          true,
	"BadEmailAddress":     true,
	"ManuallyDeactivated": true,
}

// NormalizePostmark parses a Postmark webhook body into the normalized
// shape (FR83). The provider MessageID is returned separately for
// submission-log correlation. Unknown RecordTypes normalize to "other"
// rather than erroring — Postmark adding event types must not break
// ingestion.
func NormalizePostmark(body []byte, now time.Time) (ev Event, messageID string, err error) {
	var pe postmarkEvent
	if err := json.Unmarshal(body, &pe); err != nil {
		return Event{}, "", fmt.Errorf("lifecycle: parse postmark payload: %w", err)
	}
	if pe.RecordType == "" {
		return Event{}, "", fmt.Errorf("lifecycle: postmark payload has no RecordType")
	}

	kind := EventOther
	recipient := pe.Recipient
	ts := pe.ReceivedAt
	switch pe.RecordType {
	case "Delivery":
		kind = EventDelivered
		ts = firstNonEmpty(pe.DeliveredAt, ts)
	case "Bounce":
		kind = EventSoftBounce
		if hardBounceTypes[pe.Type] {
			kind = EventHardBounce
		}
		recipient = firstNonEmpty(pe.Email, recipient)
		ts = firstNonEmpty(pe.BouncedAt, ts)
	case "SpamComplaint":
		kind = EventSpamComplaint
		recipient = firstNonEmpty(pe.Email, recipient)
		ts = firstNonEmpty(pe.BouncedAt, ts)
	case "Open":
		kind = EventOpened
	case "Click":
		kind = EventClicked
	}

	when := now
	if ts != "" {
		if parsed, perr := time.Parse(time.RFC3339, ts); perr == nil {
			when = parsed
		}
	}

	return Event{
		Event:        kind,
		Recipient:    recipient,
		Timestamp:    when.UTC(),
		Provider:     "postmark",
		ProviderData: json.RawMessage(body),
	}, pe.MessageID, nil
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

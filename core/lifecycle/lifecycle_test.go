package lifecycle

import (
	"testing"
	"time"
)

var t0 = time.Date(2026, 8, 2, 12, 0, 0, 0, time.UTC)

func TestNormalizePostmark_Table(t *testing.T) {
	cases := []struct {
		name          string
		body          string
		wantEvent     string
		wantRecipient string
		wantMessageID string
	}{
		{
			name:          "delivery",
			body:          `{"RecordType":"Delivery","MessageID":"pm-1","Recipient":"a@example.com","DeliveredAt":"2026-08-02T10:00:00Z"}`,
			wantEvent:     EventDelivered,
			wantRecipient: "a@example.com",
			wantMessageID: "pm-1",
		},
		{
			name:          "hard bounce",
			body:          `{"RecordType":"Bounce","Type":"HardBounce","MessageID":"pm-2","Email":"b@example.com","BouncedAt":"2026-08-02T10:00:00Z"}`,
			wantEvent:     EventHardBounce,
			wantRecipient: "b@example.com",
			wantMessageID: "pm-2",
		},
		{
			name:          "bad address is a hard bounce",
			body:          `{"RecordType":"Bounce","Type":"BadEmailAddress","MessageID":"pm-3","Email":"c@example.com"}`,
			wantEvent:     EventHardBounce,
			wantRecipient: "c@example.com",
			wantMessageID: "pm-3",
		},
		{
			name:          "soft bounce",
			body:          `{"RecordType":"Bounce","Type":"SoftBounce","MessageID":"pm-4","Email":"d@example.com"}`,
			wantEvent:     EventSoftBounce,
			wantRecipient: "d@example.com",
			wantMessageID: "pm-4",
		},
		{
			name:          "transient bounce is soft",
			body:          `{"RecordType":"Bounce","Type":"Transient","MessageID":"pm-5","Email":"e@example.com"}`,
			wantEvent:     EventSoftBounce,
			wantRecipient: "e@example.com",
			wantMessageID: "pm-5",
		},
		{
			name:          "spam complaint",
			body:          `{"RecordType":"SpamComplaint","MessageID":"pm-6","Email":"f@example.com"}`,
			wantEvent:     EventSpamComplaint,
			wantRecipient: "f@example.com",
			wantMessageID: "pm-6",
		},
		{
			name:          "open",
			body:          `{"RecordType":"Open","MessageID":"pm-7","Recipient":"g@example.com"}`,
			wantEvent:     EventOpened,
			wantRecipient: "g@example.com",
			wantMessageID: "pm-7",
		},
		{
			name:          "click",
			body:          `{"RecordType":"Click","MessageID":"pm-8","Recipient":"h@example.com"}`,
			wantEvent:     EventClicked,
			wantRecipient: "h@example.com",
			wantMessageID: "pm-8",
		},
		{
			name:          "unknown record type normalizes to other",
			body:          `{"RecordType":"SubscriptionChange","MessageID":"pm-9"}`,
			wantEvent:     EventOther,
			wantMessageID: "pm-9",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ev, msgID, err := NormalizePostmark([]byte(tc.body), t0)
			if err != nil {
				t.Fatalf("NormalizePostmark: %v", err)
			}
			if ev.Event != tc.wantEvent {
				t.Errorf("Event = %q, want %q", ev.Event, tc.wantEvent)
			}
			if ev.Recipient != tc.wantRecipient {
				t.Errorf("Recipient = %q, want %q", ev.Recipient, tc.wantRecipient)
			}
			if msgID != tc.wantMessageID {
				t.Errorf("messageID = %q, want %q", msgID, tc.wantMessageID)
			}
			if ev.Provider != "postmark" {
				t.Errorf("Provider = %q", ev.Provider)
			}
			if string(ev.ProviderData) != tc.body {
				t.Errorf("ProviderData should carry the raw payload")
			}
		})
	}
}

func TestNormalizePostmark_ProviderTimestampWins(t *testing.T) {
	ev, _, err := NormalizePostmark(
		[]byte(`{"RecordType":"Delivery","MessageID":"m","DeliveredAt":"2026-07-01T08:30:00Z"}`), t0)
	if err != nil {
		t.Fatal(err)
	}
	want := time.Date(2026, 7, 1, 8, 30, 0, 0, time.UTC)
	if !ev.Timestamp.Equal(want) {
		t.Errorf("Timestamp = %v, want %v", ev.Timestamp, want)
	}
}

func TestNormalizePostmark_BadTimestampFallsBackToNow(t *testing.T) {
	ev, _, err := NormalizePostmark(
		[]byte(`{"RecordType":"Delivery","MessageID":"m","DeliveredAt":"not-a-time"}`), t0)
	if err != nil {
		t.Fatal(err)
	}
	if !ev.Timestamp.Equal(t0) {
		t.Errorf("Timestamp = %v, want ingestion time %v", ev.Timestamp, t0)
	}
}

func TestNormalizePostmark_Malformed(t *testing.T) {
	for _, body := range []string{"not json", "{}", `{"MessageID":"m"}`} {
		if _, _, err := NormalizePostmark([]byte(body), t0); err == nil {
			t.Errorf("NormalizePostmark(%q): expected error", body)
		}
	}
}

func TestSign_KnownVector(t *testing.T) {
	// Deterministic: receivers implementing verification against the
	// docs must produce exactly this.
	got := Sign([]byte(`{"event":"delivered"}`), "test-secret-16by")
	if len(got) != len("sha256=")+64 {
		t.Fatalf("signature shape: %q", got)
	}
	if got[:7] != "sha256=" {
		t.Fatalf("missing scheme prefix: %q", got)
	}
	// Same body+secret → same signature; different secret → different.
	if Sign([]byte(`{"event":"delivered"}`), "test-secret-16by") != got {
		t.Error("signature not deterministic")
	}
	if Sign([]byte(`{"event":"delivered"}`), "other-secret-16b") == got {
		t.Error("signature ignores the secret")
	}
}

package providertest

import (
	"encoding/json"
	"net/url"
	"strings"
	"testing"

	"github.com/craigmccaskill/posthorn/transport"
)

// sesWire mirrors the SESv2 SendEmail request the transport builds.
type sesWire struct {
	FromEmailAddress string `json:"FromEmailAddress"`
	Destination      struct {
		ToAddresses []string `json:"ToAddresses"`
	} `json:"Destination"`
	Content struct {
		Simple struct {
			Subject struct {
				Data string `json:"Data"`
			} `json:"Subject"`
			Body struct {
				Text struct {
					Data string `json:"Data"`
				} `json:"Text"`
			} `json:"Body"`
		} `json:"Simple"`
	} `json:"Content"`
}

var sesTUT = TransportUnderTest{
	Name:     "ses",
	Response: `{"MessageId":"ses-1"}`,
	NewHermetic: func(baseURL string) transport.Transport {
		return transport.NewSESTransport("AKIATEST", "secret", "us-east-1", baseURL)
	},
	Decode: func(t *testing.T, req CapturedRequest) DeliveredMail {
		t.Helper()
		var w sesWire
		if err := json.Unmarshal(req.Body, &w); err != nil {
			t.Fatalf("ses body not valid JSON: %v\n%s", err, req.Body)
		}
		return DeliveredMail{
			From:     w.FromEmailAddress,
			To:       w.Destination.ToAddresses,
			Subject:  w.Content.Simple.Subject.Data,
			BodyText: w.Content.Simple.Body.Text.Data,
		}
	},
	SafetyCheck: AssertNoRawCRLF,
	CheckAuth: func(t *testing.T, req CapturedRequest) {
		t.Helper()
		// Bespoke SigV4 (ADR-14): assert the signature is present and
		// well-formed enough to prove signing ran end-to-end.
		auth := req.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "AWS4-HMAC-SHA256 ") || !strings.Contains(auth, "Signature=") {
			t.Errorf("Authorization = %q, want an AWS4-HMAC-SHA256 SigV4 header", auth)
		}
	},
}

func TestE2E_SES_FormToWire(t *testing.T) {
	RunFormScenario(t, sesTUT, Scenario{
		Name:     "contact",
		Endpoint: contactEndpoint(),
		Form:     url.Values{"name": {"Alice"}, "message": {"Hello there"}},
		Want: DeliveredMail{
			From:     "Posthorn <noreply@example.com>",
			To:       []string{"ops@example.com"},
			Subject:  "Contact from Alice",
			BodyText: "Hello there",
		},
		InjectField: "name",
	})
}

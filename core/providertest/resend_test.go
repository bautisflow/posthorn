package providertest

import (
	"encoding/json"
	"net/url"
	"testing"

	"github.com/craigmccaskill/posthorn/transport"
)

type resendWire struct {
	From    string   `json:"from"`
	To      []string `json:"to"`
	Subject string   `json:"subject"`
	Text    string   `json:"text"`
}

var resendTUT = TransportUnderTest{
	Name:        "resend",
	Response:    `{"id":"re-1"}`,
	NewHermetic: func(baseURL string) transport.Transport { return transport.NewResendTransport("test-key", baseURL) },
	Decode: func(t *testing.T, req CapturedRequest) DeliveredMail {
		t.Helper()
		var w resendWire
		if err := json.Unmarshal(req.Body, &w); err != nil {
			t.Fatalf("resend body not valid JSON: %v\n%s", err, req.Body)
		}
		return DeliveredMail{From: w.From, To: w.To, Subject: w.Subject, BodyText: w.Text}
	},
	SafetyCheck: AssertNoRawCRLF,
	CheckAuth: func(t *testing.T, req CapturedRequest) {
		t.Helper()
		if got := req.Header.Get("Authorization"); got != "Bearer test-key" {
			t.Errorf("Authorization = %q, want %q", got, "Bearer test-key")
		}
	},
}

func TestE2E_Resend_FormToWire(t *testing.T) {
	RunFormScenario(t, resendTUT, Scenario{
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

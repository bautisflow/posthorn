package providertest

// Reference slice for issue #76, in the Scenario-centric shape the other
// transports copy: define a TransportUnderTest (how to build the client,
// decode its wire form, and prove injection-safety) and hand it to the
// shared RunFormScenario. The runner drives a real HTTP form through the
// real gateway handler and the real Postmark transport into a
// CaptureServer, verifying the transport.Message seam the architecture
// audit flagged as "trusted, not verified end-to-end" — hermetic, no
// network, no credentials.

import (
	"encoding/json"
	"net/url"
	"testing"

	"github.com/craigmccaskill/posthorn/config"
	"github.com/craigmccaskill/posthorn/transport"
)

// postmarkWire is the subset of the Postmark JSON body we decode.
type postmarkWire struct {
	From     string
	To       string
	Subject  string
	TextBody string
}

var postmarkTUT = TransportUnderTest{
	Name:        "postmark",
	Response:    `{"ErrorCode":0,"Message":"OK","MessageID":"m-1"}`,
	NewHermetic: func(baseURL string) transport.Transport { return transport.NewPostmarkTransport("test-key", baseURL) },
	Decode: func(t *testing.T, req CapturedRequest) DeliveredMail {
		t.Helper()
		var w postmarkWire
		if err := json.Unmarshal(req.Body, &w); err != nil {
			t.Fatalf("captured body is not valid JSON: %v\n%s", err, req.Body)
		}
		return DeliveredMail{From: w.From, To: []string{w.To}, Subject: w.Subject, BodyText: w.TextBody}
	},
	SafetyCheck: AssertNoRawCRLF,
	CheckAuth: func(t *testing.T, req CapturedRequest) {
		t.Helper()
		if got := req.Header.Get("X-Postmark-Server-Token"); got != "test-key" {
			t.Errorf("auth header X-Postmark-Server-Token = %q, want the server token", got)
		}
	},
}

// contactEndpoint is a form-mode endpoint whose Subject is templated
// from the submitter-controlled `name` field — the injection surface.
func contactEndpoint() config.EndpointConfig {
	return config.EndpointConfig{
		Path:     "/contact",
		To:       []string{"ops@example.com"},
		From:     "Posthorn <noreply@example.com>",
		Subject:  "Contact from {{.name}}",
		Body:     "{{.message}}",
		Required: []string{"name", "message"},
	}
}

func TestE2E_Postmark_FormToWire(t *testing.T) {
	RunFormScenario(t, postmarkTUT, Scenario{
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

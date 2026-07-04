package providertest

import (
	"bytes"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/url"
	"testing"

	"github.com/craigmccaskill/posthorn/transport"
)

// mailgunFieldsAllowed is the set of multipart field names the transport
// is permitted to emit. A submitter value that smuggled a new part
// (e.g. by guessing the boundary) would show up as an unexpected name.
var mailgunFieldsAllowed = map[string]bool{
	"from": true, "to": true, "subject": true, "text": true, "h:Reply-To": true,
}

// parseMailgunMultipart decodes the captured multipart body into a
// field-name → values map using the boundary from the Content-Type.
func parseMailgunMultipart(t *testing.T, req CapturedRequest) map[string][]string {
	t.Helper()
	_, params, err := mime.ParseMediaType(req.Header.Get("Content-Type"))
	if err != nil {
		t.Fatalf("mailgun content-type parse: %v", err)
	}
	mr := multipart.NewReader(bytes.NewReader(req.Body), params["boundary"])
	fields := map[string][]string{}
	for {
		part, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("mailgun multipart broke — possible boundary injection: %v", err)
		}
		val, _ := io.ReadAll(part)
		fields[part.FormName()] = append(fields[part.FormName()], string(val))
	}
	return fields
}

var mailgunTUT = TransportUnderTest{
	Name:     "mailgun",
	Response: `{"id":"<mg-1>","message":"Queued"}`,
	NewHermetic: func(baseURL string) transport.Transport {
		return transport.NewMailgunTransport("test-key", "sandbox.example.com", baseURL)
	},
	Decode: func(t *testing.T, req CapturedRequest) DeliveredMail {
		t.Helper()
		f := parseMailgunMultipart(t, req)
		return DeliveredMail{
			From:     first(f["from"]),
			To:       f["to"],
			Subject:  first(f["subject"]),
			BodyText: first(f["text"]),
		}
	},
	// Multipart carries CRLF legitimately (part separators), so the raw
	// scan is invalid. Instead assert the body still parses as multipart
	// and every part is an allowed field — a smuggled part or a broken
	// boundary would fail one of those.
	SafetyCheck: func(t *testing.T, req CapturedRequest) {
		t.Helper()
		for name := range parseMailgunMultipart(t, req) {
			if !mailgunFieldsAllowed[name] {
				t.Errorf("unexpected multipart field %q — submitter value smuggled a new part", name)
			}
		}
	},
	CheckAuth: func(t *testing.T, req CapturedRequest) {
		t.Helper()
		user, pass, ok := (&http.Request{Header: req.Header}).BasicAuth()
		if !ok || user != "api" || pass != "test-key" {
			t.Errorf("basic auth = (%q,%q,ok=%v), want (api,test-key,true)", user, pass, ok)
		}
	},
}

func TestE2E_Mailgun_FormToWire(t *testing.T) {
	RunFormScenario(t, mailgunTUT, Scenario{
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

func first(v []string) string {
	if len(v) == 0 {
		return ""
	}
	return v[0]
}

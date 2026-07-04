package providertest

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/craigmccaskill/posthorn/config"
	"github.com/craigmccaskill/posthorn/gateway"
	"github.com/craigmccaskill/posthorn/transport"
)

// DeliveredMail is the canonical, provider-agnostic view of what a
// transport actually put on the wire, decoded back from whatever
// encoding the provider uses (Postmark/Resend/SES JSON, Mailgun
// multipart, outbound-SMTP DATA). Scenarios assert against this so the
// same expected-outcome definition works for every transport.
type DeliveredMail struct {
	From     string
	To       []string
	Subject  string
	BodyText string
}

// Scenario is the shared unit between the hermetic and live tiers: an
// ingress input plus the semantic outcome it should produce. Hermetic
// runs assert the outcome against captured request bytes; live runs
// (build tag `integration`) assert it against real delivery. The
// scenario itself is tier-agnostic — only the assertion differs, because
// hermetic can see the bytes and live can only see the delivery.
type Scenario struct {
	Name     string
	Endpoint config.EndpointConfig // template + routing; the transport is supplied by the runner
	Form     url.Values            // form-mode submitter input

	Want DeliveredMail // expected canonical outcome

	// InjectField, when set, names the form field the header-injection
	// battery varies. Its value flows through the endpoint's Subject
	// template, so the decoded Subject must carry each payload verbatim
	// while the transport's SafetyCheck confirms nothing was smuggled.
	InjectField string
}

// TransportUnderTest adapts one provider to the shared runner: how to
// build its transport against a base URL, how to decode a captured
// request into DeliveredMail, and how to prove the captured wire form
// contains no header injection (per-encoding: a raw-CRLF scan for JSON
// providers, a header parse for the SMTP DATA blob).
type TransportUnderTest struct {
	Name        string
	Response    string // canned success body the CaptureServer returns
	NewHermetic func(baseURL string) transport.Transport
	Decode      func(t *testing.T, req CapturedRequest) DeliveredMail
	SafetyCheck func(t *testing.T, req CapturedRequest)
	CheckAuth   func(t *testing.T, req CapturedRequest) // optional; nil to skip
}

// RunFormScenario drives sc through a real gateway.Handler wired to
// tut's hermetic transport pointed at a CaptureServer, then asserts the
// decoded wire shape matches sc.Want. When sc.InjectField is set it also
// runs the header-injection battery. No network, no credentials.
func RunFormScenario(t *testing.T, tut TransportUnderTest, sc Scenario) {
	t.Helper()

	t.Run(sc.Name+"/happy", func(t *testing.T) {
		req := driveForm(t, tut, sc.Endpoint, sc.Form)
		got := tut.Decode(t, req)
		assertDelivered(t, got, sc.Want)
		if tut.CheckAuth != nil {
			tut.CheckAuth(t, req)
		}
		tut.SafetyCheck(t, req)
	})

	if sc.InjectField == "" {
		return
	}
	for _, payload := range InjectionValues() {
		t.Run(sc.Name+"/inject/"+SanitizeName(payload), func(t *testing.T) {
			form := cloneValues(sc.Form)
			form.Set(sc.InjectField, payload)
			req := driveForm(t, tut, sc.Endpoint, form)
			got := tut.Decode(t, req)
			if !strings.Contains(got.Subject, payload) {
				t.Errorf("Subject = %q, want it to carry the payload %q verbatim as data", got.Subject, payload)
			}
			tut.SafetyCheck(t, req)
		})
	}
}

// driveForm POSTs form to a handler built from ep + tut's transport and
// returns the single request the CaptureServer recorded.
func driveForm(t *testing.T, tut TransportUnderTest, ep config.EndpointConfig, form url.Values) CapturedRequest {
	t.Helper()
	resp := tut.Response
	if resp == "" {
		resp = "{}"
	}
	cs := NewCaptureServer(t, http.StatusOK, resp)
	h, err := gateway.New(ep, tut.NewHermetic(cs.URL))
	if err != nil {
		t.Fatalf("gateway.New: %v", err)
	}
	r := httptest.NewRequest(http.MethodPost, ep.Path, strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	if rec.Code != http.StatusOK {
		t.Fatalf("handler status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	req, ok := cs.Last()
	if !ok {
		t.Fatalf("%s transport made no request", tut.Name)
	}
	return req
}

func assertDelivered(t *testing.T, got, want DeliveredMail) {
	t.Helper()
	if got.From != want.From {
		t.Errorf("From = %q, want %q", got.From, want.From)
	}
	if strings.Join(got.To, ",") != strings.Join(want.To, ",") {
		t.Errorf("To = %v, want %v", got.To, want.To)
	}
	if got.Subject != want.Subject {
		t.Errorf("Subject = %q, want %q", got.Subject, want.Subject)
	}
	if got.BodyText != want.BodyText {
		t.Errorf("BodyText = %q, want %q", got.BodyText, want.BodyText)
	}
}

func cloneValues(v url.Values) url.Values {
	out := make(url.Values, len(v))
	for k, vals := range v {
		cp := make([]string, len(vals))
		copy(cp, vals)
		out[k] = cp
	}
	return out
}

// AssertNoRawCRLF is the SafetyCheck for JSON-body providers: a bare CR
// or LF in the serialized body means submitter data escaped its string
// context and could smuggle a header. Correct JSON encoding turns CR/LF
// into \r \n escapes, so the raw bytes carry none.
func AssertNoRawCRLF(t *testing.T, req CapturedRequest) {
	t.Helper()
	for i, c := range req.Body {
		if c == '\r' || c == '\n' {
			t.Errorf("raw CR/LF at byte %d of serialized body — header injection not neutralized:\n%q", i, req.Body)
			return
		}
	}
}

// SanitizeName renders a payload as a safe subtest name.
func SanitizeName(s string) string {
	name := strings.NewReplacer("\r", "<CR>", "\n", "<LF>", " ", "_", "/", "_").Replace(s)
	if len(name) > 40 {
		name = name[:40]
	}
	return name
}

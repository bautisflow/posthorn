package gateway_test

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/craigmccaskill/posthorn/config"
	"github.com/craigmccaskill/posthorn/gateway"
)

// End-to-end FR71/FR72: a body_format = "html" endpoint produces a
// Message with both parts, submitter input escaped, through the full
// handler pipeline.

func newHTMLTestHandler(t *testing.T, tr *recordingTransport, textBody string) *gateway.Handler {
	t.Helper()
	cfg := config.EndpointConfig{
		Path:       "/test",
		To:         []string{"to@example.com"},
		From:       "from@example.com",
		Subject:    "From {{.name}}",
		Body:       "<h1>Contact</h1><p>{{.message}}</p>",
		BodyFormat: config.BodyFormatHTML,
		TextBody:   textBody,
	}
	h, err := gateway.New(cfg, tr)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return h
}

func TestHandler_HTMLEndpoint_SendsBothParts(t *testing.T) {
	tr := &recordingTransport{}
	h := newHTMLTestHandler(t, tr, "")

	req := urlencodedRequest("name=Jane&message=Hello+there")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != 200 {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if len(tr.sent) != 1 {
		t.Fatalf("sent = %d messages", len(tr.sent))
	}
	msg := tr.sent[0]
	if !strings.Contains(msg.BodyHTML, "<p>Hello there</p>") {
		t.Errorf("BodyHTML = %q", msg.BodyHTML)
	}
	if !strings.Contains(msg.BodyText, "Hello there") {
		t.Errorf("BodyText (derived) = %q", msg.BodyText)
	}
	if strings.Contains(msg.BodyText, "<p>") {
		t.Errorf("derived BodyText leaked markup: %q", msg.BodyText)
	}
}

func TestHandler_HTMLEndpoint_EscapesSubmitterInput(t *testing.T) {
	tr := &recordingTransport{}
	h := newHTMLTestHandler(t, tr, "")

	req := urlencodedRequest("name=x&message=" + "%3Cscript%3Ealert(1)%3C/script%3E")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != 200 {
		t.Fatalf("status = %d", rec.Code)
	}
	msg := tr.sent[0]
	if strings.Contains(msg.BodyHTML, "<script>") {
		t.Errorf("live script tag in outbound HTML: %q", msg.BodyHTML)
	}
	if !strings.Contains(msg.BodyHTML, "&lt;script&gt;") {
		t.Errorf("submitter markup not escaped: %q", msg.BodyHTML)
	}
}

func TestHandler_HTMLEndpoint_ExplicitTextBody(t *testing.T) {
	tr := &recordingTransport{}
	h := newHTMLTestHandler(t, tr, "Plain: {{.message}}")

	req := urlencodedRequest("name=x&message=hi")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != 200 {
		t.Fatalf("status = %d", rec.Code)
	}
	if got := tr.sent[0].BodyText; got != "Plain: hi" {
		t.Errorf("BodyText = %q, want explicit template output", got)
	}
}

func TestHandler_HTMLEndpoint_DryRunExposesBodyHTML(t *testing.T) {
	tr := &recordingTransport{}
	cfg := config.EndpointConfig{
		Path:       "/test",
		To:         []string{"to@example.com"},
		From:       "from@example.com",
		Subject:    "S",
		Body:       "<p>{{.message}}</p>",
		BodyFormat: config.BodyFormatHTML,
		DryRun:     true,
	}
	h, err := gateway.New(cfg, tr)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	req := urlencodedRequest("message=hi")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != 200 {
		t.Fatalf("status = %d", rec.Code)
	}
	if len(tr.sent) != 0 {
		t.Fatal("dry run must not send")
	}
	var resp struct {
		PreparedMessage struct {
			BodyText string `json:"body_text"`
			BodyHTML string `json:"body_html"`
		} `json:"prepared_message"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("response not JSON: %v", err)
	}
	if !strings.Contains(resp.PreparedMessage.BodyHTML, "<p>hi</p>") {
		t.Errorf("body_html = %q", resp.PreparedMessage.BodyHTML)
	}
	if resp.PreparedMessage.BodyText == "" {
		t.Error("body_text missing from dry-run")
	}
}

func TestHandler_TextEndpoint_NoBodyHTML(t *testing.T) {
	tr := &recordingTransport{}
	h := newTestHandler(t, tr)

	req := urlencodedRequest("message=hi")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != 200 {
		t.Fatalf("status = %d", rec.Code)
	}
	if got := tr.sent[0].BodyHTML; got != "" {
		t.Errorf("text endpoint produced BodyHTML = %q", got)
	}
}

func TestNew_HTMLTemplateErrorSurfaces(t *testing.T) {
	cfg := config.EndpointConfig{
		Subject:    "S",
		Body:       `<a href="{{.x}}`, // ends mid-attribute: escape error
		BodyFormat: config.BodyFormatHTML,
	}
	if _, err := gateway.New(cfg, &recordingTransport{}); err == nil {
		t.Fatal("expected construction error for unescapable template")
	}
}

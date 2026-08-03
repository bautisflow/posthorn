package gateway_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/craigmccaskill/posthorn/config"
	"github.com/craigmccaskill/posthorn/gateway"
)

// FR90/FR91/ADR-25: opt-in, fail-closed, sniffed-type enforcement at
// both HTTP doors.

var (
	pngBytes = append([]byte("\x89PNG\r\n\x1a\n"), bytes.Repeat([]byte{0}, 64)...)
	pdfBytes = []byte("%PDF-1.4\n1 0 obj\n<<>>\nendobj\ntrailer\n<<>>\n%%EOF")
)

func attachmentEndpoint(t *testing.T, tr *recordingTransport, attCfg *config.AttachmentsConfig) *gateway.Handler {
	t.Helper()
	cfg := config.EndpointConfig{
		Path:        "/test",
		To:          []string{"to@example.com"},
		From:        "from@example.com",
		Subject:     "S",
		Body:        "B {{.message}}",
		Attachments: attCfg,
	}
	h, err := gateway.New(cfg, tr)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return h
}

// multipartUpload builds a multipart form with fields and files.
func multipartUpload(t *testing.T, fields map[string]string, files map[string][]byte) *http.Request {
	t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	for k, v := range fields {
		_ = mw.WriteField(k, v)
	}
	for name, data := range files {
		fw, err := mw.CreateFormFile("upload", name)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = fw.Write(data)
	}
	_ = mw.Close()
	req := httptest.NewRequest(http.MethodPost, "/test", &buf)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	return req
}

func TestMultipartFields_ReachPipeline(t *testing.T) {
	// The Story 17.1 bug fix: multipart form FIELDS were silently
	// dropped in v1.x (ParseForm ignores multipart bodies).
	tr := &recordingTransport{}
	h := newTestHandlerWithBody(t, tr, "Got: {{.message}}")

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, multipartUpload(t, map[string]string{"message": "MARKER"}, nil))
	if rec.Code != 200 {
		t.Fatalf("status = %d", rec.Code)
	}
	if !strings.Contains(tr.sent[0].BodyText, "MARKER") {
		t.Fatalf("multipart field dropped: %q", tr.sent[0].BodyText)
	}
}

func newTestHandlerWithBody(t *testing.T, tr *recordingTransport, body string) *gateway.Handler {
	t.Helper()
	cfg := config.EndpointConfig{
		Path: "/test", To: []string{"to@example.com"}, From: "from@example.com",
		Subject: "S", Body: body,
	}
	h, err := gateway.New(cfg, tr)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func TestFormAttachments_NotOptedIn_FilesDropped(t *testing.T) {
	tr := &recordingTransport{}
	h := newTestHandlerWithBody(t, tr, "B")

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, multipartUpload(t, map[string]string{"message": "hi"}, map[string][]byte{"cv.png": pngBytes}))
	if rec.Code != 200 {
		t.Fatalf("status = %d (v1.x drop behavior)", rec.Code)
	}
	if len(tr.sent[0].Attachments) != 0 {
		t.Fatalf("attachments crossed without opt-in: %d", len(tr.sent[0].Attachments))
	}
}

func TestFormAttachments_Accepted_SniffedType(t *testing.T) {
	tr := &recordingTransport{}
	h := attachmentEndpoint(t, tr, &config.AttachmentsConfig{AllowedTypes: []string{"image/*"}})

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, multipartUpload(t, map[string]string{"message": "hi"}, map[string][]byte{"photo.png": pngBytes}))
	if rec.Code != 200 {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
	atts := tr.sent[0].Attachments
	if len(atts) != 1 {
		t.Fatalf("attachments = %d", len(atts))
	}
	if atts[0].Filename != "photo.png" || atts[0].ContentType != "image/png" {
		t.Errorf("attachment = %+v (content type must be the sniffed value)", atts[0])
	}
	if !bytes.Equal(atts[0].Data, pngBytes) {
		t.Error("data mutated in transit")
	}
}

func TestFormAttachments_SpoofedDeclaredType_RejectedBySniff(t *testing.T) {
	tr := &recordingTransport{}
	h := attachmentEndpoint(t, tr, &config.AttachmentsConfig{AllowedTypes: []string{"image/*"}})

	// A "PNG" that is actually plain text: declared name/type lie,
	// bytes tell the truth (ADR-25).
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, multipartUpload(t, map[string]string{"message": "hi"},
		map[string][]byte{"totally-a-photo.png": []byte("#!/bin/sh\nrm -rf /\n")}))
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422", rec.Code)
	}
	if len(tr.sent) != 0 {
		t.Fatal("spoofed file was sent")
	}
	if !strings.Contains(rec.Body.String(), "not in allowed_types") {
		t.Errorf("body = %s", rec.Body.String())
	}
}

func TestFormAttachments_CountAndSizeLimits(t *testing.T) {
	tr := &recordingTransport{}
	h := attachmentEndpoint(t, tr, &config.AttachmentsConfig{
		AllowedTypes: []string{"image/*", "application/pdf"},
		MaxCount:     1,
		MaxTotalSize: "1KB",
	})

	// Count violation.
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, multipartUpload(t, map[string]string{"message": "hi"},
		map[string][]byte{"a.png": pngBytes, "b.png": pngBytes}))
	if rec.Code != http.StatusUnprocessableEntity || !strings.Contains(rec.Body.String(), "max_count") {
		t.Fatalf("count: status=%d body=%s", rec.Code, rec.Body.String())
	}

	// Size violation (single file over 1KB).
	big := append([]byte("\x89PNG\r\n\x1a\n"), bytes.Repeat([]byte{7}, 2048)...)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, multipartUpload(t, map[string]string{"message": "hi"}, map[string][]byte{"big.png": big}))
	if rec.Code != http.StatusUnprocessableEntity || !strings.Contains(rec.Body.String(), "max_total_size") {
		t.Fatalf("size: status=%d body=%s", rec.Code, rec.Body.String())
	}
	if len(tr.sent) != 0 {
		t.Fatal("violating submissions were sent")
	}
}

func TestFormAttachments_FilenameSanitized(t *testing.T) {
	tr := &recordingTransport{}
	h := attachmentEndpoint(t, tr, &config.AttachmentsConfig{AllowedTypes: []string{"image/*"}})

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, multipartUpload(t, map[string]string{"message": "hi"},
		map[string][]byte{"../../etc/passwd\r\nBcc: evil": pngBytes}))
	if rec.Code != 200 {
		t.Fatalf("status = %d", rec.Code)
	}
	name := tr.sent[0].Attachments[0].Filename
	if strings.ContainsAny(name, "/\\\r\n") {
		t.Errorf("filename not sanitized: %q", name)
	}
}

func apiAttachmentEndpoint(t *testing.T, tr *recordingTransport, attCfg *config.AttachmentsConfig) *gateway.Handler {
	t.Helper()
	cfg := apiModeConfig("valid-key")
	cfg.Attachments = attCfg
	h, err := gateway.New(cfg, tr)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func TestAPIAttachments_Base64Accepted(t *testing.T) {
	tr := &recordingTransport{}
	h := apiAttachmentEndpoint(t, tr, &config.AttachmentsConfig{AllowedTypes: []string{"application/pdf"}})

	payload := fmt.Sprintf(`{"email":"a@b.com","message":"hi","attachments":[{"filename":"license.pdf","content_type":"application/x-lies","data":"%s"}]}`,
		base64.StdEncoding.EncodeToString(pdfBytes))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, apiRequest(payload, "valid-key"))
	if rec.Code != 200 {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
	atts := tr.sent[0].Attachments
	if len(atts) != 1 || atts[0].ContentType != "application/pdf" {
		t.Fatalf("attachments = %+v (declared type must be ignored; sniffed wins)", atts)
	}
}

func TestAPIAttachments_NotOptedIn_422(t *testing.T) {
	tr := &recordingTransport{}
	h, err := gateway.New(apiModeConfig("valid-key"), tr)
	if err != nil {
		t.Fatal(err)
	}
	payload := `{"email":"a@b.com","message":"hi","attachments":[{"filename":"x.pdf","data":"aGk="}]}`
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, apiRequest(payload, "valid-key"))
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422 (not silent drop — ADR-10)", rec.Code)
	}
	if len(tr.sent) != 0 {
		t.Fatal("sent despite rejection")
	}
}

func TestAPIAttachments_BadBase64_400(t *testing.T) {
	tr := &recordingTransport{}
	h := apiAttachmentEndpoint(t, tr, &config.AttachmentsConfig{AllowedTypes: []string{"application/pdf"}})
	payload := `{"email":"a@b.com","message":"hi","attachments":[{"filename":"x.pdf","data":"!!!not-base64!!!"}]}`
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, apiRequest(payload, "valid-key"))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

func TestAPIAttachments_NotATemplateField(t *testing.T) {
	// "attachments" is structural: it must not appear in the rendered
	// body's extras block or the Fields map.
	tr := &recordingTransport{}
	h := apiAttachmentEndpoint(t, tr, &config.AttachmentsConfig{AllowedTypes: []string{"application/pdf"}})
	payload := fmt.Sprintf(`{"email":"a@b.com","message":"hi","attachments":[{"filename":"l.pdf","data":"%s"}]}`,
		base64.StdEncoding.EncodeToString(pdfBytes))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, apiRequest(payload, "valid-key"))
	if rec.Code != 200 {
		t.Fatalf("status = %d", rec.Code)
	}
	if strings.Contains(tr.sent[0].BodyText, "attachments") {
		t.Errorf("attachments leaked into rendered body: %q", tr.sent[0].BodyText)
	}
	if _, present := tr.sent[0].Fields["attachments"]; present {
		t.Error("attachments leaked into Fields")
	}
}

func TestAttachments_ConfigValidation(t *testing.T) {
	base := `
[[endpoints]]
path = "/api/contact"
to = ["c@example.com"]
from = "n@example.com"
subject = "S"
body = "B"
[endpoints.transport]
type = "postmark"
[endpoints.transport.settings]
api_key = "k"
`
	cases := []struct {
		name    string
		extra   string
		wantErr string
	}{
		{"missing allowed_types", "[endpoints.attachments]\nmax_count = 3\n", "allowed_types"},
		{"bad pattern", "[endpoints.attachments]\nallowed_types = [\"pdf\"]\n", "type/subtype"},
		{"uppercase pattern", "[endpoints.attachments]\nallowed_types = [\"Image/PNG\"]\n", "lowercase"},
		{"valid", "[endpoints.attachments]\nallowed_types = [\"image/*\"]\n", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var cfg config.Config
			_, err := loadConfigString(t, base+tc.extra, &cfg)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("err = %v, want %q", err, tc.wantErr)
			}
		})
	}
}

// loadConfigString round-trips TOML through config.Load via a temp file.
func loadConfigString(t *testing.T, content string, _ *config.Config) (*config.Config, error) {
	t.Helper()
	path := t.TempDir() + "/config.toml"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return config.Load(path)
}

func TestAttachments_MaxBodySizeInterplay(t *testing.T) {
	// Explicit max_body_size smaller than the attachment budget is a
	// construction error (FR91).
	cfg := config.EndpointConfig{
		Path: "/test", To: []string{"t@example.com"}, From: "f@example.com",
		Subject: "S", Body: "B",
		MaxBodySize: "64KB",
		Attachments: &config.AttachmentsConfig{AllowedTypes: []string{"image/*"}, MaxTotalSize: "10MB"},
	}
	if _, err := gateway.New(cfg, &recordingTransport{}); err == nil {
		t.Fatal("expected construction error for max_body_size < max_total_size")
	}

	// Unset max_body_size defaults to budget + headroom: a payload
	// bigger than 1MB (the old default) must be accepted.
	cfg.MaxBodySize = ""
	cfg.Attachments.MaxTotalSize = "3MB"
	tr := &recordingTransport{}
	h, err := gateway.New(cfg, tr)
	if err != nil {
		t.Fatal(err)
	}
	big := append([]byte("\x89PNG\r\n\x1a\n"), bytes.Repeat([]byte{1}, 2<<20)...)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, multipartUpload(t, map[string]string{"message": "hi"}, map[string][]byte{"big.png": big}))
	if rec.Code != 200 {
		t.Fatalf("status = %d — 2MB upload should fit the raised default cap", rec.Code)
	}
}

func TestAttachments_DryRunDoesNotSend(t *testing.T) {
	tr := &recordingTransport{}
	cfg := config.EndpointConfig{
		Path: "/test", To: []string{"t@example.com"}, From: "f@example.com",
		Subject: "S", Body: "B", DryRun: true,
		Attachments: &config.AttachmentsConfig{AllowedTypes: []string{"image/*"}},
	}
	h, err := gateway.New(cfg, tr)
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, multipartUpload(t, map[string]string{"message": "hi"}, map[string][]byte{"p.png": pngBytes}))
	if rec.Code != 200 || len(tr.sent) != 0 {
		t.Fatalf("dry-run: status=%d sends=%d", rec.Code, len(tr.sent))
	}
	var resp map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp["status"] != "dry_run" {
		t.Errorf("status field = %v", resp["status"])
	}
}

package config_test

import (
	"strings"
	"testing"

	"github.com/craigmccaskill/posthorn/config"
)

// FR71/FR72 config surface: body_format enum + text_body pairing rule.

const htmlEndpointTOML = `
[[endpoints]]
path = "/api/contact"
to = ["craig@example.com"]
from = "noreply@example.com"
subject = "Contact"
body = "<p>Hello {{.name}}</p>"
body_format = "html"
text_body = "Hello {{.name}}"

[endpoints.transport]
type = "postmark"

[endpoints.transport.settings]
api_key = "test-key"
`

func TestLoad_HTMLBodyFormat(t *testing.T) {
	cfg, err := loadString(t, htmlEndpointTOML)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	ep := cfg.Endpoints[0]
	if ep.BodyFormat != config.BodyFormatHTML {
		t.Errorf("BodyFormat = %q, want %q", ep.BodyFormat, config.BodyFormatHTML)
	}
	if ep.TextBody != "Hello {{.name}}" {
		t.Errorf("TextBody = %q", ep.TextBody)
	}
}

func TestLoad_BodyFormatDefaultsToText(t *testing.T) {
	cfg, err := loadString(t, minimalTOML)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got := cfg.Endpoints[0].BodyFormat; got != "" {
		t.Errorf("BodyFormat = %q, want empty (defaults to text)", got)
	}
}

func TestLoad_BodyFormatExplicitText(t *testing.T) {
	toml := strings.Replace(minimalTOML, `body = "Body"`, "body = \"Body\"\nbody_format = \"text\"", 1)
	if _, err := loadString(t, toml); err != nil {
		t.Fatalf("Load: %v", err)
	}
}

func TestLoad_BodyFormatInvalid(t *testing.T) {
	toml := strings.Replace(minimalTOML, `body = "Body"`, "body = \"Body\"\nbody_format = \"markdown\"", 1)
	_, err := loadString(t, toml)
	if err == nil {
		t.Fatal("expected error for body_format = markdown")
	}
	if !strings.Contains(err.Error(), "body_format") {
		t.Errorf("error should name body_format: %v", err)
	}
}

func TestLoad_TextBodyWithoutHTMLFormat(t *testing.T) {
	toml := strings.Replace(minimalTOML, `body = "Body"`, "body = \"Body\"\ntext_body = \"fallback\"", 1)
	_, err := loadString(t, toml)
	if err == nil {
		t.Fatal("expected error for text_body on a text endpoint")
	}
	if !strings.Contains(err.Error(), "text_body") {
		t.Errorf("error should name text_body: %v", err)
	}
}

func TestLoad_TextBodyWithExplicitTextFormat(t *testing.T) {
	toml := strings.Replace(minimalTOML, `body = "Body"`,
		"body = \"Body\"\nbody_format = \"text\"\ntext_body = \"fallback\"", 1)
	if _, err := loadString(t, toml); err == nil {
		t.Fatal("expected error for text_body with body_format = text")
	}
}

package template

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ADR-19: submitter values are contextually escaped by construction;
// the template author's own markup renders as HTML.

func TestHTMLRenderer_AutoEscapesSubmitterValues(t *testing.T) {
	r, err := NewHTMLRenderer("Subject", "<h1>From {{.name}}</h1><p>{{.message}}</p>", "", nil)
	if err != nil {
		t.Fatalf("NewHTMLRenderer: %v", err)
	}
	form := map[string][]string{
		"name":    {`<script>alert(1)</script>`},
		"message": {`<img src=x onerror=steal()>`},
	}
	html, _, err := r.RenderBodyHTML(form)
	if err != nil {
		t.Fatalf("RenderBodyHTML: %v", err)
	}
	if strings.Contains(html, "<script>") || strings.Contains(html, "<img") {
		t.Errorf("submitter markup rendered live:\n%s", html)
	}
	if !strings.Contains(html, "&lt;script&gt;") {
		t.Errorf("submitter markup not escaped:\n%s", html)
	}
	// The author's own markup must render as HTML.
	if !strings.Contains(html, "<h1>From ") {
		t.Errorf("author markup was escaped:\n%s", html)
	}
}

func TestHTMLRenderer_AttributeContextEscaped(t *testing.T) {
	r, err := NewHTMLRenderer("S", `<a href="https://example.com/?q={{.q}}">link</a>`, "", nil)
	if err != nil {
		t.Fatalf("NewHTMLRenderer: %v", err)
	}
	html, _, err := r.RenderBodyHTML(map[string][]string{
		"q": {`" onmouseover="evil()`},
	})
	if err != nil {
		t.Fatalf("RenderBodyHTML: %v", err)
	}
	if strings.Contains(html, `onmouseover="evil()`) {
		t.Errorf("attribute breakout:\n%s", html)
	}
}

func TestHTMLRenderer_AutoDerivedTextPart(t *testing.T) {
	r, err := NewHTMLRenderer("S", "<h1>Hello {{.name}}</h1><p>Welcome aboard.</p>", "", nil)
	if err != nil {
		t.Fatalf("NewHTMLRenderer: %v", err)
	}
	_, text, err := r.RenderBodyHTML(map[string][]string{"name": {"Jane"}})
	if err != nil {
		t.Fatalf("RenderBodyHTML: %v", err)
	}
	want := "Hello Jane\n\nWelcome aboard."
	if text != want {
		t.Errorf("derived text = %q, want %q", text, want)
	}
}

func TestHTMLRenderer_DerivedTextUnescapesEntities(t *testing.T) {
	// The HTML part correctly escapes "&" to "&amp;"; the derived text
	// part must decode it back so text-only readers see the real value.
	r, err := NewHTMLRenderer("S", "<p>{{.co}}</p>", "", nil)
	if err != nil {
		t.Fatalf("NewHTMLRenderer: %v", err)
	}
	html, text, err := r.RenderBodyHTML(map[string][]string{"co": {"Fish & Chips Ltd"}})
	if err != nil {
		t.Fatalf("RenderBodyHTML: %v", err)
	}
	if !strings.Contains(html, "Fish &amp; Chips Ltd") {
		t.Errorf("html part should escape the ampersand: %q", html)
	}
	if text != "Fish & Chips Ltd" {
		t.Errorf("text part should decode it back: %q", text)
	}
}

func TestHTMLRenderer_ExplicitTextBodyWins(t *testing.T) {
	r, err := NewHTMLRenderer("S", "<p>HTML for {{.name}}</p>", "Plain greeting for {{.name}}", nil)
	if err != nil {
		t.Fatalf("NewHTMLRenderer: %v", err)
	}
	html, text, err := r.RenderBodyHTML(map[string][]string{"name": {"Jane"}})
	if err != nil {
		t.Fatalf("RenderBodyHTML: %v", err)
	}
	if !strings.Contains(html, "HTML for Jane") {
		t.Errorf("html = %q", html)
	}
	if text != "Plain greeting for Jane" {
		t.Errorf("text = %q, want explicit template output", text)
	}
}

func TestHTMLRenderer_ExtrasBlockInBothParts(t *testing.T) {
	r, err := NewHTMLRenderer("S", "<p>{{.message}}</p>", "", []string{"email"})
	if err != nil {
		t.Fatalf("NewHTMLRenderer: %v", err)
	}
	form := map[string][]string{
		"message": {"hi"},
		"email":   {"a@b.com"},        // reserved — excluded
		"company": {"<b>Evil&Co</b>"}, // unnamed — appears, escaped in HTML
	}
	html, text, err := r.RenderBodyHTML(form)
	if err != nil {
		t.Fatalf("RenderBodyHTML: %v", err)
	}
	if !strings.Contains(html, "<p>Additional fields:</p>") {
		t.Errorf("html missing extras block:\n%s", html)
	}
	if !strings.Contains(html, "&lt;b&gt;Evil&amp;Co&lt;/b&gt;") {
		t.Errorf("extras value not escaped in html:\n%s", html)
	}
	if strings.Contains(html, "<b>Evil") {
		t.Errorf("raw extras markup leaked into html:\n%s", html)
	}
	if strings.Contains(html, "a@b.com") {
		t.Errorf("reserved field leaked into extras:\n%s", html)
	}
	// Derived text comes from the final HTML, so it carries the block too,
	// with entities decoded back to literal text.
	if !strings.Contains(text, "Additional fields:") {
		t.Errorf("text missing extras block:\n%s", text)
	}
	if !strings.Contains(text, "company: <b>Evil&Co</b>") {
		t.Errorf("text extras should decode to the literal value:\n%s", text)
	}
}

func TestHTMLRenderer_ExplicitTextBodyGetsPlainExtrasBlock(t *testing.T) {
	r, err := NewHTMLRenderer("S", "<p>{{.message}}</p>", "{{.message}}", nil)
	if err != nil {
		t.Fatalf("NewHTMLRenderer: %v", err)
	}
	_, text, err := r.RenderBodyHTML(map[string][]string{
		"message": {"hi"},
		"extra":   {"val"},
	})
	if err != nil {
		t.Fatalf("RenderBodyHTML: %v", err)
	}
	if !strings.Contains(text, "\nAdditional fields:\n  extra: val\n") {
		t.Errorf("plain extras block missing from explicit text part:\n%q", text)
	}
}

func TestHTMLRenderer_FieldsInTextBodyExcludedFromExtras(t *testing.T) {
	r, err := NewHTMLRenderer("S", "<p>{{.message}}</p>", "{{.message}} from {{.city}}", nil)
	if err != nil {
		t.Fatalf("NewHTMLRenderer: %v", err)
	}
	html, _, err := r.RenderBodyHTML(map[string][]string{
		"message": {"hi"},
		"city":    {"Oslo"}, // referenced by text_body — not an extra
	})
	if err != nil {
		t.Fatalf("RenderBodyHTML: %v", err)
	}
	if strings.Contains(html, "Additional fields") {
		t.Errorf("city should be a named field, not an extra:\n%s", html)
	}
}

func TestHTMLRenderer_FileBasedTemplates(t *testing.T) {
	dir := t.TempDir()
	htmlPath := filepath.Join(dir, "welcome.html")
	if err := os.WriteFile(htmlPath, []byte("<h1>Hi {{.name}}</h1>"), 0o644); err != nil {
		t.Fatal(err)
	}
	textPath := filepath.Join(dir, "welcome.txt")
	if err := os.WriteFile(textPath, []byte("Hi {{.name}}"), 0o644); err != nil {
		t.Fatal(err)
	}
	r, err := NewHTMLRenderer("S", htmlPath, textPath, nil)
	if err != nil {
		t.Fatalf("NewHTMLRenderer: %v", err)
	}
	html, text, err := r.RenderBodyHTML(map[string][]string{"name": {"Jane"}})
	if err != nil {
		t.Fatalf("RenderBodyHTML: %v", err)
	}
	if !strings.Contains(html, "<h1>Hi Jane</h1>") {
		t.Errorf("html = %q", html)
	}
	if text != "Hi Jane" {
		t.Errorf("text = %q", text)
	}
}

func TestHTMLRenderer_StaticInlineHTMLIsNotAFilePath(t *testing.T) {
	// Static HTML with no template vars contains "/" in closing tags;
	// the inline-vs-file heuristic must recognize markup as inline
	// rather than erroring "path does not exist".
	r, err := NewHTMLRenderer("S", "<p>Thanks! We got it.</p>", "", nil)
	if err != nil {
		t.Fatalf("NewHTMLRenderer: %v", err)
	}
	html, _, err := r.RenderBodyHTML(map[string][]string{})
	if err != nil {
		t.Fatalf("RenderBodyHTML: %v", err)
	}
	if !strings.Contains(html, "<p>Thanks! We got it.</p>") {
		t.Errorf("html = %q", html)
	}
}

func TestHTMLRenderer_ParseErrorSurfaces(t *testing.T) {
	if _, err := NewHTMLRenderer("S", "<p>{{.x</p>", "", nil); err == nil {
		t.Fatal("expected parse error")
	}
}

func TestHTMLRenderer_EscapeAnalysisErrorSurfacesAtConstruction(t *testing.T) {
	// A template ending mid-attribute is structurally unescapable;
	// html/template only reports it at first Execute. NewHTMLRenderer
	// must force that so it fails at config load, not on the first
	// live submission.
	if _, err := NewHTMLRenderer("S", `<a href="{{.x}}`, "", nil); err == nil {
		t.Fatal("expected escape-analysis error at construction")
	}
}

func TestHTMLRenderer_SubjectStaysText(t *testing.T) {
	r, err := NewHTMLRenderer("Hello {{.name}}", "<p>x</p>", "", nil)
	if err != nil {
		t.Fatalf("NewHTMLRenderer: %v", err)
	}
	subj, err := r.RenderSubject(map[string][]string{"name": {"<Jane>"}})
	if err != nil {
		t.Fatalf("RenderSubject: %v", err)
	}
	// Subjects are headers, not markup: no HTML entities.
	if subj != "Hello <Jane>" {
		t.Errorf("subject = %q, want raw text", subj)
	}
}

func TestHTMLRenderer_HTMLReportsMode(t *testing.T) {
	hr, err := NewHTMLRenderer("S", "<p>x</p>", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	if !hr.HTML() {
		t.Error("HTML() = false for HTML renderer")
	}
	tr, err := NewRenderer("S", "text body", nil)
	if err != nil {
		t.Fatal(err)
	}
	if tr.HTML() {
		t.Error("HTML() = true for text renderer")
	}
}

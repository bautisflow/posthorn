package template

import (
	"html"
	"strings"
)

// HTMLToText converts rendered HTML into a plain-text approximation for
// the multipart text/plain fallback part (FR72). It is deliberately a
// bespoke ~150-line scanner, not an HTML-parser dependency (ADR-19):
// the fallback part's fidelity requirement is "readable in a text-only
// client," not "faithful layout."
//
// Behavior:
//   - tags are stripped; block-level tags (p, div, h1-h6, li, tr, ...)
//     become line breaks; <br> becomes a line break
//   - <li> content is prefixed with "- "
//   - <a href="...">text</a> becomes "text (href)" for http/https/mailto
//     hrefs; the suffix is omitted when the link text already is the href
//   - <style> and <script> element content is dropped entirely
//   - comments are dropped; entities are decoded; whitespace is
//     normalized (single spaces within lines, at most one blank line)
//
// Exported because the SMTP listener reuses it to derive a text part for
// HTML-only inbound mail (FR75).
func HTMLToText(src string) string {
	var out strings.Builder
	var anchor strings.Builder
	inAnchor := false
	anchorHref := ""
	skipUntil := "" // non-empty while inside <style>/<script>

	emit := func(s string) {
		if inAnchor {
			anchor.WriteString(s)
		} else {
			out.WriteString(s)
		}
	}

	closeAnchor := func() {
		text := anchor.String()
		out.WriteString(text)
		href := anchorHref
		if href != "" && strings.TrimSpace(html.UnescapeString(text)) != html.UnescapeString(href) {
			out.WriteString(" (" + href + ")")
		}
		anchor.Reset()
		anchorHref = ""
		inAnchor = false
	}

	i, n := 0, len(src)
	for i < n {
		c := src[i]
		if c != '<' {
			if skipUntil == "" {
				emit(string(c))
			}
			i++
			continue
		}
		if strings.HasPrefix(src[i:], "<!--") {
			if end := strings.Index(src[i+4:], "-->"); end >= 0 {
				i += 4 + end + 3
			} else {
				i = n
			}
			continue
		}
		name, attrs, closing, next := parseTag(src, i)
		if next < 0 {
			// Lone '<' with no closing '>': treat as literal text.
			if skipUntil == "" {
				emit("<")
			}
			i++
			continue
		}
		i = next
		if skipUntil != "" {
			if closing && name == skipUntil {
				skipUntil = ""
			}
			continue
		}
		switch {
		case name == "style" || name == "script":
			if !closing {
				skipUntil = name
			}
		case name == "br":
			emit("\n")
		case name == "a":
			if closing {
				if inAnchor {
					closeAnchor()
				}
			} else {
				if inAnchor {
					closeAnchor() // unclosed previous anchor; flush
				}
				href := attrValue(attrs, "href")
				if strings.HasPrefix(href, "http://") || strings.HasPrefix(href, "https://") || strings.HasPrefix(href, "mailto:") {
					anchorHref = href
				}
				inAnchor = true
			}
		case name == "li":
			// Open supplies both the break and the bullet; close adds
			// nothing so consecutive items stay on adjacent lines.
			if !closing {
				emit("\n- ")
			}
		case blockTags[name]:
			emit("\n")
		}
	}
	if inAnchor {
		closeAnchor()
	}
	return normalizeWhitespace(html.UnescapeString(out.String()))
}

var blockTags = map[string]bool{
	"p": true, "div": true, "section": true, "article": true,
	"header": true, "footer": true, "main": true, "aside": true,
	"h1": true, "h2": true, "h3": true, "h4": true, "h5": true, "h6": true,
	"ul": true, "ol": true, "li": true, "table": true, "tr": true,
	"blockquote": true, "pre": true, "hr": true, "figure": true,
	"figcaption": true, "form": true, "fieldset": true, "address": true,
}

// parseTag reads a tag starting at src[i] == '<'. Returns the lowercased
// tag name, the raw attribute substring, whether it is a closing tag, and
// the index just past the '>' — or next == -1 when no '>' terminates the
// tag. The scan respects single- and double-quoted attribute values so a
// '>' inside a quoted href does not end the tag.
func parseTag(src string, i int) (name, attrs string, closing bool, next int) {
	j := i + 1
	n := len(src)
	if j < n && src[j] == '/' {
		closing = true
		j++
	}
	// HTML5 tokenizer rule: a tag open requires an ASCII letter (or '!'
	// for doctype/CDATA) after '<'; anything else means the '<' is
	// literal text, not markup. Without this, "1 < 2" would swallow
	// everything up to the next unrelated '>'.
	if j >= n || !isTagStart(src[j]) {
		return "", "", false, -1
	}
	nameStart := j
	for j < n && (isAlnum(src[j]) || src[j] == '!') {
		j++
	}
	name = strings.ToLower(src[nameStart:j])
	attrStart := j
	var quote byte
	for j < n {
		c := src[j]
		if quote != 0 {
			if c == quote {
				quote = 0
			}
		} else if c == '"' || c == '\'' {
			quote = c
		} else if c == '>' {
			return name, src[attrStart:j], closing, j + 1
		}
		j++
	}
	return "", "", false, -1
}

func isTagStart(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c == '!'
}

func isAlnum(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
}

// attrValue extracts a named attribute's value from a raw attribute
// substring, handling quoted and unquoted forms. Case-insensitive on the
// attribute name. Returns "" when absent.
func attrValue(attrs, name string) string {
	lower := strings.ToLower(attrs)
	idx := 0
	for {
		pos := strings.Index(lower[idx:], name)
		if pos < 0 {
			return ""
		}
		pos += idx
		// Must be a word boundary followed by '='.
		if pos > 0 && isAlnum(lower[pos-1]) {
			idx = pos + len(name)
			continue
		}
		rest := pos + len(name)
		for rest < len(attrs) && (attrs[rest] == ' ' || attrs[rest] == '\t' || attrs[rest] == '\n' || attrs[rest] == '\r') {
			rest++
		}
		if rest >= len(attrs) || attrs[rest] != '=' {
			idx = pos + len(name)
			continue
		}
		rest++
		for rest < len(attrs) && (attrs[rest] == ' ' || attrs[rest] == '\t' || attrs[rest] == '\n' || attrs[rest] == '\r') {
			rest++
		}
		if rest >= len(attrs) {
			return ""
		}
		if q := attrs[rest]; q == '"' || q == '\'' {
			end := strings.IndexByte(attrs[rest+1:], q)
			if end < 0 {
				return attrs[rest+1:]
			}
			return attrs[rest+1 : rest+1+end]
		}
		end := rest
		for end < len(attrs) && attrs[end] != ' ' && attrs[end] != '\t' {
			end++
		}
		return attrs[rest:end]
	}
}

// normalizeWhitespace produces clean fallback text: single spaces within
// lines, no trailing space, at most one blank line between paragraphs,
// no leading/trailing blank lines.
func normalizeWhitespace(s string) string {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	s = strings.ReplaceAll(s, "\r", "\n")
	lines := strings.Split(s, "\n")
	var b strings.Builder
	blankRun := 0
	wrote := false
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			blankRun++
			continue
		}
		if wrote {
			b.WriteByte('\n')
			if blankRun > 0 {
				b.WriteByte('\n')
			}
		}
		blankRun = 0
		b.WriteString(strings.Join(fields, " "))
		wrote = true
	}
	return b.String()
}

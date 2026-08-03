package template

import (
	"strings"
	"testing"
)

func TestHTMLToText(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "paragraphs become blank-line separated",
			in:   "<p>Hello</p><p>World</p>",
			want: "Hello\n\nWorld",
		},
		{
			name: "br becomes single newline",
			in:   "Hello<br>World",
			want: "Hello\nWorld",
		},
		{
			name: "self-closing br",
			in:   "Hello<br/>World",
			want: "Hello\nWorld",
		},
		{
			name: "entities decoded",
			in:   "<p>Fish &amp; chips &lt;3 &#39;quoted&#39;</p>",
			want: "Fish & chips <3 'quoted'",
		},
		{
			name: "escaped submitter content stays literal text",
			in:   "<p>&lt;script&gt;alert(1)&lt;/script&gt;</p>",
			want: "<script>alert(1)</script>",
		},
		{
			name: "anchor becomes text with href suffix",
			in:   `<p>See <a href="https://example.com/docs">the docs</a> now</p>`,
			want: "See the docs (https://example.com/docs) now",
		},
		{
			name: "anchor whose text is the href is not duplicated",
			in:   `<p><a href="https://example.com">https://example.com</a></p>`,
			want: "https://example.com",
		},
		{
			name: "mailto anchor kept",
			in:   `<a href="mailto:x@example.com">write me</a>`,
			want: "write me (mailto:x@example.com)",
		},
		{
			name: "javascript href dropped",
			in:   `<a href="javascript:evil()">click</a>`,
			want: "click",
		},
		{
			name: "style content dropped",
			in:   "<style>body { color: red }</style><p>Visible</p>",
			want: "Visible",
		},
		{
			name: "script content dropped",
			in:   "<script>var x = '<p>not text</p>'</script><p>Visible</p>",
			want: "Visible",
		},
		{
			name: "comments dropped",
			in:   "<p>a</p><!-- hidden --><p>b</p>",
			want: "a\n\nb",
		},
		{
			name: "list items get dash prefixes",
			in:   "<ul><li>one</li><li>two</li></ul>",
			want: "- one\n- two",
		},
		{
			name: "headings and divs break lines",
			in:   "<h1>Title</h1><div>Body text</div>",
			want: "Title\n\nBody text",
		},
		{
			name: "quoted gt inside attribute does not end tag",
			in:   `<a href="https://example.com/?a>b">link</a>`,
			want: "link (https://example.com/?a>b)",
		},
		{
			name: "indented template source collapses cleanly",
			in:   "<div>\n    <p>\n      Hello there\n    </p>\n</div>",
			want: "Hello there",
		},
		{
			name: "multiple blank lines collapse to one",
			in:   "<p>a</p><div></div><div></div><p>b</p>",
			want: "a\n\nb",
		},
		{
			name: "lone lt is literal",
			in:   "<p>1 < 2 always</p>",
			want: "1 < 2 always",
		},
		{
			name: "table rows break lines",
			in:   "<table><tr><td>r1</td></tr><tr><td>r2</td></tr></table>",
			want: "r1\n\nr2",
		},
		{
			name: "full branded template shape",
			in: `<html><head><style>.h{font-weight:bold}</style></head><body>
				<div class="h">New message from Jane</div>
				<p>Body line one.<br>Body line two.</p>
				<p><a href="https://example.com/reply">Reply</a></p>
				</body></html>`,
			want: "New message from Jane\n\nBody line one.\nBody line two.\n\nReply (https://example.com/reply)",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := HTMLToText(tc.in)
			if got != tc.want {
				t.Errorf("HTMLToText(%q)\n got: %q\nwant: %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestHTMLToTextNeverPanicsOnMalformed(t *testing.T) {
	inputs := []string{
		"",
		"<",
		"<p",
		"<a href=",
		`<a href="unterminated`,
		"<!-- unterminated comment",
		"<style>unterminated",
		"</closes-nothing>",
		strings.Repeat("<div>", 1000),
		"<p>text</p" + strings.Repeat("x", 10),
	}
	for _, in := range inputs {
		_ = HTMLToText(in) // must not panic
	}
}

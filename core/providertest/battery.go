package providertest

// InjectionValues returns submitter-controlled string payloads that a
// transport must render as inert data, never as email structure. Every
// transport's e2e test feeds these through a header-bound field (e.g. a
// templated Subject) and asserts no new header was smuggled — the
// NFR1/NFR2 header-injection invariant, verified end-to-end through the
// real ingress and the real transport rather than a hand-built Message.
func InjectionValues() []string {
	return []string{
		"plain subject",                   // control
		"line1\r\nBcc: attacker@evil.com", // classic Bcc smuggle
		"subject\nX-Injected: 1",          // bare-LF header
		"subject\r\n\r\nInjected body",    // header/body separator
		"a\rb\nc",                         // stray CR / LF
		"日本語 subject 🎌",                   // non-ASCII must survive encoding
	}
}

package smtp

// Real-client ingress e2e (issue #76 S3). The parse-unit tests assert
// NFR22 by calling parseMIMEToMessage directly; this drives the FULL
// listener with Go's stdlib net/smtp client — the same library
// self-hosted apps use — over a real TCP connection, confirming the
// envelope-only-recipients invariant survives real EHLO/MAIL/RCPT/DATA
// sequencing and DATA dot-stuffing, not just the parser in isolation.
// It's the "real client → real ingress → capturing egress" half that
// mirrors the outbound "real form → real gateway → real egress" e2e.

import (
	"net/smtp"
	"testing"
	"time"
)

func TestE2E_Listener_RealClient_EnvelopeOnlyRecipients(t *testing.T) {
	// auth "none" on loopback is the internal-relay shape and lets the
	// stdlib client send without STARTTLS/AUTH.
	cfg := baseTestConfig()
	cfg.AuthRequired = AuthNone
	cfg.RequireTLS = false
	cfg.SMTPUsers = nil
	cfg.AllowedSenders = []string{"*@example.com"}
	f := startListener(t, cfg)

	// The MIME headers try to smuggle extra recipients (To/Cc/Bcc) that
	// differ from the envelope RCPT. NFR22: only the envelope wins.
	body := "To: shown@example.com\r\n" +
		"Cc: cc-victim@evil.com\r\n" +
		"Bcc: bcc-victim@evil.com\r\n" +
		"Subject: Real client says hi\r\n" +
		"\r\n" +
		"Body line one.\r\n" +
		".dotstuffed line survives.\r\n"

	err := smtp.SendMail(
		f.addr,
		nil, // no auth
		"sender@example.com",
		[]string{"envelope@example.com"},
		[]byte(body),
	)
	if err != nil {
		t.Fatalf("smtp.SendMail: %v", err)
	}

	waitForSend(t, f.mt, 1, 2*time.Second)
	sent := f.mt.Sent()
	if len(sent) != 1 {
		t.Fatalf("delivered %d messages, want 1", len(sent))
	}
	got := sent[0]

	// NFR22: recipients come from the envelope, never the MIME headers.
	if len(got.To) != 1 || got.To[0] != "envelope@example.com" {
		t.Errorf("To = %v, want [envelope@example.com] — MIME To/Cc/Bcc must be ignored", got.To)
	}
	if got.From != "sender@example.com" {
		t.Errorf("From = %q, want sender@example.com", got.From)
	}
	if got.Subject != "Real client says hi" {
		t.Errorf("Subject = %q", got.Subject)
	}
}

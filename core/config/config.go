// Package config defines the Posthorn configuration schema and TOML loader.
//
// Configuration flows: TOML file → resolveEnvVars → toml.Unmarshal → Validate.
// The Config struct is the single source of truth for runtime behavior.
// Validation runs at load time (FR24) so operators get fast feedback
// rather than runtime surprises.
package config

import (
	"errors"
	"fmt"
	"net"
	"net/mail"
	"net/netip"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/craigmccaskill/posthorn/csrf"
	"github.com/craigmccaskill/posthorn/transport"
)

// Config is the top-level configuration object.
type Config struct {
	Endpoints    []EndpointConfig    `toml:"endpoints"`
	Logging      LoggingConfig       `toml:"logging"`
	SMTPListener *SMTPListenerConfig `toml:"smtp_listener"`
}

// SMTPListenerConfig is the top-level [smtp_listener] block (FR62).
// When non-nil after parse, cmd/posthorn starts an SMTP ingress
// alongside the HTTP one. Lives in this package to avoid a config →
// smtp circular dependency; the smtp package converts it to its
// internal ListenerConfig shape.
type SMTPListenerConfig struct {
	Listen string `toml:"listen"`

	// RequireTLS forces STARTTLS upgrade before AUTH / MAIL / RCPT.
	// A *bool (per ADR-4 precedent) so we can distinguish unset (default
	// true — TLS-required is the safe production posture documented in
	// marketing) from explicit `require_tls = false` (operator opted into
	// plaintext, only sensible for local development).
	RequireTLS *bool `toml:"require_tls"`

	TLSCert                 string          `toml:"tls_cert"`
	TLSKey                  string          `toml:"tls_key"`
	ClientCertCA            string          `toml:"client_cert_ca"`
	AuthRequired            string          `toml:"auth_required"`
	SMTPUsers               []SMTPUser      `toml:"smtp_users"`
	AllowedSenders          []string        `toml:"allowed_senders"`
	AllowedRecipients       []string        `toml:"allowed_recipients"`
	MaxRecipientsPerSession int             `toml:"max_recipients_per_session"`
	MaxMessageSize          string          `toml:"max_message_size"`
	IdleTimeout             Duration        `toml:"idle_timeout"`
	Transport               TransportConfig `toml:"transport"`

	// TrustedNetwork acknowledges that an auth_required = "none"
	// listener bound to a non-loopback/non-private address is reachable
	// only from a trusted network (Docker bridge with no port exposure,
	// VPN, firewall). Without it, that combination is a parse error —
	// an unauthenticated listener on a public bind is an open relay
	// gated only by the sender allowlist (#41).
	TrustedNetwork bool `toml:"trusted_network"`

	// MaxConnections caps concurrent SMTP connections across all
	// clients; MaxConnectionsPerIP caps them per remote IP (#50).
	// 0 = defaults (100 / 16). Excess connections get 421 and close.
	MaxConnections      int `toml:"max_connections"`
	MaxConnectionsPerIP int `toml:"max_connections_per_ip"`
}

// SMTPUser is a single AUTH PLAIN credential pair.
type SMTPUser struct {
	Username string `toml:"username"`
	Password string `toml:"password"`
}

// Auth mode values for EndpointConfig.Auth. Empty / unset is equivalent to
// AuthForm (FR45 — v1.0 configs unchanged).
const (
	AuthForm   = "form"
	AuthAPIKey = "api-key"
)

// EndpointConfig configures one ingress endpoint. Multiple endpoints in one
// Config are independent — no shared rate-limit budget, no cross-endpoint
// state (FR2).
//
// Two modes:
//   - Form mode (default; v1.0 behavior): browser POSTs form-encoded bodies,
//     defended by honeypot / Origin / rate limit / max-body-size.
//   - API-key mode (v1.1): server-to-server callers POST JSON bodies with
//     Authorization: Bearer <key>; browser defenses do not apply (FR31, FR32).
type EndpointConfig struct {
	Path                 string           `toml:"path"`
	To                   []string         `toml:"to"`
	From                 string           `toml:"from"`
	Transport            TransportConfig  `toml:"transport"`
	RateLimit            *RateLimitConfig `toml:"rate_limit"`
	TrustedProxies       []string         `toml:"trusted_proxies"`
	Honeypot             string           `toml:"honeypot"`
	AllowedOrigins       []string         `toml:"allowed_origins"`
	MaxBodySize          string           `toml:"max_body_size"` // e.g. "32KB"; parsed at handler-construction time
	Required             []string         `toml:"required"`
	EmailField           string           `toml:"email_field"`
	ReplyToEmailField    string           `toml:"reply_to_email_field"`
	Subject              string           `toml:"subject"`
	Body                 string           `toml:"body"`
	LogFailedSubmissions *bool            `toml:"log_failed_submissions"`
	RedirectSuccess      string           `toml:"redirect_success"`
	RedirectError        string           `toml:"redirect_error"`

	// v1.1: API mode. Auth selects the endpoint shape; empty defaults to
	// AuthForm preserving v1.0 behavior (FR31, FR45). APIKeys is the list
	// of valid Bearer tokens when Auth is AuthAPIKey (FR33). Multiple keys
	// support rotation. IdempotencyCacheSize sets the per-endpoint cache
	// capacity (FR42); zero or unset means use the package default.
	Auth                 string   `toml:"auth"`
	APIKeys              []string `toml:"api_keys"`
	IdempotencyCacheSize int      `toml:"idempotency_cache_size"`

	// v1.0 block C: dry-run mode (FR56). When true, the handler runs the
	// full pipeline up to but not including transport.Send and returns
	// 200 with a JSON body containing the prepared transport.Message.
	// Operators use this to debug template rendering and recipient
	// resolution without sending mail.
	DryRun bool `toml:"dry_run"`

	// v1.0 block C: GDPR-shaped IP-stripping option (FR59). When true,
	// the resolved client IP is omitted from all log lines for this
	// endpoint. Rate-limit keying is unaffected — IP is still computed
	// internally; it just doesn't reach the log surface.
	StripClientIP bool `toml:"strip_client_ip"`

	// v1.0 block C: CSRF (FR57, ADR-16). When CSRFSecret is non-empty,
	// the handler requires a `_csrf_token` form field on every form-mode
	// submission and verifies its HMAC-SHA256 signature against
	// CSRFSecret. Tokens older than CSRFTokenTTL (default 1h) are
	// rejected with 403. Form-mode only — api-mode endpoints reject
	// csrf_secret at parse time.
	CSRFSecret   string   `toml:"csrf_secret"`
	CSRFTokenTTL Duration `toml:"csrf_token_ttl"`

	// Reputation: optional StopForumSpam lookup on the submitter email/IP
	// (form-mode only). Content-agnostic — targets repeat form-spam
	// identities. See ReputationConfig.
	Reputation *ReputationConfig `toml:"reputation"`

	// ProofOfBrowser: optional JS-gated submit token (form-mode only,
	// #45/ADR-18). Blocks bots that POST directly without executing the
	// page JavaScript that fetches the token. See ProofOfBrowserConfig.
	ProofOfBrowser *ProofOfBrowserConfig `toml:"proof_of_browser"`

	// Captcha: optional Cloudflare Turnstile verification (form-mode only,
	// #33). The escalation tier — stops bots that render JS. See
	// CaptchaConfig.
	Captcha *CaptchaConfig `toml:"captcha"`
}

// CaptchaConfig configures the optional captcha check
// (`[endpoints.captcha]`). Form-mode only.
type CaptchaConfig struct {
	// Provider is the captcha service. Only "turnstile" in this release.
	Provider string `toml:"provider"`

	// SecretKey is the provider secret used for server-side verification.
	// Never sent to the client.
	SecretKey string `toml:"secret_key"`

	// OnProviderError selects behavior when the provider can't be reached:
	// "closed" (default) rejects the submission; "open" allows it. A
	// captcha that fails open is weak, so closed is the default; fail-open
	// events increment posthorn_check_failed_open_total{check="captcha"}.
	OnProviderError string `toml:"on_provider_error"`

	// Timeout per verification. Default 3s.
	Timeout Duration `toml:"timeout"`

	// BaseURL overrides the siteverify endpoint (testing / self-hosted).
	BaseURL string `toml:"base_url"`
}

// ProofOfBrowserConfig configures the proof-of-browser check
// (`[endpoints.proof_of_browser]`). Its presence enables the check.
// Posthorn serves a challenge token from a GET on the endpoint; the
// operator embeds a small script that fetches it and injects it as the
// `_pob_token` field before submit. Form-mode only (ADR-18).
type ProofOfBrowserConfig struct {
	// Secret is the HMAC key for the challenge token. Optional: when
	// empty, Posthorn generates a random one at startup (fine for a
	// single replica). Set it explicitly for multi-replica deployments so
	// every replica verifies the same tokens; ≥16 bytes when set.
	Secret string `toml:"secret"`

	// TTL is the token lifetime. Default 30m.
	TTL Duration `toml:"ttl"`

	// MinAge, when set, rejects a token submitted sooner than this after
	// it was issued — a time-trap for bots that fetch-then-submit
	// instantly. Must be less than the effective TTL.
	MinAge Duration `toml:"min_age"`
}

// ReputationConfig configures the optional reputation check
// (`[endpoints.reputation]`). Form-mode only.
type ReputationConfig struct {
	// Provider is the reputation source. Only "stopforumspam" in v1.
	Provider string `toml:"provider"`

	// BaseURL overrides the provider endpoint. Empty uses StopForumSpam's
	// public API; set it to a compatible mirror or a privacy proxy.
	BaseURL string `toml:"base_url"`

	// Check lists which fields to look up: "email", "ip", or both.
	// Non-empty; unknown entries are a parse error.
	Check []string `toml:"check"`

	// Confidence is the block threshold (0–100). A looked-up field that
	// appears in the database with confidence ≥ this blocks the
	// submission. Default 90.
	Confidence float64 `toml:"confidence"`

	// FailOpen: on provider error/timeout, allow (true, default) or block
	// (false). Fail-open keeps a provider outage from blocking real mail.
	FailOpen *bool `toml:"fail_open"`

	// Timeout per lookup. Default 2s.
	Timeout Duration `toml:"timeout"`

	// CacheSize / CacheTTL bound the in-memory result cache. Defaults
	// 10000 / 1h.
	CacheSize int      `toml:"cache_size"`
	CacheTTL  Duration `toml:"cache_ttl"`
}

// validate checks the reputation block. Called only for form-mode
// endpoints (api-mode rejects the whole block above).
func (r *ReputationConfig) validate() error {
	if r.Provider != "stopforumspam" {
		return fmt.Errorf("provider: only \"stopforumspam\" is supported, got %q", r.Provider)
	}
	if len(r.Check) == 0 {
		return errors.New("check: list at least one of \"email\", \"ip\"")
	}
	for _, c := range r.Check {
		if c != "email" && c != "ip" {
			return fmt.Errorf("check: unknown value %q (want \"email\" or \"ip\")", c)
		}
	}
	if r.Confidence < 0 || r.Confidence > 100 {
		return fmt.Errorf("confidence: must be 0–100, got %v", r.Confidence)
	}
	if r.Timeout.Std() < 0 {
		return fmt.Errorf("timeout: must be non-negative, got %v", r.Timeout.Std())
	}
	if r.CacheSize < 0 {
		return fmt.Errorf("cache_size: must be non-negative, got %d", r.CacheSize)
	}
	if r.CacheTTL.Std() < 0 {
		return fmt.Errorf("cache_ttl: must be non-negative, got %v", r.CacheTTL.Std())
	}
	return nil
}

// validate checks the proof_of_browser block. Called only for form-mode
// endpoints (api-mode rejects the whole block above).
func (p *ProofOfBrowserConfig) validate() error {
	if p.Secret != "" {
		if err := csrf.ValidateSecret([]byte(p.Secret)); err != nil {
			return err
		}
	}
	if p.TTL.Std() < 0 {
		return fmt.Errorf("ttl: must be non-negative, got %v", p.TTL.Std())
	}
	if p.MinAge.Std() < 0 {
		return fmt.Errorf("min_age: must be non-negative, got %v", p.MinAge.Std())
	}
	// Resolve the effective TTL for the min_age < ttl check (default 30m).
	ttl := p.TTL.Std()
	if ttl == 0 {
		ttl = 30 * time.Minute
	}
	if p.MinAge.Std() >= ttl {
		return fmt.Errorf("min_age (%v) must be less than ttl (%v)", p.MinAge.Std(), ttl)
	}
	return nil
}

// validate checks the captcha block. Called only for form-mode endpoints.
func (c *CaptchaConfig) validate() error {
	if c.Provider != "turnstile" {
		return fmt.Errorf("provider: only \"turnstile\" is supported, got %q", c.Provider)
	}
	if c.SecretKey == "" {
		return errors.New("secret_key: required")
	}
	switch c.OnProviderError {
	case "", "closed", "open":
		// ok; empty means closed
	default:
		return fmt.Errorf("on_provider_error: must be \"closed\" or \"open\", got %q", c.OnProviderError)
	}
	if c.Timeout.Std() < 0 {
		return fmt.Errorf("timeout: must be non-negative, got %v", c.Timeout.Std())
	}
	return nil
}

// TransportConfig is the polymorphic transport block. Type names a concrete
// transport; Settings is transport-specific. v1.0 supports only "postmark".
// New transports in v1.1+ (resend, mailgun, ses, smtp) extend the Type
// switch in Validate without breaking config compatibility.
type TransportConfig struct {
	Type     string         `toml:"type"`
	Settings map[string]any `toml:"settings"`
}

// RateLimitConfig is the per-endpoint token-bucket configuration.
type RateLimitConfig struct {
	Count    int      `toml:"count"`
	Interval Duration `toml:"interval"`
}

// LoggingConfig is the global logging configuration.
type LoggingConfig struct {
	Level  string `toml:"level"`  // debug | info | warn | error (default info)
	Format string `toml:"format"` // json (only json supported in v1.0)
}

// Duration wraps time.Duration with TOML support. BurntSushi/toml does not
// natively unmarshal time.Duration, so we provide a TextUnmarshaler.
type Duration time.Duration

// UnmarshalText parses a duration string like "1m", "30s", "1h30m".
func (d *Duration) UnmarshalText(text []byte) error {
	parsed, err := time.ParseDuration(string(text))
	if err != nil {
		return err
	}
	*d = Duration(parsed)
	return nil
}

// Std returns the underlying time.Duration.
func (d Duration) Std() time.Duration { return time.Duration(d) }

// Load reads a TOML config file from path, resolves ${env.VAR} placeholders,
// parses the TOML, and runs validation. Returns the validated Config or an
// error describing the first problem encountered.
func Load(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}

	resolved, err := resolveEnvVars(raw)
	if err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}

	var cfg Config
	md, err := toml.Decode(string(resolved), &cfg)
	if err != nil {
		return nil, fmt.Errorf("config: parse TOML: %w", err)
	}

	// Reject unknown top-level keys and unknown struct fields. Silent
	// acceptance of typos (e.g., writing `starttls = true` when the
	// real field is `require_tls`) is a high-cost foot-gun: the parse
	// succeeds, the runtime behavior doesn't match the intent, and the
	// operator only finds out when something downstream fails to work.
	if undecoded := md.Undecoded(); len(undecoded) > 0 {
		keys := make([]string, 0, len(undecoded))
		for _, k := range undecoded {
			keys = append(keys, k.String())
		}
		return nil, fmt.Errorf("config: unknown field(s) — likely a typo or stale config: %s", strings.Join(keys, ", "))
	}

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}

	return &cfg, nil
}

// envVarPattern matches ${env.VARNAME} placeholders. Variable names must
// be UPPER_SNAKE_CASE per POSIX env-var conventions; this also reduces
// false matches in body templates and other user-controlled strings.
var envVarPattern = regexp.MustCompile(`\$\{env\.([A-Z_][A-Z0-9_]*)\}`)

// resolveEnvVars replaces ${env.VAR} placeholders with os.Getenv values.
// Reports all missing variables in a single error so operators don't play
// whack-a-mole on first run.
func resolveEnvVars(raw []byte) ([]byte, error) {
	var missing []string
	seen := map[string]bool{}
	out := envVarPattern.ReplaceAllFunc(raw, func(match []byte) []byte {
		sub := envVarPattern.FindSubmatch(match)
		name := string(sub[1])
		val, ok := os.LookupEnv(name)
		if !ok {
			if !seen[name] {
				missing = append(missing, name)
				seen[name] = true
			}
			return match // leave as-is; caller will surface the error
		}
		return []byte(val)
	})
	if len(missing) > 0 {
		return nil, fmt.Errorf("env var(s) not set: %s", strings.Join(missing, ", "))
	}
	return out, nil
}

// Validate checks structural and semantic constraints on a parsed Config.
// Returns the first error; runs cheap checks before expensive ones.
func (c *Config) Validate() error {
	// An SMTP-listener-only deployment is a first-class shape (the
	// Ghost/Gitea recipes run exactly this); the HTTP mux still serves
	// /healthz and /metrics with zero endpoints. Require at least one
	// ingress of either kind.
	if len(c.Endpoints) == 0 && c.SMTPListener == nil {
		return errors.New("at least one ingress required: define [[endpoints]] or [smtp_listener]")
	}

	seenPaths := map[string]bool{}
	for i, ep := range c.Endpoints {
		if err := ep.Validate(); err != nil {
			return fmt.Errorf("endpoints[%d] (%s): %w", i, ep.Path, err)
		}
		if seenPaths[ep.Path] {
			return fmt.Errorf("duplicate endpoint path: %s", ep.Path)
		}
		seenPaths[ep.Path] = true
	}

	if c.Logging.Format != "" && c.Logging.Format != "json" {
		return fmt.Errorf("logging.format: only \"json\" supported in v1.0, got %q", c.Logging.Format)
	}
	switch c.Logging.Level {
	case "", "debug", "info", "warn", "error":
		// ok
	default:
		return fmt.Errorf("logging.level: must be one of debug|info|warn|error, got %q", c.Logging.Level)
	}

	if c.SMTPListener != nil {
		if err := c.SMTPListener.Validate(); err != nil {
			return fmt.Errorf("smtp_listener: %w", err)
		}
	}

	return nil
}

// Validate runs structural checks on the SMTP listener block. The
// detailed semantic checks (auth/cert combinations) live in the smtp
// package's own Validate; here we just confirm required fields are
// present and the transport block is well-formed.
func (s *SMTPListenerConfig) Validate() error {
	if s.Listen == "" {
		return errors.New("listen is required (e.g., \":2525\")")
	}
	if len(s.AllowedSenders) == 0 {
		return errors.New("allowed_senders: at least one entry required")
	}
	if err := s.Transport.Validate(); err != nil {
		return fmt.Errorf("transport: %w", err)
	}
	if s.MaxRecipientsPerSession < 0 {
		return fmt.Errorf("max_recipients_per_session: must be non-negative, got %d", s.MaxRecipientsPerSession)
	}
	if s.IdleTimeout.Std() < 0 {
		return fmt.Errorf("idle_timeout: must be non-negative, got %v", s.IdleTimeout.Std())
	}
	if s.MaxConnections < 0 {
		return fmt.Errorf("max_connections: must be non-negative, got %d", s.MaxConnections)
	}
	if s.MaxConnectionsPerIP < 0 {
		return fmt.Errorf("max_connections_per_ip: must be non-negative, got %d", s.MaxConnectionsPerIP)
	}
	// #41: with auth_required = "none" the sender allowlist is the only
	// gate, so refuse a bind address we can't verify as private unless
	// the operator explicitly asserts the network is trusted. Fail-closed
	// at parse time per the ADR-10 footgun philosophy: better a startup
	// error with a fix in it than a silently open relay.
	if s.AuthRequired == "none" && !s.TrustedNetwork {
		if err := validatePrivateBind(s.Listen); err != nil {
			return fmt.Errorf("auth_required = \"none\": %w — bind to a loopback/private address, require auth, or set trusted_network = true if the listener is reachable only from a trusted network (Docker bridge with no port exposure, VPN, firewall)", err)
		}
	}
	return nil
}

// validatePrivateBind returns an error when the listen address is not
// verifiably private: empty host / unspecified IP (binds all
// interfaces), a public IP, or a hostname we can't classify. Loopback,
// RFC1918/ULA-private, and link-local addresses pass, as does the
// literal "localhost".
func validatePrivateBind(listen string) error {
	host, _, err := net.SplitHostPort(listen)
	if err != nil {
		return fmt.Errorf("listen %q: %v", listen, err)
	}
	if host == "" {
		return fmt.Errorf("listen %q binds all interfaces", listen)
	}
	if strings.EqualFold(host, "localhost") {
		return nil
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		// A hostname we can't classify without resolving — fail closed.
		return fmt.Errorf("listen host %q is not an IP address; cannot verify it is private", host)
	}
	if ip.IsUnspecified() {
		return fmt.Errorf("listen %q binds all interfaces", listen)
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() {
		return nil
	}
	return fmt.Errorf("listen address %q is public", host)
}

// EffectiveRequireTLS resolves the *bool RequireTLS to a concrete value.
// Unset (nil) defaults to true — STARTTLS-required is the documented
// production default; operators opt out by explicitly setting
// `require_tls = false` for local development.
func (s *SMTPListenerConfig) EffectiveRequireTLS() bool {
	if s.RequireTLS == nil {
		return true
	}
	return *s.RequireTLS
}

// Validate checks one endpoint's configuration.
func (e *EndpointConfig) Validate() error {
	if e.Path == "" {
		return errors.New("path is required")
	}
	if !strings.HasPrefix(e.Path, "/") {
		return fmt.Errorf("path must start with /: %q", e.Path)
	}

	if len(e.To) == 0 {
		return errors.New("to is required (one or more recipient addresses)")
	}
	for _, addr := range e.To {
		if _, err := mail.ParseAddress(addr); err != nil {
			return fmt.Errorf("to: invalid email %q: %w", addr, err)
		}
	}

	if e.From == "" {
		return errors.New("from is required")
	}
	if _, err := mail.ParseAddress(e.From); err != nil {
		return fmt.Errorf("from: invalid email %q: %w", e.From, err)
	}

	if e.Subject == "" {
		return errors.New("subject is required")
	}
	if e.Body == "" {
		return errors.New("body is required")
	}

	if err := e.Transport.Validate(); err != nil {
		return fmt.Errorf("transport: %w", err)
	}

	// FR31: resolve effective auth mode. Empty / unset defaults to form.
	auth := e.Auth
	if auth == "" {
		auth = AuthForm
	}
	switch auth {
	case AuthForm, AuthAPIKey:
		// valid
	default:
		return fmt.Errorf("auth: must be %q or %q, got %q", AuthForm, AuthAPIKey, e.Auth)
	}

	if auth == AuthAPIKey {
		// FR33: api-mode requires non-empty api_keys.
		if len(e.APIKeys) == 0 {
			return errors.New("api_keys: at least one key required when auth = \"api-key\"")
		}
		for i, k := range e.APIKeys {
			if strings.TrimSpace(k) == "" {
				return fmt.Errorf("api_keys[%d]: empty key", i)
			}
		}
		// FR32: api-mode rejects form-mode browser defenses at parse time
		// (ADR-10). Silent ignore would let an operator think they were
		// protected when they weren't.
		if e.Honeypot != "" {
			return errors.New("honeypot: not valid on auth=\"api-key\" endpoints (api-mode is authenticated; browser bot defenses do not apply)")
		}
		if e.AllowedOrigins != nil {
			return errors.New("allowed_origins: not valid on auth=\"api-key\" endpoints (api-mode is authenticated; browser CORS defenses do not apply)")
		}
		if e.RedirectSuccess != "" {
			return errors.New("redirect_success: not valid on auth=\"api-key\" endpoints (servers do not follow redirects in this flow)")
		}
		if e.RedirectError != "" {
			return errors.New("redirect_error: not valid on auth=\"api-key\" endpoints (servers do not follow redirects in this flow)")
		}
		if e.CSRFSecret != "" {
			return errors.New("csrf_secret: not valid on auth=\"api-key\" endpoints (api-mode callers are server-to-server; CSRF defense is form-mode only)")
		}
		if e.Reputation != nil {
			return errors.New("reputation: not valid on auth=\"api-key\" endpoints (form-mode only in v1.1)")
		}
		if e.ProofOfBrowser != nil {
			return errors.New("proof_of_browser: not valid on auth=\"api-key\" endpoints (server-to-server callers don't run a browser)")
		}
		if e.Captcha != nil {
			return errors.New("captcha: not valid on auth=\"api-key\" endpoints (server-to-server callers don't solve captchas)")
		}
		// FR42: idempotency_cache_size must be positive when set; zero
		// means "use the default" (handler-side resolution).
		if e.IdempotencyCacheSize < 0 {
			return fmt.Errorf("idempotency_cache_size: must be non-negative, got %d", e.IdempotencyCacheSize)
		}
	} else {
		// Form mode: api-mode-only fields must be unset. Catches the
		// "operator forgot to set auth = api-key" misconfiguration.
		if e.IdempotencyCacheSize != 0 {
			return errors.New("idempotency_cache_size: only valid on auth=\"api-key\" endpoints")
		}
		if len(e.APIKeys) > 0 {
			return errors.New("api_keys: must be unset unless auth = \"api-key\"")
		}
		// FR57: form-mode CSRF. When csrf_secret is set, validate it
		// passes the minimum-length check. csrf_token_ttl must be
		// positive when set; zero means "use the default" at handler-
		// construction time.
		if e.CSRFSecret != "" {
			if err := csrf.ValidateSecret([]byte(e.CSRFSecret)); err != nil {
				return err
			}
		}
		if e.CSRFTokenTTL.Std() < 0 {
			return fmt.Errorf("csrf_token_ttl: must be non-negative, got %v", e.CSRFTokenTTL.Std())
		}
		if e.Reputation != nil {
			if err := e.Reputation.validate(); err != nil {
				return fmt.Errorf("reputation: %w", err)
			}
		}
		if e.ProofOfBrowser != nil {
			if err := e.ProofOfBrowser.validate(); err != nil {
				return fmt.Errorf("proof_of_browser: %w", err)
			}
		}
		if e.Captcha != nil {
			if err := e.Captcha.validate(); err != nil {
				return fmt.Errorf("captcha: %w", err)
			}
		}
	}

	// NFR4: explicitly-empty allowed_origins is a misconfiguration.
	// BurntSushi/toml leaves the slice nil when the key is absent and
	// returns a non-nil empty slice when the operator wrote `allowed_origins = []`.
	// (Already rejected above for api-mode; this catches form-mode.)
	if e.AllowedOrigins != nil && len(e.AllowedOrigins) == 0 {
		return errors.New("allowed_origins is explicitly empty; either remove the key (to allow all origins) or list at least one origin")
	}

	if e.RateLimit != nil {
		if e.RateLimit.Count <= 0 {
			return fmt.Errorf("rate_limit.count must be positive, got %d", e.RateLimit.Count)
		}
		if e.RateLimit.Interval.Std() <= 0 {
			return fmt.Errorf("rate_limit.interval must be positive, got %v", e.RateLimit.Interval.Std())
		}
	}

	return nil
}

// Validate checks transport configuration for the declared type. Dispatch
// is via the transport package's registry — each transport (postmark,
// resend, mailgun, ses, smtp-out) registers its validator at init.
// Adding a new transport requires no edits here.
func (t *TransportConfig) Validate() error {
	if t.Type == "" {
		return errors.New("type is required (e.g., \"postmark\")")
	}
	reg, ok := transport.Lookup(t.Type)
	if !ok {
		return transport.UnknownTypeError(t.Type)
	}
	return reg.Validate(t.Settings)
}

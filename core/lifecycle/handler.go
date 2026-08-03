package lifecycle

import (
	"crypto/subtle"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/craigmccaskill/posthorn/metrics"
	"github.com/craigmccaskill/posthorn/ratelimit"
	"github.com/craigmccaskill/posthorn/storage"
)

// maxEventBody bounds an inbound event payload. Postmark events are
// single-digit KB; 256KB is generous headroom, not an invitation.
const maxEventBody = 256 << 10

// Threat posture for the ingestion endpoint (threat→defense table,
// architecture doc): forged events poisoning the suppression list are
// blocked by mandatory fail-closed basic auth; retry storms and
// brute-force are blunted by the per-IP rate limit; oversized bodies by
// MaxBytesReader; unknown message IDs are answered 200 so a
// misconfigured (or probing) sender gets no retry loop and no oracle.
type Handler struct {
	username  string
	password  string
	gate      *storage.Gate
	forwarder *Forwarder
	logger    *slog.Logger
	recorder  *metrics.Recorder
	limiter   *ratelimit.Limiter

	// now is injectable for tests. Production: time.Now.
	now func() time.Time
}

// NewHandler builds the /events/postmark handler (FR82). username and
// password are the mandatory basic-auth pair; forwarder carries the
// per-endpoint webhook map and may deliver inline or via the queue.
func NewHandler(username, password string, gate *storage.Gate, forwarder *Forwarder, logger *slog.Logger, recorder *metrics.Recorder) (*Handler, error) {
	// 60 posts/min per source IP: far above any legitimate Postmark
	// event rate for a self-hosted sender, low enough to blunt
	// brute-force against the basic-auth pair.
	limiter, err := ratelimit.New(60, time.Minute, 0)
	if err != nil {
		return nil, err
	}
	return &Handler{
		username:  username,
		password:  password,
		gate:      gate,
		forwarder: forwarder,
		logger:    logger,
		recorder:  recorder,
		limiter:   limiter,
		now:       time.Now,
	}, nil
}

// ServeHTTP implements the Postmark event sink (FR82, FR83, FR85).
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	ip := remoteIP(r)
	if !h.limiter.Allow(ip) {
		http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
		return
	}

	// Fail-closed basic auth, constant-time on both fields (NFR29).
	user, pass, ok := r.BasicAuth()
	userOK := subtle.ConstantTimeCompare([]byte(user), []byte(h.username))
	passOK := subtle.ConstantTimeCompare([]byte(pass), []byte(h.password))
	if !ok || userOK&passOK != 1 {
		w.Header().Set("WWW-Authenticate", `Basic realm="posthorn-events"`)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxEventBody))
	if err != nil {
		http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
		return
	}

	// From here on the answer is 200 regardless of processing outcome:
	// the sender is authenticated, and non-2xx answers only buy
	// provider retry storms for events we will never process
	// differently (FR83). Problems surface in logs and metrics.
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))

	ev, messageID, err := NormalizePostmark(body, h.now())
	if err != nil {
		h.logger.Warn("lifecycle_event_malformed", slog.String("error", err.Error()))
		h.recorder.LifecycleDropped("malformed")
		return
	}

	if !h.gate.Healthy() {
		// Degraded storage: no correlation possible. Drop loudly.
		h.logger.Warn("lifecycle_event_dropped_storage_degraded", slog.String("event", ev.Event))
		h.recorder.LifecycleDropped("unmatched")
		return
	}
	sub, found, err := h.gate.Store().FindByMessageID(messageID)
	if err != nil {
		h.gate.ReportError(err)
		h.recorder.LifecycleDropped("unmatched")
		return
	}
	if !found {
		h.logger.Info("lifecycle_event_unmatched",
			slog.String("event", ev.Event),
			slog.String("transport_message_id", messageID),
		)
		h.recorder.LifecycleDropped("unmatched")
		return
	}

	ev.SubmissionID = sub.ID
	ev.Endpoint = sub.Endpoint
	h.recorder.LifecycleEvent(ev.Event)
	h.logger.Info("lifecycle_event",
		slog.String("event", ev.Event),
		slog.String("submission_id", sub.ID),
		slog.String("endpoint", sub.Endpoint),
	)

	// FR85: hard bounces and spam complaints auto-suppress globally.
	if (ev.Event == EventHardBounce || ev.Event == EventSpamComplaint) && ev.Recipient != "" {
		if err := h.gate.Store().AddSuppression(ev.Recipient, suppressionReason(ev.Event), sub.Endpoint, h.now()); err != nil {
			h.gate.ReportError(err)
		} else {
			h.logger.Info("suppression_added",
				slog.String("reason", suppressionReason(ev.Event)),
				slog.String("endpoint", sub.Endpoint),
			)
		}
	}

	// FR84: forward to the originating endpoint's webhook, if any.
	payload, err := json.Marshal(ev)
	if err != nil {
		h.logger.Error("lifecycle_event_encode_failed", slog.String("error", err.Error()))
		return
	}
	h.forwarder.Deliver(r.Context(), sub.Endpoint, payload)
}

func suppressionReason(event string) string {
	if event == EventSpamComplaint {
		return storage.ReasonSpamComplaint
	}
	return storage.ReasonHardBounce
}

func remoteIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

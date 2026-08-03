package metrics

import (
	"net/http"
)

// HealthzHandler returns an HTTP handler that responds with `200 OK` and
// body `ok` for any GET request. The endpoint is auth-free and
// rate-limit-free; operators concerned about exposure firewall the path
// at the reverse proxy (FR54).
func HealthzHandler() http.Handler {
	return HealthzHandlerWithStorage(nil)
}

// StorageState reports the storage layer's current health for /healthz
// (FR80). Wired by cmd/posthorn when a [storage] block is configured.
type StorageState func() (healthy bool)

// HealthzHandlerWithStorage extends /healthz with the storage canary
// state. With a nil state func the response is the v1.x plain-text "ok",
// byte-identical. With storage configured the body becomes JSON:
//
//	{"status":"ok","storage":"ok"}      — canary passing
//	{"status":"ok","storage":"degraded"} — canary failing
//
// The HTTP status stays 200 in both cases: a degraded disk does not
// stop mail flow (NFR27), so it must not fail liveness probes and cause
// restarts that wouldn't help.
func HealthzHandlerWithStorage(state StorageState) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if state == nil {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("ok"))
			return
		}
		storage := "ok"
		if !state() {
			storage = "degraded"
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok","storage":"` + storage + `"}`))
	})
}

// Handler returns an HTTP handler that serves the registry's metrics in
// Prometheus text exposition format (FR55). Like /healthz, auth-free
// and rate-limit-free; firewall at the reverse proxy if needed.
//
// The Content-Type is the Prometheus exposition 0.0.4 format, recognized
// by Prometheus servers and promtool.
func (r *Registry) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_ = r.Emit(w)
	})
}

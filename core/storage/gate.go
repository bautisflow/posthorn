package storage

import (
	"context"
	"log/slog"
	"sync/atomic"
	"time"
)

// Gate wraps a Store with the degrade switch (FR80, NFR27). Callers ask
// Healthy() before persisting; when the answer is false they skip
// storage entirely and the gateway behaves exactly like v1.x — mail
// keeps flowing, nothing persists, no 202s are offered.
//
// State transitions are driven two ways: the periodic canary probe
// (authoritative, both directions) and ReportError (fast downgrade when
// a live write fails between probes; only a probe brings health back).
type Gate struct {
	store   *Store
	logger  *slog.Logger
	healthy atomic.Bool
}

// NewGate wraps store, starting healthy.
func NewGate(store *Store, logger *slog.Logger) *Gate {
	g := &Gate{store: store, logger: logger}
	g.healthy.Store(true)
	return g
}

// Store returns the underlying store. Callers must check Healthy first.
func (g *Gate) Store() *Store { return g.store }

// Healthy reports whether persistence is currently trusted.
func (g *Gate) Healthy() bool { return g.healthy.Load() }

// ReportError downgrades immediately after a live write failure. The
// canary probe owns recovery.
func (g *Gate) ReportError(err error) {
	if g.healthy.CompareAndSwap(true, false) {
		g.logger.Error("storage_degraded",
			slog.String("error", err.Error()),
			slog.String("effect", "mail flow continues synchronously; persistence and queueing paused"),
		)
	}
}

func (g *Gate) setFromProbe(err error) {
	if err == nil {
		if g.healthy.CompareAndSwap(false, true) {
			g.logger.Info("storage_recovered")
		}
		return
	}
	if g.healthy.CompareAndSwap(true, false) {
		g.logger.Error("storage_degraded",
			slog.String("error", err.Error()),
			slog.String("effect", "mail flow continues synchronously; persistence and queueing paused"),
		)
	}
}

// MaintenanceHooks observe the maintenance loop for metrics wiring.
// Nil funcs are skipped.
type MaintenanceHooks struct {
	OnHealth func(healthy bool)
	OnDepth  func(depth int)
}

// RunMaintenance runs the canary probe (FR80) and retention pruning
// (FR79) until ctx is canceled. probeInterval defaults to 15s,
// pruneInterval to 1h. Pruning only runs while healthy.
func (g *Gate) RunMaintenance(ctx context.Context, probeInterval, pruneInterval, retention time.Duration, hooks MaintenanceHooks) {
	if probeInterval <= 0 {
		probeInterval = 15 * time.Second
	}
	if pruneInterval <= 0 {
		pruneInterval = time.Hour
	}
	probe := time.NewTicker(probeInterval)
	prune := time.NewTicker(pruneInterval)
	defer probe.Stop()
	defer prune.Stop()

	// Immediate first probe so /healthz is accurate at startup, not
	// after the first interval.
	g.probeOnce(hooks)

	for {
		select {
		case <-ctx.Done():
			return
		case <-probe.C:
			g.probeOnce(hooks)
		case <-prune.C:
			if !g.Healthy() || retention <= 0 {
				continue
			}
			n, err := g.store.Prune(time.Now().Add(-retention))
			if err != nil {
				g.logger.Error("storage_prune_failed", slog.String("error", err.Error()))
				continue
			}
			if n > 0 {
				g.logger.Info("storage_pruned", slog.Int64("rows", n))
			}
		}
	}
}

func (g *Gate) probeOnce(hooks MaintenanceHooks) {
	err := g.store.Probe(time.Now())
	g.setFromProbe(err)
	if hooks.OnHealth != nil {
		hooks.OnHealth(g.Healthy())
	}
	if hooks.OnDepth != nil && g.Healthy() {
		if depth, derr := g.store.QueueDepth(); derr == nil {
			hooks.OnDepth(depth)
		}
	}
}

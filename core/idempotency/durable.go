package idempotency

import (
	"sync"
	"time"

	"github.com/craigmccaskill/posthorn/storage"
)

// Cacher is the idempotency contract the gateway consumes. Two
// implementations: the v1.x in-memory Cache (ADR-8) and the
// storage-backed Durable (FR81). The gateway swaps between them at
// construction based on whether [storage] is configured — the exact
// backend-swap seam ADR-8 reserved.
type Cacher interface {
	Lookup(key string) (resp *Response, inFlight bool)
	ClaimInFlight(key string) bool
	Store(key string, resp Response)
	Abandon(key string)
}

var (
	_ Cacher = (*Cache)(nil)
	_ Cacher = (*Durable)(nil)
)

// Durable is the SQLite-backed idempotency cache (FR81): same contract
// as Cache, restart-survivable entries, same 24h TTL, expiry enforced
// on read with background pruning.
//
// The in-flight tracker stays in-memory: ADR-9's 409 semantics are
// process-local, which NFR26's single-writer stance makes correct by
// assumption. Only completed responses persist.
//
// Degrade posture (NFR27): while the storage gate is unhealthy, lookups
// miss and stores drop — callers fall through to a fresh send. A
// retried key during a disk outage may therefore double-send; that is
// the documented cost of never letting storage block mail.
type Durable struct {
	gate     *storage.Gate
	endpoint string
	ttl      time.Duration

	mu       sync.Mutex
	inflight map[string]struct{}

	// now is injectable for TTL tests. Production: time.Now.
	now func() time.Time
}

// NewDurable constructs the storage-backed cache for one endpoint
// (per-endpoint scoping preserved via the endpoint column — FR41's
// no-cross-endpoint-collision guarantee, now by key, not by instance).
func NewDurable(gate *storage.Gate, endpoint string, ttl time.Duration) *Durable {
	if ttl <= 0 {
		ttl = DefaultTTL
	}
	return &Durable{
		gate:     gate,
		endpoint: endpoint,
		ttl:      ttl,
		inflight: make(map[string]struct{}),
		now:      time.Now,
	}
}

// Lookup implements Cacher. Same three-shape contract as Cache.Lookup.
func (d *Durable) Lookup(key string) (*Response, bool) {
	d.mu.Lock()
	_, inflight := d.inflight[key]
	d.mu.Unlock()
	if inflight {
		return nil, true
	}
	if !d.gate.Healthy() {
		return nil, false
	}
	status, contentType, body, ok, err := d.gate.Store().GetIdempotent(key, d.endpoint, d.now())
	if err != nil {
		d.gate.ReportError(err)
		return nil, false
	}
	if !ok {
		return nil, false
	}
	return &Response{Status: status, Body: body, ContentType: contentType}, false
}

// ClaimInFlight implements Cacher. Process-local (ADR-9, NFR26).
func (d *Durable) ClaimInFlight(key string) bool {
	// A completed entry must refuse the claim so the caller re-Lookups,
	// mirroring Cache.ClaimInFlight.
	if resp, _ := d.lookupStored(key); resp != nil {
		return false
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if _, ok := d.inflight[key]; ok {
		return false
	}
	d.inflight[key] = struct{}{}
	return true
}

func (d *Durable) lookupStored(key string) (*Response, bool) {
	if !d.gate.Healthy() {
		return nil, false
	}
	status, contentType, body, ok, err := d.gate.Store().GetIdempotent(key, d.endpoint, d.now())
	if err != nil || !ok {
		return nil, false
	}
	return &Response{Status: status, Body: body, ContentType: contentType}, false
}

// Store implements Cacher: persist and release the claim.
func (d *Durable) Store(key string, resp Response) {
	if d.gate.Healthy() {
		err := d.gate.Store().PutIdempotent(key, d.endpoint, resp.Status, resp.ContentType, resp.Body, d.now().Add(d.ttl))
		if err != nil {
			d.gate.ReportError(err)
		}
	}
	d.mu.Lock()
	delete(d.inflight, key)
	d.mu.Unlock()
}

// Abandon implements Cacher: release the claim without persisting.
func (d *Durable) Abandon(key string) {
	d.mu.Lock()
	delete(d.inflight, key)
	d.mu.Unlock()
}

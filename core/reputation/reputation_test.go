package reputation

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// fakeSFS serves a canned StopForumSpam JSON and counts requests.
func fakeSFS(t *testing.T, body string) (*httptest.Server, *int32) {
	t.Helper()
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv, &hits
}

func newChecker(t *testing.T, base string, cfg Config) *Checker {
	t.Helper()
	cfg.BaseURL = base
	c, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c
}

func TestChecker_BlocksHighConfidenceEmail(t *testing.T) {
	srv, _ := fakeSFS(t, `{"success":1,"email":{"appears":1,"confidence":96.5},"ip":{"appears":0,"confidence":0}}`)
	c := newChecker(t, srv.URL, Config{CheckEmail: true, CheckIP: true, Threshold: 95, FailOpen: true})

	res := c.Check(context.Background(), "zekisuquc419@gmail.com", "203.0.113.7")
	if !res.Blocked {
		t.Fatalf("want blocked for confidence 96.5 ≥ 95; got %+v", res)
	}
}

func TestChecker_BlocksHighConfidenceIP(t *testing.T) {
	srv, _ := fakeSFS(t, `{"success":1,"email":{"appears":0,"confidence":0},"ip":{"appears":1,"confidence":99}}`)
	c := newChecker(t, srv.URL, Config{CheckIP: true, Threshold: 95, FailOpen: true})
	if res := c.Check(context.Background(), "", "54.240.9.6"); !res.Blocked {
		t.Fatalf("want blocked on ip; got %+v", res)
	}
}

func TestChecker_PassesBelowThreshold(t *testing.T) {
	srv, _ := fakeSFS(t, `{"success":1,"email":{"appears":1,"confidence":40},"ip":{"appears":0,"confidence":0}}`)
	c := newChecker(t, srv.URL, Config{CheckEmail: true, Threshold: 95, FailOpen: true})
	if res := c.Check(context.Background(), "maybe@example.com", "203.0.113.1"); res.Blocked {
		t.Errorf("confidence 40 < 95 should pass; got %+v", res)
	}
}

func TestChecker_PassesWhenNotAppearing(t *testing.T) {
	// High confidence but appears=0 must not block (SFS returns stale
	// confidence for never-seen entries).
	srv, _ := fakeSFS(t, `{"success":1,"email":{"appears":0,"confidence":100},"ip":{"appears":0,"confidence":0}}`)
	c := newChecker(t, srv.URL, Config{CheckEmail: true, Threshold: 95, FailOpen: true})
	if res := c.Check(context.Background(), "real@example.com", "203.0.113.2"); res.Blocked {
		t.Errorf("appears=0 must not block regardless of confidence; got %+v", res)
	}
}

func TestChecker_CachesResult(t *testing.T) {
	srv, hits := fakeSFS(t, `{"success":1,"email":{"appears":1,"confidence":99},"ip":{"appears":0,"confidence":0}}`)
	c := newChecker(t, srv.URL, Config{CheckEmail: true, Threshold: 95, FailOpen: true})

	for i := 0; i < 3; i++ {
		c.Check(context.Background(), "same@bad.com", "203.0.113.9")
	}
	if got := atomic.LoadInt32(hits); got != 1 {
		t.Errorf("provider hit %d times, want 1 (subsequent lookups cached)", got)
	}
}

func TestChecker_CacheExpires(t *testing.T) {
	srv, hits := fakeSFS(t, `{"success":1,"email":{"appears":1,"confidence":99},"ip":{"appears":0,"confidence":0}}`)
	c := newChecker(t, srv.URL, Config{CheckEmail: true, Threshold: 95, FailOpen: true, CacheTTL: time.Minute})

	base := time.Now()
	c.now = func() time.Time { return base }
	c.Check(context.Background(), "x@bad.com", "1.2.3.4")
	c.now = func() time.Time { return base.Add(2 * time.Minute) } // past TTL
	c.Check(context.Background(), "x@bad.com", "1.2.3.4")

	if got := atomic.LoadInt32(hits); got != 2 {
		t.Errorf("provider hit %d times, want 2 (cache should expire)", got)
	}
}

func TestChecker_FailOpenOnProviderError(t *testing.T) {
	// Point at a closed server so the request errors.
	srv, _ := fakeSFS(t, `{}`)
	base := srv.URL
	srv.Close() // now requests fail
	c := newChecker(t, base, Config{CheckEmail: true, Threshold: 95, FailOpen: true, Timeout: 200 * time.Millisecond})

	res := c.Check(context.Background(), "a@b.com", "1.1.1.1")
	if res.Blocked {
		t.Errorf("fail-open must not block on provider error; got %+v", res)
	}
	if !res.FailedOpen {
		t.Errorf("want FailedOpen=true so the bypass is metered; got %+v", res)
	}
}

func TestChecker_FailClosedOnProviderError(t *testing.T) {
	srv, _ := fakeSFS(t, `{}`)
	base := srv.URL
	srv.Close()
	c := newChecker(t, base, Config{CheckEmail: true, Threshold: 95, FailOpen: false, Timeout: 200 * time.Millisecond})

	if res := c.Check(context.Background(), "a@b.com", "1.1.1.1"); !res.Blocked {
		t.Errorf("fail-closed should block on provider error; got %+v", res)
	}
}

func TestNew_RequiresACheck(t *testing.T) {
	if _, err := New(Config{Threshold: 95}); err == nil {
		t.Error("New should reject a config that checks neither email nor ip")
	}
}

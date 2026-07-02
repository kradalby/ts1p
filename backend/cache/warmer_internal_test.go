package cache

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tailscale/setec/types/api"

	"github.com/kradalby/ts1p/backend"
	"github.com/kradalby/ts1p/backend/mem"
)

// spyBackend counts warmer-driven (force-refreshed) Loads — and can fail leading
// ones — to prove the warmer hits, spares, or retries the inner store. Unforced
// Loads (a test's own probes) pass through uncounted, so assertions observe the
// warmer and not the probe.
type spyBackend struct {
	backend.Backend

	loads     atomic.Int64 // forced Loads only
	failFirst atomic.Int64 // fail this many leading forced Loads with ErrUnavailable

	mu     sync.Mutex
	warmed map[string]int // name -> successful forced Loads
}

func (s *spyBackend) Load(ctx context.Context, name string) (*backend.Record, error) {
	if !backend.ForceRefresh(ctx) {
		return s.Backend.Load(ctx, name)
	}

	n := s.loads.Add(1)
	if n <= s.failFirst.Load() {
		return nil, backend.ErrUnavailable
	}

	s.mu.Lock()
	if s.warmed == nil {
		s.warmed = map[string]int{}
	}

	s.warmed[name]++
	s.mu.Unlock()

	return s.Backend.Load(ctx, name)
}

func (s *spyBackend) warmedCount(name string) int {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.warmed[name]
}

func recOf(name, val string) *backend.Record {
	return &backend.Record{
		Name:     name,
		Versions: map[api.SecretVersion][]byte{1: []byte(val)},
		Active:   1,
		Latest:   1,
	}
}

// TestWarmRefreshFracBelowFloor guards the cross-file invariant the warmer relies
// on: it must refresh before the minimum jittered lifetime (1 - 1/jitterFrac), or
// an entry could expire onto the request path between refreshes.
func TestWarmRefreshFracBelowFloor(t *testing.T) {
	require.Less(t, warmRefreshFrac, 1-1.0/jitterFrac,
		"warmer must refresh before the minimum jittered cache lifetime")
}

// TestWarmerDisabledWhenNoExpiry: with no positive TTL, entries never expire, so
// Run must return without warming anything (no busy-loop, no wasted core calls).
func TestWarmerDisabledWhenNoExpiry(t *testing.T) {
	spy := &spyBackend{Backend: mem.New()}
	w := NewWarmer(New(spy, 0, 0), nil)

	done := make(chan struct{})

	go func() { w.Run(context.Background()); close(done) }()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return for a non-expiring cache")
	}

	require.Zero(t, spy.loads.Load(), "a disabled warmer must not load anything")
}

// TestWarmerWarmsEverything: the warmer prefetches every secret, after which a
// normal read is served from cache.
func TestWarmerWarmsEverything(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	mb := mem.New()
	require.NoError(t, mb.Save(ctx, "a", recOf("a", "1")))
	require.NoError(t, mb.Save(ctx, "b", recOf("b", "1")))
	spy := &spyBackend{Backend: mb}
	c := New(spy, 0, 60*time.Millisecond)
	w := NewWarmer(c, nil)

	go w.Run(ctx)

	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		assert.GreaterOrEqual(ct, spy.loads.Load(), int64(2))
	}, 2*time.Second, 5*time.Millisecond, "warmer should warm every secret")

	cancel()
	w.Wait() // returns once Run has stopped (shutdown ordering)
}

// TestWarmerDiscoversNewSecret: a secret created out-of-band after start is found
// by the warmer's force-refreshed relist and warmed without any client traffic.
func TestWarmerDiscoversNewSecret(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	mb := mem.New()
	require.NoError(t, mb.Save(ctx, "a", recOf("a", "1")))
	spy := &spyBackend{Backend: mb}
	c := New(spy, 0, 60*time.Millisecond)
	w := NewWarmer(c, nil)

	go w.Run(ctx)

	require.NoError(t, mb.Save(ctx, "b", recOf("b", "1"))) // out-of-band create

	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		// Not just listed: the warmer must have actually loaded (warmed) b, so
		// the first client read of it is a cache hit.
		assert.Positive(ct, spy.warmedCount("b"))

		names, err := c.List(ctx)
		assert.NoError(ct, err)
		assert.Contains(ct, names, "b")
	}, 2*time.Second, 5*time.Millisecond, "warmer should discover and warm a new secret")
	cancel()
	w.Wait()
}

// TestWarmerEvictsDeletedSecret: a secret deleted out-of-band disappears from
// serving at the next relist — the warmer both stops warming it and evicts the
// cached record, so a deleted (e.g. revoked) secret cannot be served until its
// TTL runs out.
func TestWarmerEvictsDeletedSecret(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	mb := mem.New()
	require.NoError(t, mb.Save(ctx, "a", recOf("a", "1")))
	spy := &spyBackend{Backend: mb}
	c := New(spy, 0, 60*time.Millisecond)
	w := NewWarmer(c, nil)

	go w.Run(ctx)

	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		assert.Positive(ct, spy.warmedCount("a"))
	}, 2*time.Second, 5*time.Millisecond, "initial warm")

	require.NoError(t, mb.Delete(ctx, "a")) // out-of-band delete

	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		_, err := c.Load(ctx, "a")
		assert.ErrorIs(ct, err, backend.ErrNotFound)
	}, 2*time.Second, 5*time.Millisecond, "deleted secret must stop being served")
	cancel()
	w.Wait()
}

// TestWarmerRetriesFailedRefresh: a transient failure does not strand an entry;
// the warmer retries sooner than its normal cadence.
func TestWarmerRetriesFailedRefresh(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	mb := mem.New()
	require.NoError(t, mb.Save(ctx, "a", recOf("a", "1")))
	spy := &spyBackend{Backend: mb}
	spy.failFirst.Store(1) // first warm fails, then recovers
	c := New(spy, 0, 90*time.Millisecond)
	w := NewWarmer(c, nil)

	go w.Run(ctx)

	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		assert.GreaterOrEqual(ct, spy.loads.Load(), int64(2)) // failed once, retried
		got, err := c.Load(ctx, "a")
		assert.NoError(ct, err)

		if assert.NotNil(ct, got) {
			assert.Equal(ct, []byte("1"), got.Versions[1])
		}
	}, 2*time.Second, 5*time.Millisecond, "warmer should retry a failed refresh")
	cancel()
	w.Wait()
}

// TestWarmerReprime: a Reprime (as a flush would trigger) re-warms every secret.
func TestWarmerReprime(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	mb := mem.New()
	require.NoError(t, mb.Save(ctx, "a", recOf("a", "1")))
	spy := &spyBackend{Backend: mb}
	c := New(spy, 0, time.Hour) // long TTL: no natural refresh during the test
	w := NewWarmer(c, nil)

	go w.Run(ctx)

	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		assert.GreaterOrEqual(ct, spy.loads.Load(), int64(1))
	}, 2*time.Second, 5*time.Millisecond, "initial warm")

	base := spy.loads.Load()

	w.Reprime()
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		assert.Greater(ct, spy.loads.Load(), base)
	}, 2*time.Second, 5*time.Millisecond, "reprime should re-warm")
	cancel()
	w.Wait()
}

// TestWarmerRunStopsOnCancel: Run must return promptly when its context is done,
// and Wait must then unblock.
func TestWarmerRunStopsOnCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	w := NewWarmer(New(mem.New(), 0, time.Hour), nil)

	go w.Run(ctx)

	done := make(chan struct{})

	go func() { w.Wait(); close(done) }()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not stop on context cancel")
	}
}

package cache

import (
	"context"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kradalby/ts1p/backend"
	"github.com/kradalby/ts1p/backend/mem"
)

// ctrlBackend is a controllable backend for cache internal tests: it counts
// Loads, can be made to fail, and can gate Loads to force concurrent overlap.
type ctrlBackend struct {
	mem *mem.Backend

	loads atomic.Int64

	mu      sync.Mutex
	failErr error // when non-nil, Load returns it

	gate        chan struct{} // when non-nil, Load blocks until closed
	entered     chan struct{} // closed when the first gated Load enters
	enteredOnce sync.Once

	onGateRelease func(ctx context.Context) // observes the Load ctx after the gate opens
}

func newCtrl() *ctrlBackend { return &ctrlBackend{mem: mem.New()} }

func (b *ctrlBackend) Load(ctx context.Context, name string) (*backend.Record, error) {
	b.loads.Add(1)
	// Snapshot the stored value before any gating, so a write that lands while
	// this Load is parked does not change what this Load returns — that is what
	// makes a returning fill "stale" and exercises the seq-guard.
	r, err := b.mem.Load(ctx, name)
	if b.gate != nil {
		b.enteredOnce.Do(func() { close(b.entered) })
		<-b.gate

		if b.onGateRelease != nil {
			b.onGateRelease(ctx)
		}
	}

	b.mu.Lock()
	fe := b.failErr
	b.mu.Unlock()

	if fe != nil {
		return nil, fe
	}

	return r, err
}

func (b *ctrlBackend) Save(ctx context.Context, name string, r *backend.Record) error {
	return b.mem.Save(ctx, name, r)
}

func (b *ctrlBackend) List(ctx context.Context) ([]string, error) {
	b.mu.Lock()
	fe := b.failErr
	b.mu.Unlock()

	if fe != nil {
		return nil, fe
	}

	return b.mem.List(ctx)
}

func (b *ctrlBackend) Delete(ctx context.Context, name string) error {
	return b.mem.Delete(ctx, name)
}
func (b *ctrlBackend) Close() error { return b.mem.Close() }

func (b *ctrlBackend) setFail(err error) {
	b.mu.Lock()
	b.failErr = err
	b.mu.Unlock()
}

// TestJitterWithinBounds: per-entry lifetimes stay within ±20% of the base TTL
// and actually vary, so a burst of cached secrets does not all refetch at once.
func TestJitterWithinBounds(t *testing.T) {
	const ttl = time.Hour

	c := New(nil, 0, ttl)

	lo, hi := ttl-ttl/5, ttl+ttl/5
	seen := map[time.Duration]struct{}{}

	for range 1000 {
		d := c.randomLifetime()
		require.GreaterOrEqual(t, d, lo, "lifetime below -20%")
		require.LessOrEqual(t, d, hi, "lifetime above +20%")
		seen[d] = struct{}{}
	}

	require.Greater(t, len(seen), 1, "jitter must spread lifetimes")
}

// TestNoJitterWhenDisabled: ttl 0 means cache-forever (no logical expiry), so
// the lifetime is 0 and entries never jitter-expire.
func TestNoJitterWhenDisabled(t *testing.T) {
	c := New(nil, 0, 0)
	require.Zero(t, c.randomLifetime())
	require.True(t, c.expiresAt().IsZero(), "ttl 0 entries never expire")
}

// TestSingleflightCoalesces: concurrent cold reads of the same key collapse into
// a single inner Load, so a stampede cannot pile onto the WASM core.
func TestSingleflightCoalesces(t *testing.T) {
	ctx := context.Background()
	b := newCtrl()
	require.NoError(t, b.mem.Save(ctx, "a", recOf("a", "1")))
	b.gate = make(chan struct{})
	b.entered = make(chan struct{})

	c := New(b, 0, time.Hour)

	const n = 12

	var (
		arrived atomic.Int32
		wg      sync.WaitGroup
	)

	got := make([]*backend.Record, n)
	for i := range n {
		wg.Go(func() {
			arrived.Add(1)

			r, err := c.Load(ctx, "a")
			assert.NoError(t, err)

			got[i] = r
		})
	}

	require.Eventually(t, func() bool { return arrived.Load() == n }, time.Second, time.Millisecond)
	<-b.entered // the leader is inside inner.Load, holding the singleflight key
	close(b.gate)
	wg.Wait()

	// Asserted after completion, so the result is deterministic: without
	// coalescing every caller would have reached the inner backend (loads == n);
	// with it, callers either joined the leader's flight or hit the cache the
	// leader filled.
	require.EqualValues(t, 1, b.loads.Load(), "concurrent misses must coalesce to one inner load")

	for i := range n {
		require.Equal(t, []byte("1"), got[i].Versions[1])
	}
}

// TestServeStaleOnUnavailable: when an expired entry is read and the inner
// backend is unavailable, the cache serves the resident (stale) value instead of
// failing — stale-while-revalidate for a read-mostly store fronting a fragile core.
func TestServeStaleOnUnavailable(t *testing.T) {
	ctx := context.Background()
	b := newCtrl()
	require.NoError(t, b.mem.Save(ctx, "a", recOf("a", "1")))

	c := New(b, 0, time.Hour)
	now := time.Now()
	c.now = func() time.Time { return now }

	_, err := c.Load(ctx, "a") // warm
	require.NoError(t, err)

	now = now.Add(2 * time.Hour) // entry is now logically expired

	b.setFail(backend.ErrUnavailable)

	got, err := c.Load(ctx, "a")
	require.NoError(t, err, "expired entry must be served stale when inner is unavailable")
	require.Equal(t, []byte("1"), got.Versions[1])

	// A genuine not-found still surfaces (nothing resident to serve).
	b.setFail(backend.ErrNotFound)

	_, err = c.Load(ctx, "missing")
	require.ErrorIs(t, err, backend.ErrNotFound)
}

// TestSeqGuardWriteDuringFill: a Save that lands while a read-fill is in flight
// must win — the returning fill must not clobber the cache back to the old value.
func TestSeqGuardWriteDuringFill(t *testing.T) {
	ctx := context.Background()
	b := newCtrl()
	require.NoError(t, b.mem.Save(ctx, "a", recOf("a", "1")))
	b.gate = make(chan struct{})
	b.entered = make(chan struct{})

	c := New(b, 0, time.Hour)

	// Start a read-fill; it blocks inside inner.Load holding the old value (1).
	done := make(chan struct{})

	go func() {
		_, err := c.Load(ctx, "a")
		assert.NoError(t, err)
		close(done)
	}()

	<-b.entered

	// While the fill is parked, write a new value through the cache.
	require.NoError(t, c.Save(ctx, "a", recOf("a", "2")))

	close(b.gate) // let the fill return with the stale value (1)
	<-done

	// The cache must still hold the written value (2), not the clobbered fill (1).
	loadsBefore := b.loads.Load()
	got, err := c.Load(ctx, "a")
	require.NoError(t, err)
	require.Equal(t, []byte("2"), got.Versions[1], "write during fill must win")
	require.Equal(t, loadsBefore, b.loads.Load(), "post-write read should be a cache hit")
}

// TestForceRefreshFreshOrFail: a forced read must not be satisfied by the
// stale-while-unavailable fallback — the warmer and Cache-Control: no-cache
// demand freshness, and being handed a stale value would mask the outage from
// exactly the callers that exist to notice it.
func TestForceRefreshFreshOrFail(t *testing.T) {
	ctx := context.Background()
	b := newCtrl()
	require.NoError(t, b.mem.Save(ctx, "a", recOf("a", "1")))
	require.NoError(t, b.mem.Save(ctx, "l", recOf("l", "1")))

	c := New(b, 0, time.Hour)
	now := time.Now()
	c.now = func() time.Time { return now }

	_, err := c.Load(ctx, "a") // warm the record
	require.NoError(t, err)
	_, err = c.List(ctx) // warm the name list
	require.NoError(t, err)

	now = now.Add(2 * time.Hour)

	b.setFail(backend.ErrUnavailable)

	_, err = c.Load(ctx, "a")
	require.NoError(t, err, "ordinary read is served stale")
	_, err = c.Load(backend.WithForceRefresh(ctx), "a")
	require.ErrorIs(t, err, backend.ErrUnavailable, "forced read must fail, not go stale")

	_, err = c.List(ctx)
	require.NoError(t, err, "ordinary list is served stale")
	_, err = c.List(backend.WithForceRefresh(ctx))
	require.ErrorIs(t, err, backend.ErrUnavailable, "forced list must fail, not go stale")
}

// TestConfirmedNotFoundEvicts: once the inner backend confirms a name is gone,
// the resident entry must not be servable — not even via the stale fallback —
// or a deleted (revoked) secret could be resurrected during an outage.
func TestConfirmedNotFoundEvicts(t *testing.T) {
	ctx := context.Background()
	b := newCtrl()
	require.NoError(t, b.mem.Save(ctx, "a", recOf("a", "1")))

	c := New(b, 0, time.Hour)
	now := time.Now()
	c.now = func() time.Time { return now }

	_, err := c.Load(ctx, "a") // resident
	require.NoError(t, err)

	require.NoError(t, b.mem.Delete(ctx, "a")) // deleted out-of-band

	now = now.Add(2 * time.Hour) // entry expired

	_, err = c.Load(ctx, "a")
	require.ErrorIs(t, err, backend.ErrNotFound, "expired read must see the delete")

	// An outage right after must not resurrect the deleted value.
	b.setFail(backend.ErrUnavailable)

	now = now.Add(time.Hour) // past the cached negative's lifetime
	_, err = c.Load(ctx, "a")
	require.ErrorIs(t, err, backend.ErrUnavailable, "no stale fallback for an evicted record")
}

// TestNegativeCachedBriefly: a confirmed not-found is cached for a short window
// so a crash-looping consumer of a missing secret cannot hammer the inner
// backend; the negative expires on its own so an out-of-band create appears.
func TestNegativeCachedBriefly(t *testing.T) {
	ctx := context.Background()
	b := newCtrl()
	c := New(b, 0, time.Hour)
	now := time.Now()
	c.now = func() time.Time { return now }

	_, err := c.Load(ctx, "nope")
	require.ErrorIs(t, err, backend.ErrNotFound)
	_, err = c.Load(ctx, "nope")
	require.ErrorIs(t, err, backend.ErrNotFound)
	require.EqualValues(t, 1, b.loads.Load(), "repeated misses must be absorbed by the cached negative")

	// The negative expires (ttl/10 capped at negTTLCap), and a created secret
	// then appears on the next read.
	require.NoError(t, b.mem.Save(ctx, "nope", recOf("nope", "1")))

	now = now.Add(negTTLCap + time.Second)
	got, err := c.Load(ctx, "nope")
	require.NoError(t, err, "negative must expire and admit the created secret")
	require.Equal(t, []byte("1"), got.Versions[1])

	// With expiry disabled there is no warmer to discover creates, so negatives
	// are not cached at all.
	b2 := newCtrl()
	c2 := New(b2, 0, 0)
	_, err = c2.Load(ctx, "nope")
	require.ErrorIs(t, err, backend.ErrNotFound)
	_, err = c2.Load(ctx, "nope")
	require.ErrorIs(t, err, backend.ErrNotFound)
	require.EqualValues(t, 2, b2.loads.Load(), "ttl<=0 must not cache negatives")
}

// TestListServeStaleOnUnavailable: the name list gets the same
// stale-while-unavailable treatment records do — /api/list and the store lean on
// it during a 1Password outage.
func TestListServeStaleOnUnavailable(t *testing.T) {
	ctx := context.Background()
	b := newCtrl()
	require.NoError(t, b.mem.Save(ctx, "a", recOf("a", "1")))

	c := New(b, 0, time.Hour)
	now := time.Now()
	c.now = func() time.Time { return now }

	names, err := c.List(ctx) // warm
	require.NoError(t, err)
	require.Equal(t, []string{"a"}, names)

	now = now.Add(2 * time.Hour)

	b.setFail(backend.ErrUnavailable)

	names, err = c.List(ctx)
	require.NoError(t, err, "expired name list must be served stale when inner is unavailable")
	require.Equal(t, []string{"a"}, names)
}

// TestFetchDetachedFromCaller: the inner fetch must not run on the winning
// caller's cancelable context — a client disconnect mid-fetch would otherwise
// fail the shared result for every coalesced waiter and discard a successful
// fetch instead of caching it.
func TestFetchDetachedFromCaller(t *testing.T) {
	ctx := context.Background()
	b := newCtrl()
	require.NoError(t, b.mem.Save(ctx, "a", recOf("a", "1")))
	b.gate = make(chan struct{})
	b.entered = make(chan struct{})

	c := New(b, 0, time.Hour)

	cctx, cancel := context.WithCancel(ctx)

	var sawCanceled atomic.Bool

	b.onGateRelease = func(ctx context.Context) { sawCanceled.Store(ctx.Err() != nil) }

	done := make(chan struct{})
	go func() {
		defer close(done)

		r, err := c.Load(cctx, "a")
		// The fetch succeeded; the (departed) winner still gets the value.
		assert.NoError(t, err)

		if assert.NotNil(t, r) {
			assert.Equal(t, []byte("1"), r.Versions[1])
		}
	}()

	<-b.entered
	cancel() // the caller disconnects while the fetch is in flight
	close(b.gate)
	<-done

	require.False(t, sawCanceled.Load(), "inner fetch must run detached from the caller's context")

	// And the fill was cached, not discarded.
	before := b.loads.Load()
	_, err := c.Load(ctx, "a")
	require.NoError(t, err)
	require.Equal(t, before, b.loads.Load(), "successful fill from a canceled caller must still be cached")
}

// TestNoGoroutineLeak: constructing caches with a positive TTL must not spawn
// per-cache background sweeper goroutines that nothing can reap.
func TestNoGoroutineLeak(t *testing.T) {
	before := runtime.NumGoroutine()

	for range 50 {
		_ = New(mem.New(), 0, time.Hour)
	}

	require.Eventually(t, func() bool {
		runtime.GC()
		return runtime.NumGoroutine() <= before+2
	}, 2*time.Second, 20*time.Millisecond, "cache.New must not leak goroutines")
}

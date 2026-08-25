// Package cache wraps a backend.Backend with a lazy, expiry-based read cache.
// It exists so ts1p does not hit the underlying password manager on every
// client poll: a remote read happens only on a cold or expired cache entry, not
// on a timer. It uses the same expirable LRU that headscale uses for its
// registration cache.
//
// Each entry's lifetime is the configured TTL jittered by ±20%, so a burst of
// secrets cached together (e.g. a List) does not all expire at the same instant
// and stampede the password manager. Concurrent misses for the same key are
// coalesced with singleflight, so even a cold start or a post-flush burst makes
// at most one inner call per key; the inner fetch is detached from the caller
// that happens to win the flight, so one client's disconnect cannot fail the
// shared result. A read carrying backend.WithForceRefresh bypasses the cache
// for that call and refreshes the entry, so a secret edited out-of-band can be
// picked up on demand; forced reads are fresh-or-fail, while ordinary reads
// fall back to a resident-but-expired value when the inner backend is
// unavailable. A confirmed not-found evicts any resident value and is cached
// briefly, so a consumer crash-looping on a missing name cannot hammer the
// inner backend.
//
// The record cache and the name-list cache are independent and only eventually
// consistent: a write invalidates the name list, and List is authoritative for
// membership while per-record reads may briefly disagree (store.List tolerates a
// per-name miss). A monotonic sequence guards against a slow read-fill clobbering
// a newer write.
package cache

import (
	"context"
	"errors"
	"math/rand/v2"
	"slices"
	"sync"
	"time"

	"github.com/hashicorp/golang-lru/v2/expirable"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"golang.org/x/sync/singleflight"

	"github.com/kradalby/ts1p/backend"
)

// jitterFrac is the ± fraction applied to the TTL for each entry's lifetime.
const jitterFrac = 5 // 1/5 = 20%

// negTTLCap bounds how long a confirmed not-found is cached: long enough to
// absorb a crash-looping consumer, short enough that an out-of-band create
// appears promptly even before the warmer's next relist.
const negTTLCap = 30 * time.Second

// listKey is the fixed singleflight key for the List path (record fetches are
// keyed by "rec:"+name, which cannot collide with it).
const listKey = "list"

// cacheStaleServed counts reads served from a resident-but-expired entry because
// the inner backend was unavailable (stale-while-revalidate).
var cacheStaleServed = promauto.NewCounter(prometheus.CounterOpts{
	Name: "ts1p_cache_stale_served_total",
	Help: "Reads served from a resident-but-expired entry because 1Password was unavailable.",
})

// entry pairs a cached value with its jittered expiry. A zero expires means the
// entry never logically expires (ttl <= 0). A nil record value is a cached
// negative: the name was confirmed absent.
type entry[T any] struct {
	val     T
	expires time.Time
}

// Cache is an expiry-caching decorator around another backend.Backend.
type Cache struct {
	inner backend.Backend
	ttl   time.Duration
	now   func() time.Time // injectable clock; defaults to time.Now

	recs *expirable.LRU[string, entry[*backend.Record]]
	sf   singleflight.Group // coalesces concurrent record and list fetches

	mu    sync.Mutex
	seq   uint64           // bumped on every mutation; a read-fill caches only if it is unchanged
	names *entry[[]string] // cached List result; nil means none; guarded by mu
}

// New returns a Cache over inner. maxEntries bounds the number of cached records
// (0 means unbounded); ttl is the base lifetime of a cached record or name list
// (jittered ±20% per entry) before the inner backend is consulted again. ttl <= 0
// disables expiry (entries live until evicted or invalidated by a write).
//
// The records LRU is created with no TTL of its own — expiry is enforced per
// entry by live() — so it spawns no background sweeper goroutine. inner may be
// nil only if the caller restricts itself to the jitter helpers (the tests do).
func New(inner backend.Backend, maxEntries int, ttl time.Duration) *Cache {
	return &Cache{
		inner: inner,
		ttl:   ttl,
		now:   time.Now,
		recs:  expirable.NewLRU[string, entry[*backend.Record]](maxEntries, nil, 0),
	}
}

// TTL reports the base (un-jittered) cache lifetime, so the warmer can derive its
// refresh cadence from the same source of truth.
func (c *Cache) TTL() time.Duration { return c.ttl }

// randomLifetime returns the base TTL jittered by ±20% (0 when expiry is off).
func (c *Cache) randomLifetime() time.Duration {
	if c.ttl <= 0 {
		return 0
	}

	delta := c.ttl / jitterFrac
	//nolint:gosec // cache-spread jitter, not security-sensitive
	return c.ttl + rand.N(2*delta+1) - delta
}

// expiresAt returns the (jittered) expiry for a freshly cached entry, or the
// zero time when expiry is disabled (randomLifetime already guards ttl <= 0).
func (c *Cache) expiresAt() time.Time {
	d := c.randomLifetime()
	if d <= 0 {
		return time.Time{}
	}

	return c.now().Add(d)
}

// live reports whether an entry with the given expiry is still servable.
func (c *Cache) live(expires time.Time) bool {
	return expires.IsZero() || c.now().Before(expires)
}

// snapshot returns the current mutation sequence, used by a read-fill to detect
// a write that intervened while it was fetching.
func (c *Cache) snapshot() uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.seq
}

// store caches r for name unless a write intervened since seq was taken.
func (c *Cache) store(name string, r *backend.Record, seq uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.seq == seq {
		c.recs.Add(name, entry[*backend.Record]{val: r.Clone(), expires: c.expiresAt()})
	}
}

// storeNegative records a confirmed not-found: it evicts any resident value —
// so the stale fallback cannot resurrect a deleted secret — and caches the
// negative briefly. With expiry disabled there is no warmer relist to discover
// an out-of-band create, so the negative is not cached at all and misses keep
// consulting the inner backend promptly.
func (c *Cache) storeNegative(name string, seq uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.seq != seq {
		return
	}

	if c.ttl <= 0 {
		c.recs.Remove(name)
		return
	}

	c.recs.Add(name, entry[*backend.Record]{expires: c.now().Add(min(c.ttl/10, negTTLCap))})
}

// Load returns the cached record if present, unexpired, and not force-refreshed,
// otherwise fetches it from the inner backend (coalescing concurrent misses) and
// caches it. Records are cloned in and out so a caller can mutate the result
// without disturbing the cache.
func (c *Cache) Load(ctx context.Context, name string) (*backend.Record, error) {
	force := backend.ForceRefresh(ctx)
	if !force {
		if e, ok := c.recs.Get(name); ok && c.live(e.expires) {
			if e.val == nil {
				return nil, backend.ErrNotFound
			}

			return e.val.Clone(), nil
		}
	}

	v, err, _ := c.sf.Do("rec:"+name, func() (any, error) {
		seq := c.snapshot()
		// Detach the fetch from the caller that won the flight: its disconnect
		// must not fail the shared result for coalesced waiters or discard a
		// fetch that succeeded. WithoutCancel keeps the ForceRefresh value, and
		// the inner backend bounds the call with its own deadline.
		r, err := c.inner.Load(context.WithoutCancel(ctx), name)
		if errors.Is(err, backend.ErrNotFound) {
			c.storeNegative(name, seq)
		}

		if err != nil {
			return nil, err
		}

		c.store(name, r, seq)

		return r, nil
	})
	if err != nil {
		// Serve a resident (possibly expired) value rather than failing an
		// ordinary read during an inner outage. Forced readers (the warmer,
		// Cache-Control: no-cache) get fresh-or-fail instead, so an outage
		// stays visible to exactly the callers that demanded freshness.
		if !force && errors.Is(err, backend.ErrUnavailable) {
			if e, ok := c.recs.Peek(name); ok && e.val != nil {
				cacheStaleServed.Inc()
				return e.val.Clone(), nil
			}
		}

		return nil, err
	}

	r, _ := v.(*backend.Record) // always a *backend.Record: the closure only returns one on success

	return r.Clone(), nil
}

// Save writes through to the inner backend, then refreshes the cache.
func (c *Cache) Save(ctx context.Context, name string, r *backend.Record) error {
	err := c.inner.Save(ctx, name, r)
	if err != nil {
		return err
	}

	c.mu.Lock()
	c.seq++
	c.recs.Add(name, entry[*backend.Record]{val: r.Clone(), expires: c.expiresAt()})
	// Conservatively drop the name list on every write: Save cannot tell a create
	// (which changes membership) from an update, and an eviction race makes an
	// unconditional invalidation the safer default.
	c.names = nil
	c.mu.Unlock()

	return nil
}

// List returns the cached name list if present, unexpired, and not
// force-refreshed, otherwise fetches it (coalescing concurrent misses).
func (c *Cache) List(ctx context.Context) ([]string, error) {
	force := backend.ForceRefresh(ctx)
	if !force {
		c.mu.Lock()
		if c.names != nil && c.live(c.names.expires) {
			names := slices.Clone(c.names.val)
			c.mu.Unlock()

			return names, nil
		}
		c.mu.Unlock()
	}

	v, err, _ := c.sf.Do(listKey, func() (any, error) {
		seq := c.snapshot()
		// Detached from the winning caller for the same reason as Load.
		names, err := c.inner.List(context.WithoutCancel(ctx))
		if err != nil {
			return nil, err
		}

		c.mu.Lock()
		if c.seq == seq {
			c.names = &entry[[]string]{val: slices.Clone(names), expires: c.expiresAt()}
		}
		c.mu.Unlock()

		return names, nil
	})
	if err != nil {
		if !force && errors.Is(err, backend.ErrUnavailable) {
			c.mu.Lock()
			defer c.mu.Unlock()

			if c.names != nil {
				cacheStaleServed.Inc()
				return slices.Clone(c.names.val), nil
			}
		}

		return nil, err
	}

	names, _ := v.([]string) // always a []string: the closure only returns one on success

	return slices.Clone(names), nil
}

// Delete writes through to the inner backend, then evicts the cached record and
// name list.
func (c *Cache) Delete(ctx context.Context, name string) error {
	err := c.inner.Delete(ctx, name)
	if err != nil {
		return err
	}

	c.Remove(name)
	c.mu.Lock()
	c.names = nil
	c.mu.Unlock()

	return nil
}

// Remove evicts name from the record cache without touching the inner backend.
// The warmer calls it when the authoritative name list no longer contains the
// name, so a secret deleted out-of-band cannot keep being served until its TTL.
// The seq bump stops an in-flight read-fill from resurrecting the evicted record.
func (c *Cache) Remove(name string) {
	c.mu.Lock()
	c.seq++
	c.recs.Remove(name)
	c.mu.Unlock()
}

// Purge drops every cached entry, forcing the next reads to refetch from the
// inner backend. It does not touch the inner backend itself.
func (c *Cache) Purge() {
	c.mu.Lock()
	c.seq++
	c.recs.Purge()
	c.names = nil
	c.mu.Unlock()
}

// Close closes the inner backend.
func (c *Cache) Close() error { return c.inner.Close() }

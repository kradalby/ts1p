package cache_test

import (
	"context"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/tailscale/setec/types/api"

	"github.com/kradalby/ts1p/backend"
	"github.com/kradalby/ts1p/backend/cache"
	"github.com/kradalby/ts1p/backend/mem"
)

// counting wraps a backend and counts calls, to prove the cache hits and misses
// the inner backend as expected.
type counting struct {
	inner               backend.Backend
	loads, lists, saves atomic.Int64
}

func (c *counting) Load(ctx context.Context, name string) (*backend.Record, error) {
	c.loads.Add(1)
	return c.inner.Load(ctx, name)
}

func (c *counting) Save(ctx context.Context, name string, r *backend.Record) error {
	c.saves.Add(1)
	return c.inner.Save(ctx, name, r)
}

func (c *counting) List(ctx context.Context) ([]string, error) {
	c.lists.Add(1)
	return c.inner.List(ctx)
}

func (c *counting) Delete(ctx context.Context, name string) error { return c.inner.Delete(ctx, name) }
func (c *counting) Close() error                                  { return c.inner.Close() }

func rec(name, val string) *backend.Record {
	return &backend.Record{
		Name:     name,
		Versions: map[api.SecretVersion][]byte{1: []byte(val)},
		Active:   1,
		Latest:   1,
	}
}

func TestCacheHitsAndInvalidation(t *testing.T) {
	ctx := context.Background()
	mb := mem.New()
	cnt := &counting{inner: mb}
	c := cache.New(cnt, 0, time.Hour) // long TTL: no expiry during test

	// Seed the inner backend directly so the cache starts cold for "a".
	require.NoError(t, mb.Save(ctx, "a", rec("a", "1")))

	// First load is a miss; second is served from cache.
	_, err := c.Load(ctx, "a")
	require.NoError(t, err)
	got, err := c.Load(ctx, "a")
	require.NoError(t, err)
	require.Equal(t, []byte("1"), got.Versions[1])
	require.EqualValues(t, 1, cnt.loads.Load(), "second load should hit cache")

	// Save refreshes the cache without a load.
	require.NoError(t, c.Save(ctx, "a", rec("a", "2")))
	got, err = c.Load(ctx, "a")
	require.NoError(t, err)
	require.Equal(t, []byte("2"), got.Versions[1])
	require.EqualValues(t, 1, cnt.loads.Load(), "save should have refreshed cache")

	// List is cached; a Save invalidates it.
	_, err = c.List(ctx)
	require.NoError(t, err)
	_, err = c.List(ctx)
	require.NoError(t, err)
	require.EqualValues(t, 1, cnt.lists.Load(), "second list should hit cache")

	require.NoError(t, c.Save(ctx, "b", rec("b", "1")))
	names, err := c.List(ctx)
	require.NoError(t, err)
	require.ElementsMatch(t, []string{"a", "b"}, names)
	require.EqualValues(t, 2, cnt.lists.Load(), "save should have invalidated list cache")

	// Delete evicts the record and invalidates the name list.
	require.NoError(t, c.Delete(ctx, "a"))

	before := cnt.loads.Load()
	_, err = c.Load(ctx, "a")
	require.ErrorIs(t, err, backend.ErrNotFound)
	require.Equal(t, before+1, cnt.loads.Load(), "delete should have evicted, forcing a load")
	listsBefore := cnt.lists.Load()
	names, err = c.List(ctx)
	require.NoError(t, err)
	require.ElementsMatch(t, []string{"b"}, names)
	require.Equal(t, listsBefore+1, cnt.lists.Load(), "delete should have invalidated the list cache")
}

// TestForceRefreshBypassesCache: a read carrying backend.WithForceRefresh must
// skip the cache, refetch from the inner backend, and refresh the cached value
// (so a secret edited out-of-band in 1Password can be picked up on demand).
func TestForceRefreshBypassesCache(t *testing.T) {
	ctx := context.Background()
	mb := mem.New()
	cnt := &counting{inner: mb}
	c := cache.New(cnt, 0, time.Hour) // long TTL: nothing expires during the test

	require.NoError(t, mb.Save(ctx, "a", rec("a", "1")))

	// Warm the cache.
	got, err := c.Load(ctx, "a")
	require.NoError(t, err)
	require.Equal(t, []byte("1"), got.Versions[1])
	require.EqualValues(t, 1, cnt.loads.Load())

	// Change the value out-of-band, straight in the inner backend.
	require.NoError(t, mb.Save(ctx, "a", rec("a", "2")))

	// A normal Load is still served stale from cache.
	got, err = c.Load(ctx, "a")
	require.NoError(t, err)
	require.Equal(t, []byte("1"), got.Versions[1], "normal load stays cached")
	require.EqualValues(t, 1, cnt.loads.Load(), "normal load does not hit inner")

	// A force-refresh Load bypasses the cache and refetches.
	got, err = c.Load(backend.WithForceRefresh(ctx), "a")
	require.NoError(t, err)
	require.Equal(t, []byte("2"), got.Versions[1], "force refresh sees the new value")
	require.EqualValues(t, 2, cnt.loads.Load(), "force refresh hits inner")

	// ...and updates the cache, so the next normal Load is served fresh.
	got, err = c.Load(ctx, "a")
	require.NoError(t, err)
	require.Equal(t, []byte("2"), got.Versions[1], "refresh updated the cache")
	require.EqualValues(t, 2, cnt.loads.Load(), "served from cache again")
}

// TestPurgeClearsEverything: Purge drops every cached record and the name list,
// so the next reads go back to the inner backend.
func TestPurgeClearsEverything(t *testing.T) {
	ctx := context.Background()
	cnt := &counting{inner: mem.New()}
	c := cache.New(cnt, 0, time.Hour)

	require.NoError(t, c.Save(ctx, "a", rec("a", "1"))) // record cached, names invalidated
	_, err := c.List(ctx)                               // name list cached
	require.NoError(t, err)

	loadsBefore, listsBefore := cnt.loads.Load(), cnt.lists.Load()

	c.Purge()

	_, err = c.Load(ctx, "a")
	require.NoError(t, err)
	require.Greater(t, cnt.loads.Load(), loadsBefore, "purge forces a reload")

	_, err = c.List(ctx)
	require.NoError(t, err)
	require.Greater(t, cnt.lists.Load(), listsBefore, "purge forces a relist")
}

func TestCacheExpiry(t *testing.T) {
	// A synctest bubble makes expiry exact instead of polled: the bubble's fake
	// clock jumps straight past the TTL, and synctest.Sleep also waits for the
	// bubble's goroutines to settle, so one assertion replaces a 2s poll loop.
	// Lifetime is the TTL jittered by +/-20%, so the longest possible life is
	// 36ms and 40ms clears it.
	synctest.Test(t, func(t *testing.T) {
		ctx := t.Context()
		cnt := &counting{inner: mem.New()}
		c := cache.New(cnt, 0, 30*time.Millisecond)

		require.NoError(t, c.Save(ctx, "a", rec("a", "1")))
		_, err := c.Load(ctx, "a") // populate cache
		require.NoError(t, err)

		first := cnt.loads.Load()

		synctest.Sleep(40 * time.Millisecond)

		// After the TTL elapses, a load must consult the inner backend again.
		_, err = c.Load(ctx, "a")
		require.NoError(t, err)
		require.Greater(t, cnt.loads.Load(), first, "cache entry should expire and refetch")
	})
}

// TestEvictionRefetches: an entry pushed out by the maxEntries bound is gone, so
// the next read of it consults the inner backend again.
func TestEvictionRefetches(t *testing.T) {
	ctx := context.Background()
	mb := mem.New()
	require.NoError(t, mb.Save(ctx, "a", rec("a", "1")))
	require.NoError(t, mb.Save(ctx, "b", rec("b", "1")))
	cnt := &counting{inner: mb}
	c := cache.New(cnt, 1, time.Hour) // capacity 1

	_, err := c.Load(ctx, "a") // miss -> cache a
	require.NoError(t, err)
	_, err = c.Load(ctx, "b") // miss -> cache b, evicting a
	require.NoError(t, err)

	before := cnt.loads.Load()
	_, err = c.Load(ctx, "a") // a was evicted -> miss
	require.NoError(t, err)
	require.Equal(t, before+1, cnt.loads.Load(), "evicted entry must refetch")
}

// TestNegativeCached: a missing name is cached briefly (so a crash-looping
// consumer cannot hammer the inner backend), and a create through the cache
// replaces the negative immediately — no waiting out its lifetime.
func TestNegativeCached(t *testing.T) {
	ctx := context.Background()
	cnt := &counting{inner: mem.New()}
	c := cache.New(cnt, 0, time.Hour)

	_, err := c.Load(ctx, "nope")
	require.ErrorIs(t, err, backend.ErrNotFound)
	_, err = c.Load(ctx, "nope")
	require.ErrorIs(t, err, backend.ErrNotFound)
	require.EqualValues(t, 1, cnt.loads.Load(), "repeated misses are absorbed by the cached negative")

	require.NoError(t, c.Save(ctx, "nope", rec("nope", "1")))
	got, err := c.Load(ctx, "nope")
	require.NoError(t, err, "a create through the cache replaces the negative")
	require.Equal(t, []byte("1"), got.Versions[1])
	require.EqualValues(t, 1, cnt.loads.Load(), "the created secret is served from cache")
}

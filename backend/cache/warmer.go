package cache

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/cenkalti/backoff/v5"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/kradalby/ts1p/backend"
)

// warmRefreshFrac is the fraction of the base TTL after which the warmer re-reads
// an entry. It must sit below the cache's minimum jittered lifetime (1-1/jitterFrac,
// i.e. 80%) so a refresh always lands before the entry can expire. The warmer
// anchors each key's next refresh to when that key was last warmed, not to a
// global pass, so per-call latency and list reordering cannot stretch the gap.
const warmRefreshFrac = 0.75

// warmRetryGap is how soon a failed refresh is retried, well inside the jitter
// floor so one transient failure does not strand an entry past its expiry.
const warmRetryGap = 5 * time.Second

var (
	cacheWarms = promauto.NewCounter(prometheus.CounterOpts{
		Name: "ts1p_cache_warm_total",
		Help: "Background cache refreshes that succeeded.",
	})
	cacheWarmFails = promauto.NewCounter(prometheus.CounterOpts{
		Name: "ts1p_cache_warm_fail_total",
		Help: "Background cache refreshes that failed.",
	})
	cacheLastWarm = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "ts1p_cache_last_warm_timestamp_seconds",
		Help: "Unix time of the last successful background cache refresh.",
	})
	cacheLastWarmErr = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "ts1p_cache_last_warm_error_timestamp_seconds",
		Help: "Unix time of the last failed background cache refresh.",
	})
)

// Warmer keeps a Cache warm in the background so cold reads never land on the
// request path. It refreshes each secret a fixed lead (warmRefreshFrac of the
// TTL) before that secret's own expiry — one at a time, so the password manager's
// single-threaded core is only ever driven off-request and is never stampeded by
// a burst of expiries.
type Warmer struct {
	c            *Cache
	log          *slog.Logger
	refreshAhead time.Duration
	retryGap     time.Duration
	reprime      chan struct{}
	done         chan struct{}
}

// NewWarmer returns a Warmer for c. The refresh cadence is derived from c.TTL(),
// so the cache is the single source of truth for the lifetime the warmer races.
func NewWarmer(c *Cache, log *slog.Logger) *Warmer {
	if log == nil {
		log = slog.Default()
	}

	refreshAhead := time.Duration(float64(c.TTL()) * warmRefreshFrac)

	return &Warmer{
		c:            c,
		log:          log,
		refreshAhead: refreshAhead,
		// Retry a failed refresh well before the normal cadence, but never wait
		// longer than the cap (relevant only for very short TTLs in tests).
		retryGap: min(warmRetryGap, refreshAhead/3),
		reprime:  make(chan struct{}, 1),
		done:     make(chan struct{}),
	}
}

// Run warms the cache until ctx is done. It returns immediately (warming nothing)
// when the cache has no positive expiry, since entries then never expire.
func (w *Warmer) Run(ctx context.Context) {
	defer close(w.done)

	if w.refreshAhead <= 0 {
		w.log.Info("cache warmer: disabled (cache expiry is not positive; entries never expire)")
		return
	}

	w.loop(ctx)
}

// Wait blocks until Run has returned, so shutdown can order warmer teardown
// before closing the backend (no in-flight core call outliving Close).
func (w *Warmer) Wait() { <-w.done }

// Reprime asks the warmer to re-warm every secret promptly, e.g. after a cache
// flush leaves it cold. Non-blocking and coalescing.
func (w *Warmer) Reprime() {
	select {
	case w.reprime <- struct{}{}:
	default:
	}
}

// loop drives per-key refresh deadlines plus a periodic membership relist.
func (w *Warmer) loop(ctx context.Context) {
	next := map[string]time.Time{} // name -> when it must be re-warmed
	relistAt := time.Now()         // force an immediate prefetch
	listBO := backoff.NewExponentialBackOff()

	for {
		if ctx.Err() != nil {
			return
		}

		// Refresh membership on its own cadence (force-refreshed, so out-of-band
		// creates and deletes are discovered deterministically, not via traffic).
		if !time.Now().Before(relistAt) {
			names, err := w.list(ctx)
			if err != nil {
				if !w.wait(ctx, listBO.NextBackOff()) {
					return
				}

				continue
			}

			listBO.Reset()
			w.reconcile(next, names)
			relistAt = time.Now().Add(w.refreshAhead)
		}

		// Warm every key whose deadline has passed, anchoring its next refresh to
		// the moment it was actually (re)read.
		for name, deadline := range next {
			if ctx.Err() != nil {
				return
			}

			if time.Now().Before(deadline) {
				continue
			}

			err := w.warm(ctx, name)
			switch {
			case err == nil:
				next[name] = time.Now().Add(w.refreshAhead)
			case errors.Is(err, backend.ErrNotFound):
				// Deleted out-of-band (the forced Load already evicted it from
				// the cache): stop warming; the relist re-adds it if it returns.
				delete(next, name)
			case errors.Is(err, backend.ErrRateLimited):
				// Fast-retrying a quota only keeps us pinned at it.
				next[name] = time.Now().Add(w.refreshAhead)
			case errors.Is(err, backend.ErrUnavailable):
				next[name] = time.Now().Add(w.retryGap) // transient: retry inside the jitter floor
			default:
				// Permanent-looking (e.g. a corrupt item): fast-retrying cannot
				// help, so park it until its normal cadence to spare the backend.
				next[name] = time.Now().Add(w.refreshAhead)
			}
		}

		select {
		case <-ctx.Done():
			return
		case <-w.reprime:
			now := time.Now()
			for name := range next {
				next[name] = now // re-warm everything after a flush
			}

			relistAt = now
		case <-time.After(time.Until(earliest(next, relistAt))):
		}
	}
}

// reconcile adds newly-seen names (due immediately) and drops names that are
// gone — evicting the latter from the cache too, so a secret deleted out-of-band
// stops being served at the next relist instead of lingering until its TTL.
func (w *Warmer) reconcile(next map[string]time.Time, names []string) {
	now := time.Now()

	live := make(map[string]struct{}, len(names))
	for _, name := range names {
		live[name] = struct{}{}
		if _, ok := next[name]; !ok {
			next[name] = now
		}
	}

	for name := range next {
		if _, ok := live[name]; !ok {
			delete(next, name)
			w.c.Remove(name)
		}
	}
}

// earliest returns the soonest deadline among the keys and the relist time.
func earliest(next map[string]time.Time, relistAt time.Time) time.Time {
	soonest := relistAt
	for _, t := range next {
		if t.Before(soonest) {
			soonest = t
		}
	}

	return soonest
}

// list re-reads the secret names through the cache, forcing a fresh read so the
// warmer's view of membership does not itself go stale.
func (w *Warmer) list(ctx context.Context) ([]string, error) {
	names, err := w.c.List(backend.WithForceRefresh(ctx))
	if err != nil {
		w.log.Warn("cache warmer: list failed", "err", err)
		return nil, err
	}

	return names, nil
}

// warm force-refreshes one secret through the cache. The error class decides
// how soon the loop retries it.
func (w *Warmer) warm(ctx context.Context, name string) error {
	err := ctx.Err()
	if err != nil {
		return err
	}

	_, err = w.c.Load(backend.WithForceRefresh(ctx), name)
	if err != nil {
		w.log.Warn("cache warmer: refresh failed", "name", name, "err", err)
		cacheWarmFails.Inc()
		cacheLastWarmErr.SetToCurrentTime()

		return err
	}

	cacheWarms.Inc()
	cacheLastWarm.SetToCurrentTime()

	return nil
}

// wait sleeps for d or until ctx is done; it reports false if ctx was cancelled.
func (w *Warmer) wait(ctx context.Context, d time.Duration) bool {
	if d < 0 {
		d = 0
	}

	t := time.NewTimer(d)
	defer t.Stop()

	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

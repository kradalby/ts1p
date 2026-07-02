package server

import (
	"log/slog"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/kradalby/ts1p/backend/cache"
)

// FlushCacheHandler drops the entire read cache on POST, then asks the warmer
// (if any) to re-prime it so the flush does not leave a cold cliff. A flush
// within one cache TTL of the previous one is debounced (202) so a tight loop
// cannot hold the cache perpetually cold against the single-threaded core; the
// debounce window is a tenth of the TTL (capped at a minute) so an operator
// making several out-of-band edits in a row is not locked out for a whole TTL.
func FlushCacheHandler(c *cache.Cache, warmer *cache.Warmer, log *slog.Logger) http.HandlerFunc {
	var lastFlush atomic.Int64 // unix-nanos of the last accepted flush

	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST required", http.StatusMethodNotAllowed)
			return
		}

		now := time.Now()

		window := min(c.TTL()/10, time.Minute)
		if last := lastFlush.Load(); last != 0 && window > 0 && now.Sub(time.Unix(0, last)) < window {
			w.WriteHeader(http.StatusAccepted) // debounced: a recent flush already dropped the cache
			return
		}

		lastFlush.Store(now.UnixNano())
		c.Purge()

		if warmer != nil {
			warmer.Reprime()
		}

		log.Info("1Password read cache flushed via /debug/flush-cache")
		w.WriteHeader(http.StatusNoContent)
	}
}

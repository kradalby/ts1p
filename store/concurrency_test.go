package store_test

import (
	"context"
	"fmt"
	"slices"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tailscale/setec/types/api"

	"github.com/kradalby/ts1p/backend/mem"
	"github.com/kradalby/ts1p/store"
)

// TestConcurrentPutsNoLostUpdate: the store's write mutex must serialize the
// load-mutate-save sequence so concurrent Puts of distinct values to one secret
// all land — none is lost to a racing latest++. Run under -race.
func TestConcurrentPutsNoLostUpdate(t *testing.T) {
	ctx := context.Background()
	s := store.New(mem.New())

	const n = 20

	var wg sync.WaitGroup
	for i := range n {
		wg.Go(func() {
			_, err := s.Put(ctx, "k", []byte(fmt.Sprintf("v%d", i)))
			assert.NoError(t, err)
		})
	}

	wg.Wait()

	info, err := s.Info(ctx, "k")
	require.NoError(t, err)
	require.Len(t, info.Versions, n, "every distinct concurrent put must produce a version; none lost")
}

// TestPutDedupWithDeletedLatest: when the latest version has been deleted, a Put
// must not de-duplicate against it (it is gone), and must never return a deleted
// version as the current one — including the empty-value case.
func TestPutDedupWithDeletedLatest(t *testing.T) {
	ctx := context.Background()
	s := store.New(mem.New())

	_, err := s.Put(ctx, "k", []byte("a")) // v1, active
	require.NoError(t, err)
	_, err = s.Put(ctx, "k", []byte("b")) // v2, latest, inactive
	require.NoError(t, err)
	require.NoError(t, s.Activate(ctx, "k", 1))      // active stays 1
	require.NoError(t, s.DeleteVersion(ctx, "k", 2)) // delete the latest version

	live := func(v api.SecretVersion) bool {
		info, err := s.Info(ctx, "k")
		require.NoError(t, err)

		return slices.Contains(info.Versions, v)
	}

	v, err := s.Put(ctx, "k", []byte("c"))
	require.NoError(t, err)
	require.Greater(t, v, api.SecretVersion(2), "put must move past the deleted latest")
	require.True(t, live(v), "returned version must be live")

	// The empty value must not collide with the absent (deleted) latest slot.
	v, err = s.Put(ctx, "k", nil)
	require.NoError(t, err)
	require.True(t, live(v), "empty put must return a live version, not the deleted latest")
}

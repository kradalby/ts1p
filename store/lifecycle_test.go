package store_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/tailscale/setec/types/api"

	"github.com/kradalby/ts1p/backend/mem"
	"github.com/kradalby/ts1p/store"
)

// These mirror setec's db/db_test.go scenarios at the store layer, giving
// explicit, named parity with setec's own version-semantics tests in addition
// to the randomized invariant and differential suites.

func newStore() (context.Context, *store.Store) {
	return context.Background(), store.New(mem.New())
}

func TestCreate(t *testing.T) {
	ctx, s := newStore()

	v, err := s.Put(ctx, "test", []byte("foo"))
	require.NoError(t, err)
	require.Equal(t, api.SecretVersion(1), v)

	sv, err := s.Get(ctx, "test")
	require.NoError(t, err)
	require.Equal(t, []byte("foo"), sv.Value)
	require.Equal(t, api.SecretVersion(1), sv.Version)
}

func TestPutDedupAndIncrement(t *testing.T) {
	ctx, s := newStore()
	v1, v2 := []byte("value1"), []byte("value2")

	ver1, err := s.Put(ctx, "k", v1)
	require.NoError(t, err)
	require.Equal(t, api.SecretVersion(1), ver1)

	// Same value as the latest version de-duplicates to the same version.
	ver2, err := s.Put(ctx, "k", v1)
	require.NoError(t, err)
	require.Equal(t, ver1, ver2)

	// A different value creates a new (inactive) version.
	ver3, err := s.Put(ctx, "k", v2)
	require.NoError(t, err)
	require.Equal(t, api.SecretVersion(2), ver3)

	// value1 again — but the latest is now value2, so it is a fresh version.
	ver4, err := s.Put(ctx, "k", v1)
	require.NoError(t, err)
	require.Equal(t, api.SecretVersion(3), ver4)

	// Active is unchanged by inactive puts.
	sv, err := s.Get(ctx, "k")
	require.NoError(t, err)
	require.Equal(t, api.SecretVersion(1), sv.Version)
}

// TestPutAfterDeletedLatest pins a deliberate divergence from setec: setec
// dedups a Put against Versions[Latest] even when the latest version was
// deleted, so an empty Put matches the missing key's zero value and returns
// the deleted version number — which then 404s on Get. ts1p dedups only
// against a live latest and allocates a fresh version instead: strictly better
// for clients. Kept out of the differential suite by design; this is the pin.
func TestPutAfterDeletedLatest(t *testing.T) {
	ctx, s := newStore()

	_, err := s.Put(ctx, "k", []byte("one"))
	require.NoError(t, err)
	v2, err := s.Put(ctx, "k", []byte("two")) // latest, inactive
	require.NoError(t, err)
	require.NoError(t, s.DeleteVersion(ctx, "k", v2)) // latest is now deleted

	v3, err := s.Put(ctx, "k", nil) // empty value: setec would return the deleted v2
	require.NoError(t, err)
	require.Equal(t, v2+1, v3, "a deleted latest must not satisfy dedup")

	sv, err := s.GetVersion(ctx, "k", v3)
	require.NoError(t, err)
	require.Empty(t, sv.Value)
}

func TestGetAndGetVersion(t *testing.T) {
	ctx, s := newStore()
	_, _ = s.Put(ctx, "k", []byte("v1"))
	_, _ = s.Put(ctx, "k", []byte("v2"))

	// Active version.
	sv, err := s.Get(ctx, "k")
	require.NoError(t, err)
	require.Equal(t, []byte("v1"), sv.Value)

	// Specific version.
	sv, err = s.GetVersion(ctx, "k", 2)
	require.NoError(t, err)
	require.Equal(t, []byte("v2"), sv.Value)

	// Missing version and missing secret.
	_, err = s.GetVersion(ctx, "k", 99)
	require.ErrorIs(t, err, api.ErrNotFound)
	_, err = s.Get(ctx, "missing")
	require.ErrorIs(t, err, api.ErrNotFound)
}

func TestListAndInfo(t *testing.T) {
	ctx, s := newStore()
	_, _ = s.Put(ctx, "test", []byte("foo"))
	_, _ = s.Put(ctx, "test", []byte("bar"))
	_, _ = s.Put(ctx, "test2", []byte("quux"))
	require.NoError(t, s.Activate(ctx, "test", 2))

	infos, err := s.List(ctx, nil)
	require.NoError(t, err)
	require.Len(t, infos, 2)
	require.Equal(t, "test", infos[0].Name) // sorted by name
	require.Equal(t, []api.SecretVersion{1, 2}, infos[0].Versions)
	require.Equal(t, api.SecretVersion(2), infos[0].ActiveVersion)
	require.Equal(t, "test2", infos[1].Name)

	info, err := s.Info(ctx, "test")
	require.NoError(t, err)
	require.Equal(t, api.SecretVersion(2), info.ActiveVersion)
}

func TestCreateVersion(t *testing.T) {
	const year2099 = api.SecretVersion(4070908800)

	t.Run("create_claim_disjoint", func(t *testing.T) {
		ctx, s := newStore()
		require.NoError(t, s.CreateVersion(ctx, "k", 1, []byte("v1")))

		require.NoError(t, s.CreateVersion(ctx, "k", year2099, []byte("v2")))
		// Active follows the created version; latest is the max.
		sv, err := s.Get(ctx, "k")
		require.NoError(t, err)
		require.Equal(t, year2099, sv.Version)

		// Recreating an existing version is rejected.
		require.ErrorIs(t, s.CreateVersion(ctx, "k", year2099, []byte("v2")), api.ErrVersionClaimed)

		// A lower, never-used version is allowed (disjoint).
		require.NoError(t, s.CreateVersion(ctx, "k", 100, []byte("v3")))
	})

	t.Run("create_on_new_secret", func(t *testing.T) {
		ctx, s := newStore()
		require.NoError(t, s.CreateVersion(ctx, "k", 100, []byte("v1")))
		sv, err := s.Get(ctx, "k")
		require.NoError(t, err)
		require.Equal(t, api.SecretVersion(100), sv.Version)
	})

	t.Run("zero_prohibited", func(t *testing.T) {
		ctx, s := newStore()
		require.ErrorIs(t, s.CreateVersion(ctx, "k", 0, []byte("v1")), store.ErrInvalidVersion)
	})

	t.Run("recreate_deleted_version_fails", func(t *testing.T) {
		ctx, s := newStore()
		require.NoError(t, s.CreateVersion(ctx, "k", 100, []byte("v1")))
		_, err := s.Put(ctx, "k", []byte("v2")) // adds an inactive version; active stays 100
		require.NoError(t, err)
		// Make another version active so 100 can be deleted.
		require.NoError(t, s.CreateVersion(ctx, "k", 50, []byte("v3"))) // active 50
		require.NoError(t, s.DeleteVersion(ctx, "k", 100))
		require.ErrorIs(t, s.CreateVersion(ctx, "k", 100, []byte("v4")), api.ErrVersionClaimed)
	})
}

func TestDelete(t *testing.T) {
	ctx, s := newStore()
	v1, err := s.Put(ctx, "k", []byte("ver1"))
	require.NoError(t, err)

	require.NoError(t, s.Delete(ctx, "k"))
	require.NoError(t, s.Delete(ctx, "k")) // missing is a no-op

	_, err = s.GetVersion(ctx, "k", v1)
	require.ErrorIs(t, err, api.ErrNotFound)
}

func TestDeleteVersion(t *testing.T) {
	ctx, s := newStore()
	v1, _ := s.Put(ctx, "k", []byte("version1")) // active
	v2, _ := s.Put(ctx, "k", []byte("version2"))

	// Unknown version.
	require.ErrorIs(t, s.DeleteVersion(ctx, "k", 1000), api.ErrNotFound)

	// Active version cannot be deleted (setec returns a plain error here).
	require.Error(t, s.DeleteVersion(ctx, "k", v1))

	// Inactive version deletes, and is then gone.
	require.NoError(t, s.DeleteVersion(ctx, "k", v2))
	_, err := s.GetVersion(ctx, "k", v2)
	require.ErrorIs(t, err, api.ErrNotFound)

	// Version 0 is invalid.
	require.Error(t, s.DeleteVersion(ctx, "k", 0))
}

func TestGetConditional(t *testing.T) {
	ctx, s := newStore()
	_, _ = s.Put(ctx, "k", []byte("v1"))

	// Same as active → not changed.
	_, err := s.GetConditional(ctx, "k", 1)
	require.ErrorIs(t, err, api.ErrValueNotChanged)

	// Different → returns the active value.
	sv, err := s.GetConditional(ctx, "k", 99)
	require.NoError(t, err)
	require.Equal(t, api.SecretVersion(1), sv.Version)
}

package store_test

import (
	"context"
	"fmt"
	"math/rand/v2"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/tailscale/setec/types/api"

	"github.com/kradalby/ts1p/backend"
	"github.com/kradalby/ts1p/backend/mem"
	"github.com/kradalby/ts1p/store"
)

// TestInvariants drives random operation sequences through the store and, after
// every step, asserts the invariants setec guarantees hold for every record.
// It also checks claimed-forever: any version live or deleted in the current
// record cannot be recreated (a full Delete, however, resets that history,
// which is why "claimed" is derived from the live record rather than
// accumulated across deletes).
func TestInvariants(t *testing.T) {
	ctx := context.Background()
	b := mem.New()
	s := store.New(b)

	names := []string{"alpha", "beta", "gamma"}
	rng := rand.New(rand.NewPCG(1, 2))

	for i := range 3000 {
		n := names[rng.IntN(len(names))]
		switch rng.IntN(6) {
		case 0:
			_, _ = s.Put(ctx, n, []byte(fmt.Sprintf("v%d", i)))
		case 1:
			_ = s.CreateVersion(ctx, n, rng.N(api.SecretVersion(8)), []byte(fmt.Sprintf("c%d", i)))
		case 2:
			_ = s.Activate(ctx, n, rng.N(api.SecretVersion(8)))
		case 3:
			_ = s.DeleteVersion(ctx, n, rng.N(api.SecretVersion(8)))
		case 4:
			_ = s.Delete(ctx, n)
		case 5:
			// Any version claimed in the current record must be unrecreatable.
			if r := load(t, b, n); r != nil {
				for _, v := range claimedVersions(r) {
					require.ErrorIsf(t, s.CreateVersion(ctx, n, v, []byte("reclaim")),
						api.ErrVersionClaimed, "recreating claimed version %d of %q", v, n)
				}
			}
		}

		if r := load(t, b, n); r != nil {
			checkRecord(t, r)
		}
	}
}

func claimedVersions(r *backend.Record) []api.SecretVersion {
	out := make([]api.SecretVersion, 0, len(r.Versions)+len(r.Deleted))
	for v := range r.Versions {
		out = append(out, v)
	}

	for v := range r.Deleted {
		out = append(out, v)
	}

	return out
}

func load(t *testing.T, b *mem.Backend, name string) *backend.Record {
	t.Helper()

	r, err := b.Load(context.Background(), name)
	if err != nil {
		return nil
	}

	return r
}

func checkRecord(t *testing.T, r *backend.Record) {
	t.Helper()
	require.NotEmpty(t, r.Versions, "a live record must have at least one version")

	// Active must point at a live version.
	_, ok := r.Versions[r.Active]
	require.Truef(t, ok, "active version %d not present in %q", r.Active, r.Name)

	// Latest is the high-water mark over all versions ever assigned.
	for v := range r.Versions {
		require.GreaterOrEqualf(t, r.Latest, v, "latest < live version %d in %q", v, r.Name)
		require.NotZero(t, v, "version 0 is reserved")
		_, deleted := r.Deleted[v]
		require.Falsef(t, deleted, "version %d is both live and deleted in %q", v, r.Name)
	}

	for v := range r.Deleted {
		require.GreaterOrEqualf(t, r.Latest, v, "latest < deleted version %d in %q", v, r.Name)
	}
}

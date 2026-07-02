package mem_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/tailscale/setec/types/api"

	"github.com/kradalby/ts1p/backend"
	"github.com/kradalby/ts1p/backend/mem"
)

func TestRoundTripAndIsolation(t *testing.T) {
	ctx := context.Background()
	b := mem.New()

	_, err := b.Load(ctx, "missing")
	require.ErrorIs(t, err, backend.ErrNotFound)

	rec := &backend.Record{
		Name:     "k",
		Versions: map[api.SecretVersion][]byte{1: []byte("one")},
		Active:   1,
		Latest:   1,
	}
	require.NoError(t, b.Save(ctx, "k", rec))

	// Mutating the saved-from record must not affect stored state.
	rec.Versions[1] = []byte("tampered")
	rec.Active = 99

	got, err := b.Load(ctx, "k")
	require.NoError(t, err)
	require.Equal(t, []byte("one"), got.Versions[1])
	require.Equal(t, api.SecretVersion(1), got.Active)

	// Mutating a loaded record must not affect stored state either.
	got.Versions[1] = []byte("tampered2")
	got2, err := b.Load(ctx, "k")
	require.NoError(t, err)
	require.Equal(t, []byte("one"), got2.Versions[1])

	names, err := b.List(ctx)
	require.NoError(t, err)
	require.Equal(t, []string{"k"}, names)

	require.NoError(t, b.Delete(ctx, "k"))
	require.NoError(t, b.Delete(ctx, "k")) // no-op
	_, err = b.Load(ctx, "k")
	require.ErrorIs(t, err, backend.ErrNotFound)
}

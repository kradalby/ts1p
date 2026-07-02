package onepassword_test

import (
	"context"
	"log/slog"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/tailscale/setec/types/api"

	"github.com/kradalby/ts1p/backend"
	"github.com/kradalby/ts1p/backend/onepassword"
	"github.com/kradalby/ts1p/store"
)

// TestIntegration exercises the 1Password backend against a real vault. It is
// skipped unless OP_SERVICE_ACCOUNT_TOKEN and TS1P_TEST_VAULT are set. The
// vault should be dedicated to testing: the test creates and deletes a secret
// named "ts1p-integration-test".
func TestIntegration(t *testing.T) {
	token := os.Getenv("OP_SERVICE_ACCOUNT_TOKEN")

	vault := os.Getenv("TS1P_TEST_VAULT")
	if token == "" || vault == "" {
		t.Skip("set OP_SERVICE_ACCOUNT_TOKEN and TS1P_TEST_VAULT to run the 1Password integration test")
	}

	ctx := context.Background()
	b, err := onepassword.New(ctx, token, vault, slog.Default(), 0)
	require.NoError(t, err)
	t.Cleanup(func() { _ = b.Close() })

	const name = "ts1p-integration-test"

	_ = b.Delete(ctx, name) // start clean

	t.Cleanup(func() { _ = b.Delete(ctx, name) })

	s := store.New(b)

	// Full version lifecycle through the store, exactly as the server would.
	v1, err := s.Put(ctx, name, []byte("one"))
	require.NoError(t, err)
	require.Equal(t, api.SecretVersion(1), v1)

	v2, err := s.Put(ctx, name, []byte("two"))
	require.NoError(t, err)
	require.Equal(t, api.SecretVersion(2), v2)

	sv, err := s.Get(ctx, name)
	require.NoError(t, err)
	require.Equal(t, []byte("one"), sv.Value, "active should still be v1")

	require.NoError(t, s.Activate(ctx, name, v2))
	sv, err = s.Get(ctx, name)
	require.NoError(t, err)
	require.Equal(t, []byte("two"), sv.Value)

	require.ErrorIs(t, s.CreateVersion(ctx, name, v1, []byte("x")), api.ErrVersionClaimed)

	info, err := s.Info(ctx, name)
	require.NoError(t, err)
	require.Equal(t, []api.SecretVersion{1, 2}, info.Versions)

	// Binary value round-trips losslessly via ts1p-meta.
	require.NoError(t, s.CreateVersion(ctx, name, 7, []byte{0x00, 0xff, 0x10}))
	sv, err = s.GetVersion(ctx, name, 7)
	require.NoError(t, err)
	require.Equal(t, []byte{0x00, 0xff, 0x10}, sv.Value)

	require.NoError(t, s.Delete(ctx, name))
	_, err = s.Get(ctx, name)
	require.ErrorIs(t, err, backend.ErrNotFound)
}

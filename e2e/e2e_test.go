//go:build e2e

// Package e2e exercises the whole ts1p stack end to end: setec's real client →
// ts1p HTTP server → store → the 1Password backend, against a real vault. It is
// guarded by the e2e build tag and skips unless OP_SERVICE_ACCOUNT_TOKEN and
// TS1P_TEST_VAULT are set.
//
//	OP_SERVICE_ACCOUNT_TOKEN=... TS1P_TEST_VAULT=ts1p-test \
//	  go test -tags e2e ./e2e/...
package e2e

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/tailscale/setec/audit"
	"github.com/tailscale/setec/client/setec"
	"github.com/tailscale/setec/setectest"
	"github.com/tailscale/setec/types/api"

	"github.com/kradalby/ts1p/backend/cache"
	"github.com/kradalby/ts1p/backend/onepassword"
	"github.com/kradalby/ts1p/server"
	"github.com/kradalby/ts1p/store"
)

func TestEndToEnd(t *testing.T) {
	token := os.Getenv("OP_SERVICE_ACCOUNT_TOKEN")
	vault := os.Getenv("TS1P_TEST_VAULT")
	if token == "" || vault == "" {
		t.Skip("set OP_SERVICE_ACCOUNT_TOKEN and TS1P_TEST_VAULT to run the e2e test")
	}
	ctx := context.Background()

	be, err := onepassword.New(ctx, token, vault, slog.Default(), 0)
	require.NoError(t, err)
	cached := cache.New(be, 0, 0) // 0 TTL: always read through, so we see writes immediately
	t.Cleanup(func() { _ = cached.Close() })

	mux := http.NewServeMux()
	_, err = server.New(server.Config{
		Store: store.New(cached),
		WhoIs: setectest.AllAccess,
		Audit: audit.New(io.Discard),
		Mux:   mux,
	})
	require.NoError(t, err)
	hs := httptest.NewTestServer(t, mux)
	hc := hs.Client() // starts the in-memory network and populates hs.URL

	cli := setec.Client{Server: hs.URL, DoHTTP: hc.Do}

	const name = "ts1p-e2e-test"
	_ = cli.Delete(ctx, name)
	t.Cleanup(func() { _ = cli.Delete(ctx, name) })

	// Drive the full lifecycle through setec's real client against 1Password.
	v1, err := cli.Put(ctx, name, []byte("one"))
	require.NoError(t, err)
	require.Equal(t, api.SecretVersion(1), v1)

	v2, err := cli.Put(ctx, name, []byte("two"))
	require.NoError(t, err)
	require.Equal(t, api.SecretVersion(2), v2)

	sv, err := cli.Get(ctx, name)
	require.NoError(t, err)
	require.Equal(t, []byte("one"), sv.Value, "active should still be v1")

	require.NoError(t, cli.Activate(ctx, name, v2))
	sv, err = cli.Get(ctx, name)
	require.NoError(t, err)
	require.Equal(t, []byte("two"), sv.Value)

	require.ErrorIs(t, cli.CreateVersion(ctx, name, v1, []byte("x")), api.ErrVersionClaimed)

	info, err := cli.Info(ctx, name)
	require.NoError(t, err)
	require.Equal(t, []api.SecretVersion{1, 2}, info.Versions)

	require.NoError(t, cli.Delete(ctx, name))
	_, err = cli.Get(ctx, name)
	require.ErrorIs(t, err, api.ErrNotFound)
}

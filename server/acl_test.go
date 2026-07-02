package server_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/tailscale/setec/acl"
	"github.com/tailscale/setec/audit"
	"github.com/tailscale/setec/client/setec"
	"github.com/tailscale/setec/types/api"
	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/tailcfg"

	"github.com/kradalby/ts1p/backend/mem"
	"github.com/kradalby/ts1p/server"
	"github.com/kradalby/ts1p/store"
)

// whoIsRule returns a WhoIs function granting exactly the given ACL rule (or no
// access when rule is nil), so we can exercise ts1p's authorization the same way
// setec's server_test does.
func whoIsRule(t *testing.T, rule *acl.Rule) func(context.Context, string) (*apitype.WhoIsResponse, error) {
	t.Helper()

	var caps []tailcfg.RawMessage

	if rule != nil {
		b, err := json.Marshal(*rule)
		require.NoError(t, err)

		caps = []tailcfg.RawMessage{tailcfg.RawMessage(b)}
	}

	return func(context.Context, string) (*apitype.WhoIsResponse, error) {
		return &apitype.WhoIsResponse{
			Node:        &tailcfg.Node{Name: "node.example.com"},
			UserProfile: &tailcfg.UserProfile{ID: 1, LoginName: "user@example.com"},
			CapMap:      tailcfg.PeerCapMap{server.ACLCap: caps},
		}, nil
	}
}

// serverWith builds a ts1p server over st with the given identity.
func serverWith(t *testing.T, st *store.Store, whois func(context.Context, string) (*apitype.WhoIsResponse, error)) setec.Client {
	t.Helper()

	mux := http.NewServeMux()
	_, err := server.New(server.Config{Store: st, WhoIs: whois, Audit: audit.New(io.Discard), Mux: mux})
	require.NoError(t, err)

	hs := httptest.NewServer(mux)
	t.Cleanup(hs.Close)

	return setec.Client{Server: hs.URL, DoHTTP: hs.Client().Do}
}

func TestAccessControl(t *testing.T) {
	ctx := context.Background()

	rule := func(actions []acl.Action, secrets ...acl.Secret) *acl.Rule {
		return &acl.Rule{Action: actions, Secret: secrets}
	}

	t.Run("no_capability_denies", func(t *testing.T) {
		st := store.New(mem.New())
		_, err := st.Put(ctx, "s", []byte("v"))
		require.NoError(t, err)

		cli := serverWith(t, st, whoIsRule(t, nil))
		_, err = cli.Get(ctx, "s")
		require.ErrorIs(t, err, api.ErrAccessDenied)
	})

	t.Run("read_only", func(t *testing.T) {
		st := store.New(mem.New())
		_, err := st.Put(ctx, "s", []byte("v"))
		require.NoError(t, err)

		cli := serverWith(t, st, whoIsRule(t, rule([]acl.Action{acl.ActionGet, acl.ActionInfo}, "*")))

		// Reads are allowed.
		sv, err := cli.Get(ctx, "s")
		require.NoError(t, err)
		require.Equal(t, []byte("v"), sv.Value)

		_, err = cli.Info(ctx, "s")
		require.NoError(t, err)

		// Writes are denied.
		_, err = cli.Put(ctx, "s", []byte("v2"))
		require.ErrorIs(t, err, api.ErrAccessDenied)
		require.ErrorIs(t, cli.Delete(ctx, "s"), api.ErrAccessDenied)
	})

	t.Run("secret_scoped", func(t *testing.T) {
		st := store.New(mem.New())
		_, err := st.Put(ctx, "allowed/x", []byte("a"))
		require.NoError(t, err)
		_, err = st.Put(ctx, "other/y", []byte("b"))
		require.NoError(t, err)

		cli := serverWith(t, st, whoIsRule(t, rule([]acl.Action{acl.ActionGet}, "allowed/*")))

		sv, err := cli.Get(ctx, "allowed/x")
		require.NoError(t, err)
		require.Equal(t, []byte("a"), sv.Value)

		_, err = cli.Get(ctx, "other/y")
		require.ErrorIs(t, err, api.ErrAccessDenied)
	})

	t.Run("list_filters_by_capability", func(t *testing.T) {
		st := store.New(mem.New())
		_, err := st.Put(ctx, "allowed/x", []byte("a"))
		require.NoError(t, err)
		_, err = st.Put(ctx, "secret/y", []byte("b"))
		require.NoError(t, err)

		cli := serverWith(t, st, whoIsRule(t, rule([]acl.Action{acl.ActionInfo}, "allowed/*")))

		infos, err := cli.List(ctx)
		require.NoError(t, err)
		require.Len(t, infos, 1)
		require.Equal(t, "allowed/x", infos[0].Name)
	})
}

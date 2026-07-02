package server_test

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/tailscale/setec/acl"
	"github.com/tailscale/setec/audit"
	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/tailcfg"

	"github.com/kradalby/ts1p/backend/cache"
	"github.com/kradalby/ts1p/backend/mem"
	"github.com/kradalby/ts1p/server"
	"github.com/kradalby/ts1p/store"
)

// whoIsGrant returns a WhoIs granting exactly rule (or no grant when nil).
func whoIsGrant(t *testing.T, rule *acl.Rule) server.WhoIsFunc {
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
			UserProfile: &tailcfg.UserProfile{ID: 1, LoginName: "op@example.com"},
			CapMap:      tailcfg.PeerCapMap{server.ACLCap: caps},
		}, nil
	}
}

func newGateServer(t *testing.T, whois server.WhoIsFunc) *server.Server {
	t.Helper()

	srv, err := server.New(server.Config{
		Store: store.New(mem.New()),
		WhoIs: whois,
		Audit: audit.New(io.Discard),
		Mux:   http.NewServeMux(),
	})
	require.NoError(t, err)

	return srv
}

// AdminGate admits only a caller holding delete on "*" and requires the
// anti-CSRF header, auditing every attempt.
func TestAdminGate(t *testing.T) {
	deleteAll := &acl.Rule{Action: []acl.Action{acl.ActionDelete}, Secret: []acl.Secret{"*"}}
	readOnly := &acl.Rule{Action: []acl.Action{acl.ActionGet}, Secret: []acl.Secret{"*"}}
	// A wildcard in a grant is a pattern, but the gate's literal "*" name must
	// not be matchable by a merely-scoped delete grant.
	scopedDelete := &acl.Rule{Action: []acl.Action{acl.ActionDelete}, Secret: []acl.Secret{"prod/*"}}

	call := func(whois server.WhoIsFunc, withHeader bool) (int, bool) {
		reached := false
		next := func(w http.ResponseWriter, _ *http.Request) {
			reached = true

			w.WriteHeader(http.StatusNoContent)
		}
		h := newGateServer(t, whois).AdminGate(next)

		req := httptest.NewRequest(http.MethodPost, "/debug/flush-cache", nil)
		if withHeader {
			req.Header.Set("Sec-X-Tailscale-No-Browsers", "setec")
		}

		rec := httptest.NewRecorder()
		h(rec, req)

		return rec.Code, reached
	}

	t.Run("delete_grant_passes", func(t *testing.T) {
		code, reached := call(whoIsGrant(t, deleteAll), true)
		require.Equal(t, http.StatusNoContent, code)
		require.True(t, reached, "handler must run for an authorized operator")
	})
	t.Run("no_grant_denied", func(t *testing.T) {
		code, reached := call(whoIsGrant(t, readOnly), true)
		require.Equal(t, http.StatusForbidden, code)
		require.False(t, reached)
	})
	t.Run("scoped_delete_denied", func(t *testing.T) {
		code, reached := call(whoIsGrant(t, scopedDelete), true)
		require.Equal(t, http.StatusForbidden, code)
		require.False(t, reached, `a delete grant scoped to "prod/*" must not satisfy the gate's "*"`)
	})
	t.Run("missing_grant_denied", func(t *testing.T) {
		code, reached := call(whoIsGrant(t, nil), true)
		require.Equal(t, http.StatusForbidden, code)
		require.False(t, reached)
	})
	t.Run("missing_header_denied", func(t *testing.T) {
		code, reached := call(whoIsGrant(t, deleteAll), false)
		require.Equal(t, http.StatusForbidden, code)
		require.False(t, reached)
	})
}

func postFlush(h http.HandlerFunc, method string) int {
	rec := httptest.NewRecorder()
	h(rec, httptest.NewRequest(method, "/debug/flush-cache", nil))

	return rec.Code
}

// The flush-cache handler purges on POST, rejects other methods, and debounces
// a rapid second flush (a tenth of the TTL) so a tight loop cannot hold the
// cache cold — while an operator's later legitimate flush still goes through.
func TestFlushCacheHandler(t *testing.T) {
	c := cache.New(mem.New(), 0, time.Hour)
	h := server.FlushCacheHandler(c, nil, slog.Default())

	require.Equal(t, http.StatusMethodNotAllowed, postFlush(h, http.MethodGet), "GET must not flush")
	require.Equal(t, http.StatusNoContent, postFlush(h, http.MethodPost), "first POST flushes")
	require.Equal(t, http.StatusAccepted, postFlush(h, http.MethodPost), "immediate second POST is debounced")
}

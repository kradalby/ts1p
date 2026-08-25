package server_test

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/tailscale/setec/acl"
	"github.com/tailscale/setec/audit"
	"github.com/tailscale/setec/types/api"

	"github.com/kradalby/ts1p/backend"
	"github.com/kradalby/ts1p/server"
	"github.com/kradalby/ts1p/store"
)

// refreshSpy records whether the last Load saw a force-refresh context.
type refreshSpy struct{ forced atomic.Bool }

func (s *refreshSpy) Load(ctx context.Context, name string) (*backend.Record, error) {
	s.forced.Store(backend.ForceRefresh(ctx))

	return &backend.Record{
		Name:     name,
		Versions: map[api.SecretVersion][]byte{1: []byte("v")},
		Active:   1,
		Latest:   1,
	}, nil
}

func (s *refreshSpy) Save(context.Context, string, *backend.Record) error { return nil }
func (s *refreshSpy) List(context.Context) ([]string, error)              { return nil, nil }
func (s *refreshSpy) Delete(context.Context, string) error                { return nil }
func (s *refreshSpy) Close() error                                        { return nil }

// A get carrying "Cache-Control: no-cache" must force a fresh backend read;
// without it, the read uses the cache normally.
func TestNoCacheHeaderForcesRefresh(t *testing.T) {
	spy := &refreshSpy{}
	mux := http.NewServeMux()
	_, err := server.New(server.Config{
		Store: store.New(spy),
		WhoIs: whoIsRule(t, &acl.Rule{Action: []acl.Action{acl.ActionGet}, Secret: []acl.Secret{"*"}}),
		Audit: audit.New(io.Discard),
		Mux:   mux,
	})
	require.NoError(t, err)

	hs := httptest.NewTestServer(t, mux)
	hc := hs.Client() // starts the in-memory network and populates hs.URL

	get := func(noCache bool) bool {
		req, err := http.NewRequest(http.MethodPost, hs.URL+"/api/get", bytes.NewReader([]byte(`{"Name":"s"}`)))
		require.NoError(t, err)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Sec-X-Tailscale-No-Browsers", "setec")

		if noCache {
			req.Header.Set("Cache-Control", "no-cache")
		}

		resp, err := hc.Do(req)
		require.NoError(t, err)

		defer resp.Body.Close()

		require.Equal(t, http.StatusOK, resp.StatusCode)

		return spy.forced.Load()
	}

	require.False(t, get(false), "plain read must not force refresh")
	require.True(t, get(true), "Cache-Control: no-cache must force refresh")
}

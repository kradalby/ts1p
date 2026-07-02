package server_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/tailscale/setec/acl"
	"github.com/tailscale/setec/audit"
	"tailscale.com/client/tailscale/apitype"

	"github.com/kradalby/ts1p/backend/mem"
	"github.com/kradalby/ts1p/server"
	"github.com/kradalby/ts1p/store"
)

func serverURL(t *testing.T, whois func(context.Context, string) (*apitype.WhoIsResponse, error)) string {
	t.Helper()

	mux := http.NewServeMux()
	_, err := server.New(server.Config{Store: store.New(mem.New()), WhoIs: whois, Audit: audit.New(io.Discard), Mux: mux})
	require.NoError(t, err)

	hs := httptest.NewServer(mux)
	t.Cleanup(hs.Close)

	return hs.URL
}

// TestTransportGuards exercises the security-load-bearing checks in serveJSON
// that every other test satisfies implicitly, so a refactor that dropped one
// would be caught: POST-only, JSON content type, and the anti-CSRF header.
func TestTransportGuards(t *testing.T) {
	url := serverURL(t, whoIsRule(t, &acl.Rule{Action: []acl.Action{acl.ActionGet}, Secret: []acl.Secret{"*"}}))

	do := func(method string, headers map[string]string) int {
		req, err := http.NewRequest(method, url+"/api/get", strings.NewReader(`{"name":"s"}`))
		require.NoError(t, err)

		for k, v := range headers {
			req.Header.Set(k, v)
		}

		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)

		_ = resp.Body.Close()

		return resp.StatusCode
	}

	full := map[string]string{"Content-Type": "application/json", "Sec-X-Tailscale-No-Browsers": "setec"}

	require.Equal(t, http.StatusBadRequest, do(http.MethodGet, full), "GET must be rejected")
	require.Equal(t, http.StatusBadRequest,
		do(http.MethodPost, map[string]string{"Sec-X-Tailscale-No-Browsers": "setec"}),
		"missing Content-Type must be rejected")
	require.Equal(t, http.StatusForbidden,
		do(http.MethodPost, map[string]string{"Content-Type": "application/json"}),
		"missing anti-CSRF header must be rejected")
	require.Equal(t, http.StatusForbidden,
		do(http.MethodPost, map[string]string{"Content-Type": "application/json", "Sec-X-Tailscale-No-Browsers": "nope"}),
		"wrong anti-CSRF header must be rejected")
	// A fully-headed, authorized request reaches the handler: the secret is absent,
	// so a 404 proves the guards (and auth) passed rather than short-circuiting.
	require.Equal(t, http.StatusNotFound, do(http.MethodPost, full), "valid request must reach the handler")
}

// TestIdentityUnavailableIs503: a transient WhoIs failure (e.g. tailscaled
// restarting) is retryable, so the server answers 503, not 500.
func TestIdentityUnavailableIs503(t *testing.T) {
	url := serverURL(t, func(context.Context, string) (*apitype.WhoIsResponse, error) {
		return nil, errors.New("localapi: tailscaled restarting")
	})
	require.Equal(t, http.StatusServiceUnavailable, postFull(t, url))
}

// TestNilNodeNoPanic: a WhoIs response with no Node must not panic the handler
// (it is treated as an unavailable identity → 503).
func TestNilNodeNoPanic(t *testing.T) {
	url := serverURL(t, func(context.Context, string) (*apitype.WhoIsResponse, error) {
		return &apitype.WhoIsResponse{Node: nil}, nil
	})
	require.Equal(t, http.StatusServiceUnavailable, postFull(t, url))
}

func postFull(t *testing.T, url string) int {
	t.Helper()

	req, err := http.NewRequest(http.MethodPost, url+"/api/get", strings.NewReader(`{"name":"s"}`))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Sec-X-Tailscale-No-Browsers", "setec")
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)

	_ = resp.Body.Close()

	return resp.StatusCode
}

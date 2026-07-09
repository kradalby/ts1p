package main

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
	"tailscale.com/tsweb"

	"github.com/kradalby/ts1p/backend/cache"
	"github.com/kradalby/ts1p/backend/mem"
	"github.com/kradalby/ts1p/server"
	"github.com/kradalby/ts1p/store"
)

func TestNormalizeService(t *testing.T) {
	tests := []struct {
		in      string
		want    string
		wantErr bool
	}{
		{"secrets", "svc:secrets", false},
		{"svc:secrets", "svc:secrets", false},
		{"my-secrets", "svc:my-secrets", false},
		{"bad name", "", true}, // space is not a valid DNS label
		{"svc:", "", true},     // empty label
		{"", "", true},         // empty
	}
	for _, tt := range tests {
		got, err := normalizeService(tt.in)
		if tt.wantErr {
			require.Errorf(t, err, "input %q", tt.in)
			continue
		}

		require.NoErrorf(t, err, "input %q", tt.in)
		require.Equal(t, tt.want, got)
	}
}

func TestChooseServeMode(t *testing.T) {
	require.Equal(t, modeDev, chooseServeMode(true, ""))
	require.Equal(t, modeDev, chooseServeMode(true, "secrets"), "dev wins over service")
	require.Equal(t, modeService, chooseServeMode(false, "secrets"))
	require.Equal(t, modeTLS, chooseServeMode(false, ""))
}

// The production config errors are the first thing a new deployment hits; they
// must name the missing knob (flag and env var) rather than fail obscurely.
func TestBuildBackendValidation(t *testing.T) {
	ctx := context.Background()
	str := func(s string) *string { return &s }
	f := false

	t.Run("missing_vault", func(t *testing.T) {
		cfg := &config{dev: &f, vault: str("")}
		_, _, _, err := buildBackend(ctx, slog.Default(), cfg)
		require.ErrorContains(t, err, "--vault")
		require.ErrorContains(t, err, "TS1P_VAULT")
	})
	t.Run("missing_token", func(t *testing.T) {
		t.Setenv("OP_SERVICE_ACCOUNT_TOKEN", "")

		cfg := &config{dev: &f, vault: str("v")}
		_, _, _, err := buildBackend(ctx, slog.Default(), cfg)
		require.ErrorContains(t, err, "OP_SERVICE_ACCOUNT_TOKEN")
	})
}

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

// debugMux builds the debug surface exactly as serve() wires it.
func debugMux(t *testing.T, dev bool, rule *acl.Rule, cached *cache.Cache) *http.ServeMux {
	t.Helper()

	mux := http.NewServeMux()
	srv, err := server.New(server.Config{
		Store: store.New(mem.New()),
		WhoIs: whoIsGrant(t, rule),
		Audit: audit.New(io.Discard),
		Mux:   mux,
	})
	require.NoError(t, err)
	registerDebug(mux, dev, srv, cached, nil, slog.Default())

	return mux
}

func get(t *testing.T, mux *http.ServeMux, path string, gateHeader bool) int {
	t.Helper()

	req := httptest.NewRequest(http.MethodGet, path, nil)
	if gateHeader {
		req.Header.Set("Sec-X-Tailscale-No-Browsers", "setec")
	}

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	return rec.Code
}

// TestRegisterDebugProduction pins the README's security claims about the
// production debug surface as wired: pprof (a heap dump of a process full of
// decrypted secrets) does not exist, /debug/vars sits behind the admin gate,
// and /debug/flush-cache exists only when there is a cache.
func TestRegisterDebugProduction(t *testing.T) {
	operator := &acl.Rule{Action: []acl.Action{acl.ActionDelete}, Secret: []acl.Secret{"*"}}

	t.Run("no_pprof", func(t *testing.T) {
		mux := debugMux(t, false, operator, cache.New(mem.New(), 0, time.Hour))
		require.Equal(t, http.StatusNotFound, get(t, mux, "/debug/pprof/heap", true))
		require.Equal(t, http.StatusNotFound, get(t, mux, "/debug/pprof/", true))
		require.Equal(t, http.StatusNotFound, get(t, mux, "/debug/", true))
	})
	t.Run("vars_gated", func(t *testing.T) {
		mux := debugMux(t, false, nil, nil) // no grant
		require.Equal(t, http.StatusForbidden, get(t, mux, "/debug/vars", true))
		muxOp := debugMux(t, false, operator, nil)
		require.Equal(t, http.StatusForbidden, get(t, muxOp, "/debug/vars", false), "gate requires the anti-CSRF header")
		require.Equal(t, http.StatusOK, get(t, muxOp, "/debug/vars", true))
	})
	t.Run("flush_only_with_cache", func(t *testing.T) {
		mux := debugMux(t, false, operator, nil) // no cache (--dev shape)
		require.Equal(t, http.StatusNotFound, get(t, mux, "/debug/flush-cache", true))
	})
	t.Run("dev_has_debug_suite", func(t *testing.T) {
		mux := debugMux(t, true, nil, nil)
		// tsweb's debugger serves localhost/tailnet callers; the httptest
		// request comes from 192.0.2.1, so anything but 404 proves it is wired.
		require.NotEqual(t, http.StatusNotFound, get(t, mux, "/debug/", false))
	})
	t.Run("metrics_ungated", func(t *testing.T) {
		mux := debugMux(t, false, nil, nil) // no grant, no cache

		req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)

		require.Equal(t, http.StatusOK, rec.Code, "a scraper must pass without grant or header")

		body := rec.Body.String()
		require.Contains(t, body, "ts1p_cache_stale_served_total", "the ts1p_* counters must be exported")
		require.NotContains(t, body, "--vault", "argv must not serialize")
	})
	// The loopback debug listener carries the full suite — pprof included — that
	// the tailnet listener must never expose. AllowDebugAccess permits loopback
	// callers, so the test speaks from 127.0.0.1.
	t.Run("loopback_debugger_full_suite", func(t *testing.T) {
		dmux := http.NewServeMux()
		wireFullDebugger(tsweb.Debugger(dmux), dmux)

		code, body := getLoopback(t, dmux, "/debug/")
		require.Equal(t, http.StatusOK, code, "the /debug index serves loopback callers")
		require.Contains(t, body, "statsviz", "statsviz is linked from /debug")
		require.Contains(t, body, "Metrics (Prometheus)", "/metrics is linked from /debug")

		code, _ = getLoopback(t, dmux, "/debug/pprof/")
		require.Equal(t, http.StatusOK, code, "pprof lives on the loopback listener")

		code, body = getLoopback(t, dmux, "/metrics")
		require.Equal(t, http.StatusOK, code)
		require.Contains(t, body, "ts1p_cache_stale_served_total", "the ts1p_* counters must be exported")

		code, _ = getLoopback(t, dmux, "/debug/statsviz/")
		require.NotEqual(t, http.StatusNotFound, code, "statsviz is wired")
	})
}

// getLoopback issues a GET to path as if from loopback, so tsweb.AllowDebugAccess
// admits it, and returns the status and body.
func getLoopback(t *testing.T, mux *http.ServeMux, path string) (int, string) {
	t.Helper()

	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.RemoteAddr = "127.0.0.1:12345"

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	return rec.Code, rec.Body.String()
}

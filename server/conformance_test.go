package server_test

import (
	"bytes"
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
	"github.com/tailscale/setec/setectest"
	"github.com/tailscale/setec/types/api"

	"github.com/kradalby/ts1p/backend/mem"
	"github.com/kradalby/ts1p/server"
	"github.com/kradalby/ts1p/store"
)

// newTS1P starts a ts1p server with an in-memory backend and all-access
// identity, returning its httptest server.
func newTS1P(t *testing.T) *httptest.Server {
	t.Helper()

	mux := http.NewServeMux()
	_, err := server.New(server.Config{
		Store: store.New(mem.New()),
		WhoIs: setectest.AllAccess,
		Audit: audit.New(io.Discard),
		Mux:   mux,
	})
	require.NoError(t, err)

	hs := httptest.NewServer(mux)
	t.Cleanup(hs.Close)

	return hs
}

// newSetec starts setec's own reference server, the differential gold standard.
func newSetec(t *testing.T) *httptest.Server {
	t.Helper()
	db := setectest.NewDB(t, nil)
	ss := setectest.NewServer(t, db, nil)
	hs := httptest.NewServer(ss.Mux)
	t.Cleanup(hs.Close)

	return hs
}

// post issues a setec API call with the required headers and returns the raw
// status code and body.
func post(t *testing.T, hs *httptest.Server, path string, body any) (int, string) {
	t.Helper()

	b, err := json.Marshal(body)
	require.NoError(t, err)
	req, err := http.NewRequest(http.MethodPost, hs.URL+path, bytes.NewReader(b))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Sec-X-Tailscale-No-Browsers", "setec")
	resp, err := hs.Client().Do(req)
	require.NoError(t, err)

	defer resp.Body.Close()

	out, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	return resp.StatusCode, string(out)
}

// op is one API call in a differential script.
type op struct {
	desc string
	path string
	body any
}

// TestDifferential replays an identical operation script against both setec's
// reference server and ts1p, asserting byte-identical HTTP responses at every
// step. This is the strongest correctness guarantee: any divergence in the
// version state machine, error mapping, or wire format fails here.
func TestDifferential(t *testing.T) {
	ref := newSetec(t)
	ts1p := newTS1P(t)

	b := func(s string) []byte { return []byte(s) }

	script := []op{
		{"get missing", "/api/get", api.GetRequest{Name: "a"}},
		{"info missing", "/api/info", api.InfoRequest{Name: "a"}},
		{"list empty", "/api/list", api.ListRequest{}},

		{"put a=v1", "/api/put", api.PutRequest{Name: "a", Value: b("v1")}},
		{"get a (active=1)", "/api/get", api.GetRequest{Name: "a"}},

		{"put a=v2 (inactive)", "/api/put", api.PutRequest{Name: "a", Value: b("v2")}},
		{"get a still active=1", "/api/get", api.GetRequest{Name: "a"}},
		{"put a=v2 dedup", "/api/put", api.PutRequest{Name: "a", Value: b("v2")}},
		{"info a versions", "/api/info", api.InfoRequest{Name: "a"}},
		{"get a version 2", "/api/get", api.GetRequest{Name: "a", Version: 2}},
		{"getIfChanged old=1 -> 304", "/api/get", api.GetRequest{Name: "a", Version: 1, UpdateIfChanged: true}},
		{"getIfChanged old=2 -> value", "/api/get", api.GetRequest{Name: "a", Version: 2, UpdateIfChanged: true}},

		{"activate a v2", "/api/activate", api.ActivateRequest{Name: "a", Version: 2}},
		{"get a active=2", "/api/get", api.GetRequest{Name: "a"}},
		{"getIfChanged old=1 -> value now", "/api/get", api.GetRequest{Name: "a", Version: 1, UpdateIfChanged: true}},

		{"create-version a v1 claimed", "/api/create-version", api.CreateVersionRequest{Name: "a", Version: 1, Value: b("x")}},
		{"create-version a v5", "/api/create-version", api.CreateVersionRequest{Name: "a", Version: 5, Value: b("v5")}},
		{"get a active=5", "/api/get", api.GetRequest{Name: "a"}},
		{"create-version a v0 -> 400", "/api/create-version", api.CreateVersionRequest{Name: "a", Version: 0, Value: b("x")}},

		{"delete-version a v0 -> 500", "/api/delete-version", api.DeleteVersionRequest{Name: "a", Version: 0}},
		{"delete-version active(5) -> 500", "/api/delete-version", api.DeleteVersionRequest{Name: "a", Version: 5}},
		{"activate a v1", "/api/activate", api.ActivateRequest{Name: "a", Version: 1}},
		{"delete-version a v5", "/api/delete-version", api.DeleteVersionRequest{Name: "a", Version: 5}},
		{"create-version a v5 reclaimed", "/api/create-version", api.CreateVersionRequest{Name: "a", Version: 5, Value: b("y")}},

		{"activate missing version 9 -> 404", "/api/activate", api.ActivateRequest{Name: "a", Version: 9}},
		{"activate missing secret -> 404", "/api/activate", api.ActivateRequest{Name: "zzz", Version: 1}},
		{"delete-version missing secret -> 404", "/api/delete-version", api.DeleteVersionRequest{Name: "zzz", Version: 1}},

		{"put b=hello", "/api/put", api.PutRequest{Name: "b", Value: b("hello")}},
		{"list two", "/api/list", api.ListRequest{}},

		{"delete a", "/api/delete", api.DeleteRequest{Name: "a"}},
		{"get a -> 404", "/api/get", api.GetRequest{Name: "a"}},
		{"delete a again (noop)", "/api/delete", api.DeleteRequest{Name: "a"}},
		{"list one", "/api/list", api.ListRequest{}},

		// Empty names: writes are validated before anything else (500), reads
		// and delete treat "" as any other missing name.
		{"put empty name -> 500", "/api/put", api.PutRequest{Name: "", Value: b("v")}},
		{"activate empty name -> 500", "/api/activate", api.ActivateRequest{Name: "", Version: 1}},
		{"create-version empty name+v0 -> name checked first", "/api/create-version", api.CreateVersionRequest{Name: "", Version: 0, Value: b("x")}},
		{"get empty name -> 404", "/api/get", api.GetRequest{Name: ""}},
		{"info empty name -> 404", "/api/info", api.InfoRequest{Name: ""}},
		{"delete empty name (noop)", "/api/delete", api.DeleteRequest{Name: ""}},
		{"delete-version empty name -> 404", "/api/delete-version", api.DeleteVersionRequest{Name: "", Version: 1}},

		// setec reserves the _internal/ prefix on put/activate/delete paths
		// (but, faithfully mirrored, NOT on create-version or reads).
		{"put _internal/x -> 500", "/api/put", api.PutRequest{Name: "_internal/x", Value: b("v")}},
		{"activate _internal/x -> 500", "/api/activate", api.ActivateRequest{Name: "_internal/x", Version: 1}},
		{"delete-version _internal/x -> 500", "/api/delete-version", api.DeleteVersionRequest{Name: "_internal/x", Version: 1}},
		{"delete _internal/x -> 500", "/api/delete", api.DeleteRequest{Name: "_internal/x"}},
		{"get _internal/x -> 404 (never created)", "/api/get", api.GetRequest{Name: "_internal/x"}},
		{"list unchanged after _internal writes", "/api/list", api.ListRequest{}},

		// Version-edge reads.
		{"put b v2", "/api/put", api.PutRequest{Name: "b", Value: b("world")}},
		{"delete-version b v2", "/api/delete-version", api.DeleteVersionRequest{Name: "b", Version: 2}},
		{"get b deleted version -> 404", "/api/get", api.GetRequest{Name: "b", Version: 2}},
		{"getIfChanged v0 falls through to plain get", "/api/get", api.GetRequest{Name: "b", Version: 0, UpdateIfChanged: true}},
	}

	for _, o := range script {
		refStatus, refBody := post(t, ref, o.path, o.body)
		gotStatus, gotBody := post(t, ts1p, o.path, o.body)
		require.Equalf(t, refStatus, gotStatus, "status mismatch on %q", o.desc)
		require.Equalf(t, refBody, gotBody, "body mismatch on %q (status %d)", o.desc, refStatus)
	}
}

// TestDifferentialAccessDenied replays forbidden operations against both setec's
// reference server and ts1p under an identical scoped identity, asserting
// byte-identical responses. ACL denial precedes existence checks on both, so a
// forbidden op is a 403 regardless of whether the secret exists — no seeding
// needed. This guards the access-denied wire behaviour the happy-path
// differential does not exercise.
func TestDifferentialAccessDenied(t *testing.T) {
	whois := whoIsRule(t, &acl.Rule{
		Action: []acl.Action{acl.ActionGet, acl.ActionInfo},
		Secret: []acl.Secret{"allowed/*"},
	})

	db := setectest.NewDB(t, nil)
	ss := setectest.NewServer(t, db, &setectest.ServerOptions{WhoIs: whois})
	ref := httptest.NewServer(ss.Mux)
	t.Cleanup(ref.Close)

	mux := http.NewServeMux()
	_, err := server.New(server.Config{
		Store: store.New(mem.New()),
		WhoIs: whois,
		Audit: audit.New(io.Discard),
		Mux:   mux,
	})
	require.NoError(t, err)

	ts1p := httptest.NewServer(mux)
	t.Cleanup(ts1p.Close)

	b := func(s string) []byte { return []byte(s) }

	script := []op{
		{"get forbidden secret -> 403", "/api/get", api.GetRequest{Name: "secret/y"}},
		{"info forbidden secret -> 403", "/api/info", api.InfoRequest{Name: "secret/y"}},
		{"put without grant -> 403", "/api/put", api.PutRequest{Name: "allowed/x", Value: b("v")}},
		{"delete without grant -> 403", "/api/delete", api.DeleteRequest{Name: "allowed/x"}},
		{"get allowed but missing -> 404", "/api/get", api.GetRequest{Name: "allowed/x"}},
		{"list -> only allowed (empty)", "/api/list", api.ListRequest{}},
		// Name validation runs before authorization, so an ungranted caller
		// sees 500 (not 403) for an empty name — pinned against the reference.
		{"put empty name unauthorized -> 500", "/api/put", api.PutRequest{Name: "", Value: b("v")}},
	}
	for _, o := range script {
		refStatus, refBody := post(t, ref, o.path, o.body)
		gotStatus, gotBody := post(t, ts1p, o.path, o.body)
		require.Equalf(t, refStatus, gotStatus, "status mismatch on %q", o.desc)
		require.Equalf(t, refBody, gotBody, "body mismatch on %q (status %d)", o.desc, refStatus)
	}
}

// TestClientLifecycle drives ts1p with setec's real client, proving the client
// library works unchanged against ts1p.
func TestClientLifecycle(t *testing.T) {
	ctx := context.Background()
	hs := newTS1P(t)
	cli := setec.Client{Server: hs.URL, DoHTTP: hs.Client().Do}

	// Missing secret.
	_, err := cli.Get(ctx, "k")
	require.ErrorIs(t, err, api.ErrNotFound)

	// Put creates version 1, active.
	v1, err := cli.Put(ctx, "k", []byte("one"))
	require.NoError(t, err)
	require.Equal(t, api.SecretVersion(1), v1)

	sv, err := cli.Get(ctx, "k")
	require.NoError(t, err)
	require.Equal(t, []byte("one"), sv.Value)
	require.Equal(t, api.SecretVersion(1), sv.Version)

	// Second put is inactive.
	v2, err := cli.Put(ctx, "k", []byte("two"))
	require.NoError(t, err)
	require.Equal(t, api.SecretVersion(2), v2)

	sv, err = cli.Get(ctx, "k")
	require.NoError(t, err)
	require.Equal(t, api.SecretVersion(1), sv.Version)

	// GetIfChanged on the active version reports not-changed.
	_, err = cli.GetIfChanged(ctx, "k", v1)
	require.ErrorIs(t, err, api.ErrValueNotChanged)

	// Activate the new version.
	require.NoError(t, cli.Activate(ctx, "k", v2))
	sv, err = cli.Get(ctx, "k")
	require.NoError(t, err)
	require.Equal(t, []byte("two"), sv.Value)

	// Claimed version cannot be recreated.
	require.ErrorIs(t, cli.CreateVersion(ctx, "k", v1, []byte("x")), api.ErrVersionClaimed)

	// Info reports both versions.
	info, err := cli.Info(ctx, "k")
	require.NoError(t, err)
	require.Equal(t, []api.SecretVersion{1, 2}, info.Versions)
	require.Equal(t, v2, info.ActiveVersion)

	// Delete removes it.
	require.NoError(t, cli.Delete(ctx, "k"))
	_, err = cli.Get(ctx, "k")
	require.ErrorIs(t, err, api.ErrNotFound)
}

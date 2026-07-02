package server_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
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

// syncBuffer is a goroutine-safe buffer for capturing audit output.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	return b.buf.Write(p)
}

func (b *syncBuffer) entries(t *testing.T) []audit.Entry {
	t.Helper()
	b.mu.Lock()
	defer b.mu.Unlock()

	var out []audit.Entry

	dec := json.NewDecoder(bytes.NewReader(b.buf.Bytes()))
	for dec.More() {
		var e audit.Entry
		require.NoError(t, dec.Decode(&e))
		out = append(out, e)
	}

	return out
}

// auditedServer builds a ts1p server whose audit log is captured in buf.
func auditedServer(t *testing.T, buf *syncBuffer, rule *acl.Rule) setec.Client {
	t.Helper()

	mux := http.NewServeMux()
	st := store.New(mem.New())
	_, err := server.New(server.Config{
		Store: st,
		WhoIs: whoIsRule(t, rule),
		Audit: audit.New(buf),
		Mux:   mux,
	})
	require.NoError(t, err)

	hs := httptest.NewServer(mux)
	t.Cleanup(hs.Close)

	return setec.Client{Server: hs.URL, DoHTTP: hs.Client().Do}
}

// TestAuditTrail pins the audit placement the README sells as a security
// property: every allowed and denied call leaves the right entry, list writes
// exactly one, and an unchanged conditional get writes none.
func TestAuditTrail(t *testing.T) {
	ctx := context.Background()
	buf := &syncBuffer{}
	cli := auditedServer(t, buf, &acl.Rule{
		Action: []acl.Action{acl.ActionGet, acl.ActionInfo, acl.ActionPut},
		Secret: []acl.Secret{"ok/*"},
	})

	_, err := cli.Put(ctx, "ok/a", []byte("v"))
	require.NoError(t, err)

	_, err = cli.Get(ctx, "ok/a") // allowed
	require.NoError(t, err)

	_, err = cli.Get(ctx, "secret/x") // denied
	require.ErrorIs(t, err, api.ErrAccessDenied)

	_, err = cli.GetIfChanged(ctx, "ok/a", 1) // unchanged: 304, unaudited
	require.ErrorIs(t, err, api.ErrValueNotChanged)

	_, err = cli.List(ctx) // exactly one entry, no per-secret fan-out
	require.NoError(t, err)

	es := buf.entries(t)
	require.Len(t, es, 4, "put, allowed get, denied get, list — and nothing for the 304")

	require.Equal(t, acl.ActionPut, es[0].Action)
	require.Equal(t, "ok/a", es[0].Secret)
	require.True(t, es[0].Authorized)
	require.Equal(t, "user@example.com", es[0].Principal.User)

	require.Equal(t, acl.ActionGet, es[1].Action)
	require.True(t, es[1].Authorized)

	require.Equal(t, acl.ActionGet, es[2].Action)
	require.Equal(t, "secret/x", es[2].Secret)
	require.False(t, es[2].Authorized, "the denial itself must be recorded")

	require.Equal(t, acl.ActionInfo, es[3].Action)
	require.Empty(t, es[3].Secret, "list is one entry with no secret name")
}

// failingWriter fails every write, modeling a full or broken audit disk.
type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("disk full") }

// TestAuditFailClosed: if the audit entry cannot be written, the operation must
// not proceed — an unauditable secrets server must stop serving writes, not
// serve them invisibly.
func TestAuditFailClosed(t *testing.T) {
	ctx := context.Background()
	mux := http.NewServeMux()
	be := mem.New()
	st := store.New(be)
	_, err := server.New(server.Config{
		Store: st,
		WhoIs: whoIsRule(t, &acl.Rule{Action: []acl.Action{acl.ActionPut, acl.ActionGet}, Secret: []acl.Secret{"*"}}),
		Audit: audit.New(failingWriter{}),
		Mux:   mux,
	})
	require.NoError(t, err)

	hs := httptest.NewServer(mux)
	t.Cleanup(hs.Close)
	cli := setec.Client{Server: hs.URL, DoHTTP: hs.Client().Do}

	_, err = cli.Put(ctx, "k", []byte("v"))
	require.Error(t, err, "an unaudited put must fail")

	_, err = be.Load(ctx, "k")
	require.Error(t, err, "the store must not have been mutated by the unaudited put")
}

// TestTaggedNodeIdentity: production setec clients are typically tagged server
// nodes, whose identity comes from Node.Tags rather than a user profile. The
// grant must apply and the audit entry must carry the tags.
func TestTaggedNodeIdentity(t *testing.T) {
	ctx := context.Background()
	rule := &acl.Rule{Action: []acl.Action{acl.ActionGet, acl.ActionPut}, Secret: []acl.Secret{"*"}}
	b, err := json.Marshal(*rule)
	require.NoError(t, err)

	whois := func(context.Context, string) (*apitype.WhoIsResponse, error) {
		node := &tailcfg.Node{
			Name: "srv.example.com",
			Tags: []string{"tag:server"},
		}

		return &apitype.WhoIsResponse{
			Node:   node,
			CapMap: tailcfg.PeerCapMap{server.ACLCap: {tailcfg.RawMessage(b)}},
		}, nil
	}

	buf := &syncBuffer{}
	mux := http.NewServeMux()
	_, err = server.New(server.Config{
		Store: store.New(mem.New()),
		WhoIs: whois,
		Audit: audit.New(buf),
		Mux:   mux,
	})
	require.NoError(t, err)

	hs := httptest.NewServer(mux)
	t.Cleanup(hs.Close)
	cli := setec.Client{Server: hs.URL, DoHTTP: hs.Client().Do}

	_, err = cli.Put(ctx, "k", []byte("v"))
	require.NoError(t, err, "a tagged node's grant must authorize")
	sv, err := cli.Get(ctx, "k")
	require.NoError(t, err)
	require.Equal(t, []byte("v"), sv.Value)

	es := buf.entries(t)
	require.NotEmpty(t, es)
	require.Equal(t, []string{"tag:server"}, es[0].Principal.Tags, "audit must attribute the tagged node")
	require.Empty(t, es[0].Principal.User)
}

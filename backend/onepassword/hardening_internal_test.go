package onepassword

import (
	"context"
	"errors"
	"log/slog"
	"testing"
	"time"

	op "github.com/1password/onepassword-sdk-go"
	"github.com/cenkalti/backoff/v5"
	"github.com/stretchr/testify/require"
	"github.com/tailscale/setec/types/api"

	"github.com/kradalby/ts1p/backend"
)

func validRecord() *backend.Record {
	return &backend.Record{
		Name:     "k",
		Versions: map[api.SecretVersion][]byte{1: []byte("v")},
		Active:   1,
		Latest:   1,
	}
}

// #8: the ts1p-meta field (the source of truth, carrying every version's value)
// must be Concealed, not a plaintext-visible Text field.
func TestMetaFieldConcealed(t *testing.T) {
	fields, _, err := recordToFields(validRecord())
	require.NoError(t, err)

	for _, f := range fields {
		require.Equal(t, op.ItemFieldTypeConcealed, f.FieldType,
			"field %q must be concealed", f.Title)
	}
}

// #20: duplicate titles are ambiguous; findID must fail closed rather than pick
// one arbitrarily and let Load/Save/Delete disagree.
func TestDuplicateTitleFailsClosed(t *testing.T) {
	f := newFakeItems()
	f.byID["id-1"] = op.Item{ID: "id-1", Title: "dup", VaultID: "v1"}
	f.byID["id-2"] = op.Item{ID: "id-2", Title: "dup", VaultID: "v1"}
	b := testBackend(f)

	_, err := b.Load(context.Background(), "dup")
	require.Error(t, err)
	require.NotErrorIs(t, err, backend.ErrNotFound, "a collision is an error, not absence")
}

// #20: an empty name is rejected rather than turned into a vault scan/odd item.
func TestEmptyNameRejected(t *testing.T) {
	b := newTestBackend()
	require.Error(t, b.Save(context.Background(), "", validRecord()))
}

// #21: a transient error during Create must not be retried — a retry of a create
// that already took effect would leave a duplicate item.
func TestNoDuplicateOnTransientCreate(t *testing.T) {
	f := newFakeItems()
	f.createErrOnce = errors.New("transient network blip")
	b := testBackend(f)

	err := b.Save(context.Background(), "k", validRecord())
	require.Error(t, err, "the transient create error must surface, not be retried")
	require.Equal(t, 1, f.creates, "create must run exactly once")
	require.Empty(t, f.byID, "no item should have been created")
}

// #23: an item without a ts1p-meta field is not a ts1p item; recordFromItem must
// report it absent so store.List skips it instead of failing the whole listing.
func TestMissingMetaIsNotFound(t *testing.T) {
	item := op.Item{ID: "id-1", Title: "foreign", Fields: []op.ItemField{{ID: "note", Title: "note", Value: "hi"}}}
	_, err := recordFromItem("foreign", item)
	require.ErrorIs(t, err, backend.ErrNotFound)
}

// #22: a structurally-inconsistent stored record (active not among versions) is
// rejected with a descriptive, named error rather than round-tripping silently.
func TestDecodeRejectsActiveNotInVersions(t *testing.T) {
	// active=2 but only version 1 exists.
	_, err := decodeMeta("k", `{"active":2,"latest":2,"versions":{"1":"dg=="}}`)
	require.Error(t, err)
	require.Contains(t, err.Error(), "k")

	// A versionless record stays permissive (the empty case).
	_, err = decodeMeta("k", `{"active":0,"latest":0,"versions":{}}`)
	require.NoError(t, err)

	// Malformed JSON is rejected, naming the secret.
	_, err = decodeMeta("k", `{not json`)
	require.Error(t, err)
	require.Contains(t, err.Error(), "k")
}

// #19: a misconfigured vault title never resolves; start must fail fast (one
// attempt) rather than retry for the full startup window.
func TestVaultNotFoundIsPermanent(t *testing.T) {
	calls := 0
	b := &Backend{
		log:          slog.Default(),
		startBackOff: backoff.NewConstantBackOff(time.Millisecond),
		connect: func(context.Context) (*conn, string, error) {
			calls++
			return nil, "", errVaultNotFound
		},
	}
	err := b.start(context.Background())
	require.ErrorIs(t, err, errVaultNotFound)
	require.Equal(t, 1, calls, "a permanent error must not be retried")
}

// #58: updating a secret must preserve fields a human added to the item, replacing
// only the two fields ts1p manages.
func TestUpdatePreservesForeignFields(t *testing.T) {
	ctx := context.Background()
	b := newTestBackend()
	require.NoError(t, b.Save(ctx, "k", validRecord()))

	// Add a human field directly to the stored item.
	f := b.conn.items.(*fakeItems)

	var id string
	for k := range f.byID {
		id = k
	}

	item := f.byID[id]
	item.Fields = append(item.Fields, op.ItemField{ID: "note", Title: "note", Value: "keep me"})
	f.byID[id] = item

	// A normal update through Save must not drop it.
	r := validRecord()
	r.Versions[2] = []byte("v2")
	r.Active, r.Latest = 2, 2
	require.NoError(t, b.Save(ctx, "k", r))

	var hasNote bool

	for _, fld := range f.byID[id].Fields {
		if fld.Title == "note" {
			hasNote = true
		}
	}

	require.True(t, hasNote, "human-added field must survive an update")
}

// #59: if an item is deleted between findID and the update Get, Save recreates it
// rather than surfacing a 503.
func TestUpdateRecreatesIfDeletedMidway(t *testing.T) {
	ctx := context.Background()
	b := newTestBackend()
	require.NoError(t, b.Save(ctx, "k", validRecord())) // creates the item

	// Make the update Get fail once (as if the item vanished); the fake's byID is
	// also emptied so the recreate path sees it as genuinely gone.
	f := b.conn.items.(*fakeItems)
	f.getErrOnce = errors.New("not found")
	f.byID = map[string]op.Item{}

	require.NoError(t, b.Save(ctx, "k", validRecord()), "deleted-midway update should recreate")
	require.Len(t, f.byID, 1, "the secret should exist again after recreate")
}

// #24/#52: a hung SDK call is bounded by the backend's own timeout (the SDK does
// not honour cancellation inside wasm) and counted as a core timeout.
func TestHungCallTimesOut(t *testing.T) {
	f := newFakeItems()
	f.byID["id-1"] = op.Item{ID: "id-1", Title: "k", VaultID: "v1", Fields: mustFields(t)}

	f.getBlock = make(chan struct{}) // Get blocks forever
	defer close(f.getBlock)

	b := testBackend(f)
	b.callTimeout = 50 * time.Millisecond

	done := make(chan error, 1)

	go func() { _, err := b.Load(context.Background(), "k"); done <- err }()

	select {
	case err := <-done:
		require.ErrorIs(t, err, backend.ErrUnavailable, "a hung call must surface as unavailable, not hang")
		require.GreaterOrEqual(t, b.coreTimeout.Load(), int64(1), "the self-timeout must be counted")
	case <-time.After(2 * time.Second):
		t.Fatal("Load hung past the call timeout")
	}
}

func mustFields(t *testing.T) []op.ItemField {
	t.Helper()

	fields, _, err := recordToFields(validRecord())
	require.NoError(t, err)

	return fields
}

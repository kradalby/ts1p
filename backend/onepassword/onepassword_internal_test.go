package onepassword

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"testing"
	"time"

	op "github.com/1password/onepassword-sdk-go"
	"github.com/cenkalti/backoff/v5"
	"github.com/stretchr/testify/require"
	"github.com/tailscale/setec/types/api"

	"github.com/kradalby/ts1p/backend"
)

// fakeItems is an in-memory stand-in for the 1Password items API, exercising
// the backend's name→ID resolution and create-vs-update logic without a real
// vault. Its single mutex — held even across the block channels — mirrors the
// SDK's process-global lock: a call abandoned by the backend's timeout keeps
// holding it, so subsequent calls hang too, just like a wedged core.
type fakeItems struct {
	mu            sync.Mutex
	vaultID       string
	byID          map[string]op.Item
	nextID        int
	creates       int           // number of Create calls
	lists         int           // number of List calls
	gets          int           // number of Get calls
	listErr       error         // if set, List always returns it instead of the contents
	listErrOnce   error         // if set, List returns it once then clears it (transient)
	createErrOnce error         // if set, Create returns it once then clears it (transient)
	getErrOnce    error         // if set, Get returns it once then clears it (transient)
	getBlock      chan struct{} // if set, Get blocks on it (to exercise the call timeout)
	listBlock     chan struct{} // if set, List blocks on it (a truly hung core hangs everything)
}

func newFakeItems() *fakeItems {
	return &fakeItems{vaultID: "v1", byID: map[string]op.Item{}}
}

func (f *fakeItems) Create(_ context.Context, params op.ItemCreateParams) (op.Item, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.creates++
	if f.createErrOnce != nil {
		e := f.createErrOnce
		f.createErrOnce = nil

		return op.Item{}, e
	}

	f.nextID++
	id := fmt.Sprintf("id-%d", f.nextID)
	item := op.Item{ID: id, Title: params.Title, Category: params.Category, VaultID: params.VaultID, Fields: params.Fields}
	f.byID[id] = item

	return item, nil
}

func (f *fakeItems) Get(_ context.Context, _, itemID string) (op.Item, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.gets++
	if f.getBlock != nil {
		<-f.getBlock
	}

	if f.getErrOnce != nil {
		e := f.getErrOnce
		f.getErrOnce = nil

		return op.Item{}, e
	}

	item, ok := f.byID[itemID]
	if !ok {
		return op.Item{}, errors.New("not found")
	}

	return item, nil
}

func (f *fakeItems) Put(_ context.Context, item op.Item) (op.Item, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if _, ok := f.byID[item.ID]; !ok {
		return op.Item{}, errors.New("not found")
	}

	f.byID[item.ID] = item

	return item, nil
}

func (f *fakeItems) Delete(_ context.Context, _, itemID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	delete(f.byID, itemID)

	return nil
}

func (f *fakeItems) List(_ context.Context, _ string, _ ...op.ItemListFilter) ([]op.ItemOverview, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.lists++
	if f.listBlock != nil {
		<-f.listBlock
	}

	if f.listErrOnce != nil {
		e := f.listErrOnce
		f.listErrOnce = nil

		return nil, e
	}

	if f.listErr != nil {
		return nil, f.listErr
	}

	var out []op.ItemOverview
	for _, item := range f.byID {
		out = append(out, op.ItemOverview{ID: item.ID, Title: item.Title, VaultID: item.VaultID})
	}

	return out, nil
}

func newTestBackend() *Backend {
	return testBackend(newFakeItems())
}

// testBackend builds a Backend over items with safe test defaults: a no-op exit
// (so a recycle/fatal path never kills the test runner), a healthy connect, and
// millisecond retry pacing.
func testBackend(items itemsAPI) *Backend {
	return &Backend{
		log:          slog.Default(),
		vaultID:      "v1",
		conn:         &conn{items: items},
		now:          time.Now,
		exit:         func(int) {},
		retryBackOff: func() backoff.BackOff { return backoff.NewConstantBackOff(time.Millisecond) },
		connect: func(context.Context) (*conn, string, error) {
			return &conn{items: newFakeItems()}, "v1", nil
		},
	}
}

func TestBackendRoundTrip(t *testing.T) {
	ctx := context.Background()
	b := newTestBackend()

	_, err := b.Load(ctx, "missing")
	require.ErrorIs(t, err, backend.ErrNotFound)

	r := &backend.Record{
		Name:     "k",
		Versions: map[api.SecretVersion][]byte{1: []byte("one"), 3: []byte("three")},
		Active:   3,
		Latest:   3,
		Deleted:  map[api.SecretVersion]struct{}{2: {}},
	}
	require.NoError(t, b.Save(ctx, "k", r))

	got, err := b.Load(ctx, "k")
	require.NoError(t, err)
	require.True(t, r.Equal(got), "loaded record should equal saved: %+v vs %+v", r, got)

	// Update in place (no duplicate item created).
	r.Versions[4] = []byte("four")
	r.Active, r.Latest = 4, 4
	require.NoError(t, b.Save(ctx, "k", r))
	got, err = b.Load(ctx, "k")
	require.NoError(t, err)
	require.True(t, r.Equal(got))

	names, err := b.List(ctx)
	require.NoError(t, err)
	require.Equal(t, []string{"k"}, names)
	require.Len(t, b.conn.items.(*fakeItems).byID, 1, "update must not create a second item")

	require.NoError(t, b.Delete(ctx, "k"))
	require.NoError(t, b.Delete(ctx, "k")) // no-op
	_, err = b.Load(ctx, "k")
	require.ErrorIs(t, err, backend.ErrNotFound)
}

// wasmOOB is the verbatim signature the 1Password SDK's extism/wazero core
// emits once its WASM instance is corrupted; observed in production on ts1p-ldn.
const wasmOOB = "wasm error: out of bounds memory access\n" +
	"wasm stack trace:\n" +
	"\top_extism_core.wasm._ZN10extism_pdk6extism10load_input17h1fed4249c383a9e7E(i32)\n" +
	"\top_extism_core.wasm._ZN10extism_pdk11input_bytes17h13d5c98ff491778fE(i32)\n" +
	"\top_extism_core.wasm.invoke() i32"

// TestTransientOOBRecoversOnRetry: an OOB that clears on the retry must recover
// (no process exit), while still being counted for forensics.
func TestTransientOOBRecoversOnRetry(t *testing.T) {
	b := testBackend(&fakeItems{vaultID: "v1", byID: map[string]op.Item{}, listErrOnce: errors.New(wasmOOB)})
	exited := false
	b.exit = func(int) { exited = true }

	names, err := b.List(context.Background())
	require.NoError(t, err)
	require.Empty(t, names)
	require.False(t, exited, "a transient OOB must not exit the process")
	require.Equal(t, int64(1), b.OOBCount())
}

// TestPersistentOOBExits: an OOB that survives the retry means the shared WASM
// core is wedged; the backend must exit(1) so systemd restarts with a fresh core.
func TestPersistentOOBExits(t *testing.T) {
	b := testBackend(&fakeItems{vaultID: "v1", byID: map[string]op.Item{}, listErr: errors.New(wasmOOB)})
	code := -1
	b.exit = func(c int) { code = c }

	_, _ = b.List(context.Background())

	require.Equal(t, 1, code, "confirmed core corruption must exit(1)")
	require.GreaterOrEqual(t, b.OOBCount(), int64(2), "both fault detections counted")
}

// TestProactiveRecycleExits: once the WASM core is past its max age, the backend
// exits(0) for a clean systemd restart before corruption sets in.
func TestProactiveRecycleExits(t *testing.T) {
	b := testBackend(newFakeItems())
	b.recycleAt = time.Now().Add(-time.Minute) // already due
	code := -1
	b.exit = func(c int) { code = c }

	_, _ = b.List(context.Background())

	require.Equal(t, 0, code, "proactive recycle must exit(0)")
}

// TestCtxCanceledCounted: a request abandoned by the caller is counted (the ramp
// is the alert signal) and never reaches the SDK.
func TestCtxCanceledCounted(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	b := testBackend(newFakeItems())

	_, _ = b.List(ctx)
	require.Equal(t, int64(1), b.CtxCanceledCount())
}

// TestStartRetriesTransientErrors: a transient failure at boot (DNS not ready,
// a service-account token that has not settled) must be retried with backoff,
// not crash the process on the first error.
func TestStartRetriesTransientErrors(t *testing.T) {
	calls := 0
	b := &Backend{
		log:          slog.Default(),
		startBackOff: backoff.NewConstantBackOff(time.Millisecond),
		connect: func(context.Context) (*conn, string, error) {
			calls++
			if calls < 3 {
				return nil, "", errors.New("dial tcp: lookup my.1password.com: no such host")
			}

			return &conn{items: newFakeItems()}, "v1", nil
		},
	}

	require.NoError(t, b.start(context.Background()))
	require.Equal(t, 3, calls, "should retry until connect succeeds")
	require.Equal(t, "v1", b.vaultID)
}

// TestContextCancelNotUnavailable: a cancelled request context (client gone) is
// not a storage outage. It must surface as context.Canceled, not ErrUnavailable
// (which would map to a 503 and log a spurious storage error).
func TestContextCancelNotUnavailable(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	b := testBackend(&fakeItems{vaultID: "v1", byID: map[string]op.Item{}, listErr: context.Canceled})

	_, err := b.List(ctx)
	require.ErrorIs(t, err, context.Canceled)
	require.NotErrorIs(t, err, backend.ErrUnavailable)
}

// TestIDMemoization: once a full-vault listing has resolved titles to IDs,
// single-secret Loads cost one SDK call (Get), not a full-vault List plus a
// Get — the warm cycle must not be O(N^2) in vault size.
func TestIDMemoization(t *testing.T) {
	ctx := context.Background()
	b := newTestBackend()
	require.NoError(t, b.Save(ctx, "k", validRecord()))
	f := b.conn.items.(*fakeItems)

	lists, gets := f.lists, f.gets
	_, err := b.Load(ctx, "k")
	require.NoError(t, err)
	require.Equal(t, lists, f.lists, "a memoized Load must not list the vault")
	require.Equal(t, gets+1, f.gets, "a memoized Load is exactly one Get")

	// A List refreshes the memo for names it did not create.
	f2 := newFakeItems()
	f2.byID["id-9"] = op.Item{ID: "id-9", Title: "other", VaultID: "v1", Fields: mustFields(t)}
	b2 := testBackend(f2)
	_, err = b2.List(ctx)
	require.NoError(t, err)

	lists = f2.lists
	_, err = b2.Load(ctx, "other")
	require.NoError(t, err)
	require.Equal(t, lists, f2.lists, "List must have populated the memo")
}

// TestLoadDeletedMidwayIsNotFound: an item deleted between the listing and the
// Get is absent, not a storage outage — the caller must see not-found, not a
// retryable 503.
func TestLoadDeletedMidwayIsNotFound(t *testing.T) {
	ctx := context.Background()
	b := newTestBackend()
	require.NoError(t, b.Save(ctx, "k", validRecord()))

	// Empty the vault behind the memo's back: the memoized Get now fails, and
	// the fresh re-resolve finds the item genuinely gone.
	f := b.conn.items.(*fakeItems)
	f.byID = map[string]op.Item{}

	_, err := b.Load(ctx, "k")
	require.ErrorIs(t, err, backend.ErrNotFound)
}

// TestRateLimitedNotRetried: 1Password's typed quota refusal must not be
// re-run (the quota resets on the hour; retries only pin us at the limit), is
// counted, and carries ErrRateLimited so the warmer backs off to its cadence.
func TestRateLimitedNotRetried(t *testing.T) {
	f := newFakeItems()
	f.listErr = &op.RateLimitExceededError{} // the message field is unexported; the type is the signal
	b := testBackend(f)

	_, err := b.List(context.Background())
	require.ErrorIs(t, err, backend.ErrRateLimited)
	require.ErrorIs(t, err, backend.ErrUnavailable, "clients still see a retryable 503")
	require.Equal(t, 1, f.lists, "a rate-limited call must not be retried")
	require.Equal(t, int64(1), b.rateLimited.Load())
}

// TestAuthErrorPermanentAtStart: a credential failure at boot never resolves;
// start must fail fast (one attempt) with the real error rather than retrying
// out the whole startup window.
func TestAuthErrorPermanentAtStart(t *testing.T) {
	calls := 0
	b := &Backend{
		log:          slog.Default(),
		startBackOff: backoff.NewConstantBackOff(time.Millisecond),
		connect: func(context.Context) (*conn, string, error) {
			calls++
			return nil, "", errors.New("(auth) Invalid bearer token")
		},
	}
	err := b.start(context.Background())
	require.Error(t, err)
	require.Equal(t, 1, calls, "an auth failure must not be retried")
}

// TestConsecutiveTimeoutsExit: a wedged (hung, not faulting) core is only
// recoverable by a process restart; after maxConsecTimeouts self-timeouts in a
// row the backend must exit rather than brown out forever.
func TestConsecutiveTimeoutsExit(t *testing.T) {
	ctx := context.Background()
	f := newFakeItems()
	f.byID["id-1"] = op.Item{ID: "id-1", Title: "k", VaultID: "v1", Fields: mustFields(t)}
	b := testBackend(f)
	b.callTimeout = 20 * time.Millisecond
	code := -1
	b.exit = func(c int) { code = c }

	// Prime the ID memo while the fake is healthy, then hang everything: a
	// truly wedged core times out Gets and Lists alike, so no call in between
	// can reset the consecutive counter.
	_, err := b.Load(ctx, "k")
	require.NoError(t, err)

	block := make(chan struct{})
	defer close(block)

	f.getBlock, f.listBlock = block, block

	for range maxConsecTimeouts {
		_, err := b.Load(ctx, "k")
		require.Error(t, err)
	}

	require.Equal(t, 1, code, "a hung core must exit for a clean restart")
	require.GreaterOrEqual(t, b.coreTimeout.Load(), int64(maxConsecTimeouts))
}

// TestMetaSizeCap: a record whose encoded meta exceeds 1Password's item limit
// is refused with an actionable, non-retryable error — a 503 would send
// clients into a futile retry loop against a permanent condition.
func TestMetaSizeCap(t *testing.T) {
	b := newTestBackend()
	r := validRecord()
	r.Versions[1] = make([]byte, metaMaxBytes) // base64 inflates it well past the cap

	err := b.Save(context.Background(), "big", r)
	require.Error(t, err)
	require.NotErrorIs(t, err, backend.ErrUnavailable, "over-limit is permanent, not retryable")
	require.Contains(t, err.Error(), "delete old versions")
	require.Empty(t, b.conn.items.(*fakeItems).byID, "the oversized item must not be written")
}

func TestMetaRoundTrip(t *testing.T) {
	r := &backend.Record{
		Name:     "x",
		Versions: map[api.SecretVersion][]byte{1: {0x00, 0x01, 0xff}, 5: []byte("hello")},
		Active:   5,
		Latest:   5,
		Deleted:  map[api.SecretVersion]struct{}{2: {}, 3: {}},
	}
	s, err := encodeMeta(r)
	require.NoError(t, err)
	got, err := decodeMeta("x", s)
	require.NoError(t, err)
	require.True(t, r.Equal(got))
}

// FuzzMetaRoundTrip asserts the hybrid serialization is lossless for arbitrary
// records, so no secret bytes or version metadata are ever corrupted on a write.
func FuzzMetaRoundTrip(f *testing.F) {
	f.Add("k", []byte("v"), uint32(1), uint32(1), uint32(2))
	f.Fuzz(func(t *testing.T, name string, val []byte, active, latest, deleted uint32) {
		if active == 0 {
			active = 1
		}

		if latest < active {
			latest = active
		}

		r := &backend.Record{
			Name:     name,
			Versions: map[api.SecretVersion][]byte{api.SecretVersion(active): val},
			Active:   api.SecretVersion(active),
			Latest:   api.SecretVersion(latest),
		}
		// Exercise multi-version records: add an older live version so round-trip
		// covers more than the active-only case.
		if active > 1 {
			r.Versions[api.SecretVersion(active-1)] = []byte("older")
		}

		if deleted != 0 && api.SecretVersion(deleted) != r.Active {
			if api.SecretVersion(deleted) > r.Latest {
				r.Latest = api.SecretVersion(deleted)
			}

			r.Deleted = map[api.SecretVersion]struct{}{api.SecretVersion(deleted): {}}
			// And a second deleted version when there is room, for multi-deleted coverage.
			if deleted > 1 && api.SecretVersion(deleted-1) != r.Active {
				if _, live := r.Versions[api.SecretVersion(deleted-1)]; !live {
					r.Deleted[api.SecretVersion(deleted-1)] = struct{}{}
				}
			}
		}

		s, err := encodeMeta(r)
		require.NoError(t, err)
		got, err := decodeMeta(name, s)
		require.NoError(t, err)
		require.True(t, r.Equal(got), "round-trip mismatch: %+v vs %+v", r, got)
	})
}

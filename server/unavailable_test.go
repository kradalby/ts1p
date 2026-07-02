package server_test

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/tailscale/setec/acl"
	"github.com/tailscale/setec/audit"

	"github.com/kradalby/ts1p/backend"
	"github.com/kradalby/ts1p/server"
	"github.com/kradalby/ts1p/store"
)

// unavailableBackend fails every operation with backend.ErrUnavailable, modeling
// an unreachable or under-scoped 1Password vault.
type unavailableBackend struct{}

func (unavailableBackend) Load(context.Context, string) (*backend.Record, error) {
	return nil, backend.ErrUnavailable
}

func (unavailableBackend) Save(context.Context, string, *backend.Record) error {
	return backend.ErrUnavailable
}

func (unavailableBackend) List(context.Context) ([]string, error) {
	return nil, backend.ErrUnavailable
}
func (unavailableBackend) Delete(context.Context, string) error { return backend.ErrUnavailable }
func (unavailableBackend) Close() error                         { return nil }

// A backend that is unreachable must surface as 503, not an opaque 500, so an
// authorized client knows to retry rather than treating it as a permanent fault.
func TestUnavailableBackendReturns503(t *testing.T) {
	mux := http.NewServeMux()
	st := store.New(unavailableBackend{})
	_, err := server.New(server.Config{
		Store: st,
		WhoIs: whoIsRule(t, &acl.Rule{Action: []acl.Action{acl.ActionGet}, Secret: []acl.Secret{"*"}}),
		Audit: audit.New(io.Discard),
		Mux:   mux,
	})
	require.NoError(t, err)

	hs := httptest.NewServer(mux)
	t.Cleanup(hs.Close)

	req, err := http.NewRequest(http.MethodPost, hs.URL+"/api/get", bytes.NewReader([]byte(`{"Name":"s"}`)))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Sec-X-Tailscale-No-Browsers", "setec")

	resp, err := hs.Client().Do(req)
	require.NoError(t, err)

	defer resp.Body.Close()

	require.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
}

// canceledBackend fails every read with context.Canceled, modeling a client
// that disconnected mid-request so the request context was cancelled.
type canceledBackend struct{}

func (canceledBackend) Load(context.Context, string) (*backend.Record, error) {
	return nil, context.Canceled
}

func (canceledBackend) Save(context.Context, string, *backend.Record) error { return context.Canceled }

func (canceledBackend) List(context.Context) ([]string, error) { return nil, context.Canceled }

func (canceledBackend) Delete(context.Context, string) error { return context.Canceled }
func (canceledBackend) Close() error                         { return nil }

// recordingHandler captures slog records so a test can assert on log level.
type recordingHandler struct {
	mu      sync.Mutex
	records []slog.Record
}

func (h *recordingHandler) Enabled(context.Context, slog.Level) bool { return true }
func (h *recordingHandler) Handle(_ context.Context, r slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.records = append(h.records, r)

	return nil
}
func (h *recordingHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *recordingHandler) WithGroup(string) slog.Handler      { return h }

func (h *recordingHandler) maxLevel() slog.Level {
	h.mu.Lock()
	defer h.mu.Unlock()

	lvl := slog.LevelDebug
	for _, r := range h.records {
		if r.Level > lvl {
			lvl = r.Level
		}
	}

	return lvl
}

func (h *recordingHandler) errorCount() int {
	h.mu.Lock()
	defer h.mu.Unlock()

	n := 0

	for _, r := range h.records {
		if r.Level >= slog.LevelError {
			n++
		}
	}

	return n
}

// A sustained backend outage must not log an error on every single request:
// the storage-unavailable log is rate-limited so a flood of failures stays
// readable (while still surfacing at least once).
func TestStorageUnavailableLogsAreRateLimited(t *testing.T) {
	logs := &recordingHandler{}
	mux := http.NewServeMux()
	st := store.New(unavailableBackend{})
	_, err := server.New(server.Config{
		Store:  st,
		WhoIs:  whoIsRule(t, &acl.Rule{Action: []acl.Action{acl.ActionGet}, Secret: []acl.Secret{"*"}}),
		Audit:  audit.New(io.Discard),
		Mux:    mux,
		Logger: slog.New(logs),
	})
	require.NoError(t, err)

	hs := httptest.NewServer(mux)
	t.Cleanup(hs.Close)

	const n = 10
	for range n {
		req, err := http.NewRequest(http.MethodPost, hs.URL+"/api/get", bytes.NewReader([]byte(`{"Name":"s"}`)))
		require.NoError(t, err)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Sec-X-Tailscale-No-Browsers", "setec")
		resp, err := hs.Client().Do(req)
		require.NoError(t, err)
		require.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
		resp.Body.Close()
	}

	require.GreaterOrEqual(t, logs.errorCount(), 1, "outage must surface at least once")
	require.Less(t, logs.errorCount(), n, "repeated storage errors must be rate-limited")
}

// A context.Canceled that is NOT this request's own — e.g. a coalesced fetch
// whose owning caller disconnected — must map to a retryable 503 with a body,
// never an implicit 200 with an empty body: real setec clients decode the body
// as JSON and break on emptiness. The live client here never cancelled anything.
func TestForeignCancellationIs503(t *testing.T) {
	mux := http.NewServeMux()
	st := store.New(canceledBackend{})
	_, err := server.New(server.Config{
		Store: st,
		WhoIs: whoIsRule(t, &acl.Rule{Action: []acl.Action{acl.ActionGet}, Secret: []acl.Secret{"*"}}),
		Audit: audit.New(io.Discard),
		Mux:   mux,
	})
	require.NoError(t, err)

	hs := httptest.NewServer(mux)
	t.Cleanup(hs.Close)

	req, err := http.NewRequest(http.MethodPost, hs.URL+"/api/get", bytes.NewReader([]byte(`{"Name":"s"}`)))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Sec-X-Tailscale-No-Browsers", "setec")

	resp, err := hs.Client().Do(req)
	require.NoError(t, err)

	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	require.Equal(t, http.StatusServiceUnavailable, resp.StatusCode,
		"a foreign cancellation is a retryable abort, not this caller going away")
	require.NotEmpty(t, body, "a live client must never receive a bodyless response")
}

// blockingBackend parks its (single) Load until the request context is
// cancelled, modeling a slow backend a client gives up on.
type blockingBackend struct{ entered, done chan struct{} }

func (b *blockingBackend) Load(ctx context.Context, _ string) (*backend.Record, error) {
	close(b.entered)
	<-ctx.Done()

	defer close(b.done)

	return nil, ctx.Err()
}

func (b *blockingBackend) Save(context.Context, string, *backend.Record) error {
	return backend.ErrUnavailable
}

func (b *blockingBackend) List(context.Context) ([]string, error) {
	return nil, backend.ErrUnavailable
}
func (b *blockingBackend) Delete(context.Context, string) error { return backend.ErrUnavailable }
func (b *blockingBackend) Close() error                         { return nil }

// A client that actually disconnects mid-request is the caller going away, not
// a storage outage: nothing is sent and nothing logs at ERROR.
func TestDisconnectedClientStaysSilent(t *testing.T) {
	logs := &recordingHandler{}
	be := &blockingBackend{entered: make(chan struct{}), done: make(chan struct{})}
	mux := http.NewServeMux()
	_, err := server.New(server.Config{
		Store:  store.New(be),
		WhoIs:  whoIsRule(t, &acl.Rule{Action: []acl.Action{acl.ActionGet}, Secret: []acl.Secret{"*"}}),
		Audit:  audit.New(io.Discard),
		Mux:    mux,
		Logger: slog.New(logs),
	})
	require.NoError(t, err)

	hs := httptest.NewServer(mux)
	t.Cleanup(hs.Close)

	ctx, cancel := context.WithCancel(context.Background())
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, hs.URL+"/api/get", bytes.NewReader([]byte(`{"Name":"s"}`)))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Sec-X-Tailscale-No-Browsers", "setec")

	errc := make(chan error, 1)

	go func() {
		resp, err := hs.Client().Do(req)
		if err == nil {
			resp.Body.Close()
		}

		errc <- err
	}()

	<-be.entered // the request has reached the backend
	cancel()     // ...and now the client disconnects while it is still working
	require.Error(t, <-errc, "the cancelled request must fail on the client side")
	<-be.done  // the handler's store call has returned
	hs.Close() // waits for in-flight handlers, so all logging has happened

	require.Less(t, logs.maxLevel(), slog.LevelError, "a disconnected client must not log at ERROR")
}

// Package onepassword implements backend.Backend on top of a 1Password vault,
// accessed through a service account with the official 1Password Go SDK.
//
// Each secret is one item in a dedicated vault, titled with the secret name,
// laid out in the "hybrid" form:
//
//   - a human-readable "value" field holding the active version's value, so the
//     secret can be read in the 1Password apps; and
//   - a "ts1p-meta" field holding the full version model (all versions, active,
//     latest, deleted) as JSON.
//
// ts1p-meta is the source of truth. The value field is a read-only convenience
// view: ts1p writes it but never reads it back, so editing it in the 1Password
// apps rotates nothing and the edit is overwritten on the next write. Rotate
// through the API, or (with care) edit the ts1p-meta JSON.
//
// This backend performs no caching or version logic; wrap it with
// backend/cache and drive it through store.Store.
package onepassword

import (
	"context"
	"encoding/json"
	"errors"
	"expvar"
	"fmt"
	"log/slog"
	"maps"
	"math/rand/v2"
	"os"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	op "github.com/1password/onepassword-sdk-go"
	"github.com/cenkalti/backoff/v5"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/tailscale/setec/types/api"

	"github.com/kradalby/ts1p/backend"
)

const (
	integrationName    = "ts1p"
	integrationVersion = "0.1.0"

	// metaField and valueField are used as both the field ID and Title on the
	// 1Password item (the SDK lets them coincide), so one constant covers both.
	metaField  = "ts1p-meta"
	valueField = "value"
)

// itemsAPI is the subset of the 1Password SDK's items API that this backend
// uses. The SDK's ItemsAPI satisfies it; tests supply a fake.
type itemsAPI interface {
	Create(ctx context.Context, params op.ItemCreateParams) (op.Item, error)
	Get(ctx context.Context, vaultID, itemID string) (op.Item, error)
	Put(ctx context.Context, item op.Item) (op.Item, error)
	Delete(ctx context.Context, vaultID, itemID string) error
	List(ctx context.Context, vaultID string, filters ...op.ItemListFilter) ([]op.ItemOverview, error)
}

// conn bundles the SDK client with its items handle. Both are retained for the
// Backend's lifetime: the SDK's GC finalizer calls ReleaseClient when the
// *op.Client is collected (client_builder.go), so dropping it while keeping the
// items handle releases the client out from under us ("invalid client id").
type conn struct {
	client *op.Client
	items  itemsAPI
}

// Backend is a 1Password-backed backend.Backend.
//
// The 1Password SDK's extism/wazero WASM core is a process-global instance that
// corrupts under sustained uptime (out-of-bounds memory access) and cannot be
// reloaded in-process on v0.4.0 — recreating the client reuses the same wedged
// core. The only reliable reset is a process restart. So instead of pretending
// to self-heal, the backend records faults, recycles proactively, and exits on
// confirmed corruption so systemd restarts with a fresh core. See kradalby/ts1p#2.
type Backend struct {
	log     *slog.Logger
	vaultID string
	conn    *conn // set once at start; never swapped (a swap would not reload the core)

	// connect establishes a vault-bound connection. A field so tests drive
	// startup retry without a real vault; in production it dials 1Password.
	connect func(ctx context.Context) (*conn, string, error)

	// startBackOff overrides the startup-retry schedule; nil uses the default
	// exponential. Tests shrink it.
	startBackOff backoff.BackOff

	// retryBackOff builds the per-call transient-retry schedule; nil uses the
	// default exponential. A factory (not an instance): backoffs are stateful
	// and calls run concurrently. Tests shrink it.
	retryBackOff func() backoff.BackOff

	// TODO(kradalby): the fields below exist only to work around the SDK's WASM
	// core corruption; remove them when kradalby/ts1p#2 is fixed upstream.
	maxAge      time.Duration    // 0 disables proactive recycle
	recycleAt   time.Time        // born + maxAge - jitter; zero when disabled
	callTimeout time.Duration    // bounds one SDK call; 0 means sdkCallTimeout (tests shrink it)
	now         func() time.Time // defaults to time.Now; tests inject a fixed clock
	exit        func(int)        // defaults to os.Exit; tests capture the code

	oob            atomic.Int64 // out-of-bounds faults seen at the call boundary
	ctxCanceled    atomic.Int64 // requests abandoned by the caller
	coreTimeout    atomic.Int64 // SDK calls that blew the backend's own sdkCallTimeout
	consecTimeouts atomic.Int64 // core timeouts with no intervening success; reset on any success
	rateLimited    atomic.Int64 // calls refused by 1Password's service-account quota
	authFailed     atomic.Int64 // calls that failed looking like a credential problem
	lastFault      atomic.Pointer[faultInfo]

	// idmu guards ids, a title→item-ID memo populated from every full-vault
	// List. Item IDs are stable for an item's lifetime, so this removes the
	// full-vault List from every single-secret op (the SDK has no title filter);
	// titles shared by several items are left out so findID still fails closed.
	idmu sync.Mutex
	ids  map[string]string
}

// publishOnce guards the process-global /debug/vars registration: the WASM core
// is a singleton, so ts1p runs one Backend per process and the first one's
// counters are published. A second Backend (only tests do this) reuses its own
// atomics via OOBCount/CtxCanceledCount and does not re-register (which would panic).
var publishOnce sync.Once

// lastFaultTS is the process-global gauge set by recordFault. It is registered
// once by publishVars (under publishOnce, like the counters); recordFault reads
// it, so a Backend created before publishVars ran sees nil and skips the set.
var lastFaultTS *prometheus.GaugeVec

// New connects to 1Password with the given service account token and returns a
// Backend bound to the vault with the given title. maxAge, if > 0, recycles the
// process (exits for a clean restart) once the WASM core has been alive that
// long; see kradalby/ts1p#2.
//
// The token must come from the environment (e.g. OP_SERVICE_ACCOUNT_TOKEN); do
// not pass it on the command line.
func New(ctx context.Context, token, vaultName string, log *slog.Logger, maxAge time.Duration) (*Backend, error) {
	if token == "" {
		return nil, errEmptyToken
	}

	if log == nil {
		log = slog.Default()
	}

	b := &Backend{
		log:    log,
		maxAge: maxAge,
		now:    time.Now,
		exit:   os.Exit,
		connect: func(ctx context.Context) (*conn, string, error) {
			return connectVault(ctx, token, vaultName)
		},
	}

	err := b.start(ctx)
	if err != nil {
		return nil, err
	}

	b.publishVars()

	return b, nil
}

// publishVars exposes this Backend's fault counters as Prometheus counters and
// its last fault on /debug/vars. Both are live views over the Backend's own
// atomics (one source of truth, no lock-stepped copy): the counters are read
// internally (OOBCount, CtxCanceledCount) and by tests, so a CounterFunc reads
// the atomic rather than replacing it.
//
// The last fault's numeric signal is a Prometheus gauge
// (ts1p_op_last_fault_timestamp_seconds, by bounded class/op labels). Only the
// high-cardinality WASM frame stays off Prometheus — it is forensic text, not a
// metric, and is served as the ts1p_op_last_fault expvar for on-demand inspection.
func (b *Backend) publishVars() {
	publishOnce.Do(func() {
		counter := func(name, help string, read func() int64) {
			promauto.NewCounterFunc(prometheus.CounterOpts{Name: name, Help: help},
				func() float64 { return float64(read()) })
		}

		counter("ts1p_op_oob_total", "1Password WASM out-of-bounds faults.", b.oob.Load)
		counter("ts1p_op_ctx_canceled_total", "Requests abandoned by the caller.", b.ctxCanceled.Load)
		counter("ts1p_op_core_timeout_total", "SDK calls that blew the backend's own timeout.", b.coreTimeout.Load)
		counter("ts1p_op_rate_limited_total", "Calls refused by 1Password's service-account quota.", b.rateLimited.Load)
		counter("ts1p_op_auth_failed_total", "Calls that failed looking like a credential problem.", b.authFailed.Load)

		lastFaultTS = promauto.NewGaugeVec(prometheus.GaugeOpts{
			Name: "ts1p_op_last_fault_timestamp_seconds",
			Help: "Unix time of the most recent 1Password WASM fault, by class and op.",
		}, []string{"class", "op"})

		expvar.Publish("ts1p_op_last_fault", expvar.Func(func() any {
			if fi := b.lastFault.Load(); fi != nil {
				return fi
			}

			return nil
		}))
	})
}

// errVaultNotFound is a permanent startup error: the configured vault title does
// not exist, so retrying cannot help.
var errVaultNotFound = errors.New("onepassword: vault not found")

// errEmptyToken rejects construction without a service account token.
var errEmptyToken = errors.New("onepassword: empty service account token")

// errEmptySecretName refuses a write with no name, which would otherwise create
// an untitled vault item. Reads treat an empty name as a plain not-found.
var errEmptySecretName = errors.New("onepassword: empty secret name")

// errDuplicateTitles fails closed on ambiguous item titles: 1Password does not
// enforce unique titles, and silently picking one would let Load/Save/Delete
// disagree about which item they mean.
var errDuplicateTitles = errors.New("onepassword: duplicate item titles in the vault; resolve the duplicate")

// errMetaTooLarge refuses a write whose encoded ts1p-meta would exceed
// 1Password's item ceiling. Deliberately permanent (not ErrUnavailable): a
// retryable 503 would send clients into a futile loop.
var errMetaTooLarge = errors.New("ts1p-meta is over 1Password's ~1MiB item limit; delete old versions (delete-version) to shrink it")

// errInvalidRecord marks a structurally-inconsistent stored record (a
// hand-edited or truncated item), so it fails loudly naming the secret rather
// than surfacing later as an opaque store-layer 500.
var errInvalidRecord = errors.New("onepassword: invalid stored record")

// start establishes the initial connection, retrying transient failures with
// backoff until ctx is cancelled. Deliberately unbounded in time: this is the
// secrets server the rest of the infrastructure boots against, and a bounded
// retry that exits during an ordinary upstream outage trips systemd's
// start-limit and parks the unit in failed state — a permanent, human-gated
// outage manufactured from a temporary one. Misconfiguration (bad vault name,
// bad credentials) still fails fast via backoff.Permanent below.
func (b *Backend) start(ctx context.Context) error {
	var opts []backoff.RetryOption
	if b.startBackOff != nil {
		opts = append(opts, backoff.WithBackOff(b.startBackOff))
	}

	_, err := backoff.Retry(ctx, func() (struct{}, error) {
		c, vaultID, err := b.connect(ctx)
		if err != nil {
			b.log.Warn("connecting to 1Password failed, retrying", "err", err)
			// A misconfigured vault name or a bad credential never resolves;
			// fail fast instead of retrying for the full startup window (and
			// crash-looping systemd).
			if errors.Is(err, errVaultNotFound) || isAuthError(err) {
				return struct{}{}, backoff.Permanent(err)
			}

			return struct{}{}, err
		}

		b.vaultID = vaultID
		b.conn = c

		return struct{}{}, nil
	}, opts...)
	if err != nil {
		return err
	}
	// TODO(kradalby): remove with the rest of the WASM-core workaround (#2).
	if b.maxAge > 0 {
		// Jitter down by up to 10% so a fleet does not recycle in lockstep.
		//nolint:gosec // scheduling jitter, not security-sensitive
		jitter := rand.N(b.maxAge/10 + 1)
		b.recycleAt = b.now().Add(b.maxAge - jitter)
	}

	return nil
}

// connectVault is the production connect: it dials 1Password, resolves the
// vault by title, and probes the items API before returning a ready conn.
func connectVault(ctx context.Context, token, vaultName string) (*conn, string, error) {
	client, err := op.NewClient(
		ctx,
		op.WithServiceAccountToken(token),
		op.WithIntegrationInfo(integrationName, integrationVersion),
	)
	if err != nil {
		return nil, "", fmt.Errorf("onepassword: creating client: %w: %w", backend.ErrUnavailable, err)
	}

	vaults, err := client.Vaults().List(ctx)
	if err != nil {
		return nil, "", fmt.Errorf("onepassword: listing vaults: %w: %w", backend.ErrUnavailable, err)
	}

	var vaultID string

	for _, v := range vaults {
		if v.Title == vaultName {
			vaultID = v.ID
			break
		}
	}

	if vaultID == "" {
		return nil, "", fmt.Errorf("%w: %q (service accounts cannot use the Private vault)", errVaultNotFound, vaultName)
	}

	c := &conn{client: client, items: client.Items()}

	// Probe the items API up front so a scope or token problem fails here rather
	// than on the first client request.
	_, err = c.items.List(ctx, vaultID)
	if err != nil {
		return nil, "", fmt.Errorf("onepassword: probing items in vault %q: %w: %w", vaultName, backend.ErrUnavailable, err)
	}

	return c, vaultID, nil
}

// sdkCallTimeout bounds a single SDK call. The request context is deliberately
// NOT threaded into the call (see call); this is the backend's own ceiling so a
// wedged core surfaces as an outage rather than hanging the request.
const sdkCallTimeout = 30 * time.Second

// faultRetries is how many times call re-runs an op whose first attempt hit a
// WASM fault (the same global core, so a retry can only clear a transient one)
// before declaring the core wedged and exiting. Non-retryable ops skip it.
const faultRetries = 1

// call runs fn against the SDK with bounded retry, decoupling the SDK call from
// the request context and turning a corrupted WASM core into a clean restart.
//
// retryable says whether fn is safe to re-run on a transient error. Reads are;
// mutations (Create/Put) are not — re-running one that already took effect on the
// server would duplicate or double-apply it, so a transient mutation error is
// surfaced to the caller instead.
//
// TODO(kradalby): the fault detection, retry, and exit here exist only to work
// around the SDK's WASM-core corruption; remove when kradalby/ts1p#2 is fixed.
func (b *Backend) call[T any](ctx context.Context, label string, retryable bool, fn func(context.Context, itemsAPI) (T, error)) (T, error) {
	var zero T

	start := b.now()

	b.recycleIfStale()

	// Caller already gone: don't spend a core call on it.
	err := ctx.Err()
	if err != nil {
		b.noteCancel()
		return zero, err
	}

	// Decouple the SDK call from the request context. A client disconnect must
	// not cancel an in-flight core call mid-input-copy (the suspected OOB
	// trigger), and the SDK won't honour cancellation inside wasm anyway; our own
	// deadline bounds a stuck core instead. See kradalby/ts1p#2.
	timeout := b.callTimeout
	if timeout <= 0 {
		timeout = sdkCallTimeout
	}

	callCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), timeout)
	defer cancel()

	tries := 0
	if retryable {
		tries = faultRetries
	}

	var v T
	for attempt := 0; ; attempt++ {
		v, err = b.runOp(callCtx, retryable, fn)
		if err == nil || !isClientFault(err) {
			break
		}

		b.recordFault(label, err, ctx.Err() != nil, b.now().Sub(start))
		// A client disconnect that coincides with a fault is not confirmed
		// corruption — do not exit the process for a caller that has gone away.
		if ctx.Err() != nil {
			b.noteCancel()
			return zero, ctx.Err()
		}

		if attempt >= tries {
			b.log.Error("1Password WASM core corrupted (fault survived retry); exiting for a clean restart",
				"op", label, "frame", firstWasmFrame(err))
			b.exit(1)

			return zero, classify(label, err)
		}
	}

	// Caller left while we worked: report quietly, not as a storage outage.
	if ctx.Err() != nil {
		b.noteCancel()
		return zero, ctx.Err()
	}

	if err == nil {
		b.consecTimeouts.Store(0)
		return v, nil
	}
	// Our own deadline fired while the request was still live: the core is hung.
	// Repeated core timeouts are as strong a recycle signal as an OOB — each one
	// also leaks a goroutine parked on the SDK's global lock — so after a few in
	// a row with no success in between, exit for a clean restart instead of
	// browning out forever.
	if errors.Is(err, context.DeadlineExceeded) {
		b.recordTimeout(label)

		if b.consecTimeouts.Add(1) >= maxConsecTimeouts {
			b.log.Error("1Password WASM core hung (consecutive call timeouts); exiting for a clean restart",
				"op", label, "consecutive", b.consecTimeouts.Load())
			b.exit(1)
		}
	}

	if isRateLimited(err) {
		b.rateLimited.Add(1)
	}

	if isAuthError(err) {
		b.authFailed.Add(1)
	}

	return v, classify(label, err)
}

// maxConsecTimeouts is how many core timeouts in a row (no intervening
// successful call) confirm a hung core and trigger a recycle exit.
//
// TODO(kradalby): remove with the rest of the WASM-core workaround (#2).
const maxConsecTimeouts = 3

// isRateLimited reports whether err is 1Password refusing the call on the
// service account's API quota — the one failure the SDK types, and the one
// that retrying can only make worse.
func isRateLimited(err error) bool {
	var rle *op.RateLimitExceededError
	return errors.As(err, &rle)
}

// isAuthError reports whether err looks like a permanent credential failure
// (revoked or malformed service-account token, lost vault access). The SDK
// surfaces these only as strings; the substrings below come from observed SDK
// errors — extend the list (and its test) when a new one is captured. A false
// negative just means the old keep-retrying behaviour.
func isAuthError(err error) bool {
	s := strings.ToLower(err.Error())

	return strings.Contains(s, "invalid bearer token") ||
		strings.Contains(s, "invalid user credentials") ||
		strings.Contains(s, "token is invalid") ||
		strings.Contains(s, "unauthorized") ||
		strings.Contains(s, "not authorized")
}

// runOp runs fn, racing it against ctx so the backend's sdkCallTimeout actually
// bounds a hung WASM call (the SDK does not honour cancellation inside wasm). A
// timed-out goroutine is abandoned; it holds the SDK's global lock until the
// process recycles, which is the documented failure mode. Retryable ops get
// bounded transient-retry; non-retryable ops run exactly once.
func (b *Backend) runOp[T any](ctx context.Context, retryable bool, fn func(context.Context, itemsAPI) (T, error)) (T, error) {
	once := func() (T, error) { return raceCtx(ctx, func() (T, error) { return fn(ctx, b.conn.items) }) }
	if !retryable {
		return once()
	}

	opts := []backoff.RetryOption{backoff.WithMaxTries(4)}
	if b.retryBackOff != nil {
		opts = append(opts, backoff.WithBackOff(b.retryBackOff()))
	}

	return backoff.Retry(ctx, func() (T, error) {
		v, err := once()
		// Never re-run a WASM fault here (the shared core needs the outer
		// fault handling) and never retry into a rate limit — the quota resets
		// on the hour, so immediate retries are pure amplification.
		if err != nil && (isClientFault(err) || isRateLimited(err)) {
			return v, backoff.Permanent(err)
		}

		return v, err
	}, opts...)
}

// raceCtx runs fn in a goroutine and returns its result, or ctx's error if ctx
// is done first. The buffered channel lets an abandoned goroutine finish and exit
// without blocking, so nothing leaks beyond the in-flight SDK call itself.
func raceCtx[T any](ctx context.Context, fn func() (T, error)) (T, error) {
	type result struct {
		v   T
		err error
	}

	ch := make(chan result, 1)

	go func() {
		v, err := fn()
		ch <- result{v, err}
	}()

	select {
	case <-ctx.Done():
		var zero T
		return zero, ctx.Err()
	case r := <-ch:
		return r.v, r.err
	}
}

// classify wraps a failed SDK call as backend.ErrUnavailable under a label.
// Request-context cancellation is handled in call (returned bare); anything that
// reaches here — including the backend's own sdkCallTimeout — is a storage fault.
// A quota refusal additionally carries backend.ErrRateLimited so the warmer can
// stop hammering a limit that resets on the hour.
func classify(label string, err error) error {
	if err == nil {
		return nil
	}

	if isRateLimited(err) {
		return fmt.Errorf("onepassword: %s: %w: %w: %w", label, backend.ErrUnavailable, backend.ErrRateLimited, err)
	}

	return fmt.Errorf("onepassword: %s: %w: %w", label, backend.ErrUnavailable, err)
}

func (b *Backend) noteCancel() {
	b.ctxCanceled.Add(1)
}

// recordTimeout counts a self-inflicted sdkCallTimeout (a hung core), distinct
// from an OOB so it is independently alertable.
func (b *Backend) recordTimeout(label string) {
	b.coreTimeout.Add(1)
	b.log.Warn("1Password SDK call timed out (core may be hung)", "op", label, "timeout", sdkCallTimeout)
}

// recycleIfStale exits the process once the WASM core has been alive past
// recycleAt, so systemd restarts with a fresh core before corruption sets in.
// The background cache warmer drives this path off the request path, which is
// intentional: a recycle is a clean restart, and the warmer is the main thing
// keeping the core busy. Recycling is opt-in (op-max-age, default 0).
//
// TODO(kradalby): remove with the rest of the WASM-core workaround (#2).
func (b *Backend) recycleIfStale() {
	if b.recycleAt.IsZero() || b.now().Before(b.recycleAt) {
		return
	}

	b.log.Warn("recycling 1Password WASM core: max age reached, exiting for a clean restart", "max_age", b.maxAge)
	b.exit(0)
}

// --- WASM-core fault forensics. TODO(kradalby): remove when kradalby/ts1p#2 is
// fixed; a naive liveness probe can't catch the fault (the error is caught and
// the server stays up), so these counters are how a real crash gets diagnosed.
// The counters live on the Backend and are published once via publishVars, so
// there is a single source of truth rather than a lock-stepped global copy.

const (
	faultOOB           = "out_of_bounds"
	faultInvalidClient = "invalid_client_id"
	faultWASM          = "wasm"
)

// faultInfo is the most recent WASM fault, published on /debug/vars.
type faultInfo struct {
	Time          time.Time `json:"time"`
	Class         string    `json:"class"`
	Op            string    `json:"op"`
	CtxCanceled   bool      `json:"ctxCanceled"`
	LatencyMillis int64     `json:"latencyMs"`
	Frame         string    `json:"frame"`
}

func (b *Backend) recordFault(label string, err error, ctxCanceled bool, latency time.Duration) {
	fi := &faultInfo{
		Time:          b.now(),
		Class:         faultClass(err),
		Op:            label,
		CtxCanceled:   ctxCanceled,
		LatencyMillis: latency.Milliseconds(),
		Frame:         firstWasmFrame(err),
	}
	b.lastFault.Store(fi)

	if lastFaultTS != nil {
		lastFaultTS.WithLabelValues(fi.Class, fi.Op).Set(float64(fi.Time.Unix()))
	}

	if fi.Class == faultOOB {
		b.oob.Add(1)
	}

	b.log.Warn("1Password WASM fault",
		"class", fi.Class, "op", label, "ctx_canceled", ctxCanceled,
		"latency_ms", fi.LatencyMillis, "frame", fi.Frame)
}

// OOBCount returns the number of out-of-bounds WASM faults observed.
func (b *Backend) OOBCount() int64 { return b.oob.Load() }

// CtxCanceledCount returns the number of requests abandoned by the caller.
func (b *Backend) CtxCanceledCount() int64 { return b.ctxCanceled.Load() }

// isClientFault reports whether err is a WASM-core fault. Matched on the SDK's
// opaque error string, since it surfaces no typed errors for these.
func isClientFault(err error) bool {
	s := err.Error()

	return strings.Contains(s, "out of bounds memory access") || // wedged WASM instance (the recurring killer)
		strings.Contains(s, "invalid client id") || // client released out from under us
		strings.Contains(s, "wasm error") // any other WASM-core fault
}

func faultClass(err error) string {
	s := err.Error()
	switch {
	case strings.Contains(s, "out of bounds memory access"):
		return faultOOB
	case strings.Contains(s, "invalid client id"):
		return faultInvalidClient
	default:
		return faultWASM
	}
}

// firstWasmFrame extracts the first wasm stack frame from a fault for forensics.
func firstWasmFrame(err error) string {
	for line := range strings.SplitSeq(err.Error(), "\n") {
		if line = strings.TrimSpace(line); strings.HasPrefix(line, "op_extism_core.wasm.") {
			return line
		}
	}

	first, _, _ := strings.Cut(err.Error(), "\n")

	return first
}

// findID returns the item ID for the secret named name, from the memo when it
// has one, otherwise from a fresh vault listing. An empty name can never exist,
// so it is simply not found (keeping status codes backend-independent).
func (b *Backend) findID(ctx context.Context, name string) (string, bool, error) {
	if name == "" {
		return "", false, nil
	}

	b.idmu.Lock()
	id, found := b.ids[name]
	b.idmu.Unlock()

	if found {
		return id, true, nil
	}

	return b.resolveID(ctx, name)
}

// resolveID lists the vault to resolve name to an item ID (the SDK has no title
// filter), refreshing the whole memo as a side effect. It fails closed: a vault
// with two items sharing a title is ambiguous (1Password does not enforce unique
// titles), so rather than silently picking one — and letting Load/Save/Delete
// disagree about which — it returns an error naming the collision. This backend
// assumes a single writer and a dedicated vault.
func (b *Backend) resolveID(ctx context.Context, name string) (string, bool, error) {
	overviews, err := b.call(ctx, "listing items", true, func(ctx context.Context, items itemsAPI) ([]op.ItemOverview, error) {
		return items.List(ctx, b.vaultID)
	})
	if err != nil {
		return "", false, err
	}

	b.rememberIDs(overviews)

	var id string

	n := 0

	for _, o := range overviews {
		if o.Title == name {
			id = o.ID
			n++
		}
	}

	if n > 1 {
		b.log.Warn("multiple 1Password items share a title; refusing to guess", "name", name, "count", n)
		return "", false, fmt.Errorf("%w: %d items titled %q", errDuplicateTitles, n, name)
	}

	return id, n == 1, nil
}

// rememberIDs rebuilds the title→ID memo from a full vault listing. Duplicated
// titles are left out so a memoized hit can never bypass resolveID's
// fail-closed collision check.
func (b *Backend) rememberIDs(overviews []op.ItemOverview) {
	ids := make(map[string]string, len(overviews))
	dup := make(map[string]bool)

	for _, o := range overviews {
		if _, seen := ids[o.Title]; seen {
			dup[o.Title] = true
		}

		ids[o.Title] = o.ID
	}

	for t := range dup {
		delete(ids, t)
	}

	b.idmu.Lock()
	b.ids = ids
	b.idmu.Unlock()
}

// forgetID drops one memoized ID (the item vanished or the memo proved stale).
func (b *Backend) forgetID(name string) {
	b.idmu.Lock()
	delete(b.ids, name)
	b.idmu.Unlock()
}

// rememberID memoizes a single freshly-created item.
func (b *Backend) rememberID(name, id string) {
	b.idmu.Lock()
	if b.ids == nil {
		b.ids = map[string]string{}
	}

	b.ids[name] = id
	b.idmu.Unlock()
}

// getItem fetches one item by ID.
func (b *Backend) getItem(ctx context.Context, id string) (op.Item, error) {
	return b.call(ctx, "getting item", true, func(ctx context.Context, items itemsAPI) (op.Item, error) {
		return items.Get(ctx, b.vaultID, id)
	})
}

// Load implements backend.Backend.
func (b *Backend) Load(ctx context.Context, name string) (*backend.Record, error) {
	id, found, err := b.findID(ctx, name)
	if err != nil {
		return nil, err
	}

	if !found {
		return nil, backend.ErrNotFound
	}

	item, err := b.getItem(ctx, id)
	if err != nil {
		// The item may be gone (deleted between listing and Get, or a stale
		// memo). Re-resolve from a fresh listing rather than trusting the SDK's
		// unstable error strings: genuinely gone is a not-found, not an outage.
		b.forgetID(name)

		id2, found, ferr := b.resolveID(ctx, name)
		if ferr != nil || !found {
			if ferr != nil {
				return nil, ferr
			}

			return nil, backend.ErrNotFound
		}

		if id2 == id {
			return nil, err // same live item: the Get failure was real
		}

		item, err = b.getItem(ctx, id2)
		if err != nil {
			return nil, err
		}
	}

	return recordFromItem(name, item)
}

// metaWarnBytes and metaMaxBytes police the encoded ts1p-meta size. setec
// semantics keep every version forever, and the whole map lives in one
// 1Password field, so a frequently-rotated secret grows monotonically toward
// 1Password's ~1MiB item ceiling — where every Save would fail permanently.
// Refusing our own writes at 1MiB with an actionable error beats the SDK's
// opaque one, and the warning gives notice long before.
const (
	metaWarnBytes = 512 << 10
	metaMaxBytes  = 1 << 20
)

// Save implements backend.Backend.
func (b *Backend) Save(ctx context.Context, name string, r *backend.Record) error {
	// Reads of an empty name are a plain not-found (it can never exist), but a
	// write must be refused here too or it would create an untitled vault item.
	if name == "" {
		return errEmptySecretName
	}

	fields, metaLen, err := recordToFields(r)
	if err != nil {
		return err
	}

	if metaLen > metaMaxBytes {
		return fmt.Errorf("onepassword: item %q: %w (%d bytes)", name, errMetaTooLarge, metaLen)
	}

	if metaLen > metaWarnBytes {
		b.log.Warn("ts1p-meta is growing toward 1Password's ~1MiB item limit; delete old versions to shrink it",
			"name", name, "bytes", metaLen)
	}

	id, found, err := b.findID(ctx, name)
	if err != nil {
		return err
	}

	if !found {
		return b.create(ctx, name, fields)
	}

	// Update in place, preserving the item's ID and version for the SDK's
	// optimistic concurrency.
	item, err := b.call(ctx, "getting item for update", true, func(ctx context.Context, items itemsAPI) (op.Item, error) {
		return items.Get(ctx, b.vaultID, id)
	})
	if err != nil {
		// The item may have been deleted between findID and Get (or the memo is
		// stale). Re-check via a fresh listing (not the error string, which the
		// SDK does not stabilize); if it is genuinely gone, create it, otherwise
		// surface the error.
		b.forgetID(name)

		_, stillThere, ferr := b.resolveID(ctx, name)
		if ferr == nil && !stillThere {
			return b.create(ctx, name, fields)
		}

		return err
	}
	// Merge: keep any fields a human added to the item, replacing only the two
	// fields ts1p owns, so an out-of-band note or section is not silently dropped.
	merged := make([]op.ItemField, 0, len(item.Fields)+len(fields))
	for _, f := range item.Fields {
		if !isManagedField(f) {
			merged = append(merged, f)
		}
	}

	merged = append(merged, fields...)
	item.Fields = merged
	// Put is not retryable: a re-run after a transient error that already applied
	// would double-write.
	_, err = b.call(ctx, "updating item", false, func(ctx context.Context, items itemsAPI) (op.Item, error) {
		return items.Put(ctx, item)
	})

	return err
}

// create makes a new item for name. Create is not retryable: re-running one that
// already took effect on the server would produce a duplicate item.
func (b *Backend) create(ctx context.Context, name string, fields []op.ItemField) error {
	item, err := b.call(ctx, "creating item", false, func(ctx context.Context, items itemsAPI) (op.Item, error) {
		return items.Create(ctx, op.ItemCreateParams{
			Category: op.ItemCategoryPassword,
			VaultID:  b.vaultID,
			Title:    name,
			Fields:   fields,
		})
	})
	if err != nil {
		return err
	}

	b.rememberID(name, item.ID)

	return nil
}

// List implements backend.Backend. Every listing also refreshes the title→ID
// memo, so the warmer's periodic relist keeps single-secret ops one SDK call.
func (b *Backend) List(ctx context.Context) ([]string, error) {
	overviews, err := b.call(ctx, "listing items", true, func(ctx context.Context, items itemsAPI) ([]op.ItemOverview, error) {
		return items.List(ctx, b.vaultID)
	})
	if err != nil {
		return nil, err
	}

	b.rememberIDs(overviews)

	names := make([]string, 0, len(overviews))
	for _, o := range overviews {
		names = append(names, o.Title)
	}

	return names, nil
}

// Delete implements backend.Backend. Delete is not retryable: re-running one that
// already removed the item would fail on a now-missing item.
func (b *Backend) Delete(ctx context.Context, name string) error {
	id, found, err := b.findID(ctx, name)
	if err != nil {
		return err
	}

	if !found {
		return nil // no-op, matching backend semantics
	}

	_, err = b.call(ctx, "deleting item", false, func(ctx context.Context, items itemsAPI) (struct{}, error) {
		return struct{}{}, items.Delete(ctx, b.vaultID, id)
	})
	if err == nil {
		b.forgetID(name)
	}

	return err
}

// Close implements backend.Backend. The SDK client needs no explicit close.
func (b *Backend) Close() error { return nil }

// --- hybrid serialization (pure, unit-tested and fuzzed) ---

// meta is the JSON form of a Record stored in the ts1p-meta field. Versions
// values are []byte, which encoding/json renders as base64, keeping arbitrary
// binary secrets lossless.
type meta struct {
	Active   api.SecretVersion            `json:"active"`
	Latest   api.SecretVersion            `json:"latest"`
	Versions map[api.SecretVersion][]byte `json:"versions"`
	Deleted  []api.SecretVersion          `json:"deleted,omitempty"`
}

func encodeMeta(r *backend.Record) (string, error) {
	err := validateRecord(r.Name, r)
	if err != nil {
		return "", err
	}

	m := meta{
		Active: r.Active, Latest: r.Latest, Versions: r.Versions,
		Deleted: slices.Sorted(maps.Keys(r.Deleted)),
	}

	b, err := json.Marshal(m)
	if err != nil {
		return "", fmt.Errorf("encoding ts1p-meta: %w", err)
	}

	return string(b), nil
}

func decodeMeta(name, s string) (*backend.Record, error) {
	var m meta

	err := json.Unmarshal([]byte(s), &m)
	if err != nil {
		return nil, fmt.Errorf("decoding ts1p-meta for %q: %w", name, err)
	}

	r := &backend.Record{
		Name:     name,
		Active:   m.Active,
		Latest:   m.Latest,
		Versions: m.Versions,
	}
	if r.Versions == nil {
		r.Versions = map[api.SecretVersion][]byte{}
	}

	if len(m.Deleted) > 0 {
		r.Deleted = make(map[api.SecretVersion]struct{}, len(m.Deleted))
		for _, v := range m.Deleted {
			r.Deleted[v] = struct{}{}
		}
	}

	err = validateRecord(name, r)
	if err != nil {
		return nil, err
	}

	return r, nil
}

// validateRecord rejects a structurally-inconsistent record so a hand-edited or
// truncated 1Password item fails loudly (naming the secret) rather than
// surfacing later as an opaque store-layer 500. A versionless record is allowed
// (it is the absent/empty case).
func validateRecord(name string, r *backend.Record) error {
	if len(r.Versions) == 0 {
		return nil
	}

	if _, ok := r.Versions[r.Active]; !ok {
		return fmt.Errorf("%w: item %q: active version %d not present in versions", errInvalidRecord, name, r.Active)
	}

	for v := range r.Versions {
		if v > r.Latest {
			return fmt.Errorf("%w: item %q: version %d exceeds latest %d", errInvalidRecord, name, v, r.Latest)
		}
	}

	return nil
}

// humanValue renders the active value for the human-readable field. Non-UTF-8
// values are not placed verbatim into a 1Password string field; ts1p-meta holds
// the lossless copy regardless.
func humanValue(r *backend.Record) string {
	v := r.Versions[r.Active]
	if !utf8.Valid(v) {
		return "(binary value; see " + metaField + ")"
	}

	return string(v)
}

// recordToFields renders r as the two managed item fields, also reporting the
// encoded meta size so Save can police 1Password's item size ceiling.
func recordToFields(r *backend.Record) ([]op.ItemField, int, error) {
	m, err := encodeMeta(r)
	if err != nil {
		return nil, 0, err
	}
	// Both fields are Concealed: ts1p-meta is the source of truth and carries
	// every version's value, so it must not render unmasked in the 1Password apps
	// or exports.
	return []op.ItemField{
		{ID: valueField, Title: valueField, FieldType: op.ItemFieldTypeConcealed, Value: humanValue(r)},
		{ID: metaField, Title: metaField, FieldType: op.ItemFieldTypeConcealed, Value: m},
	}, len(m), nil
}

// isManagedField reports whether f is one of the two fields ts1p owns, so an
// update can replace them without clobbering fields a human added to the item.
func isManagedField(f op.ItemField) bool {
	switch f.Title {
	case metaField, valueField:
		return true
	}

	switch f.ID {
	case metaField, valueField:
		return true
	}

	return false
}

func recordFromItem(name string, item op.Item) (*backend.Record, error) {
	for _, f := range item.Fields {
		if f.Title == metaField || f.ID == metaField {
			return decodeMeta(name, f.Value)
		}
	}
	// No ts1p-meta field: this is not a ts1p item (a foreign vault item, or one
	// edited beyond recognition). Treat as absent so store.List skips it rather
	// than failing the whole listing.
	return nil, backend.ErrNotFound
}

// Command ts1p runs a setec-wire-compatible secrets server backed by a
// 1Password vault. Existing setec clients talk to it unchanged; secrets live in
// 1Password instead of an encrypted local database, so there is no KMS key to
// manage.
//
// Configuration is via flags or the matching TS1P_-prefixed environment
// variables (e.g. TS1P_VAULT). The 1Password service account token is read from
// OP_SERVICE_ACCOUNT_TOKEN and never accepted as a flag.
package main

import (
	"context"
	"errors"
	"expvar"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime/debug"
	"strings"
	"syscall"
	"time"

	"github.com/arl/statsviz"
	"github.com/mdlayher/sdnotify"
	"github.com/peterbourgon/ff/v4"
	"github.com/peterbourgon/ff/v4/ffhelp"
	"github.com/pires/go-proxyproto"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/tailscale/setec/audit"
	"tailscale.com/envknob"
	"tailscale.com/tailcfg"
	"tailscale.com/tsnet"
	"tailscale.com/tsweb"

	// Registers the combined expvar+Prometheus handler at /debug/varz on any
	// tsweb.Debugger (via its init), so the loopback debug listener exports the
	// Prometheus registry there too.
	_ "tailscale.com/tsweb/promvarz"

	"github.com/kradalby/ts1p/backend"
	"github.com/kradalby/ts1p/backend/cache"
	"github.com/kradalby/ts1p/backend/mem"
	"github.com/kradalby/ts1p/backend/onepassword"
	"github.com/kradalby/ts1p/server"
	"github.com/kradalby/ts1p/store"
)

func main() {
	os.Exit(run())
}

func run() int {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	// The level lives in a LevelVar because flags are parsed after the logger
	// must already exist (flag-parse errors need somewhere to go).
	lvl := new(slog.LevelVar)
	log := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: lvl}))
	// Package-level logging (e.g. store's skip-unreadable warning) must land in
	// the same handler as everything else.
	slog.SetDefault(log)

	cmd := newCommand(log, lvl)

	err := cmd.ParseAndRun(ctx, os.Args[1:], ff.WithEnvVarPrefix("TS1P"))
	if err != nil {
		if errors.Is(err, ff.ErrHelp) {
			fmt.Fprintln(os.Stderr, ffhelp.Command(cmd))
			return 0
		}

		log.Error("ts1p failed", "err", err)

		return 1
	}

	return 0
}

type config struct {
	hostname        *string
	stateDir        *string
	vault           *string
	loginServer     *string
	cacheExpiry     *time.Duration
	cacheMaxEntries *int
	cacheWarm       *bool
	opMaxAge        *time.Duration
	service         *string
	logLevel        *string
	debugAddr       *string
	dev             *bool
}

func newCommand(log *slog.Logger, lvl *slog.LevelVar) *ff.Command {
	fs := ff.NewFlagSet("ts1p")
	cfg := &config{
		hostname:        fs.StringLong("hostname", "ts1p", "tailnet hostname to serve as"),
		stateDir:        fs.StringLong("state-dir", "", "directory for tsnet state and the audit log (required)"),
		vault:           fs.StringLong("vault", "", "1Password vault name holding the secrets (required unless --dev)"),
		loginServer:     fs.StringLong("login-server", "", "Tailscale control URL (optional)"),
		cacheExpiry:     fs.DurationLong("cache-expiry", time.Hour, "base lifetime of a cached 1Password read before refetch (jittered ±20% per entry); 0 caches forever (entries never expire and the warmer is disabled)"),
		cacheMaxEntries: fs.IntLong("cache-max-entries", 0, "max cached secrets (0 = unbounded)"),
		cacheWarm:       fs.BoolLongDefault("cache-warm", true, "keep the 1Password read cache warm in the background so cold reads never hit the request path"),
		// TODO(kradalby): remove with the 1Password WASM-core workaround (kradalby/ts1p#2).
		opMaxAge:  fs.DurationLong("op-max-age", 0, "recycle (exit for a clean systemd restart) once the 1Password WASM core has been alive this long; 0 disables, minimum 10m (see kradalby/ts1p#2)"),
		service:   fs.StringLong("service", "", "advertise as a Tailscale Service (e.g. \"secrets\") instead of the node FQDN, so several instances form one HA front door; requires a tagged auth key. Empty serves the node FQDN"),
		logLevel:  fs.StringLong("log-level", "info", "log level: debug, info, warn or error; debug also surfaces tsnet's verbose backend logs"),
		debugAddr: fs.StringLong("debug-addr", "127.0.0.1:9090", "loopback address for the full debug listener (pprof, statsviz, /metrics); empty disables it. Keep it on loopback: it exposes pprof, which the tailnet deliberately does not"),
		dev:       fs.BoolLong("dev", "use an in-memory backend and serve plain HTTP over the tailnet; for testing only: secrets are lost on restart and /debug is unauthenticated"),
	}
	cmd := &ff.Command{
		Name:  "ts1p",
		Usage: "ts1p [FLAGS]",
		Flags: fs,
		Exec: func(ctx context.Context, _ []string) error {
			err := lvl.UnmarshalText([]byte(*cfg.logLevel))
			if err != nil {
				return fmt.Errorf("invalid --log-level %q: %w", *cfg.logLevel, err)
			}

			return serve(ctx, log, cfg)
		},
	}

	return cmd
}

// Config errors are the first thing a new deployment hits; each names the
// missing or invalid knob (flag and env var) as a static error.
var (
	errStateDirRequired = errors.New("--state-dir (or TS1P_STATE_DIR) is required")
	errVaultRequired    = errors.New("--vault (or TS1P_VAULT) is required")
	errTokenRequired    = errors.New("OP_SERVICE_ACCOUNT_TOKEN is required")
	errOpMaxAgeTooShort = errors.New("--op-max-age is below the 10m minimum (0 disables)")
	errNoTLSDomains     = errors.New("tailscale did not provide TLS domains")
)

func serve(ctx context.Context, log *slog.Logger, cfg *config) error {
	// Validate everything cheap before the expensive startup work (1Password
	// connect retries, tsnet up), so a typo fails in milliseconds.
	if *cfg.stateDir == "" {
		return errStateDirRequired
	}

	if *cfg.opMaxAge > 0 && *cfg.opMaxAge < 10*time.Minute {
		// Shorter recycles trip module.nix's systemd start-limit and park the
		// unit in failed state; the knob is meant to be hours.
		return fmt.Errorf("%w: %v", errOpMaxAgeTooShort, *cfg.opMaxAge)
	}

	var svc string

	if !*cfg.dev && *cfg.service != "" {
		var err error

		svc, err = normalizeService(*cfg.service)
		if err != nil {
			return err
		}
	}

	// A secrets server must not phone home: without this, tsnet streams
	// tailscaled-level logs (node metadata, peers, timings) to log.tailscale.com.
	envknob.SetNoLogsNoSupport()

	be, cached, closeBackend, err := buildBackend(ctx, log, cfg)
	if err != nil {
		return err
	}
	defer func() { _ = closeBackend() }()

	// Keep the cache warm off the request path so a cold parallel load (after a
	// restart, flush, or TTL expiry) does not stampede the 1Password core (the
	// cache coalesces concurrent misses with singleflight; the SDK's WASM core is
	// single-threaded). Disabled when there is no cache (--dev) or no positive
	// expiry (entries then never expire). Started after the server is wired below.
	var warmer *cache.Warmer
	if cached != nil && *cfg.cacheWarm && *cfg.cacheExpiry > 0 {
		warmer = cache.NewWarmer(cached, log)
	}

	ts := &tsnet.Server{
		Dir:        filepath.Join(*cfg.stateDir, "tsnet"),
		Hostname:   *cfg.hostname,
		ControlURL: *cfg.loginServer,
		AuthKey:    os.Getenv("TS_AUTHKEY"),
	}
	if *cfg.dev || log.Enabled(ctx, slog.LevelDebug) {
		// Surface tsnet's verbose control-client logs in dev mode and at
		// --log-level=debug — the situations its diagnostics exist for.
		ts.Logf = func(format string, args ...any) { log.Info("tsnet: " + fmt.Sprintf(format, args...)) }
	}
	defer func() { _ = ts.Close() }()

	log.Info("starting tsnet",
		"hostname", *cfg.hostname,
		"control", *cfg.loginServer,
		"authkey_present", os.Getenv("TS_AUTHKEY") != "")

	lc, err := ts.LocalClient()
	if err != nil {
		return fmt.Errorf("getting tailscale localapi client: %w", err)
	}

	_, err = ts.Up(ctx)
	if err != nil {
		return fmt.Errorf("tailscale did not come up: %w", err)
	}

	auditLog, err := audit.NewFile(filepath.Join(*cfg.stateDir, "audit.log"))
	if err != nil {
		return fmt.Errorf("opening audit log: %w", err)
	}
	defer func() { _ = auditLog.Close() }()

	mux := http.NewServeMux()

	srv, err := server.New(server.Config{
		Store:  store.New(be),
		WhoIs:  lc.WhoIs,
		Audit:  auditLog,
		Mux:    mux,
		Logger: log,
	})
	if err != nil {
		return fmt.Errorf("initializing ts1p server: %w", err)
	}

	publishRuntimeVars()
	registerDebug(mux, *cfg.dev, srv, cached, warmer, log)
	// Unauthenticated and secretless, so HA probers and humans have something
	// to hit. 200 means the listener is wired, nothing deeper.
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok\n")
	})

	// The full debug suite (pprof, statsviz) on loopback only. --dev already
	// mounts it on the tailnet listener, so it is redundant there.
	if !*cfg.dev && *cfg.debugAddr != "" {
		stopDebug, err := serveDebugListener(ctx, log, *cfg.debugAddr)
		if err != nil {
			return err
		}
		defer stopDebug()
	}

	if warmer != nil {
		// The warmer runs on its own context, cancelled before the deferred
		// Wait: tying it to the signal ctx alone would leave Wait blocking
		// forever when serve returns with an error (no signal ever fires), a
		// silent zombie systemd sees as active. LIFO defers run wcancel first.
		wctx, wcancel := context.WithCancel(ctx)

		defer warmer.Wait() // order warmer teardown before closeBackend on shutdown
		defer wcancel()

		go warmer.Run(wctx)
	}

	switch chooseServeMode(*cfg.dev, svc) {
	case modeDev:
		return serveDev(ctx, log, ts, mux, *cfg.hostname)
	case modeService:
		return serveService(ctx, log, ts, mux, svc)
	case modeTLS:
		return serveTLS(ctx, log, ts, mux)
	}

	panic("unreachable")
}

// serveMode is how the API is exposed on the tailnet.
type serveMode int

const (
	modeDev     serveMode = iota // plain HTTP, in-memory backend
	modeService                  // shared Tailscale Service (HA front door)
	modeTLS                      // the node's own TLS FQDN
)

// chooseServeMode picks the serve mode. --dev wins so a test instance never
// tries to advertise a service.
func chooseServeMode(dev bool, service string) serveMode {
	switch {
	case dev:
		return modeDev
	case service != "":
		return modeService
	default:
		return modeTLS
	}
}

// normalizeService returns the svc:-prefixed, validated Tailscale Service name for
// a user-supplied value (which may already carry the prefix).
func normalizeService(s string) (string, error) {
	if !strings.HasPrefix(s, "svc:") {
		s = "svc:" + s
	}

	err := tailcfg.ServiceName(s).Validate()
	if err != nil {
		return "", fmt.Errorf("invalid --service %q: %w", s, err)
	}

	return s, nil
}

// registerDebug wires the /debug surface on the tailnet listener. In --dev it is
// the full tsweb suite, unauthenticated (a local, in-memory test instance). In
// production it is gated behind the secrets ACL and pprof/statsviz are NOT
// exposed — a heap dump would leak the decrypted secrets the process holds. The
// full suite lives only on the loopback debug listener (serveDebugListener).
func registerDebug(mux *http.ServeMux, dev bool, srv *server.Server, cached *cache.Cache, warmer *cache.Warmer, log *slog.Logger) {
	if dev {
		wireFullDebugger(tsweb.Debugger(mux), mux)
		return
	}
	// Operational metrics, gated like everything else on the production listener.
	mux.HandleFunc("/debug/vars", srv.AdminGate(expvar.Handler().ServeHTTP))

	// Un-gated: a scraper cannot hold the delete-* grant, and the Prometheus
	// registry holds only numeric operational metrics, never secret material.
	mux.Handle("GET /metrics", promhttp.Handler())

	if cached != nil {
		mux.HandleFunc("/debug/flush-cache", srv.AdminGate(server.FlushCacheHandler(cached, warmer, log)))
	}
}

// wireFullDebugger adds the endpoints tsweb.Debugger does not mount itself — the
// standard /metrics scrape path and statsviz — and links them from the /debug
// index. tsweb.Debugger already provides /debug/vars (expvar), pprof, /debug/gc,
// and /debug/varz (expvar+Prometheus, via the promvarz import). Statsviz allows a
// single server per process, so this runs once per invocation (dev, or the
// loopback listener — never both).
func wireFullDebugger(dh *tsweb.DebugHandler, mux *http.ServeMux) {
	mux.Handle("GET /metrics", promhttp.Handler())
	dh.URL("/metrics", "Metrics (Prometheus)")

	err := statsviz.Register(mux)
	if err != nil {
		slog.Default().Warn("statsviz registration failed; live runtime visualizer disabled", "err", err)
		return
	}

	dh.URL("/debug/statsviz/", "statsviz (live runtime visualizer)")
}

// serveDebugListener runs the full tsweb.Debugger suite (pprof, statsviz, gc,
// vars, varz, /metrics) on a loopback-only listener, so operators get the tools
// pprof-on-the-tailnet would forbid. It is safe there: a caller that can reach
// loopback can already read the process memory via /proc, so the heap dump leaks
// nothing the tailnet does not already withhold. The returned stop drains it.
func serveDebugListener(ctx context.Context, log *slog.Logger, addr string) (func(), error) {
	dmux := http.NewServeMux()
	wireFullDebugger(tsweb.Debugger(dmux), dmux)

	var lc net.ListenConfig

	l, err := lc.Listen(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("binding debug listener %q: %w", addr, err)
	}

	hs := httpServer(dmux)

	go func() {
		err := hs.Serve(l)
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("serving debug listener", "err", err)
		}
	}()

	log.Info("debug listener serving", "addr", l.Addr())

	return func() {
		sctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), shutdownGrace)
		defer cancel()

		_ = hs.Shutdown(sctx)
	}, nil
}

// publishRuntimeVars exposes the resolved Go and WASM-stack dependency versions
// as a Prometheus info metric (value 1, versions in labels), so a deploy can
// prove which runtime is live and correlate an "OOB stopped" with it. The label
// set is bounded — it changes only on a rebuild. See kradalby/ts1p#2.
func publishRuntimeVars() {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		slog.Default().Warn("build info unavailable; ts1p_runtime_versions_info will not be published")
		return
	}

	labels := prometheus.Labels{"go": info.GoVersion, "wazero": "", "extism": "", "onepassword": ""}
	for _, d := range info.Deps {
		switch d.Path {
		case "github.com/tetratelabs/wazero":
			labels["wazero"] = d.Version
		case "github.com/extism/go-sdk":
			labels["extism"] = d.Version
		case "github.com/1password/onepassword-sdk-go":
			labels["onepassword"] = d.Version
		}
	}

	promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "ts1p_runtime_versions_info",
		Help: "Resolved Go and WASM-stack dependency versions; value is always 1.",
	}, []string{"go", "wazero", "extism", "onepassword"}).With(labels).Set(1)
}

// buildBackend returns the configured backend and a close function. In --dev it
// is an in-memory backend (no cache); otherwise a 1Password vault behind the
// expiry cache, which is also returned concretely so the caller can warm and
// flush it.
func buildBackend(ctx context.Context, log *slog.Logger, cfg *config) (backend.Backend, *cache.Cache, func() error, error) {
	if *cfg.dev {
		return mem.New(), nil, func() error { return nil }, nil
	}

	if *cfg.vault == "" {
		return nil, nil, nil, errVaultRequired
	}

	token := os.Getenv("OP_SERVICE_ACCOUNT_TOKEN")
	if token == "" {
		return nil, nil, nil, errTokenRequired
	}

	be, err := onepassword.New(ctx, token, *cfg.vault, log, *cfg.opMaxAge)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("connecting to 1Password: %w", err)
	}

	cached := cache.New(be, *cfg.cacheMaxEntries, *cfg.cacheExpiry)

	return cached, cached, cached.Close, nil
}

// HTTP server timeouts, shared by the dev and TLS listeners.
const (
	readHeaderTimeout = 10 * time.Second
	shutdownGrace     = 5 * time.Second
)

// httpServer builds an *http.Server with the shared header-read timeout.
func httpServer(h http.Handler) *http.Server {
	return &http.Server{Handler: h, ReadHeaderTimeout: readHeaderTimeout}
}

// serveDev serves the API as plain HTTP over the tailnet. The tailnet transport
// is WireGuard-encrypted; this avoids needing a provisioned TLS certificate,
// which a hermetic test environment cannot obtain.
func serveDev(ctx context.Context, log *slog.Logger, ts *tsnet.Server, mux *http.ServeMux, hostname string) error {
	l, err := ts.Listen("tcp", ":80")
	if err != nil {
		return fmt.Errorf("creating HTTP listener: %w", err)
	}

	hs := httpServer(tsweb.BrowserHeaderHandler(mux))
	done := shutdownOnDone(ctx, log, hs)

	log.Warn("ts1p serving in DEV mode: in-memory backend, plain HTTP", "hostname", hostname)
	sdReady(log)

	err = hs.Serve(l)
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("serving HTTP: %w", err)
	}

	<-done // ErrServerClosed means Shutdown began; wait for the drain

	return nil
}

// serveService serves the API as a Tailscale Service: the node advertises svc
// and the control plane routes the service's VIP/FQDN to any active backer, so
// several stateless instances form one HA front door (secrets.<tailnet>). The
// node must have a tagged identity. Clients reach the service FQDN, not the node.
//
// The service is a TCP-mode listener with in-tailscaled TLS termination and a
// PROXY protocol header, NOT ServiceModeHTTP: the HTTP mode reverse-proxies
// over a localhost connection pool shared across peers, so every request would
// arrive as 127.0.0.1 and WhoIs-based identity — the entire ACL model — would
// be impossible by construction. The PROXY header carries the real peer
// address, the go-proxyproto listener rewrites RemoteAddr from it, and WhoIs
// works exactly as on the node's own listener.
func serveService(ctx context.Context, log *slog.Logger, ts *tsnet.Server, mux *http.ServeMux, svc string) error {
	ln, err := ts.ListenService(svc, tsnet.ServiceModeTCP{
		Port:                 443,
		TerminateTLS:         true,
		PROXYProtocolVersion: 2,
	})
	if err != nil {
		if errors.Is(err, tsnet.ErrUntaggedServiceHost) {
			return fmt.Errorf("--service requires a tagged auth key (tag the node's TS_AUTHKEY): %w", err)
		}

		return fmt.Errorf("advertising Tailscale Service %q: %w", svc, err)
	}

	pln := &proxyproto.Listener{
		Listener:          ln,
		ReadHeaderTimeout: readHeaderTimeout,
		// The PROXY header is the whole identity model here, so require it
		// explicitly instead of inheriting the library default. go-proxyproto's
		// zero-value policy was USE until v0.15.0 made REQUIRE the default; under
		// USE, a header-less connection would have been served with the raw
		// tsnet-internal RemoteAddr, which is exactly the ACL bypass described
		// above. Pinning it keeps a future default flip from moving it back.
		ConnPolicy: func(proxyproto.ConnPolicyOptions) (proxyproto.Policy, error) {
			return proxyproto.REQUIRE, nil
		},
	}
	hs := httpServer(tsweb.BrowserHeaderHandler(mux))
	done := shutdownOnDone(ctx, log, hs) // Shutdown closes ln, which de-advertises the service

	log.Info("ts1p serving Tailscale Service", "service", svc, "fqdn", ln.FQDN)
	sdReady(log)

	err = hs.Serve(pln)
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("serving Tailscale Service: %w", err)
	}

	<-done

	return nil
}

// serveTLS serves the API over the tailnet TLS certificate on :443, with :80
// redirecting to HTTPS.
func serveTLS(ctx context.Context, log *slog.Logger, ts *tsnet.Server, mux *http.ServeMux) error {
	doms := ts.CertDomains()
	if len(doms) == 0 {
		return errNoTLSDomains
	}

	fqdn := doms[0]

	l80, err := ts.Listen("tcp", ":80")
	if err != nil {
		return fmt.Errorf("creating HTTP listener: %w", err)
	}

	hs80 := httpServer(tsweb.Port80Handler{Main: mux, FQDN: fqdn})
	go func() {
		err := hs80.Serve(l80)
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("serving HTTP", "err", err)
		}
	}()

	lTLS, err := ts.ListenTLS("tcp", ":443")
	if err != nil {
		return fmt.Errorf("creating TLS listener: %w", err)
	}

	hs := httpServer(tsweb.BrowserHeaderHandler(mux))
	done := shutdownOnDone(ctx, log, hs80, hs)

	log.Info("ts1p serving", "fqdn", fqdn)
	sdReady(log)

	err = hs.Serve(lTLS)
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("serving HTTPS: %w", err)
	}

	<-done

	return nil
}

// shutdownOnDone gracefully shuts down the given servers when ctx is cancelled.
// The returned channel closes when the drain has finished: Serve returns
// ErrServerClosed the moment Shutdown closes the listener, so without waiting
// on it serve()'s defers would tear down the audit log, tsnet, and the backend
// under the very requests the grace period exists to finish.
func shutdownOnDone(ctx context.Context, log *slog.Logger, servers ...*http.Server) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		defer close(done)

		<-ctx.Done()
		log.Info("shutting down")
		// WithoutCancel detaches from the now-cancelled ctx so shutdown keeps
		// its grace period.
		sctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), shutdownGrace)
		defer cancel()

		for _, s := range servers {
			_ = s.Shutdown(sctx)
		}
	}()

	return done
}

// sdReady tells systemd (Type=notify) the listener is up and serving, so
// "active" means ready and dependent units can order on it. A no-op outside
// systemd (no NOTIFY_SOCKET).
func sdReady(log *slog.Logger) {
	n, err := sdnotify.New()
	if err != nil {
		return
	}
	defer func() { _ = n.Close() }()

	err = n.Notify(sdnotify.Ready)
	if err != nil {
		log.Warn("systemd readiness notification failed", "err", err)
	}
}

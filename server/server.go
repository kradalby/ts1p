// Package server implements the setec-wire-compatible HTTP API over a
// store.Store. It is a faithful re-implementation of setec's server/server.go
// JSON dispatch: same routes, same required headers, same identity extraction
// (Tailscale WhoIs + ACL grants), same audit placement, and the same mapping
// of store errors to HTTP status codes. setec's own client and reference
// server are run against it in the conformance and differential tests.
package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/tailscale/setec/acl"
	"github.com/tailscale/setec/audit"
	"github.com/tailscale/setec/types/api"
	"golang.org/x/time/rate"
	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/tailcfg"

	"github.com/kradalby/ts1p/backend"
	"github.com/kradalby/ts1p/store"
)

// ACLCap is the Tailscale peer capability that carries ACL grants. It is
// identical to setec's, so the same tailnet policy governs both.
const ACLCap tailcfg.PeerCapability = "tailscale.com/cap/secrets"

const aclCapHTTP tailcfg.PeerCapability = "https://" + ACLCap

// Rate limit for the high-volume request-error log: at most one line per
// interval per message, with a tiny burst — so a sustained storage outage
// stays readable instead of logging a stack trace on every request.
const (
	errLogInterval = 5 * time.Second
	errLogBurst    = 1
)

// maxRequestBytes bounds a request body. It is read fully before the
// per-secret ACL check, so without a bound any identified tailnet peer — even
// one holding no grants — could buffer gigabytes into the process. 1MiB
// matches the backend's per-item ceiling, so no accepted value can exceed it.
const maxRequestBytes = 1 << 20

// errMissingConfig is returned by New for an unset required Config field.
var errMissingConfig = errors.New("server: missing required config")

// errNoCallerIdentity mirrors setec's getIdentity failure: a WhoIs response
// carrying neither tags nor a user login.
var errNoCallerIdentity = errors.New("failed to find caller identity")

// errIdentityUnavailable wraps a transient failure to resolve the caller's
// identity (a WhoIs/localapi hiccup, e.g. during a tailscaled restart), so the
// server can answer 503 (retryable) rather than 500.
var errIdentityUnavailable = errors.New("identity unavailable")

// WhoIsFunc resolves a client IP to its tailnet identity. Outside tests it is
// a Tailscale LocalClient's WhoIs.
type WhoIsFunc func(ctx context.Context, remoteAddr string) (*apitype.WhoIsResponse, error)

// Config configures a Server.
type Config struct {
	// Store is the secret store. Required.
	Store *store.Store

	// WhoIs reports an identity for a client IP. Required.
	WhoIs WhoIsFunc

	// Audit is the audit log writer. Required.
	Audit *audit.Writer

	// Mux is the mux on which handlers are registered. Required.
	Mux *http.ServeMux

	// Logger logs internal errors. It must never be given secret values.
	// Optional; defaults to slog.Default().
	Logger *slog.Logger
}

// Server serves the setec HTTP API.
type Server struct {
	store *store.Store
	whois WhoIsFunc
	log   *slog.Logger
	// errLog logs high-volume request errors (storage outages, handler errors),
	// rate-limited so a sustained failure does not log on every request.
	errLog *limitedLogger

	// auditMu serializes audit writes: setec's audit.Writer shares one
	// json.Encoder with no lock of its own, and handlers write from concurrent
	// request goroutines.
	auditMu sync.Mutex
	audit   *audit.Writer
}

// New constructs a Server and registers its handlers on cfg.Mux.
func New(cfg Config) (*Server, error) {
	switch {
	case cfg.Store == nil:
		return nil, fmt.Errorf("%w: Store", errMissingConfig)
	case cfg.WhoIs == nil:
		return nil, fmt.Errorf("%w: WhoIs", errMissingConfig)
	case cfg.Audit == nil:
		return nil, fmt.Errorf("%w: Audit", errMissingConfig)
	case cfg.Mux == nil:
		return nil, fmt.Errorf("%w: Mux", errMissingConfig)
	}

	s := &Server{
		store: cfg.Store,
		whois: cfg.WhoIs,
		audit: cfg.Audit,
		log:   cfg.Logger,
	}
	if s.log == nil {
		s.log = slog.Default()
	}

	s.errLog = newLimitedLogger(s.log)

	cfg.Mux.HandleFunc("/api/list", s.list)
	cfg.Mux.HandleFunc("/api/get", s.get)
	cfg.Mux.HandleFunc("/api/info", s.info)
	cfg.Mux.HandleFunc("/api/put", s.put)
	cfg.Mux.HandleFunc("/api/create-version", s.createVersion)
	cfg.Mux.HandleFunc("/api/activate", s.activate)
	cfg.Mux.HandleFunc("/api/delete", s.deleteSecret)
	cfg.Mux.HandleFunc("/api/delete-version", s.deleteVersion)

	return s, nil
}

// limitedLogger rate-limits Error lines per message while keeping slog attrs
// structured (tailscale's logger.RateLimitedFn would flatten them through
// Sprintf). Messages here are a handful of fixed strings, so the map stays tiny.
type limitedLogger struct {
	log *slog.Logger

	mu  sync.Mutex
	lim map[string]*rate.Limiter
}

func newLimitedLogger(log *slog.Logger) *limitedLogger {
	return &limitedLogger{log: log, lim: map[string]*rate.Limiter{}}
}

func (l *limitedLogger) Error(msg string, attrs ...any) {
	l.mu.Lock()

	lm, ok := l.lim[msg]
	if !ok {
		lm = rate.NewLimiter(rate.Every(errLogInterval), errLogBurst)
		l.lim[msg] = lm
	}
	l.mu.Unlock()

	if lm.Allow() {
		l.log.Error(msg, attrs...)
	}
}

// caller is the authenticated identity of a request.
type caller struct {
	principal audit.Principal
	perms     acl.Rules
}

// AdminGate wraps a debug handler so it enforces the same identity and
// capability checks as the /api surface: the anti-CSRF header, WhoIs identity,
// and a delete grant on "*" — the strongest secrets grant, standing in for
// "operator". Every attempt is audited.
func (s *Server) AdminGate(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Sec-X-Tailscale-No-Browsers") != "setec" {
			http.Error(w, "access denied", http.StatusForbidden)
			return
		}

		c, err := getIdentity(s.whois, r)
		if err != nil {
			if r.Context().Err() != nil {
				return // caller went away
			}

			s.log.Error("debug auth: identifying caller", "path", r.URL.Path, "err", err)
			http.Error(w, "identity unavailable", http.StatusServiceUnavailable)

			return
		}

		allowed := c.perms.Allow(acl.ActionDelete, "*")

		// Record the access attempt (authorized or not) like an ordinary ACL check.
		err = s.logAccess(c, acl.ActionDelete, r.URL.Path, 0, allowed)
		if err != nil {
			s.log.Error("debug auth: writing audit log", "path", r.URL.Path, "err", err)

			if allowed {
				// Fail closed like checkAndLog: no un-audited admin access.
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
		}

		if !allowed {
			http.Error(w, "access denied", http.StatusForbidden)
			return
		}

		next(w, r)
	}
}

// getIdentity extracts identity and permissions from a request, mirroring
// setec's getIdentity exactly.
func getIdentity(whois WhoIsFunc, r *http.Request) (caller, error) {
	addrPort, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		return caller{}, fmt.Errorf("parsing RemoteAddr %q: %w", r.RemoteAddr, err)
	}

	who, err := whois(r.Context(), r.RemoteAddr)
	if err != nil {
		// A WhoIs/localapi failure is transient (e.g. a tailscaled restart);
		// mark it so the handler answers 503 rather than 500. A cancelled request
		// keeps its context error so the handler can stay silent.
		if r.Context().Err() != nil {
			return caller{}, fmt.Errorf("calling WhoIs: %w", err)
		}

		return caller{}, fmt.Errorf("%w: calling WhoIs: %w", errIdentityUnavailable, err)
	}

	if who == nil || who.Node == nil {
		return caller{}, fmt.Errorf("%w: WhoIs returned no node", errIdentityUnavailable)
	}

	var c caller

	switch {
	case who.Node.IsTagged():
		c.principal.Tags = who.Node.Tags
	case who.UserProfile != nil && who.UserProfile.LoginName != "":
		c.principal.User = who.UserProfile.LoginName
	default:
		return caller{}, errNoCallerIdentity
	}

	c.principal.IP = addrPort.Addr()
	c.principal.Hostname = who.Node.Name

	c.perms, err = tailcfg.UnmarshalCapJSON[acl.Rule](who.CapMap, ACLCap)
	if err == nil && len(c.perms) == 0 {
		c.perms, err = tailcfg.UnmarshalCapJSON[acl.Rule](who.CapMap, aclCapHTTP)
	}

	if err != nil {
		return caller{}, fmt.Errorf("unmarshaling peer capabilities: %w", err)
	}

	return c, nil
}

// logAccess writes one audit entry recording whether the action was authorized.
// The mutex covers setec's audit.Writer, whose shared json.Encoder is not safe
// for the concurrent request goroutines calling this.
func (s *Server) logAccess(c caller, action acl.Action, secret string, version api.SecretVersion, authorized bool) error {
	s.auditMu.Lock()
	err := s.audit.WriteEntries(&audit.Entry{
		Principal:     c.principal,
		Action:        action,
		Secret:        secret,
		SecretVersion: version,
		Authorized:    authorized,
	})
	s.auditMu.Unlock()

	if err != nil {
		return fmt.Errorf("writing audit log: %w", err)
	}

	return nil
}

// checkAndLog authorizes action on secret for c and writes an audit entry,
// mirroring setec's db.checkAndLog. It returns api.ErrAccessDenied if the
// caller is not permitted; the caller must not proceed on error. A denied call
// is still audited (its write error is subordinate to the denial, but logged —
// the audit log failing is operator-critical and must not be invisible).
func (s *Server) checkAndLog(c caller, action acl.Action, secret string, version api.SecretVersion) error {
	authorized := c.perms.Allow(action, secret)

	werr := s.logAccess(c, action, secret, version, authorized)
	if !authorized {
		if werr != nil {
			s.log.Error("writing audit log for denied call", "secret", secret, "err", werr)
		}

		return api.ErrAccessDenied
	}

	return werr
}

func (s *Server) list(w http.ResponseWriter, r *http.Request) {
	s.serveJSON(w, r, func(ctx context.Context, _ api.ListRequest, c caller) ([]*api.SecretInfo, error) {
		// Mirror setec: one audit entry for the List call, then per-secret
		// permission filtering with no further audit entries.
		err := s.logAccess(c, acl.ActionInfo, "", 0, true)
		if err != nil {
			return nil, err
		}
		// Filter by acl.ActionInfo before each Load (store.List skips hidden names
		// entirely), so a caller authorized for a few secrets does not fan out a
		// full-vault read or decrypt values it cannot see. An empty result is a nil
		// slice, which marshals to null (not []), matching setec.
		return s.store.List(ctx, func(name string) bool {
			return c.perms.Allow(acl.ActionInfo, name)
		})
	})
}

func (s *Server) get(w http.ResponseWriter, r *http.Request) {
	s.serveJSON(w, r, func(ctx context.Context, req api.GetRequest, c caller) (*api.SecretValue, error) {
		if req.Version != 0 {
			if req.UpdateIfChanged {
				// Conditional fetch: evaluate permission once, and audit only on a
				// denial or when a fresh value is actually returned (an unchanged
				// value is not audited), matching setec's GetConditional.
				if !c.perms.Allow(acl.ActionGet, req.Name) {
					werr := s.logAccess(c, acl.ActionGet, req.Name, 0, false)
					if werr != nil {
						s.log.Error("writing audit log for denied call", "secret", req.Name, "err", werr)
					}

					return nil, api.ErrAccessDenied
				}

				sv, err := s.store.GetConditional(ctx, req.Name, req.Version)
				if err != nil {
					return nil, err // ErrValueNotChanged passes through, unaudited
				}

				err = s.logAccess(c, acl.ActionGet, req.Name, 0, true)
				if err != nil {
					return nil, err
				}

				return sv, nil
			}

			err := s.checkAndLog(c, acl.ActionGet, req.Name, req.Version)
			if err != nil {
				return nil, err
			}

			return s.store.GetVersion(ctx, req.Name, req.Version)
		}

		err := s.checkAndLog(c, acl.ActionGet, req.Name, 0)
		if err != nil {
			return nil, err
		}

		return s.store.Get(ctx, req.Name)
	})
}

func (s *Server) info(w http.ResponseWriter, r *http.Request) {
	s.serveJSON(w, r, func(ctx context.Context, req api.InfoRequest, c caller) (*api.SecretInfo, error) {
		err := s.checkAndLog(c, acl.ActionInfo, req.Name, 0)
		if err != nil {
			return nil, err
		}

		return s.store.Info(ctx, req.Name)
	})
}

// errEmptyName mirrors setec's write-path name validation, which runs BEFORE
// authorization (an empty name is a plain 500 regardless of grants, with no
// audit entry). The differential test pins the ordering.
var errEmptyName = errors.New("empty secret name")

func (s *Server) put(w http.ResponseWriter, r *http.Request) {
	s.serveJSON(w, r, func(ctx context.Context, req api.PutRequest, c caller) (api.SecretVersion, error) {
		if req.Name == "" {
			return 0, errEmptyName
		}

		err := s.checkAndLog(c, acl.ActionPut, req.Name, 0)
		if err != nil {
			return 0, err
		}

		return s.store.Put(ctx, req.Name, req.Value)
	})
}

func (s *Server) createVersion(w http.ResponseWriter, r *http.Request) {
	s.serveJSON(w, r, func(ctx context.Context, req api.CreateVersionRequest, c caller) (struct{}, error) {
		// setec validates the name, then the version, before authorizing — so
		// an invalid request reports 500/400 regardless of permissions.
		if req.Name == "" {
			return struct{}{}, errEmptyName
		}

		if req.Version == 0 {
			return struct{}{}, store.ErrInvalidVersion
		}

		err := s.checkAndLog(c, acl.ActionCreateVersion, req.Name, req.Version)
		if err != nil {
			return struct{}{}, err
		}

		return struct{}{}, s.store.CreateVersion(ctx, req.Name, req.Version, req.Value)
	})
}

func (s *Server) activate(w http.ResponseWriter, r *http.Request) {
	s.serveJSON(w, r, func(ctx context.Context, req api.ActivateRequest, c caller) (struct{}, error) {
		if req.Name == "" {
			return struct{}{}, errEmptyName
		}

		err := s.checkAndLog(c, acl.ActionActivate, req.Name, req.Version)
		if err != nil {
			return struct{}{}, err
		}

		return struct{}{}, s.store.Activate(ctx, req.Name, req.Version)
	})
}

func (s *Server) deleteSecret(w http.ResponseWriter, r *http.Request) {
	s.serveJSON(w, r, func(ctx context.Context, req api.DeleteRequest, c caller) (struct{}, error) {
		err := s.checkAndLog(c, acl.ActionDelete, req.Name, 0)
		if err != nil {
			return struct{}{}, err
		}

		return struct{}{}, s.store.Delete(ctx, req.Name)
	})
}

func (s *Server) deleteVersion(w http.ResponseWriter, r *http.Request) {
	s.serveJSON(w, r, func(ctx context.Context, req api.DeleteVersionRequest, c caller) (struct{}, error) {
		err := s.checkAndLog(c, acl.ActionDelete, req.Name, req.Version)
		if err != nil {
			return struct{}{}, err
		}

		return struct{}{}, s.store.DeleteVersion(ctx, req.Name, req.Version)
	})
}

// serveJSON decodes a JSON request, enforces setec's transport requirements,
// runs fn, and maps its error to the same HTTP status codes setec uses.
func (s *Server) serveJSON[REQ any, RESP any](w http.ResponseWriter, r *http.Request, fn func(context.Context, REQ, caller) (RESP, error)) {
	if r.Method != http.MethodPost {
		http.Error(w, "only POST requests allowed", http.StatusBadRequest)
		return
	}

	if r.Header.Get("Content-Type") != "application/json" {
		http.Error(w, "request body must be json", http.StatusBadRequest)
		return
	}
	// Sec- prefixed headers cannot be set by browser fetch/XHR, so requiring
	// this blocks CSRF and drive-by API use. Identical to setec.
	if r.Header.Get("Sec-X-Tailscale-No-Browsers") != "setec" {
		http.Error(w, "access denied", http.StatusForbidden)
		return
	}

	id, err := getIdentity(s.whois, r)
	if err != nil {
		switch {
		case r.Context().Err() != nil:
			return // caller went away mid-lookup; nothing to send, not a server fault
		case errors.Is(err, errIdentityUnavailable):
			s.errLog.Error("identifying caller", "path", r.URL.Path, "err", err)
			http.Error(w, "identity unavailable", http.StatusServiceUnavailable)

			return
		default:
			s.log.Error("identifying caller", "path", r.URL.Path, "err", err)
			http.Error(w, "unable to identify caller", http.StatusInternalServerError)

			return
		}
	}

	// The body is read in full before the per-secret ACL check; bound it so an
	// identified-but-ungranted peer cannot buffer arbitrary amounts of memory.
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBytes)

	var req REQ

	err = json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	ctx := r.Context()
	// "Cache-Control: no-cache" asks ts1p to bypass its internal 1Password read
	// cache for this call, so a secret edited out-of-band is picked up on demand.
	// setec clients never send it, so this stays wire-compatible.
	if strings.Contains(r.Header.Get("Cache-Control"), "no-cache") {
		ctx = backend.WithForceRefresh(ctx)
	}

	resp, err := fn(ctx, req, id)
	switch {
	case errors.Is(err, api.ErrAccessDenied):
		http.Error(w, "access denied", http.StatusForbidden)
		return
	case errors.Is(err, api.ErrNotFound):
		http.Error(w, "not found", http.StatusNotFound)
		return
	case errors.Is(err, api.ErrValueNotChanged):
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotModified)

		return
	case errors.Is(err, store.ErrInvalidVersion):
		http.Error(w, "invalid version, please specify a version > 0", http.StatusBadRequest)
		return
	case errors.Is(err, api.ErrVersionClaimed):
		http.Error(w, "version already set", http.StatusPreconditionFailed)
		return
	case r.Context().Err() != nil:
		// THIS caller went away mid-request; nothing to send, and not a storage
		// fault, so no 503 and no error log. A backend-side stall (the SDK's own
		// deadline) is wrapped as ErrUnavailable instead and falls through to 503.
		return
	case errors.Is(err, context.Canceled):
		// A cancellation that is not ours — e.g. a coalesced fetch whose owner
		// disconnected. The work was aborted, not failed; tell the (still
		// live) client to retry. Staying silent here would emit an implicit
		// 200 with an empty body, which breaks real setec clients.
		s.errLog.Error("request aborted by foreign cancellation", "path", r.URL.Path, "err", err)
		http.Error(w, "storage backend unavailable", http.StatusServiceUnavailable)

		return
	case errors.Is(err, backend.ErrUnavailable):
		s.errLog.Error("storage unavailable", "path", r.URL.Path, "err", err)
		http.Error(w, "storage backend unavailable", http.StatusServiceUnavailable)

		return
	case err != nil:
		s.errLog.Error("handling request", "path", r.URL.Path, "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)

		return
	}

	bs, err := json.Marshal(resp)
	if err != nil {
		s.log.Error("encoding response", "path", r.URL.Path, "err", err)
		http.Error(w, "failed to encode response", http.StatusInternalServerError)

		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(bs)
}

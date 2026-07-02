// Package store implements setec's secret version semantics on top of a
// backend.Backend. It is a faithful re-implementation of setec's db/kv.go
// logic — the one part of setec that cannot be reused, because setec's db is
// concrete and welded to Tink encryption and on-disk persistence.
//
// All version rules (active/latest tracking, claimed-forever versions, the
// Put de-duplication, and which failures are "invalid version" vs "not found")
// live here and nowhere else, so the conformance and differential tests in
// package server can prove them against setec's own client and reference
// server.
package store

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"slices"
	"strings"
	"sync"

	"github.com/tailscale/setec/types/api"

	"github.com/kradalby/ts1p/backend"
)

// configPrefix is setec's reserved name prefix: writes under it are refused
// with the same plain "unknown config value" error (HTTP 500), so a client
// cannot create secrets here that setec would refuse — and the namespace stays
// free for whatever semantics setec assigns it. Mirroring setec, CreateVersion
// is NOT guarded (its db path never checks the prefix).
const configPrefix = "_internal/"

// ErrInvalidVersion mirrors setec's db.ErrInvalidVersion: a create-version
// request with a version <= 0. The server maps it to HTTP 400. (Note: setec's
// activate and delete-version paths reject version 0 with a *plain* error that
// maps to 500 instead; store reproduces that asymmetry deliberately — see
// errInvalidVersionPlain.)
var ErrInvalidVersion = errors.New("invalid version")

// errEmptyName rejects a write with no secret name, mirroring setec's plain
// error (HTTP 500) exactly.
var errEmptyName = errors.New("empty secret name")

// errUnexpectedNoActive marks an invariant violation that should be impossible
// by construction (active always names a live version); it maps to a 500 and is
// a greppable signal of a corrupt record or a store bug.
var errUnexpectedNoActive = errors.New("[unexpected] active secret version missing")

// errDeleteActive mirrors setec's refusal to delete the active version.
var errDeleteActive = errors.New("cannot delete active version")

// errUnknownConfig is the reserved-prefix refusal; wrapped with the name, the
// message is byte-identical to setec's "unknown config value %q".
var errUnknownConfig = errors.New("unknown config value")

// errInvalidVersionPlain is the version-0 rejection for Activate and
// DeleteVersion. It is deliberately NOT ErrInvalidVersion: setec rejects a 0
// version on those paths with a plain error that the server maps to HTTP 500
// (not 400), and the differential test pins that asymmetry.
var errInvalidVersionPlain = errors.New("invalid version")

// Store applies setec's version semantics over a Backend.
//
// Writes take mu so concurrent read-modify-write sequences cannot lose updates,
// and load the record with backend.WithForceRefresh so the sequence starts from
// the source of truth rather than a possibly-stale cache — with several
// instances sharing one vault, a write computed from a cached record would
// silently clobber a newer write made through another instance. Writes are rare;
// the extra roundtrip is cheap. (Cross-instance writes in the same few-second
// window remain last-writer-wins; see the README's HA section.)
//
// Reads (Get/Info/List/GetVersion/GetConditional) are deliberately lock-free:
// they may briefly observe an in-progress write on a backend whose Save is not
// atomic, which matches setec's eventual-consistency contract for reads.
type Store struct {
	// mu serializes read-modify-write sequences so concurrent writers cannot
	// lose updates.
	//
	// ponytail: one global write mutex; go per-secret locks only if throughput
	// ever bites.
	mu sync.Mutex
	b  backend.Backend
}

// New returns a Store backed by b.
func New(b backend.Backend) *Store { return &Store{b: b} }

// load fetches a record, translating the backend's not-found into the
// api.ErrNotFound sentinel the server maps to HTTP 404.
func (s *Store) load(ctx context.Context, name string) (*backend.Record, error) {
	r, err := s.b.Load(ctx, name)
	if errors.Is(err, backend.ErrNotFound) {
		return nil, api.ErrNotFound
	}

	if err != nil {
		return nil, err
	}

	return r, nil
}

// info projects a record to its public metadata. It deliberately omits Latest
// (setec's SecretInfo exposes only the active version and the version list).
func info(r *backend.Record) *api.SecretInfo {
	return &api.SecretInfo{
		Name:          r.Name,
		ActiveVersion: r.Active,
		Versions:      slices.Sorted(maps.Keys(r.Versions)),
	}
}

// List returns metadata for every secret the allow predicate admits, sorted by
// name. Filtering happens before the per-secret Load, so a caller authorized for
// a few of many secrets does not trigger a full-vault fan-out of Loads — and
// never decrypts values it is not allowed to see. A nil allow admits everything.
func (s *Store) List(ctx context.Context, allow func(name string) bool) ([]*api.SecretInfo, error) {
	names, err := s.b.List(ctx)
	if err != nil {
		return nil, err
	}

	slices.Sort(names)

	var out []*api.SecretInfo

	for _, name := range names {
		if allow != nil && !allow(name) {
			continue
		}

		r, err := s.b.Load(ctx, name)
		switch {
		case errors.Is(err, backend.ErrNotFound):
			continue // raced with a delete; skip
		case errors.Is(err, backend.ErrUnavailable):
			return nil, err // the whole backend is down; fail the listing
		case err != nil:
			// One unreadable record (say, a hand-mangled 1Password item) must
			// not take /api/list down for every caller; it already fails loudly
			// on its own reads.
			slog.Warn("store: skipping unreadable secret in list", "name", name, "err", err)
			continue
		}

		out = append(out, info(r))
	}

	return out, nil
}

// Info returns metadata for a single secret.
func (s *Store) Info(ctx context.Context, name string) (*api.SecretInfo, error) {
	r, err := s.load(ctx, name)
	if err != nil {
		return nil, err
	}

	return info(r), nil
}

// active returns the record's active version as a SecretValue.
func active(r *backend.Record) (*api.SecretValue, error) {
	val, ok := r.Versions[r.Active]
	if !ok {
		return nil, errUnexpectedNoActive
	}

	return &api.SecretValue{Value: val, Version: r.Active}, nil
}

// Get returns the active value of a secret.
func (s *Store) Get(ctx context.Context, name string) (*api.SecretValue, error) {
	r, err := s.load(ctx, name)
	if err != nil {
		return nil, err
	}

	return active(r)
}

// GetConditional returns the active value unless it equals oldVersion, in which
// case it reports api.ErrValueNotChanged.
func (s *Store) GetConditional(ctx context.Context, name string, oldVersion api.SecretVersion) (*api.SecretValue, error) {
	r, err := s.load(ctx, name)
	if err != nil {
		return nil, err
	}

	sv, err := active(r)
	if err != nil {
		return nil, err
	}

	if sv.Version == oldVersion {
		return nil, api.ErrValueNotChanged
	}

	return sv, nil
}

// GetVersion returns a secret's value at a specific version.
func (s *Store) GetVersion(ctx context.Context, name string, version api.SecretVersion) (*api.SecretValue, error) {
	r, err := s.load(ctx, name)
	if err != nil {
		return nil, err
	}

	val, ok := r.Versions[version]
	if !ok {
		return nil, api.ErrNotFound
	}

	return &api.SecretValue{Value: val, Version: version}, nil
}

// Put writes value to name. A new secret is created at version 1 and made
// active. For an existing secret the value is stored as a new inactive version,
// except that writing a value identical to the current latest version is a
// no-op that returns the existing latest version.
func (s *Store) Put(ctx context.Context, name string, value []byte) (api.SecretVersion, error) {
	if name == "" {
		return 0, errEmptyName
	}

	if strings.HasPrefix(name, configPrefix) {
		return 0, fmt.Errorf("%w %q", errUnknownConfig, name)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	r, err := s.load(backend.WithForceRefresh(ctx), name)
	if errors.Is(err, api.ErrNotFound) {
		nr := &backend.Record{
			Name:     name,
			Latest:   1,
			Active:   1,
			Versions: map[api.SecretVersion][]byte{1: value},
		}

		err := s.b.Save(ctx, name, nr)
		if err != nil {
			return 0, err
		}

		return 1, nil
	} else if err != nil {
		return 0, err
	}

	// De-duplicate only against a live latest version. If the latest version was
	// deleted it is absent from Versions, and comparing against the zero value
	// would (for an empty Put) wrongly return the deleted version as current.
	if cur, ok := r.Versions[r.Latest]; ok && bytes.Equal(cur, value) {
		return r.Latest, nil
	}

	r.Latest++
	r.Versions[r.Latest] = value

	err = s.b.Save(ctx, name, r)
	if err != nil {
		return 0, err
	}

	return r.Latest, nil
}

// CreateVersion creates a specific version and makes it active. A version that
// has ever existed (live or deleted) cannot be recreated.
func (s *Store) CreateVersion(ctx context.Context, name string, version api.SecretVersion, value []byte) error {
	if name == "" {
		return errEmptyName
	}

	if version == 0 {
		return ErrInvalidVersion
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	r, err := s.load(backend.WithForceRefresh(ctx), name)
	if errors.Is(err, api.ErrNotFound) {
		nr := &backend.Record{
			Name:     name,
			Latest:   version,
			Active:   version,
			Versions: map[api.SecretVersion][]byte{version: value},
		}

		return s.b.Save(ctx, name, nr)
	} else if err != nil {
		return err
	}

	if r.IsClaimed(version) {
		return api.ErrVersionClaimed
	}

	r.Versions[version] = value
	r.Latest = max(r.Latest, version)
	r.Active = version

	return s.b.Save(ctx, name, r)
}

// Activate changes the active version of a secret.
func (s *Store) Activate(ctx context.Context, name string, version api.SecretVersion) error {
	if name == "" {
		return errEmptyName
	}

	if strings.HasPrefix(name, configPrefix) {
		return fmt.Errorf("%w %q", errUnknownConfig, name)
	}

	if version == 0 {
		return errInvalidVersionPlain // plain error → HTTP 500, matching setec's setActive
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	r, err := s.load(backend.WithForceRefresh(ctx), name)
	if err != nil {
		return err
	}

	if _, ok := r.Versions[version]; !ok {
		return api.ErrNotFound
	}

	if r.Active == version {
		return nil
	}

	r.Active = version

	return s.b.Save(ctx, name, r)
}

// DeleteVersion deletes a single, non-active version. The version is recorded
// as claimed so it can never be recreated.
func (s *Store) DeleteVersion(ctx context.Context, name string, version api.SecretVersion) error {
	if cfg, ok := strings.CutPrefix(name, configPrefix); ok {
		// setec reports only the prefix-stripped name here; the differential
		// test pins that quirk.
		return fmt.Errorf("%w %q", errUnknownConfig, cfg)
	}

	if version == 0 {
		return errInvalidVersionPlain // plain error → HTTP 500, matching setec's deleteVersion
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	r, err := s.load(backend.WithForceRefresh(ctx), name)
	if errors.Is(err, api.ErrNotFound) {
		return fmt.Errorf("secret %q: %w", name, api.ErrNotFound)
	} else if err != nil {
		return err
	}

	if version == r.Active {
		return errDeleteActive
	}

	if _, ok := r.Versions[version]; !ok {
		return fmt.Errorf("version %v: %w", version, api.ErrNotFound)
	}

	delete(r.Versions, version)

	if r.Deleted == nil {
		r.Deleted = make(map[api.SecretVersion]struct{})
	}

	r.Deleted[version] = struct{}{}

	return s.b.Save(ctx, name, r)
}

// Delete removes all versions of a secret. Deleting a missing secret is a
// no-op without error.
func (s *Store) Delete(ctx context.Context, name string) error {
	if cfg, ok := strings.CutPrefix(name, configPrefix); ok {
		return fmt.Errorf("%w %q", errUnknownConfig, cfg) // prefix-stripped, matching setec
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	return s.b.Delete(ctx, name)
}

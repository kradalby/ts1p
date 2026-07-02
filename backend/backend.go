// Package backend defines the storage abstraction behind ts1p: a password
// manager (or any key/value store) that persists secret records. All version
// semantics live above this layer in package store, so a new backend only has
// to implement dumb load/save/list/delete of a Record.
package backend

import (
	"context"
	"errors"
	"maps"
	"slices"

	"github.com/tailscale/setec/types/api"
)

// ErrNotFound is returned by a Backend when a named secret does not exist.
// Backends should return this rather than a nil record so callers can
// distinguish "absent" from "empty".
var ErrNotFound = errors.New("backend: secret not found")

// ErrUnavailable is returned (wrapped) by a Backend when the underlying store
// cannot be reached or refuses the request for reasons outside the caller's
// control — a transport failure, an expired or under-scoped credential, an
// upstream outage. Callers map it to a 503 so clients know to retry rather than
// treating it as a permanent failure. It never carries secret material.
var ErrUnavailable = errors.New("backend: storage unavailable")

// ErrRateLimited is wrapped alongside ErrUnavailable when the underlying store
// refused the request on a usage quota. It still maps to a 503 for clients, but
// background callers (the cache warmer) use it to back off to their normal
// cadence instead of fast-retrying into a limit that only time can clear.
var ErrRateLimited = errors.New("backend: rate limited")

// Record is the persisted form of a single secret across all of its versions.
// It mirrors setec's internal secret model (db/kv.go) so package store can
// reproduce setec's behaviour exactly, and so the 1Password hybrid layout can
// serialize it field-for-field.
type Record struct {
	// Name is the secret's name (its key in the store).
	Name string

	// Versions maps each live version to its value. A deleted version is
	// removed from this map but remains in Deleted.
	Versions map[api.SecretVersion][]byte

	// Active is the version served to clients that do not request a specific
	// version. It always refers to a key present in Versions.
	Active api.SecretVersion

	// Latest is the highest version ever assigned by a Put or CreateVersion.
	// It never decreases.
	Latest api.SecretVersion

	// Deleted is the set of versions that were previously set but have since
	// been deleted; they may never be recreated (api.ErrVersionClaimed).
	Deleted map[api.SecretVersion]struct{}
}

// IsClaimed reports whether v has ever been assigned to this secret, whether it
// is still live or has been deleted.
func (r *Record) IsClaimed(v api.SecretVersion) bool {
	if _, live := r.Versions[v]; live {
		return true
	}

	_, deleted := r.Deleted[v]

	return deleted
}

// Clone returns a deep copy of r. Backends must clone on the way in and out so
// that a caller mutating a returned Record cannot corrupt stored state.
func (r *Record) Clone() *Record {
	if r == nil {
		return nil
	}

	c := &Record{
		Name:   r.Name,
		Active: r.Active,
		Latest: r.Latest,
	}
	if r.Versions != nil {
		c.Versions = make(map[api.SecretVersion][]byte, len(r.Versions))
		for ver, val := range r.Versions {
			c.Versions[ver] = slices.Clone(val)
		}
	}

	if r.Deleted != nil {
		c.Deleted = maps.Clone(r.Deleted)
	}

	return c
}

// Equal reports whether two records hold identical data.
func (r *Record) Equal(o *Record) bool {
	if r == nil || o == nil {
		return r == o
	}

	if r.Name != o.Name || r.Active != o.Active || r.Latest != o.Latest {
		return false
	}

	if !maps.EqualFunc(r.Versions, o.Versions, slices.Equal) {
		return false
	}
	// A nil and an empty Deleted set compare equal (maps.Equal compares by length
	// and membership), so absent vs. present-but-empty does not matter.
	return maps.Equal(r.Deleted, o.Deleted)
}

// Backend is the storage abstraction behind ts1p. Implementations persist and
// retrieve Records by name. They perform no version logic of their own; that
// belongs to package store.
//
// Implementations must be safe for concurrent use.
type Backend interface {
	// Load returns the record for name, or ErrNotFound if it does not exist.
	// The returned record is owned by the caller and may be mutated freely.
	Load(ctx context.Context, name string) (*Record, error)

	// Save persists r under name, replacing any existing record. The backend
	// must not retain a reference to r after Save returns.
	Save(ctx context.Context, name string, r *Record) error

	// List returns the names of all stored secrets, in unspecified order.
	List(ctx context.Context) ([]string, error)

	// Delete removes all versions of name. Deleting a missing secret is not an
	// error.
	Delete(ctx context.Context, name string) error

	// Close releases any resources held by the backend.
	Close() error
}

// forceRefreshKey marks a context requesting a fresh read that bypasses any
// caching backend's cache.
type forceRefreshKey struct{}

// WithForceRefresh returns a context asking caching backends to bypass their
// cache for this read and refetch from the underlying store. It is an optional
// hint: backends without a cache (mem, onepassword) ignore it; package cache
// honours it. ts1p sets it when a request carries "Cache-Control: no-cache".
func WithForceRefresh(ctx context.Context) context.Context {
	return context.WithValue(ctx, forceRefreshKey{}, true)
}

// ForceRefresh reports whether ctx carries a WithForceRefresh hint.
func ForceRefresh(ctx context.Context) bool {
	v, _ := ctx.Value(forceRefreshKey{}).(bool)
	return v
}

// Package mem is an in-memory Backend implementation. It exists so the store
// and server can be tested against setec's own client without touching a real
// password manager, and as the reference the differential conformance test
// compares the 1Password backend against.
package mem

import (
	"context"
	"sync"

	"github.com/kradalby/ts1p/backend"
)

// Backend is an in-memory, concurrency-safe backend.Backend.
type Backend struct {
	// A single Mutex (not RWMutex) is deliberate: this is a test/reference backend
	// where simplicity beats read concurrency.
	mu      sync.Mutex
	records map[string]*backend.Record
}

// New returns an empty in-memory backend.
func New() *Backend {
	return &Backend{records: make(map[string]*backend.Record)}
}

// Load implements backend.Backend.
func (b *Backend) Load(_ context.Context, name string) (*backend.Record, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	r, ok := b.records[name]
	if !ok {
		return nil, backend.ErrNotFound
	}

	return r.Clone(), nil
}

// Save implements backend.Backend.
func (b *Backend) Save(_ context.Context, name string, r *backend.Record) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.records[name] = r.Clone()

	return nil
}

// List implements backend.Backend.
func (b *Backend) List(_ context.Context) ([]string, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	names := make([]string, 0, len(b.records))
	for name := range b.records {
		names = append(names, name)
	}

	return names, nil
}

// Delete implements backend.Backend.
func (b *Backend) Delete(_ context.Context, name string) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	delete(b.records, name)

	return nil
}

// Close implements backend.Backend.
func (b *Backend) Close() error { return nil }

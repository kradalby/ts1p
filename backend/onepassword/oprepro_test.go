//go:build oprepro

// This is the genuine reproduction effort for the extism/wazero "out of bounds
// memory access" fault that wedges the 1Password SDK's WASM core in production
// (observed on ts1p-ldn; see kradalby/ts1p#2). There is no public deterministic
// trigger, so this harness hammers a real client under sustained, concurrent
// load to try to provoke it. A persistent OOB exits the process (os.Exit(1)) —
// that abrupt termination is the reproduction; a transient OOB recovers on retry
// and is counted. Gated behind the `oprepro` build tag and real credentials.
//
//	OP_SERVICE_ACCOUNT_TOKEN=... TS1P_TEST_VAULT=ts1p-test \
//	  go test -tags oprepro -run TestOOBReproduction -timeout 30m ./backend/onepassword/
//
// Tunables: TS1P_OOB_DURATION (default 2m), TS1P_OOB_WORKERS (default 8).
package onepassword_test

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"

	"github.com/kradalby/ts1p/backend/onepassword"
	"github.com/kradalby/ts1p/store"
)

func TestOOBReproduction(t *testing.T) {
	token := os.Getenv("OP_SERVICE_ACCOUNT_TOKEN")
	vault := os.Getenv("TS1P_TEST_VAULT")
	if token == "" || vault == "" {
		t.Skip("set OP_SERVICE_ACCOUNT_TOKEN and TS1P_TEST_VAULT to run the OOB reproduction harness")
	}

	dur := 2 * time.Minute
	if s := os.Getenv("TS1P_OOB_DURATION"); s != "" {
		d, err := time.ParseDuration(s)
		require.NoError(t, err)
		dur = d
	}
	workers := 8
	if s := os.Getenv("TS1P_OOB_WORKERS"); s != "" {
		n, err := strconv.Atoi(s)
		require.NoError(t, err)
		workers = n
	}

	ctx := context.Background()
	// maxAge 0: never recycle, so the stress keeps hammering the same core to
	// maximise the chance of provoking the OOB.
	b, err := onepassword.New(ctx, token, vault, slog.Default(), 0)
	require.NoError(t, err)
	t.Cleanup(func() { _ = b.Close() })

	// Seed a secret so the read path has something to fetch.
	const name = "ts1p-oob-repro"
	st := store.New(b)
	_, err = st.Put(ctx, name, []byte("repro"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = b.Delete(ctx, name) })

	deadline := time.Now().Add(dur)
	var ops atomic.Int64
	g, gctx := errgroup.WithContext(ctx)
	for range workers {
		g.Go(func() error {
			for time.Now().Before(deadline) {
				if gctx.Err() != nil {
					return gctx.Err()
				}
				if _, err := b.List(gctx); err != nil {
					return fmt.Errorf("List failed under load: %w", err)
				}
				if _, err := b.Load(gctx, name); err != nil {
					return fmt.Errorf("Load failed under load: %w", err)
				}
				ops.Add(2)
			}
			return nil
		})
	}

	// A persistent OOB would have exited the process (os.Exit(1)) before reaching
	// here — that abrupt termination is itself the reproduction. Surviving means
	// any OOBs were transient and recovered on retry.
	require.NoError(t, g.Wait(), "an operation failed under load")
	t.Logf("oprepro: %d ops across %d workers over %s; %d transient OOBs recovered",
		ops.Load(), workers, dur, b.OOBCount())
	if b.OOBCount() == 0 {
		t.Logf("oprepro: did not trigger the WASM OOB this run; harness retained as the reproduction record")
	}
}

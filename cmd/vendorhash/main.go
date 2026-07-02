// Command vendorhash keeps flakehashes.json's vendorHash in sync with go.mod by
// asking Nix to compute it. Run "vendorhash check" in CI/pre-commit and
// "vendorhash update" after changing dependencies.
//
// It works the way everyone computes a Go vendorHash: write a known-wrong hash,
// build, and read the "got:" hash out of Nix's mismatch error.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"regexp"
	"syscall"
)

const (
	hashesFile = "flakehashes.json"
	fakeHash   = "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
)

type hashes struct {
	VendorHash string `json:"vendorHash"`
}

var gotRE = regexp.MustCompile(`got:\s*(sha256-[A-Za-z0-9+/=]+)`)

// errNoGotHash means the nix build failed for a reason other than the expected
// hash mismatch, so there is no hash to extract.
var errNoGotHash = errors.New("no got-hash in nix output")

func main() { os.Exit(run()) }

func run() int {
	if len(os.Args) != 2 || (os.Args[1] != "check" && os.Args[1] != "update") {
		fmt.Fprintln(os.Stderr, "usage: vendorhash check|update")
		return 2
	}

	write := os.Args[1] == "update"

	// Cancel the nix build on Ctrl-C/SIGTERM so compute's deferred restore runs
	// rather than leaving the fake hash on disk.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	current, err := read()
	if err != nil {
		return fail(err)
	}

	computed, err := compute(ctx)
	if err != nil {
		return fail(err)
	}

	if computed == current.VendorHash {
		fmt.Println("vendorHash up to date")
		return 0
	}

	if !write {
		fmt.Fprintf(os.Stderr, "vendorHash out of date: have %s, want %s\nrun: go run ./cmd/vendorhash update\n",
			current.VendorHash, computed)

		return 1
	}

	err = store(hashes{VendorHash: computed})
	if err != nil {
		return fail(err)
	}

	fmt.Printf("updated vendorHash to %s\n", computed)

	return 0
}

// compute returns the vendorHash Nix derives for the current go.mod/go.sum. It
// temporarily writes a fake hash, builds the flake to provoke the mismatch error
// that reveals the real hash, then restores the file — so even a read-only
// "check" has no side effects. No git staging is needed: the flake fetcher sees
// worktree modifications of a tracked file as-is.
func compute(ctx context.Context) (string, error) {
	original, err := os.ReadFile(hashesFile)
	if err != nil {
		return "", err
	}
	defer func() {
		// Restore must run even if ctx was cancelled (that is the whole point).
		//nolint:gosec // hashesFile is a compile-time constant, not user input
		err := os.WriteFile(hashesFile, original, 0o600)
		if err != nil {
			fmt.Fprintln(os.Stderr, "vendorhash: WARNING restoring", hashesFile, "failed:", err,
				"- the file may hold a fake hash; restore it from git")
		}
	}()

	err = store(hashes{VendorHash: fakeHash})
	if err != nil {
		return "", err
	}

	cmd := exec.CommandContext(ctx, "nix",
		"--extra-experimental-features", "nix-command flakes",
		"build", ".#default", "--no-link")
	out, _ := cmd.CombinedOutput() // expected to fail on the hash mismatch

	if ctx.Err() != nil {
		return "", ctx.Err()
	}

	m := gotRE.FindSubmatch(out)
	if m == nil {
		return "", fmt.Errorf("%w:\n%s", errNoGotHash, out)
	}

	return string(m[1]), nil
}

func read() (hashes, error) {
	var h hashes

	b, err := os.ReadFile(hashesFile)
	if err != nil {
		return h, err
	}

	return h, json.Unmarshal(b, &h)
}

func store(h hashes) error {
	b, err := json.MarshalIndent(h, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(hashesFile, append(b, '\n'), 0o600)
}

func fail(err error) int {
	fmt.Fprintln(os.Stderr, "vendorhash:", err)
	return 1
}

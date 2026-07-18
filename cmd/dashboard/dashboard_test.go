package main

import "testing"

// TestBuildDashboard exercises the SDK schema validation (Build) and confirms
// the dashboard is non-empty, so a broken panel fails the build that generates
// ts1p.json rather than shipping invalid JSON.
func TestBuildDashboard(t *testing.T) {
	d, err := buildDashboard()
	if err != nil {
		t.Fatalf("buildDashboard: %v", err)
	}

	if len(d.Panels) == 0 {
		t.Fatal("dashboard has no panels")
	}

	if d.Uid == nil || *d.Uid == "" {
		t.Fatal("dashboard has no uid")
	}
}

package maintenance

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/andreipaciurca/aegis/internal/signatures"
)

// isolate points HOME/XDG_CONFIG_HOME at a temp dir so the cache file never
// touches a real config directory, and returns a loaded, empty signature DB.
func isolate(t *testing.T) *signatures.DB {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
	db, err := signatures.Load()
	if err != nil {
		t.Fatalf("signatures.Load: %v", err)
	}
	return db
}

func seedCache(t *testing.T, entry cacheEntry) {
	t.Helper()
	path, err := cachePath()
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.MarshalIndent(entry, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestStartupIntervalDefaultsAndParses(t *testing.T) {
	t.Setenv("AEGIS_STARTUP_CHECK_INTERVAL", "")
	if got := StartupInterval(); got != DefaultStartupInterval {
		t.Fatalf("expected default %v, got %v", DefaultStartupInterval, got)
	}
	t.Setenv("AEGIS_STARTUP_CHECK_INTERVAL", "10m")
	if got := StartupInterval(); got != 10*time.Minute {
		t.Fatalf("expected 10m, got %v", got)
	}
	t.Setenv("AEGIS_STARTUP_CHECK_INTERVAL", "not-a-duration")
	if got := StartupInterval(); got != DefaultStartupInterval {
		t.Fatalf("invalid value should fall back to default, got %v", got)
	}
	t.Setenv("AEGIS_STARTUP_CHECK_INTERVAL", "-5m")
	if got := StartupInterval(); got != DefaultStartupInterval {
		t.Fatalf("negative value should fall back to default, got %v", got)
	}
}

// TestStartupCachedSkipsNetworkWithinInterval seeds a fresh cache entry with
// a sentinel value that Startup() could never itself produce, then asserts
// StartupCached returns exactly that sentinel under a context too short for
// any real network call to complete — proving the cache path was taken, not
// a live one that happened to fail fast.
func TestStartupCachedSkipsNetworkWithinInterval(t *testing.T) {
	db := isolate(t)
	const sentinel = "9.9.9-cache-sentinel"
	seedCache(t, cacheEntry{
		CheckedAt: time.Now(),
		Report:    Report{Aegis: ReleaseStatus{Latest: sentinel}},
	})

	shortCtx, cancel := context.WithTimeout(context.Background(), 5*time.Millisecond)
	defer cancel()
	got := StartupCached(shortCtx, db, "1.0.0", time.Hour)

	if got.Aegis.Latest != sentinel {
		t.Fatalf("expected cached sentinel %q, got %+v (cache was not used)", sentinel, got)
	}
}

// TestStartupCachedRefetchesAfterIntervalElapses seeds an already-expired
// cache entry and asserts it's ignored (a live Startup — bounded by the
// short ctx here, so it fails fast rather than actually reaching the
// network — replaces it) rather than served stale forever.
func TestStartupCachedRefetchesAfterIntervalElapses(t *testing.T) {
	db := isolate(t)
	const staleSentinel = "0.0.0-stale-sentinel"
	seedCache(t, cacheEntry{
		CheckedAt: time.Now().Add(-2 * time.Hour),
		Report:    Report{Aegis: ReleaseStatus{Latest: staleSentinel}},
	})

	shortCtx, cancel := context.WithTimeout(context.Background(), 5*time.Millisecond)
	defer cancel()
	got := StartupCached(shortCtx, db, "1.0.0", time.Hour)

	if got.Aegis.Latest == staleSentinel {
		t.Fatal("expected an expired cache entry to be ignored, got the stale value back")
	}
}

// TestStartupCachedZeroIntervalNeverCaches confirms AEGIS_STARTUP_CHECK_INTERVAL=0
// (interval=0 here) disables the cache entirely, even with a fresh entry on disk.
func TestStartupCachedZeroIntervalNeverCaches(t *testing.T) {
	db := isolate(t)
	const sentinel = "9.9.9-should-be-ignored"
	seedCache(t, cacheEntry{
		CheckedAt: time.Now(),
		Report:    Report{Aegis: ReleaseStatus{Latest: sentinel}},
	})

	shortCtx, cancel := context.WithTimeout(context.Background(), 5*time.Millisecond)
	defer cancel()
	got := StartupCached(shortCtx, db, "1.0.0", 0)

	if got.Aegis.Latest == sentinel {
		t.Fatal("interval=0 should disable the cache entirely, but the fresh cache entry was returned")
	}
}

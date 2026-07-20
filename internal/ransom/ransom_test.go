package ransom

import (
	"os"
	"path/filepath"
	"testing"
)

// TestCanaryLifecycle deploys canaries, simulates a ransomware attack that
// encrypts one, and verifies aegis detects the tampering.
func TestCanaryLifecycle(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	// os.UserConfigDir on macOS/Linux derives from HOME/XDG; ensure it resolves.
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))

	docs := filepath.Join(home, "Documents")
	if err := os.MkdirAll(docs, 0o755); err != nil {
		t.Fatal(err)
	}

	m, err := Deploy([]string{docs})
	if err != nil {
		t.Fatalf("deploy: %v", err)
	}
	if len(m.Canaries) == 0 {
		t.Fatal("no canaries deployed")
	}

	// Clean state: no tamper events.
	if ev := CheckCanaries(); len(ev) != 0 {
		t.Fatalf("expected no events on fresh canaries, got %d", len(ev))
	}

	// Simulate ransomware encrypting a canary with high-entropy content.
	enc := make([]byte, 4096)
	for i := range enc {
		enc[i] = byte((i*2654435761 + 1013904223) >> 16) // cheap pseudo-random
	}
	if err := os.WriteFile(m.Canaries[0].Path, enc, 0o600); err != nil {
		t.Fatal(err)
	}
	events := CheckCanaries()
	if len(events) == 0 {
		t.Fatal("tampered canary not detected")
	}
	if events[0].Severity != "CRITICAL" {
		t.Fatalf("expected CRITICAL, got %s", events[0].Severity)
	}
	t.Logf("detected: %s", events[0].Detail)

	// Simulate deletion of another canary.
	if len(m.Canaries) > 1 {
		os.Remove(m.Canaries[1].Path)
		if ev := CheckCanaries(); len(ev) < 2 {
			t.Fatalf("expected deletion + encryption events, got %d", len(ev))
		}
	}

	n, _ := Cleanup()
	if n < 1 {
		t.Fatalf("cleanup removed %d files", n)
	}
}

func TestRansomIndicators(t *testing.T) {
	if !HasKnownExtension("budget.xlsx.lockbit") {
		t.Error(".lockbit not recognized")
	}
	if HasKnownExtension("photo.jpg") {
		t.Error(".jpg falsely flagged")
	}
	if !IsRansomNote("HOW_TO_DECRYPT.txt") {
		t.Error("ransom note not recognized")
	}
	if IsRansomNote("meeting_notes.txt") {
		t.Error("benign file flagged as ransom note")
	}
}

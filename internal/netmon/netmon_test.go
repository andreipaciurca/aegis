package netmon

import (
	"runtime"
	"testing"
)

func TestDedupeConnections(t *testing.T) {
	in := []Conn{
		{Proc: "p", PID: "1", Proto: "TCP", Local: "*:5000", State: "LISTEN"},
		{Proc: "p", PID: "1", Proto: "TCP", Local: "*:5000", State: "LISTEN"},
		{Proc: "p", PID: "1", Proto: "TCP", Local: "*:7000", State: "LISTEN"},
	}
	got := dedupe(in)
	if len(got) != 2 {
		t.Fatalf("expected 2 unique connections, got %+v", got)
	}
}

func TestTrustedPlatformListener(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("macOS Control Center allowlist is darwin-specific")
	}
	c := Conn{Proc: "ControlCe", PID: "710", Proto: "TCP", Local: "*:5000", State: "LISTEN"}
	if got := assess(c); got != "" {
		t.Fatalf("expected macOS Control Center listener to be trusted, got %q", got)
	}
}

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/andreipaciurca/aegis/internal/netmon"
	"github.com/andreipaciurca/aegis/internal/rules"
	"github.com/andreipaciurca/aegis/internal/signatures"
)

func TestCLIScanExitCodes(t *testing.T) {
	eng, err := rules.Load(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	db := &signatures.DB{Hashes: map[string]struct{}{}}

	cleanDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(cleanDir, "hello.txt"), []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}
	if code := cliScan(db, eng, []string{cleanDir}); code != 0 {
		t.Fatalf("clean scan exit code = %d, want 0", code)
	}

	threatDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(threatDir, "eicar.txt"),
		[]byte(`X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*`), 0o644); err != nil {
		t.Fatal(err)
	}
	if code := cliScan(db, eng, []string{threatDir}); code != 1 {
		t.Fatalf("threat scan exit code = %d, want 1", code)
	}
}

func TestHelpFlagDetection(t *testing.T) {
	for _, flag := range []string{"--help", "-h", "help"} {
		if !isHelpFlag(flag) {
			t.Fatalf("%q should be a help flag", flag)
		}
	}
	if isHelpFlag("--json") {
		t.Fatal("--json should not be a help flag")
	}
}

func TestNetworkHintsWindowsIncludeCommandPromptFallbacks(t *testing.T) {
	h := networkHints(netmon.Conn{PID: "1234", Local: "0.0.0.0:4444", Suspect: "listening on 4444"}, "windows")
	joined := strings.Join(append(h.Explore, h.Stop...), "\n")
	for _, want := range []string{"PowerShell:", "Command Prompt: netstat", "Command Prompt: tasklist", "Command Prompt: taskkill"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("network hints missing %q:\n%s", want, joined)
		}
	}
}

func TestParseGUIFlagsHTTPS(t *testing.T) {
	flags := parseGUIFlags([]string{"--no-open", "--https", "--cert", "localhost.pem", "--key=localhost-key.pem", "--socket", "aegis.sock"})
	if flags.open {
		t.Fatal("--no-open should disable browser opening")
	}
	if !flags.https {
		t.Fatal("--https should enable HTTPS")
	}
	if flags.cert != "localhost.pem" || flags.key != "localhost-key.pem" || flags.socket != "aegis.sock" {
		t.Fatalf("unexpected parsed flags: %+v", flags)
	}
}

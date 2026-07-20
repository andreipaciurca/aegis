package main

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/andreipaciurca/aegis/internal/ai"
	"github.com/andreipaciurca/aegis/internal/netmon"
	"github.com/andreipaciurca/aegis/internal/rules"
	"github.com/andreipaciurca/aegis/internal/scanner"
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

func TestThreatPromptRedactsParentDirectories(t *testing.T) {
	path := filepath.Join(t.TempDir(), "Secret Client", "invoice.pdf.exe")
	prompt := threatPrompt(scanner.Threat{
		Path:     path,
		SHA256:   strings.Repeat("a", 64),
		Reason:   "test",
		Severity: scanner.SevCritical,
		Size:     123,
	}, ai.Config{PrivacyMode: "metadata"})
	if strings.Contains(prompt, filepath.Dir(path)) || strings.Contains(prompt, "Secret Client") {
		t.Fatalf("AI prompt leaked parent path:\n%s", prompt)
	}
	if !strings.Contains(prompt, "invoice.pdf.exe") {
		t.Fatalf("AI prompt should keep filename context:\n%s", prompt)
	}
}

func TestSafeExcerptRejectsUnsafeInput(t *testing.T) {
	if got := safeExcerpt("bad\x00path", 32); got != "" {
		t.Fatalf("expected NUL path excerpt to be empty, got %q", got)
	}
	dir := t.TempDir()
	if got := safeExcerpt(dir, 32); got != "" {
		t.Fatalf("expected directory excerpt to be empty, got %q", got)
	}
	file := filepath.Join(dir, "note.txt")
	if err := os.WriteFile(file, []byte("plain text for analyst"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := safeExcerpt(file, 0); got != "" {
		t.Fatalf("expected non-positive cap excerpt to be empty, got %q", got)
	}
	if got := safeExcerpt(file, 8); got != "plain te" {
		t.Fatalf("unexpected excerpt %q", got)
	}
}

func TestUsageMentionsEveryPrimaryCommand(t *testing.T) {
	out := captureStdout(t, usage)
	for _, want := range []string{
		"aegis app",
		"scan PATH",
		"status",
		"update",
		"gui",
		"shield",
		"network [--all]",
		"firewall [status]",
		"audit",
		"checkup",
		"ai",
		"intel HASH",
		"clamav PATH",
		"analyze PATH",
		"history",
		"restore ID",
		"version",
		"aegis help scan",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("top-level usage missing %q:\n%s", want, out)
		}
	}
}

func TestCommandUsageTopicsAreHumanReadable(t *testing.T) {
	topics := map[string][]string{
		"scan":     {"aegis scan PATH", "Exit codes"},
		"shield":   {"aegis shield", "ransomware"},
		"audit":    {"aegis audit", "persistence"},
		"firewall": {"aegis firewall", "macOS", "Linux", "Windows"},
		"network":  {"aegis network", "why it was flagged", "Command Prompt"},
		"status":   {"aegis status", "posture score"},
		"checkup":  {"aegis checkup", "CISA KEV", "NVD"},
		"ai":       {"aegis ai status", "advisory"},
		"intel":    {"aegis intel HASH", "VirusTotal", "normal scans never call VirusTotal"},
		"clamav":   {"aegis clamav PATH", "clamd"},
		"gui":      {"aegis gui", "127.0.0.1", "--https"},
		"app":      {"aegis app", "TUI and local browser GUI"},
		"analyze":  {"aegis analyze", "disk"},
		"history":  {"aegis history", "quarantine"},
		"restore":  {"aegis restore", "review folder"},
		"update":   {"aegis update", "SHA256SUMS", "Restart aegis"},
		"version":  {"aegis version", "installed aegis version"},
	}
	for topic, wants := range topics {
		out := captureStdout(t, func() { commandUsage(topic) })
		for _, want := range wants {
			if !strings.Contains(out, want) {
				t.Fatalf("help topic %q missing %q:\n%s", topic, want, out)
			}
		}
	}
}

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe stdout: %v", err)
	}
	os.Stdout = w
	fn()
	_ = w.Close()
	os.Stdout = old
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read stdout: %v", err)
	}
	return string(out)
}

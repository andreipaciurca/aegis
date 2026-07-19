package main

import (
	"os"
	"path/filepath"
	"testing"

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

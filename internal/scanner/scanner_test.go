package scanner

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/andreipaciurca/aegis/internal/rules"
	"github.com/andreipaciurca/aegis/internal/signatures"
)

func TestScanCancelledBeforeWork(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "file.txt"), []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}
	cancel := make(chan struct{})
	close(cancel)

	var final Progress
	for p := range Scan(root, &signatures.DB{Hashes: map[string]struct{}{}}, nil, cancel) {
		final = p
	}
	if final.Phase != "cancelled" {
		t.Fatalf("expected cancelled phase, got %q", final.Phase)
	}
	if final.Ended.IsZero() {
		t.Fatal("cancelled scan should include an end time")
	}
}

func TestScanSortsThreatsBySeverityThenPath(t *testing.T) {
	root := t.TempDir()
	files := map[string]string{
		"z-note.txt":       "Your files have been encrypted. Pay bitcoin.",
		"a-benign.js":      "console.log('ok')",
		"m-budget.lockbit": "encrypted",
	}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(root, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	eng, err := rules.Load("")
	if err != nil {
		t.Fatal(err)
	}
	cancel := make(chan struct{})
	var final Progress
	for p := range Scan(root, &signatures.DB{Hashes: map[string]struct{}{}}, eng, cancel) {
		final = p
	}
	if final.Phase != "done" {
		t.Fatalf("expected done phase, got %q", final.Phase)
	}
	if len(final.Threats) < 2 {
		t.Fatalf("expected at least two threats, got %v", final.Threats)
	}
	for i := 1; i < len(final.Threats); i++ {
		prev, cur := final.Threats[i-1], final.Threats[i]
		if prev.Severity < cur.Severity {
			t.Fatalf("threats not sorted by severity: %v", final.Threats)
		}
		if prev.Severity == cur.Severity && prev.Path > cur.Path {
			t.Fatalf("threats not sorted by path: %v", final.Threats)
		}
	}
}

func TestScanFollowsRootSymlinkForMacTmpStylePath(t *testing.T) {
	target := t.TempDir()
	if err := os.WriteFile(filepath.Join(target, "eicar.txt"),
		[]byte(`X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*`), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "tmp-link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}

	cancel := make(chan struct{})
	var final Progress
	for p := range Scan(link, &signatures.DB{Hashes: map[string]struct{}{}}, nil, cancel) {
		final = p
	}
	if final.Phase != "done" {
		t.Fatalf("expected done phase, got %q", final.Phase)
	}
	if final.Scanned != 1 {
		t.Fatalf("expected one scanned file, got %d", final.Scanned)
	}
	if len(final.Threats) != 1 || final.Threats[0].Reason != "EICAR antivirus test file" {
		t.Fatalf("expected EICAR threat, got %+v", final.Threats)
	}
}

func TestEICARReasonWinsOverBuiltinSignature(t *testing.T) {
	path := filepath.Join(t.TempDir(), "eicar.txt")
	body := []byte(`X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*`)
	if err := os.WriteFile(path, body, 0o644); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(body)
	db := &signatures.DB{Hashes: map[string]struct{}{}, Info: map[string]signatures.SignatureInfo{}}
	db.Hashes[hex.EncodeToString(sum[:])] = struct{}{}

	threat, ok, skip := scanFile(path, db, nil)
	if skip || !ok {
		t.Fatalf("skip=%v ok=%v threat=%+v", skip, ok, threat)
	}
	if threat.Reason != "EICAR antivirus test file" {
		t.Fatalf("got reason %q", threat.Reason)
	}
}

func TestSignatureConfidenceControlsSeverity(t *testing.T) {
	path := filepath.Join(t.TempDir(), "payload.bin")
	body := []byte("not suspicious by content")
	if err := os.WriteFile(path, body, 0o644); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(body)
	hash := hex.EncodeToString(sum[:])

	medium := &signatures.DB{Hashes: map[string]struct{}{hash: {}}, Info: map[string]signatures.SignatureInfo{
		hash: {SHA256: hash, Sources: []signatures.SourceHit{{Name: "URLhaus payloads", Confidence: signatures.ConfidenceMedium}}},
	}}
	threat, ok, skip := scanFile(path, medium, nil)
	if skip || !ok {
		t.Fatalf("medium signature not found: skip=%v ok=%v", skip, ok)
	}
	if threat.Severity != SevWarning || !strings.Contains(threat.Reason, "review before action") {
		t.Fatalf("unexpected medium threat: %+v", threat)
	}

	high := &signatures.DB{Hashes: map[string]struct{}{hash: {}}, Info: map[string]signatures.SignatureInfo{
		hash: {SHA256: hash, Sources: []signatures.SourceHit{{Name: "MalwareBazaar", Confidence: signatures.ConfidenceHigh}}},
	}}
	threat, ok, skip = scanFile(path, high, nil)
	if skip || !ok {
		t.Fatalf("high signature not found: skip=%v ok=%v", skip, ok)
	}
	if threat.Severity != SevCritical || !strings.Contains(threat.Reason, "known malware hash") {
		t.Fatalf("unexpected high threat: %+v", threat)
	}
}

func TestHiddenExecutableInHomeIsFlagged(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix executable-bit hidden-file heuristic is not used on Windows")
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	path := filepath.Join(home, ".hidden-tool")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	threat, ok, skip := scanFile(path, &signatures.DB{Hashes: map[string]struct{}{}}, nil)
	if skip {
		t.Fatal("hidden executable should not be skipped")
	}
	if !ok {
		t.Fatal("hidden executable was not flagged")
	}
	if threat.Severity != SevWarning || threat.Reason != "Hidden executable file" {
		t.Fatalf("unexpected threat: %+v", threat)
	}
}

func TestWorkerCountEnvCap(t *testing.T) {
	t.Setenv("AEGIS_SCAN_WORKERS", "999")
	if got := workerCount(); got != 8 {
		t.Fatalf("expected worker cap 8, got %d", got)
	}
	t.Setenv("AEGIS_SCAN_WORKERS", "2")
	if got := workerCount(); got != 2 {
		t.Fatalf("expected 2 workers, got %d", got)
	}
}

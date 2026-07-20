package scanner

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

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

func TestQuarantineAndRestoreRoundTrip(t *testing.T) {
	home := t.TempDir()
	setTestConfigHome(t, home)

	src := filepath.Join(home, "Downloads", "invoice.pdf.exe")
	if err := os.MkdirAll(filepath.Dir(src), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(src, []byte("payload"), 0o644); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte("payload"))
	threat := Threat{Path: src, SHA256: hex.EncodeToString(sum[:]), Reason: "test", Severity: SevCritical}

	rec, err := Quarantine(threat)
	if err != nil {
		t.Fatalf("quarantine: %v", err)
	}
	if _, err := os.Stat(src); !os.IsNotExist(err) {
		t.Fatal("original file should be gone after quarantine")
	}
	if _, err := os.Stat(rec.Stored); err != nil {
		t.Fatalf("stored file missing: %v", err)
	}
	if !strings.HasSuffix(rec.Stored, ".aqv") || !rec.Encrypted || rec.RecordHMAC == "" || rec.VaultHMAC == "" {
		t.Fatalf("expected encrypted signed vault record, got %+v", rec)
	}
	_ = os.Chmod(rec.Stored, 0o600)
	vaultBytes, err := os.ReadFile(rec.Stored)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(vaultBytes), "payload") {
		t.Fatal("quarantine vault should not contain plaintext payload")
	}

	hist, err := QuarantineHistory()
	if err != nil || len(hist) != 1 || hist[0].Restored {
		t.Fatalf("expected one unrestored history entry, got %+v (err=%v)", hist, err)
	}

	restored, err := Restore(rec.Stored)
	if err != nil {
		t.Fatalf("restore: %v", err)
	}
	if !restored.Restored || restored.RestoredAt == nil {
		t.Fatalf("restore did not mark record as restored: %+v", restored)
	}
	if restored.RestoredTo == "" || strings.Contains(restored.RestoredTo, string(filepath.Separator)+"Downloads"+string(filepath.Separator)) {
		t.Fatalf("default restore should go to review folder, got %+v", restored)
	}
	if _, err := os.Stat(src); !os.IsNotExist(err) {
		t.Fatalf("original file should stay absent after safe restore, got %v", err)
	}
	if got, err := os.ReadFile(restored.RestoredTo); err != nil || string(got) != "payload" {
		t.Fatalf("review restore content mismatch: %q err=%v", got, err)
	}
	if _, err := os.Stat(rec.Stored); !os.IsNotExist(err) {
		t.Fatal("quarantined copy should be gone after restore")
	}

	if _, err := Restore(rec.Stored); err == nil {
		t.Fatal("expected error restoring an already-restored record")
	}

	// Restoring again onto an existing file must refuse to overwrite.
	rec2, err := Quarantine(Threat{Path: writeTemp(t, filepath.Join(home, "Downloads", "again.exe"), "x"), Reason: "t", Severity: SevWarning})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(rec2.Original, []byte("someone recreated this"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := RestoreOriginal(rec2.Stored); err == nil {
		t.Fatal("expected original restore to refuse overwriting an existing file")
	}
}

func TestRestoreOriginalRoundTrip(t *testing.T) {
	home := t.TempDir()
	setTestConfigHome(t, home)

	src := writeTemp(t, filepath.Join(home, "Downloads", "false-positive.exe"), "payload")
	sum := sha256.Sum256([]byte("payload"))
	rec, err := Quarantine(Threat{Path: src, SHA256: hex.EncodeToString(sum[:]), Reason: "test", Severity: SevWarning})
	if err != nil {
		t.Fatal(err)
	}
	restored, err := RestoreOriginal(rec.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	if restored.RestoredTo != src {
		t.Fatalf("expected original restore to %s, got %s", src, restored.RestoredTo)
	}
	if got, err := os.ReadFile(src); err != nil || string(got) != "payload" {
		t.Fatalf("original restore content mismatch: %q err=%v", got, err)
	}
}

func TestQuarantineVaultTamperIsRejected(t *testing.T) {
	home := t.TempDir()
	setTestConfigHome(t, home)

	src := writeTemp(t, filepath.Join(home, "Downloads", "bad.exe"), "payload")
	sum := sha256.Sum256([]byte("payload"))
	rec, err := Quarantine(Threat{Path: src, SHA256: hex.EncodeToString(sum[:]), Reason: "test", Severity: SevCritical})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(rec.Stored, 0o600); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(rec.Stored)
	if err != nil {
		t.Fatal(err)
	}
	var vault quarantineVault
	if err := json.Unmarshal(b, &vault); err != nil {
		t.Fatal(err)
	}
	vault.HMAC = strings.Repeat("0", 64)
	b, err = json.MarshalIndent(vault, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(rec.Stored, b, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Restore(rec.Stored); err == nil || !strings.Contains(err.Error(), "integrity check failed") {
		t.Fatalf("expected vault tamper refusal, got %v", err)
	}
}

func TestQuarantineLogTamperIsRejected(t *testing.T) {
	home := t.TempDir()
	setTestConfigHome(t, home)

	src := writeTemp(t, filepath.Join(home, "Downloads", "bad.exe"), "payload")
	sum := sha256.Sum256([]byte("payload"))
	if _, err := Quarantine(Threat{Path: src, SHA256: hex.EncodeToString(sum[:]), Reason: "test", Severity: SevCritical}); err != nil {
		t.Fatal(err)
	}
	qdir, err := quarantineDir()
	if err != nil {
		t.Fatal(err)
	}
	var recs []QuarantineRecord
	b, err := os.ReadFile(quarantineLogPath(qdir))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &recs); err != nil {
		t.Fatal(err)
	}
	recs[0].Reason = "tampered"
	b, err = json.MarshalIndent(recs, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(quarantineLogPath(qdir), b, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := QuarantineHistory(); err == nil || !strings.Contains(err.Error(), "log integrity check failed") {
		t.Fatalf("expected log tamper refusal, got %v", err)
	}
}

func TestQuarantineRejectsUnsafePathsAndIDs(t *testing.T) {
	home := t.TempDir()
	setTestConfigHome(t, home)

	if _, err := Quarantine(Threat{Path: "bad\x00path", Reason: "test"}); err == nil {
		t.Fatal("expected quarantine to reject a path containing NUL")
	}

	src := writeTemp(t, filepath.Join(home, "Downloads", "payload.exe"), "x")
	if _, err := Quarantine(Threat{Path: src, SHA256: "../escape", Reason: "test"}); err == nil {
		t.Fatal("expected quarantine to reject an unsafe supplied id")
	}
}

func TestRestoreRejectsStoredPathOutsideQuarantine(t *testing.T) {
	home := t.TempDir()
	setTestConfigHome(t, home)

	qdir, err := quarantineDir()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(qdir, 0o700); err != nil {
		t.Fatal(err)
	}
	outside := writeTemp(t, filepath.Join(home, "outside.quar"), "payload")
	rec := QuarantineRecord{
		Original: filepath.Join(home, "restore-target.exe"),
		SHA256:   strings.Repeat("a", 64),
		Reason:   "test",
		When:     nowForTest(),
		Stored:   outside,
	}
	if err := saveLog(qdir, []QuarantineRecord{rec}); err != nil {
		t.Fatal(err)
	}
	if _, err := Restore(rec.SHA256); err == nil || !strings.Contains(err.Error(), "outside quarantine directory") {
		t.Fatalf("expected outside-quarantine restore refusal, got %v", err)
	}
}

func writeTemp(t *testing.T, path, content string) string {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func setTestConfigHome(t *testing.T, home string) {
	t.Helper()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
	t.Setenv("APPDATA", filepath.Join(home, "AppData", "Roaming"))
	t.Setenv("LOCALAPPDATA", filepath.Join(home, "AppData", "Local"))
}

func nowForTest() time.Time { return time.Unix(1, 0).UTC() }

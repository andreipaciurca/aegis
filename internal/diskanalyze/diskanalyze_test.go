package diskanalyze

import (
	"os"
	"path/filepath"
	"testing"
)

func TestAnalyzeReportsTopEntriesAndLargeFiles(t *testing.T) {
	root := t.TempDir()
	bigDir := filepath.Join(root, "big")
	smallDir := filepath.Join(root, "small")
	if err := os.MkdirAll(bigDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(smallDir, 0o755); err != nil {
		t.Fatal(err)
	}
	large := filepath.Join(bigDir, "backup.sql")
	if err := os.WriteFile(large, make([]byte, DefaultLargeFileSize+1), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(smallDir, "note.txt"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	report, err := Analyze(root)
	if err != nil {
		t.Fatal(err)
	}
	if report.TotalFiles != 2 {
		t.Fatalf("expected 2 files, got %d", report.TotalFiles)
	}
	if len(report.Entries) < 2 || report.Entries[0].Name != "big" {
		t.Fatalf("expected largest entry first, got %+v", report.Entries)
	}
	if len(report.LargeFiles) != 1 {
		t.Fatalf("expected one large file, got %+v", report.LargeFiles)
	}
	if report.LargeFiles[0].Reason != "large data store or backup" {
		t.Fatalf("unexpected large file reason: %+v", report.LargeFiles[0])
	}
}

func TestTopChildUsesRootPrefix(t *testing.T) {
	root := filepath.Join(string(filepath.Separator), "tmp", "root")
	got := topChild(root, root+string(filepath.Separator), filepath.Join(root, "child", "file.txt"))
	want := filepath.Join(root, "child")
	if got != want {
		t.Fatalf("topChild = %q, want %q", got, want)
	}
	if got := topChild(root, root+string(filepath.Separator), filepath.Join(string(filepath.Separator), "tmp", "other")); got != "" {
		t.Fatalf("expected outside path to be ignored, got %q", got)
	}
}

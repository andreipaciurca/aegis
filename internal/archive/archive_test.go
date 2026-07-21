package archive

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"os"
	"path/filepath"
	"testing"
)

func writeZip(t *testing.T, path string, files map[string]string) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	zw := zip.NewWriter(f)
	for name, content := range files {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
}

func writeTarGz(t *testing.T, path string, files map[string]string) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	for name, content := range files {
		hdr := &tar.Header{Name: name, Mode: 0o644, Size: int64(len(content))}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
}

func writeTarGzEntries(t *testing.T, path string, entries []*tar.Header, bodies []string) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	compressed := gzip.NewWriter(f)
	writer := tar.NewWriter(compressed)
	for i, header := range entries {
		if err := writer.WriteHeader(header); err != nil {
			t.Fatal(err)
		}
		if bodies[i] != "" {
			if _, err := writer.Write([]byte(bodies[i])); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := compressed.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestExtractZip(t *testing.T) {
	dir := t.TempDir()
	zipPath := filepath.Join(dir, "a.zip")
	writeZip(t, zipPath, map[string]string{
		"aegis-1.0.0-linux-amd64/aegis":     "binary-content",
		"aegis-1.0.0-linux-amd64/README.md": "readme",
	})
	dest := filepath.Join(dir, "out")
	if err := os.MkdirAll(dest, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := Extract(zipPath, dest); err != nil {
		t.Fatalf("Extract: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(dest, "aegis-1.0.0-linux-amd64", "aegis"))
	if err != nil {
		t.Fatalf("read extracted file: %v", err)
	}
	if string(got) != "binary-content" {
		t.Errorf("content = %q, want %q", got, "binary-content")
	}
}

func TestExtractTarGz(t *testing.T) {
	dir := t.TempDir()
	tarPath := filepath.Join(dir, "a.tar.gz")
	writeTarGz(t, tarPath, map[string]string{
		"aegis-1.0.0-linux-amd64/aegis": "binary-content",
	})
	dest := filepath.Join(dir, "out")
	if err := os.MkdirAll(dest, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := Extract(tarPath, dest); err != nil {
		t.Fatalf("Extract: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(dest, "aegis-1.0.0-linux-amd64", "aegis"))
	if err != nil {
		t.Fatalf("read extracted file: %v", err)
	}
	if string(got) != "binary-content" {
		t.Errorf("content = %q, want %q", got, "binary-content")
	}
}

func TestExtractZipRejectsPathTraversal(t *testing.T) {
	dir := t.TempDir()
	zipPath := filepath.Join(dir, "evil.zip")
	writeZip(t, zipPath, map[string]string{
		"../../etc/evil": "pwned",
	})
	dest := filepath.Join(dir, "out")
	if err := os.MkdirAll(dest, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := Extract(zipPath, dest); err == nil {
		t.Fatal("expected an error for a path-traversal entry, got nil")
	}
	if _, err := os.Stat(filepath.Join(dir, "etc", "evil")); err == nil {
		t.Fatal("path-traversal entry was written outside the destination")
	}
}

func TestExtractTarGzRejectsAbsolutePath(t *testing.T) {
	dir := t.TempDir()
	tarPath := filepath.Join(dir, "evil.tar.gz")
	writeTarGz(t, tarPath, map[string]string{
		"/etc/evil": "pwned",
	})
	dest := filepath.Join(dir, "out")
	if err := os.MkdirAll(dest, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := Extract(tarPath, dest); err == nil {
		t.Fatal("expected an error for an absolute-path entry, got nil")
	}
}

func TestExtractTarGzPreservesSafeSymlink(t *testing.T) {
	dir := t.TempDir()
	tarPath := filepath.Join(dir, "links.tar.gz")
	writeTarGzEntries(t, tarPath, []*tar.Header{
		{Name: "llama/libllama.0.0.10075.dylib", Mode: 0o644, Size: 7},
		{Name: "llama/libllama.0.dylib", Typeflag: tar.TypeSymlink, Linkname: "libllama.0.0.10075.dylib"},
	}, []string{"runtime", ""})
	dest := filepath.Join(dir, "out")
	if err := os.MkdirAll(dest, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := Extract(tarPath, dest); err != nil {
		t.Fatalf("Extract: %v", err)
	}
	link := filepath.Join(dest, "llama", "libllama.0.dylib")
	info, err := os.Lstat(link)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("%s is not a symlink", link)
	}
	got, err := os.Readlink(link)
	if err != nil {
		t.Fatal(err)
	}
	if got != "libllama.0.0.10075.dylib" {
		t.Fatalf("link target = %q", got)
	}
}

func TestExtractTarGzRejectsEscapingSymlink(t *testing.T) {
	dir := t.TempDir()
	tarPath := filepath.Join(dir, "evil-links.tar.gz")
	writeTarGzEntries(t, tarPath, []*tar.Header{
		{Name: "llama/escape", Typeflag: tar.TypeSymlink, Linkname: "../../outside"},
	}, []string{""})
	dest := filepath.Join(dir, "out")
	if err := os.MkdirAll(dest, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := Extract(tarPath, dest); err == nil {
		t.Fatal("expected unsafe symlink target error, got nil")
	}
}

func TestExtractZipRejectsWindowsAbsolutePath(t *testing.T) {
	dir := t.TempDir()
	zipPath := filepath.Join(dir, "evil.zip")
	writeZip(t, zipPath, map[string]string{
		`C:\Windows\System32\evil.dll`: "pwned",
	})
	dest := filepath.Join(dir, "out")
	if err := os.MkdirAll(dest, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := Extract(zipPath, dest); err == nil {
		t.Fatal("expected an error for a Windows drive-letter absolute entry, got nil")
	}
}

func TestExtractUnsupportedExtension(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "a.rar")
	if err := os.WriteFile(path, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := Extract(path, dir); err == nil {
		t.Fatal("expected an error for an unsupported extension, got nil")
	}
}

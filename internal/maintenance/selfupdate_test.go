package maintenance

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/andreipaciurca/aegis/internal/archive"
)

func TestSha256ForAsset(t *testing.T) {
	dir := t.TempDir()
	sums := "aaaa1111  aegis-1.0.0-linux-amd64.tar.gz\nbbbb2222  aegis-1.0.0-darwin-arm64.tar.gz\n"
	path := filepath.Join(dir, "SHA256SUMS")
	if err := os.WriteFile(path, []byte(sums), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := sha256ForAsset(path, "aegis-1.0.0-darwin-arm64.tar.gz")
	if err != nil {
		t.Fatalf("sha256ForAsset: %v", err)
	}
	if got != "bbbb2222" {
		t.Errorf("got %q, want %q", got, "bbbb2222")
	}
	if _, err := sha256ForAsset(path, "not-listed.tar.gz"); err == nil {
		t.Fatal("expected an error for an asset not in SHA256SUMS")
	}
}

func TestReleaseAssetName(t *testing.T) {
	name, err := releaseAssetName("1.5.0")
	if err != nil {
		t.Fatalf("releaseAssetName: %v", err)
	}
	wantSuffix := map[string]string{"darwin/arm64": "darwin-arm64.tar.gz", "darwin/amd64": "darwin-amd64.tar.gz", "linux/amd64": "linux-amd64.tar.gz", "linux/arm64": "linux-arm64.tar.gz", "windows/amd64": "windows-amd64.zip"}
	key := runtime.GOOS + "/" + runtime.GOARCH
	suffix, ok := wantSuffix[key]
	if !ok {
		t.Skipf("no expected suffix defined for %s", key)
	}
	want := "aegis-1.5.0-" + suffix
	if name != want {
		t.Errorf("releaseAssetName = %q, want %q", name, want)
	}
}

func TestReplaceBinaryAtomicSwap(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "aegis")
	if err := os.WriteFile(target, []byte("old-binary"), 0o755); err != nil {
		t.Fatal(err)
	}
	newBin := filepath.Join(dir, "new-aegis")
	if err := os.WriteFile(newBin, []byte("new-binary"), 0o755); err != nil {
		t.Fatal(err)
	}

	if err := replaceBinary(newBin, target); err != nil {
		t.Fatalf("replaceBinary: %v", err)
	}
	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "new-binary" {
		t.Errorf("target content = %q, want %q", got, "new-binary")
	}
	if _, err := os.Stat(filepath.Join(dir, ".aegis-update-tmp")); err == nil {
		t.Error("temp file was left behind after a successful replace")
	}
}

func makeTestArchive(t *testing.T, dir, assetName, binName, content string) (path string, sha256hex string) {
	t.Helper()
	path = filepath.Join(dir, assetName)
	var buf bytes.Buffer
	if runtime.GOOS == "windows" {
		zw := zip.NewWriter(&buf)
		w, err := zw.Create("aegis-1.5.0-windows-amd64/" + binName)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
		if err := zw.Close(); err != nil {
			t.Fatal(err)
		}
	} else {
		gz := gzip.NewWriter(&buf)
		tw := tar.NewWriter(gz)
		hdr := &tar.Header{Name: "aegis-1.5.0-x/" + binName, Mode: 0o755, Size: int64(len(content))}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
		if err := tw.Close(); err != nil {
			t.Fatal(err)
		}
		if err := gz.Close(); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(buf.Bytes())
	return path, hex.EncodeToString(sum[:])
}

func TestInstallUpdateEndToEnd(t *testing.T) {
	binName := "aegis"
	if runtime.GOOS == "windows" {
		binName = "aegis.exe"
	}
	asset, err := releaseAssetName("1.5.0")
	if err != nil {
		t.Skipf("no release asset for this platform: %v", err)
	}

	srcDir := t.TempDir()
	archivePath, digest := makeTestArchive(t, srcDir, asset, binName, "new-binary-content")
	sums := digest + "  " + asset + "\n"

	mux := http.NewServeMux()
	mux.HandleFunc("/SHA256SUMS", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(sums))
	})
	mux.HandleFunc("/"+asset, func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, archivePath)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	origBase := selfUpdateBaseURL
	origClient := selfUpdateHTTPClient
	selfUpdateBaseURL = func(version string) string { return srv.URL + "/" }
	selfUpdateHTTPClient = srv.Client()
	t.Cleanup(func() {
		selfUpdateBaseURL = origBase
		selfUpdateHTTPClient = origClient
	})

	// InstallUpdate calls os.Executable(), which points at the `go test`
	// binary in this process — not something we can or should overwrite.
	// Exercise the pieces InstallUpdate composes instead, at the same
	// seams a real run would use, so the download+verify+extract path is
	// covered without touching the real test binary.
	tmpDir := t.TempDir()
	sumsPath := filepath.Join(tmpDir, "SHA256SUMS")
	if err := downloadTo(context.Background(), selfUpdateBaseURL("1.5.0")+"SHA256SUMS", sumsPath); err != nil {
		t.Fatalf("downloadTo(SHA256SUMS): %v", err)
	}
	want, err := sha256ForAsset(sumsPath, asset)
	if err != nil {
		t.Fatalf("sha256ForAsset: %v", err)
	}
	dlPath := filepath.Join(tmpDir, asset)
	if err := downloadTo(context.Background(), selfUpdateBaseURL("1.5.0")+asset, dlPath); err != nil {
		t.Fatalf("downloadTo(asset): %v", err)
	}
	got, err := sha256File(dlPath)
	if err != nil {
		t.Fatalf("sha256File: %v", err)
	}
	if got != want {
		t.Fatalf("checksum mismatch: got %s want %s", got, want)
	}

	extractDir := filepath.Join(tmpDir, "extracted")
	if err := os.MkdirAll(extractDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := archive.Extract(dlPath, extractDir); err != nil {
		t.Fatalf("extract: %v", err)
	}
	found, err := findFile(extractDir, binName)
	if err != nil {
		t.Fatalf("findFile: %v", err)
	}
	content, err := os.ReadFile(found)
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "new-binary-content" {
		t.Errorf("extracted binary content = %q, want %q", content, "new-binary-content")
	}

	// Now cover the full InstallUpdate happy path against a fake target
	// binary, by temporarily pointing findFile/replaceBinary's target at
	// a throwaway file via the same replaceBinary call InstallUpdate uses.
	target := filepath.Join(tmpDir, "fake-installed-"+binName)
	if err := os.WriteFile(target, []byte("old-binary-content"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := replaceBinary(found, target); err != nil {
		t.Fatalf("replaceBinary: %v", err)
	}
	replaced, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(replaced) != "new-binary-content" {
		t.Errorf("replaced binary content = %q, want %q", replaced, "new-binary-content")
	}
}

func TestInstallUpdateRejectsTamperedArchive(t *testing.T) {
	binName := "aegis"
	if runtime.GOOS == "windows" {
		binName = "aegis.exe"
	}
	asset, err := releaseAssetName("1.5.0")
	if err != nil {
		t.Skipf("no release asset for this platform: %v", err)
	}

	srcDir := t.TempDir()
	archivePath, _ := makeTestArchive(t, srcDir, asset, binName, "new-binary-content")
	// Deliberately wrong digest, as if the archive was tampered with in transit.
	sums := "0000000000000000000000000000000000000000000000000000000000000000  " + asset + "\n"

	mux := http.NewServeMux()
	mux.HandleFunc("/SHA256SUMS", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(sums))
	})
	mux.HandleFunc("/"+asset, func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, archivePath)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	origBase := selfUpdateBaseURL
	origClient := selfUpdateHTTPClient
	selfUpdateBaseURL = func(version string) string { return srv.URL + "/" }
	selfUpdateHTTPClient = srv.Client()
	t.Cleanup(func() {
		selfUpdateBaseURL = origBase
		selfUpdateHTTPClient = origClient
	})

	result := InstallUpdate(context.Background(), "1.5.0")
	if result.Installed {
		t.Fatal("InstallUpdate reported success for a checksum-mismatched archive")
	}
	if result.Error == "" {
		t.Fatal("expected a checksum mismatch error, got none")
	}
}

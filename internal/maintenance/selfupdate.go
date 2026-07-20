package maintenance

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/andreipaciurca/aegis/internal/archive"
)

// InstallResult describes the outcome of an attempted self-update.
type InstallResult struct {
	Installed  bool   `json:"installed"`
	Version    string `json:"version,omitempty"`
	BinaryPath string `json:"binary_path,omitempty"`
	Error      string `json:"error,omitempty"`
	NeedsSudo  bool   `json:"needs_sudo,omitempty"`
}

// selfUpdateBaseURL and selfUpdateHTTPClient are package-level seams so
// tests can point downloads at a local httptest.Server instead of GitHub.
var (
	selfUpdateBaseURL = func(version string) string {
		return "https://github.com/andreipaciurca/aegis/releases/download/v" + version + "/"
	}
	selfUpdateHTTPClient = &http.Client{Timeout: 60 * time.Second}
)

// InstallUpdate downloads the release archive for the current OS/arch at
// the given version, verifies it against the release's published
// SHA256SUMS, extracts it, and atomically replaces the running binary on
// disk. It never restarts the process — the caller is still running the
// old binary in memory and should tell the user to relaunch aegis.
//
// This is only ever called from an explicit, user-triggered check (aegis
// update, the TUI's u key, the GUI's Update button) — never from an
// automatic background check — matching the rest of aegis's "no daemons,
// nothing happens without you asking" design.
func InstallUpdate(ctx context.Context, version string) InstallResult {
	if strings.TrimSpace(version) == "" {
		return InstallResult{Error: "no target version given"}
	}
	asset, err := releaseAssetName(version)
	if err != nil {
		return InstallResult{Error: err.Error()}
	}

	tmpDir, err := os.MkdirTemp("", "aegis-update-*")
	if err != nil {
		return InstallResult{Error: err.Error()}
	}
	defer os.RemoveAll(tmpDir)

	base := selfUpdateBaseURL(version)

	sumsPath := filepath.Join(tmpDir, "SHA256SUMS")
	if err := downloadTo(ctx, base+"SHA256SUMS", sumsPath); err != nil {
		return InstallResult{Error: "download checksums: " + err.Error()}
	}
	want, err := sha256ForAsset(sumsPath, asset)
	if err != nil {
		return InstallResult{Error: err.Error()}
	}

	archivePath := filepath.Join(tmpDir, asset)
	if err := downloadTo(ctx, base+asset, archivePath); err != nil {
		return InstallResult{Error: "download release: " + err.Error()}
	}
	got, err := sha256File(archivePath)
	if err != nil {
		return InstallResult{Error: err.Error()}
	}
	if !strings.EqualFold(got, want) {
		return InstallResult{Error: fmt.Sprintf("checksum mismatch for %s: got %s, want %s — refusing to install", asset, got, want)}
	}

	extractDir := filepath.Join(tmpDir, "extracted")
	if err := os.MkdirAll(extractDir, 0o755); err != nil {
		return InstallResult{Error: err.Error()}
	}
	if err := archive.Extract(archivePath, extractDir); err != nil {
		return InstallResult{Error: "extract: " + err.Error()}
	}

	binName := "aegis"
	if runtime.GOOS == "windows" {
		binName = "aegis.exe"
	}
	newBinary, err := findFile(extractDir, binName)
	if err != nil {
		return InstallResult{Error: err.Error()}
	}

	execPath, err := os.Executable()
	if err != nil {
		return InstallResult{Error: err.Error()}
	}
	if resolved, err := filepath.EvalSymlinks(execPath); err == nil {
		execPath = resolved
	}

	if err := replaceBinary(newBinary, execPath); err != nil {
		if errors.Is(err, os.ErrPermission) {
			return InstallResult{Error: err.Error(), NeedsSudo: true}
		}
		return InstallResult{Error: err.Error()}
	}

	return InstallResult{Installed: true, Version: version, BinaryPath: execPath}
}

func releaseAssetName(version string) (string, error) {
	var suffix string
	switch runtime.GOOS {
	case "darwin":
		switch runtime.GOARCH {
		case "arm64":
			suffix = "darwin-arm64.tar.gz"
		case "amd64":
			suffix = "darwin-amd64.tar.gz"
		}
	case "linux":
		switch runtime.GOARCH {
		case "arm64":
			suffix = "linux-arm64.tar.gz"
		case "amd64":
			suffix = "linux-amd64.tar.gz"
		}
	case "windows":
		if runtime.GOARCH == "amd64" {
			suffix = "windows-amd64.zip"
		}
	}
	if suffix == "" {
		return "", fmt.Errorf("no prebuilt aegis release for %s/%s; build from source instead", runtime.GOOS, runtime.GOARCH)
	}
	return fmt.Sprintf("aegis-%s-%s", version, suffix), nil
}

func downloadTo(ctx context.Context, url, path string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := selfUpdateHTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("HTTP %d for %s", resp.StatusCode, url)
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(f, resp.Body)
	closeErr := f.Close()
	if copyErr != nil {
		return copyErr
	}
	return closeErr
}

func sha256File(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// sha256ForAsset parses a `shasum -a 256` style SHA256SUMS file (lines of
// "<hex digest>  <filename>") and returns the digest for the given
// filename.
func sha256ForAsset(sumsPath, filename string) (string, error) {
	b, err := os.ReadFile(sumsPath)
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		if fields[len(fields)-1] == filename {
			return fields[0], nil
		}
	}
	return "", fmt.Errorf("%s not listed in SHA256SUMS", filename)
}

// findFile walks dir looking for a file named name, returning the first
// match. Release archives extract to a single nested directory, so a walk
// is simpler and more robust than assuming an exact depth.
func findFile(dir, name string) (string, error) {
	var found string
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if found != "" {
			return filepath.SkipDir
		}
		if !info.IsDir() && info.Name() == name {
			found = path
		}
		return nil
	})
	if err != nil {
		return "", err
	}
	if found == "" {
		return "", fmt.Errorf("%s not found in extracted release archive", name)
	}
	return found, nil
}

// replaceBinary atomically swaps newPath's content into targetPath. On
// Unix this is a same-directory rename, which is atomic and safe even
// while targetPath is the currently-running executable (the running
// process keeps its open file handle to the old inode; the next launch of
// that path picks up the new file). Windows won't allow overwriting or
// deleting a running .exe in place, so the running file is renamed aside
// first (renaming a running executable is allowed) and the new binary
// takes its name.
func replaceBinary(newPath, targetPath string) error {
	info, err := os.Stat(targetPath)
	if err != nil {
		return err
	}
	data, err := os.ReadFile(newPath)
	if err != nil {
		return err
	}
	dir := filepath.Dir(targetPath)
	tmp := filepath.Join(dir, ".aegis-update-tmp")
	if err := os.WriteFile(tmp, data, info.Mode()); err != nil {
		return err
	}

	if runtime.GOOS == "windows" {
		old := targetPath + ".old"
		_ = os.Remove(old) // best-effort cleanup left over from a previous update
		if err := os.Rename(targetPath, old); err != nil {
			_ = os.Remove(tmp)
			return err
		}
		if err := os.Rename(tmp, targetPath); err != nil {
			_ = os.Rename(old, targetPath) // best-effort rollback
			return err
		}
		return nil
	}

	if err := os.Rename(tmp, targetPath); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

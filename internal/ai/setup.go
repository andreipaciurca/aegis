package ai

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
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

type SetupOptions struct {
	DownloadLlama bool
}

type llamaRelease struct {
	TagName     string       `json:"tag_name"`
	HTMLURL     string       `json:"html_url"`
	PublishedAt string       `json:"published_at"`
	Assets      []llamaAsset `json:"assets"`
}

type llamaAsset struct {
	Name               string `json:"name"`
	Size               int64  `json:"size"`
	Digest             string `json:"digest"`
	BrowserDownloadURL string `json:"browser_download_url"`
}

type LlamaLatest struct {
	Tag           string `json:"tag"`
	PublishedAt   string `json:"published_at"`
	ReleaseURL    string `json:"release_url"`
	Asset         string `json:"asset"`
	AssetDigest   string `json:"asset_digest,omitempty"`
	AssetURL      string `json:"asset_url,omitempty"`
	UpdateCommand string `json:"update_command"`
}

func LatestLlama() (LlamaLatest, error) {
	rel, asset, err := latestLlamaAsset()
	if err != nil {
		return LlamaLatest{}, err
	}
	return LlamaLatest{
		Tag:           rel.TagName,
		PublishedAt:   rel.PublishedAt,
		ReleaseURL:    rel.HTMLURL,
		Asset:         asset.Name,
		AssetDigest:   asset.Digest,
		AssetURL:      asset.BrowserDownloadURL,
		UpdateCommand: "aegis ai setup --download-llama",
	}, nil
}

func RunSetup(opts SetupOptions) (SetupPlan, error) {
	plan, err := PlanSetup()
	if err != nil {
		return plan, err
	}
	rel, asset, err := latestLlamaAsset()
	if err != nil {
		plan.Notes = append(plan.Notes, "llama.cpp latest release lookup failed: "+err.Error())
		return plan, nil
	}
	plan.LlamaReleaseURL = rel.HTMLURL
	plan.Notes = append(plan.Notes, fmt.Sprintf("latest llama.cpp release: %s published %s", rel.TagName, rel.PublishedAt))
	plan.Commands = append(plan.Commands, "selected llama.cpp asset: "+asset.Name)

	if !opts.DownloadLlama {
		plan.Commands = append(plan.Commands, "aegis ai setup --download-llama")
		return plan, nil
	}
	target := filepath.Join(plan.InstallDir, rel.TagName)
	if err := os.MkdirAll(target, 0o755); err != nil {
		return plan, err
	}
	archivePath := filepath.Join(target, asset.Name)
	sum, err := downloadFile(asset.BrowserDownloadURL, archivePath)
	if err != nil {
		return plan, err
	}
	if asset.Digest != "" && strings.HasPrefix(asset.Digest, "sha256:") {
		want := strings.TrimPrefix(asset.Digest, "sha256:")
		if !strings.EqualFold(sum, want) {
			return plan, fmt.Errorf("llama.cpp asset checksum mismatch: got %s want %s", sum, want)
		}
	}
	if err := archive.Extract(archivePath, target); err != nil {
		return plan, err
	}
	plan.Commands = append(plan.Commands,
		"downloaded "+archivePath,
		"verified sha256 "+sum,
		"extracted to "+target,
		"find "+shellQuote(target)+" -name 'llama-server*' -o -name 'llama-cli*'",
	)
	return plan, nil
}

func latestLlamaAsset() (llamaRelease, llamaAsset, error) {
	client := http.Client{Timeout: 20 * time.Second}
	resp, err := client.Get("https://api.github.com/repos/ggml-org/llama.cpp/releases/latest")
	if err != nil {
		return llamaRelease{}, llamaAsset{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return llamaRelease{}, llamaAsset{}, fmt.Errorf("GitHub HTTP %d", resp.StatusCode)
	}
	var rel llamaRelease
	if err := json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(&rel); err != nil {
		return llamaRelease{}, llamaAsset{}, err
	}
	needle := llamaAssetNeedle()
	for _, a := range rel.Assets {
		if strings.Contains(a.Name, needle) {
			return rel, a, nil
		}
	}
	return rel, llamaAsset{}, fmt.Errorf("no release asset matched %q for %s/%s", needle, runtime.GOOS, runtime.GOARCH)
}

func llamaAssetNeedle() string {
	switch runtime.GOOS {
	case "darwin":
		if runtime.GOARCH == "arm64" {
			return "bin-macos-arm64.tar.gz"
		}
		return "bin-macos-x64.tar.gz"
	case "linux":
		if runtime.GOARCH == "arm64" {
			return "bin-ubuntu-arm64.tar.gz"
		}
		return "bin-ubuntu-x64.tar.gz"
	case "windows":
		if runtime.GOARCH == "arm64" {
			return "bin-win-cpu-arm64.zip"
		}
		return "bin-win-cpu-x64.zip"
	default:
		return "bin-ubuntu-x64.tar.gz"
	}
}

func downloadFile(url, path string) (string, error) {
	resp, err := http.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("download HTTP %d", resp.StatusCode)
	}
	tmp := path + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	_, copyErr := io.Copy(io.MultiWriter(f, h), resp.Body)
	closeErr := f.Close()
	if copyErr != nil {
		_ = os.Remove(tmp)
		return "", copyErr
	}
	if closeErr != nil {
		_ = os.Remove(tmp)
		return "", closeErr
	}
	if err := os.Rename(tmp, path); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

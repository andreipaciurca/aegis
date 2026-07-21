package ai

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"

	"github.com/andreipaciurca/aegis/internal/archive"
	"github.com/andreipaciurca/aegis/internal/signatures"
)

type SetupOptions struct {
	DownloadLlama bool
	Configure     bool
	StartServer   bool
	Wait          time.Duration
	Progress      func(SetupProgress)
}

// SetupProgress describes a user-visible step in the local AI bootstrap.
// Download counts are populated only while a release archive is transferring.
type SetupProgress struct {
	Stage          string `json:"stage"`
	Message        string `json:"message"`
	CompletedBytes int64  `json:"completed_bytes,omitempty"`
	TotalBytes     int64  `json:"total_bytes,omitempty"`
}

func reportSetupProgress(opts SetupOptions, progress SetupProgress) {
	if opts.Progress != nil {
		opts.Progress(progress)
	}
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
	if opts.StartServer {
		opts.DownloadLlama = true
		opts.Configure = true
	}
	reportSetupProgress(opts, SetupProgress{Stage: "prepare", Message: "Preparing the local AI install directories"})
	plan, err := PlanSetup()
	if err != nil {
		return plan, err
	}
	reportSetupProgress(opts, SetupProgress{Stage: "discover", Message: "Checking the latest llama.cpp release"})
	rel, asset, err := latestLlamaAsset()
	if err != nil {
		plan.Notes = append(plan.Notes, "llama.cpp latest release lookup failed: "+err.Error())
		if opts.Configure {
			if err := configureDefaultServer(&plan); err != nil {
				return plan, err
			}
		}
		if opts.StartServer {
			reportSetupProgress(opts, SetupProgress{Stage: "start", Message: "Starting the installed llama.cpp server"})
			start, startErr := StartManagedServer(ManagedServerOptions{
				InstallDir: plan.InstallDir,
				ModelRef:   DefaultModelRef,
				Wait:       opts.Wait,
				Progress:   opts.Progress,
			})
			plan.Run = &start
			if startErr != nil {
				return plan, startErr
			}
		}
		return plan, nil
	}
	plan.LlamaReleaseURL = rel.HTMLURL
	plan.Notes = append(plan.Notes, fmt.Sprintf("latest llama.cpp release: %s published %s", rel.TagName, rel.PublishedAt))
	plan.Commands = append(plan.Commands, "selected llama.cpp asset: "+asset.Name)

	if !opts.DownloadLlama {
		plan.Commands = append(plan.Commands, "aegis ai setup --download-llama")
		return plan, nil
	}
	reportSetupProgress(opts, SetupProgress{Stage: "download", Message: "Downloading " + asset.Name, TotalBytes: asset.Size})
	target := filepath.Join(plan.InstallDir, rel.TagName)
	if err := os.MkdirAll(target, 0o755); err != nil {
		return plan, err
	}
	archivePath := filepath.Join(target, asset.Name)
	sum, err := downloadFile(asset.BrowserDownloadURL, archivePath, func(done, total int64) {
		reportSetupProgress(opts, SetupProgress{
			Stage:          "download",
			Message:        "Downloading " + asset.Name,
			CompletedBytes: done,
			TotalBytes:     total,
		})
	})
	if err != nil {
		return plan, err
	}
	reportSetupProgress(opts, SetupProgress{Stage: "verify", Message: "Verifying the llama.cpp download checksum"})
	if asset.Digest != "" && strings.HasPrefix(asset.Digest, "sha256:") {
		want := strings.TrimPrefix(asset.Digest, "sha256:")
		if !strings.EqualFold(sum, want) {
			return plan, fmt.Errorf("llama.cpp asset checksum mismatch: got %s want %s", sum, want)
		}
	}
	reportSetupProgress(opts, SetupProgress{Stage: "extract", Message: "Extracting llama.cpp"})
	if err := archive.Extract(archivePath, target); err != nil {
		return plan, err
	}
	serverPath, serverErr := findLlamaBinary(target, "llama-server")
	if serverErr == nil {
		plan.LlamaServer = serverPath
	}
	plan.Commands = append(plan.Commands,
		"downloaded "+archivePath,
		"verified sha256 "+sum,
		"extracted to "+target,
		"find "+shellQuote(target)+" -name 'llama-server*' -o -name 'llama-cli*'",
	)
	if opts.Configure {
		reportSetupProgress(opts, SetupProgress{Stage: "configure", Message: "Configuring Aegis to use the local server"})
		if err := configureDefaultServer(&plan); err != nil {
			return plan, err
		}
	}
	if opts.StartServer {
		reportSetupProgress(opts, SetupProgress{Stage: "start", Message: "Starting llama-server and preparing Gemma"})
		start, err := StartManagedServer(ManagedServerOptions{
			InstallDir: plan.InstallDir,
			ModelRef:   DefaultModelRef,
			Wait:       opts.Wait,
			Progress:   opts.Progress,
		})
		plan.Run = &start
		if err != nil {
			return plan, err
		}
		plan.Commands = append(plan.Commands, "started llama-server pid "+fmt.Sprint(start.PID))
	}
	reportSetupProgress(opts, SetupProgress{Stage: "complete", Message: "Local AI setup is complete"})
	return plan, nil
}

func configureDefaultServer(plan *SetupPlan) error {
	cfg := DefaultConfig()
	cfg.Backend = BackendServer
	cfg.Endpoint = DefaultURL
	if err := Save(cfg); err != nil {
		return err
	}
	plan.Configured = true
	plan.Commands = append(plan.Commands, "configured Aegis AI endpoint: "+DefaultURL)
	return nil
}

type ManagedServerOptions struct {
	InstallDir string
	ModelRef   string
	Wait       time.Duration
	Progress   func(SetupProgress)
}

type ManagedServerResult struct {
	AlreadyRunning bool   `json:"already_running"`
	Started        bool   `json:"started"`
	Ready          bool   `json:"ready"`
	PID            int    `json:"pid,omitempty"`
	Command        string `json:"command"`
	LogFile        string `json:"log_file,omitempty"`
	Endpoint       string `json:"endpoint"`
	ModelRef       string `json:"model_ref"`
	Message        string `json:"message"`
}

func StartManagedServer(opts ManagedServerOptions) (ManagedServerResult, error) {
	if opts.ModelRef == "" {
		opts.ModelRef = DefaultModelRef
	}
	if opts.Wait <= 0 {
		opts.Wait = 15 * time.Second
	}
	cfg := DefaultConfig()
	cfg.Backend = BackendServer
	cfg.Endpoint = DefaultURL
	if st := Check(cfg); st.ServerReady {
		if opts.Progress != nil {
			opts.Progress(SetupProgress{Stage: "ready", Message: "llama-server is already ready"})
		}
		return ManagedServerResult{
			AlreadyRunning: true,
			Ready:          true,
			Endpoint:       DefaultURL,
			ModelRef:       opts.ModelRef,
			Message:        "llama-server is already ready",
		}, nil
	}
	server, err := resolveLlamaServer(opts.InstallDir)
	if err != nil {
		return ManagedServerResult{}, err
	}
	if err := ensureLlamaRuntimeLinks(server); err != nil {
		return ManagedServerResult{}, err
	}
	dir, err := signatures.Dir()
	if err != nil {
		return ManagedServerResult{}, err
	}
	logPath := filepath.Join(dir, "llama-server.log")
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return ManagedServerResult{}, err
	}
	cmd := exec.Command(server,
		"-hf", opts.ModelRef,
		"--host", "127.0.0.1",
		"--port", "8080",
		"--cors-origins", "localhost",
		"--no-cors-credentials",
	)
	cmd.Dir = filepath.Dir(server)
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	if err := cmd.Start(); err != nil {
		_ = logFile.Close()
		return ManagedServerResult{}, err
	}
	if opts.Progress != nil {
		opts.Progress(SetupProgress{Stage: "waiting", Message: "llama-server started; waiting for Gemma to download and become ready"})
	}
	res := ManagedServerResult{
		Started:  true,
		PID:      cmd.Process.Pid,
		Command:  strings.Join(append([]string{server}, cmd.Args[1:]...), " "),
		LogFile:  logPath,
		Endpoint: DefaultURL,
		ModelRef: opts.ModelRef,
		Message:  "llama-server started; first run may download the model and take a few minutes",
	}
	exited := make(chan error, 1)
	go func() {
		exited <- cmd.Wait()
		_ = logFile.Close()
	}()
	deadline := time.Now().Add(opts.Wait)
	for attempt := 1; time.Now().Before(deadline); attempt++ {
		select {
		case exitErr := <-exited:
			if exitErr == nil {
				exitErr = fmt.Errorf("exited without reporting readiness")
			}
			return ManagedServerResult{}, fmt.Errorf("llama-server exited before becoming ready; inspect %s: %w", logPath, exitErr)
		default:
		}
		if st := Check(cfg); st.ServerReady {
			res.Ready = true
			res.Message = "llama-server is ready"
			if opts.Progress != nil {
				opts.Progress(SetupProgress{Stage: "ready", Message: res.Message})
			}
			return res, nil
		}
		if opts.Progress != nil && attempt%4 == 0 {
			opts.Progress(SetupProgress{Stage: "waiting", Message: "Gemma is still downloading or loading; checking the local server again"})
		}
		time.Sleep(700 * time.Millisecond)
	}
	if opts.Progress != nil {
		opts.Progress(SetupProgress{Stage: "waiting", Message: "llama-server is running; Gemma is still downloading or loading"})
	}
	select {
	case exitErr := <-exited:
		if exitErr == nil {
			exitErr = fmt.Errorf("exited without reporting readiness")
		}
		return ManagedServerResult{}, fmt.Errorf("llama-server exited before becoming ready; inspect %s: %w", logPath, exitErr)
	default:
	}
	return res, nil
}

var versionedDylib = regexp.MustCompile(`^(lib.+?)\.([0-9]+)\.[0-9.]+\.dylib$`)
var versionedSharedObject = regexp.MustCompile(`^(lib.+?\.so)\.([0-9]+)(?:\.[0-9]+)*$`)

// ensureLlamaRuntimeLinks repairs macOS and Linux compatibility aliases that
// llama.cpp releases ship as tar symlinks. Older Aegis versions did not
// extract those links, leaving otherwise valid installations unable to start.
func ensureLlamaRuntimeLinks(server string) error {
	dir := filepath.Dir(server)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	var pattern *regexp.Regexp
	switch runtime.GOOS {
	case "darwin":
		pattern = versionedDylib
	case "linux":
		pattern = versionedSharedObject
	default:
		return nil
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		match := pattern.FindStringSubmatch(entry.Name())
		if match == nil {
			continue
		}
		extension := ".dylib"
		if runtime.GOOS == "linux" {
			extension = ""
		}
		alias := filepath.Join(dir, match[1]+"."+match[2]+extension)
		if _, err := os.Lstat(alias); err == nil {
			continue
		} else if !os.IsNotExist(err) {
			return err
		}
		if err := os.Symlink(entry.Name(), alias); err != nil {
			return fmt.Errorf("create llama.cpp runtime link %s: %w", alias, err)
		}
	}
	return nil
}

func resolveLlamaServer(installDir string) (string, error) {
	if p, err := exec.LookPath("llama-server"); err == nil {
		return p, nil
	}
	if installDir != "" {
		if p, err := findLlamaBinary(installDir, "llama-server"); err == nil {
			return p, nil
		}
	}
	dir, err := signatures.Dir()
	if err == nil {
		if p, err := findLlamaBinary(filepath.Join(dir, "llama.cpp"), "llama-server"); err == nil {
			return p, nil
		}
	}
	return "", fmt.Errorf("llama-server not found; run `aegis ai setup --download-llama` first")
}

func findLlamaBinary(root, name string) (string, error) {
	want := name
	if runtime.GOOS == "windows" {
		want += ".exe"
	}
	var found string
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || found != "" {
			return err
		}
		base := strings.ToLower(d.Name())
		if base == strings.ToLower(want) {
			found = path
			return filepath.SkipAll
		}
		return nil
	})
	if err != nil {
		return "", err
	}
	if found == "" {
		return "", fmt.Errorf("%s not found under %s", want, root)
	}
	return found, nil
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

func downloadFile(url, path string, progress func(done, total int64)) (string, error) {
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
	var copied int64
	reader := io.TeeReader(resp.Body, writerFunc(func(p []byte) (int, error) {
		copied += int64(len(p))
		if progress != nil {
			progress(copied, resp.ContentLength)
		}
		return len(p), nil
	}))
	_, copyErr := io.Copy(io.MultiWriter(f, h), reader)
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

type writerFunc func([]byte) (int, error)

func (f writerFunc) Write(p []byte) (int, error) { return f(p) }

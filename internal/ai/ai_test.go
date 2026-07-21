package ai

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestNormalizeDefaults(t *testing.T) {
	cfg := Config{}
	normalize(&cfg)
	if cfg.Backend != BackendServer {
		t.Errorf("expected default backend %q, got %q", BackendServer, cfg.Backend)
	}
	if cfg.Endpoint != DefaultURL {
		t.Errorf("expected default endpoint %q, got %q", DefaultURL, cfg.Endpoint)
	}
	if cfg.Command != "llama-cli" {
		t.Errorf("expected default command llama-cli, got %q", cfg.Command)
	}
	if cfg.MaxExcerptBytes != 2048 {
		t.Errorf("expected default excerpt cap 2048, got %d", cfg.MaxExcerptBytes)
	}
	if cfg.PrivacyMode != "metadata" {
		t.Errorf("expected default privacy mode metadata, got %q", cfg.PrivacyMode)
	}
}

func TestDownloadFileReportsProgress(t *testing.T) {
	payload := strings.Repeat("aegis", 16*1024)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "81920")
		_, _ = w.Write([]byte(payload))
	}))
	defer server.Close()

	var completed, total int64
	target := filepath.Join(t.TempDir(), "llama.cpp.tar.gz")
	if _, err := downloadFile(server.URL, target, func(done, size int64) {
		completed, total = done, size
	}); err != nil {
		t.Fatalf("downloadFile: %v", err)
	}
	if completed != int64(len(payload)) || total != int64(len(payload)) {
		t.Fatalf("progress = %d/%d, want %d/%d", completed, total, len(payload), len(payload))
	}
	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("read downloaded file: %v", err)
	}
	if string(got) != payload {
		t.Fatal("downloaded file does not match response body")
	}
}

func TestNormalizeRemoteBackendDefaults(t *testing.T) {
	cfg := Config{Backend: BackendOpenAICompatible}
	normalize(&cfg)
	if cfg.Endpoint != DefaultRemoteURL {
		t.Errorf("expected remote endpoint %q, got %q", DefaultRemoteURL, cfg.Endpoint)
	}
	if cfg.APIKeyEnv != DefaultRemoteKeyEnv {
		t.Errorf("expected default api key env %q, got %q", DefaultRemoteKeyEnv, cfg.APIKeyEnv)
	}
	if cfg.Model == "" {
		t.Error("expected a default remote model to be set")
	}
}

func TestNormalizePreservesExplicitValues(t *testing.T) {
	cfg := Config{Backend: BackendCLI, Command: "my-llama", MaxExcerptBytes: 500, PrivacyMode: "excerpt"}
	normalize(&cfg)
	if cfg.Command != "my-llama" {
		t.Errorf("normalize overwrote an explicit command: got %q", cfg.Command)
	}
	if cfg.MaxExcerptBytes != 500 {
		t.Errorf("normalize overwrote an explicit excerpt cap: got %d", cfg.MaxExcerptBytes)
	}
	if cfg.PrivacyMode != "excerpt" {
		t.Errorf("normalize overwrote an explicit privacy mode: got %q", cfg.PrivacyMode)
	}
}

func TestLoadSaveRoundTrip(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))

	// No config on disk yet: Load should hand back defaults, not an error.
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load with no config file: %v", err)
	}
	if cfg.Backend != BackendServer {
		t.Fatalf("expected default backend, got %q", cfg.Backend)
	}

	cfg.Backend = BackendCLI
	cfg.ModelPath = "/models/test.gguf"
	if err := Save(cfg); err != nil {
		t.Fatalf("Save: %v", err)
	}

	reloaded, err := Load()
	if err != nil {
		t.Fatalf("Load after Save: %v", err)
	}
	if reloaded.Backend != BackendCLI || reloaded.ModelPath != "/models/test.gguf" {
		t.Fatalf("round trip mismatch: got %+v", reloaded)
	}
}

func TestAddNoteAndNotesRoundTrip(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))

	if err := AddNote("port 5000 is expected on this dev machine"); err != nil {
		t.Fatalf("AddNote: %v", err)
	}
	if err := AddNote("  "); err != nil { // blank notes are silently ignored
		t.Fatalf("AddNote blank: %v", err)
	}
	notes, err := Notes()
	if err != nil {
		t.Fatalf("Notes: %v", err)
	}
	if len(notes) != 1 {
		t.Fatalf("expected 1 note (blank one skipped), got %d: %+v", len(notes), notes)
	}
	if notes[0].Text != "port 5000 is expected on this dev machine" {
		t.Fatalf("unexpected note text: %q", notes[0].Text)
	}

	prompt := PromptWithNotes("system prompt")
	if prompt == "system prompt" {
		t.Fatal("expected PromptWithNotes to append remembered context")
	}
}

func TestPlanSetupIsPortableAndActionable(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))

	plan, err := PlanSetup()
	if err != nil {
		t.Fatalf("PlanSetup: %v", err)
	}
	if !plan.Idempotent {
		t.Fatal("setup plan should explicitly report that commands are idempotent")
	}
	if plan.ModelDir == "" || plan.InstallDir == "" || plan.ModelFile == "" {
		t.Fatalf("expected resolved install/model paths, got %+v", plan)
	}
	if len(plan.ModelSources) < 3 {
		t.Fatalf("expected recommended model plus fallbacks, got %+v", plan.ModelSources)
	}
	if len(plan.Sections) < 5 {
		t.Fatalf("expected step-by-step sections, got %d", len(plan.Sections))
	}

	blob, err := json.Marshal(plan.Sections)
	if err != nil {
		t.Fatalf("marshal sections: %v", err)
	}
	text := string(blob)
	for _, want := range []string{
		"AEGIS_MODEL_DIR",
		"%LOCALAPPDATA%",
		"$env:LOCALAPPDATA",
		"llama-server -hf",
		"aegis ai install",
		"aegis ai setup --download-llama",
		"aegis ai config --backend llamacpp-server",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("setup plan missing %q in sections: %s", want, text)
		}
	}
	if strings.Contains(text, home) || strings.Contains(text, "/Users/") {
		t.Fatalf("copy-paste commands should avoid hardcoded user paths: %s", text)
	}
}

func TestEnsureLlamaRuntimeLinks(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("macOS dynamic library compatibility links only")
	}
	dir := t.TempDir()
	server := filepath.Join(dir, "llama-server")
	if err := os.WriteFile(server, []byte("server"), 0o755); err != nil {
		t.Fatal(err)
	}
	versioned := "libllama-common.0.0.10075.dylib"
	if err := os.WriteFile(filepath.Join(dir, versioned), []byte("library"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := ensureLlamaRuntimeLinks(server); err != nil {
		t.Fatalf("ensureLlamaRuntimeLinks: %v", err)
	}
	alias := filepath.Join(dir, "libllama-common.0.dylib")
	got, err := os.Readlink(alias)
	if err != nil {
		t.Fatalf("read repaired alias: %v", err)
	}
	if got != versioned {
		t.Fatalf("alias target = %q, want %q", got, versioned)
	}
}

func TestCheckServerUsesModelMetadataEndpoint(t *testing.T) {
	var calls int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Method != http.MethodGet || r.URL.Path != "/v1/models" {
			t.Errorf("readiness request = %s %s, want GET /v1/models", r.Method, r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	status := Check(Config{Backend: BackendServer, Endpoint: server.URL + "/v1/chat/completions"})
	if !status.ServerReady || status.Message != "ready" {
		t.Fatalf("server status = %+v, want healthy server", status)
	}
	if calls != 1 {
		t.Fatalf("health calls = %d, want 1", calls)
	}
}

func TestCheckServerDoesNotTreatCLIAsServerReadiness(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	status := Check(Config{Backend: BackendServer, Endpoint: "http://127.0.0.1:1/v1/chat/completions"})
	if status.ServerReady || status.CLIReady {
		t.Fatalf("unreachable server should not be ready: %+v", status)
	}
	if !strings.Contains(status.Message, "server unavailable") {
		t.Fatalf("unexpected status message: %q", status.Message)
	}
}

func TestManagedServerArgsUseCompactProfile(t *testing.T) {
	args := strings.Join(managedServerArgs(DefaultModelRef), " ")
	for _, want := range []string{
		"-hf " + DefaultModelRef,
		"--no-mmproj",
		"--ctx-size 2048",
		"--batch-size 256",
		"--ubatch-size 128",
		"--parallel 1",
		"--n-gpu-layers 0",
		"--no-kv-offload",
		"--fit-target 2048",
	} {
		if !strings.Contains(args, want) {
			t.Errorf("managed server arguments missing %q: %s", want, args)
		}
	}
}

func TestParseListenerPIDAcrossSupportedPlatforms(t *testing.T) {
	tests := []struct {
		name   string
		goos   string
		output string
		want   int
	}{
		{name: "macOS lsof", goos: "unix", output: "4312\n", want: 4312},
		{name: "Linux ss", goos: "linux", output: "LISTEN 0 4096 127.0.0.1:8080 0.0.0.0:* users:((\"llama-server\",pid=912,fd=6))\n", want: 912},
		{name: "Windows netstat", goos: "windows", output: "  TCP    127.0.0.1:8080       0.0.0.0:0              LISTENING       2468\r\n", want: 2468},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseListenerPID(tt.output, tt.goos)
			if err != nil || got != tt.want {
				t.Fatalf("parseListenerPID(%q, %q) = %d, %v; want %d, nil", tt.output, tt.goos, got, err, tt.want)
			}
		})
	}
}

func TestParseListenerPIDRejectsUnrelatedOutput(t *testing.T) {
	if _, err := parseListenerPID("LISTEN 0 4096 127.0.0.1:9090 0.0.0.0:*", "linux"); err == nil {
		t.Fatal("expected unrelated listener output to be rejected")
	}
	if _, err := parseListenerPID("  TCP    0.0.0.0:8080         0.0.0.0:0              LISTENING       2468\r\n", "windows"); err == nil {
		t.Fatal("expected public Windows listener output to be rejected")
	}
}

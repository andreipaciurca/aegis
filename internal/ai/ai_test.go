package ai

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
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

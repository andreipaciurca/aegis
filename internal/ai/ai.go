// Package ai integrates optional local LLM analysis. It is advisory only:
// detections remain rule/signature driven, and the model never performs
// destructive actions.
package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/andreipaciurca/aegis/internal/signatures"
)

const (
	BackendServer           = "llamacpp-server"
	BackendCLI              = "llamacpp-cli"
	BackendOpenAICompatible = "openai-compatible"
	DefaultURL              = "http://127.0.0.1:8080/v1/chat/completions"
	DefaultRemoteURL        = "https://api.openai.com/v1/chat/completions"
	DefaultRemoteKeyEnv     = "OPENAI_API_KEY"
)

type Config struct {
	Backend         string `json:"backend"`
	Endpoint        string `json:"endpoint,omitempty"`
	Model           string `json:"model,omitempty"`
	ModelPath       string `json:"model_path,omitempty"`
	Command         string `json:"command,omitempty"`
	APIKeyEnv       string `json:"api_key_env,omitempty"`
	MaxExcerptBytes int    `json:"max_excerpt_bytes"`
	PrivacyMode     string `json:"privacy_mode"`
}

type Status struct {
	Config      Config `json:"config"`
	ServerReady bool   `json:"server_ready"`
	CLIReady    bool   `json:"cli_ready"`
	RemoteReady bool   `json:"remote_ready"`
	Message     string `json:"message"`
}

type SetupPlan struct {
	InstallDir      string   `json:"install_dir"`
	ModelDir        string   `json:"model_dir"`
	Recommended     string   `json:"recommended_model"`
	LlamaReleaseURL string   `json:"llama_release_url"`
	Notes           []string `json:"notes"`
	Commands        []string `json:"commands"`
}

type Request struct {
	System string `json:"system"`
	Prompt string `json:"prompt"`
}

type Note struct {
	When time.Time `json:"when"`
	Text string    `json:"text"`
}

func DefaultConfig() Config {
	return Config{
		Backend:         BackendServer,
		Endpoint:        DefaultURL,
		Command:         "llama-cli",
		MaxExcerptBytes: 2048,
		PrivacyMode:     "metadata",
	}
}

func Load() (Config, error) {
	cfg := DefaultConfig()
	path, err := configPath()
	if err != nil {
		return cfg, err
	}
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return cfg, nil
	}
	if err != nil {
		return cfg, err
	}
	if err := json.Unmarshal(b, &cfg); err != nil {
		return cfg, err
	}
	normalize(&cfg)
	return cfg, nil
}

func Save(cfg Config) error {
	normalize(&cfg)
	path, err := configPath()
	if err != nil {
		return err
	}
	b, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o600)
}

func Check(cfg Config) Status {
	normalize(&cfg)
	s := Status{Config: cfg}
	if cfg.Backend == BackendOpenAICompatible {
		if cfg.Endpoint == "" {
			s.Message = "remote endpoint is not configured"
			return s
		}
		if cfg.Model == "" {
			s.Message = "remote model is not configured"
			return s
		}
		if cfg.APIKeyEnv == "" {
			s.Message = "api_key_env is not configured"
			return s
		}
		if os.Getenv(cfg.APIKeyEnv) == "" {
			s.Message = cfg.APIKeyEnv + " is not set"
			return s
		}
		s.RemoteReady = true
		s.Message = "ready"
		return s
	}
	if cfg.Endpoint != "" {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		_, err := generateServer(ctx, cfg, Request{Prompt: "Reply with: ok"})
		cancel()
		s.ServerReady = err == nil
		if err != nil {
			s.Message = "server unavailable: " + err.Error()
		}
	}
	cmd := cfg.Command
	if cmd == "" {
		cmd = "llama-cli"
	}
	if _, err := exec.LookPath(cmd); err == nil {
		s.CLIReady = true
	} else if s.Message == "" {
		s.Message = "llama-cli not found"
	}
	if s.ServerReady || s.CLIReady {
		s.Message = "ready"
	}
	return s
}

func Generate(ctx context.Context, cfg Config, req Request) (string, error) {
	normalize(&cfg)
	switch cfg.Backend {
	case BackendServer:
		return generateServer(ctx, cfg, req)
	case BackendCLI:
		return generateCLI(ctx, cfg, req)
	case BackendOpenAICompatible:
		return generateServer(ctx, cfg, req)
	default:
		return "", fmt.Errorf("unsupported AI backend %q", cfg.Backend)
	}
}

func SecuritySystemPrompt() string {
	return `You are Aegis Local Analyst, a defensive security assistant running fully locally.
Your job is to explain Aegis findings, estimate false-positive likelihood, and suggest safe next steps.
Rules:
- Treat signatures, ransomware canary tampering, and CISA KEV matches as high confidence.
- Do not claim a finding is clean; use "likely false positive" only with reasons.
- Do not suggest deletion as the first response; prefer quarantine, isolation, updating, or manual review.
- Do not ask to upload private files.`
}

func AddNote(text string) error {
	text = strings.TrimSpace(text)
	if text == "" {
		return nil
	}
	notes, err := Notes()
	if err != nil {
		return err
	}
	notes = append(notes, Note{When: time.Now(), Text: text})
	if len(notes) > 100 {
		notes = notes[len(notes)-100:]
	}
	b, err := json.MarshalIndent(notes, "", "  ")
	if err != nil {
		return err
	}
	path, err := notesPath()
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o600)
}

func Notes() ([]Note, error) {
	path, err := notesPath()
	if err != nil {
		return nil, err
	}
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var notes []Note
	if err := json.Unmarshal(b, &notes); err != nil {
		return nil, err
	}
	return notes, nil
}

func PromptWithNotes(system string) string {
	notes, err := Notes()
	if err != nil || len(notes) == 0 {
		return system
	}
	var b strings.Builder
	b.WriteString(system)
	b.WriteString("\n\nUser-approved local context notes:\n")
	start := 0
	if len(notes) > 20 {
		start = len(notes) - 20
	}
	for _, note := range notes[start:] {
		b.WriteString("- ")
		b.WriteString(note.Text)
		b.WriteByte('\n')
	}
	return b.String()
}

func PlanSetup() (SetupPlan, error) {
	dir, err := signatures.Dir()
	if err != nil {
		return SetupPlan{}, err
	}
	modelDir := filepath.Join(dir, "models")
	installDir := filepath.Join(dir, "llama.cpp")
	homeModel := filepath.Join(modelDir, "gemma.gguf")
	return SetupPlan{
		InstallDir:      installDir,
		ModelDir:        modelDir,
		Recommended:     "Gemma 3 or Gemma 2 instruction-tuned GGUF, 2B-4B, Q4_K_M quantization",
		LlamaReleaseURL: "https://api.github.com/repos/ggml-org/llama.cpp/releases/latest",
		Notes: []string{
			"aegis queries llama.cpp releases at setup time so it can use the current build instead of a hardcoded tag",
			"model weights are separate; download GGUF files only from sources you trust and pin checksums for operational use",
			"local llama.cpp remains the default privacy-preserving path; remote API backends are opt-in",
		},
		Commands: []string{
			"mkdir -p " + shellQuote(modelDir),
			"download a Gemma GGUF model to " + shellQuote(homeModel),
			"llama-server -m " + shellQuote(homeModel) + " --host 127.0.0.1 --port 8080",
			"aegis ai config --backend llamacpp-server --endpoint " + DefaultURL,
			"aegis ai status",
		},
	}, nil
}

func configPath() (string, error) {
	dir, err := signatures.Dir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "ai.json"), nil
}

func notesPath() (string, error) {
	dir, err := signatures.Dir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "ai_context.json"), nil
}

func normalize(cfg *Config) {
	if cfg.Backend == "" {
		cfg.Backend = BackendServer
	}
	if cfg.Backend == BackendOpenAICompatible && (cfg.Endpoint == "" || cfg.Endpoint == DefaultURL) {
		cfg.Endpoint = DefaultRemoteURL
	}
	if cfg.Endpoint == "" {
		cfg.Endpoint = DefaultURL
	}
	if cfg.Backend == BackendOpenAICompatible && cfg.APIKeyEnv == "" {
		cfg.APIKeyEnv = DefaultRemoteKeyEnv
	}
	if cfg.Backend == BackendOpenAICompatible && cfg.Model == "" {
		cfg.Model = "gpt-5-mini"
	}
	if cfg.Command == "" {
		cfg.Command = "llama-cli"
	}
	if cfg.MaxExcerptBytes <= 0 {
		cfg.MaxExcerptBytes = 2048
	}
	if cfg.PrivacyMode == "" {
		cfg.PrivacyMode = "metadata"
	}
}

func generateServer(ctx context.Context, cfg Config, req Request) (string, error) {
	model := cfg.Model
	if model == "" {
		model = "local"
	}
	body := map[string]any{
		"model":       model,
		"temperature": 0.2,
		"messages": []map[string]string{
			{"role": "system", "content": req.System},
			{"role": "user", "content": req.Prompt},
		},
	}
	b, err := json.Marshal(body)
	if err != nil {
		return "", err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.Endpoint, bytes.NewReader(b))
	if err != nil {
		return "", err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if cfg.Backend == BackendOpenAICompatible {
		key := os.Getenv(cfg.APIKeyEnv)
		if key == "" {
			return "", fmt.Errorf("%s is not set", cfg.APIKeyEnv)
		}
		httpReq.Header.Set("Authorization", "Bearer "+key)
	}
	resp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(data)))
	}
	var out struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(data, &out); err != nil {
		return "", err
	}
	if len(out.Choices) == 0 {
		return "", errors.New("no model response")
	}
	return strings.TrimSpace(out.Choices[0].Message.Content), nil
}

func shellQuote(s string) string {
	if s == "" {
		return "''"
	}
	return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'"
}

func generateCLI(ctx context.Context, cfg Config, req Request) (string, error) {
	if cfg.ModelPath == "" {
		return "", errors.New("model_path is required for llamacpp-cli backend")
	}
	prompt := req.System + "\n\nUser:\n" + req.Prompt + "\n\nAssistant:\n"
	args := []string{"-m", cfg.ModelPath, "-p", prompt, "-n", "512", "--temp", "0.2"}
	cmd := exec.CommandContext(ctx, cfg.Command, args...)
	out, err := cmd.CombinedOutput()
	if ctx.Err() == context.DeadlineExceeded {
		return "", ctx.Err()
	}
	if err != nil {
		return "", fmt.Errorf("%v: %s", err, strings.TrimSpace(string(out)))
	}
	return strings.TrimSpace(string(out)), nil
}

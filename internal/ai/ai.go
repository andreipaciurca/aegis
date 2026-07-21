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
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
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
	// DefaultModelRef deliberately favors responsive local diagnostics on
	// 8 GB laptops. Larger models remain documented as opt-in alternatives.
	DefaultModelRef = "ggml-org/gemma-3-1b-it-GGUF:Q4_K_M"
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
	InstallDir      string               `json:"install_dir"`
	ModelDir        string               `json:"model_dir"`
	ModelFile       string               `json:"model_file"`
	Recommended     string               `json:"recommended_model"`
	LlamaReleaseURL string               `json:"llama_release_url"`
	ModelSources    []ModelSource        `json:"model_sources"`
	Sections        []SetupSection       `json:"sections"`
	Notes           []string             `json:"notes"`
	Commands        []string             `json:"commands"`
	LegacyCommands  []string             `json:"legacy_commands,omitempty"`
	Idempotent      bool                 `json:"idempotent"`
	Configured      bool                 `json:"configured"`
	LlamaServer     string               `json:"llama_server,omitempty"`
	Run             *ManagedServerResult `json:"run,omitempty"`
}

type ModelSource struct {
	Name     string `json:"name"`
	URL      string `json:"url"`
	Ref      string `json:"ref"`
	Filename string `json:"filename,omitempty"`
	Note     string `json:"note"`
}

type SetupSection struct {
	Title    string         `json:"title"`
	Why      string         `json:"why"`
	Commands []SetupCommand `json:"commands"`
}

type SetupCommand struct {
	Label      string `json:"label"`
	Unix       string `json:"unix,omitempty"`
	PowerShell string `json:"powershell,omitempty"`
	Cmd        string `json:"cmd,omitempty"`
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
		err := checkServerHealth(ctx, cfg.Endpoint)
		cancel()
		s.ServerReady = err == nil
		if err != nil {
			s.Message = "server unavailable: " + err.Error()
		}
	}
	if cfg.Backend == BackendCLI {
		cmd := cfg.Command
		if cmd == "" {
			cmd = "llama-cli"
		}
		if _, err := exec.LookPath(cmd); err == nil {
			s.CLIReady = true
		} else if s.Message == "" {
			s.Message = "llama-cli not found"
		}
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
	modelSources := []ModelSource{
		{
			Name:     "Gemma 3 1B instruct GGUF (compact default)",
			URL:      "https://huggingface.co/ggml-org/gemma-3-1b-it-GGUF",
			Ref:      DefaultModelRef,
			Filename: "gemma-3-1b-it-Q4_K_M.gguf",
			Note:     "Default for 8 GB laptops: approximately 806 MB, text-only, and fast enough for Aegis diagnostics.",
		},
		{
			Name:     "Gemma 3 4B instruct GGUF",
			URL:      "https://huggingface.co/ggml-org/gemma-3-4b-it-GGUF",
			Ref:      "ggml-org/gemma-3-4b-it-GGUF:Q4_K_M",
			Filename: "gemma-3-4b-it-Q4_K_M.gguf",
			Note:     "Higher-quality option for systems with at least 16 GB of unified or system memory.",
		},
		{
			Name:     "Gemma 4 E4B instruct GGUF",
			URL:      "https://huggingface.co/lmstudio-community/gemma-4-E4B-it-GGUF",
			Ref:      "lmstudio-community/gemma-4-E4B-it-GGUF:Q4_K_M",
			Filename: "gemma-4-E4B-it-Q4_K_M.gguf",
			Note:     "Large multimodal option. Do not use on 8 GB machines; it can exhaust unified GPU memory.",
		},
	}
	sections := []SetupSection{
		{
			Title: "0. One-command default",
			Why:   "Recommended for most users. It reuses an installed current llama.cpp build and cached model when available, configures Aegis, then starts the compact local Gemma profile.",
			Commands: []SetupCommand{{
				Label:      "Install and run",
				Unix:       "aegis ai install",
				PowerShell: "aegis ai install",
				Cmd:        "aegis ai install",
			}},
		},
		{
			Title: "1. Create the model folder",
			Why:   "Safe to run again. It creates the Aegis model directory for the current user without hardcoding a username.",
			Commands: []SetupCommand{{
				Label:      "Create directory",
				Unix:       unixModelDirCommand(runtime.GOOS) + "\nmkdir -p \"$AEGIS_MODEL_DIR\"",
				PowerShell: "$env:AEGIS_MODEL_DIR = Join-Path $env:LOCALAPPDATA 'aegis\\models'\nNew-Item -ItemType Directory -Force -Path $env:AEGIS_MODEL_DIR | Out-Null",
				Cmd:        "set \"AEGIS_MODEL_DIR=%LOCALAPPDATA%\\aegis\\models\"\nif not exist \"%AEGIS_MODEL_DIR%\" mkdir \"%AEGIS_MODEL_DIR%\"",
			}},
		},
		{
			Title: "2. Install or update llama.cpp",
			Why:   "Aegis queries the latest ggml-org/llama.cpp release and downloads the matching macOS, Linux, or Windows asset.",
			Commands: []SetupCommand{{
				Label:      "Aegis managed",
				Unix:       "aegis ai setup --download-llama",
				PowerShell: "aegis ai setup --download-llama",
				Cmd:        "aegis ai setup --download-llama",
			}, {
				Label:      "Source fallback",
				Unix:       "git clone https://github.com/ggml-org/llama.cpp \"$HOME/src/llama.cpp\"\ncmake -S \"$HOME/src/llama.cpp\" -B \"$HOME/src/llama.cpp/build\"\ncmake --build \"$HOME/src/llama.cpp/build\" --config Release",
				PowerShell: "git clone https://github.com/ggml-org/llama.cpp \"$env:USERPROFILE\\src\\llama.cpp\"\ncmake -S \"$env:USERPROFILE\\src\\llama.cpp\" -B \"$env:USERPROFILE\\src\\llama.cpp\\build\"\ncmake --build \"$env:USERPROFILE\\src\\llama.cpp\\build\" --config Release",
				Cmd:        "git clone https://github.com/ggml-org/llama.cpp \"%USERPROFILE%\\src\\llama.cpp\"\ncmake -S \"%USERPROFILE%\\src\\llama.cpp\" -B \"%USERPROFILE%\\src\\llama.cpp\\build\"\ncmake --build \"%USERPROFILE%\\src\\llama.cpp\\build\" --config Release",
			}},
		},
		{
			Title: "3. Download a model",
			Why:   "The compact default is text-only and tuned to leave headroom on 8 GB laptops. llama.cpp reuses its Hugging Face cache after the first download.",
			Commands: []SetupCommand{{
				Label:      "Auto-download via llama.cpp",
				Unix:       "llama-server -hf " + DefaultModelRef + " --no-mmproj --ctx-size 2048 --batch-size 256 --parallel 1 --n-gpu-layers 0 --no-kv-offload --host 127.0.0.1 --port 8080",
				PowerShell: "llama-server -hf " + DefaultModelRef + " --no-mmproj --ctx-size 2048 --batch-size 256 --parallel 1 --n-gpu-layers 0 --no-kv-offload --host 127.0.0.1 --port 8080",
				Cmd:        "llama-server -hf " + DefaultModelRef + " --no-mmproj --ctx-size 2048 --batch-size 256 --parallel 1 --n-gpu-layers 0 --no-kv-offload --host 127.0.0.1 --port 8080",
			}, {
				Label:      "Manual Hugging Face fallback",
				Unix:       "python -m pip install -U huggingface_hub\nhuggingface-cli download ggml-org/gemma-3-1b-it-GGUF " + modelSources[0].Filename + " --local-dir \"$AEGIS_MODEL_DIR\" --local-dir-use-symlinks False",
				PowerShell: "python -m pip install -U huggingface_hub\nhuggingface-cli download ggml-org/gemma-3-1b-it-GGUF " + modelSources[0].Filename + " --local-dir \"$env:AEGIS_MODEL_DIR\" --local-dir-use-symlinks False",
				Cmd:        "python -m pip install -U huggingface_hub\nhuggingface-cli download ggml-org/gemma-3-1b-it-GGUF " + modelSources[0].Filename + " --local-dir \"%AEGIS_MODEL_DIR%\" --local-dir-use-symlinks False",
			}},
		},
		{
			Title: "4. Start the local server",
			Why:   "Runs only on 127.0.0.1 so findings and host context stay on this machine.",
			Commands: []SetupCommand{{
				Label:      "If you downloaded a GGUF file manually",
				Unix:       "llama-server -m \"$AEGIS_MODEL_DIR/" + modelSources[0].Filename + "\" --host 127.0.0.1 --port 8080",
				PowerShell: "llama-server -m \"$env:AEGIS_MODEL_DIR\\" + modelSources[0].Filename + "\" --host 127.0.0.1 --port 8080",
				Cmd:        "llama-server -m \"%AEGIS_MODEL_DIR%\\" + modelSources[0].Filename + "\" --host 127.0.0.1 --port 8080",
			}},
		},
		{
			Title: "5. Point Aegis at the server",
			Why:   "Safe to run again. It updates Aegis AI config to use the local OpenAI-compatible llama.cpp endpoint.",
			Commands: []SetupCommand{{
				Label:      "Configure and verify",
				Unix:       "aegis ai config --backend llamacpp-server --endpoint " + DefaultURL + "\naegis ai status\naegis ai test \"Explain what Aegis checks\"",
				PowerShell: "aegis ai config --backend llamacpp-server --endpoint " + DefaultURL + "\naegis ai status\naegis ai test \"Explain what Aegis checks\"",
				Cmd:        "aegis ai config --backend llamacpp-server --endpoint " + DefaultURL + "\naegis ai status\naegis ai test \"Explain what Aegis checks\"",
			}},
		},
	}
	return SetupPlan{
		InstallDir:      installDir,
		ModelDir:        modelDir,
		ModelFile:       homeModel,
		Recommended:     "Gemma 3 1B instruction-tuned GGUF, Q4_K_M quantization (compact default for 8 GB laptops)",
		LlamaReleaseURL: "https://api.github.com/repos/ggml-org/llama.cpp/releases/latest",
		ModelSources:    modelSources,
		Sections:        sections,
		Idempotent:      true,
		Notes: []string{
			"aegis queries llama.cpp releases at setup time so it can use the current build instead of a hardcoded tag",
			"setup commands are idempotent for the current user on macOS, Linux/Unix and Windows; they avoid hardcoded usernames",
			"model weights are cached by llama.cpp; repeat setup reuses the selected cached model instead of downloading it again",
			"model weights are separate; download GGUF files only from sources you trust, review the model card/license and pin checksums for operational use",
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

func unixModelDirCommand(goos string) string {
	if goos == "darwin" {
		return "export AEGIS_MODEL_DIR=\"$HOME/Library/Application Support/aegis/models\""
	}
	return "export AEGIS_MODEL_DIR=\"${XDG_CONFIG_HOME:-$HOME/.config}/aegis/models\""
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
		"max_tokens":  384,
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

func checkServerHealth(ctx context.Context, endpoint string) error {
	u, err := url.Parse(endpoint)
	if err != nil {
		return err
	}
	if u.Scheme == "" || u.Host == "" {
		return fmt.Errorf("invalid server endpoint %q", endpoint)
	}
	// /v1/models confirms that the OpenAI-compatible server has loaded a model
	// without dispatching a completion. This keeps routine UI status polling
	// from waking the model or allocating a decode batch.
	u.Path = "/v1/models"
	u.RawQuery = ""
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<10))
		return fmt.Errorf("health HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(data)))
	}
	return nil
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

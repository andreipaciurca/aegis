package gui

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/andreipaciurca/aegis/internal/ai"
)

func TestAIInstallStatusReportsIdleAndActiveJob(t *testing.T) {
	srv := &Server{}

	idle := httptest.NewRecorder()
	srv.aiInstall(idle, httptest.NewRequest(http.MethodGet, "/api/ai/install", nil))
	if idle.Code != http.StatusOK {
		t.Fatalf("idle status code = %d, want %d", idle.Code, http.StatusOK)
	}
	var idleBody map[string]any
	if err := json.NewDecoder(idle.Body).Decode(&idleBody); err != nil {
		t.Fatalf("decode idle response: %v", err)
	}
	if idleBody["state"] != "idle" {
		t.Fatalf("idle state = %#v, want idle", idleBody["state"])
	}

	srv.aiInstallJob = &aiInstallJob{
		State:          "running",
		Stage:          "download",
		Message:        "Downloading llama.cpp",
		CompletedBytes: 50,
		TotalBytes:     100,
	}
	active := httptest.NewRecorder()
	srv.aiInstall(active, httptest.NewRequest(http.MethodGet, "/api/ai/install", nil))
	if active.Code != http.StatusOK {
		t.Fatalf("active status code = %d, want %d", active.Code, http.StatusOK)
	}
	var job aiInstallJob
	if err := json.NewDecoder(active.Body).Decode(&job); err != nil {
		t.Fatalf("decode active response: %v", err)
	}
	if job.State != "running" || job.Stage != "download" || job.CompletedBytes != 50 || job.TotalBytes != 100 {
		t.Fatalf("unexpected active job: %+v", job)
	}
}

func TestAIConfigReadyUsesConfiguredBackend(t *testing.T) {
	cases := []struct {
		name   string
		status ai.Status
		want   bool
	}{
		{"server ready", ai.Status{Config: ai.Config{Backend: ai.BackendServer}, ServerReady: true}, true},
		{"server ignores cli", ai.Status{Config: ai.Config{Backend: ai.BackendServer}, CLIReady: true}, false},
		{"cli ready", ai.Status{Config: ai.Config{Backend: ai.BackendCLI}, CLIReady: true}, true},
		{"remote ready", ai.Status{Config: ai.Config{Backend: ai.BackendOpenAICompatible}, RemoteReady: true}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := aiConfigReady(tc.status); got != tc.want {
				t.Fatalf("aiConfigReady(%+v) = %v, want %v", tc.status, got, tc.want)
			}
		})
	}
}

func TestNormalizeAIInstallWaitingFixesLegacyCompleteState(t *testing.T) {
	srv := &Server{aiInstallJob: &aiInstallJob{
		State:      "complete",
		Stage:      "waiting",
		FinishedAt: "2026-07-21T11:12:42Z",
	}}
	srv.normalizeAIInstallWaiting()
	if srv.aiInstallJob.State != "waiting" {
		t.Fatalf("state = %q, want waiting", srv.aiInstallJob.State)
	}
	if srv.aiInstallJob.FinishedAt != "" {
		t.Fatalf("finished_at = %q, want empty until the model is ready", srv.aiInstallJob.FinishedAt)
	}
}

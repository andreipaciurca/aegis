package gui

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
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

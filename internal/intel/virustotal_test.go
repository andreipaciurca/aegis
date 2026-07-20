package intel

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const sampleSHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"

func TestVirusTotalLookupFile(t *testing.T) {
	var gotKey string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotKey = r.Header.Get("x-apikey")
		if r.URL.Path != "/files/"+sampleSHA256 {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"data": {
				"id": "` + sampleSHA256 + `",
				"links": {"self": "https://www.virustotal.com/api/v3/files/` + sampleSHA256 + `"},
				"attributes": {
					"meaningful_name": "eicar.txt",
					"type_description": "Text",
					"reputation": -12,
					"last_analysis_stats": {
						"malicious": 5,
						"suspicious": 1,
						"harmless": 10,
						"undetected": 60
					}
				}
			}
		}`))
	}))
	defer srv.Close()

	report, err := VirusTotalClient{BaseURL: srv.URL, APIKey: "secret", HTTPClient: srv.Client()}.LookupFile(context.Background(), sampleSHA256)
	if err != nil {
		t.Fatalf("lookup failed: %v", err)
	}
	if gotKey != "secret" {
		t.Fatalf("missing api key header: %q", gotKey)
	}
	if !report.Found || report.ID != sampleSHA256 {
		t.Fatalf("unexpected report: %+v", report)
	}
	if report.LastAnalysisStats["malicious"] != 5 || report.MeaningfulName != "eicar.txt" {
		t.Fatalf("did not parse attributes: %+v", report)
	}
}

func TestVirusTotalLookupFileNotFound(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	defer srv.Close()

	report, err := VirusTotalClient{BaseURL: srv.URL, APIKey: "secret", HTTPClient: srv.Client()}.LookupFile(context.Background(), sampleSHA256)
	if err != nil {
		t.Fatalf("lookup should not fail on 404: %v", err)
	}
	if report.Found || !strings.Contains(report.Error, "not found") {
		t.Fatalf("unexpected report: %+v", report)
	}
}

func TestVirusTotalLookupFileRequiresAPIKey(t *testing.T) {
	_, err := VirusTotalClient{}.LookupFile(context.Background(), sampleSHA256)
	if err == nil || !strings.Contains(err.Error(), "API key") {
		t.Fatalf("expected api key error, got %v", err)
	}
}

func TestVirusTotalLookupFileValidatesHash(t *testing.T) {
	_, err := VirusTotalClient{APIKey: "secret"}.LookupFile(context.Background(), "not-a-hash")
	if err == nil || !strings.Contains(err.Error(), "hash") {
		t.Fatalf("expected hash validation error, got %v", err)
	}
}

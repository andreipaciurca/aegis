// Package intel contains optional, user-triggered OSINT lookups.
package intel

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

const VirusTotalBaseURL = "https://www.virustotal.com/api/v3"

var hashRE = regexp.MustCompile(`(?i)^(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})$`)

type VirusTotalClient struct {
	BaseURL    string
	APIKey     string
	HTTPClient *http.Client
}

type VirusTotalReport struct {
	Provider          string         `json:"provider"`
	Query             string         `json:"query"`
	Found             bool           `json:"found"`
	ID                string         `json:"id,omitempty"`
	Link              string         `json:"link,omitempty"`
	Reputation        int            `json:"reputation,omitempty"`
	LastAnalysisStats map[string]int `json:"last_analysis_stats,omitempty"`
	MeaningfulName    string         `json:"meaningful_name,omitempty"`
	TypeDescription   string         `json:"type_description,omitempty"`
	Error             string         `json:"error,omitempty"`
}

func (c VirusTotalClient) LookupFile(ctx context.Context, hash string) (VirusTotalReport, error) {
	hash = strings.ToLower(strings.TrimSpace(hash))
	report := VirusTotalReport{Provider: "virustotal", Query: hash, Link: "https://www.virustotal.com/gui/file/" + hash}
	if !hashRE.MatchString(hash) {
		return report, fmt.Errorf("expected an MD5, SHA-1 or SHA-256 hash")
	}
	if strings.TrimSpace(c.APIKey) == "" {
		return report, errors.New("missing VirusTotal API key; set VT_API_KEY or pass --api-key-env NAME")
	}
	base := strings.TrimRight(c.BaseURL, "/")
	if base == "" {
		base = VirusTotalBaseURL
	}
	httpClient := c.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 20 * time.Second}
	}
	endpoint, err := url.JoinPath(base, "files", hash)
	if err != nil {
		return report, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return report, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "aegis-intel/1.0")
	req.Header.Set("x-apikey", c.APIKey)

	resp, err := httpClient.Do(req)
	if err != nil {
		return report, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		report.Found = false
		report.Error = "hash not found in VirusTotal"
		return report, nil
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		var apiErr vtErrorResponse
		_ = json.NewDecoder(resp.Body).Decode(&apiErr)
		msg := strings.TrimSpace(apiErr.Error.Message)
		if msg == "" {
			msg = resp.Status
		}
		return report, fmt.Errorf("virustotal: %s", msg)
	}

	var body vtFileResponse
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return report, err
	}
	report.Found = true
	report.ID = body.Data.ID
	report.Reputation = body.Data.Attributes.Reputation
	report.MeaningfulName = body.Data.Attributes.MeaningfulName
	report.TypeDescription = body.Data.Attributes.TypeDescription
	report.LastAnalysisStats = body.Data.Attributes.LastAnalysisStats
	if body.Data.Links.Self != "" {
		report.Link = "https://www.virustotal.com/gui/file/" + body.Data.ID
	}
	return report, nil
}

type vtFileResponse struct {
	Data struct {
		ID         string                `json:"id"`
		Links      struct{ Self string } `json:"links"`
		Attributes struct {
			LastAnalysisStats map[string]int `json:"last_analysis_stats"`
			MeaningfulName    string         `json:"meaningful_name"`
			Reputation        int            `json:"reputation"`
			TypeDescription   string         `json:"type_description"`
		} `json:"attributes"`
	} `json:"data"`
}

type vtErrorResponse struct {
	Error struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

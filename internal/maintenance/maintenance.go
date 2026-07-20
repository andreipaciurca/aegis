package maintenance

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/andreipaciurca/aegis/internal/ai"
	"github.com/andreipaciurca/aegis/internal/signatures"
)

const aegisLatestURL = "https://api.github.com/repos/andreipaciurca/aegis/releases/latest"

// DefaultStartupInterval is how often automatic startup checks are allowed to
// touch the network. Explicit checks (pressing u, aegis update, the GUI's
// Update button) always call Startup directly and are never throttled.
const DefaultStartupInterval = 30 * time.Minute

type Report struct {
	SignatureAdded int            `json:"signature_added"`
	SignatureTotal int            `json:"signature_total"`
	SignatureError string         `json:"signature_error,omitempty"`
	Aegis          ReleaseStatus  `json:"aegis"`
	Llama          ai.LlamaLatest `json:"llama"`
	LlamaError     string         `json:"llama_error,omitempty"`
}

type ReleaseStatus struct {
	Current     string `json:"current"`
	Latest      string `json:"latest,omitempty"`
	ReleaseURL  string `json:"release_url,omitempty"`
	PublishedAt string `json:"published_at,omitempty"`
	Update      bool   `json:"update"`
	Error       string `json:"error,omitempty"`
}

func Startup(ctx context.Context, db *signatures.DB, currentVersion string) Report {
	var r Report
	added, err := db.Update()
	r.SignatureAdded = added
	r.SignatureTotal = db.Count()
	if err != nil {
		r.SignatureError = err.Error()
	}
	r.Aegis = CheckAegisUpdate(ctx, currentVersion)
	if llama, err := ai.LatestLlama(); err == nil {
		r.Llama = llama
	} else {
		r.LlamaError = err.Error()
	}
	return r
}

// StartupInterval reads AEGIS_STARTUP_CHECK_INTERVAL (a Go duration string,
// e.g. "10m" or "1h") and falls back to DefaultStartupInterval. A value of
// "0" disables throttling — every automatic check hits the network live,
// matching the old always-on behavior.
func StartupInterval() time.Duration {
	v := strings.TrimSpace(os.Getenv("AEGIS_STARTUP_CHECK_INTERVAL"))
	if v == "" {
		return DefaultStartupInterval
	}
	d, err := time.ParseDuration(v)
	if err != nil || d < 0 {
		return DefaultStartupInterval
	}
	return d
}

type cacheEntry struct {
	CheckedAt time.Time `json:"checked_at"`
	Report    Report    `json:"report"`
}

func cachePath() (string, error) {
	dir, err := signatures.Dir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "maintenance_cache.json"), nil
}

// StartupCached runs Startup at most once per interval; a call made sooner
// than that returns the cached report immediately with no network activity,
// so launching aegis repeatedly in a short span (a dev/test loop, a busy
// shell) doesn't refetch signatures and poll two GitHub endpoints every
// single time. The signature count is always read fresh from db so a cached
// report never shows a stale total even when the network calls are skipped.
//
// This is only for automatic startup checks (TUI/GUI launch). Anything the
// user explicitly triggers — pressing u, aegis update, the GUI's Update
// button — should call Startup directly so it's never stale on request.
func StartupCached(ctx context.Context, db *signatures.DB, currentVersion string, interval time.Duration) Report {
	path, pathErr := cachePath()
	if pathErr == nil && interval > 0 {
		if b, err := os.ReadFile(path); err == nil {
			var entry cacheEntry
			if json.Unmarshal(b, &entry) == nil && time.Since(entry.CheckedAt) < interval {
				entry.Report.SignatureTotal = db.Count()
				return entry.Report
			}
		}
	}
	report := Startup(ctx, db, currentVersion)
	if pathErr == nil {
		if b, err := json.MarshalIndent(cacheEntry{CheckedAt: time.Now(), Report: report}, "", "  "); err == nil {
			_ = os.WriteFile(path, b, 0o600)
		}
	}
	return report
}

func CheckAegisUpdate(ctx context.Context, currentVersion string) ReleaseStatus {
	s := ReleaseStatus{Current: currentVersion}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, aegisLatestURL, nil)
	if err != nil {
		s.Error = err.Error()
		return s
	}
	req.Header.Set("User-Agent", "aegis/"+currentVersion+" update-check")
	client := http.Client{Timeout: 8 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		s.Error = err.Error()
		return s
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		s.Error = "no GitHub release found"
		return s
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		s.Error = fmt.Sprintf("GitHub HTTP %d", resp.StatusCode)
		return s
	}
	var out struct {
		TagName     string `json:"tag_name"`
		HTMLURL     string `json:"html_url"`
		PublishedAt string `json:"published_at"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 2<<20)).Decode(&out); err != nil {
		s.Error = err.Error()
		return s
	}
	s.Latest = strings.TrimPrefix(out.TagName, "v")
	s.ReleaseURL = out.HTMLURL
	s.PublishedAt = out.PublishedAt
	s.Update = newerVersion(s.Latest, currentVersion)
	return s
}

func Summary(r Report) (string, bool) {
	var parts []string
	err := false
	if r.SignatureError != "" {
		parts = append(parts, "signature update failed: "+r.SignatureError)
		err = true
	} else {
		parts = append(parts, fmt.Sprintf("signatures +%d (%d total)", r.SignatureAdded, r.SignatureTotal))
	}
	if r.Aegis.Error != "" {
		parts = append(parts, "Aegis update check: "+r.Aegis.Error)
	} else if r.Aegis.Update {
		parts = append(parts, "Aegis "+r.Aegis.Latest+" available")
	} else if r.Aegis.Latest != "" {
		parts = append(parts, "Aegis current")
	}
	if r.LlamaError != "" {
		parts = append(parts, "llama.cpp check: "+r.LlamaError)
	} else if r.Llama.Tag != "" {
		parts = append(parts, "llama.cpp "+r.Llama.Tag)
	}
	if len(parts) == 0 {
		return "startup checks complete", false
	}
	return strings.Join(parts, " · "), err
}

func newerVersion(latest, current string) bool {
	l := versionParts(latest)
	c := versionParts(current)
	for i := 0; i < len(l) || i < len(c); i++ {
		var lv, cv int
		if i < len(l) {
			lv = l[i]
		}
		if i < len(c) {
			cv = c[i]
		}
		if lv > cv {
			return true
		}
		if lv < cv {
			return false
		}
	}
	return latest != "" && current == ""
}

func versionParts(s string) []int {
	s = strings.TrimPrefix(strings.TrimSpace(s), "v")
	fields := strings.FieldsFunc(s, func(r rune) bool { return r == '.' || r == '-' || r == '_' })
	out := make([]int, 0, len(fields))
	for _, f := range fields {
		n := 0
		for _, r := range f {
			if r < '0' || r > '9' {
				break
			}
			n = n*10 + int(r-'0')
		}
		out = append(out, n)
	}
	return out
}

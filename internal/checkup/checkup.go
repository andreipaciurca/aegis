// Package checkup performs a read-only system security posture check across
// macOS, Linux and Windows.
package checkup

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"sort"
	"strings"
	"time"
)

const (
	CISAKEVURL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
	NVDAPIURL  = "https://services.nvd.nist.gov/rest/json/cves/2.0"
)

type Options struct {
	Offline bool
	Now     time.Time
	Root    string
}

type Report struct {
	CollectedAt       time.Time           `json:"collected_at"`
	OS                OSReport            `json:"os"`
	Updates           []Check             `json:"updates"`
	Dependencies      []Check             `json:"dependencies"`
	Vulnerabilities   VulnerabilityReport `json:"vulnerabilities"`
	Recommendations   []string            `json:"recommendations,omitempty"`
	UnsupportedChecks []string            `json:"unsupported_checks,omitempty"`
	Sources           map[string]string   `json:"sources,omitempty"`
}

type OSReport struct {
	GOOS     string `json:"goos"`
	GOARCH   string `json:"goarch"`
	Hostname string `json:"hostname,omitempty"`
	Name     string `json:"name,omitempty"`
	Version  string `json:"version,omitempty"`
	Kernel   string `json:"kernel,omitempty"`
}

type Check struct {
	Name     string   `json:"name"`
	Status   string   `json:"status"` // ok | warn | error | unknown
	Summary  string   `json:"summary"`
	Items    []string `json:"items,omitempty"`
	Command  string   `json:"command,omitempty"`
	Error    string   `json:"error,omitempty"`
	Duration string   `json:"duration,omitempty"`
}

type VulnerabilityReport struct {
	Offline        bool       `json:"offline"`
	RecentKEV      []KEVEntry `json:"recent_kev,omitempty"`
	RecentCritical []NVDEntry `json:"recent_critical,omitempty"`
	Errors         []string   `json:"errors,omitempty"`
}

type KEVEntry struct {
	CVE                        string `json:"cve"`
	VendorProject              string `json:"vendor_project"`
	Product                    string `json:"product"`
	VulnerabilityName          string `json:"vulnerability_name"`
	DateAdded                  string `json:"date_added"`
	DueDate                    string `json:"due_date"`
	KnownRansomwareCampaignUse string `json:"known_ransomware_campaign_use,omitempty"`
	RequiredAction             string `json:"required_action,omitempty"`
}

type NVDEntry struct {
	ID           string `json:"id"`
	Published    string `json:"published"`
	LastModified string `json:"last_modified,omitempty"`
	Severity     string `json:"severity,omitempty"`
	Score        string `json:"score,omitempty"`
	Summary      string `json:"summary,omitempty"`
}

func Run(opts Options) Report {
	now := opts.Now
	if now.IsZero() {
		now = time.Now()
	}
	r := Report{
		CollectedAt: now,
		OS:          collectOS(),
		Sources: map[string]string{
			"cisa_kev": CISAKEVURL,
			"nvd_cves": NVDAPIURL,
		},
	}
	r.Updates = collectUpdates()
	r.Dependencies = collectDependencies(opts.Root)
	if opts.Offline {
		r.Vulnerabilities.Offline = true
	} else {
		r.Vulnerabilities = collectVulnerabilities(now)
	}
	r.Recommendations, r.UnsupportedChecks = recommendations(r)
	return r
}

func collectOS() OSReport {
	host, _ := os.Hostname()
	r := OSReport{GOOS: runtime.GOOS, GOARCH: runtime.GOARCH, Hostname: host}
	switch runtime.GOOS {
	case "darwin":
		r.Name = "macOS"
		if out, err := run(3*time.Second, "sw_vers", "-productVersion"); err == nil {
			r.Version = strings.TrimSpace(out)
		}
		if out, err := run(3*time.Second, "uname", "-r"); err == nil {
			r.Kernel = strings.TrimSpace(out)
		}
	case "linux":
		r.Name, r.Version = linuxRelease()
		if out, err := run(3*time.Second, "uname", "-r"); err == nil {
			r.Kernel = strings.TrimSpace(out)
		}
	case "windows":
		r.Name = "Windows"
		if out, err := run(6*time.Second, "powershell", "-NoProfile", "-Command",
			"(Get-CimInstance Win32_OperatingSystem | Select-Object -First 1 Caption,Version,BuildNumber | ConvertTo-Json -Compress)"); err == nil {
			var m map[string]any
			if json.Unmarshal([]byte(out), &m) == nil {
				if s, ok := m["Caption"].(string); ok {
					r.Name = s
				}
				if s, ok := m["Version"].(string); ok {
					r.Version = s
				}
				if s, ok := m["BuildNumber"].(string); ok {
					r.Kernel = s
				}
			}
		}
	}
	return r
}

func linuxRelease() (string, string) {
	f, err := os.Open("/etc/os-release")
	if err != nil {
		return "Linux", ""
	}
	defer f.Close()
	vals := map[string]string{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		k, v, ok := strings.Cut(sc.Text(), "=")
		if ok {
			vals[k] = strings.Trim(v, `"`)
		}
	}
	name := vals["PRETTY_NAME"]
	if name == "" {
		name = vals["NAME"]
	}
	return name, vals["VERSION_ID"]
}

func collectUpdates() []Check {
	switch runtime.GOOS {
	case "darwin":
		return []Check{commandCheck("macOS software updates", "softwareupdate -l", 20*time.Second, "softwareupdate", "-l")}
	case "linux":
		for _, c := range []struct {
			bin  string
			args []string
		}{
			{"apt", []string{"list", "--upgradable"}},
			{"dnf", []string{"check-update"}},
			{"zypper", []string{"list-updates"}},
			{"pacman", []string{"-Qu"}},
			{"apk", []string{"version", "-l", "<"}},
		} {
			if has(c.bin) {
				return []Check{commandCheck("Linux package updates", c.bin+" "+strings.Join(c.args, " "), 20*time.Second, c.bin, c.args...)}
			}
		}
		return []Check{{Name: "Linux package updates", Status: "unknown", Summary: "no supported package manager found"}}
	case "windows":
		return []Check{
			commandCheck("Windows hotfix history", "Get-HotFix", 10*time.Second, "powershell", "-NoProfile", "-Command",
				"Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 10 HotFixID,InstalledOn,Description | Format-Table -AutoSize"),
		}
	}
	return []Check{{Name: "OS updates", Status: "unknown", Summary: "unsupported OS"}}
}

func collectDependencies(root string) []Check {
	var checks []Check
	if has("brew") {
		checks = append(checks, commandCheck("Homebrew outdated", "brew outdated --quiet", 20*time.Second, "brew", "outdated", "--quiet"))
	}
	if has("npm") {
		checks = append(checks, commandCheck("npm global outdated", "npm outdated -g --depth=0", 20*time.Second, "npm", "outdated", "-g", "--depth=0"))
	}
	if has("python3") {
		checks = append(checks, commandCheck("Python packages outdated", "python3 -m pip list --outdated --format=json", 20*time.Second, "python3", "-m", "pip", "list", "--outdated", "--format=json"))
	} else if has("python") {
		checks = append(checks, commandCheck("Python packages outdated", "python -m pip list --outdated --format=json", 20*time.Second, "python", "-m", "pip", "list", "--outdated", "--format=json"))
	}
	if has("winget") {
		checks = append(checks, commandCheck("winget upgrades", "winget upgrade", 20*time.Second, "winget", "upgrade"))
	}
	if root == "" {
		root, _ = os.Getwd()
	}
	if _, err := os.Stat(root + string(os.PathSeparator) + "go.mod"); err == nil && has("go") {
		checks = append(checks, commandCheck("Go module updates", "go list -m -u all", 25*time.Second, "go", "list", "-m", "-u", "all"))
	}
	if len(checks) == 0 {
		checks = append(checks, Check{Name: "Dependency updates", Status: "unknown", Summary: "no supported dependency tools found"})
	}
	return checks
}

func commandCheck(name, command string, timeout time.Duration, bin string, args ...string) Check {
	start := time.Now()
	out, err := run(timeout, bin, args...)
	items := firstLines(out, 12)
	if name == "Go module updates" {
		items = filterGoUpdates(items)
	}
	c := Check{Name: name, Command: command, Items: items, Duration: time.Since(start).Round(time.Millisecond).String()}
	if err != nil {
		if strings.TrimSpace(out) != "" {
			c.Status = "warn"
			c.Summary = fmt.Sprintf("%d item(s) reported", len(items))
			return c
		}
		c.Status = "error"
		c.Summary = "check failed"
		c.Error = err.Error()
		return c
	}
	if len(items) == 0 || outputMeansClean(out) {
		c.Status = "ok"
		c.Summary = "no updates reported"
		c.Items = nil
		return c
	}
	c.Status = "warn"
	c.Summary = fmt.Sprintf("%d item(s) reported", len(items))
	return c
}

func collectVulnerabilities(now time.Time) VulnerabilityReport {
	var r VulnerabilityReport
	if kev, err := fetchKEV(now.AddDate(0, 0, -30)); err != nil {
		r.Errors = append(r.Errors, "CISA KEV: "+err.Error())
	} else {
		r.RecentKEV = kev
	}
	if nvd, err := fetchNVDCritical(now); err != nil {
		r.Errors = append(r.Errors, "NVD: "+err.Error())
	} else {
		r.RecentCritical = nvd
	}
	return r
}

func fetchKEV(since time.Time) ([]KEVEntry, error) {
	var payload struct {
		Vulnerabilities []struct {
			CVE                        string `json:"cveID"`
			VendorProject              string `json:"vendorProject"`
			Product                    string `json:"product"`
			VulnerabilityName          string `json:"vulnerabilityName"`
			DateAdded                  string `json:"dateAdded"`
			DueDate                    string `json:"dueDate"`
			KnownRansomwareCampaignUse string `json:"knownRansomwareCampaignUse"`
			RequiredAction             string `json:"requiredAction"`
		} `json:"vulnerabilities"`
	}
	if err := getJSON(CISAKEVURL, &payload); err != nil {
		return nil, err
	}
	var entries []KEVEntry
	for _, v := range payload.Vulnerabilities {
		t, err := time.Parse("2006-01-02", v.DateAdded)
		if err == nil && t.Before(since) {
			continue
		}
		entries = append(entries, KEVEntry(v))
	}
	sort.SliceStable(entries, func(i, j int) bool { return entries[i].DateAdded > entries[j].DateAdded })
	if len(entries) > 12 {
		entries = entries[:12]
	}
	return entries, nil
}

func fetchNVDCritical(now time.Time) ([]NVDEntry, error) {
	start := now.AddDate(0, 0, -14).UTC().Format("2006-01-02T15:04:05.000")
	end := now.UTC().Format("2006-01-02T15:04:05.000")
	u, _ := url.Parse(NVDAPIURL)
	q := u.Query()
	q.Set("pubStartDate", start)
	q.Set("pubEndDate", end)
	q.Set("cvssV3Severity", "CRITICAL")
	q.Set("resultsPerPage", "10")
	u.RawQuery = q.Encode()

	var payload struct {
		Vulnerabilities []struct {
			CVE struct {
				ID           string `json:"id"`
				Published    string `json:"published"`
				LastModified string `json:"lastModified"`
				Descriptions []struct {
					Lang  string `json:"lang"`
					Value string `json:"value"`
				} `json:"descriptions"`
				Metrics struct {
					CVSSMetricV31 []struct {
						CVSSData struct {
							BaseScore    float64 `json:"baseScore"`
							BaseSeverity string  `json:"baseSeverity"`
						} `json:"cvssData"`
					} `json:"cvssMetricV31"`
					CVSSMetricV30 []struct {
						CVSSData struct {
							BaseScore    float64 `json:"baseScore"`
							BaseSeverity string  `json:"baseSeverity"`
						} `json:"cvssData"`
					} `json:"cvssMetricV30"`
				} `json:"metrics"`
			} `json:"cve"`
		} `json:"vulnerabilities"`
	}
	if err := getJSON(u.String(), &payload); err != nil {
		return nil, err
	}
	var entries []NVDEntry
	for _, v := range payload.Vulnerabilities {
		e := NVDEntry{ID: v.CVE.ID, Published: v.CVE.Published, LastModified: v.CVE.LastModified}
		for _, d := range v.CVE.Descriptions {
			if d.Lang == "en" {
				e.Summary = trim(d.Value, 220)
				break
			}
		}
		if len(v.CVE.Metrics.CVSSMetricV31) > 0 {
			m := v.CVE.Metrics.CVSSMetricV31[0].CVSSData
			e.Severity, e.Score = m.BaseSeverity, fmt.Sprintf("%.1f", m.BaseScore)
		} else if len(v.CVE.Metrics.CVSSMetricV30) > 0 {
			m := v.CVE.Metrics.CVSSMetricV30[0].CVSSData
			e.Severity, e.Score = m.BaseSeverity, fmt.Sprintf("%.1f", m.BaseScore)
		}
		if e.Severity != "CRITICAL" {
			continue
		}
		entries = append(entries, e)
	}
	return entries, nil
}

func recommendations(r Report) ([]string, []string) {
	var recs, unsupported []string
	for _, c := range append(r.Updates, r.Dependencies...) {
		switch c.Status {
		case "warn":
			recs = append(recs, "Review "+c.Name+": "+c.Command)
		case "error", "unknown":
			unsupported = append(unsupported, c.Name+": "+c.Summary)
		}
	}
	if len(r.Vulnerabilities.RecentKEV) > 0 {
		recs = append(recs, "Review recent CISA KEV entries for affected products in your environment")
	}
	if len(r.Vulnerabilities.RecentCritical) > 0 {
		recs = append(recs, "Review recent critical NVD CVEs and match them to installed software")
	}
	return recs, unsupported
}

func run(timeout time.Duration, bin string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, args...)
	out, err := cmd.CombinedOutput()
	if ctx.Err() == context.DeadlineExceeded {
		return string(out), ctx.Err()
	}
	return string(out), err
}

func has(bin string) bool {
	_, err := exec.LookPath(bin)
	return err == nil
}

func getJSON(rawURL string, dest any) error {
	client := http.Client{Timeout: 15 * time.Second}
	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "aegis-checkup/1.0")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return json.NewDecoder(resp.Body).Decode(dest)
}

func firstLines(out string, max int) []string {
	var lines []string
	sc := bufio.NewScanner(strings.NewReader(out))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "Listing...") ||
			strings.Contains(line, "JSON API") ||
			strings.HasPrefix(line, "Package ") {
			continue
		}
		lines = append(lines, line)
		if len(lines) >= max {
			break
		}
	}
	return lines
}

func outputMeansClean(out string) bool {
	l := strings.ToLower(out)
	return strings.Contains(l, "no new software available") ||
		strings.Contains(l, "no updates") ||
		strings.Contains(l, "nothing to do") ||
		strings.Contains(l, "all packages are up to date") ||
		strings.TrimSpace(l) == "[]"
}

func trim(s string, n int) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}

func filterGoUpdates(items []string) []string {
	out := items[:0]
	for _, item := range items {
		if strings.Contains(item, " [") {
			out = append(out, item)
		}
	}
	return out
}

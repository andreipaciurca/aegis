package gui

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/andreipaciurca/aegis/internal/ai"
	"github.com/andreipaciurca/aegis/internal/appsync"
	"github.com/andreipaciurca/aegis/internal/checkup"
	"github.com/andreipaciurca/aegis/internal/firewall"
	"github.com/andreipaciurca/aegis/internal/maintenance"
	"github.com/andreipaciurca/aegis/internal/netmon"
	"github.com/andreipaciurca/aegis/internal/persist"
	"github.com/andreipaciurca/aegis/internal/ransom"
	"github.com/andreipaciurca/aegis/internal/rules"
	"github.com/andreipaciurca/aegis/internal/scanner"
	"github.com/andreipaciurca/aegis/internal/signatures"
)

type Options struct {
	OpenBrowser bool
	Version     string
	OnEvent     func(appsync.Event)
}

type Server struct {
	db            *signatures.DB
	eng           *rules.Engine
	version       string
	maintenanceMu sync.RWMutex
	maintenance   *maintenance.Report
	maintRunning  bool
	onEvent       func(appsync.Event)
}

func Run(ctx context.Context, db *signatures.DB, eng *rules.Engine, opts Options) error {
	version := opts.Version
	if version == "" {
		version = "dev"
	}
	srv := &Server{db: db, eng: eng, version: version, onEvent: opts.OnEvent}
	mux := http.NewServeMux()
	api := func(pattern string, h http.HandlerFunc) { mux.HandleFunc(pattern, requireSameOrigin(h)) }
	mux.HandleFunc("/", srv.index)
	api("/api/status", srv.status)
	api("/api/scan", srv.scan)
	api("/api/update", srv.update)
	api("/api/checkup", srv.checkup)
	api("/api/network", srv.network)
	api("/api/audit", srv.audit)
	api("/api/shield", srv.shield)
	api("/api/quarantine", srv.quarantine)
	api("/api/firewall", srv.firewallHandler)
	api("/api/history", srv.history)
	api("/api/restore", srv.restore)
	api("/api/ai/status", srv.aiStatus)
	api("/api/ai/remember", srv.aiRemember)
	api("/api/ai/setup", srv.aiSetup)
	api("/api/startup", srv.startup)
	srv.startMaintenance(ctx, opts.Version)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	url := "http://" + ln.Addr().String()
	fmt.Println("Aegis GUI:", url)
	if opts.OpenBrowser {
		_ = openBrowser(url)
	}

	httpSrv := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	errCh := make(chan error, 1)
	go func() { errCh <- httpSrv.Serve(ln) }()
	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = httpSrv.Shutdown(shutdownCtx)
		return ctx.Err()
	case err := <-errCh:
		if err == http.ErrServerClosed {
			return nil
		}
		return err
	}
}

// requireSameOrigin blocks the well-known "a webpage open in another tab
// silently calls your localhost tool" pattern. The GUI binds to 127.0.0.1
// with no login (it's a single-user local tool), so this is the cheap
// equivalent: reject browser requests that didn't originate from this page,
// while still allowing non-browser callers (curl, scripts) which don't send
// these headers at all.
func requireSameOrigin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !sameOriginOrTrusted(r) {
			http.Error(w, "cross-origin requests to the Aegis GUI API are not allowed", http.StatusForbidden)
			return
		}
		next(w, r)
	}
}

func sameOriginOrTrusted(r *http.Request) bool {
	// Modern browsers send Sec-Fetch-Site on essentially every request; it's
	// the most reliable signal and covers cases plain Origin checks miss.
	if site := r.Header.Get("Sec-Fetch-Site"); site != "" {
		return site == "same-origin" || site == "none"
	}
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true // no Origin header at all: not a cross-origin browser fetch
	}
	return origin == "http://"+r.Host
}

func (s *Server) index(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(indexHTML))
}

func (s *Server) status(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, collectStatus(s.db, s.eng))
}

func (s *Server) startup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	s.maintenanceMu.RLock()
	defer s.maintenanceMu.RUnlock()
	resp := map[string]any{"running": s.maintRunning}
	if s.maintenance != nil {
		text, isErr := maintenance.Summary(*s.maintenance)
		resp["summary"] = text
		resp["error"] = isErr
		resp["report"] = s.maintenance
	}
	writeJSON(w, resp)
}

func (s *Server) scan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Path string `json:"path"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if req.Path == "" {
		home, _ := os.UserHomeDir()
		req.Path = home
	}
	cancel := make(chan struct{})
	var final scanner.Progress
	for p := range scanner.Scan(req.Path, s.db, s.eng, cancel) {
		if p.Phase == "done" || p.Phase == "cancelled" || p.Phase == "error" {
			final = p
		}
	}
	if final.Err != nil {
		s.emit("scan", "GUI scan failed: "+final.Err.Error(), true)
	} else {
		s.emit("scan", fmt.Sprintf("GUI scanned %s: %d files, %d threat(s)", req.Path, final.Scanned, len(final.Threats)), len(final.Threats) > 0)
	}
	writeJSON(w, scanResult(req.Path, final))
}

func (s *Server) update(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 90*time.Second)
	defer cancel()
	report := maintenance.Startup(ctx, s.db, s.version)
	s.maintenanceMu.Lock()
	s.maintenance = &report
	s.maintRunning = false
	s.maintenanceMu.Unlock()
	text, isErr := maintenance.Summary(report)
	s.emit("update", "GUI maintenance: "+text, isErr)
	added := report.SignatureAdded
	var err error
	if report.SignatureError != "" {
		err = fmt.Errorf("%s", report.SignatureError)
	}
	writeJSON(w, map[string]any{"added": added, "total": s.db.Count(), "error": errString(err), "summary": text, "report": report})
}

func (s *Server) checkup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	report := checkup.Run(checkup.Options{})
	s.emit("checkup", "GUI completed security checkup", false)
	writeJSON(w, report)
}

func (s *Server) network(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	conns, err := netmon.List()
	flagged := 0
	for _, c := range conns {
		if c.Suspect != "" {
			flagged++
		}
	}
	s.emit("network", fmt.Sprintf("GUI refreshed network: %d connection(s), %d flagged", len(conns), flagged), flagged > 0)
	writeJSON(w, map[string]any{"connections": conns, "flagged": flagged, "error": errString(err)})
}

func (s *Server) audit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	entries := persist.Audit()
	suspicious := 0
	for _, e := range entries {
		if e.Suspect != "" {
			suspicious++
		}
	}
	s.emit("audit", fmt.Sprintf("GUI refreshed persistence audit: %d entries, %d suspicious", len(entries), suspicious), suspicious > 0)
	writeJSON(w, map[string]any{"entries": entries, "suspicious": suspicious})
}

func (s *Server) shield(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		events := ransom.CheckCanaries()
		writeJSON(w, map[string]any{
			"canaries": ransom.LoadManifest().Canaries,
			"events":   events,
			"dirs":     ransom.DefaultDirs(),
		})
	case http.MethodPost:
		var req struct {
			Action string `json:"action"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		switch req.Action {
		case "deploy":
			manifest, err := ransom.Deploy(ransom.DefaultDirs())
			s.emit("shield", fmt.Sprintf("GUI armed ransomware shield: %d canaries", len(manifest.Canaries)), err != nil)
			writeJSON(w, map[string]any{"canaries": manifest.Canaries, "deployed": manifest.Deployed, "error": errString(err)})
		case "check", "":
			events := ransom.Check(ransom.DefaultDirs())
			s.emit("shield", fmt.Sprintf("GUI checked ransomware shield: %d alert(s)", len(events)), len(events) > 0)
			writeJSON(w, map[string]any{"events": events, "canaries": ransom.LoadManifest().Canaries})
		case "cleanup":
			removed, err := ransom.Cleanup()
			s.emit("shield", fmt.Sprintf("GUI removed ransomware canaries: %d file(s)", removed), err != nil)
			writeJSON(w, map[string]any{"removed": removed, "error": errString(err)})
		default:
			http.Error(w, "unknown shield action", http.StatusBadRequest)
		}
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) quarantine(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Path     string `json:"path"`
		SHA256   string `json:"sha256"`
		Reason   string `json:"reason"`
		Severity string `json:"severity"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if strings.TrimSpace(req.Path) == "" {
		http.Error(w, "path is required", http.StatusBadRequest)
		return
	}
	sev := scanner.SevWarning
	switch strings.ToUpper(req.Severity) {
	case "CRITICAL":
		sev = scanner.SevCritical
	case "INFO":
		sev = scanner.SevInfo
	}
	rec, err := scanner.Quarantine(scanner.Threat{Path: req.Path, SHA256: req.SHA256, Reason: req.Reason, Severity: sev})
	if err != nil {
		s.emit("quarantine", "GUI quarantine failed: "+err.Error(), true)
		writeJSON(w, map[string]any{"error": err.Error()})
		return
	}
	s.emit("quarantine", "GUI quarantined "+rec.Original, false)
	writeJSON(w, map[string]any{"record": rec, "error": ""})
}

func (s *Server) firewallHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, firewall.Get())
	case http.MethodPost:
		var req struct {
			Action string `json:"action"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		var err error
		switch req.Action {
		case "enable":
			err = firewall.SetEnabled(true)
		case "disable":
			err = firewall.SetEnabled(false)
		case "stealth_on":
			err = firewall.SetStealth(true)
		case "stealth_off":
			err = firewall.SetStealth(false)
		default:
			http.Error(w, "unknown firewall action", http.StatusBadRequest)
			return
		}
		s.emit("firewall", firewallEmitText(req.Action, err), err != nil)
		writeJSON(w, map[string]any{"status": firewall.Get(), "error": errString(err)})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func firewallEmitText(action string, err error) string {
	if err != nil {
		return "GUI firewall " + action + " failed: " + err.Error()
	}
	return "GUI firewall: " + action
}

func (s *Server) history(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	recs, err := scanner.QuarantineHistory()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]any{"quarantine": recs})
}

func (s *Server) restore(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	rec, err := scanner.Restore(req.ID)
	if err != nil {
		s.emit("restore", "GUI restore failed: "+err.Error(), true)
		writeJSON(w, map[string]any{"record": rec, "error": err.Error()})
		return
	}
	s.emit("restore", "GUI restored "+rec.Original, false)
	writeJSON(w, map[string]any{"record": rec, "error": ""})
}

func (s *Server) aiStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	cfg, err := ai.Load()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	notes, _ := ai.Notes()
	status := ai.Check(cfg)
	writeJSON(w, map[string]any{"status": status, "notes": notes})
}

func (s *Server) aiRemember(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Text string `json:"text"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := ai.AddNote(req.Text); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	notes, _ := ai.Notes()
	s.emit("ai", "GUI remembered local AI context", false)
	writeJSON(w, map[string]any{"notes": notes})
}

func (s *Server) aiSetup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	plan, err := ai.RunSetup(ai.SetupOptions{})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.emit("ai", "GUI loaded AI setup plan", false)
	writeJSON(w, plan)
}

func (s *Server) startMaintenance(ctx context.Context, version string) {
	if version == "" {
		version = "dev"
	}
	s.maintenanceMu.Lock()
	s.maintRunning = true
	s.maintenanceMu.Unlock()
	go func() {
		runCtx, cancel := context.WithTimeout(ctx, 90*time.Second)
		defer cancel()
		report := maintenance.StartupCached(runCtx, s.db, version, maintenance.StartupInterval())
		s.maintenanceMu.Lock()
		s.maintenance = &report
		s.maintRunning = false
		s.maintenanceMu.Unlock()
		text, isErr := maintenance.Summary(report)
		s.emit("startup", "GUI startup: "+text, isErr)
	}()
}

func (s *Server) emit(kind, text string, isErr bool) {
	if s.onEvent == nil {
		return
	}
	s.onEvent(appsync.Event{Source: "gui", Kind: kind, Text: text, Error: isErr})
}

type statusJSON struct {
	HealthScore        int             `json:"health_score"`
	Health             string          `json:"health"`
	HealthSummary      string          `json:"health_summary"`
	HealthGood         []string        `json:"health_good"`
	HealthIssues       []string        `json:"health_issues"`
	Firewall           firewall.Status `json:"firewall"`
	SignatureHashes    int             `json:"signature_hashes"`
	SignatureRules     int             `json:"signature_rules"`
	SignatureAge       string          `json:"signature_age"`
	Canaries           int             `json:"canaries"`
	RansomAlerts       []ransom.Event  `json:"ransom_alerts"`
	PersistenceTotal   int             `json:"persistence_total"`
	PersistenceSuspect int             `json:"persistence_suspicious"`
	NetworkTotal       int             `json:"network_total"`
	NetworkFlagged     int             `json:"network_flagged"`
	NetworkError       string          `json:"network_error,omitempty"`
	FlaggedNetwork     []netmon.Conn   `json:"flagged_network,omitempty"`
}

func collectStatus(db *signatures.DB, eng *rules.Engine) statusJSON {
	fw := firewall.Get()
	events := ransom.CheckCanaries()
	entries := persist.Audit()
	suspAuto := 0
	for _, e := range entries {
		if e.Suspect != "" {
			suspAuto++
		}
	}
	conns, err := netmon.List()
	flagged := 0
	var flaggedConns []netmon.Conn
	if err == nil {
		for _, c := range conns {
			if c.Suspect != "" {
				flagged++
				flaggedConns = append(flaggedConns, c)
			}
		}
	}
	age := "never"
	if a := db.Age(); a >= 0 {
		age = a.Round(time.Minute).String()
	}
	s := statusJSON{
		Firewall:           fw,
		SignatureHashes:    db.Count(),
		SignatureRules:     eng.Count(),
		SignatureAge:       age,
		Canaries:           len(ransom.LoadManifest().Canaries),
		RansomAlerts:       events,
		PersistenceTotal:   len(entries),
		PersistenceSuspect: suspAuto,
		NetworkTotal:       len(conns),
		NetworkFlagged:     flagged,
		FlaggedNetwork:     flaggedConns,
	}
	if err != nil {
		s.NetworkError = err.Error()
	}
	s.HealthScore, s.Health, s.HealthSummary, s.HealthGood, s.HealthIssues = securityHealth(s, db.Age())
	return s
}

func securityHealth(s statusJSON, sigAge time.Duration) (int, string, string, []string, []string) {
	score := 100
	var good []string
	var issues []string
	if !s.Firewall.Enabled {
		score -= 25
		issues = append(issues, "-25 firewall is disabled")
	} else {
		good = append(good, "Firewall is active")
	}
	if sigAge < 0 {
		score -= 12
		issues = append(issues, "-12 signatures have never been updated")
	} else if sigAge > 7*24*time.Hour {
		score -= 8
		issues = append(issues, "-8 signatures are older than 7 days")
	} else {
		good = append(good, "Malware signatures are fresh")
	}
	if len(s.RansomAlerts) > 0 {
		deduction := min(30, 12+len(s.RansomAlerts)*6)
		score -= deduction
		issues = append(issues, fmt.Sprintf("-%d ransomware canary alert(s)", deduction))
	} else {
		good = append(good, "No ransomware canary alerts")
	}
	if s.PersistenceSuspect > 0 {
		deduction := min(20, s.PersistenceSuspect*5)
		score -= deduction
		issues = append(issues, fmt.Sprintf("-%d suspicious persistence entries", deduction))
	} else {
		good = append(good, "No suspicious persistence entries")
	}
	if s.NetworkFlagged > 0 {
		deduction := min(15, s.NetworkFlagged*4)
		score -= deduction
		issues = append(issues, fmt.Sprintf("-%d network exposure: %d flagged connection(s)", deduction, s.NetworkFlagged))
	} else {
		good = append(good, "No flagged network connections")
	}
	if score < 0 {
		score = 0
	}
	label := "Excellent"
	switch {
	case score < 45:
		label = "Needs Attention"
	case score < 65:
		label = "Fair"
	case score < 85:
		label = "Good"
	}
	summary := "This is a posture score, not a virus probability. It starts at 100 and subtracts for disabled protections, stale signatures, ransomware alerts, suspicious persistence, and exposed network listeners."
	return score, label, summary, good, issues
}

type scanJSONOutput struct {
	Path     string             `json:"path"`
	Phase    string             `json:"phase"`
	Scanned  int64              `json:"scanned"`
	Skipped  int64              `json:"skipped"`
	Duration string             `json:"duration"`
	Threats  []scanThreatOutput `json:"threats"`
	Error    string             `json:"error,omitempty"`
}

type scanThreatOutput struct {
	Path     string `json:"path"`
	SHA256   string `json:"sha256,omitempty"`
	Reason   string `json:"reason"`
	Severity string `json:"severity"`
	Size     int64  `json:"size"`
}

func scanResult(path string, p scanner.Progress) scanJSONOutput {
	out := scanJSONOutput{
		Path:     path,
		Phase:    p.Phase,
		Scanned:  p.Scanned,
		Skipped:  p.Skipped,
		Duration: p.Ended.Sub(p.Started).Round(time.Millisecond).String(),
	}
	if p.Err != nil {
		out.Error = p.Err.Error()
	}
	for _, t := range p.Threats {
		out.Threats = append(out.Threats, scanThreatOutput{
			Path:     t.Path,
			SHA256:   t.SHA256,
			Reason:   t.Reason,
			Severity: t.Severity.String(),
			Size:     t.Size,
		})
	}
	return out
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func openBrowser(url string) error {
	switch runtime.GOOS {
	case "darwin":
		return exec.Command("open", url).Start()
	case "windows":
		return exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
	default:
		return exec.Command("xdg-open", url).Start()
	}
}

const indexHTML = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>aegis — GUI</title>
<link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24'%3E%3Cpath fill='%23cba6f7' d='M12 2 21 5.5v6.3c0 5.6-3.5 9.6-9 10.7-5.5-1.1-9-5.1-9-10.7V5.5Z'/%3E%3C/svg%3E">
<style>
:root{color-scheme:dark;--bg:#11111b;--panel:#1e1e2e;--panel2:#181825;--line:#313244;--line2:#45475a;--text:#cdd6f4;--muted:#9399b2;--faint:#6c7086;--accent:#cba6f7;--ink:#11111b;--green:#a6e3a1;--red:#f38ba8;--yellow:#f9e2af;--blue:#89b4fa}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);font:14px/1.6 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;-webkit-font-smoothing:antialiased}
button,input,textarea{font:inherit}
a{color:var(--blue)}
::selection{background:var(--accent);color:var(--ink)}
.ic svg{width:1em;height:1em;vertical-align:-0.15em}

header{position:sticky;top:0;background:rgba(17,17,27,.92);backdrop-filter:blur(10px);border-bottom:1px solid var(--line);z-index:3}
.bar{max-width:1180px;margin:0 auto;padding:13px 20px;display:flex;gap:12px;align-items:center;flex-wrap:wrap}
.brand{display:inline-flex;align-items:center;gap:6px;background:var(--accent);color:var(--ink);font-weight:800;padding:4px 10px;border-radius:6px;letter-spacing:.02em}
.brand svg{width:14px;height:14px}
.sub{color:var(--faint);font-size:12.5px}
.sync{margin-left:auto;display:inline-flex;align-items:center;gap:7px;color:var(--faint);font-size:12px}
.dot{width:7px;height:7px;border-radius:50%;background:var(--green);flex:none}
.dot.busy{background:var(--yellow);animation:pulse 1.1s ease-in-out infinite}
.dot.err{background:var(--red)}
@keyframes pulse{50%{opacity:.35}}

.status-strip{max-width:1180px;margin:0 auto;padding:9px 20px;font-size:12.5px;color:var(--muted);border-bottom:1px solid var(--line)}
.status-strip.ok{color:var(--green)}.status-strip.err{color:var(--red)}

nav.tabs{max-width:1180px;margin:0 auto;padding:10px 20px 0;display:flex;gap:2px;flex-wrap:wrap}
nav.tabs button{background:none;border:none;color:var(--muted);padding:9px 12px;border-radius:6px 6px 0 0;cursor:pointer;font-size:13px;border-bottom:2px solid transparent;display:inline-flex;align-items:center;gap:6px}
nav.tabs button:hover{color:var(--text)}
nav.tabs button.active{color:var(--accent);border-bottom-color:var(--accent)}

main{max-width:1180px;margin:0 auto;padding:22px 20px 56px}

.hero-score{display:flex;align-items:center;gap:22px;border:1px solid var(--line);border-radius:10px;background:var(--panel);padding:20px 22px;margin-bottom:16px;flex-wrap:wrap}
.hero-score .num{font-size:40px;font-weight:800;line-height:1;min-width:5ch}
.hero-score .meta{flex:1;min-width:200px}
.hero-score .meta .label{font-size:14px;color:var(--text);margin-bottom:4px}
.hero-score .meta .why{font-size:12.5px;color:var(--faint);max-width:70ch}

.why-grid{display:grid;grid-template-columns:1fr 1fr;gap:20px;margin-top:14px;padding-top:14px;border-top:1px solid var(--line)}
.why-grid h4{margin:0 0 8px;font-size:11px;letter-spacing:.06em;text-transform:uppercase;color:var(--faint)}
.why-grid ul{margin:0;padding-left:16px}
.why-grid li{margin:4px 0;font-size:12.5px}

.grid{display:grid;grid-template-columns:repeat(5,minmax(0,1fr));gap:12px;margin-bottom:16px}
.card{border:1px solid var(--line);border-radius:9px;background:var(--panel);padding:14px}
.card .k{display:flex;align-items:center;gap:6px;color:var(--faint);text-transform:uppercase;letter-spacing:.04em;font-size:10.5px;margin-bottom:9px}
.value{font-size:19px;font-weight:700}
.ok{color:var(--green)}.bad{color:var(--red)}.warn{color:var(--yellow)}.blue{color:var(--blue)}.muted{color:var(--muted)}

.panel{border:1px solid var(--line);border-radius:10px;background:var(--panel);padding:20px}
.panel h2{display:flex;align-items:center;gap:9px;font-size:15px;margin:0 0 6px;color:var(--text);font-weight:700}
.panel h2 .ic{color:var(--accent)}
.panel h3{font-size:12px;margin:16px 0 6px;color:var(--faint);text-transform:uppercase;letter-spacing:.04em;font-weight:400}
.panel>p.muted{max-width:64ch}

.actions{display:flex;gap:9px;flex-wrap:wrap;margin-top:14px}
button{background:var(--panel2);color:var(--text);border:1px solid var(--line2);border-radius:7px;padding:9px 13px;cursor:pointer;font-size:13px;transition:border-color .15s,filter .15s}
button:hover{border-color:var(--accent)}
button:disabled{opacity:.5;cursor:default}
button.primary{background:var(--accent);color:var(--ink);border-color:var(--accent);font-weight:700}
button.primary:hover{filter:brightness(1.08)}
button.ghost{background:none}

input,textarea{width:100%;background:var(--panel2);border:1px solid var(--line2);border-radius:7px;color:var(--text);padding:10px 12px;font-size:13px}
input:focus,textarea:focus,button:focus-visible{outline:2px solid var(--accent);outline-offset:1px}
textarea{min-height:80px;resize:vertical}

pre{white-space:pre-wrap;overflow:auto;background:var(--bg);border:1px solid var(--line);border-radius:7px;padding:13px;max-height:420px;font-size:12.5px}

.item{border:1px solid var(--line);border-left:3px solid var(--line2);border-radius:7px;padding:10px 12px;margin-top:8px;background:var(--panel2)}
.item.sev-bad{border-left-color:var(--red)}
.item.sev-warn{border-left-color:var(--yellow)}
.item.sev-ok{border-left-color:var(--green)}
.item:first-child{margin-top:0}
.item-head{display:flex;align-items:center;justify-content:space-between;gap:10px;flex-wrap:wrap}
.item-head .who{min-width:0;overflow-wrap:anywhere}
.item .detail{color:var(--muted);font-size:12.5px;margin-top:4px}

.pill{display:inline-block;border-radius:5px;padding:2px 7px;font-size:10.5px;font-weight:700;letter-spacing:.02em;text-transform:uppercase}
.pill.bad{background:rgba(243,139,168,.14);color:var(--red)}
.pill.warn{background:rgba(249,226,175,.14);color:var(--yellow)}
.pill.ok{background:rgba(166,227,161,.14);color:var(--green)}

.details-head{display:flex;gap:10px;align-items:center;justify-content:space-between}
.small{font-size:12px}
.list{margin:8px 0 0;padding-left:18px}
.list li{margin:4px 0}
.view{display:none}
.view.active{display:block}

footer{max-width:1180px;margin:24px auto 0;padding:20px 20px 30px;color:var(--faint);font-size:12px;display:flex;flex-wrap:wrap;gap:8px 18px;align-items:center;border-top:1px solid var(--line)}
footer a{color:var(--faint)}
.repo-link{display:inline-flex;align-items:center;gap:7px}
.repo-link svg{width:14px;height:14px}

@media(max-width:900px){.grid{grid-template-columns:repeat(2,minmax(0,1fr))}.why-grid{grid-template-columns:1fr}}
@media(max-width:540px){.grid{grid-template-columns:1fr}.value{font-size:17px}.bar{align-items:flex-start}main{padding-inline:14px}.actions button{width:100%}.hero-score{flex-direction:column;align-items:flex-start}.hero-score .num{font-size:32px}}
</style>
</head>
<body>
<header><div class="bar">
  <div class="brand"><svg viewBox="0 0 24 24" fill="none" aria-hidden="true"><path d="M12 3 20 6v6c0 5-3 8-8 11-5-3-8-6-8-11V6l8-3Z" stroke="currentColor" stroke-width="2"/></svg>AEGIS</div>
  <div class="sub">local browser GUI · same core as the TUI · 127.0.0.1 only</div>
  <div class="sync"><span class="dot" id="syncDot"></span><span id="syncOut">syncing…</span></div>
</div></header>
<div class="status-strip" id="startupOut">Checking Aegis updates, refreshing signatures, and checking llama.cpp…</div>
<nav class="tabs" id="nav"></nav>
<main>
  <section class="view" data-view="dashboard">
    <div class="hero-score">
      <div class="num" id="scoreNum">--</div>
      <div class="meta">
        <div class="label" id="scoreLabel">Checking protection score…</div>
        <div class="why" id="scoreWhy">This is a posture score, not a virus probability.</div>
      </div>
    </div>
    <div class="grid" id="cards"></div>
    <div class="panel" id="healthWhy" style="display:none"></div>
  </section>

  <div class="panel view" data-view="scan">
    <h2><span class="ic" data-ic="scan"></span>Scanner</h2>
    <p class="muted">Scan a folder or file with the same hash, rule, entropy, extension, and EICAR checks used by the TUI. Quarantine a finding directly from the results below.</p>
    <input id="path" placeholder="Path to scan, e.g. ~/Downloads or /tmp">
    <div class="actions"><button class="primary" onclick="scan()">Scan path</button><button onclick="updateSigs()">Update &amp; check versions</button><button class="ghost" onclick="refresh()">Refresh status</button></div>
    <div id="scanOut" class="muted" style="margin-top:14px">Choose a folder or file and run a scan.</div>
  </div>

  <div class="panel view" data-view="shield">
    <h2><span class="ic" data-ic="shield"></span>Ransom Shield</h2>
    <p class="muted">Canaries are harmless decoy files placed in common folders. If they disappear or change, Aegis treats it as a strong ransomware signal.</p>
    <div class="actions"><button class="primary" onclick="shield('deploy')">Arm canaries</button><button onclick="shield('check')">Check shield</button><button class="ghost" onclick="shield('cleanup')">Remove canaries</button></div>
    <div id="shieldOut" class="muted" style="margin-top:14px">Ready to arm or check ransomware canaries.</div>
  </div>

  <div class="panel view" data-view="network">
    <h2><span class="ic" data-ic="net"></span>Network</h2>
    <p class="muted">Lists live connections and highlights risky listeners or ports often used by backdoors.</p>
    <div class="actions"><button class="primary" onclick="network()">Refresh network</button></div>
    <div id="networkOut" class="muted" style="margin-top:14px">Network details will appear here.</div>
  </div>

  <div class="panel view" data-view="firewall">
    <h2><span class="ic" data-ic="fw"></span>Firewall</h2>
    <p class="muted">Reads and toggles the native OS firewall directly — macOS Application Firewall, Linux ufw/nftables/iptables, or Windows Defender Firewall.</p>
    <div class="actions"><button class="primary" onclick="firewallAction('enable')">Enable</button><button onclick="firewallAction('disable')">Disable</button><button onclick="firewallAction('stealth_on')">Stealth on</button><button onclick="firewallAction('stealth_off')">Stealth off</button><button class="ghost" onclick="firewallStatus()">Refresh</button></div>
    <div id="firewallOut" class="muted" style="margin-top:14px">Firewall status will appear here.</div>
  </div>

  <div class="panel view" data-view="audit">
    <h2><span class="ic" data-ic="audit"></span>Persistence Audit</h2>
    <p class="muted">Checks startup locations: LaunchAgents, systemd, cron, autostart folders, Windows Run keys, Scheduled Tasks and auto-start services.</p>
    <div class="actions"><button class="primary" onclick="audit()">Run audit</button></div>
    <div id="auditOut" class="muted" style="margin-top:14px">Audit details will appear here.</div>
  </div>

  <div class="panel view" data-view="checkup">
    <h2><span class="ic" data-ic="check"></span>System Checkup</h2>
    <p class="muted">Checks OS updates, dependency updates, and recent CISA/NVD vulnerability feeds. It is read-only.</p>
    <div class="actions"><button class="primary" onclick="checkup()">Run checkup</button></div>
    <div id="checkupOut" class="muted" style="margin-top:14px">Run this when you want to know what needs updating.</div>
  </div>

  <div class="panel view" data-view="ai">
    <h2><span class="ic" data-ic="ai"></span>AI Assistant</h2>
    <p class="muted">Shows local llama.cpp readiness and the setup path. The model is advisory only; detections still come from signatures, rules, canaries, and audits.</p>
    <div class="actions"><button class="primary" onclick="aiStatus()">Check AI status</button><button onclick="aiSetup()">Setup guide</button></div>
    <h3>Remember local context</h3>
    <textarea id="note" placeholder="Example: This Mac is used for development; ignore known local dev servers on 127.0.0.1."></textarea>
    <div class="actions"><button onclick="remember()">Remember note</button></div>
    <div id="aiOut" class="muted" style="margin-top:14px">AI status will appear here.</div>
  </div>

  <div class="panel view" data-view="history">
    <h2><span class="ic" data-ic="hist"></span>Quarantine History</h2>
    <p class="muted">Every quarantined file, newest first. Restoring moves a file back to its original location; Aegis refuses to overwrite an existing file or restore the same record twice.</p>
    <div class="actions"><button class="primary" onclick="history_()">Refresh history</button></div>
    <div id="historyOut" class="muted" style="margin-top:14px">Press refresh to load quarantine history.</div>
  </div>

  <div class="panel view" data-view="details">
    <div class="details-head"><h2><span class="ic" data-ic="code"></span>Details</h2><button class="ghost" onclick="copyDetails()">Copy JSON</button></div>
    <p class="muted">Raw output is kept here for debugging, support, or pasting into an issue. Every other tab summarizes what it means.</p>
    <pre id="detailsOut">No details yet.</pre>
  </div>
</main>
<footer>
  <span>&copy; <span id="year"></span></span>
  <a class="repo-link" href="https://github.com/andreipaciurca/aegis" aria-label="andreipaciurca/aegis on GitHub">
    <svg viewBox="0 0 24 24" aria-hidden="true"><path fill="currentColor" d="M12 .5a12 12 0 0 0-3.79 23.39c.6.11.82-.26.82-.58v-2.03c-3.34.73-4.04-1.42-4.04-1.42-.55-1.39-1.34-1.76-1.34-1.76-1.09-.75.08-.74.08-.74 1.21.09 1.85 1.24 1.85 1.24 1.07 1.84 2.81 1.31 3.5 1 .11-.78.42-1.31.76-1.61-2.67-.3-5.47-1.33-5.47-5.92 0-1.31.47-2.38 1.24-3.22-.12-.3-.54-1.53.12-3.18 0 0 1.01-.32 3.3 1.23a11.4 11.4 0 0 1 6.01 0c2.29-1.55 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.77.84 1.24 1.91 1.24 3.22 0 4.6-2.81 5.62-5.48 5.92.43.37.81 1.1.81 2.22v3.29c0 .32.22.69.83.57A12 12 0 0 0 12 .5Z"/></svg>
    andreipaciurca/aegis
  </a>
</footer>
<script>
document.getElementById('year').textContent=new Date().getFullYear();
const $=id=>document.getElementById(id);
let lastJSON='', currentView='dashboard';
const views=['dashboard','scan','shield','network','firewall','audit','checkup','ai','history','details'];
const ICONS={
 shield:'<svg viewBox="0 0 24 24" fill="none"><path d="M12 3 20 6v6c0 5-3 8-8 11-5-3-8-6-8-11V6l8-3Z" stroke="currentColor" stroke-width="2"/></svg>',
 scan:'<svg viewBox="0 0 24 24" fill="none"><path d="M4 5h16M4 12h16M4 19h16" stroke="currentColor" stroke-width="2"/><path d="M8 5v14M16 5v14" stroke="currentColor" stroke-width="2" opacity=".55"/></svg>',
 net:'<svg viewBox="0 0 24 24" fill="none"><path d="M5 12h4l2-5 3 10 2-5h3" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>',
 fw:'<svg viewBox="0 0 24 24" fill="none"><path d="M6 10V7a6 6 0 0 1 12 0v3M5 10h14v10H5z" stroke="currentColor" stroke-width="2" stroke-linejoin="round"/></svg>',
 audit:'<svg viewBox="0 0 24 24" fill="none"><path d="M5 6h14v12H5z" stroke="currentColor" stroke-width="2"/><path d="M8 10h8M8 14h5" stroke="currentColor" stroke-width="2" stroke-linecap="round"/></svg>',
 ai:'<svg viewBox="0 0 24 24" fill="none"><path d="M8 8h8v8H8zM12 3v3M12 18v3M3 12h3M18 12h3M5 5l2 2M17 17l2 2M19 5l-2 2M7 17l-2 2" stroke="currentColor" stroke-width="2" stroke-linecap="round"/></svg>',
 hist:'<svg viewBox="0 0 24 24" fill="none"><path d="M12 7v5l4 2" stroke="currentColor" stroke-width="2" stroke-linecap="round"/><path d="M21 12a9 9 0 1 1-9-9" stroke="currentColor" stroke-width="2" stroke-linecap="round"/></svg>',
 check:'<svg viewBox="0 0 24 24" fill="none"><path d="M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18Z" stroke="currentColor" stroke-width="2"/><path d="M8 12l3 3 5-6" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>',
 code:'<svg viewBox="0 0 24 24" fill="none"><path d="M8 8 4 12l4 4M16 8l4 4-4 4" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>'
};
function paintIcons(){document.querySelectorAll('.ic[data-ic]').forEach(function(el){el.innerHTML=ICONS[el.dataset.ic]||''})}
function esc(s){return String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));}
function setDetails(name,obj){lastJSON=JSON.stringify(obj,null,2); $('detailsOut').textContent=name?name+'\n\n'+lastJSON:lastJSON}
function copyDetails(){if(!lastJSON){return} navigator.clipboard?.writeText(lastJSON).then(()=>{$('detailsOut').textContent='Copied JSON to clipboard.\n\n'+lastJSON}).catch(()=>{$('detailsOut').focus();document.execCommand('selectAll');document.execCommand('copy')})}
async function api(path,opts){const r=await fetch(path,opts); if(!r.ok) throw new Error(await r.text()); return r.json();}
function initNav(){ $('nav').innerHTML=views.map(v=>'<button id="nav-'+v+'" onclick="showView(\''+v+'\')"><span class="ic" data-ic="'+navIcon(v)+'"></span>'+label(v)+'</button>').join(''); showView(currentView); paintIcons()}
function label(v){return {dashboard:'Dashboard',scan:'Scanner',shield:'Shield',network:'Network',firewall:'Firewall',audit:'Audit',checkup:'Checkup',ai:'AI',history:'History',details:'Details'}[v]||v}
function navIcon(v){return {dashboard:'check',scan:'scan',shield:'shield',network:'net',firewall:'fw',audit:'audit',checkup:'check',ai:'ai',history:'hist',details:'code'}[v]||'code'}
function showView(v){currentView=v; document.querySelectorAll('.view').forEach(function(el){el.classList.toggle('active', el.dataset.view===v)}); views.forEach(function(x){const b=$('nav-'+x); if(b) b.classList.toggle('active',x===v)})}
function setSync(state,text){const dot=$('syncDot'); dot.className='dot'+(state?' '+state:''); $('syncOut').textContent=text}
async function refresh(){setSync('busy','syncing…'); try{const s=await api('/api/status'); renderStatus(s); setSync('','synced '+new Date().toLocaleTimeString())}catch(e){$('cards').innerHTML='<div class="card"><div class="k">Status</div><div class="value bad">Failed</div><div class="muted small">'+esc(e.message)+'</div></div>'; setSync('err','sync failed')}}
async function startup(){try{const s=await api('/api/startup'); const strip=$('startupOut'); if(s.running){strip.className='status-strip'; strip.textContent='Checking for Aegis updates, refreshing signatures, and checking llama.cpp…'} else {const isErr=!!s.error; strip.className='status-strip '+(isErr?'err':'ok'); strip.textContent=(isErr?'⚠ ':'✓ ')+(s.summary||'Startup checks complete.'); setDetails('Startup maintenance',s); await refresh()}}catch(e){$('startupOut').innerHTML='<span class="bad">'+esc(e.message)+'</span>'}}
function renderStatus(s){
  const score=s.health_score||0;
  $('scoreNum').textContent=score+'%';
  $('scoreNum').className='num '+(score>=85?'ok':score>=65?'warn':'bad');
  $('scoreLabel').textContent=esc(s.health||'Protection score');
  $('scoreWhy').textContent=s.health_summary||'This is a posture score, not a virus probability.';
  const fw=s.firewall?.enabled;
  $('cards').innerHTML=[
   card('Firewall',fw?'Active':'Off',s.firewall?.backend||'unknown',fw?'ok':'bad','fw'),
   card('Signatures',s.signature_hashes,(s.signature_rules||0)+' rules · '+s.signature_age,'','check'),
   card('Network',s.network_flagged+' flagged',(s.network_total||0)+' connections',s.network_flagged?'warn':'ok','net'),
   card('Persistence',s.persistence_suspicious+' suspicious',(s.persistence_total||0)+' entries',s.persistence_suspicious?'warn':'ok','audit'),
   card('Ransom Shield',(s.ransom_alerts||[]).length+' alerts',(s.canaries||0)+' canaries',(s.ransom_alerts||[]).length?'bad':'ok','shield')
  ].join('');
  renderHealthWhy(s); paintIcons();
}
function renderHealthWhy(s){$('healthWhy').style.display='block'; const good=(s.health_good||[]).map(x=>'<li class="ok">'+esc(x)+'</li>').join('')||'<li class="muted">No strengths reported yet.</li>'; const issues=(s.health_issues||[]).map(x=>'<li class="warn">'+esc(x)+'</li>').join('')||'<li class="ok">No deductions right now.</li>'; $('healthWhy').innerHTML='<div class="why-grid"><div><h4>Deductions</h4><ul class="list">'+issues+'</ul></div><div><h4>Working well</h4><ul class="list">'+good+'</ul></div></div>'}
function card(k,v,n,cls,icon){return '<div class="card"><div class="k"><span class="ic" data-ic="'+icon+'"></span>'+esc(k)+'</div><div class="value '+(cls||'')+'">'+esc(v)+'</div><div class="muted small">'+esc(n)+'</div></div>'}
async function scan(){const path=$('path').value.trim()||undefined; $('scanOut').textContent='Scanning...'; try{const r=await api('/api/scan',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({path})}); $('scanOut').innerHTML=renderScan(r); setDetails('Scan result',r); await refresh()}catch(e){$('scanOut').innerHTML='<span class="bad">'+esc(e.message)+'</span>'}}
let lastThreats=[];
function renderScan(r){lastThreats=r.threats||[]; let html='<p><b>'+esc(r.scanned)+'</b> scanned · <b>'+esc(r.skipped)+'</b> skipped · '+esc(r.duration)+'</p>'; if(!lastThreats.length) return html+'<p class="ok">Clean. No signatures, rules, entropy, or ransomware patterns matched.</p>'; return html+lastThreats.map((t,i)=>{const sev=t.severity==='CRITICAL'?'bad':'warn'; return '<div class="item sev-'+sev+'" id="threat-'+i+'"><div class="item-head"><span class="who"><span class="pill '+sev+'">'+esc(t.severity)+'</span> '+esc(t.path)+'</span><button onclick="quarantineItem(this,'+i+')">Quarantine</button></div><div class="detail">'+esc(t.reason)+'</div></div>'}).join('')}
async function quarantineItem(btn,i){const t=lastThreats[i]; if(!t){return} btn.disabled=true; btn.textContent='Quarantining...'; try{const r=await api('/api/quarantine',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({path:t.path,sha256:t.sha256,reason:t.reason,severity:t.severity})}); if(r.error){throw new Error(r.error)} setDetails('Quarantine',r); btn.textContent='Quarantined'; btn.closest('.item').style.opacity='0.6'}catch(e){btn.disabled=false; btn.textContent='Quarantine'; alert('Quarantine failed: '+e.message)}}
async function updateSigs(){$('scanOut').textContent='Updating signatures and checking Aegis/llama.cpp releases...'; try{const r=await api('/api/update',{method:'POST'}); $('scanOut').innerHTML=r.error?'<span class="bad">'+esc(r.error)+'</span>':'<span class="ok">'+esc(r.summary||('Added '+r.added+' signatures; '+r.total+' total.'))+'</span>'; setDetails('Maintenance update',r); await refresh(); startup()}catch(e){$('scanOut').innerHTML='<span class="bad">'+esc(e.message)+'</span>'}}
async function shield(action){$('shieldOut').textContent='Working...'; try{const r=await api('/api/shield',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({action})}); setDetails('Ransom shield '+action,r); const events=r.events||[]; if(action==='deploy') $('shieldOut').innerHTML='<span class="ok">Armed '+(r.canaries?.length||0)+' canary files.</span>'; else if(action==='cleanup') $('shieldOut').innerHTML='Removed '+esc(r.removed||0)+' canary files.'; else $('shieldOut').innerHTML=events.length?events.map(renderEvent).join(''):'<span class="ok">No ransomware canary or sweep alerts.</span>'; await refresh()}catch(e){$('shieldOut').innerHTML='<span class="bad">'+esc(e.message)+'</span>'}}
function renderEvent(e){return '<div class="item sev-bad"><div class="item-head"><span class="who"><span class="pill bad">'+esc(e.severity||'ALERT')+'</span> '+esc(e.path)+'</span></div><div class="detail">'+esc(e.detail||e.kind)+'</div></div>'}
async function network(){$('networkOut').textContent='Refreshing network...'; try{const r=await api('/api/network'); setDetails('Network connections',r); const flagged=(r.connections||[]).filter(c=>c.suspect); $('networkOut').innerHTML=flagged.length?flagged.slice(0,12).map(c=>'<div class="item sev-warn"><div class="item-head"><span class="who"><span class="pill warn">FLAGGED</span> '+esc(c.proc)+' '+esc(c.pid)+'</span></div><div class="detail">'+esc(c.local)+' -> '+esc(c.remote||'listener')+' · '+esc(c.suspect)+'</div></div>').join(''):'<span class="ok">No risky network listeners or suspicious ports found.</span>'}catch(e){$('networkOut').innerHTML='<span class="bad">'+esc(e.message)+'</span>'}}
async function firewallStatus(){$('firewallOut').textContent='Checking firewall...'; try{const r=await api('/api/firewall'); setDetails('Firewall status',r); $('firewallOut').innerHTML=renderFirewall(r)}catch(e){$('firewallOut').innerHTML='<span class="bad">'+esc(e.message)+'</span>'}}
function renderFirewall(r){const on=r.enabled; let html='<p class="'+(on?'ok':'bad')+'">'+(on?'● Enabled':'○ Disabled')+'</p><p class="muted">'+esc(r.backend||'unknown backend'); if(r.stealth_mode) html+=' · stealth '+esc(r.stealth_mode); if(r.rule_count) html+=' · '+esc(r.rule_count)+' rules'; html+='</p>'; if(r.detail) html+='<p class="muted small">'+esc(r.detail)+'</p>'; return html}
async function firewallAction(action){$('firewallOut').textContent='Applying...'; try{const r=await api('/api/firewall',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({action})}); setDetails('Firewall '+action,r); $('firewallOut').innerHTML=r.error?'<span class="bad">'+esc(r.error)+'</span>':renderFirewall(r.status); await refresh()}catch(e){$('firewallOut').innerHTML='<span class="bad">'+esc(e.message)+'</span>'}}
async function audit(){$('auditOut').textContent='Running persistence audit...'; try{const r=await api('/api/audit'); setDetails('Persistence audit',r); const bad=(r.entries||[]).filter(e=>e.suspect); $('auditOut').innerHTML=bad.length?bad.map(e=>'<div class="item sev-warn"><div class="item-head"><span class="who"><span class="pill warn">SUSPICIOUS</span> '+esc(e.label)+'</span></div><div class="detail">'+esc(e.suspect)+' · '+esc(e.command)+'</div></div>').join(''):'<span class="ok">No suspicious startup entries found across supported locations.</span>'}catch(e){$('auditOut').innerHTML='<span class="bad">'+esc(e.message)+'</span>'}}
async function checkup(){$('checkupOut').textContent='Checking OS updates, dependency updates, and vulnerability feeds...'; try{const r=await api('/api/checkup'); setDetails('System checkup',r); $('checkupOut').innerHTML=renderCheckup(r)}catch(e){$('checkupOut').innerHTML='<span class="bad">'+esc(e.message)+'</span>'}}
function renderCheckup(r){const checks=[...(r.updates||[]),...(r.dependencies||[])]; const warn=checks.filter(c=>c.status==='warn').length, err=checks.filter(c=>c.status==='error').length; let html='<p><b>'+esc(r.os?.name||r.os?.goos)+'</b> '+esc(r.os?.version||'')+' · '+warn+' warning checks · '+err+' errors.</p>'; html+=checks.map(c=>'<div class="item sev-'+(c.status==='ok'?'ok':c.status==='warn'?'warn':'bad')+'"><div class="item-head"><span class="who"><span class="pill '+(c.status==='ok'?'ok':c.status==='warn'?'warn':'bad')+'">'+esc(c.status)+'</span> '+esc(c.name)+'</span></div><div class="detail">'+esc(c.summary)+'</div></div>').join(''); const kev=r.vulnerabilities?.recent_kev?.length||0, nvd=r.vulnerabilities?.recent_critical?.length||0; html+='<p class="'+(kev||nvd?'warn':'ok')+'" style="margin-top:12px">'+kev+' recent CISA KEV · '+nvd+' recent critical NVD CVEs.</p>'; return html}
async function aiStatus(){$('aiOut').textContent='Checking AI backend...'; try{const r=await api('/api/ai/status'); setDetails('AI status',r); const s=r.status||{}, ready=s.server_ready||s.cli_ready||s.remote_ready; $('aiOut').innerHTML='<p class="'+(ready?'ok':'warn')+'">'+(ready?'● AI backend is ready.':'○ AI backend is not ready yet.')+'</p><p class="muted">'+esc(s.message||'No status message.')+'</p><p class="muted small">Backend: '+esc(s.config?.backend||'unknown')+' · Privacy: '+esc(s.config?.privacy_mode||'metadata')+' · Notes: '+esc((r.notes||[]).length)+'</p>'}catch(e){$('aiOut').innerHTML='<span class="bad">'+esc(e.message)+'</span>'}}
async function aiSetup(){$('aiOut').textContent='Building setup guide...'; try{const r=await api('/api/ai/setup'); setDetails('AI setup plan',r); $('aiOut').innerHTML='<p><b>What this does:</b> helps you install llama.cpp, choose a small Gemma GGUF model, start a local model server, and point Aegis at it.</p><p class="muted">Recommended: '+esc(r.recommended_model||'Gemma GGUF')+'</p><h3>Steps</h3><ol class="list">'+(r.commands||[]).map(c=>'<li>'+esc(c)+'</li>').join('')+'</ol>'}catch(e){$('aiOut').innerHTML='<span class="bad">'+esc(e.message)+'</span>'}}
async function remember(){const text=$('note').value.trim(); if(!text){$('aiOut').innerHTML='<span class="warn">Write a note first.</span>'; return} try{const r=await api('/api/ai/remember',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({text})}); $('note').value=''; $('aiOut').innerHTML='<span class="ok">Saved local context note. The AI will include recent notes when explaining findings.</span>'; setDetails('AI context notes',r)}catch(e){$('aiOut').innerHTML='<span class="bad">'+esc(e.message)+'</span>'}}
async function history_(){$('historyOut').textContent='Loading quarantine history...'; try{const r=await api('/api/history'); setDetails('Quarantine history',r); renderHistory(r.quarantine||[])}catch(e){$('historyOut').innerHTML='<span class="bad">'+esc(e.message)+'</span>'}}
function renderHistory(recs){if(!recs.length){$('historyOut').innerHTML='<span class="ok">Nothing has been quarantined yet.</span>'; return} $('historyOut').innerHTML=recs.map(r=>{
  const id=esc(r.stored); const when=esc((r.when||'').replace('T',' ').slice(0,16));
  const status=r.restored?'<span class="pill ok">RESTORED</span>':'<span class="pill warn">QUARANTINED</span>';
  const action=r.restored?('<span class="muted small">restored '+esc((r.restored_at||'').replace('T',' ').slice(0,16))+'</span>')
    :('<button onclick="restoreItem(this,\''+id.replace(/'/g,"\\'")+'\')">Restore</button>');
  return '<div class="item sev-'+(r.restored?'ok':'warn')+'"><div class="item-head"><span class="who">'+status+' '+esc(r.original)+'</span>'+action+'</div><div class="detail">'+when+' · '+esc(r.reason)+'</div></div>';
}).join('')}
async function restoreItem(btn,id){btn.disabled=true; btn.textContent='Restoring...'; try{const r=await api('/api/restore',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({id})}); if(r.error){throw new Error(r.error)} setDetails('Restore',r); await history_()}catch(e){btn.disabled=false; btn.textContent='Restore'; alert('Restore failed: '+e.message)}}
initNav(); refresh(); startup(); setTimeout(startup,2500); setInterval(refresh,4000);
</script>
</body>
</html>`

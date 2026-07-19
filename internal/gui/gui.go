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
	mux.HandleFunc("/", srv.index)
	mux.HandleFunc("/api/status", srv.status)
	mux.HandleFunc("/api/scan", srv.scan)
	mux.HandleFunc("/api/update", srv.update)
	mux.HandleFunc("/api/checkup", srv.checkup)
	mux.HandleFunc("/api/network", srv.network)
	mux.HandleFunc("/api/audit", srv.audit)
	mux.HandleFunc("/api/shield", srv.shield)
	mux.HandleFunc("/api/ai/status", srv.aiStatus)
	mux.HandleFunc("/api/ai/remember", srv.aiRemember)
	mux.HandleFunc("/api/ai/setup", srv.aiSetup)
	mux.HandleFunc("/api/startup", srv.startup)
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
		report := maintenance.Startup(runCtx, s.db, version)
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
<title>Aegis GUI</title>
<style>
:root{color-scheme:dark;--bg:#11111b;--panel:#1e1e2e;--panel2:#181825;--line:#45475a;--text:#cdd6f4;--muted:#9399b2;--accent:#cba6f7;--green:#a6e3a1;--red:#f38ba8;--yellow:#f9e2af;--blue:#89b4fa}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:14px/1.55 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}button,input,textarea{font:inherit}
header{position:sticky;top:0;background:rgba(17,17,27,.9);backdrop-filter:blur(10px);border-bottom:1px solid var(--line);z-index:2}.bar{max-width:1220px;margin:0 auto;padding:14px 18px;display:flex;gap:14px;align-items:center;flex-wrap:wrap}.brand{display:inline-flex;align-items:center;background:var(--accent);color:#11111b;font-weight:800;padding:3px 10px;border-radius:4px;letter-spacing:.02em}.sub{color:var(--muted)}.sync{margin-left:auto;color:var(--muted);font-size:12px}
main{max-width:1220px;margin:0 auto;padding:22px 18px 50px}.grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:14px}.card,.panel{border:1px solid var(--line);border-radius:8px;background:var(--panel);padding:16px}.card b,.panel h2{display:block;color:var(--muted);text-transform:uppercase;letter-spacing:.04em;font-size:12px;margin:0 0 8px}.panel h3{font-size:14px;margin:14px 0 6px}.value{font-size:24px;font-weight:800}.ok{color:var(--green)}.bad{color:var(--red)}.warn{color:var(--yellow)}.blue{color:var(--blue)}.muted{color:var(--muted)}
.section{margin-top:14px}.cols{display:grid;grid-template-columns:1fr 1fr;gap:14px}.wide{grid-column:1/-1}.actions{display:flex;gap:10px;flex-wrap:wrap;margin-top:12px}button{background:var(--panel2);color:var(--text);border:1px solid var(--line);border-radius:6px;padding:9px 12px;cursor:pointer}button.primary{border-color:var(--accent);color:var(--accent)}button:hover{border-color:var(--blue)}input,textarea{width:100%;background:var(--panel2);border:1px solid var(--line);border-radius:6px;color:var(--text);padding:10px 12px}textarea{min-height:86px;resize:vertical}
pre{white-space:pre-wrap;overflow:auto;background:#11111b;border:1px solid var(--line);border-radius:6px;padding:12px;max-height:360px}.item{border-top:1px solid var(--line);padding:10px 0}.item:first-child{border-top:0}.pill{display:inline-block;border:1px solid var(--line);border-radius:999px;padding:2px 8px;margin-right:8px}.small{font-size:12px}.why{display:grid;grid-template-columns:1fr 1fr;gap:14px}.list{margin:8px 0 0;padding-left:18px}.list li{margin:4px 0}.details-head{display:flex;gap:10px;align-items:center;justify-content:space-between}.nav{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:14px}.nav button{padding:7px 10px}.nav button.active{border-color:var(--accent);color:var(--accent)}
.iconline{display:flex;flex-wrap:wrap;gap:8px;margin-top:12px}.chip{border:1px solid var(--line);border-radius:999px;background:var(--panel2);color:var(--muted);padding:4px 9px;font-size:12px}.chip b{color:var(--accent);font-weight:800}
footer{max-width:1220px;margin:0 auto;padding:0 18px 28px;color:var(--muted);font-size:12px;display:flex;flex-wrap:wrap;gap:8px 18px;align-items:center}footer a{color:var(--muted)}.repo-link{display:inline-flex;align-items:center;gap:7px}.repo-link svg{width:14px;height:14px}
@media(max-width:900px){.grid{grid-template-columns:repeat(2,minmax(0,1fr))}.cols,.why{grid-template-columns:1fr}.sync{margin-left:0}}@media(max-width:540px){.grid{grid-template-columns:1fr}.value{font-size:20px}.bar{align-items:flex-start}main{padding-inline:12px}.actions button{width:100%}}
</style>
</head>
<body>
<header><div class="bar"><div class="brand">AEGIS</div><div class="sub">local browser GUI · same core as the TUI · 127.0.0.1 only</div><div class="sync" id="syncOut">syncing with local core</div></div></header>
<main>
  <div class="nav" id="nav"></div>
  <section class="panel" id="startupBox"><h2>Startup Maintenance</h2><div id="startupOut" class="muted">Checking Aegis updates, refreshing signatures, and checking llama.cpp...</div></section>
  <section class="iconline" aria-label="Aegis modules"><span class="chip"><b>01</b> scanner</span><span class="chip"><b>02</b> shield</span><span class="chip"><b>03</b> network</span><span class="chip"><b>04</b> firewall</span><span class="chip"><b>05</b> audit</span><span class="chip"><b>06</b> ai</span><span class="chip"><b>ok</b> suspiciously useful</span></section>
  <section class="grid section" id="cards"></section>
  <section class="panel why section" id="healthWhy" style="display:none"></section>
  <section class="cols section">
    <div class="panel view" data-view="dashboard scan">
      <h2>Scanner</h2>
      <p class="muted">Scan a folder or file with the same hash, rule, entropy, extension, and EICAR checks used by the TUI.</p>
      <input id="path" placeholder="Path to scan, e.g. ~/Downloads or /tmp">
      <div class="actions"><button class="primary" onclick="scan()">Scan Path</button><button onclick="updateSigs()">Update & Check Versions</button><button onclick="refresh()">Refresh Status</button></div>
      <div id="scanOut" class="muted" style="margin-top:12px">Choose a folder or file and run a scan.</div>
    </div>
    <div class="panel view" data-view="dashboard shield">
      <h2>Ransom Shield</h2>
      <p class="muted">Canaries are harmless decoy files placed in common folders. If they disappear or change, Aegis treats it as a strong ransomware signal.</p>
      <div class="actions"><button class="primary" onclick="shield('deploy')">Arm Canaries</button><button onclick="shield('check')">Check Shield</button><button onclick="shield('cleanup')">Remove Canaries</button></div>
      <div id="shieldOut" class="muted" style="margin-top:12px">Ready to arm or check ransomware canaries.</div>
    </div>
    <div class="panel view" data-view="dashboard network">
      <h2>Network</h2>
      <p class="muted">Lists live connections and highlights risky listeners or ports often used by backdoors.</p>
      <div class="actions"><button class="primary" onclick="network()">Refresh Network</button></div>
      <div id="networkOut" class="muted" style="margin-top:12px">Network details will appear here.</div>
    </div>
    <div class="panel view" data-view="dashboard audit">
      <h2>Persistence Audit</h2>
      <p class="muted">Checks startup locations such as LaunchAgents, systemd, cron, autostart folders, and Windows Run keys.</p>
      <div class="actions"><button class="primary" onclick="audit()">Run Audit</button></div>
      <div id="auditOut" class="muted" style="margin-top:12px">Audit details will appear here.</div>
    </div>
    <div class="panel view" data-view="dashboard checkup">
      <h2>System Checkup</h2>
      <p class="muted">Checks OS updates, dependency updates, and recent CISA/NVD vulnerability feeds. It is read-only.</p>
      <div class="actions"><button class="primary" onclick="checkup()">Run Checkup</button></div>
      <div id="checkupOut" class="muted" style="margin-top:12px">Run this when you want to know what needs updating.</div>
    </div>
    <div class="panel view" data-view="dashboard ai">
      <h2>AI Assistant</h2>
      <p class="muted">Shows local llama.cpp readiness and the setup path. The model is advisory only; detections still come from signatures, rules, canaries, and audits.</p>
      <div class="actions"><button class="primary" onclick="aiStatus()">Check AI Status</button><button onclick="aiSetup()">Setup Guide</button></div>
      <h3>Remember Local Context</h3>
      <textarea id="note" placeholder="Example: This Mac is used for development; ignore known local dev servers on 127.0.0.1."></textarea>
      <div class="actions"><button onclick="remember()">Remember Note</button></div>
      <div id="aiOut" class="muted" style="margin-top:12px">AI status will appear here.</div>
    </div>
    <div class="panel wide view" data-view="dashboard details">
      <div class="details-head"><h2>Details</h2><button onclick="copyDetails()">Copy JSON</button></div>
      <p class="muted">Raw output is kept here for debugging, support, or pasting into an issue. The panels above summarize what it means.</p>
      <pre id="detailsOut">No details yet.</pre>
    </div>
  </section>
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
const views=['dashboard','scan','shield','network','audit','checkup','ai','details'];
function esc(s){return String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));}
function setDetails(name,obj){lastJSON=JSON.stringify(obj,null,2); $('detailsOut').textContent=name?name+'\n\n'+lastJSON:lastJSON}
function copyDetails(){if(!lastJSON){return} navigator.clipboard?.writeText(lastJSON).then(()=>{$('detailsOut').textContent='Copied JSON to clipboard.\n\n'+lastJSON}).catch(()=>{$('detailsOut').focus();document.execCommand('selectAll');document.execCommand('copy')})}
async function api(path,opts){const r=await fetch(path,opts); if(!r.ok) throw new Error(await r.text()); return r.json();}
function initNav(){ $('nav').innerHTML=views.map(v=>'<button id="nav-'+v+'" onclick="showView(\''+v+'\')">'+label(v)+'</button>').join(''); showView(currentView)}
function label(v){return {dashboard:'Dashboard',scan:'Scanner',shield:'Shield',network:'Network',audit:'Audit',checkup:'Checkup',ai:'AI',details:'Details'}[v]||v}
function showView(v){currentView=v; document.querySelectorAll('.view').forEach(el=>{const tags=el.dataset.view.split(' '); el.style.display=(v==='dashboard'||tags.includes(v))?'block':'none'}); views.forEach(x=>$('nav-'+x)?.classList.toggle('active',x===v))}
async function refresh(){try{const s=await api('/api/status'); renderStatus(s); $('syncOut').textContent='synced '+new Date().toLocaleTimeString()}catch(e){$('cards').innerHTML='<div class="card bad">Status failed<br>'+esc(e.message)+'</div>'; $('syncOut').textContent='sync failed'}}
async function startup(){try{const s=await api('/api/startup'); $('startupOut').innerHTML=s.running?'Checking for Aegis updates, refreshing signatures, and checking llama.cpp...':esc(s.summary||'Startup checks complete.'); if(!s.running) setDetails('Startup maintenance',s); if(!s.running) await refresh()}catch(e){$('startupOut').innerHTML='<span class="bad">'+esc(e.message)+'</span>'}}
function renderStatus(s){const fw=s.firewall?.enabled; $('cards').innerHTML=[
 card('Protection Score',s.health_score+'%',s.health,s.health_score>=85?'ok':s.health_score>=65?'warn':'bad'),
 card('Firewall',fw?'Active':'Off',s.firewall?.backend||'unknown',fw?'ok':'bad'),
 card('Signatures',s.signature_hashes,(s.signature_rules||0)+' rules · '+s.signature_age,''),
 card('Network',s.network_flagged+' flagged',(s.network_total||0)+' connections',s.network_flagged?'warn':'ok'),
 card('Persistence',s.persistence_suspicious+' suspicious',(s.persistence_total||0)+' entries',s.persistence_suspicious?'warn':'ok'),
 card('Ransom Shield',(s.ransom_alerts||[]).length+' alerts',(s.canaries||0)+' canaries',(s.ransom_alerts||[]).length?'bad':'ok')
].join(''); renderHealthWhy(s)}
function renderHealthWhy(s){$('healthWhy').style.display='grid'; const good=(s.health_good||[]).map(x=>'<li class="ok">'+esc(x)+'</li>').join('')||'<li class="muted">No strengths reported yet.</li>'; const issues=(s.health_issues||[]).map(x=>'<li class="warn">'+esc(x)+'</li>').join('')||'<li class="ok">No deductions right now.</li>'; $('healthWhy').innerHTML='<div><h2>What '+esc(s.health_score)+'% means</h2><p class="muted">'+esc(s.health_summary||'Protection score summarizes current local security posture.')+'</p></div><div><h2>Deductions</h2><ul class="list">'+issues+'</ul><h2 style="margin-top:14px">Working well</h2><ul class="list">'+good+'</ul></div>'}
function card(k,v,n,cls){return '<div class="card"><b>'+esc(k)+'</b><div class="value '+(cls||'')+'">'+esc(v)+'</div><div class="muted">'+esc(n)+'</div></div>'}
async function scan(){const path=$('path').value.trim()||undefined; $('scanOut').textContent='Scanning...'; try{const r=await api('/api/scan',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({path})}); $('scanOut').innerHTML=renderScan(r); setDetails('Scan result',r); await refresh()}catch(e){$('scanOut').innerHTML='<span class="bad">'+esc(e.message)+'</span>'}}
function renderScan(r){let html='<p><b>'+esc(r.scanned)+'</b> scanned · <b>'+esc(r.skipped)+'</b> skipped · '+esc(r.duration)+'</p>'; if(!r.threats?.length) return html+'<p class="ok">Clean. No signatures, rules, entropy, or ransomware patterns matched.</p>'; return html+r.threats.map(t=>'<div class="item"><span class="pill '+(t.severity==='CRITICAL'?'bad':'warn')+'">'+esc(t.severity)+'</span>'+esc(t.path)+'<br><span class="muted">'+esc(t.reason)+'</span></div>').join('')}
async function updateSigs(){$('scanOut').textContent='Updating signatures and checking Aegis/llama.cpp releases...'; try{const r=await api('/api/update',{method:'POST'}); $('scanOut').innerHTML=r.error?'<span class="bad">'+esc(r.error)+'</span>':'<span class="ok">'+esc(r.summary||('Added '+r.added+' signatures; '+r.total+' total.'))+'</span>'; setDetails('Maintenance update',r); await refresh(); startup()}catch(e){$('scanOut').innerHTML='<span class="bad">'+esc(e.message)+'</span>'}}
async function shield(action){$('shieldOut').textContent='Working...'; try{const r=await api('/api/shield',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({action})}); setDetails('Ransom shield '+action,r); const events=r.events||[]; if(action==='deploy') $('shieldOut').innerHTML='<span class="ok">Armed '+(r.canaries?.length||0)+' canary files.</span>'; else if(action==='cleanup') $('shieldOut').innerHTML='Removed '+esc(r.removed||0)+' canary files.'; else $('shieldOut').innerHTML=events.length?events.map(renderEvent).join(''):'<span class="ok">No ransomware canary or sweep alerts.</span>'; await refresh()}catch(e){$('shieldOut').innerHTML='<span class="bad">'+esc(e.message)+'</span>'}}
function renderEvent(e){return '<div class="item"><span class="pill bad">'+esc(e.severity||'ALERT')+'</span>'+esc(e.path)+'<br><span class="muted">'+esc(e.detail||e.kind)+'</span></div>'}
async function network(){$('networkOut').textContent='Refreshing network...'; try{const r=await api('/api/network'); setDetails('Network connections',r); const flagged=(r.connections||[]).filter(c=>c.suspect); $('networkOut').innerHTML=flagged.length?flagged.slice(0,12).map(c=>'<div class="item"><span class="pill warn">FLAGGED</span>'+esc(c.proc)+' '+esc(c.pid)+'<br><span class="muted">'+esc(c.local)+' -> '+esc(c.remote||'listener')+' · '+esc(c.suspect)+'</span></div>').join(''):'<span class="ok">No risky network listeners or suspicious ports found.</span>'}catch(e){$('networkOut').innerHTML='<span class="bad">'+esc(e.message)+'</span>'}}
async function audit(){$('auditOut').textContent='Running persistence audit...'; try{const r=await api('/api/audit'); setDetails('Persistence audit',r); const bad=(r.entries||[]).filter(e=>e.suspect); $('auditOut').innerHTML=bad.length?bad.map(e=>'<div class="item"><span class="pill warn">SUSPICIOUS</span>'+esc(e.label)+'<br><span class="muted">'+esc(e.suspect)+' · '+esc(e.command)+'</span></div>').join(''):'<span class="ok">No suspicious startup entries found across supported locations.</span>'}catch(e){$('auditOut').innerHTML='<span class="bad">'+esc(e.message)+'</span>'}}
async function checkup(){$('checkupOut').textContent='Checking OS updates, dependency updates, and vulnerability feeds...'; try{const r=await api('/api/checkup'); setDetails('System checkup',r); $('checkupOut').innerHTML=renderCheckup(r)}catch(e){$('checkupOut').innerHTML='<span class="bad">'+esc(e.message)+'</span>'}}
function renderCheckup(r){const checks=[...(r.updates||[]),...(r.dependencies||[])]; const warn=checks.filter(c=>c.status==='warn').length, err=checks.filter(c=>c.status==='error').length; let html='<p><b>'+esc(r.os?.name||r.os?.goos)+'</b> '+esc(r.os?.version||'')+' · '+warn+' warning checks · '+err+' errors.</p>'; html+=checks.map(c=>'<div class="item"><span class="pill '+(c.status==='ok'?'ok':c.status==='warn'?'warn':'bad')+'">'+esc(c.status)+'</span>'+esc(c.name)+'<br><span class="muted">'+esc(c.summary)+'</span></div>').join(''); const kev=r.vulnerabilities?.recent_kev?.length||0, nvd=r.vulnerabilities?.recent_critical?.length||0; html+='<p class="'+(kev||nvd?'warn':'ok')+'">'+kev+' recent CISA KEV · '+nvd+' recent critical NVD CVEs.</p>'; return html}
async function aiStatus(){$('aiOut').textContent='Checking AI backend...'; try{const r=await api('/api/ai/status'); setDetails('AI status',r); const s=r.status||{}, ready=s.server_ready||s.cli_ready||s.remote_ready; $('aiOut').innerHTML='<p class="'+(ready?'ok':'warn')+'">'+(ready?'AI backend is ready.':'AI backend is not ready yet.')+'</p><p class="muted">'+esc(s.message||'No status message.')+'</p><p class="muted">Backend: '+esc(s.config?.backend||'unknown')+' · Privacy: '+esc(s.config?.privacy_mode||'metadata')+' · Notes: '+esc((r.notes||[]).length)+'</p>'}catch(e){$('aiOut').innerHTML='<span class="bad">'+esc(e.message)+'</span>'}}
async function aiSetup(){$('aiOut').textContent='Building setup guide...'; try{const r=await api('/api/ai/setup'); setDetails('AI setup plan',r); $('aiOut').innerHTML='<p><b>What this does:</b> helps you install llama.cpp, choose a small Gemma GGUF model, start a local model server, and point Aegis at it.</p><p class="muted">Recommended: '+esc(r.recommended_model||'Gemma GGUF')+'</p><h3>Steps</h3><ol class="list">'+(r.commands||[]).map(c=>'<li>'+esc(c)+'</li>').join('')+'</ol>'}catch(e){$('aiOut').innerHTML='<span class="bad">'+esc(e.message)+'</span>'}}
async function remember(){const text=$('note').value.trim(); if(!text){$('aiOut').innerHTML='<span class="warn">Write a note first.</span>'; return} try{const r=await api('/api/ai/remember',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({text})}); $('note').value=''; $('aiOut').innerHTML='<span class="ok">Saved local context note. The AI will include recent notes when explaining findings.</span>'; setDetails('AI context notes',r)}catch(e){$('aiOut').innerHTML='<span class="bad">'+esc(e.message)+'</span>'}}
initNav(); refresh(); startup(); setTimeout(startup,2500); setInterval(refresh,4000);
</script>
</body>
</html>`

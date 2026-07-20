// aegis — a fast, minimal internet-security TUI: malware & ransomware scanning,
// firewall control, network monitoring and persistence auditing in one static
// binary.
//
//	aegis            launch the TUI
//	aegis scan PATH  headless scan (exit code 1 if threats found)
//	aegis shield     ransomware sweep (canaries + notes + encrypted files)
//	aegis audit      list autostart / persistence entries, flag suspicious ones
//	aegis analyze    disk exposure summary
//	aegis clamav     optional local ClamAV daemon scan
//	aegis ai         local/remote security analyst
//	aegis checkup    OS/dependency/vulnerability update check
//	aegis intel HASH optional OSINT reputation lookup for a file hash
//	aegis gui        local browser GUI
//	aegis app        TUI + local browser GUI together
//	aegis history    list quarantine history
//	aegis restore ID undo a quarantine (by stored path or hash)
//	aegis update     refresh signatures, check for aegis/llama.cpp updates
//	aegis status     one-shot security summary
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/andreipaciurca/aegis/internal/ai"
	"github.com/andreipaciurca/aegis/internal/appsync"
	"github.com/andreipaciurca/aegis/internal/checkup"
	"github.com/andreipaciurca/aegis/internal/clamav"
	"github.com/andreipaciurca/aegis/internal/diskanalyze"
	"github.com/andreipaciurca/aegis/internal/firewall"
	"github.com/andreipaciurca/aegis/internal/gui"
	"github.com/andreipaciurca/aegis/internal/intel"
	"github.com/andreipaciurca/aegis/internal/maintenance"
	"github.com/andreipaciurca/aegis/internal/netmon"
	"github.com/andreipaciurca/aegis/internal/persist"
	"github.com/andreipaciurca/aegis/internal/ransom"
	"github.com/andreipaciurca/aegis/internal/rules"
	"github.com/andreipaciurca/aegis/internal/scanner"
	"github.com/andreipaciurca/aegis/internal/signatures"
	"github.com/andreipaciurca/aegis/internal/ui"
)

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "version", "--version", "-v":
			fmt.Println("aegis", ui.Version)
			return
		case "help", "--help", "-h":
			if len(os.Args) > 2 {
				commandUsage(os.Args[2])
			} else {
				usage()
			}
			return
		}
		if len(os.Args) > 2 && isHelpFlag(os.Args[2]) {
			commandUsage(os.Args[1])
			return
		}
	}

	db, err := signatures.Load()
	if err != nil {
		fmt.Fprintln(os.Stderr, "aegis: cannot load signatures:", err)
		os.Exit(2)
	}
	cfgDir, _ := signatures.Dir()
	eng, _ := rules.Load(cfgDir)

	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "scan":
			os.Exit(cliScan(db, eng, os.Args[2:]))
		case "shield":
			os.Exit(cliShield(os.Args[2:]))
		case "audit":
			os.Exit(cliAudit(os.Args[2:]))
		case "analyze", "analyse":
			os.Exit(cliAnalyze(os.Args[2:]))
		case "clamav":
			os.Exit(cliClamAV(os.Args[2:]))
		case "ai":
			os.Exit(cliAI(os.Args[2:]))
		case "checkup":
			os.Exit(cliCheckup(os.Args[2:]))
		case "intel", "vt":
			os.Exit(cliIntel(os.Args[2:]))
		case "gui":
			os.Exit(cliGUI(db, eng, os.Args[2:]))
		case "app":
			os.Exit(cliApp(db, eng, os.Args[2:]))
		case "history":
			os.Exit(cliHistory(os.Args[2:]))
		case "restore":
			os.Exit(cliRestore(os.Args[2:]))
		case "update":
			os.Exit(cliUpdate(db, os.Args[2:]))
		case "status":
			os.Exit(cliStatus(db, eng, os.Args[2:]))
		default:
			fmt.Fprintln(os.Stderr, "aegis: unknown command:", os.Args[1])
			usage()
			os.Exit(2)
		}
	}

	os.Exit(runTUI(db, eng))
}

func usage() {
	fmt.Println(`aegis — terminal internet security

usage:
  aegis                 launch the TUI
  aegis app             launch TUI + local GUI together
  aegis help <topic>    explain one command

everyday:
  scan PATH             scan files; exit 1 only when threats are found
  status                one-shot local protection summary
  update                refresh signatures, check for aegis/llama.cpp updates
  gui                   local browser GUI

protection:
  shield                ransomware canaries + encrypted-file sweep
  firewall              use the TUI Firewall tab for native firewall controls
  audit                 persistence/autostart audit
  network               use the TUI Network tab for live connections

advanced:
  checkup               OS, dependency, and vulnerability feed checks
  ai                    local/remote analyst setup, chat and explanations
  intel HASH            optional VirusTotal hash lookup
  clamav PATH           optional local ClamAV daemon scan
  analyze PATH          disk exposure summary
  history               quarantine history
  restore ID            undo a quarantine (stored path or hash from history)

try:
  aegis app
  aegis scan ~/Downloads
  aegis help scan`)
}

func commandUsage(topic string) {
	switch topic {
	case "scan":
		fmt.Println(`aegis scan PATH [--json] [--full-paths] [--ai]

Scans a file or folder with hash signatures, built-in rules, entropy checks,
extension checks and the safe EICAR test signature.

Exit codes: 0 clean, 1 threats found, 2 scan error.`)
	case "shield":
		fmt.Println(`aegis shield [--json]

Checks ransomware canaries, ransom-note names, known ransomware extensions and
encrypted-file patterns in common user folders. Use the TUI Shield tab to deploy
or remove canaries interactively.`)
	case "audit":
		fmt.Println(`aegis audit [--json]

Lists autostart and persistence entries and flags suspicious commands, temp-dir
payloads and encoded launchers. The TUI Audit tab shows exact disable commands.`)
	case "firewall":
		fmt.Println(`aegis firewall

Firewall controls live in the TUI Firewall tab: press 5, then e enable,
d disable, or t toggle stealth when supported. This keeps privileged actions
visible and confirmable.`)
	case "network":
		fmt.Println(`aegis network

Network controls live in the TUI Network tab: press 4 to view connections,
select a row, k to terminate a process, or b to show a firewall block command.`)
	case "status":
		fmt.Println(`aegis status [--json]

Prints a quick posture summary: firewall, signatures, canaries, persistence and
network exposure. The score is a local posture score, not a virus probability.`)
	case "checkup":
		fmt.Println(`aegis checkup [--json] [--offline]

Checks OS/dependency update signals and recent CISA KEV/NVD vulnerability feeds.
Use --offline to skip online vulnerability feeds.`)
	case "ai":
		fmt.Println(`aegis ai status
aegis ai setup [--download-llama]
aegis ai config --backend llamacpp-server --endpoint URL
aegis ai test [prompt]
aegis ai chat
aegis ai remember <note>
aegis ai context

Configures an optional analyst. AI is advisory: it explains findings but never
overrides signatures, rules, canaries or audits.`)
	case "intel", "vt":
		fmt.Println(`aegis intel HASH [--json] [--api-key-env VT_API_KEY]

Optional VirusTotal API v3 file reputation lookup. Aegis sends only the hash you
provide; normal scans never call VirusTotal or upload files.`)
	case "clamav":
		fmt.Println(`aegis clamav PATH [--json] [--addr tcp://127.0.0.1:3310]

Streams files to your own local clamd daemon with ClamAV INSTREAM. Install and
start ClamAV yourself; Aegis does not bundle ClamAV or its databases.`)
	case "gui":
		fmt.Println(`aegis gui [--no-open] [--socket PATH]

Starts the local browser GUI on 127.0.0.1 only. Use aegis app for TUI + GUI sync.
--socket also serves the API on a Unix domain socket at PATH, for a native app
shell to talk to instead of opening a browser tab (macOS/Linux, and Windows
10 1809+ / Server 2019+; older Windows falls back to TCP only).`)
	case "app":
		fmt.Println(`aegis app [--no-open] [--socket PATH]

Starts the TUI and local browser GUI together so GUI actions appear in the TUI.
--socket also serves the API on a Unix domain socket at PATH; see aegis gui --help.`)
	case "analyze", "analyse":
		fmt.Println(`aegis analyze [PATH] [--json]

Summarizes top disk locations and large files. Useful for spotting exposed or
unexpectedly large folders before scanning.`)
	case "history":
		fmt.Println(`aegis history [--json]

Shows quarantine history, newest first. Each record's "stored" path is the ID
to pass to aegis restore.`)
	case "restore":
		fmt.Println(`aegis restore <stored-path|sha256> [--json]

Undoes a quarantine: moves the file back to its original location and marks
the record as restored. Refuses to run twice on the same record and refuses
to overwrite a file that already exists at the original path. Find the ID to
pass with aegis history, or in the TUI Scanner tab (press v, then x).`)
	case "update":
		fmt.Println(`aegis update [--json]

Refreshes malware signatures from public abuse.ch defensive feeds, and checks
whether a newer aegis release or llama.cpp release is available — the same
checks that run at TUI/GUI startup and on pressing u. aegis never
self-replaces its own binary; if a newer release exists, this prints the
release URL so you can re-run the install script or download it yourself.`)
	default:
		fmt.Fprintf(os.Stderr, "aegis: unknown help topic %q\n\n", topic)
		usage()
	}
}

func isHelpFlag(s string) bool {
	return s == "--help" || s == "-h" || s == "help"
}

func runTUI(db *signatures.DB, eng *rules.Engine) int {
	return runTUIWithStartup(db, eng, true)
}

func runTUIWithStartup(db *signatures.DB, eng *rules.Engine, startup bool) int {
	p := tea.NewProgram(ui.NewWithOptions(db, eng, ui.Options{StartupMaintenance: startup}), tea.WithAltScreen())
	if _, err := p.Run(); err != nil {
		fmt.Fprintln(os.Stderr, "aegis:", err)
		return 1
	}
	return 0
}

func cliScan(db *signatures.DB, eng *rules.Engine, args []string) int {
	args, jsonMode := splitJSON(args)
	args, aiMode := splitBoolFlag(args, "--ai")
	args, fullPaths := splitBoolFlag(args, "--full-paths")
	root, _ := os.UserHomeDir()
	if len(args) > 0 {
		root = args[0]
	}
	if !jsonMode {
		c := newCLIColors()
		fmt.Printf("%s %s  %s signatures · %s rules\n",
			c.Blue("scan"), c.Bold(root), c.Muted(fmt.Sprint(db.Count())), c.Muted(fmt.Sprint(eng.Count())))
	}
	cancel := make(chan struct{})
	var final scanner.Progress
	for p := range scanner.Scan(root, db, eng, cancel) {
		if p.Phase == "done" || p.Phase == "cancelled" || p.Phase == "error" {
			final = p
		}
	}
	if final.Phase == "cancelled" {
		if jsonMode {
			encodeJSON(scanJSON(root, final))
		}
		fmt.Fprintln(os.Stderr, "scan cancelled")
		return 130
	}
	if final.Err != nil {
		if jsonMode {
			encodeJSON(scanJSON(root, final))
		}
		fmt.Fprintln(os.Stderr, "scan error:", final.Err)
		return 2
	}
	if jsonMode {
		encodeJSON(scanJSON(root, final))
		if len(final.Threats) > 0 {
			return 1
		}
		return 0
	}
	printScanReport(root, final, fullPaths)
	if aiMode {
		printAIThreatExplanations(final.Threats)
	}
	if len(final.Threats) > 0 {
		return 1
	}
	return 0
}

func cliShield(args []string) int {
	_, jsonMode := splitJSON(args)
	dirs := ransom.DefaultDirs()
	events := ransom.Check(dirs)
	if jsonMode {
		encodeJSON(map[string]any{
			"directories": dirs,
			"events":      events,
			"clean":       len(events) == 0,
		})
		if len(events) > 0 {
			return 1
		}
		return 0
	}
	fmt.Printf("ransomware sweep across %d folder(s)…\n", len(dirs))
	if len(events) == 0 {
		fmt.Println("no ransomware indicators ✓")
		return 0
	}
	fmt.Printf("%d indicator(s):\n", len(events))
	for _, e := range events {
		fmt.Printf("  [%s] %s — %s\n", e.Severity, e.Path, e.Detail)
	}
	return 1
}

func cliAudit(args []string) int {
	_, jsonMode := splitJSON(args)
	entries := persist.Audit()
	susp := 0
	for _, e := range entries {
		if e.Suspect != "" {
			susp++
		}
	}
	if jsonMode {
		encodeJSON(map[string]any{
			"entries":    entries,
			"suspicious": susp,
			"clean":      susp == 0,
		})
		return 0
	}
	fmt.Printf("%d autostart / persistence entries, %d suspicious\n", len(entries), susp)
	for _, e := range entries {
		if e.Suspect != "" {
			fmt.Printf("  ⚠ [%s] %s — %s\n     runs: %s\n     fix:  %s\n",
				e.Source, e.Label, e.Suspect, e.Command, e.DisableCmd)
		}
	}
	if susp == 0 {
		fmt.Println("nothing suspicious ✓")
	}
	return 0
}

func cliAnalyze(args []string) int {
	args, jsonMode := splitJSON(args)
	root, _ := os.UserHomeDir()
	if len(args) > 0 {
		root = args[0]
	}
	report, err := diskanalyze.Analyze(root)
	if err != nil {
		fmt.Fprintln(os.Stderr, "analyze failed:", err)
		return 2
	}
	if jsonMode {
		encodeJSON(report)
		return 0
	}
	fmt.Printf("Analyze Disk  %s  (%d files, %d skipped)\n", report.Path, report.TotalFiles, report.Skipped)
	fmt.Printf("Total scanned: %s\n\n", humanBytes(report.TotalSize))
	fmt.Println("Top locations:")
	limit := minInt(len(report.Entries), 8)
	for i := 0; i < limit; i++ {
		e := report.Entries[i]
		pct := 0.0
		if report.TotalSize > 0 {
			pct = float64(e.Size) * 100 / float64(report.TotalSize)
		}
		fmt.Printf("  %2d. %-34s %8s  %5.1f%%\n", i+1, truncateName(e.Name, 34), humanBytes(e.Size), pct)
	}
	if len(report.LargeFiles) > 0 {
		fmt.Println("\nLarge files to review:")
		for _, f := range report.LargeFiles {
			fmt.Printf("  %-8s %-18s %s\n", humanBytes(f.Size), f.Reason, f.Path)
		}
	}
	return 0
}

func cliClamAV(args []string) int {
	args, jsonMode := splitJSON(args)
	addr := clamav.DefaultAddress
	clean := args[:0]
	for i := 0; i < len(args); i++ {
		if args[i] == "--addr" {
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "usage: aegis clamav PATH [--json] [--addr tcp://127.0.0.1:3310]")
				return 2
			}
			i++
			addr = args[i]
			continue
		}
		clean = append(clean, args[i])
	}
	root := "."
	if len(clean) > 0 {
		root = clean[0]
	}
	client, err := clamav.New(addr)
	if err != nil {
		if jsonMode {
			encodeJSON(clamav.Report{Root: root, Error: err.Error()})
		} else {
			fmt.Fprintln(os.Stderr, "clamav:", err)
		}
		return 2
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := client.Ping(ctx); err != nil {
		msg := "cannot reach clamd at " + addr + ": " + err.Error()
		if jsonMode {
			encodeJSON(clamav.Report{Root: root, Error: msg})
		} else {
			fmt.Fprintln(os.Stderr, "clamav:", msg)
			fmt.Fprintln(os.Stderr, "hint: install ClamAV, run freshclam, start clamd, then retry. Files stay on this machine.")
		}
		return 2
	}
	report := client.ScanPath(ctx, root)
	if jsonMode {
		encodeJSON(report)
		if len(report.Findings) > 0 {
			return 1
		}
		if report.Error != "" {
			return 2
		}
		return 0
	}
	printClamAVReport(report, addr)
	if len(report.Findings) > 0 {
		return 1
	}
	if report.Error != "" {
		return 2
	}
	return 0
}

func cliAI(args []string) int {
	cfg, err := ai.Load()
	if err != nil {
		fmt.Fprintln(os.Stderr, "ai:", err)
		return 1
	}
	if len(args) == 0 || args[0] == "status" {
		status := ai.Check(cfg)
		encodeJSON(status)
		return 0
	}
	switch args[0] {
	case "setup":
		return cliAISetup(args[1:]...)
	case "config":
		cfg = applyAIConfig(cfg, args[1:])
		if err := ai.Save(cfg); err != nil {
			fmt.Fprintln(os.Stderr, "ai config:", err)
			return 1
		}
		encodeJSON(cfg)
		return 0
	case "test":
		prompt := "Briefly explain what Aegis is."
		if len(args) > 1 {
			prompt = strings.Join(args[1:], " ")
		}
		return runAIPrompt(cfg, prompt)
	case "chat":
		return runAIChat(cfg)
	case "remember":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "usage: aegis ai remember <note>")
			return 2
		}
		if err := ai.AddNote(strings.Join(args[1:], " ")); err != nil {
			fmt.Fprintln(os.Stderr, "ai remember:", err)
			return 1
		}
		fmt.Println("remembered")
		return 0
	case "context":
		notes, err := ai.Notes()
		if err != nil {
			fmt.Fprintln(os.Stderr, "ai context:", err)
			return 1
		}
		encodeJSON(notes)
		return 0
	default:
		fmt.Fprintln(os.Stderr, "usage: aegis ai status | setup | config [--backend ... --endpoint ... --model ... --remote-model ... --command ... --api-key-env ... --privacy metadata|excerpt] | test [prompt] | chat | remember <note> | context")
		return 2
	}
}

func cliAISetup(args ...string) int {
	opts := ai.SetupOptions{}
	for _, a := range args {
		if a == "--download-llama" {
			opts.DownloadLlama = true
		}
	}
	plan, err := ai.RunSetup(opts)
	if err != nil {
		fmt.Fprintln(os.Stderr, "ai setup:", err)
		return 1
	}
	encodeJSON(plan)
	return 0
}

func cliCheckup(args []string) int {
	args, jsonMode := splitJSON(args)
	offline := false
	for _, a := range args {
		if a == "--offline" {
			offline = true
		}
	}
	report := checkup.Run(checkup.Options{Offline: offline})
	if jsonMode {
		encodeJSON(report)
		return checkupExit(report)
	}
	fmt.Printf("Security Checkup  %s/%s  %s", report.OS.GOOS, report.OS.GOARCH, report.OS.Name)
	if report.OS.Version != "" {
		fmt.Printf(" %s", report.OS.Version)
	}
	fmt.Println()
	printChecks("OS Updates", report.Updates)
	printChecks("Dependencies", report.Dependencies)
	printVulnerabilitySummary(report.Vulnerabilities)
	if len(report.Recommendations) > 0 {
		fmt.Println("\nRecommendations:")
		for _, r := range report.Recommendations {
			fmt.Println("  - " + r)
		}
	}
	if len(report.UnsupportedChecks) > 0 {
		fmt.Println("\nUnsupported or inconclusive checks:")
		for _, r := range report.UnsupportedChecks {
			fmt.Println("  - " + r)
		}
	}
	return checkupExit(report)
}

func cliIntel(args []string) int {
	args, jsonMode := splitJSON(args)
	apiKeyEnv := "VT_API_KEY"
	clean := args[:0]
	for i := 0; i < len(args); i++ {
		if args[i] == "--api-key-env" {
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "usage: aegis intel <hash> [--json] [--api-key-env NAME]")
				return 2
			}
			i++
			apiKeyEnv = args[i]
			continue
		}
		clean = append(clean, args[i])
	}
	if len(clean) != 1 {
		fmt.Fprintln(os.Stderr, "usage: aegis intel <md5|sha1|sha256> [--json] [--api-key-env NAME]")
		return 2
	}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	report, err := intel.VirusTotalClient{APIKey: os.Getenv(apiKeyEnv)}.LookupFile(ctx, clean[0])
	if err != nil {
		report.Error = err.Error()
		if jsonMode {
			encodeJSON(report)
		} else {
			fmt.Fprintln(os.Stderr, "intel:", err)
			if strings.Contains(err.Error(), "API key") {
				fmt.Fprintf(os.Stderr, "hint: export %s=... and retry. Aegis only sends the hash you provide.\n", apiKeyEnv)
			}
		}
		return 1
	}
	if jsonMode {
		encodeJSON(report)
		return 0
	}
	printIntelReport(report)
	if report.Error != "" {
		return 1
	}
	return 0
}

// parseGUIFlags reads the flags shared by `aegis gui` and `aegis app`:
// --no-open (skip launching a browser tab) and --socket <path> (also serve
// the API on a Unix domain socket, for a future native app shell).
func parseGUIFlags(args []string) (open bool, socket string) {
	open = true
	for i := 0; i < len(args); i++ {
		switch {
		case args[i] == "--no-open":
			open = false
		case args[i] == "--socket" && i+1 < len(args):
			i++
			socket = args[i]
		case strings.HasPrefix(args[i], "--socket="):
			socket = strings.TrimPrefix(args[i], "--socket=")
		}
	}
	return open, socket
}

func cliGUI(db *signatures.DB, eng *rules.Engine, args []string) int {
	open, socket := parseGUIFlags(args)
	if err := gui.Run(context.Background(), db, eng, gui.Options{OpenBrowser: open, Version: ui.Version, Socket: socket}); err != nil && err != context.Canceled {
		fmt.Fprintln(os.Stderr, "gui:", err)
		return 1
	}
	return 0
}

func cliApp(db *signatures.DB, eng *rules.Engine, args []string) int {
	open, socket := parseGUIFlags(args)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	p := tea.NewProgram(ui.NewWithOptions(db, eng, ui.Options{StartupMaintenance: false}), tea.WithAltScreen())
	go func() {
		errCh <- gui.Run(ctx, db, eng, gui.Options{
			OpenBrowser: open,
			Version:     ui.Version,
			Socket:      socket,
			OnEvent: func(e appsync.Event) {
				p.Send(e)
			},
		})
	}()

	select {
	case err := <-errCh:
		if err != nil && err != context.Canceled {
			fmt.Fprintln(os.Stderr, "gui:", err)
			return 1
		}
	case <-time.After(250 * time.Millisecond):
	}

	code := 0
	if _, err := p.Run(); err != nil {
		fmt.Fprintln(os.Stderr, "aegis:", err)
		code = 1
	}
	cancel()
	select {
	case <-errCh:
	case <-time.After(2 * time.Second):
	}
	return code
}

func cliHistory(args []string) int {
	_, jsonMode := splitJSON(args)
	recs, err := scanner.QuarantineHistory()
	if err != nil {
		fmt.Fprintln(os.Stderr, "history failed:", err)
		return 1
	}
	if jsonMode {
		encodeJSON(map[string]any{"quarantine": recs})
		return 0
	}
	if len(recs) == 0 {
		fmt.Println("no quarantine history")
		return 0
	}
	fmt.Printf("%d quarantine record(s), newest first\n", len(recs))
	for _, r := range recs {
		status := ""
		if r.Restored {
			status = "  [restored " + r.RestoredAt.Format("2006-01-02 15:04") + "]"
		}
		fmt.Printf("  %s  %s%s\n     reason: %s\n     stored: %s\n",
			r.When.Format("2006-01-02 15:04"), r.Original, status, r.Reason, r.Stored)
	}
	return 0
}

func cliRestore(args []string) int {
	args, jsonMode := splitJSON(args)
	if len(args) != 1 {
		fmt.Fprintln(os.Stderr, "usage: aegis restore <stored-path|sha256> [--json]")
		return 2
	}
	rec, err := scanner.Restore(args[0])
	if err != nil {
		if jsonMode {
			encodeJSON(map[string]any{"error": err.Error()})
		} else {
			fmt.Fprintln(os.Stderr, "restore:", err)
		}
		return 1
	}
	if jsonMode {
		encodeJSON(rec)
		return 0
	}
	fmt.Printf("restored %s\n", rec.Original)
	return 0
}

func cliUpdate(db *signatures.DB, args []string) int {
	_, jsonMode := splitJSON(args)
	if !jsonMode {
		fmt.Println("checking for updates: signatures, aegis release, llama.cpp release")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	report := maintenance.Startup(ctx, db, ui.Version)
	if jsonMode {
		encodeJSON(report)
		if report.SignatureError != "" {
			return 1
		}
		return 0
	}
	text, isErr := maintenance.Summary(report)
	fmt.Println(text)
	if report.Aegis.Update {
		fmt.Printf("→ aegis %s is available (you have %s): %s\n", report.Aegis.Latest, report.Aegis.Current, report.Aegis.ReleaseURL)
		fmt.Println("  aegis does not self-replace; re-run the install script or download the release yourself.")
	}
	if isErr {
		return 1
	}
	return 0
}

func cliStatus(db *signatures.DB, eng *rules.Engine, args []string) int {
	_, jsonMode := splitJSON(args)
	s := collectStatus(db, eng)
	if jsonMode {
		encodeJSON(s)
		return 0
	}
	fmt.Printf("health:      %d/100 (%s)\n", s.HealthScore, s.Health)
	fw := s.Firewall
	state := "disabled"
	if fw.Enabled {
		state = "enabled"
	}
	fmt.Printf("firewall:    %s (%s)\n", state, fw.Backend)
	age := s.SignatureAge
	if age != "never" {
		age += " ago"
	}
	fmt.Printf("signatures:  %d hashes + %d rules, updated %s\n", s.SignatureHashes, s.SignatureRules, age)

	canaries := s.Canaries
	events := s.RansomAlerts
	fmt.Printf("ransomware:  %d canaries armed, %d tamper alert(s)\n", canaries, len(events))
	for _, e := range events {
		fmt.Printf("  ⚠ %s — %s\n", e.Path, e.Detail)
	}

	fmt.Printf("persistence: %d autostart entries, %d suspicious\n", s.PersistenceTotal, s.PersistenceSuspect)

	if s.NetworkError != "" {
		fmt.Printf("network:     unavailable (%s)\n", s.NetworkError)
		return 0
	}
	fmt.Printf("network:     %d connections, %d flagged\n", s.NetworkTotal, s.NetworkFlagged)
	for _, c := range s.FlaggedNetwork {
		fmt.Printf("  ⚠ %s (%s) %s -> %s: %s\n", c.Proc, c.PID, c.Local, c.Remote, c.Suspect)
	}
	return 0
}

type statusJSON struct {
	HealthScore        int             `json:"health_score"`
	Health             string          `json:"health"`
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
	s.HealthScore, s.Health = securityHealth(s, db.Age())
	return s
}

func securityHealth(s statusJSON, sigAge time.Duration) (int, string) {
	score := 100
	var issues []string
	if !s.Firewall.Enabled {
		score -= 25
		issues = append(issues, "firewall disabled")
	}
	if sigAge < 0 {
		score -= 12
		issues = append(issues, "signatures never updated")
	} else if sigAge > 7*24*time.Hour {
		score -= 8
		issues = append(issues, "stale signatures")
	}
	if len(s.RansomAlerts) > 0 {
		score -= minInt(30, 12+len(s.RansomAlerts)*6)
		issues = append(issues, "ransomware alerts")
	}
	if s.PersistenceSuspect > 0 {
		score -= minInt(20, s.PersistenceSuspect*5)
		issues = append(issues, "suspicious persistence")
	}
	if s.NetworkFlagged > 0 {
		score -= minInt(15, s.NetworkFlagged*4)
		issues = append(issues, "flagged network")
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
	if len(issues) > 0 {
		label += ": " + joinIssues(issues)
	}
	return score, label
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

func scanJSON(path string, p scanner.Progress) scanJSONOutput {
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

func printScanReport(root string, p scanner.Progress, fullPaths bool) {
	c := newCLIColors()
	duration := p.Ended.Sub(p.Started).Round(time.Millisecond)
	fmt.Printf("%s scanned %s files in %s  %s skipped\n",
		c.Green("done"), c.Bold(fmt.Sprint(p.Scanned)), c.Bold(duration.String()), c.Muted(fmt.Sprint(p.Skipped)))
	if len(p.Threats) == 0 {
		fmt.Println(c.Green("clean") + " no threats found")
		return
	}

	counts := threatCounts(p.Threats)
	fmt.Printf("%s %s threat(s): %s critical · %s warning · %s info\n\n",
		c.Red("alert"), c.Bold(fmt.Sprint(len(p.Threats))),
		c.Red(fmt.Sprint(counts[scanner.SevCritical])),
		c.Yellow(fmt.Sprint(counts[scanner.SevWarning])),
		c.Muted(fmt.Sprint(counts[scanner.SevInfo])))

	limit := 24
	if fullPaths {
		limit = len(p.Threats)
	}
	for i, t := range p.Threats {
		if i == limit {
			fmt.Printf("  %s %d more finding(s). Re-run with %s to show everything.\n",
				c.Muted("…"), len(p.Threats)-limit, c.Bold("--full-paths"))
			break
		}
		printThreat(c, root, t, fullPaths)
	}
	fmt.Println()
	fmt.Printf("%s Review critical findings first. Use the TUI/GUI for quarantine and assisted remediation.\n", c.Blue("next"))
}

func printClamAVReport(r clamav.Report, addr string) {
	c := newCLIColors()
	fmt.Printf("%s %s via %s\n", c.Blue("clamav"), c.Bold(r.Root), c.Muted(addr))
	fmt.Printf("%s scanned %s files  %s skipped\n",
		c.Green("done"), c.Bold(fmt.Sprint(r.Scanned)), c.Muted(fmt.Sprint(r.Skipped)))
	if r.Error != "" {
		fmt.Println(c.Yellow("warning") + " " + r.Error)
	}
	if len(r.Findings) == 0 {
		fmt.Println(c.Green("clean") + " no ClamAV detections")
		return
	}
	fmt.Printf("%s %s ClamAV detection(s):\n\n", c.Red("alert"), c.Bold(fmt.Sprint(len(r.Findings))))
	for _, f := range r.Findings {
		fmt.Printf("  %s %s\n", c.Red("FOUND"), c.Bold(f.Path))
		fmt.Printf("      %s %s\n", c.Muted("signature:"), f.Signature)
	}
	fmt.Println()
	fmt.Printf("%s ClamAV is advisory beside Aegis rules/signatures; review before quarantine.\n", c.Blue("next"))
}

func printThreat(c cliColors, root string, t scanner.Threat, fullPath bool) {
	badge := c.Muted("INFO")
	switch t.Severity {
	case scanner.SevCritical:
		badge = c.Red("CRITICAL")
	case scanner.SevWarning:
		badge = c.Yellow("WARNING")
	}
	path := t.Path
	if !fullPath {
		path = compactPath(root, t.Path, 92)
	}
	fmt.Printf("  %s %s\n", badge, c.Bold(path))
	fmt.Printf("      %s %s\n", c.Muted("reason:"), t.Reason)
	if t.SHA256 != "" {
		fmt.Printf("      %s %s  %s %s\n", c.Muted("sha256:"), c.Muted(shortHash(t.SHA256)), c.Muted("size:"), humanBytes(t.Size))
	} else if t.Size > 0 {
		fmt.Printf("      %s %s\n", c.Muted("size:"), humanBytes(t.Size))
	}
}

func threatCounts(threats []scanner.Threat) map[scanner.Severity]int {
	counts := map[scanner.Severity]int{}
	for _, t := range threats {
		counts[t.Severity]++
	}
	return counts
}

func compactPath(root, path string, width int) string {
	if rel, err := filepath.Rel(root, path); err == nil && !strings.HasPrefix(rel, "..") {
		if rel == "." {
			path = filepath.Base(path)
		} else {
			path = rel
		}
	}
	if len(path) <= width {
		return path
	}
	base := filepath.Base(path)
	dir := filepath.Dir(path)
	keep := width - len(base) - 4
	if keep < 10 {
		if len(base) <= width-1 {
			return "…" + base
		}
		return "…" + base[len(base)-width+1:]
	}
	if len(dir) > keep {
		dir = "…" + dir[len(dir)-keep:]
	}
	return dir + string(os.PathSeparator) + base
}

func shortHash(s string) string {
	if len(s) <= 16 {
		return s
	}
	return s[:12] + "…" + s[len(s)-6:]
}

type cliColors struct {
	on bool
}

func newCLIColors() cliColors {
	stat, err := os.Stdout.Stat()
	isTerminal := err == nil && stat.Mode()&os.ModeCharDevice != 0
	return cliColors{on: os.Getenv("NO_COLOR") == "" &&
		os.Getenv("TERM") != "dumb" &&
		isTerminal}
}

func (c cliColors) wrap(code, s string) string {
	if !c.on {
		return s
	}
	return "\x1b[" + code + "m" + s + "\x1b[0m"
}

func (c cliColors) Bold(s string) string   { return c.wrap("1", s) }
func (c cliColors) Muted(s string) string  { return c.wrap("2", s) }
func (c cliColors) Red(s string) string    { return c.wrap("31;1", s) }
func (c cliColors) Yellow(s string) string { return c.wrap("33;1", s) }
func (c cliColors) Green(s string) string  { return c.wrap("32;1", s) }
func (c cliColors) Blue(s string) string   { return c.wrap("34;1", s) }

func splitJSON(args []string) ([]string, bool) {
	out := args[:0]
	jsonMode := false
	for _, a := range args {
		if a == "--json" {
			jsonMode = true
			continue
		}
		out = append(out, a)
	}
	return out, jsonMode
}

func encodeJSON(v any) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		fmt.Fprintln(os.Stderr, "json:", err)
	}
}

func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%dB", n)
	}
	div, exp := int64(unit), 0
	for n/div >= unit && exp < 4 {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f%cB", float64(n)/float64(div), "KMGTPE"[exp])
}

func truncateName(s string, n int) string {
	base := filepath.Base(s)
	if len(base) <= n {
		return base
	}
	if n < 2 {
		return base
	}
	return base[:n-1] + "…"
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func joinIssues(xs []string) string {
	if len(xs) == 0 {
		return ""
	}
	s := xs[0]
	for _, x := range xs[1:] {
		s += ", " + x
	}
	return s
}

func printChecks(title string, checks []checkup.Check) {
	fmt.Println("\n" + title + ":")
	for _, c := range checks {
		fmt.Printf("  [%s] %s — %s\n", c.Status, c.Name, c.Summary)
		for _, item := range c.Items {
			fmt.Println("    " + item)
		}
		if c.Error != "" {
			fmt.Println("    error: " + c.Error)
		}
	}
}

func printVulnerabilitySummary(v checkup.VulnerabilityReport) {
	fmt.Println("\nVulnerability Intelligence:")
	if v.Offline {
		fmt.Println("  [unknown] offline mode: skipped CISA KEV and NVD")
		return
	}
	if len(v.RecentKEV) == 0 && len(v.RecentCritical) == 0 && len(v.Errors) == 0 {
		fmt.Println("  [ok] no recent KEV or critical NVD entries returned")
	}
	if len(v.RecentKEV) > 0 {
		fmt.Printf("  [warn] %d recent CISA KEV entrie(s)\n", len(v.RecentKEV))
		for _, e := range v.RecentKEV {
			fmt.Printf("    %s  %s %s — %s\n", e.DateAdded, e.VendorProject, e.Product, e.CVE)
		}
	}
	if len(v.RecentCritical) > 0 {
		fmt.Printf("  [warn] %d recent critical NVD CVE(s)\n", len(v.RecentCritical))
		for _, e := range v.RecentCritical {
			fmt.Printf("    %s  %s  %s\n", e.ID, e.Score, e.Summary)
		}
	}
	for _, err := range v.Errors {
		fmt.Println("  [error] " + err)
	}
}

func printIntelReport(r intel.VirusTotalReport) {
	c := newCLIColors()
	fmt.Printf("%s %s\n", c.Blue("intel"), c.Bold("VirusTotal file reputation"))
	fmt.Printf("  %s %s\n", c.Muted("hash:"), r.Query)
	if !r.Found {
		msg := r.Error
		if msg == "" {
			msg = "not found"
		}
		fmt.Printf("  %s %s\n", c.Muted("result:"), c.Yellow(msg))
		fmt.Printf("  %s Aegis sent only this hash because you requested an OSINT lookup.\n", c.Muted("privacy:"))
		return
	}
	if r.MeaningfulName != "" {
		fmt.Printf("  %s %s\n", c.Muted("name:"), r.MeaningfulName)
	}
	if r.TypeDescription != "" {
		fmt.Printf("  %s %s\n", c.Muted("type:"), r.TypeDescription)
	}
	malicious := r.LastAnalysisStats["malicious"]
	suspicious := r.LastAnalysisStats["suspicious"]
	harmless := r.LastAnalysisStats["harmless"]
	undetected := r.LastAnalysisStats["undetected"]
	verdict := c.Green("no vendor detections")
	if suspicious > 0 {
		verdict = c.Yellow("suspicious")
	}
	if malicious > 0 {
		verdict = c.Red("malicious detections")
	}
	fmt.Printf("  %s %s  %s malicious · %s suspicious · %s harmless · %s undetected\n",
		c.Muted("verdict:"), verdict, c.Red(fmt.Sprint(malicious)), c.Yellow(fmt.Sprint(suspicious)),
		c.Green(fmt.Sprint(harmless)), c.Muted(fmt.Sprint(undetected)))
	fmt.Printf("  %s %d\n", c.Muted("reputation:"), r.Reputation)
	fmt.Printf("  %s %s\n", c.Muted("link:"), r.Link)
	fmt.Printf("  %s Aegis sent only this hash because you requested an OSINT lookup.\n", c.Muted("privacy:"))
}

func checkupExit(r checkup.Report) int {
	for _, c := range append(r.Updates, r.Dependencies...) {
		if c.Status == "warn" {
			return 1
		}
	}
	if len(r.Vulnerabilities.RecentKEV) > 0 || len(r.Vulnerabilities.RecentCritical) > 0 {
		return 1
	}
	return 0
}

func applyAIConfig(cfg ai.Config, args []string) ai.Config {
	for i := 0; i < len(args); i++ {
		next := func() string {
			if i+1 >= len(args) {
				return ""
			}
			i++
			return args[i]
		}
		switch args[i] {
		case "--backend":
			cfg.Backend = next()
		case "--endpoint":
			cfg.Endpoint = next()
		case "--model":
			cfg.ModelPath = next()
		case "--remote-model", "--model-name":
			cfg.Model = next()
		case "--command":
			cfg.Command = next()
		case "--api-key-env":
			cfg.APIKeyEnv = next()
		case "--privacy":
			cfg.PrivacyMode = next()
		case "--max-excerpt":
			var n int
			fmt.Sscanf(next(), "%d", &n)
			if n > 0 {
				cfg.MaxExcerptBytes = n
			}
		}
	}
	return cfg
}

func runAIPrompt(cfg ai.Config, prompt string) int {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	out, err := ai.Generate(ctx, cfg, ai.Request{System: ai.PromptWithNotes(ai.SecuritySystemPrompt()), Prompt: prompt})
	if err != nil {
		fmt.Fprintln(os.Stderr, "ai:", err)
		return 1
	}
	fmt.Println(out)
	return 0
}

func runAIChat(cfg ai.Config) int {
	fmt.Println("Aegis local analyst. Type /quit to exit.")
	sc := bufio.NewScanner(os.Stdin)
	for {
		fmt.Print("> ")
		if !sc.Scan() {
			return 0
		}
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		if line == "/quit" || line == "/exit" {
			return 0
		}
		if code := runAIPrompt(cfg, line); code != 0 {
			return code
		}
	}
}

func printAIThreatExplanations(threats []scanner.Threat) {
	cfg, err := ai.Load()
	if err != nil {
		fmt.Fprintln(os.Stderr, "ai:", err)
		return
	}
	fmt.Println("\nLocal AI triage:")
	for _, t := range threats {
		prompt := threatPrompt(t, cfg)
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		out, err := ai.Generate(ctx, cfg, ai.Request{System: ai.PromptWithNotes(ai.SecuritySystemPrompt()), Prompt: prompt})
		cancel()
		if err != nil {
			fmt.Printf("  %s: AI unavailable: %v\n", t.Path, err)
			continue
		}
		fmt.Printf("\n[%s] %s\n%s\n", t.Severity, t.Path, out)
	}
}

func threatPrompt(t scanner.Threat, cfg ai.Config) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Aegis flagged this file. Assess likely risk and false-positive likelihood.\n")
	fmt.Fprintf(&b, "Path: %s\nSeverity: %s\nReason: %s\nSize: %d\nSHA256: %s\n", t.Path, t.Severity, t.Reason, t.Size, t.SHA256)
	if cfg.PrivacyMode == "excerpt" {
		if ex := safeExcerpt(t.Path, cfg.MaxExcerptBytes); ex != "" {
			fmt.Fprintf(&b, "\nSmall printable excerpt:\n%s\n", ex)
		}
	} else {
		fmt.Fprintf(&b, "\nPrivacy mode is metadata-only; do not ask for the file contents.\n")
	}
	fmt.Fprintf(&b, "\nReturn: risk, false-positive likelihood, why, and safe next steps.")
	return b.String()
}

func safeExcerpt(path string, maxBytes int) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	buf := make([]byte, maxBytes)
	n, _ := f.Read(buf)
	buf = buf[:n]
	printable := 0
	for _, c := range buf {
		if c == '\n' || c == '\r' || c == '\t' || (c >= 32 && c < 127) {
			printable++
		}
	}
	if len(buf) == 0 || printable*100/len(buf) < 85 {
		return ""
	}
	return string(buf)
}

func splitBoolFlag(args []string, flag string) ([]string, bool) {
	out := args[:0]
	found := false
	for _, a := range args {
		if a == flag {
			found = true
			continue
		}
		out = append(out, a)
	}
	return out, found
}

package ui

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"

	"github.com/andreipaciurca/aegis/internal/ai"
	"github.com/andreipaciurca/aegis/internal/persist"
)

func (m Model) View() string {
	if m.width == 0 {
		return "loading…"
	}
	var body string
	if m.showHelp {
		body = m.viewHelp()
	} else {
		switch m.tab {
		case tabDashboard:
			body = m.viewDashboard()
		case tabScanner:
			body = m.viewScanner()
		case tabShield:
			body = m.viewShield()
		case tabNetwork:
			body = m.viewNetwork()
		case tabFirewall:
			body = m.viewFirewall()
		case tabAudit:
			body = m.viewAudit()
		case tabAI:
			body = m.viewAI()
		}
	}
	header := m.viewHeader()
	footer := m.viewFooter()
	gap := m.height - lipgloss.Height(header) - lipgloss.Height(body) - lipgloss.Height(footer)
	if gap < 0 {
		gap = 0
	}
	return header + "\n" + body + strings.Repeat("\n", gap+1) + footer
}

func (m Model) viewHeader() string {
	logo := logoStyle.Render("⛨ AEGIS")
	var tabs []string
	for i, name := range tabNames {
		label := tabLabel(i, name, m.width)
		if tabID(i) == m.tab {
			tabs = append(tabs, tabActiveStyle.Render(label))
		} else {
			tabs = append(tabs, tabStyle.Render(label))
		}
	}
	right := ""
	if m.monitoring {
		right = okStyle.Render("● LIVE")
	}
	tabsRow := strings.Join(tabs, "")
	row := lipgloss.JoinHorizontal(lipgloss.Center, logo, "  ", tabsRow)
	if lipgloss.Width(row) > m.width {
		active := tabActiveStyle.Render(tabLabel(int(m.tab), tabNames[m.tab], m.width))
		row = lipgloss.JoinHorizontal(lipgloss.Center, logo, "  ", active)
	}
	if right != "" && lipgloss.Width(row)+lipgloss.Width(right)+1 <= m.width {
		row += strings.Repeat(" ", m.width-lipgloss.Width(row)-lipgloss.Width(right)) + right
	}
	if lipgloss.Width(row) > m.width {
		row = logo
		if m.width >= 18 {
			row = lipgloss.JoinHorizontal(lipgloss.Center, logo, "  ",
				tabActiveStyle.Render(fmt.Sprintf("%d %s", int(m.tab)+1, shortTabName(tabNames[m.tab]))))
		}
	}
	if lipgloss.Width(tabsRow) > 0 && lipgloss.Width(row) < m.width && m.width >= 64 {
		pad := m.width - lipgloss.Width(row)
		if pad > 0 {
			row += strings.Repeat(" ", pad)
		}
	}
	line := dimStyle.Render(strings.Repeat("─", max(m.width, 1)))
	return row + "\n" + line
}

func (m Model) viewFooter() string {
	var keys [][2]string
	if m.showHelp {
		keys = [][2]string{{"?", "close help"}, {"esc", "back"}}
	} else {
		switch m.tab {
		case tabScanner:
			if m.editing {
				keys = [][2]string{{"enter/esc", "done editing"}}
			} else if m.quarantineView {
				keys = [][2]string{{"↑↓", "select"}, {"x", "restore"}, {"r", "refresh"}, {"v/esc", "back to scanner"}}
			} else {
				keys = [][2]string{{"s", "scan"}, {"e", "edit path"}, {"c", "cancel"},
					{"↑↓", "select"}, {"x", "quarantine"}, {"v", "quarantine history"}}
			}
		case tabShield:
			keys = [][2]string{{"d", "deploy canaries"}, {"c", "clear"}, {"s", "sweep now"}, {"m", "monitor"}}
		case tabFirewall:
			keys = [][2]string{{"e", "enable"}, {"d", "disable"}, {"t", "stealth"}, {"r", "refresh"}}
		case tabNetwork:
			keys = [][2]string{{"↑↓", "select"}, {"k", "kill process"}, {"b", "block port"}, {"r", "refresh"}}
		case tabAudit:
			keys = [][2]string{{"↑↓", "select"}, {"x", "show fix"}, {"r", "refresh"}}
		case tabAI:
			if m.aiEditing {
				keys = [][2]string{{"enter", "submit"}, {"esc", "cancel"}}
			} else if !m.aiReady() {
				keys = [][2]string{{"n", "remember"}, {"r", "refresh"}}
			} else {
				keys = [][2]string{{"a", "ask"}, {"x", "explain threat"}, {"n", "remember"}, {"t", "test"}, {"r", "refresh"}}
			}
		default:
			keys = [][2]string{{"1-7", "tabs"}, {"u", "update/check"}}
		}
	}
	keys = append(keys, [2]string{"?", "help"})
	keys = append(keys, [2]string{"q", "quit"})
	bar := renderKeyBar(keys, max(m.width, 20))

	line := dimStyle.Render(strings.Repeat("─", max(m.width, 1)))

	// A pending confirmation takes over the status line.
	if m.confirm != nil {
		prompt := warnStyle.Render("? "+m.confirm.prompt) + dimStyle.Render("   press ") +
			footerKeyStyle.Render("y") + dimStyle.Render(" to confirm · any other key cancels")
		return line + "\n" + wrapStyledLine(prompt, max(m.width, 20)) + "\n" + bar
	}

	status := ""
	if m.status != "" {
		if m.statusErr {
			status = statusErrStyle.Render("✗ " + m.status)
		} else {
			status = statusOKStyle.Render("✓ " + m.status)
		}
	} else if m.updating {
		status = blueStyle.Render(m.spin.View() + " updating signatures…")
	}
	if status != "" {
		return line + "\n" + wrapStyledLine(status, max(m.width, 20)) + "\n" + bar
	}
	return line + "\n" + bar
}

// ---- dashboard ----

func (m Model) viewDashboard() string {
	fwVal, fwNote := dimStyle.Render("checking…"), ""
	if m.fwLoaded {
		if m.fw.Err != nil && !m.fw.Enabled {
			fwVal = warnStyle.Render("UNKNOWN")
			fwNote = m.fw.Backend
		} else if m.fw.Enabled {
			fwVal = okStyle.Render("● ACTIVE")
			fwNote = m.fw.Backend
		} else {
			fwVal = badStyle.Render("○ OFF")
			fwNote = m.fw.Backend
		}
	}
	scanVal, scanNote := dimStyle.Render("no scan yet"), "press 2 then s"
	if m.scanning {
		scanVal = blueStyle.Render(m.spin.View() + " scanning…")
		scanNote = fmt.Sprintf("%d files", m.prog.Scanned)
	} else if m.lastScan != nil {
		n := len(m.lastScan.Threats)
		if n == 0 {
			scanVal = okStyle.Render("● CLEAN")
		} else {
			scanVal = badStyle.Render(fmt.Sprintf("● %d THREAT(S)", n))
		}
		scanNote = fmt.Sprintf("%d files in %s", m.lastScan.Scanned,
			m.lastScan.Ended.Sub(m.lastScan.Started).Round(time.Second))
	}

	// Ransomware shield card.
	shieldVal, shieldNote := dimStyle.Render("no canaries"), "press 3 then d"
	crit := 0
	for _, e := range m.shieldEvents {
		if e.Severity == "CRITICAL" {
			crit++
		}
	}
	if crit > 0 {
		shieldVal = badStyle.Render(fmt.Sprintf("● %d ALERT(S)", crit))
		shieldNote = "check Shield tab"
	} else if m.canaryCount > 0 {
		if m.monitoring {
			shieldVal = okStyle.Render("● MONITORING")
		} else {
			shieldVal = okStyle.Render("● ARMED")
		}
		shieldNote = fmt.Sprintf("%d canaries", m.canaryCount)
	}

	flagged := 0
	for _, c := range m.conns {
		if c.Suspect != "" {
			flagged++
		}
	}
	netVal := okStyle.Render(fmt.Sprintf("%d conns", len(m.conns)))
	netNote := "none flagged"
	if flagged > 0 {
		netVal = warnStyle.Render(fmt.Sprintf("⚠ %d flagged", flagged))
		netNote = fmt.Sprintf("%d total connections", len(m.conns))
	}

	suspAuto := 0
	for _, e := range m.auditEntries {
		if e.Suspect != "" {
			suspAuto++
		}
	}
	autoVal := okStyle.Render(fmt.Sprintf("%d entries", len(m.auditEntries)))
	autoNote := "nothing suspicious"
	if suspAuto > 0 {
		autoVal = warnStyle.Render(fmt.Sprintf("⚠ %d suspicious", suspAuto))
		autoNote = "check Audit tab"
	}

	aiVal := dimStyle.Render("not checked")
	aiNote := "press 7"
	if m.aiLoaded {
		if m.aiReady() {
			aiVal = okStyle.Render("● READY")
			aiNote = m.aiStatus.Config.Backend
		} else {
			aiVal = warnStyle.Render("○ OFFLINE")
			aiNote = "llama.cpp not running"
		}
	}

	cards := []dashboardCard{
		{"FIREWALL", fwVal, fwNote},
		{"MALWARE SCAN", scanVal, scanNote},
		{"RANSOM SHIELD", shieldVal, shieldNote},
		{"NETWORK", netVal, netNote},
		{"PERSISTENCE", autoVal, autoNote},
		{"SIGNATURES", textStyle.Render(fmt.Sprintf("%d hashes", m.db.Count())),
			fmt.Sprintf("%d rules · %s", m.eng.Count(), sigAge(m))},
		{"LOCAL AI", aiVal, aiNote},
		{"CHECKUP", textStyle.Render("OS + deps"), "aegis checkup"},
		{"TRUST", textStyle.Render("signed releases"), "make checksums"},
	}

	width := dashboardWidth(m.width)
	grid := dashboardGrid(cards, width)
	tip := "Seven layers, one binary: native firewall, hash/rule/entropy scanning, " +
		"ransomware canaries, connection monitor, persistence audit, OS/dependency checkups, " +
		"and a local llama.cpp analyst. Press ? for help, u to update signatures and check releases; each tab suggests a fix."
	tips := dimStyle.Width(width).Render(wrapText(tip, width, ""))
	body := grid + "\n\n" + tips

	return "\n" + lipgloss.PlaceHorizontal(m.width, lipgloss.Center, body)
}

func (m Model) viewHelp() string {
	width := min(max(m.width-4, 36), 96)
	sections := []string{
		cardTitleStyle.Render("START HERE") + "\n" +
			textStyle.Render("1 Dashboard gives the summary. Press tab to explore. Press u to update signatures."),
		cardTitleStyle.Render("MAIN WORKFLOWS") + "\n" +
			helpLine("2 Scanner", "s scan, e edit path, x quarantine a finding, v view/restore quarantine history") + "\n" +
			helpLine("3 Shield", "d deploy canaries, s sweep, m monitor for ransomware tampering") + "\n" +
			helpLine("4 Network", "select a connection, k kill, b show firewall block command") + "\n" +
			helpLine("5 Firewall", "e enable, d disable, t toggle stealth when supported") + "\n" +
			helpLine("6 Audit", "review autostart entries, x show the exact disable command") + "\n" +
			helpLine("7 AI", "optional analyst; helps explain findings once configured"),
		cardTitleStyle.Render("TERMINAL COMMANDS") + "\n" +
			dimStyle.Render("Most users can run ") + footerKeyStyle.Render("aegis app") +
			dimStyle.Render(" and stay in the paired TUI + GUI. For scripts, run ") +
			footerKeyStyle.Render("aegis --help") + dimStyle.Render(" or ") +
			footerKeyStyle.Render("aegis help scan") + dimStyle.Render("."),
		cardTitleStyle.Render("SAFETY MODEL") + "\n" +
			dimStyle.Render(wrapText("Aegis reports first. Destructive actions confirm before running, quarantine changes file permissions instead of deleting, and optional AI explains findings but never overrides deterministic detections.", width-4, "")),
	}
	panel := panelStyle.Width(width).Render(strings.Join(sections, "\n\n"))
	return "\n" + lipgloss.PlaceHorizontal(m.width, lipgloss.Center, panel)
}

func helpLine(k, v string) string {
	return footerKeyStyle.Render(k) + dimStyle.Render("  "+v)
}

func sigAge(m Model) string {
	if age := m.db.Age(); age >= 0 {
		return "updated " + humanAge(age) + " ago"
	}
	return "never updated"
}

type dashboardCard struct {
	title string
	value string
	note  string
}

func dashboardWidth(termWidth int) int {
	if termWidth <= 0 {
		return 80
	}
	width := termWidth - 4
	if width > 86 {
		width = 86
	}
	if width < 28 {
		width = 28
	}
	return width
}

func dashboardGrid(cards []dashboardCard, width int) string {
	cols := 1
	switch {
	case width >= 82:
		cols = 3
	case width >= 72:
		cols = 2
	}
	gap := 2
	totalCardWidth := (width - gap*(cols-1)) / cols
	cardWidth := totalCardWidth - 2 // rounded border adds the remaining visible columns
	if cardWidth < 18 {
		cardWidth = 18
	}

	rows := make([]string, 0, (len(cards)+cols-1)/cols)
	separator := strings.Repeat(" ", gap)
	for i := 0; i < len(cards); i += cols {
		end := i + cols
		if end > len(cards) {
			end = len(cards)
		}
		parts := make([]string, 0, cols*2-1)
		for _, c := range cards[i:end] {
			if len(parts) > 0 {
				parts = append(parts, separator)
			}
			parts = append(parts, card(c.title, c.value, c.note, cardWidth))
		}
		rows = append(rows, lipgloss.JoinHorizontal(lipgloss.Top, parts...))
	}
	return strings.Join(rows, "\n")
}

func card(title, value, note string, width int) string {
	inner := cardTitleStyle.Render(title) + "\n" + value
	if note != "" {
		inner += "\n" + dimStyle.Render(truncate(note, max(width-4, 12)))
	}
	return cardStyle.Width(width).MarginRight(0).Render(inner)
}

// ---- scanner ----

func (m Model) viewScanner() string {
	if m.quarantineView {
		return m.viewQuarantine()
	}
	var b strings.Builder
	b.WriteString("\n  " + cardTitleStyle.Render("TARGET") + "\n")
	b.WriteString("  " + m.pathInput.View() + "\n\n")

	switch {
	case m.scanning && m.prog.Phase == "counting":
		b.WriteString("  " + m.spin.View() + blueStyle.Render(
			fmt.Sprintf(" discovering files… %d found", m.prog.Total)) + "\n")
	case m.scanning:
		frac := 0.0
		if m.prog.Total > 0 {
			frac = float64(m.prog.Scanned) / float64(m.prog.Total)
		}
		b.WriteString("  " + m.bar.ViewAs(frac) + "\n")
		b.WriteString(dimStyle.Render(fmt.Sprintf("  %d / %d files  ·  %d skipped  ·  %s elapsed",
			m.prog.Scanned, m.prog.Total, m.prog.Skipped,
			time.Since(m.prog.Started).Round(time.Second))) + "\n")
	case m.lastScan != nil:
		res := okStyle.Render("✓ clean")
		if len(m.lastScan.Threats) > 0 {
			res = badStyle.Render(fmt.Sprintf("✗ %d threat(s) found", len(m.lastScan.Threats)))
		}
		b.WriteString("  " + res + dimStyle.Render(fmt.Sprintf(
			"  ·  %d files in %s", m.lastScan.Scanned,
			m.lastScan.Ended.Sub(m.lastScan.Started).Round(time.Second))) + "\n")
	default:
		b.WriteString(dimStyle.Render("  press s to start a scan, e to change the target path") + "\n")
	}

	threats := m.threats()
	if len(threats) > 0 {
		b.WriteString("\n  " + cardTitleStyle.Render(fmt.Sprintf("THREATS (%d)", len(threats))) + "\n")
		maxRows := max(m.height-16, 3)
		start := 0
		if m.sel >= maxRows {
			start = m.sel - maxRows + 1
		}
		for i := start; i < len(threats) && i < start+maxRows; i++ {
			t := threats[i]
			sev := sevStyle(t.Severity.String()).Render(fmt.Sprintf("%-8s", t.Severity.String()))
			path := shortenPath(t.Path, m.width-44)
			line := fmt.Sprintf("%s %s  %s", sev, textStyle.Render(path), dimStyle.Render(t.Reason))
			if i == m.sel && !m.scanning {
				line = selStyle.Render("▸ ") + line
			} else {
				line = "  " + line
			}
			b.WriteString("  " + line + "\n")
		}
	}
	b.WriteString("\n" + dimStyle.Render(fmt.Sprintf("  press v to view quarantine history (%d record(s))", len(m.quarHistory))) + "\n")
	return b.String()
}

// ---- quarantine history / restore ----

func (m Model) viewQuarantine() string {
	var b strings.Builder
	b.WriteString("\n  " + cardTitleStyle.Render("QUARANTINE HISTORY") + "\n")
	if m.quarBusy && len(m.quarHistory) == 0 {
		b.WriteString("  " + m.spin.View() + dimStyle.Render(" loading…") + "\n")
		return b.String()
	}
	if len(m.quarHistory) == 0 {
		b.WriteString(dimStyle.Render("  nothing quarantined yet — press esc to go back") + "\n")
		return b.String()
	}
	maxRows := max(m.height-16, 3)
	start := 0
	if m.quarSel >= maxRows {
		start = m.quarSel - maxRows + 1
	}
	for i := start; i < len(m.quarHistory) && i < start+maxRows; i++ {
		r := m.quarHistory[i]
		status := badStyle.Render("quarantined")
		if r.Restored {
			status = okStyle.Render("restored")
		}
		path := shortenPath(r.Original, m.width-46)
		line := fmt.Sprintf("%s  %s  %s", status, textStyle.Render(path), dimStyle.Render(r.When.Format("2006-01-02 15:04")))
		if i == m.quarSel {
			line = selStyle.Render("▸ ") + line
		} else {
			line = "  " + line
		}
		b.WriteString("  " + line + "\n")
	}
	if m.quarSel < len(m.quarHistory) {
		r := m.quarHistory[m.quarSel]
		b.WriteString("\n  " + dimStyle.Render("reason: ") + textStyle.Render(r.Reason) + "\n")
		if r.Restored && r.RestoredAt != nil {
			b.WriteString("  " + dimStyle.Render("restored: ") + okStyle.Render(r.RestoredAt.Format("2006-01-02 15:04")) + "\n")
		} else {
			b.WriteString("  " + dimStyle.Render("press x to restore this file to its original location") + "\n")
		}
	}
	return b.String()
}

// ---- shield (ransomware) ----

func (m Model) viewShield() string {
	var b strings.Builder
	b.WriteString("\n")

	state := badStyle.Render("○ NOT ARMED")
	detail := "no canary tripwires deployed"
	if m.canaryCount > 0 {
		if m.monitoring {
			state = okStyle.Render("● MONITORING")
			detail = "re-checking canaries every 3 seconds"
		} else {
			state = okStyle.Render("● ARMED")
			detail = "canaries in place — press m for real-time monitoring"
		}
	}
	if m.shieldBusy {
		state = blueStyle.Render(m.spin.View() + " working…")
	}

	rows := []string{
		row("Status", state),
		row("Canaries", textStyle.Render(fmt.Sprint(m.canaryCount))+dimStyle.Render("  "+detail)),
		row("Protecting", dimStyle.Render(foldDirs(m.canaryDirs))),
	}
	panel := panelStyle.Width(min(m.width-4, 96)).Render(strings.Join(rows, "\n"))
	b.WriteString(lipgloss.NewStyle().PaddingLeft(2).Render(panel) + "\n\n")

	if len(m.shieldEvents) == 0 {
		b.WriteString(dimStyle.Render(
			"  Canary files are harmless decoys; if ransomware encrypts them, aegis notices\n" +
				"  instantly. Press d to deploy, s to sweep for ransom notes and encrypted files."))
		return b.String()
	}

	b.WriteString("  " + cardTitleStyle.Render(fmt.Sprintf("FINDINGS (%d)", len(m.shieldEvents))) + "\n")
	maxRows := max(m.height-16, 3)
	start := 0
	if m.shieldSel >= maxRows {
		start = m.shieldSel - maxRows + 1
	}
	for i := start; i < len(m.shieldEvents) && i < start+maxRows; i++ {
		e := m.shieldEvents[i]
		sev := sevStyle(e.Severity).Render(fmt.Sprintf("%-8s", e.Severity))
		path := shortenPath(e.Path, m.width-46)
		line := fmt.Sprintf("%s %s  %s", sev, textStyle.Render(path), dimStyle.Render(e.Detail))
		if i == m.shieldSel {
			line = selStyle.Render("▸ ") + line
		} else {
			line = "  " + line
		}
		b.WriteString("  " + line + "\n")
	}
	b.WriteString("\n" + warnStyle.Render("  ⚠ If canaries were encrypted, disconnect from the network and power down.") + "\n")
	return b.String()
}

func foldDirs(dirs []string) string {
	if len(dirs) == 0 {
		return "(no target folders found)"
	}
	home, _ := os.UserHomeDir()
	var names []string
	for _, d := range dirs {
		if home != "" && strings.HasPrefix(d, home) {
			names = append(names, "~"+d[len(home):])
		} else {
			names = append(names, d)
		}
	}
	return strings.Join(names, "  ")
}

// ---- firewall ----

func (m Model) viewFirewall() string {
	var b strings.Builder
	b.WriteString("\n")
	if !m.fwLoaded {
		return "\n  " + dimStyle.Render("checking firewall…")
	}
	state := badStyle.Render("○ DISABLED")
	if m.fw.Enabled {
		state = okStyle.Render("● ENABLED")
	}
	if m.fwWorking {
		state = blueStyle.Render(m.spin.View() + " applying…")
	}
	rows := []string{
		row("Backend", textStyle.Render(m.fw.Backend)),
		row("State", state),
	}
	if m.fw.StealthMode != "" {
		sv := dimStyle.Render("off")
		if m.fw.StealthMode == "on" {
			sv = okStyle.Render("on")
		}
		rows = append(rows, row("Stealth mode", sv))
	}
	if m.fw.RuleCount > 0 {
		rows = append(rows, row("Rules", textStyle.Render(fmt.Sprint(m.fw.RuleCount))))
	}
	if m.fw.Detail != "" {
		rows = append(rows, row("Detail", dimStyle.Render(m.fw.Detail)))
	}
	if m.fw.Err != nil {
		rows = append(rows, row("Note", warnStyle.Render(m.fw.Err.Error())))
	}
	panel := panelStyle.Width(min(m.width-4, 96)).Render(strings.Join(rows, "\n"))
	b.WriteString(lipgloss.NewStyle().PaddingLeft(2).Render(panel))
	b.WriteString("\n\n" + dimStyle.Render(
		"  Changes call the OS firewall directly (socketfilterfw / ufw / netsh).\n"+
			"  If aegis lacks privileges it shows the exact sudo command to run."))
	return b.String()
}

func row(k, v string) string {
	return dimStyle.Render(fmt.Sprintf("%-14s", k)) + " " + v
}

// ---- network ----

func (m Model) viewNetwork() string {
	var b strings.Builder
	b.WriteString("\n")
	if !m.netLoaded {
		return "\n  " + dimStyle.Render("listing connections…")
	}
	if m.netErr != nil {
		return "\n  " + warnStyle.Render("could not list connections: "+m.netErr.Error())
	}
	flagged := 0
	for _, c := range m.conns {
		if c.Suspect != "" {
			flagged++
		}
	}
	summary := fmt.Sprintf("  %s  %s", textStyle.Render(fmt.Sprintf("%d connections", len(m.conns))),
		dimStyle.Render("· auto-refresh 3s · select a row, then k to kill or b to block"))
	if flagged > 0 {
		summary += "  " + warnStyle.Render(fmt.Sprintf("⚠ %d flagged", flagged))
	}
	b.WriteString(summary + "\n\n")
	b.WriteString(lipgloss.NewStyle().PaddingLeft(2).Render(m.netTable.View()))
	return b.String()
}

// ---- audit (persistence) ----

func (m Model) viewAudit() string {
	var b strings.Builder
	b.WriteString("\n")
	if !m.auditLoaded {
		return "\n  " + dimStyle.Render("auditing autostart entries…")
	}
	susp := 0
	for _, e := range m.auditEntries {
		if e.Suspect != "" {
			susp++
		}
	}
	head := fmt.Sprintf("  %s", textStyle.Render(fmt.Sprintf("%d autostart / persistence entries", len(m.auditEntries))))
	if susp > 0 {
		head += "  " + warnStyle.Render(fmt.Sprintf("⚠ %d suspicious", susp))
	} else {
		head += "  " + okStyle.Render("✓ nothing suspicious")
	}
	b.WriteString(head + "\n\n")

	if len(m.auditEntries) == 0 {
		b.WriteString(dimStyle.Render("  No user autostart entries found. (System entries may need root to read.)"))
		return b.String()
	}

	order := auditOrder(m.auditEntries)
	visSel := indexOf(order, m.auditSel)
	if visSel < 0 {
		visSel = 0
	}

	maxRows := max(m.height-18, 4)
	start := 0
	if visSel >= maxRows {
		start = visSel - maxRows + 1
	}
	for vis := start; vis < len(order) && vis < start+maxRows; vis++ {
		i := order[vis]
		e := m.auditEntries[i]
		marker := dimStyle.Render(fmt.Sprintf("%-16s", e.Source))
		name := textStyle.Render(truncate(e.Label, 26))
		var flag string
		if e.Suspect != "" {
			flag = badStyle.Render("⚠ " + e.Suspect)
		} else {
			flag = dimStyle.Render("ok")
		}
		line := fmt.Sprintf("%s %s  %s", marker, name, flag)
		if i == m.auditSel {
			line = selStyle.Render("▸ ") + line
		} else {
			line = "  " + line
		}
		b.WriteString("  " + line + "\n")
	}

	// Detail of the selected entry, with its exact remediation command.
	if m.auditSel < len(m.auditEntries) {
		e := m.auditEntries[m.auditSel]
		b.WriteString("\n  " + cardTitleStyle.Render("SELECTED") + "\n")
		b.WriteString("  " + dimStyle.Render("runs: ") + textStyle.Render(truncate(e.Command, m.width-12)) + "\n")
		b.WriteString("  " + dimStyle.Render("fix:  ") + blueStyle.Render(truncate(e.DisableCmd, m.width-12)) + "\n")
		b.WriteString("  " + dimStyle.Render("(press x to echo this fix to the status line)") + "\n")
	}
	return b.String()
}

// ---- local AI analyst ----

func (m Model) viewAI() string {
	var b strings.Builder
	b.WriteString("\n")
	ready := m.aiReady()
	state := warnStyle.Render("○ not connected")
	detail := "start llama-server or configure llama-cli"
	if !m.aiLoaded {
		state = dimStyle.Render("checking…")
		detail = "loading local AI config"
	} else if ready {
		state = okStyle.Render("● ready")
		if m.aiCfg.Backend == ai.BackendServer {
			detail = "llama-server endpoint ready"
		} else if m.aiCfg.Backend == ai.BackendOpenAICompatible {
			detail = "remote API key configured"
		} else {
			detail = "llama-cli found"
		}
	}
	if m.aiBusy {
		state = blueStyle.Render(m.spin.View() + " thinking…")
	}
	rows := []string{
		row("Status", state),
		row("Backend", textStyle.Render(m.aiCfg.Backend)),
		row("Endpoint", dimStyle.Render(truncate(m.aiCfg.Endpoint, max(m.width-24, 24)))),
		row("Model", dimStyle.Render(truncate(aiModelLabel(m.aiCfg), max(m.width-24, 24)))),
		row("Privacy", textStyle.Render(m.aiCfg.PrivacyMode)+dimStyle.Render(fmt.Sprintf("  %d byte excerpt cap", m.aiCfg.MaxExcerptBytes))),
		row("Context", textStyle.Render(fmt.Sprintf("%d remembered note(s)", len(m.aiNotes)))),
		row("Hint", dimStyle.Render(detail)),
	}
	if !ready {
		rows = append(rows, row("Reason", dimStyle.Render(truncate(m.aiOfflineReason(), max(m.width-24, 24)))))
	}
	panel := panelStyle.Width(min(m.width-4, 100)).Render(strings.Join(rows, "\n"))
	b.WriteString(lipgloss.NewStyle().PaddingLeft(2).Render(panel) + "\n\n")

	if !ready && !m.aiEditing {
		b.WriteString("  " + cardTitleStyle.Render("SETUP") + "\n")
		b.WriteString("  " + warnStyle.Render("Ask/test/explain are disabled until a local llama.cpp backend is ready.") + "\n")
		setup := []string{
			"1. Run: aegis ai setup",
			"2. Optional managed llama.cpp install/update: aegis ai setup --download-llama",
			"3. Recommended model: Gemma 4 E4B or Gemma 3 4B instruct GGUF, Q4_K_M",
			"4. Fast model path: llama-server -hf lmstudio-community/gemma-4-E4B-it-GGUF:Q4_K_M --host 127.0.0.1 --port 8080",
			"5. Configure: aegis ai config --backend llamacpp-server --endpoint http://127.0.0.1:8080/v1/chat/completions",
			"6. Press r here after starting/configuring it.",
		}
		for _, line := range setup {
			b.WriteString("  " + dimStyle.Render(wrapText(line, max(m.width-6, 36), "  ")) + "\n")
		}
		b.WriteString("\n")
	}

	if m.aiEditing {
		mode := "Ask"
		if m.aiNoteMode {
			mode = "Remember"
		}
		b.WriteString("  " + cardTitleStyle.Render(strings.ToUpper(mode)) + "\n")
		b.WriteString("  " + m.aiInput.View() + "\n\n")
	}

	actions := []string{footerKeyStyle.Render("n") + " remember local context", footerKeyStyle.Render("r") + " refresh status"}
	if ready {
		actions = []string{
			footerKeyStyle.Render("a") + " ask",
			footerKeyStyle.Render("x") + " explain selected scan threat",
			footerKeyStyle.Render("n") + " remember local context",
			footerKeyStyle.Render("t") + " test model",
			footerKeyStyle.Render("r") + " refresh status",
		}
	}
	b.WriteString("  " + strings.Join(actions, dimStyle.Render("  ·  ")) + "\n")
	b.WriteString(dimStyle.Render("  Local AI is advisory: it explains findings but never overrides signatures, rules or canaries.") + "\n")

	if m.aiErr != "" {
		b.WriteString("\n  " + statusErrStyle.Render("AI: "+m.aiErr) + "\n")
	}
	if m.aiPrompt != "" {
		b.WriteString("\n  " + cardTitleStyle.Render("LAST QUESTION") + "\n")
		b.WriteString("  " + dimStyle.Render(wrapText(m.aiPrompt, max(m.width-6, 32), "  ")) + "\n")
	}
	if m.aiReply != "" {
		b.WriteString("\n  " + cardTitleStyle.Render("ANSWER") + "\n")
		b.WriteString("  " + textStyle.Render(wrapText(m.aiReply, max(m.width-6, 32), "  ")) + "\n")
	}
	if len(m.aiNotes) > 0 {
		b.WriteString("\n  " + cardTitleStyle.Render("RECENT CONTEXT") + "\n")
		start := 0
		if len(m.aiNotes) > 4 {
			start = len(m.aiNotes) - 4
		}
		for _, note := range m.aiNotes[start:] {
			b.WriteString("  " + dimStyle.Render("- ") + textStyle.Render(truncate(note.Text, max(m.width-8, 24))) + "\n")
		}
	}
	return b.String()
}

// ---- helpers ----

func tabLabel(i int, name string, width int) string {
	if width < 54 {
		return fmt.Sprintf("%d %s", i+1, shortTabName(name))
	}
	return fmt.Sprintf("%d %s", i+1, name)
}

func shortTabName(name string) string {
	switch name {
	case "Dashboard":
		return "Dash"
	case "Scanner":
		return "Scan"
	case "Shield":
		return "Shld"
	case "Network":
		return "Net"
	case "Firewall":
		return "FW"
	case "Audit":
		return "Audit"
	}
	return name
}

func aiModelLabel(cfg ai.Config) string {
	if cfg.Backend == ai.BackendCLI && cfg.ModelPath != "" {
		return cfg.ModelPath
	}
	if cfg.Model != "" {
		return cfg.Model
	}
	return "local"
}

func renderKeyBar(keys [][2]string, width int) string {
	sep := footerDescStyle.Render("  ·  ")
	lines := []string{""}
	for _, k := range keys {
		part := footerKeyStyle.Render(k[0]) + " " + footerDescStyle.Render(k[1])
		last := lines[len(lines)-1]
		next := part
		if last != "" {
			next = last + sep + part
		}
		if last != "" && lipgloss.Width(next) > width {
			lines = append(lines, part)
			continue
		}
		lines[len(lines)-1] = next
	}
	return strings.Join(lines, "\n")
}

func wrapStyledLine(s string, width int) string {
	if lipgloss.Width(s) <= width {
		return s
	}
	return dimStyle.Render(wrapText(stripSimpleANSI(s), width, ""))
}

func stripSimpleANSI(s string) string {
	var b strings.Builder
	inEsc := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if inEsc {
			if c >= '@' && c <= '~' {
				inEsc = false
			}
			continue
		}
		if c == 0x1b {
			inEsc = true
			continue
		}
		b.WriteByte(c)
	}
	return b.String()
}

func auditOrder(entries []persist.Entry) []int {
	order := make([]int, 0, len(entries))
	for i, e := range entries {
		if e.Suspect != "" {
			order = append(order, i)
		}
	}
	for i, e := range entries {
		if e.Suspect == "" {
			order = append(order, i)
		}
	}
	return order
}

func indexOf(xs []int, needle int) int {
	for i, x := range xs {
		if x == needle {
			return i
		}
	}
	return -1
}

func humanAge(d time.Duration) string {
	switch {
	case d < time.Minute:
		return "moments"
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%dh", int(d.Hours()))
	default:
		return fmt.Sprintf("%dd", int(d.Hours()/24))
	}
}

func truncate(s string, width int) string {
	if width < 8 {
		width = 8
	}
	if len(s) <= width {
		return s
	}
	return s[:width-1] + "…"
}

func shortenPath(p string, width int) string {
	if width < 20 {
		width = 20
	}
	if len(p) <= width {
		return p
	}
	base := filepath.Base(p)
	if len(base)+3 >= width {
		return "…" + base[len(base)-(width-1):]
	}
	return p[:width-len(base)-3] + "…/" + base
}

func wrapText(s string, width int, indent string) string {
	if width < 20 {
		width = 20
	}
	var out []string
	for _, para := range strings.Split(s, "\n") {
		words := strings.Fields(para)
		if len(words) == 0 {
			out = append(out, "")
			continue
		}
		line := words[0]
		for _, w := range words[1:] {
			if len(line)+1+len(w) > width {
				out = append(out, line)
				line = w
			} else {
				line += " " + w
			}
		}
		out = append(out, line)
	}
	return strings.Join(out, "\n"+indent)
}

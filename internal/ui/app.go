// Package ui implements the aegis terminal interface (Bubble Tea).
package ui

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/progress"
	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/table"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/andreipaciurca/aegis/internal/ai"
	"github.com/andreipaciurca/aegis/internal/appsync"
	"github.com/andreipaciurca/aegis/internal/firewall"
	"github.com/andreipaciurca/aegis/internal/maintenance"
	"github.com/andreipaciurca/aegis/internal/netmon"
	"github.com/andreipaciurca/aegis/internal/persist"
	"github.com/andreipaciurca/aegis/internal/ransom"
	"github.com/andreipaciurca/aegis/internal/remediate"
	"github.com/andreipaciurca/aegis/internal/rules"
	"github.com/andreipaciurca/aegis/internal/scanner"
	"github.com/andreipaciurca/aegis/internal/signatures"
)

var Version = "1.6.2"

type tabID int

const (
	tabDashboard tabID = iota
	tabScanner
	tabShield
	tabNetwork
	tabFirewall
	tabAudit
	tabAI
)

const tabCount = 7

var tabNames = []string{"Dashboard", "Scanner", "Shield", "Network", "Firewall", "Audit", "AI"}

// ---- messages ----

type scanMsg scanner.Progress
type fwMsg firewall.Status
type netMsg struct {
	conns []netmon.Conn
	err   error
}
type updateMsg struct {
	report  maintenance.Report
	install *maintenance.InstallResult
}
type quarMsg struct {
	rec scanner.QuarantineRecord
	err error
	idx int
}
type quarHistoryMsg struct {
	recs []scanner.QuarantineRecord
	err  error
}
type restoreMsg struct {
	rec scanner.QuarantineRecord
	err error
}
type fwToggleMsg struct{ err error }
type netTickMsg struct{}
type clearStatusMsg struct{ id int }

type shieldMsg struct {
	events []ransom.Event
	live   bool // came from the background monitor
}
type deployMsg struct {
	n   int
	err error
}
type cleanupMsg struct {
	n   int
	err error
}
type auditMsg struct{ entries []persist.Entry }
type actionMsg struct {
	label string
	err   error
}
type monitorTickMsg struct{}
type aiStatusMsg struct {
	status ai.Status
	notes  []ai.Note
	err    error
}
type aiReplyMsg struct {
	prompt string
	reply  string
	err    error
}
type startupMsg maintenance.Report

// confirmState gates a destructive action behind a y/n prompt.
type confirmState struct {
	prompt string
	action tea.Cmd
}

// ---- model ----

type Model struct {
	db     *signatures.DB
	eng    *rules.Engine
	width  int
	height int
	tab    tabID

	status    string
	statusErr bool
	statusID  int
	confirm   *confirmState
	showHelp  bool

	// scanner
	pathInput  textinput.Model
	editing    bool
	scanning   bool
	scanCancel chan struct{}
	scanCh     <-chan scanner.Progress
	prog       scanner.Progress
	lastScan   *scanner.Progress
	bar        progress.Model
	spin       spinner.Model
	sel        int

	// quarantine history/restore, shown within the Scanner tab
	quarantineView bool
	quarHistory    []scanner.QuarantineRecord
	quarSel        int
	quarBusy       bool

	// shield (ransomware)
	canaryDirs   []string
	canaryCount  int
	shieldEvents []ransom.Event
	shieldSel    int
	shieldBusy   bool
	monitoring   bool

	// firewall
	fw        firewall.Status
	fwLoaded  bool
	fwWorking bool

	// network
	netTable  table.Model
	conns     []netmon.Conn
	netErr    error
	netLoaded bool

	// audit (persistence)
	auditEntries []persist.Entry
	auditSel     int
	auditLoaded  bool

	// local AI analyst
	aiCfg      ai.Config
	aiStatus   ai.Status
	aiLoaded   bool
	aiInput    textinput.Model
	aiEditing  bool
	aiBusy     bool
	aiPrompt   string
	aiReply    string
	aiErr      string
	aiNotes    []ai.Note
	aiNoteMode bool

	updating bool

	startupMaintenance bool
}

func New(db *signatures.DB, eng *rules.Engine) Model {
	return NewWithOptions(db, eng, Options{StartupMaintenance: true})
}

type Options struct {
	StartupMaintenance bool
}

func NewWithOptions(db *signatures.DB, eng *rules.Engine, opts Options) Model {
	home, _ := os.UserHomeDir()
	ti := textinput.New()
	ti.Placeholder = "path to scan"
	ti.SetValue(home)
	ti.CharLimit = 512
	ti.Prompt = "▸ "
	ti.PromptStyle = lipgloss.NewStyle().Foreground(cMauve)
	ti.TextStyle = textStyle

	aiInput := textinput.New()
	aiInput.Placeholder = "ask the local analyst..."
	aiInput.CharLimit = 1024
	aiInput.Prompt = "ask ▸ "
	aiInput.PromptStyle = lipgloss.NewStyle().Foreground(cBlue)
	aiInput.TextStyle = textStyle

	sp := spinner.New(spinner.WithSpinner(spinner.MiniDot))
	sp.Style = lipgloss.NewStyle().Foreground(cMauve)

	bar := progress.New(progress.WithGradient("#cba6f7", "#89b4fa"))

	cols := []table.Column{
		{Title: "Process", Width: 14}, {Title: "PID", Width: 7},
		{Title: "Proto", Width: 6}, {Title: "Local", Width: 22},
		{Title: "Remote", Width: 22}, {Title: "State", Width: 12},
		{Title: "Flag", Width: 30},
	}
	nt := table.New(table.WithColumns(cols), table.WithHeight(12))
	st := table.DefaultStyles()
	st.Header = st.Header.Foreground(cSubtle).Bold(true).BorderStyle(lipgloss.NormalBorder()).
		BorderForeground(cMuted).BorderBottom(true)
	st.Selected = selStyle
	nt.SetStyles(st)

	cfg, _ := ai.Load()
	return Model{
		db: db, eng: eng, pathInput: ti, spin: sp, bar: bar, netTable: nt,
		canaryDirs:         ransom.DefaultDirs(),
		canaryCount:        len(ransom.LoadManifest().Canaries),
		aiCfg:              cfg,
		aiInput:            aiInput,
		startupMaintenance: opts.StartupMaintenance,
	}
}

func (m Model) Init() tea.Cmd {
	cmds := []tea.Cmd{fetchFirewall, fetchNet, fetchAudit, fetchAIStatus, m.spin.Tick}
	if m.startupMaintenance {
		cmds = append(cmds, startupMaintenance(m.db))
	}
	return tea.Batch(cmds...)
}

// ---- commands ----

func fetchFirewall() tea.Msg { return fwMsg(firewall.Get()) }

func fetchNet() tea.Msg {
	conns, err := netmon.List()
	return netMsg{conns: conns, err: err}
}

func fetchAudit() tea.Msg { return auditMsg{entries: persist.Audit()} }

func fetchAIStatus() tea.Msg {
	cfg, err := ai.Load()
	if err != nil {
		return aiStatusMsg{err: err}
	}
	notes, _ := ai.Notes()
	return aiStatusMsg{status: ai.Check(cfg), notes: notes}
}

func startupMaintenance(db *signatures.DB) tea.Cmd {
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
		defer cancel()
		return startupMsg(maintenance.StartupCached(ctx, db, Version, maintenance.StartupInterval()))
	}
}

func netTick() tea.Cmd {
	return tea.Tick(3*time.Second, func(time.Time) tea.Msg { return netTickMsg{} })
}

func monitorTick() tea.Cmd {
	return tea.Tick(3*time.Second, func(time.Time) tea.Msg { return monitorTickMsg{} })
}

func (m *Model) startScan() tea.Cmd {
	root := strings.TrimSpace(m.pathInput.Value())
	if root == "" {
		return m.flash("enter a path to scan", true)
	}
	if _, err := os.Stat(root); err != nil {
		return m.flash("cannot open "+root, true)
	}
	m.scanning = true
	m.sel = 0
	m.scanCancel = make(chan struct{})
	m.scanCh = scanner.Scan(root, m.db, m.eng, m.scanCancel)
	return waitScan(m.scanCh)
}

func waitScan(ch <-chan scanner.Progress) tea.Cmd {
	return func() tea.Msg {
		p, ok := <-ch
		if !ok {
			return nil
		}
		return scanMsg(p)
	}
}

func (m *Model) runUpdate() tea.Cmd {
	m.updating = true
	db := m.db
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
		defer cancel()
		report := maintenance.Startup(ctx, db, Version)
		var install *maintenance.InstallResult
		if report.Aegis.Update {
			r := maintenance.InstallUpdate(ctx, report.Aegis.Latest)
			install = &r
		}
		return updateMsg{report: report, install: install}
	}
}

func fetchQuarantineHistory() tea.Msg {
	recs, err := scanner.QuarantineHistory()
	return quarHistoryMsg{recs: recs, err: err}
}

func restoreQuarantine(id string) tea.Cmd {
	return func() tea.Msg {
		rec, err := scanner.Restore(id)
		return restoreMsg{rec: rec, err: err}
	}
}

func shieldCheck(dirs []string, live bool) tea.Cmd {
	return func() tea.Msg {
		return shieldMsg{events: ransom.Check(dirs), live: live}
	}
}

func deployCanaries(dirs []string) tea.Cmd {
	return func() tea.Msg {
		m, err := ransom.Deploy(dirs)
		return deployMsg{n: len(m.Canaries), err: err}
	}
}

func cleanupCanaries() tea.Cmd {
	return func() tea.Msg {
		n, err := ransom.Cleanup()
		return cleanupMsg{n: n, err: err}
	}
}

func (m *Model) flash(s string, isErr bool) tea.Cmd {
	m.status, m.statusErr = s, isErr
	m.statusID++
	id := m.statusID
	return tea.Tick(6*time.Second, func(time.Time) tea.Msg { return clearStatusMsg{id: id} })
}

// selectedConn returns the network connection under the table cursor.
func (m Model) selectedConn() (netmon.Conn, bool) {
	i := m.netTable.Cursor()
	if i >= 0 && i < len(m.conns) {
		return m.conns[i], true
	}
	return netmon.Conn{}, false
}

// ---- update ----

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmds []tea.Cmd

	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		m.bar.Width = min(m.width-10, 70)
		m.netTable.SetHeight(max(m.height-14, 4))
		m.sizeNetColumns()
		return m, nil

	case tea.KeyMsg:
		if m.showHelp {
			switch msg.String() {
			case "?", "h", "esc":
				m.showHelp = false
				return m, nil
			case "q", "ctrl+c":
				m.stopScan()
				return m, tea.Quit
			}
		}
		// Confirmation prompt intercepts all keys.
		if m.confirm != nil {
			switch msg.String() {
			case "y", "Y", "enter":
				act := m.confirm.action
				m.confirm = nil
				return m, act
			default:
				m.confirm = nil
				return m, m.flash("cancelled", false)
			}
		}
		if m.aiEditing {
			switch msg.String() {
			case "enter":
				prompt := strings.TrimSpace(m.aiInput.Value())
				m.aiEditing = false
				m.aiInput.Blur()
				m.aiInput.SetValue("")
				if prompt == "" {
					return m, nil
				}
				if m.aiNoteMode {
					m.aiNoteMode = false
					if err := ai.AddNote(prompt); err != nil {
						return m, m.flash("remember failed: "+err.Error(), true)
					}
					return m, tea.Batch(fetchAIStatus, m.flash("remembered local context", false))
				}
				if !m.aiReady() {
					return m, m.flash("local AI is not ready; start llama.cpp and press r", true)
				}
				m.aiBusy = true
				return m, tea.Batch(m.askAI(prompt), m.spin.Tick)
			case "esc":
				m.aiEditing = false
				m.aiNoteMode = false
				m.aiInput.Blur()
				return m, nil
			default:
				var cmd tea.Cmd
				m.aiInput, cmd = m.aiInput.Update(msg)
				return m, cmd
			}
		}
		if m.editing {
			switch msg.String() {
			case "enter", "esc":
				m.editing = false
				m.pathInput.Blur()
				return m, nil
			default:
				var cmd tea.Cmd
				m.pathInput, cmd = m.pathInput.Update(msg)
				return m, cmd
			}
		}
		switch msg.String() {
		case "?", "h":
			m.showHelp = true
		case "q", "ctrl+c":
			m.stopScan()
			return m, tea.Quit
		case "1":
			m.tab = tabDashboard
		case "2":
			m.tab = tabScanner
		case "3":
			m.tab = tabShield
		case "4":
			m.tab = tabNetwork
			m.netTable.Focus()
		case "5":
			m.tab = tabFirewall
		case "6":
			m.tab = tabAudit
		case "7":
			m.tab = tabAI
		case "tab":
			m.tab = (m.tab + 1) % tabCount
		case "shift+tab":
			m.tab = (m.tab + tabCount - 1) % tabCount
		case "u":
			if !m.updating {
				cmds = append(cmds, m.runUpdate(), m.spin.Tick)
			}
		case "r":
			cmds = append(cmds, fetchFirewall, fetchNet, fetchAudit, fetchAIStatus, fetchQuarantineHistory)
		default:
			cmds = append(cmds, m.tabKeys(msg)...)
		}
		if m.tab == tabNetwork {
			var cmd tea.Cmd
			m.netTable, cmd = m.netTable.Update(msg)
			cmds = append(cmds, cmd)
		}
		return m, tea.Batch(cmds...)

	case scanMsg:
		m.prog = scanner.Progress(msg)
		if m.prog.Phase == "done" || m.prog.Phase == "cancelled" || m.prog.Phase == "error" {
			m.scanning = false
			m.scanCancel = nil
			m.scanCh = nil
			p := m.prog
			if m.prog.Phase == "cancelled" {
				cmds = append(cmds, m.flash(fmt.Sprintf("scan cancelled after %d files", m.prog.Scanned), false))
			} else if m.prog.Phase == "error" {
				m.lastScan = &p
				cmds = append(cmds, m.flash("scan failed: "+fmt.Sprint(m.prog.Err), true))
			} else {
				m.lastScan = &p
				cmds = append(cmds, m.flash(fmt.Sprintf("scan complete: %d files, %d threat(s)",
					m.prog.Scanned, len(m.prog.Threats)), len(m.prog.Threats) > 0))
			}
		} else {
			cmds = append(cmds, waitScan(m.scanCh))
		}
		return m, tea.Batch(cmds...)

	case fwMsg:
		m.fw = firewall.Status(msg)
		m.fwLoaded = true
		m.fwWorking = false
		return m, nil

	case fwToggleMsg:
		m.fwWorking = false
		if msg.err != nil {
			return m, tea.Batch(fetchFirewall, m.flash(msg.err.Error(), true))
		}
		return m, tea.Batch(fetchFirewall, m.flash("firewall updated", false))

	case netMsg:
		m.netLoaded = true
		m.netErr = msg.err
		if msg.err == nil {
			m.conns = msg.conns
			m.netTable.SetRows(connRows(m.conns))
		}
		return m, netTick()

	case netTickMsg:
		return m, fetchNet

	case auditMsg:
		m.auditEntries = msg.entries
		m.auditLoaded = true
		if m.auditSel >= len(m.auditEntries) {
			m.auditSel = 0
		}
		return m, nil

	case aiStatusMsg:
		if msg.err != nil {
			m.aiLoaded = true
			m.aiErr = msg.err.Error()
			return m, nil
		}
		m.aiStatus = msg.status
		m.aiCfg = msg.status.Config
		m.aiNotes = msg.notes
		m.aiLoaded = true
		m.aiErr = ""
		return m, nil

	case aiReplyMsg:
		m.aiBusy = false
		m.aiPrompt = msg.prompt
		if msg.err != nil {
			m.aiErr = msg.err.Error()
			return m, m.flash("local AI failed: "+msg.err.Error(), true)
		}
		m.aiErr = ""
		m.aiReply = msg.reply
		return m, m.flash("local AI answered", false)

	case startupMsg:
		text, isErr := maintenance.Summary(maintenance.Report(msg))
		return m, tea.Batch(fetchAIStatus, m.flash(text, isErr))

	case appsync.Event:
		cmds := []tea.Cmd{m.flash(msg.Text, msg.Error)}
		switch msg.Kind {
		case "scan", "update", "startup":
			cmds = append(cmds, fetchFirewall, fetchNet, fetchAudit, fetchAIStatus)
		case "checkup", "ai":
			cmds = append(cmds, fetchAIStatus)
		}
		return m, tea.Batch(cmds...)

	case shieldMsg:
		m.shieldBusy = false
		m.shieldEvents = msg.events
		m.shieldSel = 0
		crit := 0
		for _, e := range msg.events {
			if e.Severity == "CRITICAL" {
				crit++
			}
		}
		if !msg.live {
			if len(msg.events) == 0 {
				cmds = append(cmds, m.flash("ransomware sweep clean", false))
			} else {
				cmds = append(cmds, m.flash(fmt.Sprintf("sweep: %d finding(s), %d critical", len(msg.events), crit), true))
			}
		} else if crit > 0 {
			cmds = append(cmds, m.flash(fmt.Sprintf("⚠ ransomware activity detected: %d critical", crit), true))
		}
		if m.monitoring {
			cmds = append(cmds, monitorTick())
		}
		return m, tea.Batch(cmds...)

	case monitorTickMsg:
		if m.monitoring {
			return m, shieldCheck(m.canaryDirs, true)
		}
		return m, nil

	case deployMsg:
		m.shieldBusy = false
		if msg.err != nil {
			return m, m.flash("canary deploy failed: "+msg.err.Error(), true)
		}
		m.canaryCount = msg.n
		return m, m.flash(fmt.Sprintf("%d canary tripwires deployed across %d folders", msg.n, len(m.canaryDirs)), false)

	case cleanupMsg:
		m.shieldBusy = false
		m.canaryCount = 0
		return m, m.flash(fmt.Sprintf("removed %d canary files", msg.n), false)

	case actionMsg:
		if msg.err != nil {
			return m, m.flash(msg.label+": "+msg.err.Error(), true)
		}
		return m, tea.Batch(fetchNet, m.flash(msg.label, false))

	case updateMsg:
		m.updating = false
		text, isErr := maintenance.Summary(msg.report)
		if msg.install != nil {
			switch {
			case msg.install.Installed:
				text += " · installed " + msg.install.Version + ", restart aegis to use it"
			case msg.install.NeedsSudo:
				text += " · install failed (needs elevated permissions): " + msg.install.Error
				isErr = true
			default:
				text += " · install failed: " + msg.install.Error
				isErr = true
			}
		}
		return m, m.flash(text, isErr)

	case quarMsg:
		if msg.err != nil {
			return m, m.flash("quarantine failed: "+msg.err.Error(), true)
		}
		if m.lastScan != nil && msg.idx < len(m.lastScan.Threats) {
			m.lastScan.Threats = append(m.lastScan.Threats[:msg.idx], m.lastScan.Threats[msg.idx+1:]...)
			if m.sel >= len(m.lastScan.Threats) && m.sel > 0 {
				m.sel--
			}
		}
		return m, m.flash("quarantined → "+msg.rec.Stored, false)

	case quarHistoryMsg:
		m.quarBusy = false
		if msg.err != nil {
			return m, m.flash("quarantine history failed: "+msg.err.Error(), true)
		}
		m.quarHistory = msg.recs
		if m.quarSel >= len(m.quarHistory) {
			m.quarSel = 0
		}
		return m, nil

	case restoreMsg:
		m.quarBusy = false
		if msg.err != nil {
			return m, m.flash("restore failed: "+msg.err.Error(), true)
		}
		for i, r := range m.quarHistory {
			if r.Stored == msg.rec.Stored {
				m.quarHistory[i] = msg.rec
				break
			}
		}
		return m, m.flash("restored → "+msg.rec.Original, false)

	case clearStatusMsg:
		if msg.id == m.statusID {
			m.status = ""
		}
		return m, nil

	case spinner.TickMsg:
		var cmd tea.Cmd
		m.spin, cmd = m.spin.Update(msg)
		if m.scanning || m.updating || m.fwWorking || m.shieldBusy || m.aiBusy || m.quarBusy {
			return m, cmd
		}
		return m, nil
	}

	return m, tea.Batch(cmds...)
}

// tabKeys handles keys specific to the active tab.
func (m *Model) tabKeys(msg tea.KeyMsg) []tea.Cmd {
	var cmds []tea.Cmd
	switch m.tab {
	case tabScanner:
		if m.quarantineView {
			switch msg.String() {
			case "v", "esc":
				m.quarantineView = false
			case "up", "k":
				if m.quarSel > 0 {
					m.quarSel--
				}
			case "down", "j":
				if m.quarSel < len(m.quarHistory)-1 {
					m.quarSel++
				}
			case "x":
				if m.quarSel < len(m.quarHistory) {
					r := m.quarHistory[m.quarSel]
					if r.Restored {
						cmds = append(cmds, m.flash("already restored", true))
					} else {
						m.quarBusy = true
						cmds = append(cmds, restoreQuarantine(r.Stored), m.spin.Tick)
					}
				}
			}
			return cmds
		}
		switch msg.String() {
		case "e", "p":
			m.editing = true
			m.pathInput.Focus()
			cmds = append(cmds, textinput.Blink)
		case "s", "enter":
			if !m.scanning {
				cmds = append(cmds, m.startScan(), m.spin.Tick)
			}
		case "c":
			if m.scanning {
				m.stopScan()
				cmds = append(cmds, m.flash("scan cancelled", false))
			}
		case "v":
			m.quarantineView = true
			m.quarBusy = true
			cmds = append(cmds, fetchQuarantineHistory, m.spin.Tick)
		case "up", "k":
			if m.sel > 0 {
				m.sel--
			}
		case "down", "j":
			if t := m.threats(); m.sel < len(t)-1 {
				m.sel++
			}
		case "x":
			if t := m.threats(); len(t) > 0 && m.sel < len(t) && !m.scanning {
				th, idx := t[m.sel], m.sel
				cmds = append(cmds, func() tea.Msg {
					rec, err := scanner.Quarantine(th)
					return quarMsg{rec: rec, err: err, idx: idx}
				})
			}
		}

	case tabShield:
		switch msg.String() {
		case "d":
			if len(m.canaryDirs) == 0 {
				cmds = append(cmds, m.flash("no Documents/Desktop/Pictures folders to protect", true))
			} else {
				m.shieldBusy = true
				cmds = append(cmds, deployCanaries(m.canaryDirs), m.spin.Tick)
			}
		case "c":
			m.shieldBusy = true
			cmds = append(cmds, cleanupCanaries(), m.spin.Tick)
		case "s":
			m.shieldBusy = true
			cmds = append(cmds, shieldCheck(m.canaryDirs, false), m.spin.Tick)
		case "m":
			m.monitoring = !m.monitoring
			if m.monitoring {
				cmds = append(cmds, monitorTick(), m.spin.Tick, m.flash("real-time monitor on (checks every 3s)", false))
			} else {
				cmds = append(cmds, m.flash("real-time monitor off", false))
			}
		case "up", "k":
			if m.shieldSel > 0 {
				m.shieldSel--
			}
		case "down", "j":
			if m.shieldSel < len(m.shieldEvents)-1 {
				m.shieldSel++
			}
		}

	case tabFirewall:
		switch msg.String() {
		case "e":
			m.fwWorking = true
			cmds = append(cmds, func() tea.Msg { return fwToggleMsg{err: firewall.SetEnabled(true)} }, m.spin.Tick)
		case "d":
			m.fwWorking = true
			cmds = append(cmds, func() tea.Msg { return fwToggleMsg{err: firewall.SetEnabled(false)} }, m.spin.Tick)
		case "t":
			m.fwWorking = true
			on := m.fw.StealthMode != "on"
			cmds = append(cmds, func() tea.Msg { return fwToggleMsg{err: firewall.SetStealth(on)} }, m.spin.Tick)
		}

	case tabNetwork:
		switch msg.String() {
		case "k":
			if c, ok := m.selectedConn(); ok {
				if pid, err := strconv.Atoi(c.PID); err == nil {
					proc, p := c.Proc, pid
					m.confirm = &confirmState{
						prompt: fmt.Sprintf("terminate %s (pid %d)?", proc, pid),
						action: func() tea.Msg {
							err := remediate.KillPID(p)
							return actionMsg{label: fmt.Sprintf("killed %s (pid %d)", proc, p), err: err}
						},
					}
				} else {
					cmds = append(cmds, m.flash("no numeric PID for this row", true))
				}
			}
		case "b":
			if c, ok := m.selectedConn(); ok {
				lp := lastColon(c.Local)
				sug := remediate.ForConnection(c.Proc, c.PID, lp, c.Remote, c.Suspect)
				for _, s := range sug {
					if strings.HasPrefix(s.Title, "Block") {
						cmds = append(cmds, m.flash("run: "+s.Command, false))
					}
				}
			}
		}

	case tabAudit:
		switch msg.String() {
		case "up", "k":
			order := auditOrder(m.auditEntries)
			if vis := indexOf(order, m.auditSel); vis > 0 {
				m.auditSel = order[vis-1]
			}
		case "down", "j":
			order := auditOrder(m.auditEntries)
			if vis := indexOf(order, m.auditSel); vis >= 0 && vis < len(order)-1 {
				m.auditSel = order[vis+1]
			}
		case "x":
			if m.auditSel < len(m.auditEntries) {
				e := m.auditEntries[m.auditSel]
				cmds = append(cmds, m.flash("run: "+e.DisableCmd, false))
			}
		}

	case tabAI:
		switch msg.String() {
		case "a", "enter":
			if !m.aiReady() {
				cmds = append(cmds, m.flash("local AI is offline; follow SETUP, then press r", true))
				break
			}
			m.aiNoteMode = false
			m.aiInput.Placeholder = "ask about Aegis, a finding, or your system..."
			m.aiInput.Prompt = "ask ▸ "
			m.aiEditing = true
			m.aiInput.Focus()
			cmds = append(cmds, textinput.Blink)
		case "n":
			m.aiNoteMode = true
			m.aiInput.Placeholder = "remember local context..."
			m.aiInput.Prompt = "note ▸ "
			m.aiEditing = true
			m.aiInput.Focus()
			cmds = append(cmds, textinput.Blink)
		case "t":
			if !m.aiReady() {
				cmds = append(cmds, m.flash("cannot test yet: start llama-server or configure llama-cli", true))
				break
			}
			m.aiBusy = true
			cmds = append(cmds, m.askAI("Briefly confirm you are ready to explain Aegis security findings."), m.spin.Tick)
		case "r":
			cmds = append(cmds, fetchAIStatus)
		case "x":
			if !m.aiReady() {
				cmds = append(cmds, m.flash("cannot explain yet: local AI is offline", true))
				break
			}
			if th, ok := m.selectedThreat(); ok {
				m.aiBusy = true
				cmds = append(cmds, m.askAI(threatPrompt(th, m.aiCfg)), m.spin.Tick)
			} else {
				cmds = append(cmds, m.flash("run a scan and select a threat first", true))
			}
		}
	}
	return cmds
}

func (m Model) aiReady() bool {
	if !m.aiLoaded {
		return false
	}
	switch m.aiCfg.Backend {
	case ai.BackendServer:
		return m.aiStatus.ServerReady
	case ai.BackendCLI:
		if !m.aiStatus.CLIReady || strings.TrimSpace(m.aiCfg.ModelPath) == "" {
			return false
		}
		_, err := os.Stat(m.aiCfg.ModelPath)
		return err == nil
	case ai.BackendOpenAICompatible:
		return m.aiStatus.RemoteReady
	default:
		return false
	}
}

func (m Model) aiOfflineReason() string {
	if !m.aiLoaded {
		return "checking local AI configuration"
	}
	switch m.aiCfg.Backend {
	case ai.BackendServer:
		if !m.aiStatus.ServerReady {
			if m.aiStatus.Message != "" {
				return m.aiStatus.Message
			}
			return "llama-server is not answering at " + m.aiCfg.Endpoint
		}
	case ai.BackendCLI:
		if !m.aiStatus.CLIReady {
			if m.aiStatus.Message != "" {
				return m.aiStatus.Message
			}
			return m.aiCfg.Command + " was not found on PATH"
		}
		if strings.TrimSpace(m.aiCfg.ModelPath) == "" {
			return "model path is not configured"
		}
		if _, err := os.Stat(m.aiCfg.ModelPath); err != nil {
			return "model file not found: " + m.aiCfg.ModelPath
		}
	case ai.BackendOpenAICompatible:
		if !m.aiStatus.RemoteReady {
			if m.aiStatus.Message != "" {
				return m.aiStatus.Message
			}
			return "remote API key or model is not configured"
		}
	default:
		return "unsupported backend: " + m.aiCfg.Backend
	}
	return "local AI backend is not ready"
}

func (m Model) askAI(prompt string) tea.Cmd {
	cfg := m.aiCfg
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		reply, err := ai.Generate(ctx, cfg, ai.Request{
			System: ai.PromptWithNotes(ai.SecuritySystemPrompt()),
			Prompt: prompt,
		})
		return aiReplyMsg{prompt: prompt, reply: reply, err: err}
	}
}

func (m Model) selectedThreat() (scanner.Threat, bool) {
	t := m.threats()
	if len(t) == 0 || m.sel < 0 || m.sel >= len(t) {
		return scanner.Threat{}, false
	}
	return t[m.sel], true
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

func (m *Model) stopScan() {
	if m.scanCancel != nil {
		close(m.scanCancel)
		m.scanCancel = nil
	}
	m.scanning = false
}

func (m Model) threats() []scanner.Threat {
	if m.scanning {
		return m.prog.Threats
	}
	if m.lastScan != nil {
		return m.lastScan.Threats
	}
	return nil
}

func connRows(conns []netmon.Conn) []table.Row {
	rows := make([]table.Row, 0, len(conns))
	for _, c := range conns {
		flag := c.Suspect
		if flag != "" {
			flag = "⚠ " + flag
		}
		rows = append(rows, table.Row{c.Proc, c.PID, c.Proto, c.Local, c.Remote, c.State, flag})
	}
	return rows
}

func lastColon(addr string) string {
	i := strings.LastIndex(addr, ":")
	if i < 0 || i == len(addr)-1 {
		return ""
	}
	return addr[i+1:]
}

func (m *Model) sizeNetColumns() {
	w := m.width - 10
	if w < 60 {
		return
	}
	cols := m.netTable.Columns()
	rest := w - (14 + 7 + 6 + 12)
	cols[3].Width = rest * 3 / 10
	cols[4].Width = rest * 3 / 10
	cols[6].Width = rest - cols[3].Width - cols[4].Width
	m.netTable.SetColumns(cols)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

package ui

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/charmbracelet/lipgloss"

	"github.com/andreipaciurca/aegis/internal/ai"
	"github.com/andreipaciurca/aegis/internal/firewall"
	"github.com/andreipaciurca/aegis/internal/rules"
	"github.com/andreipaciurca/aegis/internal/scanner"
	"github.com/andreipaciurca/aegis/internal/signatures"
)

func TestDashboardFitsCommonTerminalWidths(t *testing.T) {
	eng, err := rules.Load(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	db := &signatures.DB{Hashes: map[string]struct{}{}, Meta: signatures.Meta{}}
	for _, width := range []int{44, 60, 80, 129, 189} {
		m := New(db, eng)
		m.width = width
		m.height = 40
		m.tab = tabDashboard
		view := m.View()
		for lineNo, line := range strings.Split(view, "\n") {
			if got := lipgloss.Width(line); got > width {
				t.Fatalf("width %d line %d overflows: got %d: %q", width, lineNo+1, got, line)
			}
		}
	}
}

func TestDashboardUsesClearPostureAndPrioritizesShortTerminals(t *testing.T) {
	eng, err := rules.Load(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	db := &signatures.DB{Hashes: map[string]struct{}{}, Meta: signatures.Meta{}}
	m := New(db, eng)
	m.width = 80
	m.height = 24
	m.tab = tabDashboard
	m.fwLoaded = true
	m.fw.Enabled = true
	m.netLoaded = true
	m.auditLoaded = true
	view := m.View()
	if !strings.Contains(view, "PROTECTION POSTURE") || !strings.Contains(view, "CLEAR") {
		t.Fatalf("dashboard does not explain the current security posture:\n%s", view)
	}
	if strings.Contains(view, "LOCAL AI") || strings.Contains(view, "CHECKUP") {
		t.Fatalf("short dashboard should keep secondary tools out of the primary grid:\n%s", view)
	}
}

func TestDashboardPostureExplainsDeductions(t *testing.T) {
	m := Model{fwLoaded: true, fw: firewall.Status{Enabled: false}}
	p := m.dashboardPosture()
	if p.label != "ACTION NEEDED" || !strings.Contains(p.detail, "firewall needs attention") {
		t.Fatalf("unexpected posture: %#v", p)
	}
}

func TestHelpFitsCommonTerminalWidths(t *testing.T) {
	eng, err := rules.Load(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	db := &signatures.DB{Hashes: map[string]struct{}{}, Meta: signatures.Meta{}}
	for _, width := range []int{44, 60, 80, 129} {
		m := New(db, eng)
		m.width = width
		m.height = 40
		m.showHelp = true
		view := m.View()
		if !strings.Contains(view, "START HERE") {
			t.Fatalf("help view missing start section at width %d", width)
		}
		for lineNo, line := range strings.Split(view, "\n") {
			if got := lipgloss.Width(line); got > width {
				t.Fatalf("help width %d line %d overflows: got %d: %q", width, lineNo+1, got, line)
			}
		}
	}
}

func TestThreatPromptRedactsParentDirectories(t *testing.T) {
	path := filepath.Join(t.TempDir(), "Client Name", "payload.exe")
	prompt := threatPrompt(scanner.Threat{
		Path:     path,
		SHA256:   strings.Repeat("a", 64),
		Reason:   "test",
		Severity: scanner.SevCritical,
		Size:     10,
	}, ai.Config{PrivacyMode: "metadata"})
	if strings.Contains(prompt, filepath.Dir(path)) || strings.Contains(prompt, "Client Name") {
		t.Fatalf("TUI AI prompt leaked parent path:\n%s", prompt)
	}
	if !strings.Contains(prompt, "payload.exe") {
		t.Fatalf("TUI AI prompt should keep filename context:\n%s", prompt)
	}
}

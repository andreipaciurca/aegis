package ui

import (
	"strings"
	"testing"

	"github.com/charmbracelet/lipgloss"

	"github.com/andreipaciurca/aegis/internal/rules"
	"github.com/andreipaciurca/aegis/internal/signatures"
)

func TestDashboardFitsCommonTerminalWidths(t *testing.T) {
	eng, err := rules.Load(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	db := &signatures.DB{Hashes: map[string]struct{}{}, Meta: signatures.Meta{}}
	for _, width := range []int{44, 60, 80, 129} {
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

package ui

import "github.com/charmbracelet/lipgloss"

// Palette — Catppuccin Mocha, easy on the eyes in dark terminals.
var (
	cText    = lipgloss.Color("#cdd6f4")
	cSubtle  = lipgloss.Color("#7f849c")
	cMuted   = lipgloss.Color("#585b70")
	cBlue    = lipgloss.Color("#89b4fa")
	cGreen   = lipgloss.Color("#a6e3a1")
	cRed     = lipgloss.Color("#f38ba8")
	cYellow  = lipgloss.Color("#f9e2af")
	cMauve   = lipgloss.Color("#cba6f7")
	cPeach   = lipgloss.Color("#fab387")
	cSurface = lipgloss.Color("#313244")
	cCrust   = lipgloss.Color("#11111b")
)

var (
	logoStyle = lipgloss.NewStyle().Bold(true).Foreground(cCrust).
			Background(cMauve).Padding(0, 1)

	tabStyle = lipgloss.NewStyle().Foreground(cSubtle).Padding(0, 1)

	tabActiveStyle = lipgloss.NewStyle().Foreground(cMauve).Bold(true).
			Padding(0, 1).Underline(true)

	cardStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).BorderForeground(cMuted).
			Padding(0, 2).MarginRight(2)

	cardTitleStyle = lipgloss.NewStyle().Foreground(cSubtle).Bold(true)

	okStyle   = lipgloss.NewStyle().Foreground(cGreen).Bold(true)
	badStyle  = lipgloss.NewStyle().Foreground(cRed).Bold(true)
	warnStyle = lipgloss.NewStyle().Foreground(cYellow).Bold(true)
	dimStyle  = lipgloss.NewStyle().Foreground(cSubtle)
	textStyle = lipgloss.NewStyle().Foreground(cText)
	blueStyle = lipgloss.NewStyle().Foreground(cBlue)

	panelStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).BorderForeground(cMuted).
			Padding(0, 1)

	footerKeyStyle  = lipgloss.NewStyle().Foreground(cMauve).Bold(true)
	footerDescStyle = lipgloss.NewStyle().Foreground(cSubtle)

	statusOKStyle  = lipgloss.NewStyle().Foreground(cGreen)
	statusErrStyle = lipgloss.NewStyle().Foreground(cRed)

	selStyle = lipgloss.NewStyle().Background(cSurface).Foreground(cText).Bold(true)
)

func sevStyle(sev string) lipgloss.Style {
	switch sev {
	case "CRITICAL":
		return badStyle
	case "WARNING":
		return warnStyle
	}
	return dimStyle
}

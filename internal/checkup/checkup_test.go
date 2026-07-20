package checkup

import (
	"strings"
	"testing"
)

func TestOutputMeansClean(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"No new software available.\n", true},
		{"[]", true},
		{"All packages are up to date.", true},
		{"Nothing to do.", true},
		{"foo/bar 1.0 -> 2.0 [bumped major]", false},
	}
	for _, c := range cases {
		if got := outputMeansClean(c.in); got != c.want {
			t.Errorf("outputMeansClean(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestFilterGoUpdates(t *testing.T) {
	in := []string{
		"github.com/foo/bar v1.0.0 [v1.1.0]",
		"github.com/foo/baz v1.0.0", // no update available, no bracket
		"golang.org/x/sys v0.1.0 [v0.2.0]",
	}
	got := filterGoUpdates(in)
	if len(got) != 2 {
		t.Fatalf("expected 2 lines with available updates, got %d: %v", len(got), got)
	}
	for _, line := range got {
		if !strings.Contains(line, " [") {
			t.Errorf("expected only lines with an update bracket, got %q", line)
		}
	}
}

func TestRemediationForKnownTools(t *testing.T) {
	cases := map[string]string{
		"softwareupdate -l":                            "sudo softwareupdate -ia --restart",
		"apt list --upgradable":                        "sudo apt update",
		"brew outdated --quiet":                        "brew upgrade",
		"npm outdated -g --depth=0":                    "npm update -g",
		"python -m pip list --outdated --format=json":  "python -m pip install --upgrade <package>",
		"python3 -m pip list --outdated --format=json": "python3 -m pip install --upgrade <package>",
		"winget upgrade":                               "winget upgrade --all",
		"Get-HotFix":                                   "PowerShell: Start-Process ms-settings:windowsupdate",
		"go list -m -u all":                            "go get -u ./...",
	}
	for command, want := range cases {
		got := remediationFor(command)
		if len(got) == 0 || got[0] != want {
			t.Errorf("remediationFor(%q) = %v, want first command %q", command, got, want)
		}
	}
}

func TestTrimCollapsesWhitespaceAndTruncates(t *testing.T) {
	got := trim("  a   critical   vulnerability   description  ", 15)
	if len([]rune(got)) > 15 {
		t.Fatalf("trim exceeded requested length: %q (%d runes)", got, len([]rune(got)))
	}
	if !strings.HasSuffix(got, "…") {
		t.Errorf("expected truncated output to end with an ellipsis, got %q", got)
	}
	short := trim("short text", 100)
	if short != "short text" {
		t.Errorf("trim should not alter text shorter than the limit, got %q", short)
	}
}

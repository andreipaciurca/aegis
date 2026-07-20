// Package persist audits autostart / persistence mechanisms — the places
// malware plants itself to survive a reboot. It reads the same locations an
// analyst checks by hand (LaunchAgents, systemd, cron, autostart, Run keys)
// and flags entries that look suspicious, with a command to disable each.
package persist

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
)

// Entry is one autostart item.
type Entry struct {
	Source     string `json:"source"`      // where it lives (LaunchAgent, cron, systemd …)
	Label      string `json:"label"`       // name/identifier
	Command    string `json:"command"`     // what it runs
	Path       string `json:"path"`        // file backing it, if any
	Suspect    string `json:"suspect"`     // non-empty = why it's flagged
	DisableCmd string `json:"disable_cmd"` // how to remove/disable it
}

// Audit enumerates persistence entries for the current OS.
func Audit() []Entry {
	switch runtime.GOOS {
	case "darwin":
		return auditDarwin()
	case "linux":
		return auditLinux()
	case "windows":
		return auditWindows()
	}
	return nil
}

// suspicious returns a reason string if a command/path looks malicious.
func suspicious(cmd, path string) string {
	l := strings.ToLower(cmd + " " + path)
	checks := []struct{ pat, why string }{
		{"/tmp/", "runs from a temporary directory"},
		{"/private/tmp/", "runs from a temporary directory"},
		{"/var/tmp/", "runs from a temporary directory"},
		{`\temp\`, "runs from a temporary directory"},
		{"/downloads/", "runs from the Downloads folder"},
		{`\downloads\`, "runs from the Downloads folder"},
		{"base64", "decodes a base64 payload"},
		{"curl ", "downloads and runs remote code"},
		{"wget ", "downloads and runs remote code"},
		{"-enc ", "obfuscated encoded command"},
		{"-encodedcommand", "obfuscated encoded command"},
		{"python -c", "inline script payload"},
		{"perl -e", "inline script payload"},
		{"bash -c", "inline shell payload"},
		{"/dev/tcp/", "reverse-shell network redirect"},
		{"nc -e", "netcat backdoor"},
		{"ncat ", "netcat backdoor"},
		{"certutil -urlcache", "certutil used as a downloader (LOLBin)"},
		{"certutil -decode", "certutil used to decode a payload (LOLBin)"},
		{"wscript", "script host launching a payload"},
		{"cscript", "script host launching a payload"},
	}
	for _, c := range checks {
		if strings.Contains(l, c.pat) {
			return c.why
		}
	}
	// Two-part Windows LOLBin signals: the binary alone is common and
	// legitimate, but paired with a remote URL or inline script it's a
	// well-documented living-off-the-land abuse pattern.
	if strings.Contains(l, "mshta") && strings.Contains(l, "http") {
		return "mshta launching a remote HTA (LOLBin)"
	}
	if strings.Contains(l, "regsvr32") && strings.Contains(l, "/i:") && strings.Contains(l, "http") {
		return "regsvr32 /i: remote script execution (Squiblydoo)"
	}
	if strings.Contains(l, "rundll32") && strings.Contains(l, "javascript:") {
		return "rundll32 executing inline JavaScript (LOLBin)"
	}
	// Hidden binary path.
	if strings.Contains(path, "/.") && (strings.HasSuffix(l, ".sh") || filepath.Ext(path) == "") {
		return "hidden executable path"
	}
	return ""
}

// ---- macOS ----

var (
	reProgram     = regexp.MustCompile(`(?s)<key>\s*Program\s*</key>\s*<string>(.*?)</string>`)
	reProgramArgs = regexp.MustCompile(`(?s)<key>\s*ProgramArguments\s*</key>\s*<array>(.*?)</array>`)
	reString      = regexp.MustCompile(`<string>(.*?)</string>`)
)

func auditDarwin() []Entry {
	home, _ := os.UserHomeDir()
	dirs := []struct{ path, src string }{
		{filepath.Join(home, "Library/LaunchAgents"), "LaunchAgent (user)"},
		{"/Library/LaunchAgents", "LaunchAgent (system)"},
		{"/Library/LaunchDaemons", "LaunchDaemon"},
	}
	var entries []Entry
	for _, d := range dirs {
		files, _ := os.ReadDir(d.path)
		for _, f := range files {
			if f.IsDir() || !strings.HasSuffix(f.Name(), ".plist") {
				continue
			}
			full := filepath.Join(d.path, f.Name())
			b, err := os.ReadFile(full)
			if err != nil {
				continue
			}
			cmd := extractPlistCommand(string(b))
			e := Entry{
				Source:     d.src,
				Label:      strings.TrimSuffix(f.Name(), ".plist"),
				Command:    cmd,
				Path:       full,
				DisableCmd: "launchctl bootout gui/$(id -u) " + full + " 2>/dev/null; mv " + full + " " + full + ".disabled",
			}
			e.Suspect = suspicious(cmd, cmd)
			entries = append(entries, e)
		}
	}
	return entries
}

func extractPlistCommand(xml string) string {
	if m := reProgramArgs.FindStringSubmatch(xml); m != nil {
		var args []string
		for _, s := range reString.FindAllStringSubmatch(m[1], -1) {
			args = append(args, s[1])
		}
		if len(args) > 0 {
			return strings.Join(args, " ")
		}
	}
	if m := reProgram.FindStringSubmatch(xml); m != nil {
		return m[1]
	}
	return "(not specified)"
}

// ---- Linux ----

func auditLinux() []Entry {
	home, _ := os.UserHomeDir()
	var entries []Entry

	// XDG autostart .desktop files.
	autostart := filepath.Join(home, ".config/autostart")
	files, _ := os.ReadDir(autostart)
	for _, f := range files {
		if !strings.HasSuffix(f.Name(), ".desktop") {
			continue
		}
		full := filepath.Join(autostart, f.Name())
		cmd := grepLine(full, "Exec=")
		e := Entry{Source: "autostart", Label: f.Name(), Command: cmd, Path: full,
			DisableCmd: "rm " + full}
		e.Suspect = suspicious(cmd, cmd)
		entries = append(entries, e)
	}

	// systemd user services.
	sysd := filepath.Join(home, ".config/systemd/user")
	sfiles, _ := os.ReadDir(sysd)
	for _, f := range sfiles {
		if !strings.HasSuffix(f.Name(), ".service") {
			continue
		}
		full := filepath.Join(sysd, f.Name())
		cmd := grepLine(full, "ExecStart=")
		e := Entry{Source: "systemd (user)", Label: f.Name(), Command: cmd, Path: full,
			DisableCmd: "systemctl --user disable " + strings.TrimSuffix(f.Name(), ".service")}
		e.Suspect = suspicious(cmd, cmd)
		entries = append(entries, e)
	}

	// crontab entries.
	if out, err := exec.Command("crontab", "-l").Output(); err == nil {
		for _, line := range strings.Split(string(out), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			e := Entry{Source: "crontab", Label: "cron job", Command: line,
				DisableCmd: "crontab -e  # remove the offending line"}
			e.Suspect = suspicious(line, line)
			entries = append(entries, e)
		}
	}
	return entries
}

func grepLine(path, prefix string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), prefix) {
			return strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), prefix))
		}
	}
	return ""
}

// ---- Windows ----

func auditWindows() []Entry {
	var entries []Entry
	entries = append(entries, auditWindowsRegistryRun()...)
	entries = append(entries, auditWindowsScheduledTasks()...)
	entries = append(entries, auditWindowsServices()...)
	return entries
}

func auditWindowsRegistryRun() []Entry {
	var entries []Entry
	keys := []struct{ hive, path string }{
		{"HKCU", `Software\Microsoft\Windows\CurrentVersion\Run`},
		{"HKLM", `Software\Microsoft\Windows\CurrentVersion\Run`},
		{"HKCU", `Software\Microsoft\Windows\CurrentVersion\RunOnce`},
	}
	for _, k := range keys {
		full := k.hive + `\` + k.path
		out, err := exec.Command("reg", "query", full).Output()
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(out), "\n") {
			fields := strings.Fields(strings.TrimSpace(line))
			if len(fields) < 3 || strings.HasPrefix(strings.TrimSpace(line), full) {
				continue
			}
			name := fields[0]
			cmd := strings.Join(fields[2:], " ")
			e := Entry{Source: "registry Run", Label: name, Command: cmd, Path: full,
				DisableCmd: `reg delete "` + full + `" /v ` + name + " /f"}
			e.Suspect = suspicious(cmd, cmd)
			entries = append(entries, e)
		}
	}
	return entries
}

type winTask struct {
	Name    string `json:"Name"`
	Path    string `json:"Path"`
	Command string `json:"Command"`
}

// auditWindowsScheduledTasks lists non-Microsoft scheduled tasks — a common
// persistence mechanism, arguably more common than Run keys in modern
// campaigns. Windows ships hundreds of built-in tasks under \Microsoft\...;
// they're signed and low-signal for a persistence audit, so they're excluded
// here the same way a human analyst would skip them during triage.
func auditWindowsScheduledTasks() []Entry {
	script := `@(Get-ScheduledTask | Where-Object {$_.State -ne 'Disabled'} | ForEach-Object {
  $cmd = ($_.Actions | ForEach-Object { ("$($_.Execute) $($_.Arguments)").Trim() }) -join '; '
  [PSCustomObject]@{ Name = $_.TaskName; Path = $_.TaskPath; Command = $cmd }
}) | ConvertTo-Json -Compress`
	out, err := exec.Command("powershell", "-NoProfile", "-Command", script).Output()
	if err != nil {
		return nil
	}
	var tasks []winTask
	if err := json.Unmarshal(out, &tasks); err != nil {
		return nil
	}
	var entries []Entry
	for _, t := range tasks {
		if strings.HasPrefix(t.Path, `\Microsoft\`) {
			continue
		}
		full := t.Path + t.Name
		e := Entry{Source: "Scheduled Task", Label: full, Command: t.Command, Path: full,
			DisableCmd: `schtasks /Change /TN "` + full + `" /Disable`}
		e.Suspect = suspicious(t.Command, full)
		entries = append(entries, e)
	}
	return entries
}

type winService struct {
	Name     string `json:"Name"`
	PathName string `json:"PathName"`
}

// auditWindowsServices lists auto-start Windows services. Unlike scheduled
// tasks there's no large built-in noise floor to filter, so every auto-start
// service is reported and left to the suspicious() heuristic to flag.
func auditWindowsServices() []Entry {
	script := `@(Get-CimInstance Win32_Service | Where-Object {$_.StartMode -eq 'Auto'} | Select-Object Name,PathName) | ConvertTo-Json -Compress`
	out, err := exec.Command("powershell", "-NoProfile", "-Command", script).Output()
	if err != nil {
		return nil
	}
	var services []winService
	if err := json.Unmarshal(out, &services); err != nil {
		return nil
	}
	var entries []Entry
	for _, s := range services {
		e := Entry{Source: "Service (auto-start)", Label: s.Name, Command: s.PathName, Path: s.PathName,
			DisableCmd: `sc.exe config "` + s.Name + `" start= disabled`}
		e.Suspect = suspicious(s.PathName, s.PathName)
		entries = append(entries, e)
	}
	return entries
}

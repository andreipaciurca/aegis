// Package remediate turns findings into actions: it kills a process, generates
// the exact firewall command to block a port, and builds human-readable fix
// suggestions. Anything that needs privilege is returned as a command to run
// rather than executed silently.
package remediate

import (
	"fmt"
	"os"
	"runtime"
	"strconv"
	"syscall"
)

// Suggestion is a recommended fix. If Auto is true, Apply performs it directly;
// otherwise Command holds the shell command for the user to run.
type Suggestion struct {
	Title    string
	Detail   string
	Command  string
	Severity string // "CRITICAL" | "WARNING" | "INFO"
	Auto     bool
	apply    func() error
}

// Apply runs the automatic action, or explains that a manual command is needed.
func (s Suggestion) Apply() error {
	if s.apply == nil {
		return fmt.Errorf("run manually: %s", s.Command)
	}
	return s.apply()
}

// KillPID terminates a process. It refuses PIDs that would be dangerous
// (init/system, or aegis itself).
func KillPID(pid int) error {
	if pid <= 1 {
		return fmt.Errorf("refusing to kill pid %d", pid)
	}
	if pid == os.Getpid() {
		return fmt.Errorf("refusing to kill aegis itself")
	}
	p, err := os.FindProcess(pid)
	if err != nil {
		return err
	}
	if runtime.GOOS == "windows" {
		return p.Kill()
	}
	if err := p.Signal(syscall.SIGTERM); err != nil {
		return p.Kill()
	}
	return nil
}

// blockPortCommand returns the native firewall command to drop inbound traffic
// on a TCP port for the current OS.
func blockPortCommand(port string) string {
	switch runtime.GOOS {
	case "linux":
		return "sudo ufw deny " + port + "/tcp   # or: sudo iptables -A INPUT -p tcp --dport " + port + " -j DROP"
	case "windows":
		return `netsh advfirewall firewall add rule name="aegis-block-` + port +
			`" dir=in action=block protocol=TCP localport=` + port
	case "darwin":
		return `echo "block drop in proto tcp from any to any port ` + port +
			`" | sudo pfctl -ef - 2>/dev/null   # persists until pf is reloaded`
	}
	return "(no firewall command available for this platform)"
}

// ForConnection builds fixes for a flagged network connection.
func ForConnection(proc, pidStr, localPort, remote, reason string) []Suggestion {
	var out []Suggestion
	if pid, err := strconv.Atoi(pidStr); err == nil && pid > 1 {
		p := pid
		out = append(out, Suggestion{
			Title:    fmt.Sprintf("Terminate %s (pid %d)", proc, pid),
			Detail:   "stops the process holding this connection",
			Command:  "kill " + pidStr,
			Severity: "CRITICAL",
			Auto:     true,
			apply:    func() error { return KillPID(p) },
		})
	}
	if localPort != "" {
		out = append(out, Suggestion{
			Title:    "Block inbound port " + localPort,
			Detail:   "drops new connections to this port at the OS firewall",
			Command:  blockPortCommand(localPort),
			Severity: "WARNING",
		})
	}
	return out
}

// ForPersistence builds a fix for a suspicious autostart entry.
func ForPersistence(label, disableCmd string) Suggestion {
	return Suggestion{
		Title:    "Disable autostart: " + label,
		Detail:   "removes this persistence mechanism",
		Command:  disableCmd,
		Severity: "CRITICAL",
	}
}

// Package firewall wraps each platform's native firewall so aegis adds no
// kernel-level machinery of its own: macOS Application Firewall + pf,
// Linux ufw/nftables/iptables, Windows Defender Firewall.
package firewall

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

// Status is a snapshot of the host firewall.
type Status struct {
	Backend     string `json:"backend"`      // which engine we detected
	Enabled     bool   `json:"enabled"`      // whether the firewall is active
	Detail      string `json:"detail"`       // human summary lines
	StealthMode string `json:"stealth_mode"` // macOS only: "on"/"off"/""
	RuleCount   int    `json:"rule_count"`   // rules/anchors where countable
	Err         error  `json:"-"`
}

const socketfilterfw = "/usr/libexec/ApplicationFirewall/socketfilterfw"

// Get inspects the host firewall. Never needs root (degrades gracefully).
func Get() Status {
	switch runtime.GOOS {
	case "darwin":
		return darwinStatus()
	case "linux":
		return linuxStatus()
	case "windows":
		return windowsStatus()
	default:
		return Status{Backend: runtime.GOOS, Err: fmt.Errorf("unsupported platform")}
	}
}

// SetEnabled turns the firewall on/off. Needs privileges; if we don't have
// them, the returned error includes the exact command for the user to run.
func SetEnabled(on bool) error {
	state := "off"
	if on {
		state = "on"
	}
	switch runtime.GOOS {
	case "darwin":
		return runPrivileged([]string{socketfilterfw, "--setglobalstate", state},
			fmt.Sprintf("sudo %s --setglobalstate %s", socketfilterfw, state))
	case "linux":
		if _, err := exec.LookPath("ufw"); err == nil {
			verb := "disable"
			if on {
				verb = "enable"
			}
			return runPrivileged([]string{"ufw", verb}, "sudo ufw "+verb)
		}
		return fmt.Errorf("no ufw found; manage nftables/iptables rules directly")
	case "windows":
		return run("netsh", "advfirewall", "set", "allprofiles", "state", state)
	}
	return fmt.Errorf("unsupported platform")
}

// SetStealth toggles macOS stealth mode (ignore ICMP/port probes).
func SetStealth(on bool) error {
	if runtime.GOOS != "darwin" {
		return fmt.Errorf("stealth mode is macOS-only")
	}
	state := "off"
	if on {
		state = "on"
	}
	return runPrivileged([]string{socketfilterfw, "--setstealthmode", state},
		fmt.Sprintf("sudo %s --setstealthmode %s", socketfilterfw, state))
}

func darwinStatus() Status {
	s := Status{Backend: "macOS Application Firewall"}
	out, err := output(socketfilterfw, "--getglobalstate")
	if err != nil {
		s.Err = err
		return s
	}
	s.Enabled = strings.Contains(out, "enabled")
	if st, err := output(socketfilterfw, "--getstealthmode"); err == nil {
		if strings.Contains(st, "enabled") {
			s.StealthMode = "on"
		} else {
			s.StealthMode = "off"
		}
	}
	if bl, err := output(socketfilterfw, "--getblockall"); err == nil && strings.Contains(bl, "enabled") {
		s.Detail = "Block-all mode active. "
	}
	// pf (packet filter) status is root-only; report it when we can see it.
	if pf, err := output("pfctl", "-s", "info"); err == nil {
		if strings.Contains(pf, "Status: Enabled") {
			s.Detail += "pf packet filter: enabled."
		} else if strings.Contains(pf, "Status: Disabled") {
			s.Detail += "pf packet filter: disabled."
		}
	} else {
		s.Detail += "pf status needs root."
	}
	if apps, err := output(socketfilterfw, "--listapps"); err == nil {
		s.RuleCount = strings.Count(apps, "ALF:")
		if s.RuleCount == 0 {
			s.RuleCount = strings.Count(apps, "( Allow")
		}
	}
	return s
}

func linuxStatus() Status {
	if _, err := exec.LookPath("ufw"); err == nil {
		s := Status{Backend: "ufw"}
		out, err := output("ufw", "status")
		if err != nil {
			s.Err = fmt.Errorf("ufw status needs root: %w", err)
			return s
		}
		s.Enabled = strings.Contains(out, "Status: active")
		s.RuleCount = strings.Count(out, "ALLOW") + strings.Count(out, "DENY")
		return s
	}
	if _, err := exec.LookPath("nft"); err == nil {
		s := Status{Backend: "nftables"}
		out, err := output("nft", "list", "ruleset")
		if err != nil {
			s.Err = fmt.Errorf("nft needs root: %w", err)
			return s
		}
		s.RuleCount = strings.Count(out, "\n")
		s.Enabled = strings.Contains(out, "hook input")
		return s
	}
	if _, err := exec.LookPath("iptables"); err == nil {
		s := Status{Backend: "iptables"}
		out, err := output("iptables", "-S")
		if err != nil {
			s.Err = fmt.Errorf("iptables needs root: %w", err)
			return s
		}
		rules := strings.Count(out, "\n")
		s.RuleCount = rules
		s.Enabled = rules > 3 // more than the default -P policy lines
		return s
	}
	return Status{Backend: "none", Err: fmt.Errorf("no ufw/nftables/iptables found")}
}

func windowsStatus() Status {
	s := Status{Backend: "Windows Defender Firewall"}
	out, err := output("netsh", "advfirewall", "show", "allprofiles", "state")
	if err != nil {
		s.Err = err
		return s
	}
	s.Enabled = strings.Contains(out, "ON")
	return s
}

func output(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	cmd.Env = os.Environ()
	b, err := cmd.CombinedOutput()
	if err != nil {
		return string(b), fmt.Errorf("%s: %v", name, err)
	}
	return string(b), nil
}

func run(name string, args ...string) error {
	_, err := output(name, args...)
	return err
}

// runPrivileged tries the command directly, then via non-interactive sudo.
// If both fail it returns an error carrying the command the user should run.
func runPrivileged(argv []string, hint string) error {
	if os.Geteuid() == 0 {
		return run(argv[0], argv[1:]...)
	}
	sudoArgs := append([]string{"-n", "--"}, argv...)
	cmd := exec.Command("sudo", sudoArgs...)
	cmd.WaitDelay = 5 * time.Second
	if out, err := cmd.CombinedOutput(); err != nil {
		_ = out
		return fmt.Errorf("needs privileges — run: %s", hint)
	}
	return nil
}

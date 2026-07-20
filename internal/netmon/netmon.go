// Package netmon lists live network connections by parsing the platform's
// native tooling (lsof on macOS/Linux, netstat on Windows). No root needed:
// on Unix we simply see only our user's sockets without it.
package netmon

import (
	"os/exec"
	"runtime"
	"sort"
	"strconv"
	"strings"
)

// Conn is one open network connection or listener.
type Conn struct {
	Proc    string `json:"proc"`
	PID     string `json:"pid"`
	Proto   string `json:"proto"`
	Local   string `json:"local"`
	Remote  string `json:"remote"`
	State   string `json:"state"`
	Suspect string `json:"suspect"` // non-empty = why this line is flagged
}

// Well-known ports that legitimately carry most traffic.
var commonPorts = map[string]bool{
	"80": true, "443": true, "53": true, "22": true, "993": true, "995": true,
	"587": true, "465": true, "123": true, "5223": true, "8080": true, "8443": true,
}

// Ports historically associated with remote access / C2 tooling.
var riskyPorts = map[string]string{
	"4444":  "common reverse-shell port",
	"5555":  "common backdoor/adb port",
	"6667":  "IRC (legacy botnet C2)",
	"1337":  "leet backdoor port",
	"31337": "Back Orifice port",
	"3389":  "RDP exposed",
	"23":    "telnet (plaintext)",
}

// List returns current connections, listeners first then established.
func List() ([]Conn, error) {
	var conns []Conn
	var err error
	if runtime.GOOS == "windows" {
		conns, err = listWindows()
	} else {
		conns, err = listUnix()
	}
	if err != nil {
		return nil, err
	}
	for i := range conns {
		conns[i].Suspect = assess(conns[i])
	}
	conns = dedupe(conns)
	sort.SliceStable(conns, func(i, j int) bool {
		si, sj := conns[i].Suspect != "", conns[j].Suspect != ""
		if si != sj {
			return si
		}
		return conns[i].Proc < conns[j].Proc
	})
	return conns, nil
}

func dedupe(conns []Conn) []Conn {
	seen := make(map[string]struct{}, len(conns))
	out := conns[:0]
	for _, c := range conns {
		key := c.Proc + "\x00" + c.PID + "\x00" + c.Proto + "\x00" + c.Local + "\x00" + c.Remote + "\x00" + c.State
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, c)
	}
	return out
}

func listUnix() ([]Conn, error) {
	out, err := exec.Command("lsof", "-i", "-n", "-P").Output()
	if err != nil && len(out) == 0 {
		return nil, err
	}
	var conns []Conn
	lines := strings.Split(string(out), "\n")
	for _, line := range lines[1:] {
		f := strings.Fields(line)
		if len(f) < 9 {
			continue
		}
		c := Conn{Proc: f[0], PID: f[1], Proto: f[7]}
		addr := strings.Join(f[8:], " ")
		if i := strings.Index(addr, " ("); i >= 0 {
			c.State = strings.Trim(addr[i+1:], "() ")
			addr = addr[:i]
		}
		if parts := strings.Split(addr, "->"); len(parts) == 2 {
			c.Local, c.Remote = parts[0], parts[1]
		} else {
			c.Local = addr
		}
		conns = append(conns, c)
	}
	return conns, nil
}

func listWindows() ([]Conn, error) {
	out, err := exec.Command("netstat", "-ano").Output()
	if err != nil {
		return nil, err
	}
	var conns []Conn
	for _, line := range strings.Split(string(out), "\n") {
		f := strings.Fields(strings.TrimSpace(line))
		if len(f) < 4 || (f[0] != "TCP" && f[0] != "UDP") {
			continue
		}
		c := Conn{Proto: f[0], Local: f[1], Remote: f[2]}
		if f[0] == "TCP" && len(f) >= 5 {
			c.State, c.PID = f[3], f[4]
		} else {
			c.PID = f[len(f)-1]
		}
		c.Proc = "pid:" + c.PID
		conns = append(conns, c)
	}
	return conns, nil
}

func port(addr string) string {
	i := strings.LastIndex(addr, ":")
	if i < 0 {
		return ""
	}
	p := addr[i+1:]
	if _, err := strconv.Atoi(p); err != nil {
		return ""
	}
	return p
}

func assess(c Conn) string {
	rp := port(c.Remote)
	lp := port(c.Local)
	if trustedPlatformListener(c, lp) {
		return ""
	}
	if why, ok := riskyPorts[rp]; ok {
		return "remote " + rp + ": " + why
	}
	if why, ok := riskyPorts[lp]; ok && strings.Contains(strings.ToUpper(c.State), "LISTEN") {
		return "listening on " + lp + ": " + why
	}
	// Listener bound to all interfaces on an uncommon port.
	if strings.Contains(strings.ToUpper(c.State), "LISTEN") &&
		(strings.HasPrefix(c.Local, "*:") || strings.HasPrefix(c.Local, "0.0.0.0:") || strings.HasPrefix(c.Local, "[::]:")) {
		if lp != "" && !commonPorts[lp] {
			if n, _ := strconv.Atoi(lp); n < 10000 {
				return "listening on all interfaces (:" + lp + ")"
			}
		}
	}
	return ""
}

func trustedPlatformListener(c Conn, lp string) bool {
	if runtime.GOOS != "darwin" {
		return false
	}
	if c.Proc != "ControlCe" {
		return false
	}
	return lp == "5000" || lp == "7000"
}

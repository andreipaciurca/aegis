// Package rules is a lightweight, YARA-inspired detection engine: each rule is
// a set of conditions (substrings, hex byte patterns, a filename regex, a
// minimum entropy) evaluated against a file. Rules ship built-in and can be
// extended or overridden from a JSON file, so detection stays easy to update.
package rules

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// Rule is one detection definition. A rule matches when its conditions hold:
// with Match "all" (default) every specified condition must hold; with "any"
// a single condition is enough. Only non-empty conditions are considered.
type Rule struct {
	Name       string   `json:"name"`
	Severity   string   `json:"severity"` // "critical" | "warning" | "info"
	Desc       string   `json:"desc"`
	Strings    []string `json:"strings,omitempty"`     // case-insensitive substrings
	Hex        []string `json:"hex,omitempty"`         // hex byte patterns e.g. "4d5a9000"
	Filename   string   `json:"filename,omitempty"`    // regex over the base name
	MinEntropy float64  `json:"min_entropy,omitempty"` // >0 enables the check
	Match      string   `json:"match,omitempty"`       // "any" | "all"
}

// Hit is a rule that fired.
type Hit struct {
	Rule     string
	Severity string
	Desc     string
}

type compiled struct {
	r      Rule
	fnRe   *regexp.Regexp
	hexPat [][]byte
	words  [][]byte
}

// Engine holds the compiled rule set.
type Engine struct {
	rules []compiled
}

// Builtin rules cover common, high-signal malicious patterns. They are
// intentionally conservative to keep false positives low.
var Builtin = []Rule{
	{Name: "reverse_shell_bash", Severity: "critical", Match: "any",
		Desc:    "bash /dev/tcp reverse shell",
		Strings: []string{"bash -i >& /dev/tcp/", "sh -i >& /dev/tcp/", "0<&196;exec 196<>/dev/tcp"}},
	{Name: "reverse_shell_python", Severity: "critical", Match: "all",
		Desc:    "python socket reverse shell",
		Strings: []string{"socket.socket", "subprocess", "/bin/sh", "connect("}},
	{Name: "powershell_download_cradle", Severity: "critical", Match: "any",
		Desc:    "PowerShell in-memory download-and-execute",
		Strings: []string{"IEX (New-Object Net.WebClient).DownloadString", "IEX(New-Object Net.WebClient).DownloadString", "Invoke-Expression (New-Object Net.WebClient)"}},
	{Name: "powershell_encoded", Severity: "warning", Match: "any",
		Desc:    "obfuscated encoded PowerShell command",
		Strings: []string{"powershell -enc", "powershell.exe -e ", "-EncodedCommand", "FromBase64String"}},
	{Name: "mimikatz", Severity: "critical", Match: "any",
		Desc:    "Mimikatz credential-dumping strings",
		Strings: []string{"sekurlsa::logonpasswords", "privilege::debug", "lsadump::sam"}},
	{Name: "coinminer", Severity: "warning", Match: "any",
		Desc:    "cryptominer pool configuration",
		Strings: []string{"stratum+tcp://", "stratum+ssl://", "--cpu-priority", "xmrig"}},
	{Name: "ransom_note_text", Severity: "critical", Match: "all",
		Desc:    "text reads like a ransom note",
		Strings: []string{"your files have been encrypted", "bitcoin"}},
	{Name: "packed_executable", Severity: "warning", Match: "all",
		Desc:     "high-entropy body — possibly packed/encrypted executable",
		Filename: `\.(exe|dll|scr|sys)$`, MinEntropy: 7.2},
	{Name: "elf_high_entropy", Severity: "warning", Match: "all",
		Desc: "packed ELF binary",
		Hex:  []string{"7f454c46"}, MinEntropy: 7.4},
	{Name: "webshell_php", Severity: "critical", Match: "any",
		Desc:    "PHP webshell eval-of-request",
		Strings: []string{"eval($_post", "eval($_get", "eval($_request", "system($_get", "assert($_post"}},
}

// Load compiles the built-in rules merged with any user rules found in
// <config>/rules.json. User rules with the same name override built-ins.
func Load(configDir string) (*Engine, error) {
	merged := map[string]Rule{}
	for _, r := range Builtin {
		merged[r.Name] = r
	}
	var loadErr error
	if configDir != "" {
		path := filepath.Join(configDir, "rules.json")
		if b, err := os.ReadFile(path); err == nil {
			var user []Rule
			if err := json.Unmarshal(b, &user); err != nil {
				loadErr = err
			} else {
				for _, r := range user {
					merged[r.Name] = r
				}
			}
		}
	}
	e := &Engine{}
	for _, r := range merged {
		e.rules = append(e.rules, compile(r))
	}
	return e, loadErr
}

func compile(r Rule) compiled {
	c := compiled{r: r}
	if r.Filename != "" {
		c.fnRe, _ = regexp.Compile("(?i)" + r.Filename)
	}
	for _, h := range r.Hex {
		if b, err := hex.DecodeString(strings.ReplaceAll(h, " ", "")); err == nil {
			c.hexPat = append(c.hexPat, b)
		}
	}
	for _, s := range r.Strings {
		c.words = append(c.words, []byte(strings.ToLower(s)))
	}
	return c
}

// Count reports how many rules are loaded.
func (e *Engine) Count() int { return len(e.rules) }

// Match evaluates every rule against a file's name, a content sample and the
// sample's entropy, returning all rules that fired.
func (e *Engine) Match(name string, content []byte, ent float64) []Hit {
	base := strings.ToLower(filepath.Base(name))
	lowerContent := bytes.ToLower(content)
	var hits []Hit
	for _, c := range e.rules {
		if c.evaluate(base, content, lowerContent, ent) {
			hits = append(hits, Hit{Rule: c.r.Name, Severity: c.r.Severity, Desc: c.r.Desc})
		}
	}
	return hits
}

func (c compiled) evaluate(base string, content []byte, lowerContent []byte, ent float64) bool {
	any := strings.EqualFold(c.r.Match, "any")
	present := 0 // number of specified conditions
	satisfied := 0

	if c.fnRe != nil {
		present++
		if c.fnRe.MatchString(base) {
			satisfied++
		} else if !any {
			return false
		}
	}
	if len(c.words) > 0 {
		present++
		if c.matchStrings(lowerContent, any) {
			satisfied++
		} else if !any {
			return false
		}
	}
	if len(c.hexPat) > 0 {
		present++
		if c.matchHex(content, any) {
			satisfied++
		} else if !any {
			return false
		}
	}
	if c.r.MinEntropy > 0 {
		present++
		if ent >= c.r.MinEntropy {
			satisfied++
		} else if !any {
			return false
		}
	}

	if present == 0 {
		return false
	}
	if any {
		return satisfied > 0
	}
	return satisfied == present
}

// matchStrings: for "all" every substring must appear; for "any" one is enough.
func (c compiled) matchStrings(lowerContent []byte, any bool) bool {
	for _, s := range c.words {
		hit := bytes.Contains(lowerContent, s)
		if any && hit {
			return true
		}
		if !any && !hit {
			return false
		}
	}
	return !any
}

func (c compiled) matchHex(content []byte, any bool) bool {
	for _, p := range c.hexPat {
		hit := indexBytes(content, p)
		if any && hit {
			return true
		}
		if !any && !hit {
			return false
		}
	}
	return !any
}

func indexBytes(haystack, needle []byte) bool {
	return bytes.Contains(haystack, needle)
}

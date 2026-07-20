// Package ransom provides lightweight ransomware defence: honeypot "canary"
// files that are cheap to poll for tampering, plus a directory sweep for
// ransom notes, known encrypted-file extensions and entropy spikes. No kernel
// hooks, no continuous inotify tree — just a handful of tripwires.
package ransom

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/andreipaciurca/aegis/internal/entropy"
	"github.com/andreipaciurca/aegis/internal/signatures"
)

// KnownExtensions are suffixes appended by well-known ransomware families.
var KnownExtensions = map[string]bool{
	".locked": true, ".crypt": true, ".crypted": true, ".encrypted": true,
	".enc": true, ".locky": true, ".zepto": true, ".cerber": true, ".cerber3": true,
	".wannacry": true, ".wcry": true, ".wncry": true, ".wncryt": true,
	".ryuk": true, ".ryk": true, ".conti": true, ".lockbit": true,
	".djvu": true, ".stop": true, ".makop": true, ".phobos": true, ".dharma": true,
	".globe": true, ".osiris": true, ".odin": true, ".aesir": true, ".zzz": true,
	".micro": true, ".ecc": true, ".exx": true, ".abc": true, ".xyz": true, ".ttt": true,
	".petya": true, ".maze": true, ".egregor": true, ".darkside": true, ".hive": true,
	".blackcat": true, ".royal": true, ".akira": true, ".medusa": true,
}

// noteNames are common ransom-note filenames (matched case-insensitively).
var noteNames = []string{
	"readme_for_decrypt", "how_to_decrypt", "decrypt_instruction", "how_to_back_files",
	"restore_files", "recovery_key", "your_files", "help_decrypt", "readme_to_restore",
	"_readme.txt", "!!!readme", "decrypt-files", "how to decrypt", "restore-my-files",
	"read_me", "recover_your_files", "unlock_files", "!want_to_decrypt", "ransom",
}

// IsRansomNote reports whether a filename looks like a ransom note.
func IsRansomNote(name string) bool {
	n := strings.ToLower(name)
	for _, k := range noteNames {
		if strings.Contains(n, k) {
			return true
		}
	}
	return false
}

// HasKnownExtension reports whether a filename ends in a known ransomware ext.
func HasKnownExtension(name string) bool {
	return KnownExtensions[strings.ToLower(filepath.Ext(name))]
}

// Canary is one honeypot file we watch.
type Canary struct {
	Path    string  `json:"path"`
	SHA256  string  `json:"sha256"`
	Size    int64   `json:"size"`
	Entropy float64 `json:"entropy"`
}

// Manifest records deployed canaries so they can be checked and cleaned up.
type Manifest struct {
	Canaries []Canary  `json:"canaries"`
	Deployed time.Time `json:"deployed"`
}

// Severity strings match the scanner's vocabulary.
type Event struct {
	Kind     string `json:"kind"` // "canary" | "note" | "extension" | "entropy"
	Path     string `json:"path"`
	Detail   string `json:"detail"`
	Severity string `json:"severity"` // "CRITICAL" | "WARNING"
}

const canaryBody = `CONFIDENTIAL — internal reference sheet.
Account ledger, quarterly figures and archived correspondence.
This document is retained for record-keeping purposes only.
Do not modify. Row totals reconcile against the master workbook.
`

// canarySpecs are the decoy files, named to sort both first and last in a
// directory listing so alphabetical ransomware trips one early or late.
var canarySpecs = []string{
	".aegis_canary_0001.docx",
	".aegis_canary_zzzz.xlsx",
}

func manifestPath() (string, error) {
	dir, err := signatures.Dir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "canaries.json"), nil
}

// DefaultDirs returns the user directories worth protecting that exist.
func DefaultDirs() []string {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil
	}
	var dirs []string
	for _, sub := range []string{"Documents", "Desktop", "Pictures", "Downloads"} {
		p := filepath.Join(home, sub)
		if fi, err := os.Stat(p); err == nil && fi.IsDir() {
			dirs = append(dirs, p)
		}
	}
	return dirs
}

// Deploy writes canary files into each directory and saves the manifest.
func Deploy(dirs []string) (Manifest, error) {
	m := Manifest{Deployed: time.Now()}
	body := []byte(canaryBody)
	sum := sha256.Sum256(body)
	hexsum := hex.EncodeToString(sum[:])
	ent := entropy.Shannon(body)
	for _, dir := range dirs {
		for _, name := range canarySpecs {
			p := filepath.Join(dir, name)
			if err := os.WriteFile(p, body, 0o600); err != nil {
				continue // directory may be read-only; skip it
			}
			m.Canaries = append(m.Canaries, Canary{Path: p, SHA256: hexsum, Size: int64(len(body)), Entropy: ent})
		}
	}
	return m, saveManifest(m)
}

// LoadManifest reads the saved canary manifest, or an empty one.
func LoadManifest() Manifest {
	var m Manifest
	if p, err := manifestPath(); err == nil {
		if b, err := os.ReadFile(p); err == nil {
			_ = json.Unmarshal(b, &m)
		}
	}
	return m
}

func saveManifest(m Manifest) error {
	p, err := manifestPath()
	if err != nil {
		return err
	}
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(p, b, 0o600)
}

// Cleanup removes all deployed canary files and the manifest.
func Cleanup() (int, error) {
	m := LoadManifest()
	removed := 0
	for _, c := range m.Canaries {
		if err := os.Remove(c.Path); err == nil {
			removed++
		}
	}
	if p, err := manifestPath(); err == nil {
		_ = os.Remove(p)
	}
	return removed, nil
}

// CheckCanaries re-hashes every canary and reports tampering. A missing or
// altered canary is a strong ransomware signal.
func CheckCanaries() []Event {
	m := LoadManifest()
	var events []Event
	for _, c := range m.Canaries {
		data, err := os.ReadFile(c.Path)
		if err != nil {
			events = append(events, Event{Kind: "canary", Path: c.Path, Severity: "CRITICAL",
				Detail: "canary file missing — deleted or moved"})
			continue
		}
		sum := sha256.Sum256(data)
		if hex.EncodeToString(sum[:]) != c.SHA256 {
			detail := "canary modified"
			if e := entropy.Shannon(data); e > 7.0 {
				detail = "canary encrypted (entropy " + trim(e) + ") — active ransomware likely"
			}
			events = append(events, Event{Kind: "canary", Path: c.Path, Severity: "CRITICAL", Detail: detail})
		}
	}
	return events
}

// Sweep scans directories (shallow, one level deep) for ransom notes and
// known encrypted-file extensions. Cheap and bounded.
func Sweep(dirs []string) []Event {
	var events []Event
	const maxPerDir = 5000
	for _, dir := range dirs {
		count := 0
		_ = filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if d.IsDir() {
				if path != dir && strings.Count(path[len(dir):], string(filepath.Separator)) > 1 {
					return filepath.SkipDir // only one level deep
				}
				return nil
			}
			count++
			if count > maxPerDir {
				return filepath.SkipDir
			}
			name := d.Name()
			if HasKnownExtension(name) {
				events = append(events, Event{Kind: "extension", Path: path, Severity: "CRITICAL",
					Detail: "known ransomware extension " + filepath.Ext(name)})
			} else if IsRansomNote(name) {
				events = append(events, Event{Kind: "note", Path: path, Severity: "CRITICAL",
					Detail: "possible ransom note"})
			}
			return nil
		})
	}
	return events
}

// Check runs both canary verification and a directory sweep.
func Check(dirs []string) []Event {
	events := CheckCanaries()
	return append(events, Sweep(dirs)...)
}

func trim(f float64) string {
	return strconv.FormatFloat(f, 'f', 1, 64)
}

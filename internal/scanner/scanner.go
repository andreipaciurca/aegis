// Package scanner walks the filesystem, hashes files and reports threats
// found via signature matches or heuristics.
package scanner

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/andreipaciurca/aegis/internal/entropy"
	"github.com/andreipaciurca/aegis/internal/ransom"
	"github.com/andreipaciurca/aegis/internal/rules"
	"github.com/andreipaciurca/aegis/internal/signatures"
)

// MaxFileSize caps how large a file we will hash (skip huge media/VM images).
const MaxFileSize = 200 << 20 // 200 MiB

// headSize is how much of each file we read for rule and entropy analysis.
const headSize = 64 << 10 // 64 KiB

// EICAR is the standard, harmless antivirus test string.
var eicarMarker = []byte(`EICAR-STANDARD-ANTIVIRUS-TEST-FILE`)

// Severity of a finding.
type Severity int

const (
	SevInfo Severity = iota
	SevWarning
	SevCritical
)

func (s Severity) String() string {
	switch s {
	case SevCritical:
		return "CRITICAL"
	case SevWarning:
		return "WARNING"
	default:
		return "INFO"
	}
}

// Threat is a single finding.
type Threat struct {
	Path     string   `json:"path"`
	SHA256   string   `json:"sha256"`
	Reason   string   `json:"reason"`
	Severity Severity `json:"severity"`
	Size     int64    `json:"size"`
}

// Progress is a snapshot of a running scan.
type Progress struct {
	Phase   string // "counting" | "scanning" | "done" | "cancelled" | "error"
	Total   int64
	Scanned int64
	Skipped int64
	Current string
	Threats []Threat
	Err     error
	Started time.Time
	Ended   time.Time
}

var errScanCancelled = errors.New("scan cancelled")

// Scan walks root and streams Progress snapshots on the returned channel.
// The final message has Phase "done" (or "error") and the full threat list.
func Scan(root string, db *signatures.DB, eng *rules.Engine, cancel <-chan struct{}) <-chan Progress {
	out := make(chan Progress, 64)
	go func() {
		defer close(out)
		start := time.Now()
		if resolved, err := resolveScanRoot(root); err == nil {
			root = resolved
		}
		var total, scanned, skipped int64
		var cancelled atomic.Bool

		jobs := make(chan string, 256)
		var wg sync.WaitGroup
		workers := workerCount()
		var mu sync.Mutex
		var threats []Threat
		for i := 0; i < workers; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for path := range jobs {
					t, ok, skip := scanFile(path, db, eng)
					if skip {
						atomic.AddInt64(&skipped, 1)
					}
					if ok {
						mu.Lock()
						threats = append(threats, t)
						mu.Unlock()
					}
					atomic.AddInt64(&scanned, 1)
				}
			}()
		}

		ticker := time.NewTicker(200 * time.Millisecond)
		tickDone := make(chan struct{})
		tickStopped := make(chan struct{})
		go func() {
			defer close(tickStopped)
			for {
				select {
				case <-tickDone:
					return
				case <-ticker.C:
					mu.Lock()
					snap := make([]Threat, len(threats))
					copy(snap, threats)
					mu.Unlock()
					select {
					case out <- Progress{
						Phase: "scanning", Total: atomic.LoadInt64(&total),
						Scanned: atomic.LoadInt64(&scanned),
						Skipped: atomic.LoadInt64(&skipped),
						Threats: snap, Started: start,
					}:
					default: // never block the ticker on a slow consumer
					}
				}
			}
		}()

		out <- Progress{Phase: "counting", Started: start}
		err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			select {
			case <-cancel:
				cancelled.Store(true)
				return errScanCancelled
			default:
			}
			if err != nil {
				return nil // unreadable: skip, keep walking
			}
			if d.IsDir() {
				if skipDir(d.Name()) {
					return filepath.SkipDir
				}
				return nil
			}
			if !d.Type().IsRegular() {
				return nil
			}
			n := atomic.AddInt64(&total, 1)
			if n%2048 == 0 {
				out <- Progress{Phase: "counting", Total: n, Scanned: atomic.LoadInt64(&scanned), Started: start}
			}
			select {
			case <-cancel:
				cancelled.Store(true)
				return errScanCancelled
			case jobs <- path:
			}
			return nil
		})
		close(jobs)
		if errors.Is(err, errScanCancelled) || cancelled.Load() {
			wg.Wait()
			close(tickDone)
			ticker.Stop()
			<-tickStopped
			sortThreats(threats)
			out <- Progress{
				Phase: "cancelled", Total: atomic.LoadInt64(&total),
				Scanned: atomic.LoadInt64(&scanned), Skipped: atomic.LoadInt64(&skipped),
				Threats: threats, Started: start, Ended: time.Now(),
			}
			return
		}
		if err != nil {
			wg.Wait()
			close(tickDone)
			ticker.Stop()
			<-tickStopped
			out <- Progress{Phase: "error", Err: err, Started: start, Ended: time.Now()}
			return
		}
		wg.Wait()
		close(tickDone)
		ticker.Stop()
		<-tickStopped
		scannedFinal := atomic.LoadInt64(&scanned)
		sortThreats(threats)
		phase := "done"
		if cancelled.Load() {
			phase = "cancelled"
		}
		out <- Progress{
			Phase: phase, Total: atomic.LoadInt64(&total), Scanned: scannedFinal,
			Skipped: atomic.LoadInt64(&skipped), Threats: threats,
			Started: start, Ended: time.Now(),
		}
	}()
	return out
}

func resolveScanRoot(root string) (string, error) {
	info, err := os.Lstat(root)
	if err != nil {
		return root, err
	}
	if info.Mode()&os.ModeSymlink == 0 {
		return root, nil
	}
	resolved, err := filepath.EvalSymlinks(root)
	if err != nil {
		return root, err
	}
	return resolved, nil
}

// scanFile returns (threat, found, skipped). Detection layers, cheapest first:
// filename heuristics → signature hash → EICAR → YARA-lite rules + entropy.
func scanFile(path string, db *signatures.DB, eng *rules.Engine) (Threat, bool, bool) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() {
		return Threat{}, false, true
	}
	if info.Size() > MaxFileSize {
		return Threat{}, false, true
	}

	if reason, sev, hit := heuristics(path, info); hit {
		return Threat{Path: path, Reason: reason, Severity: sev, Size: info.Size()}, true, false
	}

	f, err := os.Open(path)
	if err != nil {
		return Threat{}, false, true
	}
	defer f.Close()

	h := sha256.New()
	head := make([]byte, headSize)
	n, _ := io.ReadFull(f, head)
	head = head[:n]
	h.Write(head)
	if _, err := io.Copy(h, f); err != nil {
		return Threat{}, false, true
	}
	sum := hex.EncodeToString(h.Sum(nil))

	if bytes.Contains(head, eicarMarker) {
		return Threat{Path: path, SHA256: sum, Reason: "EICAR antivirus test file", Severity: SevCritical, Size: info.Size()}, true, false
	}
	if sig, ok := db.Lookup(sum); ok {
		reason, sev := signatureReason(sig)
		return Threat{Path: path, SHA256: sum, Reason: reason, Severity: sev, Size: info.Size()}, true, false
	}

	ent := entropy.Shannon(head)

	// Magic-byte mismatch: a file whose extension promises a known format but
	// whose header doesn't match, with a high-entropy body, is very likely
	// encrypted — a hallmark of ransomware silently rewriting documents.
	if magicMismatch(path, head) && ent > 7.4 {
		return Threat{Path: path, SHA256: sum,
			Reason:   "Content doesn't match extension + high entropy (likely encrypted)",
			Severity: SevCritical, Size: info.Size()}, true, false
	}

	// Rule engine + entropy on the head sample. Critical hits win; otherwise
	// the highest-severity hit is reported.
	if eng != nil {
		if hits := eng.Match(path, head, ent); len(hits) > 0 {
			best := hits[0]
			for _, hh := range hits {
				if sevRank(hh.Severity) > sevRank(best.Severity) {
					best = hh
				}
			}
			return Threat{Path: path, SHA256: sum,
				Reason:   "Rule: " + best.Rule + " — " + best.Desc,
				Severity: sevFromString(best.Severity), Size: info.Size()}, true, false
		}
	}
	return Threat{}, false, false
}

func sevRank(s string) int {
	switch strings.ToLower(s) {
	case "critical":
		return 2
	case "warning":
		return 1
	}
	return 0
}

func sevFromString(s string) Severity {
	switch strings.ToLower(s) {
	case "critical":
		return SevCritical
	case "warning":
		return SevWarning
	}
	return SevInfo
}

func signatureReason(info signatures.SignatureInfo) (string, Severity) {
	names := make([]string, 0, len(info.Sources))
	sev := SevWarning
	for _, src := range info.Sources {
		names = append(names, src.Name)
		if src.Confidence == signatures.ConfidenceHigh {
			sev = SevCritical
		}
	}
	if len(names) == 0 {
		return "Signature match (local hash cache)", SevCritical
	}
	if sev == SevCritical {
		return "Signature match from " + strings.Join(names, ", ") + " (known malware hash)", SevCritical
	}
	return "Payload hash match from " + strings.Join(names, ", ") + " (review before action)", SevWarning
}

// heuristics flags suspicious files without needing a signature.
func heuristics(path string, info os.FileInfo) (string, Severity, bool) {
	name := strings.ToLower(filepath.Base(path))

	// Ransomware footprints: encrypted-file extensions and ransom notes.
	if ransom.HasKnownExtension(name) {
		return "Known ransomware extension (" + filepath.Ext(name) + ")", SevCritical, true
	}
	if ransom.IsRansomNote(name) {
		return "Possible ransom note", SevCritical, true
	}

	// Double extension masquerading: report.pdf.exe, photo.jpg.scr ...
	execExts := []string{".exe", ".scr", ".bat", ".cmd", ".com", ".pif", ".vbs", ".js"}
	docExts := []string{".pdf", ".doc", ".docx", ".xls", ".xlsx", ".jpg", ".jpeg", ".png", ".txt", ".mp4", ".zip"}
	for _, ee := range execExts {
		if strings.HasSuffix(name, ee) {
			base := strings.TrimSuffix(name, ee)
			for _, de := range docExts {
				if strings.HasSuffix(base, de) {
					return "Double extension masquerade (" + de + ee + ")", SevCritical, true
				}
			}
		}
	}

	// Executable hiding in a temp directory.
	dir := strings.ToLower(filepath.Dir(path))
	isTmp := strings.Contains(dir, "/tmp") || strings.Contains(dir, "\\temp") || strings.Contains(dir, "/var/folders")
	if isTmp && info.Mode()&0o111 != 0 && info.Size() > 0 {
		if strings.HasSuffix(name, ".sh") || strings.HasSuffix(name, ".command") || filepath.Ext(name) == "" {
			return "Executable in temporary directory", SevWarning, true
		}
	}

	// Hidden executable in user space (".foo" with exec bit).
	if strings.HasPrefix(name, ".") && info.Mode()&0o111 != 0 && info.Size() > 0 &&
		!strings.HasSuffix(name, ".sh") && runtime.GOOS != "windows" {
		home, _ := os.UserHomeDir()
		if home != "" && strings.HasPrefix(path, home) {
			return "Hidden executable file", SevWarning, true
		}
	}

	return "", SevInfo, false
}

// magic maps common document/media extensions to their valid leading bytes.
var magic = map[string][][]byte{
	".jpg":  {{0xFF, 0xD8, 0xFF}},
	".jpeg": {{0xFF, 0xD8, 0xFF}},
	".png":  {{0x89, 'P', 'N', 'G'}},
	".gif":  {[]byte("GIF8")},
	".pdf":  {[]byte("%PDF")},
	".zip":  {[]byte("PK")},
	".docx": {[]byte("PK")},
	".xlsx": {[]byte("PK")},
	".pptx": {[]byte("PK")},
	".doc":  {{0xD0, 0xCF, 0x11, 0xE0}},
	".xls":  {{0xD0, 0xCF, 0x11, 0xE0}},
	".ppt":  {{0xD0, 0xCF, 0x11, 0xE0}},
	".gz":   {{0x1F, 0x8B}},
}

// magicMismatch reports whether a file's extension expects a known header that
// the actual bytes don't provide.
func magicMismatch(path string, head []byte) bool {
	ext := strings.ToLower(filepath.Ext(path))
	sigs, ok := magic[ext]
	if !ok || len(head) < 4 {
		return false
	}
	for _, sig := range sigs {
		if len(head) >= len(sig) && bytes.HasPrefix(head, sig) {
			return false // matches a valid signature
		}
	}
	return true
}

func skipDir(name string) bool {
	switch name {
	case ".git", "node_modules", ".Trash", "Caches", "cache", ".cache",
		"DerivedData", ".npm", ".cargo", "go", "Xcode", ".docker", "Photos Library.photoslibrary":
		return true
	}
	return false
}

func sortThreats(threats []Threat) {
	sort.SliceStable(threats, func(i, j int) bool {
		if threats[i].Severity != threats[j].Severity {
			return threats[i].Severity > threats[j].Severity
		}
		return threats[i].Path < threats[j].Path
	})
}

func workerCount() int {
	workers := runtime.NumCPU()
	if workers > 8 {
		workers = 8
	}
	if v := strings.TrimSpace(os.Getenv("AEGIS_SCAN_WORKERS")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			workers = n
		}
	}
	if workers < 1 {
		return 1
	}
	if workers > 8 {
		return 8
	}
	return workers
}

// ---- Quarantine ----

// QuarantineRecord remembers where a quarantined file came from.
type QuarantineRecord struct {
	Original string    `json:"original"`
	SHA256   string    `json:"sha256"`
	Reason   string    `json:"reason"`
	When     time.Time `json:"when"`
	Stored   string    `json:"stored"`
}

// Quarantine moves a file into the aegis quarantine directory, strips its
// permissions and records metadata. The stored name is content-addressed.
func Quarantine(t Threat) (QuarantineRecord, error) {
	dir, err := signatures.Dir()
	if err != nil {
		return QuarantineRecord{}, err
	}
	qdir := filepath.Join(dir, "quarantine")
	if err := os.MkdirAll(qdir, 0o700); err != nil {
		return QuarantineRecord{}, err
	}
	id := t.SHA256
	if id == "" {
		id = hex.EncodeToString([]byte(filepath.Base(t.Path)))
		if len(id) > 32 {
			id = id[:32]
		}
	}
	dest := filepath.Join(qdir, id+".quar")
	if err := os.Rename(t.Path, dest); err != nil {
		// Cross-device fallback: copy then remove.
		if err2 := copyFile(t.Path, dest); err2 != nil {
			return QuarantineRecord{}, err
		}
		if err2 := os.Remove(t.Path); err2 != nil {
			return QuarantineRecord{}, err2
		}
	}
	_ = os.Chmod(dest, 0o000)
	rec := QuarantineRecord{Original: t.Path, SHA256: t.SHA256, Reason: t.Reason, When: time.Now(), Stored: dest}
	return rec, appendLog(qdir, rec)
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, in)
	return err
}

func appendLog(qdir string, rec QuarantineRecord) error {
	logPath := filepath.Join(qdir, "quarantine.json")
	var recs []QuarantineRecord
	if b, err := os.ReadFile(logPath); err == nil {
		_ = json.Unmarshal(b, &recs)
	}
	recs = append(recs, rec)
	b, err := json.MarshalIndent(recs, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(logPath, b, 0o600)
}

// QuarantineHistory returns recorded quarantine operations, newest first.
func QuarantineHistory() ([]QuarantineRecord, error) {
	dir, err := signatures.Dir()
	if err != nil {
		return nil, err
	}
	logPath := filepath.Join(dir, "quarantine", "quarantine.json")
	b, err := os.ReadFile(logPath)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var recs []QuarantineRecord
	if err := json.Unmarshal(b, &recs); err != nil {
		return nil, err
	}
	for i, j := 0, len(recs)-1; i < j; i, j = i+1, j-1 {
		recs[i], recs[j] = recs[j], recs[i]
	}
	return recs, nil
}

// Package signatures manages the local malware-hash database and its updates.
package signatures

import (
	"archive/zip"
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// MalwareBazaarFeedURL is the abuse.ch MalwareBazaar export of SHA-256 hashes
// seen in the last 48 hours. Plain text, one hash per line, '#' comments.
const MalwareBazaarFeedURL = "https://bazaar.abuse.ch/export/txt/sha256/recent/"

// URLhausPayloadFeedURL is the abuse.ch URLhaus public zip feed of collected
// payload hashes. URLhaus cautions that collected payloads are not always
// malicious, so Aegis stores this source at medium confidence.
const URLhausPayloadFeedURL = "https://urlhaus.abuse.ch/downloads/payloads/"

// FeedURL is kept for callers that display the primary feed.
const FeedURL = MalwareBazaarFeedURL

// Builtin hashes shipped with the binary so detection works before the first
// update. Includes the EICAR test file so users can safely verify scanning.
var Builtin = []string{
	"275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f", // EICAR test file
}

type Confidence string

const (
	ConfidenceHigh   Confidence = "high"
	ConfidenceMedium Confidence = "medium"
)

// Feed describes one hash source.
type Feed struct {
	Name       string
	URL        string
	Confidence Confidence
	Note       string
}

// SourceHit records where a hash came from.
type SourceHit struct {
	Name       string     `json:"name"`
	Confidence Confidence `json:"confidence"`
	Note       string     `json:"note,omitempty"`
}

// SignatureInfo is the provenance for a matched hash.
type SignatureInfo struct {
	SHA256  string      `json:"sha256"`
	Sources []SourceHit `json:"sources"`
}

// Meta describes the state of the local database.
type Meta struct {
	UpdatedAt time.Time      `json:"updated_at"`
	Count     int            `json:"count"`
	Source    string         `json:"source"`
	Sources   map[string]int `json:"sources,omitempty"`
	Errors    []string       `json:"errors,omitempty"`
}

// DB is an in-memory set of known-bad SHA-256 hashes.
type DB struct {
	mu     sync.RWMutex
	Hashes map[string]struct{}
	Info   map[string]SignatureInfo
	Meta   Meta
	Dir    string
}

// Dir returns (and creates) the aegis config directory.
func Dir() (string, error) {
	base, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(base, "aegis")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	return dir, nil
}

func dbPath(dir string) string   { return filepath.Join(dir, "signatures.txt") }
func metaPath(dir string) string { return filepath.Join(dir, "meta.json") }

// Load reads the signature database from disk, seeding with builtins.
func Load() (*DB, error) {
	dir, err := Dir()
	if err != nil {
		return nil, err
	}
	db := &DB{Hashes: make(map[string]struct{}), Info: make(map[string]SignatureInfo), Dir: dir}
	for _, h := range Builtin {
		db.addSource(strings.ToLower(h), SourceHit{Name: "builtin", Confidence: ConfidenceHigh, Note: "built-in safe test hash"})
	}
	if f, err := os.Open(dbPath(dir)); err == nil {
		defer f.Close()
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if h, sources, ok := parseSignatureLine(line); ok {
				if len(sources) == 0 {
					sources = []SourceHit{{Name: "local-cache", Confidence: ConfidenceHigh}}
				}
				for _, src := range sources {
					db.addSource(h, src)
				}
			}
		}
	}
	if b, err := os.ReadFile(metaPath(dir)); err == nil {
		_ = json.Unmarshal(b, &db.Meta)
	}
	db.Meta.Count = len(db.Hashes)
	return db, nil
}

// Match reports whether a lowercase hex SHA-256 is in the database.
func (db *DB) Match(sha256hex string) bool {
	_, ok := db.Lookup(sha256hex)
	return ok
}

// Lookup returns provenance for a matching SHA-256.
func (db *DB) Lookup(sha256hex string) (SignatureInfo, bool) {
	db.mu.RLock()
	defer db.mu.RUnlock()
	info, ok := db.Info[strings.ToLower(sha256hex)]
	if ok {
		return info, true
	}
	_, ok = db.Hashes[strings.ToLower(sha256hex)]
	if !ok {
		return SignatureInfo{}, false
	}
	return SignatureInfo{SHA256: strings.ToLower(sha256hex), Sources: []SourceHit{{Name: "local-cache", Confidence: ConfidenceHigh}}}, true
}

func (db *DB) Count() int {
	db.mu.RLock()
	defer db.mu.RUnlock()
	return len(db.Hashes)
}

// Age returns how long ago the database was updated, or -1 if never.
func (db *DB) Age() time.Duration {
	db.mu.RLock()
	defer db.mu.RUnlock()
	if db.Meta.UpdatedAt.IsZero() {
		return -1
	}
	return time.Since(db.Meta.UpdatedAt)
}

// Update fetches the feed, merges new hashes and persists the database.
// Returns the number of new hashes added.
func (db *DB) Update() (int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	return db.UpdateFromFeeds(ctx, &http.Client{Timeout: 60 * time.Second}, DefaultFeeds())
}

func DefaultFeeds() []Feed {
	return []Feed{
		{Name: "MalwareBazaar", URL: MalwareBazaarFeedURL, Confidence: ConfidenceHigh, Note: "abuse.ch malware sample hashes"},
		{Name: "URLhaus payloads", URL: URLhausPayloadFeedURL, Confidence: ConfidenceMedium, Note: "abuse.ch collected payload hash; verify before destructive action"},
	}
}

func (db *DB) UpdateFromFeeds(ctx context.Context, client *http.Client, feeds []Feed) (int, error) {
	if client == nil {
		client = &http.Client{Timeout: 60 * time.Second}
	}
	added := 0
	success := 0
	var errs []string
	for _, feed := range feeds {
		hashes, err := fetchFeed(ctx, client, feed)
		if err != nil {
			errs = append(errs, feed.Name+": "+err.Error())
			continue
		}
		success++
		db.mu.Lock()
		for _, h := range hashes {
			if _, ok := db.Hashes[h]; !ok {
				added++
			}
			db.addSourceLocked(h, SourceHit{Name: feed.Name, Confidence: feed.Confidence, Note: feed.Note})
		}
		db.mu.Unlock()
	}
	if success == 0 {
		if len(errs) == 0 {
			errs = append(errs, "no feeds configured")
		}
		return 0, errors.New(strings.Join(errs, "; "))
	}
	db.mu.Lock()
	db.Meta = Meta{UpdatedAt: time.Now(), Count: len(db.Hashes), Source: feedSummary(feeds), Sources: db.sourceCountsLocked(), Errors: errs}
	err := db.saveLocked()
	db.mu.Unlock()
	return added, err
}

func fetchFeed(ctx context.Context, client *http.Client, feed Feed) ([]string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, feed.URL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "aegis/1.2 signature-updater")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("feed returned HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		return nil, err
	}
	if bytes.HasPrefix(body, []byte("PK")) {
		body, err = unzipFirst(body)
		if err != nil {
			return nil, err
		}
	}
	return parseHashes(body), nil
}

func (db *DB) save() error {
	db.mu.Lock()
	defer db.mu.Unlock()
	return db.saveLocked()
}

func (db *DB) saveLocked() error {
	var buf bytes.Buffer
	buf.WriteString("# aegis signature database (sha256, one per line)\n")
	hashes := make([]string, 0, len(db.Hashes))
	for h := range db.Hashes {
		hashes = append(hashes, h)
	}
	sort.Strings(hashes)
	for _, h := range hashes {
		buf.WriteString(h)
		if info, ok := db.Info[h]; ok && len(info.Sources) > 0 {
			buf.WriteByte('\t')
			buf.WriteString(encodeSources(info.Sources))
		}
		buf.WriteByte('\n')
	}
	if err := os.WriteFile(dbPath(db.Dir), buf.Bytes(), 0o644); err != nil {
		return err
	}
	mb, _ := json.MarshalIndent(db.Meta, "", "  ")
	return os.WriteFile(metaPath(db.Dir), mb, 0o644)
}

func (db *DB) addSource(hash string, source SourceHit) {
	db.mu.Lock()
	defer db.mu.Unlock()
	db.addSourceLocked(hash, source)
}

func (db *DB) addSourceLocked(hash string, source SourceHit) {
	hash = strings.ToLower(hash)
	if !isSHA256Hex(hash) {
		return
	}
	db.Hashes[hash] = struct{}{}
	info := db.Info[hash]
	info.SHA256 = hash
	for _, src := range info.Sources {
		if src.Name == source.Name {
			db.Info[hash] = info
			return
		}
	}
	info.Sources = append(info.Sources, source)
	sort.SliceStable(info.Sources, func(i, j int) bool {
		if info.Sources[i].Confidence != info.Sources[j].Confidence {
			return info.Sources[i].Confidence < info.Sources[j].Confidence
		}
		return info.Sources[i].Name < info.Sources[j].Name
	})
	db.Info[hash] = info
}

func (db *DB) sourceCountsLocked() map[string]int {
	counts := map[string]int{}
	for _, info := range db.Info {
		for _, src := range info.Sources {
			counts[src.Name]++
		}
	}
	return counts
}

func feedSummary(feeds []Feed) string {
	names := make([]string, 0, len(feeds))
	for _, f := range feeds {
		names = append(names, f.Name)
	}
	return strings.Join(names, ", ")
}

var sha256Re = regexp.MustCompile(`(?i)\b[0-9a-f]{64}\b`)

func parseHashes(body []byte) []string {
	seen := map[string]struct{}{}
	for _, m := range sha256Re.FindAll(body, -1) {
		seen[strings.ToLower(string(m))] = struct{}{}
	}
	hashes := make([]string, 0, len(seen))
	for h := range seen {
		hashes = append(hashes, h)
	}
	sort.Strings(hashes)
	return hashes
}

func parseSignatureLine(line string) (string, []SourceHit, bool) {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return "", nil, false
	}
	fields := strings.Fields(line)
	if len(fields) == 0 || !isSHA256Hex(fields[0]) {
		return "", nil, false
	}
	var sources []SourceHit
	if len(fields) > 1 {
		sources = decodeSources(fields[1])
	}
	return strings.ToLower(fields[0]), sources, true
}

func encodeSources(sources []SourceHit) string {
	parts := make([]string, 0, len(sources))
	for _, src := range sources {
		name := strings.NewReplacer(" ", "_", ",", "_", ":", "_").Replace(src.Name)
		conf := string(src.Confidence)
		if conf == "" {
			conf = string(ConfidenceHigh)
		}
		parts = append(parts, name+":"+conf)
	}
	sort.Strings(parts)
	return strings.Join(parts, ",")
}

func decodeSources(s string) []SourceHit {
	if s == "" {
		return nil
	}
	var sources []SourceHit
	for _, part := range strings.Split(s, ",") {
		name, conf, ok := strings.Cut(part, ":")
		if !ok || name == "" {
			continue
		}
		name = strings.ReplaceAll(name, "_", " ")
		c := Confidence(conf)
		if c != ConfidenceMedium {
			c = ConfidenceHigh
		}
		sources = append(sources, SourceHit{Name: name, Confidence: c})
	}
	return sources
}

func unzipFirst(data []byte) ([]byte, error) {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, err
	}
	if len(zr.File) == 0 {
		return nil, fmt.Errorf("empty zip archive")
	}
	rc, err := zr.File[0].Open()
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	return io.ReadAll(io.LimitReader(rc, 256<<20))
}

func isSHA256Hex(s string) bool {
	if len(s) != 64 || strings.HasPrefix(s, "#") {
		return false
	}
	for _, r := range s {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') && (r < 'A' || r > 'F') {
			return false
		}
	}
	return true
}

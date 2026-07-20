package signatures

import (
	"archive/zip"
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestIsSHA256Hex(t *testing.T) {
	valid := strings.Repeat("a", 64)
	if !isSHA256Hex(valid) {
		t.Fatal("valid hash rejected")
	}
	for _, s := range []string{
		"",
		"#" + strings.Repeat("a", 63),
		strings.Repeat("g", 64),
		strings.Repeat("a", 63),
		strings.Repeat("a", 65),
	} {
		if isSHA256Hex(s) {
			t.Fatalf("invalid hash accepted: %q", s)
		}
	}
}

func TestSaveWritesHashesInStableOrder(t *testing.T) {
	dir := t.TempDir()
	db := &DB{
		Dir:  dir,
		Info: map[string]SignatureInfo{},
		Hashes: map[string]struct{}{
			strings.Repeat("f", 64): {},
			strings.Repeat("1", 64): {},
			strings.Repeat("a", 64): {},
		},
	}
	if err := db.save(); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(dir, "signatures.txt"))
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	got := lines[1:]
	want := []string{strings.Repeat("1", 64), strings.Repeat("a", 64), strings.Repeat("f", 64)}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("hashes not sorted\n got: %v\nwant: %v", got, want)
	}
}

func TestParseHashesFindsSHA256InCSVAndComments(t *testing.T) {
	h1 := strings.Repeat("a", 64)
	h2 := strings.Repeat("B", 64)
	body := []byte("# comment\nsha256_hash,md5\n\"" + h1 + "\",abc\nignored " + h2 + " trailing\n")
	got := parseHashes(body)
	want := []string{h1, strings.ToLower(h2)}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("hash parse mismatch\n got: %v\nwant: %v", got, want)
	}
}

func TestUpdateFromFeedsMergesSourcesAndPersists(t *testing.T) {
	h1 := strings.Repeat("1", 64)
	h2 := strings.Repeat("2", 64)
	var zipBody bytes.Buffer
	zw := zip.NewWriter(&zipBody)
	f, err := zw.Create("payload.txt")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f.Write([]byte(h1 + "\n" + h2 + "\n"))
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/mb":
			_, _ = w.Write([]byte(h1 + "\n"))
		case "/urlhaus":
			_, _ = w.Write(zipBody.Bytes())
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	dir := t.TempDir()
	db := &DB{Dir: dir, Hashes: map[string]struct{}{}, Info: map[string]SignatureInfo{}}
	added, err := db.UpdateFromFeeds(context.Background(), srv.Client(), []Feed{
		{Name: "MalwareBazaar", URL: srv.URL + "/mb", Confidence: ConfidenceHigh},
		{Name: "URLhaus payloads", URL: srv.URL + "/urlhaus", Confidence: ConfidenceMedium},
	})
	if err != nil {
		t.Fatal(err)
	}
	if added != 2 {
		t.Fatalf("added=%d, want 2", added)
	}
	info, ok := db.Lookup(h1)
	if !ok || len(info.Sources) != 2 {
		t.Fatalf("h1 sources=%+v ok=%v, want two sources", info.Sources, ok)
	}
	info, ok = db.Lookup(h2)
	if !ok || len(info.Sources) != 1 || info.Sources[0].Confidence != ConfidenceMedium {
		t.Fatalf("h2 info=%+v ok=%v, want medium URLhaus source", info, ok)
	}

	reloaded := &DB{Dir: dir, Hashes: map[string]struct{}{}, Info: map[string]SignatureInfo{}}
	b, err := os.ReadFile(filepath.Join(dir, "signatures.txt"))
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(b), "\n") {
		if h, sources, ok := parseSignatureLine(line); ok {
			for _, src := range sources {
				reloaded.addSource(h, src)
			}
		}
	}
	info, ok = reloaded.Lookup(h2)
	if !ok || len(info.Sources) != 1 || info.Sources[0].Confidence != ConfidenceMedium {
		t.Fatalf("persisted info=%+v ok=%v, want medium source", info, ok)
	}
}

func TestUpdateFromFeedsReturnsErrorWhenAllFeedsFail(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	defer srv.Close()
	db := &DB{Dir: t.TempDir(), Hashes: map[string]struct{}{}, Info: map[string]SignatureInfo{}}
	if _, err := db.UpdateFromFeeds(context.Background(), srv.Client(), []Feed{{Name: "bad", URL: srv.URL, Confidence: ConfidenceHigh}}); err == nil {
		t.Fatal("expected all-feeds-failed error")
	}
}

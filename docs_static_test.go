package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestStaticDocsAreLocalFileFriendly(t *testing.T) {
	analytics, err := os.ReadFile(filepath.Join("docs", "analytics.js"))
	if err != nil {
		t.Fatalf("read analytics.js: %v", err)
	}
	if !strings.Contains(string(analytics), `location.protocol === "file:"`) {
		t.Fatal("analytics.js should no-op when opened with file://")
	}

	for _, name := range []string{"index.html", "trust.html", "404.html"} {
		body, err := os.ReadFile(filepath.Join("docs", name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		text := string(body)
		if !strings.Contains(text, "<title>aegis</title>") {
			t.Fatalf("%s should use the plain aegis title", name)
		}
		if !strings.Contains(text, `rel="icon" href="data:image/svg+xml`) {
			t.Fatalf("%s should use the shared inline GUI favicon", name)
		}
		if strings.Contains(text, `type="module"`) {
			t.Fatalf("%s should not require module loading for file:// previews", name)
		}
	}
}

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

func TestMarkdownDocsAvoidStaleReleaseAndUIDetails(t *testing.T) {
	readme, err := os.ReadFile("README.md")
	if err != nil {
		t.Fatalf("read README.md: %v", err)
	}
	readmeText := string(readme)
	if strings.Contains(readmeText, "7 tabs") {
		t.Fatal("README architecture should not hard-code the old TUI tab count")
	}
	for _, want := range []string{"responsive tabs", "Local browser GUI", "Release flow"} {
		if !strings.Contains(readmeText, want) {
			t.Fatalf("README missing expected current documentation marker %q", want)
		}
	}

	releaseDocs, err := os.ReadFile(filepath.Join("docs", "RELEASE_SIGNING.md"))
	if err != nil {
		t.Fatalf("read RELEASE_SIGNING.md: %v", err)
	}
	releaseText := string(releaseDocs)
	for _, stale := range []string{"v1.6.0", "aegis-1.6.0"} {
		if strings.Contains(releaseText, stale) {
			t.Fatalf("release signing docs still contain stale version example %q", stale)
		}
	}
	if !strings.Contains(releaseText, "vX.Y.Z") || !strings.Contains(releaseText, "aegis-X.Y.Z") {
		t.Fatal("release signing docs should use generic release placeholders")
	}
}

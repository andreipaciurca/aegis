package gui

import (
	"os/exec"
	"strings"
	"testing"
)

func TestEmbeddedJavaScriptParses(t *testing.T) {
	if _, err := exec.LookPath("node"); err != nil {
		t.Skip("node is not available for JavaScript syntax validation")
	}

	start := strings.Index(indexHTML, "<script>")
	end := strings.LastIndex(indexHTML, "</script>")
	if start < 0 || end < 0 || end <= start {
		t.Fatal("indexHTML should contain one executable script block")
	}
	script := strings.TrimSpace(indexHTML[start+len("<script>") : end])
	cmd := exec.Command("node", "--check")
	cmd.Stdin = strings.NewReader(script)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("embedded GUI JavaScript does not parse: %v\n%s", err, out)
	}
}

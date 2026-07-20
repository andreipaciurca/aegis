package maintenance

import "testing"

func TestNewerVersion(t *testing.T) {
	cases := []struct {
		latest, current string
		want            bool
	}{
		{"1.2.4", "1.2.3", true},
		{"1.3.0", "1.2.9", true},
		{"2.0.0", "1.9.9", true},
		{"1.2.3", "1.2.3", false},
		{"1.2.2", "1.2.3", false},
		{"v1.2.4", "1.2.3", true}, // leading "v" is stripped
		{"1.2.4", "", true},       // no current version installed yet
		{"", "1.2.3", false},      // empty latest never counts as newer
		{"1.2.10", "1.2.9", true}, // numeric, not lexicographic, comparison
		{"1.2.9", "1.2.10", false},
		{"1.2.3-beta", "1.2.3", false}, // pre-release suffix parses as 0, not newer
	}
	for _, c := range cases {
		got := newerVersion(c.latest, c.current)
		if got != c.want {
			t.Errorf("newerVersion(%q, %q) = %v, want %v", c.latest, c.current, got, c.want)
		}
	}
}

func TestVersionParts(t *testing.T) {
	cases := []struct {
		in   string
		want []int
	}{
		{"1.2.3", []int{1, 2, 3}},
		{"v1.2.3", []int{1, 2, 3}},
		{"1.2.3-beta.1", []int{1, 2, 3, 0, 1}},
		{"", nil},
	}
	for _, c := range cases {
		got := versionParts(c.in)
		if len(got) != len(c.want) {
			t.Fatalf("versionParts(%q) = %v, want %v", c.in, got, c.want)
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Fatalf("versionParts(%q) = %v, want %v", c.in, got, c.want)
			}
		}
	}
}

func TestSummaryReportsErrors(t *testing.T) {
	r := Report{SignatureError: "network down"}
	text, isErr := Summary(r)
	if !isErr {
		t.Fatal("expected isErr=true when signature update failed")
	}
	if text == "" {
		t.Fatal("expected non-empty summary text")
	}
}

func TestSummaryReportsUpdateAvailable(t *testing.T) {
	r := Report{SignatureAdded: 3, SignatureTotal: 100, Aegis: ReleaseStatus{Current: "1.2.3", Latest: "1.2.4", Update: true}}
	text, isErr := Summary(r)
	if isErr {
		t.Fatal("an available update is not itself an error")
	}
	if text == "" {
		t.Fatal("expected non-empty summary text")
	}
}

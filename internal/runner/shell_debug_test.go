package runner

import (
	"os"
	"testing"
)

// TestResolveShellDebug reports what the resolution chain returns under the
// spawning process's environment (temporary diagnostic, delete after use).
func TestResolveShellDebug(t *testing.T) {
	t.Logf("SHELL=%q ProgramFiles=%q LocalAppData=%q Path-head=%q",
		os.Getenv("SHELL"), os.Getenv("ProgramFiles"), os.Getenv("LocalAppData"),
		firstPaths(os.Getenv("PATH"), 6))

	// Simulate settings' shellPath wired at session start.
	SetConfiguredShell("C:/Program Files/Git/bin/bash.exe")
	s, err := ResolveShell()
	t.Logf("with configured shellPath: %q err=%v", s, err)

	// Simulate GetSettings failing: pure fallback chain.
	ResetShellCache()
	SetConfiguredShell("")
	s2, err2 := ResolveShell()
	t.Logf("fallback only:             %q err=%v", s2, err2)
}

func firstPaths(p string, n int) string {
	out := ""
	count := 0
	start := 0
	for i := 0; i <= len(p) && count < n; i++ {
		if i == len(p) || p[i] == os.PathListSeparator {
			if count > 0 {
				out += ";"
			}
			out += p[start:min(i, start+60)]
			count++
			start = i + 1
		}
	}
	return out
}

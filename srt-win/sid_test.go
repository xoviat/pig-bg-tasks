//go:build windows

package srtwin

import (
	"strings"
	"testing"
)

// TestNormalizeDirVariants: trailing slashes, case, and relative spelling
// all collapse to one canonical form.
func TestNormalizeDirVariants(t *testing.T) {
	base := `C:\Temp\srt-win-test`
	// Structural variants collapse to one canonical form (GetFullPathNameW
	// + trailing-separator strip). Case is NOT folded here — that is what
	// dirKey/NormalizeDirs' case-insensitive compare is for, so the same
	// set spelled differently still hashes and sorts identically (see
	// TestSIDDeterminism / TestNormalizeDirsDedupAndSort).
	variants := []string{
		base,
		base + `\`,
		base + `\\\`,
		`C:\Temp\.\srt-win-test`,
		`C:\Temp\foo\..\srt-win-test`,
	}
	want, err := NormalizeDir(variants[0])
	if err != nil {
		t.Fatalf("NormalizeDir: %v", err)
	}
	for _, v := range variants {
		got, err := NormalizeDir(v)
		if err != nil {
			t.Fatalf("NormalizeDir(%q): %v", v, err)
		}
		if got != want {
			t.Errorf("NormalizeDir(%q) = %q, want %q", v, got, want)
		}
	}
	// drive root keeps its trailing backslash
	root, err := NormalizeDir(`C:\`)
	if err != nil {
		t.Fatalf("NormalizeDir(C:\\): %v", err)
	}
	if root != `C:\` {
		t.Errorf("drive root = %q, want C:\\", root)
	}
}

// TestNormalizeDirsDedupAndSort: case-insensitive dedupe + canonical order.
func TestNormalizeDirsDedupAndSort(t *testing.T) {
	in := []string{`C:\b`, `C:\B\`, `C:\a`, `c:\A\`, `C:\c`}
	got, err := NormalizeDirs(in)
	if err != nil {
		t.Fatalf("NormalizeDirs: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("got %d dirs, want 3 (case-insensitive dedupe): %v", len(got), got)
	}
	for i := 1; i < len(got); i++ {
		if dirKey(got[i-1]) > dirKey(got[i]) {
			t.Fatalf("not sorted: %v", got)
		}
	}
}

// TestSIDDeterminism: same dirs → same SID string; case and
// trailing-slash variants of the same set → same SID string; a different
// set → a different SID string.
func TestSIDDeterminism(t *testing.T) {
	set1 := mustNormalize(t, []string{`C:\work\alpha`, `C:\work\beta`})
	set2 := mustNormalize(t, []string{`C:\WORK\BETA\`, `c:\work\ALPHA`})
	set3 := mustNormalize(t, []string{`C:\work\alpha`, `C:\work\gamma`})

	sid1 := sidStringForDirs(set1)
	sid2 := sidStringForDirs(set2)
	sid3 := sidStringForDirs(set3)

	if sid1 != sid2 {
		t.Errorf("case/trailing-slash variants differ: %s vs %s", sid1, sid2)
	}
	if sid1 == sid3 {
		t.Errorf("different dir sets produced the same SID: %s", sid1)
	}
	if !strings.HasPrefix(sid1, "S-1-5-21-") || !strings.HasSuffix(sid1, "-0") {
		t.Errorf("SID shape unexpected: %s", sid1)
	}
	// Same dirs twice in a row (stability across calls).
	if again := sidStringForDirs(mustNormalize(t, []string{`C:\work\alpha`, `C:\work\beta`})); again != sid1 {
		t.Errorf("SID not stable across calls: %s vs %s", again, sid1)
	}
}

// TestAllocateSIDMatchesString: the real AllocateAndInitializeSid result
// string equals the pure-function SID string.
func TestAllocateSIDMatchesString(t *testing.T) {
	dirs := mustNormalize(t, []string{`C:\work\alpha`})
	sid, err := allocateSID(hashDirs(dirs))
	if err != nil {
		t.Fatalf("allocateSID: %v", err)
	}
	defer freeSID(sid)
	if got := sid.String(); got != sidStringForDirs(dirs) {
		t.Errorf("allocated SID %s != pure SID %s", got, sidStringForDirs(dirs))
	}
}

func mustNormalize(t *testing.T, dirs []string) []string {
	t.Helper()
	out, err := NormalizeDirs(dirs)
	if err != nil {
		t.Fatalf("NormalizeDirs(%v): %v", dirs, err)
	}
	return out
}

//go:build windows

package srtwin

import (
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

// TestNewNoDirs covers the read-only convergence state: the extension
// switches modes by calling New() with no directories. No dirs → no grants,
// no registry writes, but a fully minted restricted token whose synthetic
// SID (hash of the empty set) matches no standing grant — previous
// workspace-write grants are inert under it.
func TestNewNoDirs(t *testing.T) {
	if sourceTokenRestricted(t) {
		t.Skip("nested restricted tokens are rejected — run unconfined")
	}
	sb, err := New()
	if err != nil {
		t.Fatalf("New() with no dirs (read-only state): %v", err)
	}
	defer sb.Close()

	if got := sb.Dirs(); len(got) != 0 {
		t.Fatalf("Dirs() = %v, want empty", got)
	}
	sid := sb.SIDString()
	if !strings.HasPrefix(sid, "S-1-5-21-") {
		t.Fatalf("SIDString() = %q, want S-1-5-21-...", sid)
	}
	if w := sb.Warnings(); len(w) != 0 {
		t.Fatalf("unexpected warnings: %v", w)
	}
	// The empty-set SID must differ from any real dir-set SID.
	other, err := New(t.TempDir())
	if err != nil {
		t.Fatalf("New(tempdir): %v", err)
	}
	defer other.Close()
	if other.SIDString() == sid {
		t.Fatal("empty-set SID collides with a real dir-set SID")
	}
}

// sourceTokenRestricted reports whether the current process already runs
// under a restricted token (nested CreateRestrictedToken(WRITE_RESTRICTED)
// would be rejected).
func sourceTokenRestricted(t *testing.T) bool {
	t.Helper()
	var tok windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &tok); err != nil {
		t.Fatalf("OpenProcessToken: %v", err)
	}
	defer tok.Close()
	var n uint32
	_ = windows.GetTokenInformation(tok, windows.TokenRestrictedSids, nil, 0, &n)
	return n > 0
}

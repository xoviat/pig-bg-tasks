//go:build windows

package srtwin

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

// TestDebugDiag: end-to-end diagnostics for section pinning and move
// detection. Run with SRT_DIAG=1.
func TestDebugDiag(t *testing.T) {
	if os.Getenv("SRT_DIAG") == "" {
		t.Skip("set SRT_DIAG=1")
	}
	// ---- PART 1: msys pin diagnostics ----
	ensureMsysReady()
	msys.mu.Lock()
	fmt.Printf("helper running=%v obName=%q held=%d pinned=%d\n",
		msys.helper != nil, msys.obName, uintptr(msys.held), len(msys.pinned))
	for k, v := range msys.pinned {
		fmt.Printf("  pinned %s -> handle %d\n", k, uintptr(v[0]))
	}
	ob := msys.obName
	msys.mu.Unlock()

	user := currentUserSID()
	if ob != "" {
		diagPin(ob + `\` + user.String() + ".1")
		diagPin(ob + `\shared.5`)
	}

	// ---- PART 2: move-detection diagnostics ----
	base := filepath.Join(os.TempDir(), "srt-diag")
	_ = os.RemoveAll(base)
	orig := base + "-orig"
	renamed := base + "-renamed"
	_ = os.RemoveAll(orig)
	_ = os.RemoveAll(renamed)
	if err := os.Mkdir(orig, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = os.RemoveAll(orig)
		_ = os.RemoveAll(renamed)
	})

	sb, err := New(orig)
	if err != nil {
		t.Fatalf("New(orig): %v", err)
	}
	sidStr := sb.SIDString()
	recDirs := readDirs(sidStr)
	roots := readRoots(sidStr)
	fmt.Printf("recorded dirs=%v roots=%+v\n", recDirs, roots)
	sb.Close()

	if err := os.Rename(orig, renamed); err != nil {
		t.Fatal(err)
	}
	fmt.Printf("pathExists(orig)=%v\n", pathExists(orig))
	if len(roots) > 0 {
		vh, verr := openVolume(recDirs[0])
		fmt.Printf("openVolume: h=%d err=%v\n", uintptr(vh), verr)
		if verr == nil {
			moved, rerr := resolveByID(vh, roots[0])
			windows.CloseHandle(vh)
			fmt.Printf("resolveByID: moved=%q err=%v\n", moved, rerr)
		}
	}

	_, err2 := New(orig)
	fmt.Printf("New(orig) after rename: err=%v\n", err2)
	if se, ok := err2.(*SetupError); ok {
		fmt.Printf("warnings: %v\n", se.Warnings)
	}
	if ok, herr := hasGrant(renamed, sidStr); herr == nil {
		fmt.Printf("strip check: grant still present at renamed=%v\n", ok)
	}
	deleteSidEntry(sidStr)
	deleteConfig(configKey(hashDirs(mustNormalize(t, []string{orig}))))
}

// diagPin walks the pin steps with full status output.
func diagPin(path string) {
	oa, err := newObjectAttributes(path, objCaseInsensitive, nil)
	if err != nil {
		fmt.Println("diagPin: oa err:", err)
		return
	}
	var h windows.Handle
	r1, _, _ := procNtOpenSection.Call(uintptr(unsafe.Pointer(&h)),
		uintptr(0x00040000|0x00020000), uintptr(unsafe.Pointer(oa)))
	fmt.Printf("diagPin %s: open st=0x%08X h=%d\n", path, uint32(r1), uintptr(h))
	if h == 0 || int32(r1) != 0 {
		return
	}
	defer windows.CloseHandle(h)
	if sd, err := windows.GetSecurityInfo(h, windows.SE_KERNEL_OBJECT,
		windows.DACL_SECURITY_INFORMATION); err == nil {
		dacl, _, _ := sd.DACL()
		printACL("before", dacl)
	} else {
		fmt.Println("GetSecurityInfo before:", err)
	}
	ok := normalizeSectionDACL(h)
	fmt.Printf("normalizeSectionDACL=%v\n", ok)
	if sd, err := windows.GetSecurityInfo(h, windows.SE_KERNEL_OBJECT,
		windows.DACL_SECURITY_INFORMATION); err == nil {
		dacl, _, _ := sd.DACL()
		printACL("after", dacl)
	}
	// full-access reopen (what cygwin does)
	var h2 windows.Handle
	r2, _, _ := procNtOpenSection.Call(uintptr(unsafe.Pointer(&h2)),
		uintptr(0x000F001F), uintptr(unsafe.Pointer(oa)))
	fmt.Printf("reopen SECTION_ALL_ACCESS st=0x%08X h=%d\n", uint32(r2), uintptr(h2))
	if h2 != 0 {
		windows.CloseHandle(h2)
	}
}

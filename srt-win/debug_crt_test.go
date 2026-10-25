//go:build windows

package srtwin

import (
	"fmt"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Debug: isolate which ingredient makes CreateRestrictedToken reject.
func TestDebugCRT(t *testing.T) {
	var cur windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_ALL_ACCESS, &cur); err != nil {
		t.Fatal(err)
	}
	defer cur.Close()

	// A: TokenLogonSid class parse
	logonA, errA := logonSIDFromClass(cur)
	fmt.Printf("TokenLogonSid class: sid=%v err=%v\n", sidStr(logonA), errA)

	// B: TokenGroups scan
	groups, errB := tokenGroups(cur, windows.TokenGroups)
	fmt.Printf("TokenGroups scan: err=%v count=%d\n", errB, len(groups))
	logonB := scanLogonSID(groups)
	fmt.Printf("scan logon sid=%v\n", sidStr(logonB))

	sid, err := allocateSID(hashDirs([]string{`C:\work\x`}))
	if err != nil {
		t.Fatal(err)
	}
	defer freeSID(sid)

	try := func(name string, sids []*windows.SID) {
		sas := make([]windows.SIDAndAttributes, len(sids))
		for i, s := range sids {
			sas[i] = windows.SIDAndAttributes{Sid: s}
			fmt.Printf("   [%s] sid[%d]=%v valid=%v\n", name, i, s.String(), s.IsValid())
		}
		var tok windows.Token
		r1, _, e := procCreateRestrictedToken.Call(
			uintptr(cur), uintptr(createRestrictedTokenFlags),
			0, 0, 0, 0,
			uintptr(len(sas)), uintptr(unsafe.Pointer(&sas[0])),
			uintptr(unsafe.Pointer(&tok)))
		fmt.Printf("  %s -> r1=%d tok=%d err=%v\n", name, r1, uintptr(tok), e)
		if tok != 0 {
			tok.Close()
		}
	}

	try("everyone only", []*windows.SID{everyoneSID})
	if logonA != nil {
		try("everyone+logonA", []*windows.SID{everyoneSID, logonA})
	}
	if logonB != nil {
		try("everyone+logonB", []*windows.SID{everyoneSID, logonB})
	}
	try("everyone+logonB+cap", []*windows.SID{everyoneSID, logonB, sid})
	try("cap only", []*windows.SID{sid})

	// flag variants
	for _, fl := range []uintptr{0x1, 0x8, 0x9, 0x1 | 0x8} {
		sas := []windows.SIDAndAttributes{{Sid: everyoneSID}, {Sid: logonB}, {Sid: sid}}
		var tok windows.Token
		r1, _, e := procCreateRestrictedToken.Call(uintptr(cur), fl, 0, 0, 0, 0,
			3, uintptr(unsafe.Pointer(&sas[0])), uintptr(unsafe.Pointer(&tok)))
		fmt.Printf("  flags=0x%X -> r1=%d err=%v\n", fl, r1, e)
		if tok != 0 {
			tok.Close()
		}
	}
}

func sidStr(s *windows.SID) string {
	if s == nil {
		return "<nil>"
	}
	return s.String()
}

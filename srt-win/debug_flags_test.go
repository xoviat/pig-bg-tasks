//go:build windows

package srtwin

import (
	"fmt"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

func TestDebugFlags(t *testing.T) {
	var cur windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_ALL_ACCESS, &cur); err != nil {
		t.Fatal(err)
	}
	defer cur.Close()
	groups, _ := tokenGroups(cur, windows.TokenGroups)
	logon := scanLogonSID(groups)
	sid, err := allocateSID(hashDirs([]string{`C:\work\x`}))
	if err != nil {
		t.Fatal(err)
	}
	defer freeSID(sid)

	combos := []uintptr{0x0, 0x1, 0x2, 0x4, 0x8, 0x9, 0xC, 0xD, 0xF, 0x18, 0x19}
	for _, fl := range combos {
		sas := []windows.SIDAndAttributes{{Sid: everyoneSID}, {Sid: logon}, {Sid: sid}}
		var tok windows.Token
		r1, _, e := procCreateRestrictedToken.Call(uintptr(cur), fl, 0, 0, 0, 0,
			3, uintptr(unsafe.Pointer(&sas[0])), uintptr(unsafe.Pointer(&tok)))
		status := "OK"
		if r1 == 0 {
			status = "FAIL: " + e.Error()
		}
		fmt.Printf("  flags=0x%02X -> %s\n", fl, status)
		if tok != 0 {
			tok.Close()
		}
	}
	// sanity: does a 0x9 token come out write-restricted & restricted?
	sas := []windows.SIDAndAttributes{{Sid: everyoneSID}, {Sid: logon}, {Sid: sid}}
	var tok windows.Token
	r1, _, e := procCreateRestrictedToken.Call(uintptr(cur), 0x9, 0, 0, 0, 0,
		3, uintptr(unsafe.Pointer(&sas[0])), uintptr(unsafe.Pointer(&tok)))
	fmt.Printf("retry 0x9: r1=%d err=%v\n", r1, e)
	if tok != 0 {
		tok.Close()
	}
}

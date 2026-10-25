//go:build windows

package srtwin

import (
	"fmt"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

func TestDebugFlags2(t *testing.T) {
	groupsBase, _ := func() ([]windows.SIDAndAttributes, error) {
		var tok windows.Token
		if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &tok); err != nil {
			return nil, err
		}
		defer tok.Close()
		return tokenGroups(tok, windows.TokenGroups)
	}()
	logon := scanLogonSID(groupsBase)
	sid, _ := allocateSID(hashDirs([]string{`C:\work\x`}))
	defer freeSID(sid)

	opens := map[string]uint32{
		"ALL":       windows.TOKEN_ALL_ACCESS,
		"QUERY_DUP": windows.TOKEN_QUERY | windows.TOKEN_DUPLICATE | windows.TOKEN_ADJUST_DEFAULT,
		"DUP_QUERY": windows.TOKEN_DUPLICATE | windows.TOKEN_QUERY,
		"MAX":       windows.MAXIMUM_ALLOWED,
	}
	for name, access := range opens {
		var cur windows.Token
		if err := windows.OpenProcessToken(windows.CurrentProcess(), access, &cur); err != nil {
			fmt.Printf("  open %s: %v\n", name, err)
			continue
		}
		sas := []windows.SIDAndAttributes{{Sid: everyoneSID}, {Sid: logon}, {Sid: sid}}
		var tok windows.Token
		r1, _, e := procCreateRestrictedToken.Call(uintptr(cur), 0x9, 0, 0, 0, 0,
			3, uintptr(unsafe.Pointer(&sas[0])), uintptr(unsafe.Pointer(&tok)))
		st := "OK"
		if r1 == 0 {
			st = "FAIL: " + e.Error()
		}
		fmt.Printf("  open=%s flags=0x9 -> %s\n", name, st)
		if tok != 0 {
			tok.Close()
		}
		cur.Close()
	}
}

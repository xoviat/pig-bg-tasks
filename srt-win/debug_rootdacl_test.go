//go:build windows

package srtwin

import (
	"fmt"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Print the DACL of \BaseNamedObjects: which trustees can CREATE there?
func TestDebugRootDACL(t *testing.T) {
	sd, err := windows.GetNamedSecurityInfo(obRoot, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		// object namespace isn't a file object for GetNamedSecurityInfo?
		fmt.Printf("GetNamedSecurityInfo(obRoot): %v\n", err)
		// fallback: open the dir and GetSecurityInfo on the handle
		oa, _ := newObjectAttributes(obRoot, objCaseInsensitive, nil)
		var oh windows.Handle
		r1, _, _ := procNtOpenDirectoryObject.Call(uintptr(unsafe.Pointer(&oh)),
			0x00020000 /*READ_CONTROL*/, uintptr(unsafe.Pointer(oa)))
		fmt.Printf("NtOpenDirectoryObject(READ_CONTROL): 0x%08X\n", uint32(r1))
		if int32(r1) != 0 {
			return
		}
		defer windows.CloseHandle(oh)
		sd2, e := windows.GetSecurityInfo(oh, windows.SE_FILE_OBJECT,
			windows.DACL_SECURITY_INFORMATION)
		if e != nil {
			fmt.Printf("GetSecurityInfo: %v\n", e)
			return
		}
		dacl2, _, _ := sd2.DACL()
		printACL("BaseNamedObjects", dacl2)
		return
	}
	dacl, _, _ := sd.DACL()
	printACL("BaseNamedObjects", dacl)
}

func printACL(label string, dacl *windows.ACL) {
	if dacl == nil {
		fmt.Printf("%s: NULL DACL\n", label)
		return
	}
	fmt.Printf("%s: %d ACEs\n", label, dacl.AceCount)
	for i := uint16(0); i < dacl.AceCount; i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, uint32(i), &ace); err != nil || ace == nil {
			continue
		}
		hdr := (*aceHeader)(unsafe.Pointer(ace))
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		acct, domain, _, _ := sid.LookupAccount("")
		fmt.Printf("  type=%d flags=0x%02X mask=0x%08X sid=%s acct=%s/%s\n",
			hdr.AceType, hdr.AceFlags, uint32(ace.Mask), sid.String(), domain, acct)
	}
}

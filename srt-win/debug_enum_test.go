//go:build windows

package srtwin

import (
	"encoding/binary"
	"fmt"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

// TestDebugEnumerateDump lists object-directory entries (name + type)
// under the root and under the msys dir — diagnostic for section pinning.
func TestDebugEnumerateDump(t *testing.T) {
	ensureMsysReady()
	enumerateAndDump(obRoot)
	msys.mu.Lock()
	name := msys.obName
	msys.mu.Unlock()
	if name != "" {
		enumerateAndDump(name)
	}
}

func enumerateAndDump(path string) {
	oa, err := newObjectAttributes(path, objCaseInsensitive, nil)
	if err != nil {
		return
	}
	var h windows.Handle
	r1, _, _ := procNtOpenDirectoryObject.Call(uintptr(unsafe.Pointer(&h)),
		directoryQuery, uintptr(unsafe.Pointer(oa)))
	if h == 0 || int32(r1) != 0 {
		fmt.Printf("enumerate %s: open status=0x%08X", path, uint32(r1))
		fmt.Println("")
		return
	}
	defer windows.CloseHandle(h)
	buf := make([]byte, 8192)
	bufAddr := uintptr(unsafe.Pointer(&buf[0]))
	var ctx uint32
	restart := 1
	fmt.Printf("entries under %s:", path)
	fmt.Println("")
	for i := 0; i < 40; i++ {
		st, _, _ := procNtQueryDirectoryObject.Call(uintptr(h),
			uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)), 1,
			uintptr(restart), uintptr(unsafe.Pointer(&ctx)), 0)
		restart = 0
		if uint32(st) == statusNoMoreEntries || int32(st) != 0 {
			break
		}
		fmt.Printf("  name=%q type=%q",
			parseOBEntry(buf, bufAddr), parseOBTypeName(buf, bufAddr))
		fmt.Println("")
	}
}

// parseOBTypeName reads TypeName (the second UNICODE_STRING) of an entry.
func parseOBTypeName(buf []byte, bufAddr uintptr) string {
	if len(buf) < 64 {
		return ""
	}
	l := binary.LittleEndian.Uint16(buf[16:18])
	ptr := uintptr(binary.LittleEndian.Uint64(buf[24:32]))
	if l == 0 || l > maxOBEntryName || l%2 != 0 {
		return ""
	}
	off := int(ptr) - int(bufAddr)
	if off < 0 || off+int(l) > len(buf) {
		return ""
	}
	u := make([]uint16, l/2)
	for i := range u {
		u[i] = binary.LittleEndian.Uint16(buf[off+2*i:])
	}
	return windows.UTF16ToString(u)
}

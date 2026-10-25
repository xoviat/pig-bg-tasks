//go:build windows

package srtwin

import (
	"encoding/binary"
	"fmt"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

func TestDebugEnumerateOB(t *testing.T) {
	oa, err := newObjectAttributes(obRoot, objCaseInsensitive, nil)
	if err != nil {
		t.Fatal(err)
	}
	var oh windows.Handle
	r1, _, _ := procNtOpenDirectoryObject.Call(uintptr(unsafe.Pointer(&oh)), directoryQuery, uintptr(unsafe.Pointer(oa)))
	fmt.Printf("NtOpenDirectoryObject: status=0x%08X handle=%d\n", uint32(r1), uintptr(oh))
	if int32(r1) != 0 || oh == 0 {
		t.Skipf("open failed: 0x%08X", uint32(r1))
	}
	defer windows.CloseHandle(oh)

	for _, mode := range []struct {
		single, restart int
		bufsize         int
	}{{1, 1, 8192}, {0, 1, 65536}, {1, 1, 4096}, {0, 1, 1024}} {
		buf := make([]byte, mode.bufsize)
		var ctx uint32
		st, _, _ := procNtQueryDirectoryObject.Call(uintptr(oh), uintptr(unsafe.Pointer(&buf[0])),
			uintptr(mode.bufsize), uintptr(mode.single), uintptr(mode.restart),
			uintptr(unsafe.Pointer(&ctx)), 0)
		fmt.Printf("single=%d size=%d -> status=0x%08X ctx=%d\n", mode.single, mode.bufsize, uint32(st), ctx)
		if int32(st) == 0 {
			name := parseOBEntry(buf, uintptr(unsafe.Pointer(&buf[0])))
			l := binary.LittleEndian.Uint16(buf[0:2])
			ptr := binary.LittleEndian.Uint64(buf[8:16])
			fmt.Printf("  first entry name=%q rawLen=%d ptrOff=%d\n", name, l, int(ptr)-int(uintptr(unsafe.Pointer(&buf[0]))))
		}
	}
}

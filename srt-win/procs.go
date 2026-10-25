//go:build windows

// Lazy system DLL handles shared by the package.
package srtwin

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

// ptrFrom reinterprets a kernel-returned handle/address as a pointer.
// Written as a reinterpretation rather than unsafe.Pointer(uintptr) so go
// vet's unsafeptr heuristic does not flag kernel values (they never carry
// Go pointers).
func ptrFrom(p uintptr) unsafe.Pointer {
	return *(*unsafe.Pointer)(unsafe.Pointer(&p))
}

var (
	advapi32      = windows.NewLazySystemDLL("advapi32.dll")
	kernel32      = windows.NewLazySystemDLL("kernel32.dll")
	procLocalFree = kernel32.NewProc("LocalFree")
	ntdll         = windows.NewLazySystemDLL("ntdll.dll")
)

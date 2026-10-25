//go:build windows

// ACE handling: merge grants into the existing DACL (never replace it)
// and strip a SID's allow ACEs during eviction / move cleanup.

package srtwin

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	// grantMask is the allow mask stamped onto writable dirs, in
	// file-specific rights: read | write | execute | DELETE.
	//
	// The spec's shorthand is GENERIC_WRITE|GENERIC_EXECUTE|DELETE; the
	// read bits are REQUIRED in addition, because write-restricted
	// pass-2 evaluates the whole requested mask: a mixed read+write open
	// (O_RDWR — cygwin shared-file access, editors, package managers)
	// fails unless the restricted SID is granted the read rights too.
	// This matches Codex's WRITE_ALLOW_MASK (FILE_GENERIC_READ |
	// FILE_GENERIC_WRITE | FILE_GENERIC_EXECUTE | DELETE) and the spike
	// finding "grants must use full control, not FILE_GENERIC_WRITE
	// unions". GENERIC_* bits are expanded up front so the stored ACE
	// never depends on generic-rights mapping at check time.
	grantMask = windows.FILE_GENERIC_READ | windows.FILE_GENERIC_WRITE |
		windows.FILE_GENERIC_EXECUTE | windows.DELETE

	// grantInherit: the grant propagates to containers and objects.
	grantInherit = windows.OBJECT_INHERIT_ACE | windows.CONTAINER_INHERIT_ACE

	grantAccess = 2 // GRANT_ACCESS (merges with an existing same-trustee ACE)
	setAccess   = 1 // SET_ACCESS (used only by the object-dir bootstrap)

	// fileAllAccess is FILE_ALL_ACCESS (x/sys does not export it).
	fileAllAccess = 0x001F01FF

	trusteeIsSID   = 0
	accessAllowed  = 0
	inheritOnlyAce = 0x08
)

var (
	procSetEntriesInAcl = advapi32.NewProc("SetEntriesInAclW")
	procInitializeAcl   = advapi32.NewProc("InitializeAcl")
	procAddAce          = advapi32.NewProc("AddAce")
)

// explicitAccess mirrors Win32 EXPLICIT_ACCESS for SetEntriesInAclW.
type explicitAccess struct {
	AccessPermissions uint32
	AccessMode        uint32
	Inheritance       uint32
	Trustee           trustee
}

type trustee struct {
	MultipleTrustee          *trustee
	MultipleTrusteeOperation uint32
	TrusteeForm              uint32
	TrusteeType              uint32
	Name                     *uint16
}

func entryFor(sid *windows.SID, mask, mode, inherit uint32) explicitAccess {
	return explicitAccess{
		AccessPermissions: mask,
		AccessMode:        mode,
		Inheritance:       inherit,
		Trustee: trustee{
			TrusteeForm: trusteeIsSID,
			Name:        (*uint16)(unsafe.Pointer(sid)),
		},
	}
}

// mapGeneric expands GENERIC_* bits the way an object's generic mapping
// would, so ACE masks are compared in file-specific rights.
func mapGeneric(mask uint32) uint32 {
	out := mask
	if mask&windows.GENERIC_READ != 0 {
		out &^= windows.GENERIC_READ
		out |= windows.FILE_GENERIC_READ
	}
	if mask&windows.GENERIC_WRITE != 0 {
		out &^= windows.GENERIC_WRITE
		out |= windows.FILE_GENERIC_WRITE
	}
	if mask&windows.GENERIC_EXECUTE != 0 {
		out &^= windows.GENERIC_EXECUTE
		out |= windows.FILE_GENERIC_EXECUTE
	}
	if mask&windows.GENERIC_ALL != 0 {
		out &^= windows.GENERIC_ALL
		out |= fileAllAccess
	}
	return out
}

// daclRead returns path's DACL (nil dacl == null DACL == everyone allowed).
func daclRead(path string) (*windows.ACL, error) {
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return nil, err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return nil, err
	}
	return dacl, nil
}

// daclHasGrant reports whether sid already holds every grantMask bit on
// path (effective ACEs only — inherit-only ACEs do not apply here).
func daclHasGrant(dacl *windows.ACL, sidStr string) bool {
	if dacl == nil {
		return true // null DACL: everything (incl. our SID) is granted
	}
	for i := uint16(0); i < dacl.AceCount; i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, uint32(i), &ace); err != nil || ace == nil {
			continue
		}
		hdr := (*aceHeader)(unsafe.Pointer(ace))
		if hdr.AceType != accessAllowed || hdr.AceFlags&inheritOnlyAce != 0 {
			continue
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if sid.String() != sidStr {
			continue
		}
		if mapGeneric(uint32(ace.Mask))&grantMask == grantMask {
			return true
		}
	}
	return false
}

// hasGrant is the path-level idempotence check used by New.
func hasGrant(path, sidStr string) (bool, error) {
	dacl, err := daclRead(path)
	if err != nil {
		return false, err
	}
	return daclHasGrant(dacl, sidStr), nil
}

// grantACE merges a grant ACE for sid into path's existing DACL (never
// replaces it — unrelated entries, including denies, are preserved).
func grantACE(path string, sid *windows.SID) error {
	dacl, err := daclRead(path)
	if err != nil {
		return fmt.Errorf("srt-win: read ACL %s: %w", path, err)
	}
	ea := entryFor(sid, grantMask, grantAccess, grantInherit)
	var existing uintptr
	if dacl != nil {
		existing = uintptr(unsafe.Pointer(dacl))
	}
	var newAcl *windows.ACL
	r1, _, _ := procSetEntriesInAcl.Call(1, uintptr(unsafe.Pointer(&ea)),
		existing, uintptr(unsafe.Pointer(&newAcl)))
	if r1 != 0 || newAcl == nil {
		return fmt.Errorf("srt-win: SetEntriesInAclW(%s): 0x%X", path, r1)
	}
	defer procLocalFree.Call(uintptr(unsafe.Pointer(newAcl)))
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION, nil, nil, newAcl, nil); err != nil {
		return fmt.Errorf("srt-win: set ACL %s: %w", path, err)
	}
	return nil
}

// stripSIDACE rebuilds path's DACL without allow ACEs whose trustee is
// sidStr — the eviction and move-cleanup path.
func stripSIDACE(path, sidStr string) error {
	dacl, err := daclRead(path)
	if err != nil {
		return fmt.Errorf("srt-win: read ACL %s: %w", path, err)
	}
	if dacl == nil {
		return nil
	}
	buf := make([]byte, 8192)
	// InitializeAcl is BOOL: nonzero is success.
	r1, _, _ := procInitializeAcl.Call(uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf)), 2 /*ACL_REVISION*/)
	if r1 == 0 {
		return fmt.Errorf("srt-win: InitializeAcl failed")
	}
	newAcl := (*windows.ACL)(unsafe.Pointer(&buf[0]))
	dropped := 0
	for i := uint16(0); i < dacl.AceCount; i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, uint32(i), &ace); err != nil || ace == nil {
			continue
		}
		hdr := (*aceHeader)(unsafe.Pointer(ace))
		if hdr.AceType == accessAllowed {
			sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
			if sid.String() == sidStr {
				dropped++
				continue
			}
		}
		// AddAce is BOOL: nonzero is success.
		r2, _, _ := procAddAce.Call(uintptr(unsafe.Pointer(newAcl)), 2,
			0xFFFFFFFF, uintptr(unsafe.Pointer(ace)), uintptr(hdr.AceSize))
		if r2 == 0 {
			return fmt.Errorf("srt-win: AddAce(%s) failed", path)
		}
	}
	if dropped == 0 {
		return nil
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION, nil, nil, newAcl, nil); err != nil {
		return fmt.Errorf("srt-win: set ACL %s: %w", path, err)
	}
	return nil
}

// aceHeader mirrors the fixed part of an ACE.
type aceHeader struct {
	AceType  byte
	AceFlags byte
	AceSize  uint16
	Mask     uint32
}

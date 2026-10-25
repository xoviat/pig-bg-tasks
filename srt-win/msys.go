//go:build windows

// MSYS/cygwin object-directory bootstrap.
//
// MSYS2 puts ALL global named objects under
// \BaseNamedObjects\msys-2.0S5-<installation_key>. Named-object *creation*
// is impossible under a write-restricted token (the \BaseNamedObjects root
// denies create — parent-dir check; the root is not grantable by users),
// but opening an EXISTING directory passes both access passes, because
// cygwin creates it with an everyone_sd. So the unconstrained side of
// srt-win must have the directory open (or held) before a confined msys
// child boots — otherwise cygwin dies fatal-on-failure in
// NtCreateDirectoryObject.
//
// Discovery/hold order, all state owned by srt-win itself (CLI and library
// share the HKCU\Software\srt-win cache — no separate storage anywhere):
//
//  1. cached name (registry value MsysDir) → precreate + hold directly
//     (fast path: no helper, ~1ms);
//  2. resident helper bash: one unconstrained `bash -c 'while…; done'`
//     started once per process; its msys runtime creates and holds the
//     directory. Then best-effort enumeration of \BaseNamedObjects learns
//     the name, which is cached and held by us so the helper can go;
//  3. if enumeration fails, the helper simply stays (job-wrapped: it can
//     never outlive the process).
//
// The helper loop is inert (`sleep 60`), job-wrapped with
// KILL_ON_JOB_CLOSE so hard process death takes it with the tree.

package srtwin

import (
	"encoding/binary"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	helperReadyWait = 350 * time.Millisecond // once-per-process bound

	directoryQuery      = 0x00000001
	directoryAllAccess  = 0x001F000F
	obGrantMask         = 0x1FFFFFFF // object dirs/sections: all rights incl. generic bits (spike value)
	objCaseInsensitive  = 0x40
	objOpenIf           = 0x00000080 // OBJ_OPENIF (create-or-open)
	statusNoMoreEntries = 0x80000006
	obRoot              = `\BaseNamedObjects`
	obDirInfoSize       = 32 // OBJECT_DIRECTORY_INFORMATION: 2x UNICODE_STRING (x64)
	maxOBEntryName      = 512
)

var (
	procNtCreateDirectoryObject = ntdll.NewProc("NtCreateDirectoryObject")
	procNtOpenDirectoryObject   = ntdll.NewProc("NtOpenDirectoryObject")
	procNtQueryDirectoryObject  = ntdll.NewProc("NtQueryDirectoryObject")
	procNtOpenSection           = ntdll.NewProc("NtOpenSection")
	procNtSetSecurityObject     = ntdll.NewProc("NtSetSecurityObject")
	procInitializeSD            = advapi32.NewProc("InitializeSecurityDescriptor")
	procSetSDDacl               = advapi32.NewProc("SetSecurityDescriptorDacl")
	procAddAccessAllowedAceEx   = advapi32.NewProc("AddAccessAllowedAceEx")
)

type msysState struct {
	mu        sync.Mutex
	held      windows.Handle
	helper    *exec.Cmd
	helperJob windows.Handle
	ready     bool
	obName    string                      // cached MSYS object dir name
	pinned    map[string][]windows.Handle // section handles we hold
}

var msys msysState

// ensureMsysReady makes the MSYS object directory AND the root-level
// cygwin shared sections (<user-sid>.1, shared.N) reachable by confined
// children. Called before every spawn: the ready gate is once per
// process, the section pin runs every time (cheap) because sections can
// appear or die between spawns.
func ensureMsysReady() {
	msys.mu.Lock()
	defer msys.mu.Unlock()
	if !msys.ready {
		if startHoldHelperLocked() {
			// Its msys runtime creates the object dir AND the shared
			// sections. Learn the dir name for the cache (best effort).
			if name := enumerateMSYSDir(); name != "" {
				msys.obName = name
				writeMsysDirCache(name)
				if h := precreateAndHold(name); h != 0 {
					msys.held = h // our own hold survives a helper crash
				}
			}
		} else if name := readMsysDirCache(); name != "" {
			// No MSYS shell available: fall back to the cached dir name.
			msys.obName = name
			if h := precreateAndHold(name); h != 0 {
				msys.held = h
			}
		}
		pinSectionsLocked()
		msys.ready = true
		return
	}
	pinSectionsLocked()
}

// HoldReady reports whether the bootstrap is ready (test seam).
func HoldReady() bool {
	msys.mu.Lock()
	defer msys.mu.Unlock()
	return msys.ready
}

// pinSectionsLocked opens every cygwin shared section that exists at the
// \BaseNamedObjects ROOT (open_shared() names have no directory prefix),
// normalizes its DACL to {user, Everyone, Administrators, SYSTEM} full
// control, and holds a handle so the section cannot vanish between
// spawns. Without this, sections created by the helper carry a DACL with
// no restricting SID in it, and the confined child's CreateFileMapping
// fails the write-restricted pass-2 check with "Win32 error 5".
//
// Names: <user-sid>.1 (user_shared, USER_VERSION=1) and shared.N
// (global, SHARED_VERSION — several versions tried, absent ones skipped).
func pinSectionsLocked() {
	user := currentUserSID()
	if user == nil || msys.obName == "" {
		return // no known object dir: nothing to pin (child creates its own)
	}
	if msys.pinned == nil {
		msys.pinned = map[string][]windows.Handle{}
	}
	// Sections are created RELATIVE TO the object directory handle by the
	// shipped cygwin build (observed: <obdir>\<user-sid>.1, <obdir>\shared.5).
	var names []string
	for _, v := range []string{".1", ".2"} {
		names = append(names, msys.obName+`\`+user.String()+v)
	}
	for v := 1; v <= 5; v++ {
		names = append(names, fmt.Sprintf("%s\\shared.%d", msys.obName, v))
	}
	for _, n := range names {
		if _, ok := msys.pinned[n]; ok {
			continue // already pinned and held
		}
		if h := openAndNormalizeSection(n); h != 0 {
			msys.pinned[n] = []windows.Handle{h}
		}
	}
}

// openAndNormalizeSection opens an existing section (absent → 0) and
// rewrites its DACL; the returned handle is kept open on purpose.
func openAndNormalizeSection(path string) windows.Handle {
	oa, err := newObjectAttributes(path, objCaseInsensitive, nil)
	if err != nil {
		return 0
	}
	var h windows.Handle
	// READ_CONTROL|WRITE_DAC is all we need to inspect and fix the DACL.
	r1, _, _ := procNtOpenSection.Call(uintptr(unsafe.Pointer(&h)),
		0x00040000 /*WRITE_DAC*/ |0x00020000, /*READ_CONTROL*/
		uintptr(unsafe.Pointer(oa)))
	if h == 0 || int32(r1) != 0 {
		return 0 // absent (or not writable by us): nothing to pin
	}
	normalizeSectionDACL(h)
	return h
}

// normalizeSectionDACL rewrites the section's DACL to {user, Everyone,
// Administrators, SYSTEM} full control so ANY restricted token can
// reopen it (write-restricted pass-2 needs a restricting SID in the
// DACL; cygwin's own {user, Administrators, SYSTEM} DACL has none of our
// list — the "CreateFileMapping ... Win32 error 5" wall).
//
// InitializeSecurityDescriptor writes INTO the caller's buffer — it does
// not return a pointer — so the SD lives in a 64-byte slice kept alive
// across the calls.
func normalizeSectionDACL(h windows.Handle) bool {
	acl := buildDirACL(0) // no inheritance: sections have no children
	if acl == nil {
		return false
	}
	sdBuf := make([]byte, 64)
	if r1, _, _ := procInitializeSD.Call(uintptr(unsafe.Pointer(&sdBuf[0])), 1); r1 == 0 {
		return false
	}
	if r1, _, _ := procSetSDDacl.Call(uintptr(unsafe.Pointer(&sdBuf[0])), 1,
		uintptr(unsafe.Pointer(acl)), 0); r1 == 0 {
		return false
	}
	st, _, _ := procNtSetSecurityObject.Call(uintptr(h),
		4 /*DACL_SECURITY_INFORMATION*/, uintptr(unsafe.Pointer(&sdBuf[0])))
	defer runtime.KeepAlive(sdBuf)
	defer runtime.KeepAlive(acl)
	return int32(st) == 0
}

// startHoldHelperLocked spawns the resident helper (msys.mu held).
func startHoldHelperLocked() bool {
	if msys.helper != nil || msys.held != 0 {
		return true
	}
	shell, err := lookupBash()
	if err != nil {
		return false
	}
	cmd := exec.Command(shell, "-c", "while :; do sleep 60; done")
	cmd.Stdout, cmd.Stderr, cmd.Stdin = nil, nil, nil
	if err := cmd.Start(); err != nil {
		return false
	}
	go func() { _ = cmd.Wait() }()
	msys.helper = cmd
	msys.helperJob = attachJob(cmd)
	// The dir exists as soon as the helper's msys runtime finishes DLL init
	// (before -c runs). No query for readiness exists, so bound the wait:
	// one fixed, once-per-process delay.
	time.Sleep(helperReadyWait)
	return true
}

// attachJob wraps the helper in a KILL_ON_JOB_CLOSE job so it can never
// outlive this process (hard extension/CLI death still cleans the tree).
func attachJob(cmd *exec.Cmd) windows.Handle {
	if cmd.Process == nil {
		return 0
	}
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil || job == 0 {
		return 0
	}
	info := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{}
	info.BasicLimitInformation.LimitFlags = 0x2000 // JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	if ok, err := windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info))); ok == 0 || err != nil {
		windows.CloseHandle(job)
		return 0
	}
	proc, err := windows.OpenProcess(windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE,
		false, uint32(cmd.Process.Pid))
	if err != nil {
		windows.CloseHandle(job)
		return 0
	}
	defer windows.CloseHandle(proc)
	if err := windows.AssignProcessToJobObject(job, proc); err != nil {
		windows.CloseHandle(job)
		return 0
	}
	return job
}

// lookupBash resolves a cygwin/MSYS shell for the resident helper.
func lookupBash() (string, error) {
	if s := os.Getenv("SHELL"); s != "" {
		if _, err := os.Stat(s); err == nil {
			return s, nil
		}
	}
	candidates := []string{
		`C:\Program Files\Git\bin\bash.exe`,
		`C:\Program Files\Git\usr\bin\bash.exe`,
	}
	if pf := os.Getenv("ProgramFiles"); pf != "" && pf != `C:\Program Files` {
		candidates = append(candidates,
			filepath.Join(pf, "Git", "bin", "bash.exe"),
			filepath.Join(pf, "Git", "usr", "bin", "bash.exe"))
	}
	if la := os.Getenv("LocalAppData"); la != "" {
		candidates = append(candidates,
			filepath.Join(la, "Programs", "Git", "bin", "bash.exe"))
	}
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c, nil
		}
	}
	return "", os.ErrNotExist
}

// precreateAndHold create-or-opens the object directory (OBJ_OPENIF) with
// a DACL that grants the current user, Everyone, Administrators and SYSTEM
// full control, normalizes the DACL, and keeps a handle open so the
// transient directory survives. Returns 0 on failure.
func precreateAndHold(path string) windows.Handle {
	if path == "" {
		return 0
	}
	acl := buildDirACL(grantInherit)
	if acl == nil {
		return 0
	}
	var sd uintptr
	_ = sd
	// InitializeSecurityDescriptor writes INTO the caller's buffer — it
	// does not return a pointer — so give it a real 64-byte SD buffer
	// (an 8-byte uintptr here used to produce a misaligned garbage SD
	// pointer: STATUS_DATATYPE_MISALIGNMENT from NtSetSecurityObject).
	sdBuf := make([]byte, 64)
	if r1, _, _ := procInitializeSD.Call(uintptr(unsafe.Pointer(&sdBuf[0])), 1); r1 == 0 {
		return 0
	}
	if r1, _, _ := procSetSDDacl.Call(uintptr(unsafe.Pointer(&sdBuf[0])), 1,
		uintptr(unsafe.Pointer(acl)), 0); r1 == 0 {
		return 0
	}
	sd = uintptr(unsafe.Pointer(&sdBuf[0]))
	defer runtime.KeepAlive(sdBuf)
	defer runtime.KeepAlive(acl)

	oa, err := newObjectAttributes(path, objCaseInsensitive|objOpenIf, ptrFrom(sd))
	if err != nil {
		return 0
	}
	var h windows.Handle
	r1, _, _ := procNtCreateDirectoryObject.Call(uintptr(unsafe.Pointer(&h)),
		directoryAllAccess, uintptr(unsafe.Pointer(oa)))
	if h == 0 && int32(r1) != 0 {
		// open-existing fallbacks: full access, then owner-implicit rights
		oa2, err2 := newObjectAttributes(path, objCaseInsensitive, nil)
		if err2 == nil {
			procNtOpenDirectoryObject.Call(uintptr(unsafe.Pointer(&h)),
				directoryAllAccess, uintptr(unsafe.Pointer(oa2)))
			if h == 0 {
				procNtOpenDirectoryObject.Call(uintptr(unsafe.Pointer(&h)),
					0x60000, uintptr(unsafe.Pointer(oa2)))
			}
		}
	}
	if h == 0 {
		return 0
	}
	// Best effort: normalize the DACL so any restricted token finds a
	// restricting SID in it (ignored if the open handle lacks WRITE_DAC).
	procNtSetSecurityObject.Call(uintptr(h), 4 /*DACL_SECURITY_INFORMATION*/, uintptr(ptrFrom(sd)))

	// Upgrade to a full-access hold handle when possible.
	oa3, err3 := newObjectAttributes(path, objCaseInsensitive, nil)
	if err3 == nil {
		var h2 windows.Handle
		procNtOpenDirectoryObject.Call(uintptr(unsafe.Pointer(&h2)),
			directoryAllAccess, uintptr(unsafe.Pointer(oa3)))
		if h2 != 0 {
			windows.CloseHandle(h)
			return h2
		}
	}
	return h
}

// buildDirACL builds the DACL {user, Everyone, Administrators, SYSTEM}
// full control. inherit is the ACE flag mask (OI|CI for the object
// directory, 0 for sections). Returns nil on failure.
func buildDirACL(inherit uint32) *windows.ACL {
	buf := make([]byte, 512)
	// InitializeAcl is BOOL: nonzero is success.
	if r1, _, _ := procInitializeAcl.Call(uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf)), 2); r1 == 0 {
		return nil
	}
	acl := (*windows.ACL)(unsafe.Pointer(&buf[0]))
	sids := []*windows.SID{currentUserSID(), everyoneSID, mustParseSID("S-1-5-32-544"), mustParseSID("S-1-5-18")}
	for _, s := range sids {
		if s == nil {
			continue
		}
		// AddAccessAllowedAceEx is BOOL: nonzero is success.
		if r1, _, _ := procAddAccessAllowedAceEx.Call(uintptr(unsafe.Pointer(acl)), 2,
			uintptr(inherit), obGrantMask, uintptr(unsafe.Pointer(s))); r1 == 0 {
			return nil
		}
	}
	return acl
}

// currentUserSID returns the process user's SID (GC-owned copy).
func currentUserSID() *windows.SID {
	var tok windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &tok); err != nil {
		return nil
	}
	defer tok.Close()
	u, err := tok.GetTokenUser()
	if err != nil {
		return nil
	}
	sid, err := u.User.Sid.Copy()
	if err != nil {
		return nil
	}
	return sid
}

// unicodeString mirrors the NT UNICODE_STRING layout.
type unicodeString struct {
	Length    uint16
	MaxLength uint16
	Buffer    *uint16
}

type objectAttributes struct {
	Length                   uint32
	RootDirectory            windows.Handle
	ObjectName               *unicodeString
	Attributes               uint32
	SecurityDescriptor       unsafe.Pointer
	SecurityQualityOfService unsafe.Pointer
}

// objectAttributes builds an OBJECT_ATTRIBUTES for a full object path.
func newObjectAttributes(path string, attributes uint32, sd unsafe.Pointer) (*objectAttributes, error) {
	arr, err := windows.UTF16FromString(path)
	if err != nil {
		return nil, err
	}
	us := &unicodeString{
		Length:    uint16((len(arr) - 1) * 2),
		MaxLength: uint16(len(arr) * 2),
		Buffer:    &arr[0],
	}
	return &objectAttributes{
		Length:             uint32(unsafe.Sizeof(objectAttributes{})),
		ObjectName:         us,
		Attributes:         attributes,
		SecurityDescriptor: sd,
	}, nil
}

// enumerateMSYSDir walks \BaseNamedObjects for the live msys directory
// name ("" when it cannot be found). The call is bounded and every pointer
// it hands back is validated against the buffer it wrote into before use,
// so a malformed reply degrades to "" instead of a bad read.
func enumerateMSYSDir() string {
	oa, err := newObjectAttributes(obRoot, objCaseInsensitive, nil)
	if err != nil {
		return ""
	}
	var h windows.Handle
	r1, _, _ := procNtOpenDirectoryObject.Call(uintptr(unsafe.Pointer(&h)),
		directoryQuery, uintptr(unsafe.Pointer(oa)))
	if h == 0 || int32(r1) != 0 {
		return ""
	}
	defer windows.CloseHandle(h)

	buf := make([]byte, 8192)
	bufAddr := uintptr(unsafe.Pointer(&buf[0]))
	var ctx uint32
	restart := 1
	for i := 0; i < 256; i++ {
		st, _, _ := procNtQueryDirectoryObject.Call(
			uintptr(h),
			uintptr(unsafe.Pointer(&buf[0])),
			uintptr(len(buf)),
			1, // ReturnSingleEntry
			uintptr(restart),
			uintptr(unsafe.Pointer(&ctx)),
			0)
		restart = 0
		if uint32(st) == statusNoMoreEntries {
			return ""
		}
		if int32(st) != 0 {
			return ""
		}
		name := parseOBEntry(buf, bufAddr)
		if strings.HasPrefix(name, "msys-") {
			return obRoot + `\` + name
		}
	}
	return ""
}

// parseOBEntry reads Name out of one OBJECT_DIRECTORY_INFORMATION record,
// validating that the kernel-filled UNICODE_STRING points inside the
// buffer we passed in.
func parseOBEntry(buf []byte, bufAddr uintptr) string {
	if len(buf) < obDirInfoSize {
		return ""
	}
	l := binary.LittleEndian.Uint16(buf[0:2])
	ptr := uintptr(binary.LittleEndian.Uint64(buf[8:16]))
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

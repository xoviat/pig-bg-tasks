//go:build windows

// pipeprobe — diagnostics for the srt-win Git Bash gate.
//
//	pipeprobe dump <pipename>      print a pipe's DACL
//	pipeprobe selftest             replicate cygwin's signal-pipe sequence
//	                                 (CreateNamedPipe + client
//	                                 CreateFile(GENERIC_WRITE)) under the
//	                                 CURRENT token, once with an explicit
//	                                 {user GA} SD and once with a NULL SD.
package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	advapi        = windows.NewLazySystemDLL("advapi32.dll")
	procInitAcl   = advapi.NewProc("InitializeAcl")
	procAddAceEx  = advapi.NewProc("AddAccessAllowedAceEx")
	procInitSD    = advapi.NewProc("InitializeSecurityDescriptor")
	procSetSDDacl = advapi.NewProc("SetSecurityDescriptorDacl")
)

func main() {
	if len(os.Args) >= 3 && os.Args[1] == "dump" {
		dump(os.Args[2])
		return
	}
	if len(os.Args) >= 2 && os.Args[1] == "selftest" {
		selftest()
		return
	}
	if len(os.Args) >= 2 && os.Args[1] == "selftest2" {
		selftest2()
		return
	}
	if len(os.Args) >= 3 && os.Args[1] == "hdls" {
		// hdls <pid> <name-substring>: find the helper's pipe handles,
		// duplicate them, and print the pipe's DACL.
		pid64, _ := strconv.ParseInt(os.Args[2], 10, 64)
		handlesOf(uint32(pid64), os.Args[3])
		return
	}
	fmt.Println("usage: pipeprobe dump <pipename> | selftest | selftest2 | hdls <pid> <substr>")
}

// dump prints the DACL of an existing named pipe. The argument is the
// bare pipe name (MSYS mangles \\.\pipe\... arguments, so the prefix is
// added here instead of on the command line).
func dump(name string) {
	path := name
	if !strings.HasPrefix(path, `\\.\pipe\`) {
		path = `\\.\pipe\` + path
	}
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION)
	if err == nil {
		dacl, _, derr := sd.DACL()
		if derr != nil {
			fmt.Printf("dump %s: DACL: %v\n", path, derr)
			return
		}
		printACL(path, dacl)
		return
	}
	fmt.Printf("dump %s: GetNamedSecurityInfo=%v; trying handle\n", path, err)
	p, _ := windows.UTF16PtrFromString(path)
	h, oerr := windows.CreateFile(p, windows.GENERIC_WRITE|windows.READ_CONTROL, 0, nil,
		windows.OPEN_EXISTING, 0, 0)
	if oerr != nil {
		fmt.Printf("  CreateFile fallback: %v\n", oerr)
		return
	}
	defer windows.CloseHandle(h)
	sd2, err2 := windows.GetSecurityInfo(h, windows.SE_KERNEL_OBJECT,
		windows.DACL_SECURITY_INFORMATION)
	if err2 != nil {
		fmt.Printf("  GetSecurityInfo: %v\n", err2)
		return
	}
	dacl, _, derr := sd2.DACL()
	if derr != nil {
		fmt.Printf("  DACL: %v\n", derr)
		return
	}
	printACL(path, dacl)
}
func selftest() {
	user := currentUserSID()
	fmt.Println("== a: explicit {user GA} SD (cygwin sec_user_nih shape) ==")
	runPipe(`\\.\pipe\srt-selftest-a`, buildUserSD(user))
	fmt.Println("== b: NULL SD (token default DACL) ==")
	runPipe(`\\.\pipe\srt-selftest-b`, nil)
}

// selftest2 dumps the token's own state, then inspects the ACTUAL SD the
// kernel put on pipes created with each SD shape, plus the client-open
// result.
func selftest2() {
	dumpTokenState()
	user := currentUserSID()
	fmt.Println("== c: explicit {Everyone GA} SD ==")
	runPipeDump(`\\.\pipe\srt-selftest-c`, buildSidSD(everyoneSID()))
	fmt.Println("== a: explicit {user GA} SD ==")
	runPipeDump(`\\.\pipe\srt-selftest-a`, buildUserSD(user))
	fmt.Println("== b: NULL SD ==")
	runPipeDump(`\\.\pipe\srt-selftest-b`, nil)
}

func everyoneSID() *windows.SID {
	s, err := windows.CreateWellKnownSid(windows.WinWorldSid)
	if err != nil {
		return nil
	}
	return s
}

// dumpTokenState prints restricted SIDs and the token default DACL.
func dumpTokenState() {
	tok := windows.Token(0)
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &tok); err != nil {
		fmt.Printf("open token: %v\n", err)
		return
	}
	defer tok.Close()

	buf, err := tokenInfo(tok, windows.TokenRestrictedSids)
	if err != nil {
		fmt.Printf("TokenRestrictedSids: %v\n", err)
	} else if len(buf) >= 8 {
		count := *(*uint32)(unsafe.Pointer(&buf[0]))
		fmt.Printf("restricted SIDs: %d\n", count)
		type sidAndAttr struct {
			Sid        *windows.SID
			Attributes uint32
			_          uint32
		}
		for i := uint32(0); i < count; i++ {
			saa := (*sidAndAttr)(unsafe.Pointer(&buf[8+16*i]))
			if saa.Sid != nil {
				fmt.Printf("  %s\n", saa.Sid.String())
			}
		}
	}

	buf, err = tokenInfo(tok, tokenDefaultDaclInfo)
	if err != nil {
		fmt.Printf("TokenDefaultDacl: %v\n", err)
		return
	}
	type dacInfo struct{ Acl *windows.ACL }
	if len(buf) < 8 {
		fmt.Println("TokenDefaultDacl: empty")
		return
	}
	di := (*dacInfo)(unsafe.Pointer(&buf[0]))
	if di.Acl == nil {
		fmt.Println("token default DACL: NULL")
		return
	}
	fmt.Printf("token default DACL: %d ACEs\n", di.Acl.AceCount)
	printACL("default", di.Acl)
}

const tokenDefaultDaclInfo = 6

// tokenInfo wraps GetTokenInformation with size probing.
func tokenInfo(t windows.Token, class uint32) ([]byte, error) {
	var n uint32
	_ = windows.GetTokenInformation(t, class, nil, 0, &n)
	if n == 0 {
		return nil, fmt.Errorf("TokenInformation class %d: no size", class)
	}
	buf := make([]byte, n)
	if err := windows.GetTokenInformation(t, class, &buf[0], n, &n); err != nil {
		return nil, err
	}
	return buf[:n], nil
}

func runPipeDump(name string, sa *windows.SecurityAttributes) {
	h := runPipe(name, sa)
	if h == 0 {
		return
	}
	defer windows.CloseHandle(h)
	// What SD did the kernel actually apply? Query the SERVER handle — no
	// client open needed (which would fail on direction anyway).
	sd, err := windows.GetSecurityInfo(h, windows.SE_KERNEL_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		fmt.Printf("  GetSecurityInfo: %v\n", err)
		return
	}
	dacl, _, derr := sd.DACL()
	if derr != nil {
		fmt.Printf("  DACL: %v\n", derr)
		return
	}
	printACL("  actual pipe SD", dacl)
}

// runPipe creates the pipe, attempts the client open, and returns the
// server handle (caller closes it) so the applied SD can be inspected.
func runPipe(name string, sd *windows.SecurityAttributes) windows.Handle {
	n, _ := windows.UTF16PtrFromString(name)
	const firstInstance = 0x00080000
	const accessInbound = 0x00000001
	const typeMessage = 0x00000004
	h, err := windows.CreateNamedPipe(n, accessInbound|firstInstance,
		typeMessage, 1, 4096, 4096, 0, sd)
	if err != nil {
		fmt.Printf("  CreateNamedPipe: %v\n", err)
		return 0
	}
	fmt.Println("  CreateNamedPipe: OK")
	// cygwin's client end: GENERIC_WRITE | FILE_READ_ATTRIBUTES
	c, err := windows.CreateFile(n, windows.GENERIC_WRITE|windows.FILE_READ_ATTRIBUTES,
		0, nil, windows.OPEN_EXISTING, 0, 0)
	if err != nil {
		fmt.Printf("  CreateFile(GENERIC_WRITE|FILE_READ_ATTRIBUTES): %v\n", err)
	} else {
		fmt.Println("  CreateFile(GENERIC_WRITE|FILE_READ_ATTRIBUTES): OK")
		windows.CloseHandle(c)
	}
	return h
}

// buildUserSD builds {user: GENERIC_ALL, no inheritance} — cygwin's
// sec_user_nih shape.
func buildUserSD(user *windows.SID) *windows.SecurityAttributes {
	return buildSidSD(user)
}

// buildSidSD builds {sid: GENERIC_ALL, no inheritance}.
func buildSidSD(sid *windows.SID) *windows.SecurityAttributes {
	aclBuf := make([]byte, 512)
	if r1, _, _ := procInitAcl.Call(uintptr(unsafe.Pointer(&aclBuf[0])),
		uintptr(len(aclBuf)), 2); r1 == 0 {
		return nil
	}
	acl := (*windows.ACL)(unsafe.Pointer(&aclBuf[0]))
	if r1, _, _ := procAddAceEx.Call(uintptr(unsafe.Pointer(acl)), 2, 0,
		windows.GENERIC_ALL, uintptr(unsafe.Pointer(sid))); r1 == 0 {
		return nil
	}
	sdBuf := make([]byte, 64)
	if r1, _, _ := procInitSD.Call(uintptr(unsafe.Pointer(&sdBuf[0])), 1); r1 == 0 {
		return nil
	}
	if r1, _, _ := procSetSDDacl.Call(uintptr(unsafe.Pointer(&sdBuf[0])), 1,
		uintptr(unsafe.Pointer(acl)), 0); r1 == 0 {
		return nil
	}
	sa := &windows.SecurityAttributes{
		Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
		SecurityDescriptor: (*windows.SECURITY_DESCRIPTOR)(unsafe.Pointer(&sdBuf[0])),
	}
	// keep buffers alive through use by the caller via closure refs
	runtimeKeep(aclBuf, sdBuf)
	return sa
}

// runtimeKeep stores buffers so the GC cannot collect them while the
// SecurityAttributes pointer is in use.
var keepAlive [][]byte

func runtimeKeep(bufs ...[]byte) { keepAlive = append(keepAlive, bufs...) }

// handlesOf walks the target process's handle table (SystemExtendedHandle-
// Information), duplicates matching handles, and prints their object names
// plus — for the requested pipe — its DACL.
func handlesOf(pid uint32, substr string) {
	ntdll := windows.NewLazySystemDLL("ntdll.dll")
	procQSHI := ntdll.NewProc("NtQuerySystemInformation")
	procQO := ntdll.NewProc("NtQueryObject")

	var size uint32 = 1 << 20
	for {
		buf := make([]byte, size)
		r1, _, _ := procQSHI.Call(64, uintptr(unsafe.Pointer(&buf[0])),
			uintptr(size), uintptr(unsafe.Pointer(&size)))
		if r1 == 0xC0000004 /* STATUS_INFO_LENGTH_MISMATCH */ {
			if size < 1<<20 {
				size = 1 << 20
			}
			size += 1 << 20
			continue
		}
		if r1 != 0 {
			fmt.Printf("NtQuerySystemInformation: 0x%X size=%d\n", r1, size)
			return
		}
		hdr := (*struct {
			Count uintptr
			_     uintptr
		})(unsafe.Pointer(&buf[0]))
		type entry struct {
			Object           uintptr
			UniqueProcessID  uintptr
			HandleValue      uintptr
			GrantedAccess    uint32
			CreatorBackTrac  uint16
			ObjectTypeIndex  uint16
			HandleAttributes uint32
			Reserved         uint32
		}
		const entrySize = 40
		count := int(hdr.Count)
		base := unsafe.Pointer(&buf[16])
		proc, _ := windows.OpenProcess(windows.PROCESS_DUP_HANDLE, false, pid)
		if proc == 0 {
			fmt.Printf("OpenProcess(%d): %v\n", pid, windows.GetLastError())
			return
		}
		defer windows.CloseHandle(proc)
		for i := 0; i < count; i++ {
			e := (*entry)(unsafe.Pointer(uintptr(base) + uintptr(i*entrySize)))
			if uint32(e.UniqueProcessID) != pid {
				continue
			}
			var dup windows.Handle
			err := windows.DuplicateHandle(proc, windows.Handle(e.HandleValue),
				windows.CurrentProcess(), &dup, 0, false, windows.DUPLICATE_SAME_ACCESS)
			if err != nil {
				continue
			}
			// object name
			nbuf := make([]byte, 1024)
			r1, _, _ := procQO.Call(uintptr(dup), 1,
				uintptr(unsafe.Pointer(&nbuf[0])), uintptr(len(nbuf)), 0)
			name := ""
			if r1 == 0 {
				us := (*struct {
					Len    uint16
					MaxLen uint16
					_      uint32
					Ptr    *uint16
				})(unsafe.Pointer(&nbuf[0]))
				if us.Len > 0 {
					name = windows.UTF16ToString((*[512]uint16)(unsafe.Pointer(us.Ptr))[:us.Len/2])
				}
			}
			if name != "" && strings.Contains(strings.ToLower(name), strings.ToLower(substr)) {
				fmt.Printf("handle 0x%X: %s\n", e.HandleValue, name)
				sd, serr := windows.GetSecurityInfo(dup, windows.SE_KERNEL_OBJECT,
					windows.DACL_SECURITY_INFORMATION)
				if serr != nil {
					fmt.Printf("  GetSecurityInfo: %v\n", serr)
				} else if dacl, _, derr := sd.DACL(); derr == nil {
					printACL("  pipe DACL", dacl)
				} else {
					fmt.Printf("  DACL: %v\n", derr)
				}
			}
			windows.CloseHandle(dup)
		}
		return
	}
}

func currentUserSID() *windows.SID {
	var tok windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(),
		windows.TOKEN_QUERY, &tok); err != nil {
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
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		acct, domain, _, _ := sid.LookupAccount("")
		hdr := (*[4]byte)(unsafe.Pointer(ace))
		fmt.Printf("  type=%d flags=0x%02X mask=0x%08X sid=%s %s\\%s\n",
			hdr[0], hdr[1], uint32(ace.Mask), sid.String(), domain, acct)
	}
}

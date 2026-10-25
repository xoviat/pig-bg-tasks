//go:build windows

// Restricted token creation (private to the Sandbox — no API ever returns
// a token handle):
//
//	CreateRestrictedToken(
//	    flags = DISABLE_MAX_PRIVILEGE|WRITE_RESTRICTED (0x9),
//	    restrict = {Everyone S-1-1-0, logon SID, synthetic SID, user SID})
//	→ default DACL {Everyone, logon, synthetic} GA (so the child's
//	  NULL-SD creations — cygwin sections/events, PowerShell pipelines —
//	  pass the write-restricted check)
//	→ DuplicateTokenEx(MAXIMUM_ALLOWED) primary (the raw restricted
//	  handle may lack TOKEN_ASSIGN_PRIMARY; spike-proven).

package srtwin

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	createRestrictedTokenFlags = 0x1 | 0x8 // DISABLE_MAX_PRIVILEGE | WRITE_RESTRICTED

	tokenLogonSidClass = 26 // TOKEN_INFORMATION_CLASS TokenLogonSid
	tokenDefaultDacl   = 6  // TOKEN_INFORMATION_CLASS TokenDefaultDacl
)

var (
	procCreateRestrictedToken = advapi32.NewProc("CreateRestrictedToken")
)

// well-known SIDs used by the recipe.
var (
	everyoneSID = mustParseSID("S-1-1-0")
)

func mustParseSID(s string) *windows.SID {
	sid, err := windows.StringToSid(s)
	if err != nil {
		panic("srt-win: bad well-known SID " + s + ": " + err.Error())
	}
	return sid
}

// logonSID returns the token's logon SID (it changes every logon — a
// Sandbox must not be reused across logoff/logon). TokenLogonSid first,
// then a TokenGroups scan for SE_GROUP_LOGON_ID.
func logonSID(tok windows.Token) (*windows.SID, error) {
	if sid, err := logonSIDFromClass(tok); err == nil && sid != nil {
		return sid, nil
	}
	groups, err := tokenGroups(tok, windows.TokenGroups)
	if err == nil {
		if sid := scanLogonSID(groups); sid != nil {
			return sid, nil
		}
	}
	return nil, fmt.Errorf("srt-win: token has no logon SID")
}

func logonSIDFromClass(tok windows.Token) (*windows.SID, error) {
	groups, err := tokenGroups(tok, tokenLogonSidClass)
	if err != nil || len(groups) == 0 {
		return nil, fmt.Errorf("srt-win: TokenLogonSid: %v", err)
	}
	sid, err := groups[0].Sid.Copy()
	if err != nil {
		return nil, err
	}
	return sid, nil
}

// tokenGroups reads a TOKEN_GROUPS-shaped info class and returns a copied
// group list (the copies outlive the query buffer).
func tokenGroups(tok windows.Token, class uint32) ([]windows.SIDAndAttributes, error) {
	var n uint32
	_ = windows.GetTokenInformation(tok, class, nil, 0, &n)
	if n == 0 {
		return nil, fmt.Errorf("srt-win: GetTokenInformation(%d): no buffer", class)
	}
	buf := make([]byte, n)
	if err := windows.GetTokenInformation(tok, class, &buf[0], n, &n); err != nil {
		return nil, err
	}
	tg := (*windows.Tokengroups)(unsafe.Pointer(&buf[0]))
	raw := tg.AllGroups()
	out := make([]windows.SIDAndAttributes, 0, len(raw))
	for _, g := range raw {
		sid, err := g.Sid.Copy()
		if err != nil {
			return nil, err
		}
		out = append(out, windows.SIDAndAttributes{Sid: sid, Attributes: g.Attributes})
	}
	return out, nil
}

func scanLogonSID(groups []windows.SIDAndAttributes) *windows.SID {
	for _, g := range groups {
		if g.Attributes&windows.SE_GROUP_LOGON_ID == windows.SE_GROUP_LOGON_ID {
			if sid, err := g.Sid.Copy(); err == nil {
				return sid
			}
		}
	}
	return nil
}

// setDefaultDacl stamps a permissive default DACL onto the token so the
// child's NULL-SD creations pass the write-restricted check: objects the
// child creates without an explicit descriptor end up with this DACL, and
// restricted pass-2 then finds a restricting SID in it. This is the spike's
// "Default DACL replaces section pinning" fix and Codex's set_default_dacl.
func setDefaultDacl(tok windows.Token, sids []*windows.SID) error {
	entries := make([]explicitAccess, 0, len(sids))
	for _, s := range sids {
		entries = append(entries, entryFor(s, windows.GENERIC_ALL, grantAccess, 0))
	}
	var newAcl *windows.ACL
	r1, _, _ := procSetEntriesInAcl.Call(uintptr(len(entries)),
		uintptr(unsafe.Pointer(&entries[0])), 0, uintptr(unsafe.Pointer(&newAcl)))
	if r1 != 0 || newAcl == nil {
		return fmt.Errorf("srt-win: SetEntriesInAclW(default dacl): 0x%X", r1)
	}
	defer procLocalFree.Call(uintptr(unsafe.Pointer(newAcl)))
	info := struct{ Acl *windows.ACL }{Acl: newAcl}
	if err := windows.SetTokenInformation(tok, tokenDefaultDacl,
		(*byte)(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info))); err != nil {
		return fmt.Errorf("srt-win: SetTokenInformation(TokenDefaultDacl): %w", err)
	}
	return nil
}

// enableSeChangeNotify leaves the one privilege DISABLE_MAX_PRIVILEGE
// keeps (bypass-traverse checking) enabled. Best effort: a token that
// refuses the adjustment still spawns fine.
func enableSeChangeNotify(tok windows.Token) {
	luid := windows.LUID{}
	if err := windows.LookupPrivilegeValue(nil, windows.StringToUTF16Ptr("SeChangeNotifyPrivilege"), &luid); err != nil {
		return
	}
	tp := windows.Tokenprivileges{PrivilegeCount: 1}
	tp.Privileges[0] = windows.LUIDAndAttributes{Luid: luid, Attributes: windows.SE_PRIVILEGE_ENABLED}
	_ = windows.AdjustTokenPrivileges(tok, false, &tp, 0, nil, nil)
}

// newRestrictedToken mints the private primary token for sid.
//
// Known inherent limitation: any non-empty restricted-SID list makes
// Schannel's AcquireCredentialsHandle fail with SEC_E_NO_CREDENTIALS,
// breaking all OS-TLS HTTPS in confined children (cargo, curl,
// PowerShell). Not fixable via flags or list composition — see
// SCHANNEL-GATE.md for the bisection.
func newRestrictedToken(sid *windows.SID) (windows.Token, error) {
	var cur windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(),
		windows.TOKEN_ALL_ACCESS, &cur); err != nil {
		return 0, fmt.Errorf("srt-win: OpenProcessToken: %w", err)
	}
	defer cur.Close()

	logon, err := logonSID(cur)
	if err != nil {
		return 0, err
	}

	sas := []windows.SIDAndAttributes{
		{Sid: everyoneSID},
		{Sid: logon},
		{Sid: sid},
		// User SID: Git Bash (cygwin) creates its signal pipe with an
		// EXPLICIT SD {user, Administrators, SYSTEM} (sec_user_nih), and
		// write-restricted pass-2 only consults restricted SIDs — without
		// it, cygwin's client CreateFile is denied and bash dies at DLL
		// init ("couldn't create signal pipe, Win32 error 5"). See
		// GITBASH-GATE.md. Cost: the documented profile-tree write gap.
		{Sid: currentUserSID()},
	}
	var tok windows.Token
	r1, _, e := procCreateRestrictedToken.Call(
		uintptr(cur),
		uintptr(createRestrictedTokenFlags),
		0, 0, 0, 0, // no disable list, no delete-after-disable, no restricted SIDs to disable
		uintptr(len(sas)), uintptr(unsafe.Pointer(&sas[0])),
		uintptr(unsafe.Pointer(&tok)))
	if r1 == 0 || tok == 0 {
		return 0, fmt.Errorf("srt-win: CreateRestrictedToken: %v", e)
	}

	// The raw restricted handle may lack TOKEN_ASSIGN_PRIMARY — duplicate
	// to a primary with MAXIMUM_ALLOWED (spike-proven) and use that.
	var prim windows.Token
	err = windows.DuplicateTokenEx(tok, windows.MAXIMUM_ALLOWED, nil,
		windows.SecurityImpersonation, windows.TokenPrimary, &prim)
	tok.Close()
	if err != nil {
		return 0, fmt.Errorf("srt-win: DuplicateTokenEx: %w", err)
	}

	if err := setDefaultDacl(prim, []*windows.SID{everyoneSID, logon, sid}); err != nil {
		prim.Close()
		return 0, err
	}
	enableSeChangeNotify(prim)
	return prim, nil
}

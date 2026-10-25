//go:build windows

// Package srtwin is a Windows write-restricted sandbox: a synthetic SID
// granted write access via ACLs on whitelisted directories, and child
// processes run under a restricted token whose restricted-SID list
// includes that synthetic SID — so a command and all its descendants can
// only write to the whitelisted directories. Runs fully unelevated; no
// network restrictions (out of scope by design).
//
// Two surfaces over one core:
//
//   - this library: New(dirs...) mints ONE token reused for many commands
//     through an os/exec-style Command interface;
//   - cmd/srt-win: a thin CLI wrapper (flag parsing and exit codes only).
//
// The SID is a pure function of the directory set (see sid.go) and all
// persistent state lives in one HKCU\Software\srt-win cache (see
// registry.go) shared by both surfaces — there is no other storage.
//
// A Sandbox is immutable after New (only the private token handle is
// taken and released, under a mutex), so one Sandbox is safe for
// concurrent Command/Run use. One Sandbox = one directory set = one SID;
// a different dir list is a different New. A Sandbox is tied to the
// logon session that created it (the token embeds that session's logon
// SID) — do not persist one across logoff.
package srtwin

import (
	"fmt"
	"sync"

	"golang.org/x/sys/windows"
)

// SetupError carries the non-fatal setup warnings (degraded move probes,
// LRU evictions) alongside a fatal New error, so the CLI can still show
// what happened before the failure.
type SetupError struct {
	Err      error
	Warnings []string
}

func (e *SetupError) Error() string { return e.Err.Error() }
func (e *SetupError) Unwrap() error { return e.Err }

// Sandbox privately holds the pre-minted token, its SID, and the
// normalized directory set. No exported identifier exposes a token handle.
type Sandbox struct {
	dirs   []string
	cfgKey string
	sidStr string

	mu    sync.Mutex
	sid   *windows.SID
	token windows.Token

	warns []string
}

// New normalizes dirs, builds/verifies ACLs, runs move detection, and
// mints the restricted token ONCE. Safe to reuse for many commands.
//
// Setup order (spec): config lookup (+Used refresh) → eviction at 8
// configs → move detection for THIS SID → verify dirs exist → apply
// missing ACEs (rollback on partial failure) → registry write (only after
// the ACLs succeeded) → mint the token.
func New(dirs ...string) (*Sandbox, error) {
	norm, err := NormalizeDirs(dirs)
	if err != nil {
		return nil, err
	}
	sum := hashDirs(norm)
	key := configKey(sum)
	sidStr := sidStringForDirs(norm)
	s := &Sandbox{dirs: norm, cfgKey: key, sidStr: sidStr}

	if len(norm) > 0 {
		// 1. config lookup: hit refreshes Used, miss may evict (2).
		if _, ok := lookupConfig(key); ok {
			_ = touchUsed(sidStr)
		} else {
			s.evictIfNeeded()
		}

		// 3. move detection for this SID only (deferred to point of use).
		if recDirs := readDirs(sidStr); len(recDirs) > 0 {
			s.warns = append(s.warns, detectMoves(sidStr, key, recDirs, readRoots(sidStr))...)
		}
	}

	// 4. verify every dir exists (the caller's dir list is authoritative —
	// never retarget to a moved location), then apply missing ACEs.
	for _, d := range norm {
		if !pathExists(d) {
			return nil, s.wrapErr(fmt.Errorf("srt-win: writable directory is missing: %s", d))
		}
	}

	sid, err := allocateSID(sum)
	if err != nil {
		return nil, err
	}
	var applied []string
	for _, d := range norm {
		if ok, gerr := hasGrant(d, sidStr); gerr == nil && ok {
			continue // idempotent: no duplicate ACEs, no ACL rewrite
		}
		if err := grantACE(d, sid); err != nil {
			// best-effort rollback of the ACEs already applied by THIS call
			for _, p := range applied {
				_ = stripSIDACE(p, sidStr)
			}
			freeSID(sid)
			return nil, err
		}
		applied = append(applied, d)
	}

	// 5. registry write — only now, after the ACLs succeeded.
	if len(norm) > 0 {
		roots := make([]rootRecord, 0, len(norm))
		for _, d := range norm {
			r, rerr := fileIdentity(d)
			if rerr != nil {
				r = rootRecord{} // unknown identity: keep record alignment
			}
			roots = append(roots, r)
		}
		_ = putConfig(key, sidStr)
		_ = writeDirs(sidStr, norm)
		_ = writeRoots(sidStr, roots)
		_ = touchUsed(sidStr)
	}

	// 6. mint the restricted token once, stored privately.
	tok, err := newRestrictedToken(sid)
	if err != nil {
		freeSID(sid)
		return nil, s.wrapErr(err)
	}
	s.mu.Lock()
	s.sid, s.token = sid, tok
	s.mu.Unlock()
	return s, nil
}

// wrapErr attaches accumulated warnings to a fatal error (nil warnings
// returns the error untouched).
func (s *Sandbox) wrapErr(err error) error {
	if len(s.warns) == 0 {
		return err
	}
	return &SetupError{Err: err, Warnings: append([]string(nil), s.warns...)}
}

// evictIfNeeded: when the state DB already holds maxConfigs configs,
// evict the least-recently-used one — strip its ACEs from each of its
// dirs, then delete its Sids and Config entries.
func (s *Sandbox) evictIfNeeded() {
	sids, err := listSids()
	if err != nil || len(sids) < maxConfigs {
		return
	}
	entries := make([]sidUse, 0, len(sids))
	for _, sid := range sids {
		entries = append(entries, sidUse{sid: sid, used: readUsed(sid)})
	}
	victim := pickEviction(entries)
	if victim == "" {
		return
	}
	vdirs := readDirs(victim)
	if vsid, err := windows.StringToSid(victim); err == nil {
		for _, d := range vdirs {
			_ = stripSIDACE(d, vsid.String())
		}
	}
	deleteSidEntry(victim)
	if len(vdirs) > 0 {
		deleteConfig(configKey(hashDirs(vdirs)))
	}
	s.warns = append(s.warns, fmt.Sprintf(
		"srt-win: evicted least-recently-used config %s (%d dirs)", victim, len(vdirs)))
}

// Close releases the token handle and the SID buffer. Standing ACLs stay
// on disk (they are inert: no live token carries this SID until the same
// dir set is New'ed again) — forgetting is eviction's or move cleanup's
// job, never Close's.
func (s *Sandbox) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.token != 0 {
		s.token.Close()
		s.token = 0
	}
	if s.sid != nil {
		freeSID(s.sid)
		s.sid = nil
	}
	return nil
}

// SIDString is the deterministic synthetic SID of this dir set — the same
// string the CLI prints. A string only: no handle ever leaves the package.
func (s *Sandbox) SIDString() string { return s.sidStr }

// Dirs is the normalized, sorted directory set.
func (s *Sandbox) Dirs() []string {
	out := make([]string, len(s.dirs))
	copy(out, s.dirs)
	return out
}

// Warnings are non-fatal setup diagnostics (degraded move probes, LRU
// evictions). The CLI prints them on stderr.
func (s *Sandbox) Warnings() []string {
	out := make([]string, len(s.warns))
	copy(out, s.warns)
	return out
}

// tokenHandle returns the private token (0 after Close). Callers use it
// only to hand to a spawn; no API exposes it as an identifier.
func (s *Sandbox) tokenHandle() windows.Token {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.token
}

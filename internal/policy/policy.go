// Package policy holds the file-effect mode model and path helpers —
// parity with pi-sandbox's src/policy.ts.
package policy

import (
	"os"
	"path/filepath"
)

// Mode is one of the three permission modes.
type Mode string

const (
	ModeReadonly         Mode = "read-only"
	ModeWorkspaceWrite   Mode = "workspace-write"
	ModeDangerFullAccess Mode = "danger-full-access"
)

// SANDBOX_MODES is the user-facing vocabulary (completion + validation order).
var SANDBOX_MODES = []Mode{ModeReadonly, ModeWorkspaceWrite, ModeDangerFullAccess}

// IsMode reports whether value names a known mode.
func IsMode(value any) bool {
	s, ok := value.(string)
	if !ok {
		return false
	}
	for _, m := range SANDBOX_MODES {
		if string(m) == s {
			return true
		}
	}
	return false
}

// IsConfined reports whether mode goes through a runner.
func IsConfined(mode Mode) bool { return mode != ModeDangerFullAccess }

// Canonical resolves symlinks for comparison purposes; a path that does not
// exist yet is returned unchanged (conservative — an unresolvable root matches
// nothing, same as the reference).
func Canonical(path string) string {
	if canon, err := filepath.EvalSymlinks(path); err == nil {
		return canon
	}
	return filepath.Clean(path)
}

// DefaultTmpRoots: on Windows the only tmp root is %TEMP% (there is no POSIX
// /tmp). Mirrors the reference's defaultTmpRoots.
func DefaultTmpRoots() []string {
	return []string{os.TempDir()}
}

// WritableRoots derives workspace-write's writable roots (canonical, deduped,
// order-preserving). read-only and danger-full-access return none: extra dirs
// only apply to workspace-write.
func WritableRoots(mode Mode, workspaceRoot string, extraRoots []string) []string {
	if mode != ModeWorkspaceWrite {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	add := func(p string) {
		c := Canonical(p)
		if !seen[c] {
			seen[c] = true
			out = append(out, c)
		}
	}
	add(workspaceRoot)
	for _, t := range DefaultTmpRoots() {
		add(t)
	}
	for _, e := range extraRoots {
		add(e)
	}
	return out
}

// ResolveEffectiveMode: process-wide /sandbox override beats the config
// default. (An approved escalation applies per call, handled at the tool layer.)
func ResolveEffectiveMode(override *Mode, configDefault Mode) Mode {
	if override != nil {
		return *override
	}
	return configDefault
}

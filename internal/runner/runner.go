// Package runner selects the confinement runner for this host — parity with
// the reference's src/runners.ts structure, WINDOWS-ONLY SCOPE for now.
//
// Linux (bwrap/landlock) and macOS (seatbelt) are deliberately DEFERRED:
// their chains probe to "unavailable" and confined commands fail closed with
// a message that names the deferral. danger-full-access still runs bare on
// any platform.

package runner

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"

	"example.com/pig-bg-tasks/internal/policy"
)

// Kind names a runner backend.
type Kind string

const (
	KindWindowsACL  Kind = "windows-acl"
	KindUnavailable Kind = "unavailable"
)

// Enforcement: windows-acl is always "partial" (structural gaps: NTFS
// hard-link aliasing, unconfined reads, standing grants) — honest docs.
type Enforcement string

const (
	EnforcementFull    Enforcement = "full"
	EnforcementPartial Enforcement = "partial"
)

// Selected is the verdict (cached per process).
type Selected struct {
	Kind        Kind
	Enforcement Enforcement
}

// ErrUnavailable is the fail-closed error: the command must never run bare.
type ErrUnavailable struct {
	Detail string
}

func (e *ErrUnavailable) Error() string {
	if e.Detail != "" {
		return fmt.Sprintf("SANDBOX_UNAVAILABLE: sandbox runner failed before the command ran: %s", e.Detail)
	}
	return "SANDBOX_UNAVAILABLE: no usable sandbox runner on this host; the command was NOT executed. Linux/macOS runners are deferred in this build — set mode \"danger-full-access\" explicitly to run unconfined."
}

var (
	probeMu   sync.Mutex
	cachedSel *Selected
)

// Select resolves the runner chain once per process (availability checks only
// — no capability probing spawns anything, matching the reference's win32
// "resolveability, never spawn" rule).
func Select(probeTimeoutMs int) Selected {
	probeMu.Lock()
	defer probeMu.Unlock()
	if cachedSel != nil {
		return *cachedSel
	}
	sel := chainVerdict(probeTimeoutMs)
	cachedSel = &sel
	return sel
}

// ResetCache is for tests.
func ResetCache() { probeMu.Lock(); cachedSel = nil; probeMu.Unlock() }

func chainVerdict(probeTimeoutMs int) Selected {
	switch currentOS() {
	case "windows":
		if _, err := ResolveShell(); err != nil {
			return Selected{Kind: KindUnavailable}
		}
		return Selected{Kind: KindWindowsACL, Enforcement: EnforcementPartial}
	default:
		// Deferred: Linux (bwrap/landlock) and macOS (seatbelt).
		_ = probeTimeoutMs
		return Selected{Kind: KindUnavailable}
	}
}

// currentOS is a seam for tests.
var currentOS = func() string { return runtime.GOOS }

// ErrShellUnavailable: bash itself could not be resolved.
var ErrShellUnavailable = errors.New("bash shell could not be resolved (set shellPath semantics: PATH, then standard Git for Windows locations)")

var (
	shellMu         sync.Mutex
	shellPath       string
	configuredShell string // settings' shellPath, wired from the host at session start
)

// SetConfiguredShell records the configured bash (settings' shellPath) and
// invalidates the cache. Empty returns to default resolution.
func SetConfiguredShell(p string) {
	shellMu.Lock()
	configuredShell = p
	shellPath = ""
	shellMu.Unlock()
}

// ConfiguredShell returns the configured shellPath override ("" = none).
func ConfiguredShell() string {
	shellMu.Lock()
	defer shellMu.Unlock()
	return configuredShell
}

// ResolveShell finds the bash to run, matching pi core's documented order:
// the configured shellPath setting first, then $SHELL, then the standard Git
// for Windows locations, then `bash` on PATH — with the WSL launcher aliases
// (WindowsApps\bash.exe, System32\bash.exe) skipped on PATH unless they were
// configured explicitly, so bare commands never land in WSL by surprise
// (github.com/cyzlmh/pi-extensions/issues/2). Cached per process.
func ResolveShell() (string, error) {
	shellMu.Lock()
	defer shellMu.Unlock()
	if shellPath != "" {
		return shellPath, nil
	}
	var candidates []string
	if configuredShell != "" {
		// Explicit user choice wins outright — even a WSL/cygwin shell that
		// would be skipped below is honored when named in settings.
		candidates = append(candidates, configuredShell)
	}
	if s := os.Getenv("SHELL"); s != "" {
		candidates = append(candidates, s)
	}
	// Git for Windows standard locations BEFORE PATH on Windows, so a PATH
	// hit can never shadow Git Bash.
	progFiles := os.Getenv("ProgramFiles")
	if progFiles == "" {
		progFiles = `C:\Program Files`
	}
	local := os.Getenv("LocalAppData")
	for _, base := range []string{progFiles, local} {
		if base == "" {
			continue
		}
		candidates = append(candidates,
			filepath.Join(base, "Git", "bin", "bash.exe"),
			filepath.Join(base, "Git", "usr", "bin", "bash.exe"),
			filepath.Join(base, "Git", "mingw64", "bin", "bash.exe"),
		)
	}
	if p, err := exec.LookPath("bash"); err == nil && !isWSLAlias(p) {
		candidates = append(candidates, p)
	}
	for _, c := range candidates {
		if fi, err := os.Stat(c); err == nil && !fi.IsDir() {
			abs, err := filepath.Abs(c)
			if err == nil {
				shellPath = abs
			} else {
				shellPath = c
			}
			return shellPath, nil
		}
	}
	return "", ErrShellUnavailable
}

// isWSLAlias reports whether p is a WSL launcher that would silently run
// commands inside a WSL distro instead of a native Windows shell.
func isWSLAlias(p string) bool {
	if runtime.GOOS != "windows" {
		return false
	}
	n := strings.ToLower(filepath.Clean(p))
	return strings.HasSuffix(n, `\microsoft\windowsapps\bash.exe`) ||
		strings.HasSuffix(n, `\system32\bash.exe`)
}

// ResetShellCache is for tests.
func ResetShellCache() { shellMu.Lock(); shellPath = ""; shellMu.Unlock() }

// Describe renders the /sandbox "runner:" line.
func Describe(sel Selected, effective policy.Mode) string {
	if effective == policy.ModeDangerFullAccess {
		return "bypassed (danger-full-access)"
	}
	if sel.Kind == KindUnavailable {
		return "unavailable (fail-closed: confined commands will be refused; Linux/macOS runners deferred)"
	}
	return fmt.Sprintf("%s (%s enforcement)", sel.Kind, sel.Enforcement)
}

// probeBwrapExists is a placeholder for the deferred Linux chain; kept so the
// Select call sites keep their upstream shape.
func probeBwrapExists() bool {
	_, err := exec.LookPath("bwrap")
	return err == nil && !strings.EqualFold(os.Getenv("PIG_SANDBOX_DISABLE_BWRAP"), "1")
}

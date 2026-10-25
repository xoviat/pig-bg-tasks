// Package permission holds the process-wide mode override backing /sandbox —
// parity with the reference's src/permission.ts (the reference's slash
// command was /permission; this build's is /sandbox per CONVERGENCE.md).
//
// One PiG extension process serves every session (parent and subagents), so a
// package-level variable IS the process-wide singleton the reference needed
// globalThis for. The override applies on the next tool call in every session.

package permission

import (
	"sync"

	"example.com/pig-bg-tasks/internal/policy"
)

var (
	mu       sync.RWMutex
	override *policy.Mode
)

// Get returns the current process-wide override (nil = none).
func Get() *policy.Mode {
	mu.RLock()
	defer mu.RUnlock()
	return override
}

// Set installs a new process-wide override.
func Set(mode policy.Mode) {
	mu.Lock()
	defer mu.Unlock()
	o := mode
	override = &o
}

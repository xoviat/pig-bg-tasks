// Package ledger is the denial-first gate's per-session denial record —
// parity with the reference's src/denial-ledger.ts.
//
// A real sandbox denial records one entry; the next escalation request for the
// same session + subject consumes it (exactly once). Without an unconsumed
// record, escalation fields are ignored — this is the hard "no escalation
// before a denial" constraint that stops preemptive approval prompts.
//
// The extension runs as ONE process, so a plain package-level map is the
// process-wide singleton (the reference needed globalThis because of per-
// session module instances; not applicable here).

package ledger

import "sync"

// Kind mirrors the reference's DenialKind (bash-only build: always "command").
type Kind string

const (
	KindCommand   Kind = "command"
	KindOperation Kind = "operation"
)

var (
	mu      sync.Mutex
	pending = map[string]map[Kind]bool{}
)

// Record stores a denial (idempotent per session+kind).
func Record(sessionID string, kind Kind) {
	if sessionID == "" {
		return
	}
	mu.Lock()
	defer mu.Unlock()
	m := pending[sessionID]
	if m == nil {
		m = map[Kind]bool{}
		pending[sessionID] = m
	}
	m[kind] = true
}

// Consume spends one record; false when none exists. One-shot.
func Consume(sessionID string, kind Kind) bool {
	if sessionID == "" {
		return false
	}
	mu.Lock()
	defer mu.Unlock()
	m := pending[sessionID]
	if !m[kind] {
		return false
	}
	delete(m, kind)
	if len(m) == 0 {
		delete(pending, sessionID)
	}
	return true
}

// Forget drops a session's records (session shutdown / child disposal).
func Forget(sessionID string) {
	mu.Lock()
	defer mu.Unlock()
	delete(pending, sessionID)
}

// Package dbg is the extension's agent-facing debug trace: one JSON line per
// bash call (refusal, spawn, terminal state), appended next to the task logs
// inside the granted %TEMP% tree so an agent can read it while diagnosing an
// installed session — no source checkout, no slash command required.
package dbg

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

var mu sync.Mutex

// Path is the trace file location (%TEMP%\pi-bg-tasks\bash-calls.jsonl).
func Path() string { return filepath.Join(os.TempDir(), "pi-bg-tasks", "bash-calls.jsonl") }

// Trace appends one record. Never fails the caller: debug output must not be
// able to break a bash call.
func Trace(rec map[string]any) {
	if rec == nil {
		return
	}
	if _, ok := rec["ts"]; !ok {
		rec["ts"] = time.Now().UTC().Format(time.RFC3339Nano)
	}
	b, err := json.Marshal(rec)
	if err != nil {
		return
	}
	mu.Lock()
	defer mu.Unlock()
	if err := os.MkdirAll(filepath.Dir(Path()), 0o755); err != nil {
		return
	}
	f, err := os.OpenFile(Path(), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return
	}
	defer f.Close()
	_, _ = f.Write(append(b, '\n'))
}

// Tail returns the last n records (oldest first); nil when absent.
func Tail(n int) []map[string]any {
	if n <= 0 {
		return nil
	}
	b, err := os.ReadFile(Path())
	if err != nil {
		return nil
	}
	lines := strings.Split(strings.TrimRight(string(b), "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	out := make([]map[string]any, 0, len(lines))
	for _, l := range lines {
		if strings.TrimSpace(l) == "" {
			continue
		}
		var m map[string]any
		if json.Unmarshal([]byte(l), &m) == nil {
			out = append(out, m)
		}
	}
	return out
}

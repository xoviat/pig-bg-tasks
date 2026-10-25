// Package bg is the Go port of pi-bg-tasks' core: job registry, fd-direct
// output handling, lifecycle (SIGTERM-grace-kill semantics via Job objects),
// exactly-once completion notifications, and the UI surface (hint widget,
// status pill, list formatting).
//
// The registry is purely in-memory and process-global (one extension process
// = one registry, the Go equivalent of the reference's per-activate instance).
package bg

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"example.com/pig-bg-tasks/internal/proc"
	sdk "github.com/MichaelKinsy/PiG/extensions/sdk"
)

// Constants — parity with the reference's types.ts.
const (
	DefaultTimeoutMs    = 120_000
	QuickCompletionMs   = 2_000
	OutputPreviewChars  = 12_000
	TaskOutputTailChars = 32 * 1024
	NotifyTailChars     = 1_000
	MaxLogBytes         = 64 * 1024 * 1024
	OutputWatchInterval = 2 * time.Second
	KillGrace           = 5 * time.Second
	RecentTerminalKeep  = 20
	MaxConcurrentJobs   = 16
	StaleLogMaxAge      = 24 * time.Hour
	ForegroundTailBytes = 4_096
)

// JobStatus mirrors the reference (timed_out reserved, no producer in v1).
type JobStatus string

const (
	StatusRunning   JobStatus = "running"
	StatusCompleted JobStatus = "completed"
	StatusFailed    JobStatus = "failed"
	StatusKilled    JobStatus = "killed"
	StatusTimedOut  JobStatus = "timed_out"
)

// Terminal reports whether the status is final.
func (s JobStatus) Terminal() bool { return s != StatusRunning }

// BackgroundReason names why a foreground command moved to the background.
type BackgroundReason string

const (
	ReasonManual  BackgroundReason = "manual"
	ReasonTimeout BackgroundReason = "timeout"
	ReasonSteer   BackgroundReason = "steer"
)

// Job is one tracked command.
type Job struct {
	ID             string
	Name           string
	Command        string // display form (already human-readable)
	PID            int
	StartTime      time.Time
	Status         JobStatus
	ExitCode       *int
	LogPath        string
	ToolCallID     string
	Handle         *proc.Handle
	Notified       bool
	IsBackgrounded bool
	StopReason     string
	DoneCh         chan struct{} // closed once terminal
}

// ForegroundSlot lets Ctrl+Shift+B / the timeout timer / steering flip a
// running foreground command into the background.
type ForegroundSlot struct {
	RequestPause func(reason BackgroundReason)
}

// Registry is the single source of truth.
type Registry struct {
	mu             sync.Mutex
	Jobs           map[string]*Job
	Foreground     map[string]*ForegroundSlot
	RecentTerminal []*Job
	CompletedCount int
	FailedCount    int
	KilledCount    int
	TotalStarted   int
	NonInteractive bool
	Notifier       sdk.Context // retained context for out-of-band sends (SDK D19)
}

var (
	regOnce sync.Once
	reg     *Registry
)

// Default returns the process registry.
func Default() *Registry {
	regOnce.Do(func() {
		reg = &Registry{
			Jobs:       map[string]*Job{},
			Foreground: map[string]*ForegroundSlot{},
		}
	})
	return reg
}

// SetNotifier retains a context usable after its handler returns (SDK D19:
// retained contexts keep their connection generation). Called at session_start
// and on every tool call so the newest session drives notifications.
func (r *Registry) SetNotifier(ctx sdk.Context) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.Notifier = ctx
}

func (r *Registry) notifier() (sdk.Context, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.Notifier, r.Notifier != (sdk.Context{})
}

// IsNonInteractive reports whether there is no UI to background FOR
// (print/RPC/headless — set from session_start's HasUI).
func (r *Registry) IsNonInteractive() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.NonInteractive
}

// ForegroundPresent reports whether a slot is registered for the call id.
func (r *Registry) ForegroundPresent(toolCallID string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	_, ok := r.Foreground[toolCallID]
	return ok
}

// SetNonInteractive records whether there is a UI to background FOR.
func (r *Registry) SetNonInteractive(v bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.NonInteractive = v
}

func (r *Registry) nonInteractive() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.NonInteractive
}

// LogDir is %TEMP%\pi-bg-tasks on Windows (inside the sandbox grant, so a
// confined child can write its own log — plan Part 3.4).
func LogDir() string { return filepath.Join(os.TempDir(), "pi-bg-tasks") }

// LogPathFor maps a task id to its log file.
func LogPathFor(id string) string { return filepath.Join(LogDir(), id+".log") }

// NewJobID mints "bash-" + 8 uniform base36 chars (crypto/rand — unguessable
// and collision-checked against the live registry).
func (r *Registry) NewJobID() string {
	const alphabet = "0123456789abcdefghijklmnopqrstuvwxyz"
	for {
		var b [8]byte
		if _, err := rand.Read(b[:]); err != nil {
			// crypto failure: fall back to time+pid (still unique in-process)
			return fmt.Sprintf("bash-%08x", binary.LittleEndian.Uint32(b[:4])^uint32(time.Now().UnixNano()))
		}
		id := "bash-"
		for i := range b {
			id += string(alphabet[int(b[i])%len(alphabet)])
		}
		r.mu.Lock()
		_, clash := r.Jobs[id]
		r.mu.Unlock()
		if !clash {
			return id
		}
	}
}

// NewRunningJob builds and registers a fresh running job.
func (r *Registry) NewRunningJob(id, command string, h *proc.Handle, logPath, toolCallID, name string, backgrounded bool) *Job {
	j := &Job{
		ID:             id,
		Name:           name,
		Command:        command,
		PID:            h.PID(),
		StartTime:      time.Now(),
		Status:         StatusRunning,
		LogPath:        logPath,
		ToolCallID:     toolCallID,
		Handle:         h,
		IsBackgrounded: backgrounded,
		DoneCh:         make(chan struct{}),
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.Jobs[id] = j
	return j
}

// AtConcurrencyLimit reports the 16-running cap (short-circuits at the cap).
func (r *Registry) AtConcurrencyLimit() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for _, j := range r.Jobs {
		if j.Status == StatusRunning {
			n++
			if n >= MaxConcurrentJobs {
				return true
			}
		}
	}
	return false
}

// MarkStarted bumps the lifetime counter (promotion only — foreground jobs
// are not "started" until they move to the background).
func (r *Registry) MarkStarted() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.TotalStarted++
}

// FindJob looks in the live map, then the recent-terminal ring.
func (r *Registry) FindJob(id string) *Job {
	r.mu.Lock()
	defer r.mu.Unlock()
	if j, ok := r.Jobs[id]; ok {
		return j
	}
	for i := len(r.RecentTerminal) - 1; i >= 0; i-- {
		if r.RecentTerminal[i].ID == id {
			return r.RecentTerminal[i]
		}
	}
	return nil
}

// Forget evicts a terminal job from the live map into the ring and updates
// lifetime counters.
func (r *Registry) Forget(j *Job) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.Jobs[j.ID]; !ok {
		return
	}
	delete(r.Jobs, j.ID)
	switch j.Status {
	case StatusCompleted:
		r.CompletedCount++
	case StatusFailed:
		r.FailedCount++
	case StatusKilled, StatusTimedOut:
		r.KilledCount++
	}
	r.RecentTerminal = append(r.RecentTerminal, j)
	if len(r.RecentTerminal) > RecentTerminalKeep {
		r.RecentTerminal = r.RecentTerminal[1:]
	}
}

// SetForeground registers the in-flight foreground slot for Ctrl+Shift+B /
// timeout / steering (caller holds no lock — this method takes it).
func (r *Registry) SetForeground(toolCallID string, slot *ForegroundSlot) {
	r.mu.Lock()
	r.Foreground[toolCallID] = slot
	r.mu.Unlock()
}

// RemoveForeground drops the slot (idempotent).
func (r *Registry) RemoveForeground(toolCallID string) {
	r.mu.Lock()
	delete(r.Foreground, toolCallID)
	r.mu.Unlock()
}

// LatchTerminal marks a terminal job's outcome as already known (suppresses
// the completion notification) and runs the lazy eviction sweep. bg_output /
// bg_stop call this before returning the outcome.
func (r *Registry) LatchTerminal(j *Job) {
	if !j.Status.Terminal() {
		return
	}
	markNotified(r, j)
	r.SweepNotifiedTerminal()
}

// SweepNotifiedTerminal evicts terminal jobs whose outcome was already
// surfaced (lazy sweep run by bg_list).
func (r *Registry) SweepNotifiedTerminal() {
	r.mu.Lock()
	var evict []*Job
	for _, j := range r.Jobs {
		if j.Status.Terminal() && j.Notified {
			evict = append(evict, j)
		}
	}
	r.mu.Unlock()
	for _, j := range evict {
		r.Forget(j)
	}
}

// RunningJobs returns the current running set (snapshot order = map order;
// the formatter sorts by start time implicitly via insertion — keep it
// simple: return as-is like the reference's Map iteration).
func (r *Registry) Snapshot() (running, terminalInMap []*Job, recent []*Job) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, j := range r.Jobs {
		if j.Status.Terminal() {
			terminalInMap = append(terminalInMap, j)
		} else {
			running = append(running, j)
		}
	}
	recent = append([]*Job{}, r.RecentTerminal...)
	return
}

// Counters returns lifetime completed/failed/killed plus backgrounded-running.
func (r *Registry) Counters() (runningBG, done, failed int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, j := range r.Jobs {
		if !j.Status.Terminal() && j.IsBackgrounded {
			runningBG++
		}
	}
	return runningBG, r.CompletedCount, r.FailedCount + r.KilledCount
}

// SweepStaleLogs deletes logs older than 24h (session_start housekeeping).
func SweepStaleLogs(now time.Time) int {
	removed := 0
	entries, err := os.ReadDir(LogDir())
	if err != nil {
		return 0
	}
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".log" {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		if now.Sub(info.ModTime()) > StaleLogMaxAge {
			if os.Remove(filepath.Join(LogDir(), e.Name())) == nil {
				removed++
			}
		}
	}
	return removed
}

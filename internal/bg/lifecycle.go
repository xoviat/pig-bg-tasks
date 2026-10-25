package bg

import (
	"errors"
	"os"
	"strings"
	"time"

	"example.com/pig-bg-tasks/internal/dbg"
	"example.com/pig-bg-tasks/internal/proc"
)

// Lifecycle — parity with the reference's lifecycle.ts: the background
// orchestration entry (done promise, output-cap watcher, exit hand-off),
// terminal marking, the silent-kill path, and small helpers.

// AssertJobSlot enforces the concurrency cap.
func (r *Registry) AssertJobSlot() error {
	if r.AtConcurrencyLimit() {
		return errors.New("Max concurrent background jobs (16) reached. Stop or wait for existing jobs before starting new ones.")
	}
	return nil
}

// RequireExistingCwd fails fast with the reference's wording.
func RequireExistingCwd(cwd string) error {
	if _, err := os.Stat(cwd); err != nil {
		return errors.New("Working directory does not exist: " + cwd)
	}
	return nil
}

// IsBlankCommand rejects whitespace-only commands (bash would no-op).
func IsBlankCommand(command string) bool { return strings.TrimSpace(command) == "" }

// MarkTerminal flips a job to its final state once; resolves DoneCh.
func MarkTerminal(j *Job, status JobStatus, exitCode *int) {
	if j.Status.Terminal() {
		return
	}
	j.Status = status
	j.ExitCode = exitCode
	close(j.DoneCh)
}

// StatusFromExit maps a spawn's terminal record: our kill → killed,
// exit 0 → completed, else failed. (Windows has no signal half; Killed is
// set by the killer.)
func StatusFromExit(e proc.Exit) (JobStatus, *int) {
	code := e.Code
	switch {
	case e.Killed:
		return StatusKilled, &code
	case e.Err != nil && code < 0:
		return StatusFailed, &code
	case code == 0:
		return StatusCompleted, &code
	default:
		return StatusFailed, &code
	}
}

// StartBackgroundJob wires the completion watcher + output-cap watcher for a
// job already in the registry. Single entry point: run_in_background and
// promotion both funnel through here.
func (r *Registry) StartBackgroundJob(j *Job, shouldNotify bool) {
	r.startCapWatcher(j)
	go func() {
		e := <-j.Handle.Done()
		r.completeJob(j, e, shouldNotify)
	}()
	r.RenderStatusPill()
}

func (r *Registry) completeJob(j *Job, e proc.Exit, shouldNotify bool) {
	if j.Status.Terminal() {
		return
	}
	status, code := StatusFromExit(e)
	MarkTerminal(j, status, code)
	dbg.Trace(map[string]any{"phase": "bg_exit", "id": j.ID, "status": string(status), "code": e.Code, "killed": e.Killed, "notify": shouldNotify})
	if shouldNotify {
		SendTaskNotification(r, j)
	} else {
		markNotified(r, j)
		r.Forget(j)
	}
	r.RenderStatusPill()
}

// FinishForegroundJob closes out a foreground call whose process has exited:
// terminal status + eviction into the recent ring, with NO task-notification
// (the result is returned as the tool response instead). Without this, every
// foreground call stayed "running" forever and burned a concurrency slot.
// Guarded against a racing terminal mark (session shutdown, kill path).
func (r *Registry) FinishForegroundJob(j *Job, e proc.Exit) {
	if j.Status.Terminal() {
		return
	}
	status, code := StatusFromExit(e)
	MarkTerminal(j, status, code)
	markNotified(r, j)
	r.Forget(j)
	rec := map[string]any{"phase": "fg_terminal", "id": j.ID, "status": string(status),
		"code": e.Code, "killed": e.Killed, "age_ms": time.Since(j.StartTime).Milliseconds()}
	if e.Err != nil {
		rec["err"] = e.Err.Error()
	}
	dbg.Trace(rec)
	r.RenderStatusPill()
}

// PromoteToBackground flips a running foreground command into a tracked
// background job (Ctrl+Shift+B / timeout / steering).
func (r *Registry) PromoteToBackground(toolCallID string, j *Job, shouldNotify bool) {
	r.mu.Lock()
	delete(r.Foreground, toolCallID)
	r.mu.Unlock()
	j.IsBackgrounded = true
	r.MarkStarted()
	r.StartBackgroundJob(j, shouldNotify)
}

// TerminateJob records the stop reason and kills the tree (Job object on
// Windows — the whole tree, immediate; there is no SIGTERM on Windows).
func TerminateJob(j *Job, reason string) {
	if j.StopReason == "" && reason != "" {
		j.StopReason = reason
	}
	if j.Handle != nil {
		j.Handle.Kill()
	}
}

// TerminateJobSilently latches the outcome BEFORE the kill so the exit
// handler's notification is suppressed, flips status immediately, and evicts
// once the process actually dies (bg_stop, session_shutdown).
func (r *Registry) TerminateJobSilently(j *Job, reason string) <-chan struct{} {
	markNotified(r, j)
	TerminateJob(j, reason)
	MarkTerminal(j, StatusKilled, nil)
	gone := make(chan struct{})
	r.Forget(j)
	go func() {
		if j.Handle != nil {
			select {
			case <-j.Handle.Done():
			case <-time.After(KillGrace + time.Second):
			}
		}
		close(gone)
		r.RenderStatusPill()
	}()
	return gone
}

func markNotified(r *Registry, j *Job) {
	r.mu.Lock()
	j.Notified = true
	r.mu.Unlock()
}

// startCapWatcher polls the log size; past MaxLogBytes it appends a marker
// and kills the task so it cannot fill the disk.
func (r *Registry) startCapWatcher(j *Job) {
	tripped := false
	go func() {
		ticker := time.NewTicker(OutputWatchInterval)
		defer ticker.Stop()
		for {
			select {
			case <-j.DoneCh:
				return
			case <-ticker.C:
				if tripped {
					return
				}
				fi, err := os.Stat(j.LogPath)
				if err != nil {
					continue // log not created yet
				}
				if fi.Size() <= MaxLogBytes {
					continue
				}
				tripped = true
				f, err := os.OpenFile(j.LogPath, os.O_APPEND|os.O_WRONLY, 0o644)
				if err == nil {
					_, _ = f.WriteString("\n[bg-tasks] output exceeded the 64 MiB limit — task killed\n")
					f.Close()
				}
				j.StopReason = "output_limit"
				if j.Handle != nil {
					j.Handle.Kill()
				}
				return
			}
		}
	}()
}

// RenderStatusPill refreshes the status-bar counts
// (`▶ 2 · ✓ 3 · ✗ 1`); clears the key when everything is idle.
func (r *Registry) RenderStatusPill() {
	running, done, failed := r.Counters()
	ctx, ok := r.notifier()
	if !ok {
		return
	}
	if running == 0 && done == 0 && failed == 0 {
		ctx.SetStatus("bg-tasks", "")
		return
	}
	var parts []string
	if running > 0 {
		parts = append(parts, "▶ "+itoa(int64(running)))
	}
	if done > 0 {
		parts = append(parts, "✓ "+itoa(int64(done)))
	}
	if failed > 0 {
		parts = append(parts, "✗ "+itoa(int64(failed)))
	}
	ctx.SetStatus("bg-tasks", strings.Join(parts, " · "))
}

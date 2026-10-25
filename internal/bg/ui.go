package bg

import (
	"strconv"
	"strings"
	"sync"
	"time"
)

// UI surface — parity with the reference's ui.ts: the below-editor hint
// widget (ref-counted: parallel foreground commands share one key), the
// status pill (lifecycle.RenderStatusPill), list formatting, and the
// background-active-foreground mechanic behind Ctrl+Shift+B and /bg.

const hintKey = "bg-hint"

var (
	hintMu     sync.Mutex
	activeHint int
)

// ShowBackgroundHint displays "(ctrl+shift+b to run in background)" below the
// editor on the 0→1 transition; ctx must be live (called during a tool run).
func ShowBackgroundHint(ctx widgetCtx) {
	hintMu.Lock()
	activeHint++
	n := activeHint
	hintMu.Unlock()
	if n == 1 && ctx != nil {
		_ = ctx.SetWidget(hintKey, []string{"(ctrl+shift+b to run in background)"},
			map[string]any{"placement": "belowEditor"})
	}
}

// ClearBackgroundHint releases one hint; clears on the last 1→0.
func ClearBackgroundHint(ctx widgetCtx) {
	hintMu.Lock()
	if activeHint == 0 {
		hintMu.Unlock()
		return
	}
	activeHint--
	n := activeHint
	hintMu.Unlock()
	if n == 0 && ctx != nil {
		_ = ctx.SetWidget(hintKey, nil)
	}
}

// widgetCtx is the slice of sdk.Context the hint needs (narrow for tests).
type widgetCtx interface {
	SetWidget(key string, content any, options ...map[string]any) error
}

// BackgroundActiveForeground pauses every running foreground command. The
// bash tool's result already tells the model what happened; we only toast.
// Returns false when there was nothing to pause.
func BackgroundActiveForeground(notify func(msg, level string)) bool {
	reg := Default()
	reg.mu.Lock()
	slots := make([]*ForegroundSlot, 0, len(reg.Foreground))
	for _, s := range reg.Foreground {
		slots = append(slots, s)
	}
	reg.Foreground = map[string]*ForegroundSlot{}
	reg.mu.Unlock()
	if len(slots) == 0 {
		if notify != nil {
			notify("No running foreground process to background.", "warning")
		}
		return false
	}
	for _, s := range slots {
		if s.RequestPause != nil {
			s.RequestPause(ReasonManual)
		}
	}
	if notify != nil {
		notify("▶ Backgrounded — continuing.", "info")
	}
	return true
}

// PauseAllForeground(reason) is the steering hook's bulk pause (does not
// toast — the user just typed a message).
func PauseAllForeground(reason BackgroundReason) bool {
	reg := Default()
	reg.mu.Lock()
	slots := make([]*ForegroundSlot, 0, len(reg.Foreground))
	for _, s := range reg.Foreground {
		slots = append(slots, s)
	}
	reg.Foreground = map[string]*ForegroundSlot{}
	reg.mu.Unlock()
	for _, s := range slots {
		if s.RequestPause != nil {
			s.RequestPause(reason)
		}
	}
	return len(slots) > 0
}

// formatDuration renders "45s" / "3m20s".
func formatDuration(ms int64) string {
	total := ms / 1000
	m := total / 60
	s := total % 60
	if m > 0 {
		return strconv.FormatInt(m, 10) + "m" + strconv.FormatInt(s, 10) + "s"
	}
	return strconv.FormatInt(s, 10) + "s"
}

// FormatJobLine: "bash-ab12cd34 [▶ 1m23s] cmd… (last line)" per job.
func FormatJobLine(j *Job) string {
	head := j.ID
	if j.Name != "" {
		head = j.Name + " (" + j.ID + ")"
	}
	cmd := OneLine(j.Command)
	if r := []rune(cmd); len(r) > 60 {
		cmd = string(r[:60])
	}
	if j.Status == StatusRunning {
		dur := formatDuration(time.Since(j.StartTime).Milliseconds())
		progress := ReadLastLine(j.LogPath, 2048)
		suffix := ""
		if progress != "" {
			if r := []rune(progress); len(r) > 60 {
				progress = string(r[:60])
			}
			suffix = ": " + progress
		}
		bg := "fg"
		if j.IsBackgrounded {
			bg = "bg"
		}
		return head + " ▶ " + bg + " (" + dur + ") " + cmd + suffix
	}
	glyph := "✗"
	if j.Status == StatusCompleted {
		glyph = "✓"
	}
	exit := ""
	if j.ExitCode != nil {
		exit = " exit=" + strconv.Itoa(*j.ExitCode)
	}
	return head + " " + glyph + " " + string(j.Status) + exit + " " + cmd
}

// FormatJobList renders the bg_list //bg-tasks text: running first, then
// recent terminal (last 10, newest first).
func FormatJobList(r *Registry) string {
	running, terminalInMap, recent := r.Snapshot()
	// stable-ish order: start time descending for running
	for i := 0; i < len(running); i++ {
		for k := i + 1; k < len(running); k++ {
			if running[k].StartTime.After(running[i].StartTime) {
				running[i], running[k] = running[k], running[i]
			}
		}
	}
	var tail []*Job
	tail = append(tail, terminalInMap...)
	tail = append(tail, recent...)
	if len(tail) > 10 {
		tail = tail[len(tail)-10:]
	}
	// newest first
	for i, j := 0, len(tail)-1; i < j; i, j = i+1, j-1 {
		tail[i], tail[j] = tail[j], tail[i]
	}
	if len(running) == 0 && len(tail) == 0 {
		return "No background jobs"
	}
	var lines []string
	if len(running) > 0 {
		lines = append(lines, "Running ("+strconv.Itoa(len(running))+"):")
		for _, j := range running {
			lines = append(lines, "  "+FormatJobLine(j))
		}
	}
	if len(tail) > 0 {
		lines = append(lines, "Recent:")
		for _, j := range tail {
			lines = append(lines, "  "+FormatJobLine(j))
		}
	}
	return strings.Join(lines, "\n")
}

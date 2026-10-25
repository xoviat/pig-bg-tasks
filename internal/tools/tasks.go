package tools

import (
	"fmt"
	"strings"
	"time"

	"example.com/pig-bg-tasks/internal/bg"
	sdk "github.com/MichaelKinsy/PiG/extensions/sdk"
)

// The three task-management tools — parity with pi-bg-tasks' tools-tasks.ts.

func metaLines(j *bg.Job) []string {
	lines := []string{
		"Task: " + j.ID,
		fmt.Sprintf("Status: %s", j.Status),
		"Command: " + j.Command,
		"Log: " + j.LogPath,
	}
	if j.ExitCode != nil {
		lines[1] = fmt.Sprintf("Status: %s (exit code %d)", j.Status, *j.ExitCode)
	}
	if j.StopReason != "" {
		lines = append(lines, "Stop reason: "+j.StopReason)
	}
	return lines
}

// BgListDefinition lists running tasks first, then recent finished ones.
func BgListDefinition() sdk.ToolDefinition {
	return sdk.ToolDefinition{
		Name:          "bg_list",
		Label:         "Background Task List",
		Description:   "List background tasks: running tasks first, then recently finished ones. Returns task IDs for use with bg_output and bg_stop.",
		PromptSnippet: "List background tasks and their status",
		Parameters:    sdk.Schema{"type": "object", "properties": map[string]any{}},
		Execute: func(ctx sdk.Context, params map[string]any) (any, error) {
			reg := bg.Default()
			reg.SetNotifier(ctx)
			reg.SweepNotifiedTerminal()
			reg.RenderStatusPill()
			return bg.FormatJobList(reg), nil
		},
	}
}

// BgOutputDefinition reads a task's meta + bounded log tail (non-blocking).
func BgOutputDefinition() sdk.ToolDefinition {
	return sdk.ToolDefinition{
		Name:          "bg_output",
		Label:         "Background Task Output",
		Description:   "Read a background task's output. Non-blocking: returns the task's meta info, a tail preview of its log, and the log path. Use the Read tool to page through the full log file for more.",
		PromptSnippet: "Read a background task's output tail",
		Parameters: sdk.Schema{
			"type": "object",
			"properties": map[string]any{
				"task_id": map[string]any{"type": "string", "description": "Task ID (from bash run_in_background or bg_list)"},
			},
		},
		Execute: func(ctx sdk.Context, params map[string]any) (any, error) {
			taskID, _ := params["task_id"].(string)
			reg := bg.Default()
			reg.SetNotifier(ctx)
			j := reg.FindJob(taskID)
			if j == nil {
				return nil, fmt.Errorf("Unknown task: %s. Use bg_list to see running and recent tasks.", taskID)
			}
			reg.LatchTerminal(j)
			reg.RenderStatusPill()
			tail := bg.StripAnsi(bg.ReadBoundedTail(j.LogPath, bg.TaskOutputTailChars))
			var b strings.Builder
			for _, l := range metaLines(j) {
				b.WriteString(l + "\n")
			}
			b.WriteString("\n--- output tail (last 32 KiB) ---\n")
			b.WriteString(tail)
			b.WriteString("\n\nFull log: " + j.LogPath + " (use the Read tool with offset/limit to page through it)")
			return b.String(), nil
		},
	}
}

// BgStopDefinition stops a task: job-object terminate (Windows — no SIGTERM
// exists), bounded wait for the real death, final status returned.
func BgStopDefinition() sdk.ToolDefinition {
	return sdk.ToolDefinition{
		Name:          "bg_stop",
		Label:         "Background Task Stop",
		Description:   "Stop a running background task: Job-object terminate on Windows (kills the whole tree). Returns the final status.",
		PromptSnippet: "Stop a running background task",
		Parameters: sdk.Schema{
			"type": "object",
			"properties": map[string]any{
				"task_id": map[string]any{"type": "string", "description": "Task ID (from bash run_in_background or bg_list)"},
				"reason":  map[string]any{"type": "string", "description": "Why the task is being stopped"},
			},
		},
		Execute: func(ctx sdk.Context, params map[string]any) (any, error) {
			taskID, _ := params["task_id"].(string)
			reason, _ := params["reason"].(string)
			reg := bg.Default()
			reg.SetNotifier(ctx)
			j := reg.FindJob(taskID)
			if j == nil {
				return nil, fmt.Errorf("Unknown task: %s. Use bg_list to see running and recent tasks.", taskID)
			}
			var b strings.Builder
			writeMeta := func() {
				for _, l := range metaLines(j) {
					b.WriteString(l + "\n")
				}
			}
			if j.Status.Terminal() {
				reg.LatchTerminal(j)
				reg.RenderStatusPill()
				writeMeta()
				b.WriteString("\nTask " + j.ID + " already " + string(j.Status) + ".")
				return b.String(), nil
			}
			// Latch BEFORE the kill so the exit handler's notification is
			// suppressed: a deliberate stop is cleanup the agent knows about.
			gone := reg.TerminateJobSilently(j, reason)
			// Bounded wait for the actual death so we return the real outcome.
			select {
			case <-gone:
			case <-time.After(bg.KillGrace + time.Second):
			}
			reg.RenderStatusPill()
			writeMeta()
			b.WriteString("\nTask " + j.ID + " stopped (Job-object terminate — whole tree).")
			return b.String(), nil
		},
	}
}

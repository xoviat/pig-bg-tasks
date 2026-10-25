package bg

import (
	"strings"

	sdk "github.com/MichaelKinsy/PiG/extensions/sdk"
)

// Task-completion notifications — parity with the reference's notify.ts.
//
// Exactly-once is a check-and-set latch done BEFORE the send: any path that
// already surfaced the outcome (bg_output/bg_stop read, deliberate kill)
// suppresses the notification. A send failure loses the notification rather
// than retrying (exactly-once); the job lingers until bg_list's lazy sweep.

// TaskNotificationCustomType identifies the steered message for renderers.
const TaskNotificationCustomType = "bg-task-notification"

// EscapeXML escapes element text.
func EscapeXML(s string) string {
	r := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;")
	return r.Replace(s)
}

// OneLine collapses whitespace runs to single spaces.
func OneLine(s string) string { return strings.Join(strings.Fields(s), " ") }

// DescribeJob is the human/agent label: the name when set, else the command
// collapsed to one line and truncated at 80 runes.
func DescribeJob(j *Job) string {
	if j.Name != "" {
		return j.Name
	}
	line := OneLine(j.Command)
	r := []rune(line)
	if len(r) > 80 {
		return string(r[:80]) + "…"
	}
	return line
}

// CompletionSummary is the one-sentence outcome for a terminal job.
func CompletionSummary(j *Job) string {
	desc := DescribeJob(j)
	switch {
	case j.StopReason == "output_limit":
		return `Background command "` + desc + `" was stopped: output exceeded the size limit`
	case j.Status == StatusKilled || j.Status == StatusTimedOut:
		return `Background command "` + desc + `" was stopped`
	case j.Status == StatusFailed:
		code := "unknown"
		if j.ExitCode != nil {
			code = itoa(int64(*j.ExitCode))
		}
		return `Background command "` + desc + `" failed with exit code ` + code
	default:
		if j.ExitCode != nil && *j.ExitCode != 0 {
			return `Background command "` + desc + `" completed (exit code ` + itoa(int64(*j.ExitCode)) + `)`
		}
		return `Background command "` + desc + `" completed`
	}
}

// BuildTaskNotification renders the <task-notification> XML block.
func BuildTaskNotification(j *Job, summary string) string {
	tail := strings.TrimSpace(StripAnsi(ReadBoundedTail(j.LogPath, NotifyTailChars)))
	var b strings.Builder
	b.WriteString("<task-notification>\n")
	b.WriteString("<task_id>" + EscapeXML(j.ID) + "</task_id>\n")
	b.WriteString("<status>" + EscapeXML(string(j.Status)) + "</status>\n")
	b.WriteString("<command>" + EscapeXML(OneLine(j.Command)) + "</command>\n")
	if j.ExitCode != nil {
		b.WriteString("<exit_code>" + itoa(int64(*j.ExitCode)) + "</exit_code>\n")
	}
	b.WriteString("<output_file>" + EscapeXML(j.LogPath) + "</output_file>\n")
	b.WriteString("<summary>" + EscapeXML(summary) + "</summary>\n")
	if tail != "" && tail != "(no output yet)" {
		b.WriteString("<tail_preview>" + EscapeXML(tail) + "</tail_preview>\n")
	}
	b.WriteString("</task-notification>")
	return b.String()
}

// SendTaskNotification latches then steers the notification into the agent
// loop (deliverAs=steer, triggerTurn=true). Returns whether it was sent.
func SendTaskNotification(r *Registry, j *Job) bool {
	r.mu.Lock()
	if j.Notified {
		r.mu.Unlock()
		return false
	}
	j.Notified = true
	r.mu.Unlock()

	ctx, ok := r.notifier()
	if !ok {
		// No retained context (session never started): lose the notification
		// (exactly-once, never retried) but still evict.
		r.Forget(j)
		return false
	}
	summary := CompletionSummary(j)
	err := ctx.SendCustomMessage(sdk.CustomMessage{
		CustomType: TaskNotificationCustomType,
		Content:    BuildTaskNotification(j, summary),
		Display:    true,
		Details: map[string]any{
			"jobId":      j.ID,
			"status":     string(j.Status),
			"summary":    summary,
			"outputFile": j.LogPath,
		},
	}, sdk.SendMessageOptions{TriggerTurn: sdk.Bool(true), DeliverAs: "steer"})
	if err != nil {
		// lost rather than retried (parity)
		return false
	}
	r.Forget(j)
	return true
}

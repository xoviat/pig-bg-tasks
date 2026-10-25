package tools

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"example.com/pig-bg-tasks/internal/bg"
	"example.com/pig-bg-tasks/internal/classify"
	"example.com/pig-bg-tasks/internal/config"
	"example.com/pig-bg-tasks/internal/converge"
	"example.com/pig-bg-tasks/internal/dbg"
	"example.com/pig-bg-tasks/internal/escalation"
	"example.com/pig-bg-tasks/internal/ledger"
	"example.com/pig-bg-tasks/internal/policy"
	"example.com/pig-bg-tasks/internal/proc"
	"example.com/pig-bg-tasks/internal/runner"
	sdk "github.com/MichaelKinsy/PiG/extensions/sdk"
)

// The composed bash tool: bg semantics (run_in_background, quick window,
// auto-background, steering, notifications) x sandbox semantics (modes,
// escalation, confinement, denial classification). One definition, one
// execute path — every spawn is confined exactly like every other (plan
// Part 1/3 composition).

const noWaitHint = "next_step: You will be automatically notified when it completes — do NOT wait, poll, or call bg_output to wait on it; continue with your current work."

const sandboxNote = "Sandbox: confined to the current mode; workspace-write already allows the workspace and %TEMP%. Unless retrying a denial, omit these fields or send JSON null."

const envRedirectGuideline = "Never work around the sandbox by relocating global cache/data directories into the workspace — no environment-variable overrides (XDG_CACHE_HOME, XDG_DATA_HOME, HOME, UV_CACHE_DIR, PIP_CACHE_DIR, npm_config_cache, PNPM_HOME, YARN_CACHE_FOLDER, CARGO_HOME, GOPATH, ...), no cache-relocating tool flags (--cache-dir, --store-dir, --cache), and no config files that do the same — unless the user explicitly asked for exactly that relocation. Run tools unmodified — including on the escalated retry: when their real global write is denied, retry that same call with escalation rather than adding a relocation."

const escalationGuideline = "When a sandbox denial marker appears, you may retry the exact same call once with sandbox_permissions (the narrowest wider mode that suffices) plus justification; the user is asked to approve and may attach a reason when denying. Never send escalation fields before a denial — such requests are ignored and the call runs confined. If denied or unavailable, stop and explain instead of working around it."

const bgGuideline1 = "Use bash with run_in_background=true when a command is expected to run for a long time (dev servers, watchers, long builds)."
const bgGuideline2 = "After starting a background command, do NOT wait on it or poll its output — you will be automatically notified when it completes; continue with other work or return control to the user."
const bgGuideline3 = "Never block the turn with a bare `sleep N` or a long foreground polling loop. If a readiness gate is truly unavoidable (e.g. wait for a server to print READY before running tests), use a bounded foreground poll with a short timeout (e.g. `timeout 30 bash -c 'until grep -q READY log; do sleep 0.5; done'`) — it auto-backgrounds at the timeout and you will be notified."
const bgGuideline4 = "Check background task status with bg_list; read a task's output with bg_output (a non-blocking snapshot); stop one with bg_stop."

// BashDefinition builds the single composed bash tool.
func BashDefinition() sdk.ToolDefinition {
	logDir := filepath.Join(os.TempDir(), "pi-bg-tasks")
	return sdk.ToolDefinition{
		Name:  "bash",
		Label: "Bash (sandboxed)",
		Description: "Run a bash command. Long-running commands auto-background after the timeout. " +
			"Set run_in_background=true to start in the background immediately. " +
			"Use Ctrl+Shift+B or /bg to manually background a running command.\n\n" + sandboxNote,
		PromptSnippet: "Run shell commands; long-running commands auto-background, or use run_in_background=true",
		PromptGuidelines: []string{
			bgGuideline1, bgGuideline2, bgGuideline3, bgGuideline4,
			envRedirectGuideline, escalationGuideline,
		},
		Parameters: sdk.Schema{
			"type": "object",
			"properties": map[string]any{
				"command": map[string]any{"type": "string", "description": "Shell command to run"},
				"timeout": map[string]any{"type": "number", "description": "Timeout in seconds (default: 120). A foreground command past the timeout auto-backgrounds instead of dying."},
				"run_in_background": map[string]any{
					"type":        "boolean",
					"description": "Set to true to run this command in the background immediately. Output is saved to " + logDir + "/<taskId>.log.",
				},
				"description": map[string]any{"type": "string", "description": "Short description of what this command does"},
				"sandbox_permissions": map[string]any{
					"anyOf": []any{
						map[string]any{"const": "workspace-write"},
						map[string]any{"const": "danger-full-access"},
						map[string]any{"type": "null"},
					},
					"description": "Escalation: ONLY valid when retrying a command that just returned a sandbox denial. Narrowest wider mode that suffices; requires justification.",
				},
				"justification": map[string]any{
					"anyOf":       []any{map[string]any{"type": "string"}, map[string]any{"type": "null"}},
					"description": "One-sentence reason for the escalation; shown to the user in the approval prompt.",
				},
			},
		},
		PrepareArguments: StripEscalationPlaceholders,
		Execute:          BashExecute,
	}
}

// BashExecute is the composed execute path.
func BashExecute(ctx sdk.Context, params map[string]any) (any, error) {
	command, _ := params["command"].(string)
	if bg.IsBlankCommand(command) {
		return nil, errors.New("Command is empty.")
	}
	cwd := ctx.Cwd()
	if err := bg.RequireExistingCwd(cwd); err != nil {
		return nil, err
	}
	reg := bg.Default()
	reg.SetNotifier(ctx)
	if err := reg.AssertJobSlot(); err != nil {
		return nil, err
	}
	cfg := ConfigFor(ctx)

	rc, err := ResolveCall(ctx, params, cfg, command)
	if err != nil {
		return nil, err // fail-closed: nothing executed
	}

	runBg, _ := params["run_in_background"].(bool)
	desc, _ := params["description"].(string)
	timeoutMs := bg.DefaultTimeoutMs
	if v, ok := params["timeout"].(float64); ok && v > 0 {
		timeoutMs = int(v * 1000)
	}

	id := reg.NewJobID()
	logPath := bg.LogPathFor(id)
	setCallSession(ctx) // classification records denials against this session

	// Bind to the newest epoch and WAIT for that epoch's convergence — the
	// wait is part of the command's total duration (background-task
	// composition unchanged: the quick-window/auto-background timers start
	// after spawn). No stale-policy window; causal failure = fail-closed.
	state := converge.State{
		Mode:      rc.Mode,
		Workspace: policy.Canonical(cwd),
		Temp:      os.TempDir(),
		Extras:    cfg.ExtraWritableDirs,
	}
	fut := converge.Bind(state)
	if err := converge.Wait(fut); err != nil {
		dbg.Trace(map[string]any{"phase": "converge_failed", "id": id, "mode": string(rc.Mode), "err": err.Error()})
		return nil, fmt.Errorf("SANDBOX_UNAVAILABLE (%s): sandbox convergence failed before the command ran: %v — the command was NOT executed (fail-closed; the error carries the real cause)", rc.Mode, err)
	}

	spec, err := buildSpec(rc.Mode, cwd, command, logPath)
	if err != nil {
		dbg.Trace(map[string]any{"phase": "refused", "id": id, "mode": string(rc.Mode), "cwd": cwd, "err": err.Error()})
		return nil, err // fail-closed: confined construction failure refuses
	}
	dbg.Trace(map[string]any{"phase": "start", "id": id, "mode": string(rc.Mode),
		"confined": policy.IsConfined(rc.Mode), "token": spec.Sandbox != nil,
		"epoch": converge.Snapshot().Epoch, "sandboxSID": converge.SandboxSID(),
		"shell": spec.Argv[0], "bg": runBg, "cwd": cwd, "log": logPath})

	notes := escalationNotes(rc)

	if runBg {
		h, err := proc.Start(spec)
		if err != nil {
			dbg.Trace(map[string]any{"phase": "start_error", "id": id, "bg": true, "err": err.Error()})
			return nil, fmt.Errorf("failed to start background command: %w", err)
		}
		job := reg.NewRunningJob(id, command, h, logPath, ctx.ToolCallID(), desc, true)
		reg.StartBackgroundJob(job, true)
		text := fmt.Sprintf("Command running in background with ID: %s. Output is being written to: %s\n%s", id, logPath, noWaitHint)
		return withNotes(text, notes), nil
	}
	return runForeground(ctx, reg, spec, rc, id, command, logPath, timeoutMs, cfg)
}

func withNotes(text, notes string) string {
	if notes == "" {
		return text
	}
	return text + "\n" + notes
}

// buildSpec assembles the spawn: resolved shell, log path, and — for
// confined modes — the CONVERGED srtwin sandbox snapshot. It performs no
// ACL work and never blocks (convergence already happened; this only reads
// shared state). Every failure REFUSES the command (fail-closed, never a
// bare spawn).
func buildSpec(mode policy.Mode, cwd, command, logPath string) (proc.Spec, error) {
	shell, err := runner.ResolveShell()
	if err != nil {
		if policy.IsConfined(mode) {
			return proc.Spec{}, &runner.ErrUnavailable{Detail: "bash shell could not be resolved (PATH, then standard Git for Windows locations)"}
		}
		return proc.Spec{}, err
	}
	spec := proc.Spec{Argv: []string{shell, "-c", command}, Cwd: cwd, LogPath: logPath}
	if !policy.IsConfined(mode) {
		return spec, nil // danger-full-access: bare (explicit escape hatch)
	}
	sel := runner.Select(0)
	if sel.Kind == runner.KindUnavailable {
		return proc.Spec{}, &runner.ErrUnavailable{}
	}
	sb := converge.Sandbox()
	if sb == nil {
		return proc.Spec{}, fmt.Errorf("SANDBOX_UNAVAILABLE (%s): no converged sandbox for this epoch — the command was NOT executed (fail-closed; see the convergence status for the cause)", mode)
	}
	spec.Sandbox = sb
	return spec, nil
}

// runForeground: 2s quick window → stream+hint → race completion against
// backgrounding (Ctrl+Shift+B / timeout / steering) → classified finish.
func runForeground(ctx sdk.Context, reg *bg.Registry, spec proc.Spec, rc ResolvedCall,
	id, command, logPath string, timeoutMs int, cfg config.Config) (any, error) {

	h, err := proc.Start(spec)
	if err != nil {
		dbg.Trace(map[string]any{"phase": "start_error", "id": id, "bg": false, "err": err.Error()})
		return nil, fmt.Errorf("failed to start command: %w", err)
	}
	job := reg.NewRunningJob(id, command, h, logPath, ctx.ToolCallID(), "", false)

	var (
		pauseReq atomic.Bool
		once     sync.Once
	)
	reasonCh := make(chan bg.BackgroundReason, 1)
	pause := func(r bg.BackgroundReason) {
		pauseReq.Store(true)
		once.Do(func() { reasonCh <- r })
	}
	slot := &bg.ForegroundSlot{RequestPause: pause}
	reg.SetForeground(ctx.ToolCallID(), slot)

	// Genuine cancel (Esc / turn abort) kills the tree — unless a pause was
	// requested, in which case the process must survive into the background.
	go func() {
		select {
		case <-ctx.Done():
			if !pauseReq.Load() {
				h.Kill()
			}
		case <-job.DoneCh:
		}
	}()

	// Auto-background timer (interactive sessions only — there is nobody to
	// background FOR in print/RPC mode, so the command simply runs out).
	if !reg.IsNonInteractive() {
		timer := time.AfterFunc(time.Duration(timeoutMs)*time.Millisecond, func() {
			if !pauseReq.Load() && reg.ForegroundPresent(ctx.ToolCallID()) {
				pause(bg.ReasonTimeout)
			}
		})
		defer timer.Stop()
	}

	finish := func(e proc.Exit) (any, error) {
		reg.FinishForegroundJob(job, e)
		return finishForeground(rc, e, logPath, cfg)
	}

	// Quick-completion window.
	if e := raceExit(h, bg.QuickCompletionMs); e != nil {
		return finish(*e)
	}

	// Still running: stream progress + show the background hint.
	bg.ShowBackgroundHint(ctx)
	streamer := bg.StartStream(logPath, time.Second, func(tail string) {
		_ = ctx.OnUpdate(map[string]any{
			"content": []map[string]any{{"type": "text", "text": tail}},
		})
	})
	defer func() {
		streamer.Stop()
		bg.ClearBackgroundHint(ctx)
		reg.RemoveForeground(ctx.ToolCallID())
	}()

	for {
		select {
		case e := <-h.Done():
			return finish(e)
		case reason := <-reasonCh:
			reg.PromoteToBackground(ctx.ToolCallID(), job, true)
			var head string
			switch reason {
			case bg.ReasonManual:
				head = fmt.Sprintf("Command was manually backgrounded by user with ID: %s.", id)
			case bg.ReasonSteer:
				head = fmt.Sprintf("Command was moved to the background with ID: %s because the user sent a message while it was running.", id)
			default:
				head = fmt.Sprintf("Command auto-backgrounded after %ds with ID: %s.", timeoutMs/1000, id)
			}
			text := fmt.Sprintf("%s Output is being written to: %s\n%s", head, logPath, noWaitHint)
			return withNotes(text, escalationNotes(rc)), nil
		}
	}
}

// raceExit waits for the exit channel with a bounded window; nil = still
// running.
func raceExit(h *proc.Handle, window time.Duration) *proc.Exit {
	select {
	case e := <-h.Done():
		return &e
	case <-time.After(window):
		return nil
	}
}

// finishForeground classifies and shapes the result (reference
// finishForeground + sandbox ops classification merged — our classification
// reads the merged stdout+stderr log tail instead of a piped stderr; the
// divergence is documented).
func finishForeground(rc ResolvedCall, e proc.Exit, logPath string, cfg config.Config) (any, error) {
	output := bg.ReadBoundedTail(logPath, bg.OutputPreviewChars)
	notes := escalationNotes(rc)

	if policy.IsConfined(rc.Mode) && !e.Killed && e.Code != 0 && e.Code != -1 {
		code := e.Code
		// Runner failure first: the command NEVER RAN (cygwin init fatal).
		if fatal, ok := classify.RunnerFailure(&code, output, classify.WindowsRules); ok {
			dbg.Trace(map[string]any{"phase": "runner_failure", "code": code, "fatal": fatal, "log": logPath})
			// No ACL work here (tool executes only read shared state): force a
			// fresh epoch instead — the next call's bind waits for it, and
			// srtwin re-creates the MSYS object directory at spawn.
			converge.Invalidate()
			return nil, fmt.Errorf("SANDBOX_UNAVAILABLE (%s): sandbox runner failed before the command ran: %s. The command was NOT executed — the sandbox re-converges on the next call; retry the same command.", rc.Mode, fatal)
		}
		// Real denial: record it (arms the denial-first gate) + annotate.
		if classify.Denial(&code, output, classify.DenialSignatures) {
			dbg.Trace(map[string]any{"phase": "denial", "code": code, "log": logPath})
			if sid := currentSessionID(); sid != "" {
				ledger.Record(sid, ledger.KindCommand)
			}
			output += "\n" + escalation.DenialMarker(rc.Mode) + "\n" + escalation.EscalationHintMarker()
		}
	}

	// Deliberate kill (Esc, or job teardown): never an error result.
	if e.Killed {
		return withNotes(outputOrNoOutput(output), notes), nil
	}
	if e.Code != 0 && e.Code != -1 {
		if output == "(no output yet)" || output == "" {
			return nil, fmt.Errorf("Command exited with code %d", e.Code)
		}
		return nil, errors.New(withNotes(output, notes))
	}
	if e.Code == -1 {
		return nil, errors.New("command failed to run")
	}
	return withNotes(outputOrNoOutput(output), notes), nil
}

func outputOrNoOutput(output string) string {
	if output == "" || output == "(no output yet)" {
		return "(no output)"
	}
	return output
}

// sessionID plumbing for classification-time ledger writes: the execute path
// resolved it already; store it per call. (ctx is not threaded into
// finishForeground, so a package-level slot is set by BashExecute.)
var (
	callSessionMu sync.Mutex
	callSessionID string
)

func currentSessionID() string {
	callSessionMu.Lock()
	defer callSessionMu.Unlock()
	return callSessionID
}

// setCallSession records the executing session for ledger writes.
func setCallSession(ctx sdk.Context) {
	id, err := ctx.GetSessionID()
	if err != nil {
		id = ""
	}
	callSessionMu.Lock()
	callSessionID = id
	callSessionMu.Unlock()
}

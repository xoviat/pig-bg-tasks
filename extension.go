// Package pi_sandbox is the combined PiG extension: ONE `bash` tool composed
// from two layers (PLAN.txt):
//
//   - bg layer     — scheduling, background registry, lifecycle, notifications,
//     keybindings (ported from pi-bg-tasks)
//   - sandbox layer— modes, config, platform runner (Windows: spike-validated
//     restricted-token recipe), escalation, denial classification
//     (ported from pi-sandbox)
//
// The bg layer owns WHEN/HOW commands are scheduled; the sandbox layer owns
// HOW they are confined. Every spawn path — foreground, quick-window, timeout
// promotion, run_in_background — goes through the same confined spec. The
// only unconfined path is the explicit danger-full-access mode.
//
// Linux (bwrap/landlock) and macOS (seatbelt) runners are DEFERRED: confined
// calls fail closed there with a message that names the deferral.
package pi_sandbox

import (
	"os"
	"time"

	"example.com/pig-bg-tasks/internal/bg"
	"example.com/pig-bg-tasks/internal/converge"
	"example.com/pig-bg-tasks/internal/ledger"
	"example.com/pig-bg-tasks/internal/permission"
	"example.com/pig-bg-tasks/internal/policy"
	"example.com/pig-bg-tasks/internal/runner"
	"example.com/pig-bg-tasks/internal/tools"
	sdk "github.com/MichaelKinsy/PiG/extensions/sdk"
)

// Extension is the conventional factory entry point.
func Extension() *sdk.Extension {
	e := sdk.New("pig-bg-tasks")

	// ── Tools ────────────────────────────────────────────────────────
	// Same-name registration replaces the earlier definition in place
	// (host Map.set semantics) — `bash` is occupied by this composed
	// definition, so no unconfined built-in bash can be reached.
	e.RegisterTool(tools.BashDefinition())
	e.RegisterTool(tools.BgListDefinition())
	e.RegisterTool(tools.BgOutputDefinition())
	e.RegisterTool(tools.BgStopDefinition())
	// Agent-facing diagnostics: mode/grants/runner/shell/registry/trace —
	// the agent inspects a live installed session without slash commands.
	e.RegisterTool(tools.DebugDefinition())

	// ── Commands / shortcut / message renderer ───────────────────────
	e.RegisterCommand("sandbox", tools.SandboxCommand())
	e.RegisterCommand("bg", tools.BgCommand())
	e.RegisterCommand("bg-tasks", tools.BgTasksCommand())

	// Ctrl+Shift+B (Ctrl+B itself is the editor's cursor-left and must not
	// be claimed).
	e.Shortcut("ctrl+shift+b", "Background the current foreground process",
		func(ctx sdk.Context) error {
			bg.BackgroundActiveForeground(func(msg, level string) { ctx.Notify(msg, level) })
			return nil
		})

	// <task-notification> renders as one line: ● summary.
	e.MessageRenderer(bg.TaskNotificationCustomType,
		func(ctx sdk.Context, message map[string]any, options sdk.MessageRenderOptions, width int) ([]string, error) {
			summary := ""
			if details, ok := message["details"].(map[string]any); ok {
				if s, ok := details["summary"].(string); ok {
					summary = s
				}
			}
			if summary == "" {
				if s, ok := message["content"].(string); ok {
					summary = s
				}
			}
			line := "● " + summary
			if width > 0 {
				r := []rune(line)
				if len(r) > width {
					line = string(r[:max(0, width-1)]) + "…"
				}
			}
			return []string{line}, nil
		})

	// ── Steering auto-background ─────────────────────────────────────
	// A steering message (Enter mid-stream) pauses every running foreground
	// command so the message is delivered at the natural turn boundary
	// instead of queueing behind a long command. Deliberately NOT ctx.Abort:
	// aborting would kill the very process we are backgrounding.
	e.OnEvent(sdk.EventInput, func(ctx sdk.Context, data map[string]any) (any, error) {
		behavior, _ := data["streamingBehavior"].(string)
		deliverAs, _ := data["deliverAs"].(string)
		if behavior == "steer" || deliverAs == "steer" {
			bg.PauseAllForeground(bg.ReasonSteer)
		}
		return nil, nil
	})

	// ── Session lifecycle ────────────────────────────────────────────
	e.OnSessionStart(func(ctx sdk.Context, _ map[string]any) (any, error) {
		reg := bg.Default()
		reg.SetNotifier(ctx)
		reg.SetNonInteractive(!ctx.HasUI())
		bg.SweepStaleLogs(time.Now())
		if home, err := ctx.ConfigHome(); err == nil && home != "" {
			tools.PinConfigHome(home)
		}
		// The configured bash: settings' shellPath wins over every fallback
		// (pi core's documented resolution order), so the host's configured
		// shell — not a PATH accident like the WSL alias — runs commands.
		configured := ""
		if s, err := ctx.GetSettings(); err == nil {
			if sp, ok := s["shellPath"].(string); ok {
				configured = sp
			}
		}
		runner.SetConfiguredShell(configured)
		// CONVERGENCE.md: spawn the background convergence thread NOW and
		// return — it delays nothing (only bash waits, and only for its own
		// epoch). Initial epoch = startup policy state.
		cfg := tools.ConfigFor(ctx)
		converge.Start(converge.State{
			Mode:      policy.ResolveEffectiveMode(permission.Get(), cfg.Mode),
			Workspace: policy.Canonical(ctx.Cwd()),
			Temp:      os.TempDir(),
			Extras:    cfg.ExtraWritableDirs,
		})
		reg.RenderStatusPill()
		return nil, nil
	})

	e.OnSessionShutdown(func(ctx sdk.Context, _ map[string]any) (any, error) {
		reg := bg.Default()
		// Kill ALL running tasks on ANY shutdown reason so no orphans
		// outlive the session; the silent-kill path latches `notified`, so
		// no <task-notification> fires on the way out. Logs stay on disk for
		// the next session's 24h sweep.
		_, running, _ := reg.Snapshot()
		for _, j := range running {
			reg.TerminateJobSilently(j, "session_shutdown")
		}
		if id, err := ctx.GetSessionID(); err == nil && id != "" {
			ledger.Forget(id)
		}
		return nil, nil
	})

	return e
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

package tools

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"example.com/pig-bg-tasks/internal/bg"
	"example.com/pig-bg-tasks/internal/converge"
	"example.com/pig-bg-tasks/internal/dbg"
	"example.com/pig-bg-tasks/internal/permission"
	"example.com/pig-bg-tasks/internal/policy"
	"example.com/pig-bg-tasks/internal/runner"
	sdk "github.com/MichaelKinsy/PiG/extensions/sdk"
)

// DebugDefinition is the agent-facing debug surface for the INSTALLED
// extension: everything the extension believes about the sandbox layer
// (mode, grants, runner verdict, resolved shell, config file) and the
// background layer (job registry, counters), plus the per-call spawn trace.
// Designed for diagnosing a live session where source access is awkward:
// the agent calls bg_debug directly instead of asking the user for slash
// command output.
func DebugDefinition() sdk.ToolDefinition {
	return sdk.ToolDefinition{
		Name:          "bg_debug",
		Label:         "pig-bg-tasks Debug Info",
		Description:   "Dump pig-bg-tasks internals: effective sandbox mode and writable grants, runner verdict, resolved shell, config file state, job registry snapshot, and the recent per-call bash spawn trace. Use when sandbox confinement, escalation, or background behavior looks wrong.",
		PromptSnippet: "Inspect pig-bg-tasks sandbox and background internals",
		Parameters: sdk.Schema{
			"type": "object",
			"properties": map[string]any{
				"tail": map[string]any{
					"type":        "integer",
					"description": "How many recent bash-call trace records to include (default 20, max 200).",
				},
			},
		},
		Execute: func(ctx sdk.Context, params map[string]any) (any, error) {
			tail := 20
			if v, ok := params["tail"].(float64); ok && v > 0 {
				tail = int(v)
			}
			if tail > 200 {
				tail = 200
			}

			reg := bg.Default()
			reg.SetNotifier(ctx)
			running, terminalInMap, recent := reg.Snapshot()
			_, done, failed := reg.Counters()

			cfg := ConfigFor(ctx)
			effective := policy.ResolveEffectiveMode(permission.Get(), cfg.Mode)
			source := "config default"
			if permission.Get() != nil {
				source = "/sandbox override"
			}
			workspace := policy.Canonical(ctx.Cwd())
			roots := policy.WritableRoots(effective, workspace, cfg.ExtraWritableDirs)

			var b strings.Builder
			fmt.Fprintf(&b, "pig-bg-tasks debug  %s\n", time.Now().Format(time.RFC3339))
			sid, _ := ctx.GetSessionID()
			fmt.Fprintf(&b, "session: %s  ui: %v  toolcall: %s\n", sid, ctx.HasUI(), ctx.ToolCallID())

			fmt.Fprintf(&b, "mode: %s (%s)  confined: %v\n", effective, source, policy.IsConfined(effective))
			fmt.Fprintf(&b, "runner: %s\n", runner.Describe(runner.Select(cfg.ProbeTimeoutMs), effective))
			fmt.Fprintf(&b, "convergence: %s\n", converge.StatusLine())
			fmt.Fprintf(&b, "workspace: %s\n", workspace)
			if len(roots) > 0 {
				fmt.Fprintf(&b, "writable roots: %s\n", strings.Join(roots, " ; "))
			} else {
				fmt.Fprintf(&b, "writable roots: (none for mode %s — writes allowed only where the OS ACL already permits)\n", effective)
			}
			fmt.Fprintf(&b, "temp root: %s\n", os.TempDir())

			fmt.Fprintf(&b, "config: mode=%s probeTimeoutMs=%d extras=%v\n", cfg.Mode, cfg.ProbeTimeoutMs, cfg.ExtraWritableDirs)
			cpath := filepath.Join(ConfigHome(), "agent", "sandbox.json")
			if st, err := os.Stat(cpath); err == nil {
				fmt.Fprintf(&b, "config file: %s (%d bytes, mtime %s)\n", cpath, st.Size(), st.ModTime().Format(time.RFC3339))
			} else {
				fmt.Fprintf(&b, "config file: %s (absent — defaults in use)\n", cpath)
			}

			if shell, err := runner.ResolveShell(); err == nil {
				fmt.Fprintf(&b, "shell: %s  (configured shellPath override: %q)\n", shell, runner.ConfiguredShell())
			} else {
				fmt.Fprintf(&b, "shell: UNRESOLVED: %v  (configured shellPath override: %q)\n", err, runner.ConfiguredShell())
			}

			fmt.Fprintf(&b, "registry: running=%d/%d  terminal-in-map=%d  recent=%d  completed=%d  failed+killed=%d  noninteractive=%v\n",
				len(running), bg.MaxConcurrentJobs, len(terminalInMap), len(recent), done, failed, reg.IsNonInteractive())
			for _, j := range running {
				fmt.Fprintf(&b, "  RUN %s bg=%v age=%s log=%s\n    cmd: %s\n",
					j.ID, j.IsBackgrounded, time.Since(j.StartTime).Round(time.Second), j.LogPath, trunc(j.Command, 160))
			}
			if len(terminalInMap) > 0 {
				// Should be empty: terminal jobs are evicted by the sweep.
				// Non-empty here = an eviction bug (the historic slot leak).
				for _, j := range terminalInMap {
					fmt.Fprintf(&b, "  STUCK-TERMINAL %s status=%s notified=%v (should have been evicted)\n", j.ID, j.Status, j.Notified)
				}
			}
			for i, j := range recent {
				if i >= 8 {
					break
				}
				fmt.Fprintf(&b, "  PAST %s %s notified=%v age=%s\n", j.ID, j.Status, j.Notified, time.Since(j.StartTime).Round(time.Second))
			}

			recs := dbg.Tail(tail)
			fmt.Fprintf(&b, "trace: %s (last %d records)\n", dbg.Path(), len(recs))
			for _, r := range recs {
				line, err := json.Marshal(r)
				if err != nil {
					continue
				}
				fmt.Fprintf(&b, "  %s\n", line)
			}
			return b.String(), nil
		},
	}
}

func trunc(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n-1]) + "…"
}

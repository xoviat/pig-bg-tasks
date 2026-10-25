package tools

import (
	"fmt"
	"strings"

	"example.com/pig-bg-tasks/internal/bg"
	"example.com/pig-bg-tasks/internal/converge"
	"example.com/pig-bg-tasks/internal/permission"
	"example.com/pig-bg-tasks/internal/policy"
	"example.com/pig-bg-tasks/internal/runner"
	sdk "github.com/MichaelKinsy/PiG/extensions/sdk"
)

// The user-facing command surface (CONVERGENCE.md):
//   /sandbox      show/switch mode; status shows mode, writable set, env,
//                 and epoch/convergence. Switching bumps an epoch and
//                 returns immediately (convergence runs on the background
//                 thread; the next bash call waits for it).
//   /bg           background the running foreground command
//   /bg-tasks     show the task list as a notification

// SandboxCommand is the /sandbox slash command (replaces /permission).
func SandboxCommand() sdk.CommandOptions {
	return sdk.CommandOptions{
		Description: "Show sandbox status (mode, writable set, env, epoch/convergence) or switch mode: /sandbox read-only | workspace-write | danger-full-access",
		GetArgumentCompletions: func(argumentPrefix string) ([]sdk.AutocompleteItem, error) {
			prefix := strings.TrimSpace(argumentPrefix)
			var items []sdk.AutocompleteItem
			for _, m := range policy.SANDBOX_MODES {
				if strings.HasPrefix(string(m), prefix) {
					items = append(items, sdk.AutocompleteItem{Value: string(m), Label: string(m)})
				}
			}
			return items, nil
		},
		Handler: func(ctx sdk.Context, args string) error {
			arg := strings.TrimSpace(args)
			if arg == "" {
				ctx.Notify(sandboxStatus(ctx), "info")
				return nil
			}
			if !policy.IsMode(arg) {
				ctx.Notify(fmt.Sprintf("sandbox: unknown mode %q. Available: %s", arg, joinModes()), "error")
				return nil
			}
			// Non-blocking: install the process-wide override and bump the
			// epoch; the background thread converges. No ACL work here.
			permission.Set(policy.Mode(arg))
			epoch := converge.SetMode(policy.Mode(arg))
			ctx.Notify(fmt.Sprintf(
				"sandbox: mode set to %s (process-wide) — epoch %d converging on the background thread; the next bash call waits for it.\n%s",
				arg, epoch, converge.StatusLine()), "info")
			return nil
		},
	}
}

func joinModes() string {
	var s []string
	for _, m := range policy.SANDBOX_MODES {
		s = append(s, string(m))
	}
	return strings.Join(s, ", ")
}

// sandboxStatus renders the status block: mode+source, runner, workspace,
// writable set, resolved env, epoch/convergence, extras, shell. Read-only:
// it touches shared state, never the background thread's work.
func sandboxStatus(ctx sdk.Context) string {
	cfg := ConfigFor(ctx)
	effective := policy.ResolveEffectiveMode(permission.Get(), cfg.Mode)
	source := "config default"
	if permission.Get() != nil {
		source = "/sandbox override"
	}
	var lines []string
	lines = append(lines, fmt.Sprintf("sandbox mode: %s (%s)", effective, source))
	if effective == policy.ModeDangerFullAccess {
		lines = append(lines, "runner: bypassed (danger-full-access)")
	} else {
		lines = append(lines, "runner: "+runner.Describe(runner.Select(cfg.ProbeTimeoutMs), effective))
	}
	workspace := policy.Canonical(ctx.Cwd())
	lines = append(lines, "workspace: "+workspace)
	roots := policy.WritableRoots(effective, workspace, cfg.ExtraWritableDirs)
	if len(roots) > 0 {
		lines = append(lines, "writable set: "+strings.Join(roots, " ; "))
	} else {
		lines = append(lines, "writable set: (none for mode "+string(effective)+" — writes allowed only where the OS ACL already permits)")
	}
	lines = append(lines, "env: "+converge.EnvSummary())
	lines = append(lines, "convergence: "+converge.StatusLine())
	if len(cfg.ExtraWritableDirs) > 0 {
		suffix := ""
		if effective != policy.ModeWorkspaceWrite {
			suffix = fmt.Sprintf(" (inactive: %s)", effective)
		}
		lines = append(lines, "extra writable: "+strings.Join(cfg.ExtraWritableDirs, ", ")+suffix)
	}
	shell, err := runner.ResolveShell()
	if err == nil {
		lines = append(lines, "shell: "+shell)
	}
	return strings.Join(lines, "\n")
}

// BgCommand backgrounds the current foreground process (/bg).
func BgCommand() sdk.CommandOptions {
	return sdk.CommandOptions{
		Description: "Background the current foreground process",
		Handler: func(ctx sdk.Context, args string) error {
			bg.BackgroundActiveForeground(func(msg, level string) { ctx.Notify(msg, level) })
			return nil
		},
	}
}

// BgTasksCommand lists background tasks (/bg-tasks).
func BgTasksCommand() sdk.CommandOptions {
	return sdk.CommandOptions{
		Description: "List background tasks",
		Handler: func(ctx sdk.Context, args string) error {
			reg := bg.Default()
			reg.SetNotifier(ctx)
			ctx.Notify(bg.FormatJobList(reg), "info")
			return nil
		},
	}
}

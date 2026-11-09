//! Port of `internal/tools/commands.go` — the user-facing command surface
//! (CONVERGENCE.md): `/sandbox` show/switch, `/bg`, `/bg-tasks`.
//!
//! Documented divergence (post-E13): the Go `/sandbox` set-message said
//! "converging on the background thread; the next bash call waits for it" —
//! convergence is synchronous now, so the message reports the *converged*
//! epoch truthfully. Everything else keeps the reference wording.

use crate::bg::{Registry, ui};
use pig_sdk::{AutocompleteItem, CommandResult, Context};
use crate::policy::Mode;
use crate::runner::converge::Engine;

use crate::ext::{port::port_for, resolve::config_for};

pub const SANDBOX_DESC: &str = "Show sandbox status (mode, writable set, env, epoch/convergence) or switch mode: /sandbox read-only | workspace-write | danger-full-access";
pub const BG_DESC: &str = "Background the current foreground process";
pub const BG_TASKS_DESC: &str = "List background tasks";

/// `/sandbox` argument completions: the modes matching the prefix.
pub fn sandbox_completions(argument_prefix: &str) -> Option<Vec<AutocompleteItem>> {
    let prefix = argument_prefix.trim();
    let items: Vec<AutocompleteItem> = crate::policy::SANDBOX_MODES
        .iter()
        .filter(|m| m.as_str().starts_with(prefix))
        .map(|m| AutocompleteItem {
            value: m.as_str().to_string(),
            label: Some(m.as_str().to_string()),
            description: None,
        })
        .collect();
    (!items.is_empty()).then_some(items)
}

fn join_modes() -> String {
    crate::policy::SANDBOX_MODES
        .iter()
        .map(|m| m.as_str())
        .collect::<Vec<_>>()
        .join(", ")
}

/// `/sandbox` handler.
pub fn sandbox_handler(ctx: &Context, args: &str) -> CommandResult {
    let arg = args.trim();
    if arg.is_empty() {
        ctx.notify(&sandbox_status(ctx), "info");
        return CommandResult::Ok;
    }
    if !crate::policy::is_mode(arg) {
        ctx.notify(
            &format!("sandbox: unknown mode \"{arg}\". Available: {}", join_modes()),
            "error",
        );
        return CommandResult::Ok;
    }
    // Non-blocking (and now literally synchronous): install the process-wide
    // override, bump + converge the epoch, report. The convergence status
    // line ("epoch N — converged: …") is not echoed here — `/sandbox` with
    // no args still shows it.
    let mode = match arg {
        "read-only" => Mode::Readonly,
        "workspace-write" => Mode::WorkspaceWrite,
        _ => Mode::DangerFullAccess,
    };
    crate::policy::permission::set(mode);
    let epoch = Engine::shared().set_mode(mode);
    ctx.notify(
        &format!(
            "sandbox: mode set to {arg} (process-wide) — epoch {epoch} converged; the next bash call runs under it."
        ),
        "info",
    );
    CommandResult::Ok
}

/// The status block: mode+source, runner, workspace, writable set, resolved
/// env, epoch/convergence, extras, shell. Read-only: shared state only.
pub fn sandbox_status(ctx: &Context) -> String {
    let cfg = config_for(ctx);
    let effective = crate::policy::resolve_effective_mode(crate::policy::permission::get(), cfg.mode);
    let source = if crate::policy::permission::get().is_some() {
        "/sandbox override"
    } else {
        "config default"
    };
    let mut lines: Vec<String> = Vec::new();
    lines.push(format!("sandbox mode: {effective} ({source})"));
    if effective == Mode::DangerFullAccess {
        lines.push("runner: bypassed (danger-full-access)".to_string());
    } else {
        lines.push(format!(
            "runner: {}",
            crate::runner::describe(crate::runner::select(cfg.probe_timeout_ms), effective)
        ));
    }
    let workspace = crate::policy::canonical(ctx.cwd());
    lines.push(format!("workspace: {workspace}"));
    let roots = crate::policy::writable_roots(effective, &workspace, &cfg.extra_writable_dirs);
    if !roots.is_empty() {
        lines.push(format!("writable set: {}", roots.join(" ; ")));
    } else {
        lines.push(format!(
            "writable set: (none for mode {effective} — writes allowed only where the OS ACL already permits)"
        ));
    }
    lines.push(format!("env: {}", Engine::env_summary()));
    lines.push(format!("convergence: {}", Engine::shared().status_line()));
    if !cfg.extra_writable_dirs.is_empty() {
        let suffix = if effective != Mode::WorkspaceWrite {
            format!(" (inactive: {effective})")
        } else {
            String::new()
        };
        lines.push(format!(
            "extra writable: {}{suffix}",
            cfg.extra_writable_dirs.join(", ")
        ));
    }
    if let Ok(shell) = crate::runner::shell::resolve() {
        lines.push(format!("shell: {shell}"));
    }
    lines.join("\n")
}

/// `/bg` handler: background the current foreground process.
pub fn bg_handler(ctx: &Context, _args: &str) -> CommandResult {
    ui::background_active_foreground(
        Registry::shared(),
        Some(&|msg: &str, level: &str| ctx.notify(msg, level)),
    );
    CommandResult::Ok
}

/// `/bg-tasks` handler: show the task list as a notification.
pub fn bg_tasks_handler(ctx: &Context, _args: &str) -> CommandResult {
    let reg = Registry::shared();
    reg.set_notifier(port_for(ctx));
    ctx.notify(&ui::format_job_list(&reg), "info");
    CommandResult::Ok
}

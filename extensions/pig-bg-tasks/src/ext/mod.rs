//! The ext layer: registers everything the combined extension serves — ONE
//! composed `bash` tool, the three task tools, the
//! `/sandbox`-family commands (with completions), Ctrl+Shift+B, the
//! `<task-notification>` renderer, steering auto-background, and session
//! lifecycle (port of `extension.go`).

pub mod bash;
pub mod commands;
pub mod port;
pub mod resolve;
pub mod tasks;

use std::time::SystemTime;

use crate::bg::registry::Registry;
use pig_sdk::{CommandResult, Extension};
use crate::policy::resolve_effective_mode;
use crate::runner::converge::{Engine, State as ConvergeState};
use serde_json::Value;

use port::port_for;

/// Build the factory's extension (E7 scaffold pattern: no `main` — pig
/// drives `Extension::run`).
pub fn build() -> Extension {
    let mut ext = Extension::new("pig-bg-tasks");

    // ── Tools ────────────────────────────────────────────────────────
    // Same-name registration replaces the earlier definition in place (host
    // Map.set semantics) — `bash` is occupied by this composed definition,
    // so no unconfined built-in bash can be reached.
    ext.register_tool(bash::bash_definition());
    ext.register_tool(tasks::bg_list_definition());
    ext.register_tool(tasks::bg_output_definition());
    ext.register_tool(tasks::bg_stop_definition());

    // ── Commands / completions ───────────────────────────────────────
    ext.command("sandbox", commands::SANDBOX_DESC, commands::sandbox_handler);
    ext.command_argument_completions("sandbox", commands::sandbox_completions);
    ext.command("bg", commands::BG_DESC, commands::bg_handler);
    ext.command("bg-tasks", commands::BG_TASKS_DESC, commands::bg_tasks_handler);

    // Ctrl+Shift+B (Ctrl+B itself is the editor's cursor-left and must not
    // be claimed).
    ext.shortcut(
        "ctrl+shift+b",
        "Background the current foreground process",
        |ctx| {
            crate::bg::ui::background_active_foreground(
                Registry::shared(),
                Some(&|msg: &str, level: &str| ctx.notify(msg, level)),
            );
            CommandResult::Ok
        },
    );

    // <task-notification> renders as one line: ● summary.
    ext.message_renderer(
        crate::bg::notify::TASK_NOTIFICATION_CUSTOM_TYPE,
        |_ctx, message: Value, _options, width| {
            let mut summary = message
                .pointer("/details/summary")
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty())
                .map(String::from);
            if summary.is_none() {
                summary = message
                    .get("content")
                    .and_then(Value::as_str)
                    .map(String::from);
            }
            let mut line = format!("● {}", summary.unwrap_or_default());
            if width > 0 {
                let w = width as usize;
                if line.chars().count() > w {
                    let head: String = line.chars().take(w.saturating_sub(1)).collect();
                    line = format!("{head}…");
                }
            }
            Ok(vec![line])
        },
    );

    // ── Steering auto-background ─────────────────────────────────────
    // A steering message (Enter mid-stream) pauses every running foreground
    // command so the message is delivered at the natural turn boundary
    // instead of queueing behind a long command. Deliberately NOT an abort:
    // aborting would kill the very process we are backgrounding.
    let _ = ext.on_event("input", |_ctx, data: &mut Value| {
        let behavior = data.get("streamingBehavior").and_then(Value::as_str).unwrap_or("");
        let deliver_as = data.get("deliverAs").and_then(Value::as_str).unwrap_or("");
        if behavior == "steer" || deliver_as == "steer" {
            crate::bg::ui::pause_all_foreground(Registry::shared(), crate::bg::BackgroundReason::Steer);
        }
        None
    });

    // ── Session lifecycle ────────────────────────────────────────────
    let _ = ext.on_event("session_start", |ctx, _data: &mut Value| {
        let reg = Registry::shared();
        reg.set_notifier(port_for(ctx));
        reg.set_non_interactive(!ctx.has_ui());
        crate::bg::registry::sweep_stale_logs(SystemTime::now());
        if let Ok(home) = ctx.config_home() {
            if !home.is_empty() {
                resolve::pin_config_home(home);
            }
        }
        // The configured bash: settings' shellPath wins over every fallback
        // (pi core's documented resolution order), so the host's configured
        // shell — not a PATH accident like the WSL alias — runs commands.
        let configured = ctx
            .get_settings()
            .ok()
            .and_then(|s| s.get("shellPath").and_then(Value::as_str).map(String::from))
            .unwrap_or_default();
        crate::runner::shell::set_configured_shell(&configured);
        // Userland applets on the child PATH (E3-bis gap): settings'
        // `userlandDir` names a busybox-applet dir (sed/grep/awk/…), prepended
        // in both confined and bare spawns — brush has no built-in sed. Fallback when the setting
        // is absent: `<configHome>/agent/userland` if it exists (drop-in dir,
        // no settings edit needed). Both seams feed crate::runner::request's PATH
        // prepend (seam: settings `userlandDir` or <configHome>/agent/userland).
        let settings_userland = ctx.get_settings().ok().and_then(|s| {
            s.get("userlandDir")
                .and_then(Value::as_str)
                .filter(|v| !v.is_empty())
                .map(String::from)
        });
        let userland = settings_userland.or_else(|| {
            let p = std::path::Path::new(&resolve::config_home(ctx))
                .join("agent")
                .join("userland");
            p.is_dir().then(|| p.to_string_lossy().into_owned())
        });
        crate::runner::request::set_userland_dir(userland.as_deref().unwrap_or(""));
        // CONVERGENCE: synchronous now — initial epoch = startup policy state
        // (there is no background thread to spawn; only bash binds, and the
        // bind is a `stat` inside the call's duration).
        let cfg = resolve::config_for(ctx);
        Engine::shared().start(ConvergeState {
            mode: resolve_effective_mode(crate::policy::permission::get(), cfg.mode),
            workspace: crate::policy::canonical(ctx.cwd()),
            temp: std::env::temp_dir().to_string_lossy().into_owned(),
            extras: cfg.extra_writable_dirs,
        });
        crate::bg::lifecycle::render_status_pill(&reg);
        None
    });

    let _ = ext.on_event("session_shutdown", |ctx, _data: &mut Value| {
        let reg = Registry::shared();
        // Kill ALL running tasks on ANY shutdown reason so no orphans
        // outlive the session; the silent-kill path latches `notified`, so
        // no <task-notification> fires on the way out. Logs stay on disk for
        // the next session's 24h sweep.
        //
        // NOTE (ported intentionally, differs from the Go build): Go binds
        // `_, running, _ := reg.Snapshot()` — the *second* slot, which is
        // `terminalInMap` — so the Go shutdown loop killed nothing while its
        // comment promises "Kill ALL running tasks". We take the FIRST slot
        // (running) as the comment and CONVERGENCE.md's contract require.
        let (running, _terminal, _recent) = reg.snapshot();
        for j in running {
            crate::bg::lifecycle::terminate_job_silently(&reg, &j, "session_shutdown");
        }
        if let Ok(id) = ctx.get_session_id() {
            if !id.is_empty() {
                crate::escalate::ledger::forget(&id);
            }
        }
        None
    });

    ext
}

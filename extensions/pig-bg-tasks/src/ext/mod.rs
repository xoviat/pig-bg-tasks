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
        // ── The parent link (DELEGATED-WORKSPACES §B) ────────────────
        // This session is a CHILD when PIG_PARENT_SESSION names its parent
        // (the subprocess plugin's one marker) and a PARENT for its own SDK
        // session id — possibly both at once (nested delegation): the
        // listener always starts for the SDK id, the client only when the
        // marker is set.
        let session_id = ctx.get_session_id().unwrap_or_default();
        // A previous session's inherited policy never leaks into this one
        // (shutdown clears it too; this covers a host that skipped it).
        crate::policy::inherit::clear();
        if let Some(parent) = crate::link::parent_session() {
            // Child side FIRST: mirror the parent's policy before the
            // config is read, so the mode baseline and the roots apply
            // from the very first spawn. An unreachable parent leaves the
            // local policy untouched (a child never widens by being
            // unreachable).
            let fetched = crate::link::client::fetch_policy(
                &parent,
                &resolve::config_home(ctx),
                &session_id,
            );
            if let Some(p) = fetched {
                if let Some(mode) = crate::policy::parse_mode(&p.mode) {
                    crate::policy::inherit::set(parent, mode, p.extras);
                }
            }
        }
        if !session_id.is_empty() {
            // Parent side: this session's endpoint + ask relay. The policy
            // snapshot is read live (the `/sandbox` override and a nested
            // inheritance both show up in it). An ask is put in front of
            // THIS session's user through THIS session's own dialog — a
            // delegated escalation is asked exactly like a local one, with
            // no separate tool or surface. No UI ⇒ no approver ⇒ the child
            // is refused fail-closed.
            let policy_ctx = ctx.clone();
            let workspace = crate::policy::canonical(ctx.cwd());
            let temp = std::env::temp_dir().to_string_lossy().into_owned();
            let approver: Option<
                std::sync::Arc<
                    dyn Fn(&crate::link::Ask) -> Result<crate::link::Verdict, String>
                        + Send
                        + Sync,
                >,
            > = if ctx.has_ui() {
                let actx = ctx.clone();
                Some(std::sync::Arc::new(
                    move |ask: &crate::link::Ask| {
                        // The child sends the byte-stable dialog title;
                        // rebuild it only when a peer sent none.
                        let title = if ask.title.is_empty() {
                            crate::escalate::approval_title(
                                "command",
                                &ask.mode,
                                &ask.justification,
                                &ask.summary,
                            )
                        } else {
                            ask.title.clone()
                        };
                        match crate::ext::resolve::dialog_decide(&actx, &title) {
                            Ok(d) if d.choice.is_empty() => {
                                Ok(crate::link::Verdict::Cancelled)
                            }
                            Ok(d) if d.choice == "Deny" => {
                                Ok(crate::link::Verdict::Deny(d.reason))
                            }
                            Ok(_) => Ok(crate::link::Verdict::Allow),
                            Err(e) => Err(e),
                        }
                    },
                ))
            } else {
                None
            };
            crate::link::server::start(crate::link::server::ServerOpts {
                session_id,
                config_root: resolve::config_home(ctx),
                policy: std::sync::Arc::new(move || {
                    let c = resolve::config_for(&policy_ctx);
                    crate::link::Policy {
                        mode: resolve_effective_mode(crate::policy::permission::get(), c.mode)
                            .as_str()
                            .to_string(),
                        workspace: workspace.clone(),
                        temp: temp.clone(),
                        extras: c.extra_writable_dirs,
                    }
                }),
                approver,
            });
        }
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
        // The parent link goes down with the session: pending asks were
        // already refused fail-closed by their own deadlines, the socket
        // files are removed, and a nested child's inherited policy is
        // dropped with this session's identity.
        crate::link::server::stop();
        crate::policy::inherit::clear();
        None
    });

    ext
}

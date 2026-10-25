//! Port of `internal/tools/debug.go` — the agent-facing debug surface for
//! the INSTALLED extension: everything the extension believes about the
//! sandbox layer (mode, grants, runner verdict, resolved shell, config file)
//! and the background layer (job registry, counters), plus the per-call
//! spawn trace. The agent calls `bg_debug` directly instead of asking the
//! user for slash-command output.

use crate::bg::registry::Registry;
use pig_sdk::{ToolDefinition, ToolResult};
use crate::policy::Mode;
use serde_json::json;
use std::time::SystemTime;

use crate::ext::port::port_for;
use crate::ext::resolve::config_for;

/// Go `trunc`: n runes → n-1 + ellipsis.
fn trunc(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        return s.to_string();
    }
    let head: String = s.chars().take(n - 1).collect();
    format!("{head}…")
}

/// Go `time.Since(x).Round(time.Second).String()` — hour-aware units, "0s".
fn go_duration(d: std::time::Duration) -> String {
    let total = d.as_secs();
    if total == 0 {
        return "0s".to_string();
    }
    let h = total / 3600;
    let m = (total % 3600) / 60;
    let s = total % 60;
    if h > 0 {
        format!("{h}h{m}m{s}s")
    } else if m > 0 {
        format!("{m}m{s}s")
    } else {
        format!("{s}s")
    }
}

pub fn debug_definition() -> ToolDefinition {
    let mut def = ToolDefinition::new(
        "bg_debug",
        "pig-bg-tasks Debug Info",
        "Dump pig-bg-tasks internals: effective sandbox mode and writable grants, runner verdict, resolved shell, config file state, job registry snapshot, and the recent per-call bash spawn trace. Use when sandbox confinement, escalation, or background behavior looks wrong.",
        json!({
            "type": "object",
            "properties": {
                "tail": {
                    "type": "integer",
                    "description": "How many recent bash-call trace records to include (default 20, max 200)."
                }
            }
        }),
        |ctx, params: serde_json::Value| {
            let mut tail = 20usize;
            if let Some(v) = params.get("tail").and_then(|v| v.as_f64()) {
                if v > 0.0 {
                    tail = v as usize;
                }
            }
            if tail > 200 {
                tail = 200;
            }

            let reg = Registry::shared();
            reg.set_notifier(port_for(ctx));
            let (running, terminal_in_map, recent) = reg.snapshot();
            let (_, done, failed) = reg.counters();

            let cfg = config_for(ctx);
            let effective = crate::policy::resolve_effective_mode(crate::policy::permission::get(), cfg.mode);
            let source = if crate::policy::permission::get().is_some() {
                "/sandbox override"
            } else {
                "config default"
            };
            let workspace = crate::policy::canonical(ctx.cwd());
            let roots = crate::policy::writable_roots(effective, &workspace, &cfg.extra_writable_dirs);

            let mut b = String::new();
            b.push_str(&format!(
                "pig-bg-tasks debug  {}\n",
                crate::bg::dbg::rfc3339_at(SystemTime::now(), false)
            ));
            let sid = ctx.get_session_id().unwrap_or_default();
            b.push_str(&format!(
                "session: {sid}  ui: {}  toolcall: {}\n",
                ctx.has_ui(),
                ctx.tool_call_id().unwrap_or("")
            ));
            b.push_str(&format!(
                "mode: {effective} ({source})  confined: {}\n",
                crate::policy::is_confined(effective)
            ));
            b.push_str(&format!(
                "runner: {}\n",
                crate::runner::describe(crate::runner::select(cfg.probe_timeout_ms), effective)
            ));
            b.push_str(&format!(
                "convergence: {}\n",
                crate::runner::converge::Engine::shared().status_line()
            ));
            b.push_str(&format!("workspace: {workspace}\n"));
            if !roots.is_empty() {
                b.push_str(&format!("writable roots: {}\n", roots.join(" ; ")));
            } else {
                b.push_str(&format!(
                    "writable roots: (none for mode {effective} — writes allowed only where the OS ACL already permits)\n"
                ));
            }
            b.push_str(&format!(
                "temp root: {}\n",
                std::env::temp_dir().to_string_lossy()
            ));

            b.push_str(&format!(
                "config: mode={} probeTimeoutMs={} extras=[{}]\n",
                cfg.mode,
                cfg.probe_timeout_ms,
                cfg.extra_writable_dirs.join(", ")
            ));
            let cpath = std::path::Path::new(&crate::ext::resolve::config_home(ctx))
                .join("agent")
                .join("sandbox.json");
            match std::fs::metadata(&cpath) {
                Ok(st) => {
                    let mtime = st
                        .modified()
                        .map(|t| crate::bg::dbg::rfc3339_at(t, false))
                        .unwrap_or_default();
                    b.push_str(&format!(
                        "config file: {} ({} bytes, mtime {mtime})\n",
                        cpath.display(),
                        st.len()
                    ));
                }
                Err(_) => {
                    b.push_str(&format!(
                        "config file: {} (absent — defaults in use)\n",
                        cpath.display()
                    ));
                }
            }

            match crate::runner::shell::resolve() {
                Ok(shell) => b.push_str(&format!(
                    "shell: {shell}  (configured shellPath override: {:?})\n",
                    crate::runner::shell::configured_shell()
                )),
                Err(e) => b.push_str(&format!(
                    "shell: UNRESOLVED: {e}  (configured shellPath override: {:?})\n",
                    crate::runner::shell::configured_shell()
                )),
            }

            let userland = crate::runner::request::userland_dir();
            if userland.is_empty() {
                b.push_str(
                    "userland: unset (no extra applets on child PATH — set settings `userlandDir` or create <configHome>/agent/userland)\n",
                );
            } else {
                b.push_str(&format!("userland: {userland}\n"));
            }

            b.push_str(&format!(
                "registry: running={}/{MAX}  terminal-in-map={}  recent={}  completed={done}  failed+killed={failed}  noninteractive={}\n",
                running.len(),
                terminal_in_map.len(),
                recent.len(),
                reg.is_non_interactive(),
                MAX = crate::bg::MAX_CONCURRENT_JOBS
            ));
            for j in &running {
                b.push_str(&format!(
                    "  RUN {} bg={} age={} log={}\n    cmd: {}\n",
                    j.id,
                    j.is_backgrounded(),
                    go_duration(j.start_time.elapsed()),
                    j.log_path,
                    trunc(&j.command, 160)
                ));
            }
            for j in &terminal_in_map {
                // Should be empty: terminal jobs are evicted by the sweep.
                // Non-empty here = an eviction bug (the historic slot leak).
                b.push_str(&format!(
                    "  STUCK-TERMINAL {} status={} notified={} (should have been evicted)\n",
                    j.id,
                    j.status(),
                    j.notified()
                ));
            }
            for (i, j) in recent.iter().enumerate() {
                if i >= 8 {
                    break;
                }
                b.push_str(&format!(
                    "  PAST {} {} notified={} age={}\n",
                    j.id,
                    j.status(),
                    j.notified(),
                    go_duration(j.start_time.elapsed())
                ));
            }

            let recs = crate::bg::dbg::tail(tail);
            b.push_str(&format!(
                "trace: {} (last {} records)\n",
                crate::bg::dbg::path().display(),
                recs.len()
            ));
            for r in &recs {
                if let Ok(line) = serde_json::to_string(r) {
                    b.push_str(&format!("  {line}\n"));
                }
            }
            ToolResult::Text(b)
        },
    );
    def.prompt_snippet = Some("Inspect pig-bg-tasks sandbox and background internals".into());
    def
}

// Silence an unused-mode warning path: Mode is referenced via policy only.
#[allow(unused)]
fn _mode_ty(_: Mode) {}

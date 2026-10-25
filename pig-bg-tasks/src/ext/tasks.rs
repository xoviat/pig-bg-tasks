//! Port of `internal/tools/tasks.go` — the three task-management tools
//! (parity with pi-bg-tasks' tools-tasks.ts).

use crate::bg::registry::{Job, Registry};
use crate::bg::{lifecycle, output, ui};
use pig_sdk::Context;
use pig_sdk::{ToolDefinition, ToolResult};
use serde_json::json;
use std::sync::Arc;

use crate::ext::port::port_for;

fn meta_lines(j: &Job) -> Vec<String> {
    let mut lines = vec![
        format!("Task: {}", j.id),
        format!("Status: {}", j.status()),
        format!("Command: {}", j.command),
        format!("Log: {}", j.log_path),
    ];
    if let Some(code) = j.exit_code() {
        lines[1] = format!("Status: {} (exit code {code})", j.status());
    }
    let stop = j.stop_reason();
    if !stop.is_empty() {
        lines.push(format!("Stop reason: {stop}"));
    }
    lines
}

fn find_job(ctx: &Context, params: &serde_json::Value) -> Result<Arc<Job>, ToolResult> {
    let reg = Registry::shared();
    reg.set_notifier(port_for(ctx));
    let task_id = params.get("task_id").and_then(|v| v.as_str()).unwrap_or("");
    reg.find_job(task_id).ok_or_else(|| {
        ToolResult::Error(format!(
            "Unknown task: {task_id}. Use bg_list to see running and recent tasks."
        ))
    })
}

/// Lists running tasks first, then recent finished ones.
pub fn bg_list_definition() -> ToolDefinition {
    let mut def = ToolDefinition::new(
        "bg_list",
        "Background Task List",
        "List background tasks: running tasks first, then recently finished ones. Returns task IDs for use with bg_output and bg_stop.",
        json!({"type": "object", "properties": {}}),
        |ctx, _params: serde_json::Value| {
            let reg = Registry::shared();
            reg.set_notifier(port_for(ctx));
            reg.sweep_notified_terminal();
            lifecycle::render_status_pill(&reg);
            ToolResult::Text(ui::format_job_list(&reg))
        },
    );
    def.prompt_snippet = Some("List background tasks and their status".into());
    def
}

/// Reads a task's meta + bounded log tail (non-blocking).
pub fn bg_output_definition() -> ToolDefinition {
    let mut def = ToolDefinition::new(
        "bg_output",
        "Background Task Output",
        "Read a background task's output. Non-blocking: returns the task's meta info, a tail preview of its log, and the log path. Use the Read tool to page through the full log file for more.",
        json!({
            "type": "object",
            "properties": {
                "task_id": {"type": "string", "description": "Task ID (from bash run_in_background or bg_list)"}
            }
        }),
        |ctx, params: serde_json::Value| match find_job(ctx, &params) {
            Err(e) => e,
            Ok(j) => {
                let reg = Registry::shared();
                reg.latch_terminal(&j);
                lifecycle::render_status_pill(&reg);
                let tail = output::strip_ansi(&output::read_bounded_tail(
                    &j.log_path,
                    crate::bg::TASK_OUTPUT_TAIL_CHARS as i64,
                ));
                let mut b = String::new();
                for l in meta_lines(&j) {
                    b.push_str(&l);
                    b.push('\n');
                }
                b.push_str("\n--- output tail (last 32 KiB) ---\n");
                b.push_str(&tail);
                b.push_str(&format!(
                    "\n\nFull log: {} (use the Read tool with offset/limit to page through it)",
                    j.log_path
                ));
                ToolResult::Text(b)
            }
        },
    );
    def.prompt_snippet = Some("Read a background task's output tail".into());
    def
}

/// Stops a task: job-object terminate (Windows — no SIGTERM exists),
/// bounded wait for the real death, final status returned.
pub fn bg_stop_definition() -> ToolDefinition {
    let mut def = ToolDefinition::new(
        "bg_stop",
        "Background Task Stop",
        "Stop a running background task: Job-object terminate on Windows (kills the whole tree). Returns the final status.",
        json!({
            "type": "object",
            "properties": {
                "task_id": {"type": "string", "description": "Task ID (from bash run_in_background or bg_list)"},
                "reason": {"type": "string", "description": "Why the task is being stopped"}
            }
        }),
        |ctx, params: serde_json::Value| match find_job(ctx, &params) {
            Err(e) => e,
            Ok(j) => {
                let reg = Registry::shared();
                let reason = params.get("reason").and_then(|v| v.as_str()).unwrap_or("").to_string();
                let mut b = String::new();
                let write_meta = |b: &mut String| {
                    for l in meta_lines(&j) {
                        b.push_str(&l);
                        b.push('\n');
                    }
                };
                if j.is_terminal() {
                    reg.latch_terminal(&j);
                    lifecycle::render_status_pill(&reg);
                    write_meta(&mut b);
                    b.push_str(&format!("\nTask {} already {}.", j.id, j.status()));
                    return ToolResult::Text(b);
                }
                // Latch BEFORE the kill so the exit handler's notification is
                // suppressed: a deliberate stop is cleanup the agent knows about.
                let gone = lifecycle::terminate_job_silently(&reg, &j, &reason);
                // Bounded wait for the actual death so we return the real outcome.
                let _ = gone.recv_timeout(std::time::Duration::from_secs(
                    crate::bg::KILL_GRACE_SECS + 1,
                ));
                lifecycle::render_status_pill(&reg);
                write_meta(&mut b);
                b.push_str(&format!(
                    "\nTask {} stopped (Job-object terminate — whole tree).",
                    j.id
                ));
                ToolResult::Text(b)
            }
        },
    );
    def.prompt_snippet = Some("Stop a running background task".into());
    def
}

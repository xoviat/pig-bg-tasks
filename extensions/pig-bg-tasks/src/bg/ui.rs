//! Port of `internal/bg/ui.go` — the below-editor hint widget (ref-counted:
//! parallel foreground commands share one key), list formatting, and the
//! background-active-foreground mechanic behind Ctrl+Shift+B and `/bg`.
//!
//! The status pill lives in `lifecycle::render_status_pill`. Signatures take
//! `&Registry` (Go hardcoded the process singleton inside these helpers);
//! callers pass `Registry::shared()` in production — keeps tests hermetic.

use std::sync::atomic::{AtomicUsize, Ordering};

use serde_json::json;

use crate::bg::notify::one_line;
use crate::bg::output::read_last_line;
use crate::bg::port::SdkPort;
use crate::bg::registry::{BackgroundReason, Job, JobStatus, Registry};

const HINT_KEY: &str = "bg-hint";
const HINT_TEXT: &str = "(ctrl+shift+b to run in background)";

// Ref-count: parallel foreground commands share one hint key.
static ACTIVE_HINT: AtomicUsize = AtomicUsize::new(0);

/// Show the hint on the 0→1 transition; `port` must be live (called during
/// a tool run).
pub fn show_background_hint(port: &dyn SdkPort) {
    let n = ACTIVE_HINT.fetch_add(1, Ordering::SeqCst) + 1;
    if n == 1 {
        let _ = port.set_widget(
            HINT_KEY,
            Some(json!([HINT_TEXT])),
            Some(json!({"placement": "belowEditor"})),
        );
    }
}

/// Release one hint; clears on the last 1→0.
pub fn clear_background_hint(port: &dyn SdkPort) {
    let prev = ACTIVE_HINT.load(Ordering::SeqCst);
    if prev == 0 {
        return;
    }
    let n = ACTIVE_HINT.fetch_sub(1, Ordering::SeqCst) - 1;
    if n == 0 {
        let _ = port.set_widget(HINT_KEY, None, None);
    }
}

/// Pause every running foreground command (the bash tool's result already
/// tells the model what happened; we only toast). Returns false when there
/// was nothing to pause.
pub fn background_active_foreground(
    reg: &Registry,
    notify: Option<&dyn Fn(&str, &str)>,
) -> bool {
    let slots = reg.take_foreground_slots();
    if slots.is_empty() {
        if let Some(n) = notify {
            n("No running foreground process to background.", "warning");
        }
        return false;
    }
    for s in &slots {
        (s.request_pause)(BackgroundReason::Manual);
    }
    if let Some(n) = notify {
        n("▶ Backgrounded — continuing.", "info");
    }
    true
}

/// The steering hook's bulk pause (does not toast — the user just typed a
/// message).
pub fn pause_all_foreground(reg: &Registry, reason: BackgroundReason) -> bool {
    let slots = reg.take_foreground_slots();
    for s in &slots {
        (s.request_pause)(reason);
    }
    !slots.is_empty()
}

/// "45s" / "3m20s".
fn format_duration(ms: u128) -> String {
    let total = ms / 1000;
    let m = total / 60;
    let s = total % 60;
    if m > 0 {
        format!("{m}m{s}s")
    } else {
        format!("{s}s")
    }
}

/// `bash-ab12cd34 [▶ 1m23s] cmd… (last line)` per job — exact layout in the
/// tests.
pub fn format_job_line(job: &Job) -> String {
    let mut head = job.id.clone();
    if !job.name.is_empty() {
        head = format!("{} ({})", job.name, job.id);
    }
    let mut cmd = one_line(&job.command);
    cmd = super::notify::truncate_chars(&cmd, 60);
    if job.status() == JobStatus::Running {
        let dur = format_duration(job.age_ms());
        let progress = read_last_line(&job.log_path, 2048);
        let suffix = if progress.is_empty() {
            String::new()
        } else {
            format!(": {}", super::notify::truncate_chars(&progress, 60))
        };
        let bg = if job.is_backgrounded() { "bg" } else { "fg" };
        return format!("{head} ▶ {bg} ({dur}) {cmd}{suffix}");
    }
    let glyph = if job.status() == JobStatus::Completed { "✓" } else { "✗" };
    let exit = job
        .exit_code()
        .map(|c| format!(" exit={c}"))
        .unwrap_or_default();
    format!("{head} {glyph} {}{exit} {cmd}", job.status())
}

/// The `bg_list` / `/bg-tasks` text: running first, then recent terminal
/// (last 10, newest first).
pub fn format_job_list(reg: &Registry) -> String {
    let (mut running, terminal_in_map, recent) = reg.snapshot();
    // start time descending (Go's stable-ish selection sort)
    running.sort_by(|a, b| b.start_time.cmp(&a.start_time));
    let mut tail = Vec::with_capacity(terminal_in_map.len() + recent.len());
    tail.extend(terminal_in_map);
    tail.extend(recent);
    if tail.len() > 10 {
        tail = tail.split_off(tail.len() - 10);
    }
    tail.reverse(); // newest first
    if running.is_empty() && tail.is_empty() {
        return "No background jobs".to_string();
    }
    let mut lines = Vec::new();
    if !running.is_empty() {
        lines.push(format!("Running ({}):", running.len()));
        for j in &running {
            lines.push(format!("  {}", format_job_line(j)));
        }
    }
    if !tail.is_empty() {
        lines.push("Recent:".to_string());
        for j in &tail {
            lines.push(format!("  {}", format_job_line(j)));
        }
    }
    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bg::mock::MockPort;
    use crate::bg::registry::ForegroundSlot;
    use std::sync::Arc;
    use std::sync::atomic::AtomicUsize;

    #[test]
    fn duration_formats() {
        assert_eq!(format_duration(0), "0s");
        assert_eq!(format_duration(45_000), "45s");
        assert_eq!(format_duration(200_000), "3m20s");
    }

    #[test]
    fn job_line_running_and_terminal() {
        let reg = Registry::new();
        let j = reg.new_running_job("bash-ab12cd34", "make all >/dev/null", None, "/tmp/x.log", "tc", "", false);
        let line = format_job_line(&j);
        assert_eq!(line, "bash-ab12cd34 ▶ fg (0s) make all >/dev/null");

        let j2 = reg.new_running_job("bash-done", "make", None, "/tmp/x.log", "tc", "build", false);
        j2.mark_terminal(JobStatus::Completed, Some(0));
        assert_eq!(format_job_line(&j2), "build (bash-done) ✓ completed exit=0 make");

        let j3 = reg.new_running_job("bash-fail", "make", None, "/tmp/x.log", "tc", "", false);
        j3.mark_terminal(JobStatus::Failed, Some(2));
        assert_eq!(format_job_line(&j3), "bash-fail ✗ failed exit=2 make");

        let j4 = reg.new_running_job("bash-killed", "x", None, "/tmp/x.log", "tc", "", true);
        j4.mark_terminal(JobStatus::Killed, None);
        assert_eq!(format_job_line(&j4), "bash-killed ✗ killed x");
    }

    #[test]
    fn job_list_shape() {
        let reg = Registry::new();
        assert_eq!(format_job_list(&reg), "No background jobs");
        let run = reg.new_running_job("bash-r", "sleep 1", None, "/tmp/x.log", "tc", "", true);
        let term = reg.new_running_job("bash-t", "echo", None, "/tmp/x.log", "tc", "", false);
        term.mark_terminal(JobStatus::Completed, Some(0));
        reg.forget(&term);
        let list = format_job_list(&reg);
        assert!(list.starts_with("Running (1):"), "{list}");
        assert!(list.contains("bash-r ▶ bg"), "{list}");
        assert!(list.contains("Recent:"), "{list}");
        assert!(list.contains("bash-t ✓ completed exit=0 echo"), "{list}");
        assert!(list.find("Running").unwrap() < list.find("Recent").unwrap());
        assert!(run.is_terminal() == false);
    }

    #[test]
    fn hint_refcount_shares_one_key() {
        // Net-zero on the process-global counter so the test is re-runnable.
        let port = MockPort::new();
        show_background_hint(&port);
        show_background_hint(&port);
        {
            let w = crate::bg::glock(&port.widgets);
            assert_eq!(w.len(), 1, "second show does not re-set");
            assert_eq!(w[0].0, "bg-hint");
            assert_eq!(w[0].1, Some(json!(["(ctrl+shift+b to run in background)"])));
        }
        clear_background_hint(&port);
        {
            let w = crate::bg::glock(&port.widgets);
            assert_eq!(w.len(), 1, "still held by the other reference");
        }
        clear_background_hint(&port);
        {
            let w = crate::bg::glock(&port.widgets);
            assert_eq!(w.len(), 2, "last release clears");
            assert_eq!(w[1].1, None);
        }
        clear_background_hint(&port); // underflow guard: no-op
        let w = crate::bg::glock(&port.widgets);
        assert_eq!(w.len(), 2);
    }

    #[test]
    fn background_active_foreground_toasts_and_drains() {
        let reg = Registry::new();
        let paused = Arc::new(AtomicUsize::new(0));
        let counter = paused.clone();
        reg.set_foreground("tc1", ForegroundSlot::new(move |_| {
            counter.fetch_add(1, Ordering::SeqCst);
        }));
        let counter = paused.clone();
        reg.set_foreground("tc2", ForegroundSlot::new(move |_| {
            counter.fetch_add(1, Ordering::SeqCst);
        }));
        let toasts = std::cell::RefCell::new(Vec::<(String, String)>::new());
        let ok = background_active_foreground(&reg, Some(&|m: &str, l: &str| {
            toasts.borrow_mut().push((m.to_string(), l.to_string()));
        }));
        assert!(ok);
        assert_eq!(paused.load(Ordering::SeqCst), 2);
        assert_eq!(
            toasts.borrow().as_slice(),
            &[("▶ Backgrounded — continuing.".into(), "info".into())]
        );
        assert!(!reg.foreground_present("tc1"));
        // nothing left → warning toast + false
        let ok2 = background_active_foreground(&reg, Some(&|m: &str, l: &str| {
            toasts.borrow_mut().push((m.to_string(), l.to_string()));
        }));
        assert!(!ok2);
        assert_eq!(toasts.borrow().len(), 2);
        assert_eq!(
            toasts.borrow()[1],
            ("No running foreground process to background.".into(), "warning".into())
        );
    }

    #[test]
    fn pause_all_is_silent() {
        let reg = Registry::new();
        let paused = Arc::new(AtomicUsize::new(0));
        let c = paused.clone();
        reg.set_foreground("tc", ForegroundSlot::new(move |r| {
            assert_eq!(r, BackgroundReason::Steer);
            c.fetch_add(1, Ordering::SeqCst);
        }));
        assert!(pause_all_foreground(&reg, BackgroundReason::Steer));
        assert_eq!(paused.load(Ordering::SeqCst), 1);
        assert!(!pause_all_foreground(&reg, BackgroundReason::Steer));
    }
}

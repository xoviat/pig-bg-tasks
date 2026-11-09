//! Port of `internal/bg/lifecycle.go` — the background orchestration entry
//! (done watcher, output-cap watcher, exit hand-off), terminal marking, the
//! silent-kill path, and small helpers.

use std::path::Path;
use std::sync::mpsc::{self, Receiver};
use std::sync::Arc;
use std::time::Duration;

use serde_json::json;

use crate::bg::handle::Exit;
use crate::bg::notify;
use crate::bg::registry::{Job, JobStatus, Registry};
use crate::bg::{KILL_GRACE_SECS, MAX_LOG_BYTES, OUTPUT_WATCH_INTERVAL_MS};

/// Enforce the concurrency cap (caller-side check before spawn).
pub fn assert_job_slot(reg: &Registry) -> Result<(), String> {
    if reg.at_concurrency_limit() {
        return Err(
            "Max concurrent background jobs (16) reached. \
             Stop or wait for existing jobs before starting new ones."
                .to_string(),
        );
    }
    Ok(())
}

/// Fail fast with the reference's wording.
pub fn require_existing_cwd(cwd: &str) -> Result<(), String> {
    if !Path::new(cwd).exists() {
        return Err(format!("Working directory does not exist: {cwd}"));
    }
    Ok(())
}

/// Whitespace-only commands would no-op in bash.
pub fn is_blank_command(command: &str) -> bool {
    command.trim().is_empty()
}

/// Map a spawn's terminal record: our kill → killed, exit 0 → completed,
/// else failed. (`killed` marks a kill WE initiated; Windows has no signal
/// half — the killer sets the flag.)
pub fn status_from_exit(e: &Exit) -> (JobStatus, Option<i32>) {
    match e {
        Exit { killed: true, code, .. } => (JobStatus::Killed, Some(*code)),
        Exit { err: Some(_), code, .. } if *code < 0 => (JobStatus::Failed, Some(*code)),
        Exit { code: 0, .. } => (JobStatus::Completed, Some(0)),
        Exit { code, .. } => (JobStatus::Failed, Some(*code)),
    }
}

/// Wire the completion watcher + output-cap watcher for a registered job.
/// Single entry point: `run_in_background` and promotion funnel through here.
pub fn start_background_job(reg: &Registry, job: &Arc<Job>, should_notify: bool) {
    start_cap_watcher_with(job, Duration::from_millis(OUTPUT_WATCH_INTERVAL_MS));
    if let Some(handle) = job.handle.clone() {
        let reg = reg.clone();
        let job = job.clone();
        std::thread::spawn(move || {
            let exit = handle.wait();
            complete_job(&reg, &job, exit, should_notify);
        });
    }
    render_status_pill(reg);
}

fn complete_job(reg: &Registry, job: &Arc<Job>, exit: Exit, should_notify: bool) {
    if job.is_terminal() {
        return;
    }
    let (status, code) = status_from_exit(&exit);
    job.mark_terminal(status, code);
    crate::bg::dbg::trace(json!({
        "phase": "bg_exit",
        "id": job.id,
        "status": status.as_str(),
        "code": exit.code,
        "killed": exit.killed,
        "notify": should_notify,
    }));
    if should_notify {
        notify::send_task_notification(reg, job);
    } else {
        job.set_notified();
        reg.forget(job);
    }
    render_status_pill(reg);
}

/// Close out a foreground call whose process has exited: terminal status +
/// eviction into the recent ring, NO task-notification (the result is the
/// tool response). Without this, foreground calls stayed "running" forever
/// and burned a concurrency slot. Guarded against a racing terminal mark.
pub fn finish_foreground_job(reg: &Registry, job: &Arc<Job>, exit: Exit) {
    if job.is_terminal() {
        return;
    }
    let (status, code) = status_from_exit(&exit);
    job.mark_terminal(status, code);
    job.set_notified();
    reg.forget(job);
    let mut rec = json!({
        "phase": "fg_terminal",
        "id": job.id,
        "status": status.as_str(),
        "code": exit.code,
        "killed": exit.killed,
        "age_ms": job.age_ms(),
    });
    if let Some(err) = &exit.err {
        rec["err"] = json!(err);
    }
    crate::bg::dbg::trace(rec);
    render_status_pill(reg);
}

/// Flip a running foreground command into a tracked background job
/// (Ctrl+Shift+B / timeout / steering).
pub fn promote_to_background(reg: &Registry, tool_call_id: &str, job: &Arc<Job>, should_notify: bool) {
    reg.remove_foreground(tool_call_id);
    job.set_backgrounded(true);
    reg.mark_started();
    start_background_job(reg, job, should_notify);
}

/// Record the stop reason and kill the tree (job object on Windows — the
/// whole tree, immediate; there is no SIGTERM on Windows).
pub fn terminate_job(job: &Arc<Job>, reason: &str) {
    if job.stop_reason().is_empty() && !reason.is_empty() {
        job.set_stop_reason(reason);
    }
    if let Some(h) = &job.handle {
        h.kill();
    }
}

/// Latch the outcome BEFORE the kill so the exit watcher's notification is
/// suppressed, flip status immediately, and signal when the process actually
/// died (or after the grace fallback). `bg_stop` / `session_shutdown` wait
/// on the returned receiver.
pub fn terminate_job_silently(
    reg: &Registry,
    job: &Arc<Job>,
    reason: &str,
) -> Receiver<()> {
    job.set_notified();
    terminate_job(job, reason);
    job.mark_terminal(JobStatus::Killed, None);
    reg.forget(job);
    let (tx, rx) = mpsc::channel();
    let reg = reg.clone();
    let job = job.clone();
    std::thread::spawn(move || {
        if let Some(h) = &job.handle {
            let deadline = Duration::from_secs(KILL_GRACE_SECS + 1);
            let started = std::time::Instant::now();
            loop {
                if h.try_wait().is_some() || started.elapsed() >= deadline {
                    break;
                }
                std::thread::sleep(Duration::from_millis(25));
            }
        }
        let _ = tx.send(());
        render_status_pill(&reg);
    });
    rx
}

/// Poll the log size; past `MAX_LOG_BYTES` append a marker and kill the task
/// so it cannot fill the disk.
fn start_cap_watcher(job: &Arc<Job>, interval: Duration) {
    let job = job.clone();
    std::thread::spawn(move || {
        loop {
            std::thread::sleep(interval);
            if job.is_done() {
                return;
            }
            let Ok(meta) = std::fs::metadata(&job.log_path) else {
                continue; // log not created yet
            };
            if meta.len() <= MAX_LOG_BYTES {
                continue;
            }
            // past the cap: marker + kill, then stop watching (the loop
            // exits here, so no separate tripped flag is needed)
            if let Ok(mut f) = std::fs::OpenOptions::new().append(true).open(&job.log_path) {
                use std::io::Write;
                let _ = f.write_all(
                    "\n[bg-tasks] output exceeded the 64 MiB limit — task killed\n"
                        .as_bytes(),
                );
            }
            job.set_stop_reason("output_limit");
            if let Some(h) = &job.handle {
                h.kill();
            }
            return;
        }
    });
}

/// Test hook: cap watcher with an injected poll interval.
#[cfg(test)]
pub(crate) fn start_cap_watcher_with(job: &Arc<Job>, interval: Duration) {
    start_cap_watcher(job, interval)
}

#[cfg(not(test))]
fn start_cap_watcher_with(job: &Arc<Job>, _interval: Duration) {
    start_cap_watcher(job, Duration::from_millis(OUTPUT_WATCH_INTERVAL_MS))
}

/// Refresh the status-bar counts (`▶ 2 · ✓ 3 · ✗ 1`); clears the key when
/// everything is idle.
pub fn render_status_pill(reg: &Registry) {
    let (running, done, failed) = reg.counters();
    let Some(port) = reg.notifier() else {
        return;
    };
    if running == 0 && done == 0 && failed == 0 {
        port.set_status("bg-tasks", "");
        return;
    }
    let mut parts: Vec<String> = Vec::new();
    if running > 0 {
        parts.push(format!("▶ {running}"));
    }
    if done > 0 {
        parts.push(format!("✓ {done}"));
    }
    if failed > 0 {
        parts.push(format!("✗ {failed}"));
    }
    port.set_status("bg-tasks", &parts.join(" · "));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bg::handle::{Exit, Handle};
    use crate::bg::mock::{MockHandle, MockPort};
    use crate::bg::port::SdkPort;

    fn await_done(job: &Job, ms: u64) -> bool {
        wait_until(ms, || job.is_done())
    }

    /// Poll until `cond` holds (watcher threads perform the latch/send/forget
    /// *after* the done broadcast, so tests must wait for the effect).
    fn wait_until(ms: u64, cond: impl Fn() -> bool) -> bool {
        let deadline = std::time::Instant::now() + Duration::from_millis(ms);
        loop {
            if cond() {
                return true;
            }
            if std::time::Instant::now() >= deadline {
                return false;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    #[test]
    fn status_from_exit_matrix() {
        assert!(matches!(status_from_exit(&Exit::killed(1)), (JobStatus::Killed, Some(1))));
        assert!(matches!(
            status_from_exit(&Exit::errored("boom")),
            (JobStatus::Failed, Some(-1))
        ));
        assert!(matches!(
            status_from_exit(&Exit::code(0)),
            (JobStatus::Completed, Some(0))
        ));
        assert!(matches!(
            status_from_exit(&Exit::code(7)),
            (JobStatus::Failed, Some(7))
        ));
    }

    #[test]
    fn helpers_match_reference_wording() {
        let r = Registry::new();
        assert!(assert_job_slot(&r).is_ok());
        // platform-neutral: an existing dir (temp) and a missing one
        let existing = std::env::temp_dir().to_string_lossy().into_owned();
        assert!(require_existing_cwd(&existing).is_ok());
        let missing =
            std::env::temp_dir().join("pi-lifecycle-no-such-dir").to_string_lossy().into_owned();
        assert_eq!(
            require_existing_cwd(&missing).unwrap_err(),
            format!("Working directory does not exist: {missing}")
        );
        assert!(is_blank_command("  \n\t"));
        assert!(!is_blank_command("x"));
    }

    #[test]
    fn background_completion_notifies_exactly_once() {
        let reg = Registry::new();
        let port = Arc::new(MockPort::new());
        reg.set_notifier(port.clone() as Arc<dyn SdkPort>);
        let handle = Arc::new(MockHandle::running());
        let job = reg.new_running_job("bash-l1", "sleep 999", Some(handle.clone()), "/tmp/l1.log", "tc", "", true);
        start_background_job(&reg, &job, true);
        handle.finish(Exit::code(0));
        assert!(await_done(&job, 2_000), "job never completed");
        assert_eq!(job.status(), JobStatus::Completed);
        assert!(wait_until(2_000, || port.send_count() == 1), "watcher must send");
        assert_eq!(port.send_count(), 1, "exactly one notification");
        assert!(port.contents()[0].contains("bash-l1"));
        assert!(reg.find_job("bash-l1").is_some(), "lingers until sweep");
        // second completion path is a no-op
        complete_job(&reg, &job, Exit::code(1), true);
        assert_eq!(port.send_count(), 1);
    }

    #[test]
    fn background_without_notify_latches_silently() {
        let reg = Registry::new();
        let port = Arc::new(MockPort::new());
        reg.set_notifier(port.clone() as Arc<dyn SdkPort>);
        let handle = Arc::new(MockHandle::running());
        let job = reg.new_running_job("bash-l2", "true", Some(handle.clone()), "/tmp/l2.log", "", "", true);
        start_background_job(&reg, &job, false);
        handle.finish(Exit::code(3));
        assert!(await_done(&job, 2_000));
        assert!(wait_until(2_000, || job.notified()), "watcher must latch");
        assert_eq!(port.send_count(), 0, "suppressed");
    }

    #[test]
    fn foreground_finish_no_notification_and_evicts() {
        let reg = Registry::new();
        let port = Arc::new(MockPort::new());
        reg.set_notifier(port.clone() as Arc<dyn SdkPort>);
        let job = reg.new_running_job("bash-f1", "echo", None, "/tmp/f1.log", "tc1", "", false);
        reg.set_foreground("tc1", crate::bg::registry::ForegroundSlot::new(|_| {}));
        assert!(reg.foreground_present("tc1"));
        finish_foreground_job(&reg, &job, Exit::code(0));
        assert_eq!(port.send_count(), 0);
        assert!(job.is_terminal());
        // evicted from live map → in recent ring → counters bumped
        let (_, done, _) = reg.counters();
        assert_eq!(done, 1);
        assert_eq!(job.status(), JobStatus::Completed);
    }

    #[test]
    fn promote_flips_foreground_to_background() {
        let reg = Registry::new();
        let handle = Arc::new(MockHandle::running());
        let job = reg.new_running_job("bash-p1", "cmd", Some(handle.clone()), "/tmp/p1.log", "tc9", "", false);
        reg.set_foreground("tc9", crate::bg::registry::ForegroundSlot::new(|_| {}));
        promote_to_background(&reg, "tc9", &job, false);
        assert!(!reg.foreground_present("tc9"));
        assert!(job.is_backgrounded());
        handle.finish(Exit::code(0));
        assert!(await_done(&job, 2_000));
        assert!(wait_until(2_000, || reg.counters().1 == 1), "watcher must forget");
        let (running_bg, done, _) = reg.counters();
        // job already terminal → not counted as running_bg; done counted on forget
        assert_eq!(running_bg, 0);
        assert_eq!(done, 1);
    }

    #[test]
    fn silent_terminate_latches_before_kill() {
        let reg = Registry::new();
        let port = Arc::new(MockPort::new());
        reg.set_notifier(port.clone() as Arc<dyn SdkPort>);
        let handle = Arc::new(MockHandle::running());
        let job = reg.new_running_job("bash-s1", "long", Some(handle.clone()), "/tmp/s1.log", "", "", true);
        start_background_job(&reg, &job, true);
        let gone = terminate_job_silently(&reg, &job, "user stop");
        gone.recv_timeout(Duration::from_secs(5)).expect("death signal");
        assert_eq!(job.status(), JobStatus::Killed);
        assert_eq!(job.stop_reason(), "user stop");
        assert!(handle.was_killed());
        assert_eq!(port.send_count(), 0, "silent path suppresses notification");
        // watcher completed → no notification either
        std::thread::sleep(Duration::from_millis(50));
        assert_eq!(port.send_count(), 0);
        assert!(handle.try_wait().is_some());
    }

    #[test]
    fn cap_watcher_kills_and_marks_reason() {
        let reg = Registry::new();
        let log = std::env::temp_dir().join("pi-bg-tasks-cap-test.log");
        let f = std::fs::File::create(&log).unwrap();
        f.set_len(MAX_LOG_BYTES + 1).unwrap();
        drop(f);
        let handle = Arc::new(MockHandle::running());
        let job = reg.new_running_job(
            "bash-cap",
            "chatty",
            Some(handle.clone()),
            log.to_str().unwrap(),
            "",
            "",
            true,
        );
        start_cap_watcher_with(&job, Duration::from_millis(20));
        let deadline = std::time::Instant::now() + Duration::from_secs(3);
        while !handle.was_killed() && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(handle.was_killed(), "cap watcher must kill the task");
        assert_eq!(job.stop_reason(), "output_limit");
        // read only the tail — the test file is 64 MiB
        use std::io::{Read, Seek, SeekFrom};
        let mut f = std::fs::File::open(&log).unwrap();
        f.seek(SeekFrom::End(-64)).unwrap();
        let mut tail = String::new();
        f.read_to_string(&mut tail).unwrap();
        assert!(tail.contains("output exceeded the 64 MiB limit"), "tail: {tail}");
        let _ = std::fs::remove_file(&log);
    }

    #[test]
    fn pill_renders_and_clears() {
        let reg = Registry::new();
        let port = Arc::new(MockPort::new());
        reg.set_notifier(port.clone() as Arc<dyn SdkPort>);
        let j = reg.new_running_job("bash-x", "c", None, "/tmp/x.log", "", "", true);
        render_status_pill(&reg);
        {
            let st = crate::bg::glock(&port.statuses);
            assert_eq!(st.last().unwrap().1, "▶ 1");
        }
        j.mark_terminal(JobStatus::Failed, Some(1));
        reg.forget(&j);
        render_status_pill(&reg);
        {
            let st = crate::bg::glock(&port.statuses);
            assert_eq!(st.last().unwrap().1, "✗ 1");
        }
        // no notifier → pill skipped silently (fresh registry)
        let fresh = Registry::new();
        render_status_pill(&fresh);
    }

    #[test]
    fn exit_watcher_thread_is_independent() {
        // A handle with no terminal publication must not block anything but
        // its own watcher thread; completion happens exactly once.
        let reg = Registry::new();
        let port = Arc::new(MockPort::new());
        reg.set_notifier(port.clone() as Arc<dyn SdkPort>);
        let h: Arc<dyn Handle> = Arc::new(MockHandle::running());
        let job = reg.new_running_job("bash-t", "x", Some(h.clone()), "/tmp/t.log", "", "", true);
        start_background_job(&reg, &job, true);
        h.kill();
        assert!(await_done(&job, 2_000));
        assert!(wait_until(2_000, || port.send_count() == 1), "watcher must send");
        assert_eq!(port.send_count(), 1);
    }
}

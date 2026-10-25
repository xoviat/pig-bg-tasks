//! Port of `internal/bg/notify.go` — task-completion notifications.
//!
//! Exactly-once is a check-and-set latch done BEFORE the send: any path that
//! already surfaced the outcome (`bg_output`/`bg_stop` read, deliberate kill)
//! suppresses the notification. A send failure loses the notification rather
//! than retrying (exactly-once); the job lingers until `bg_list`'s sweep.

use std::sync::Arc;

use serde_json::json;

use crate::bg::output;
use crate::bg::port::{CustomMessage, SendOptions};
use crate::bg::registry::{Job, JobStatus, Registry};

/// Identifies the steered message for renderers.
pub const TASK_NOTIFICATION_CUSTOM_TYPE: &str = "bg-task-notification";

/// Escape element text.
pub fn escape_xml(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;")
}

/// Collapse whitespace runs to single spaces.
pub fn one_line(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Truncate to `n` characters with an ellipsis (Go's rune truncation).
pub(crate) fn truncate_chars(s: &str, n: usize) -> String {
    if s.chars().count() > n {
        let head: String = s.chars().take(n).collect();
        format!("{head}…")
    } else {
        s.to_string()
    }
}

/// The human/agent label: the name when set, else the command collapsed to
/// one line and truncated at 80 runes.
pub fn describe_job(job: &Job) -> String {
    if !job.name.is_empty() {
        return job.name.clone();
    }
    truncate_chars(&one_line(&job.command), 80)
}

/// The one-sentence outcome for a terminal job.
pub fn completion_summary(job: &Job) -> String {
    let desc = describe_job(job);
    if job.stop_reason() == "output_limit" {
        return format!("Background command \"{desc}\" was stopped: output exceeded the size limit");
    }
    match job.status() {
        JobStatus::Killed | JobStatus::TimedOut => {
            format!("Background command \"{desc}\" was stopped")
        }
        JobStatus::Failed => {
            let code = job
                .exit_code()
                .map(|c| c.to_string())
                .unwrap_or_else(|| "unknown".to_string());
            format!("Background command \"{desc}\" failed with exit code {code}")
        }
        // Go's default arm covers completed (and any unknown): a non-zero
        // exit on completion is called out.
        _ => match job.exit_code() {
            Some(c) if c != 0 => {
                format!("Background command \"{desc}\" completed (exit code {c})")
            }
            _ => format!("Background command \"{desc}\" completed"),
        },
    }
}

/// Render the `<task-notification>` XML block.
pub fn build_task_notification(job: &Job, summary: &str) -> String {
    let tail = output::read_bounded_tail(&job.log_path, crate::bg::NOTIFY_TAIL_CHARS)
        .trim()
        .to_string();
    let tail = output::strip_ansi(&tail);
    let tail = tail.trim().to_string();
    let mut b = String::new();
    b.push_str("<task-notification>\n");
    b.push_str(&format!("<task_id>{}</task_id>\n", escape_xml(&job.id)));
    b.push_str(&format!(
        "<status>{}</status>\n",
        escape_xml(job.status().as_str())
    ));
    b.push_str(&format!(
        "<command>{}</command>\n",
        escape_xml(&one_line(&job.command))
    ));
    if let Some(code) = job.exit_code() {
        b.push_str(&format!("<exit_code>{code}</exit_code>\n"));
    }
    b.push_str(&format!(
        "<output_file>{}</output_file>\n",
        escape_xml(&job.log_path)
    ));
    b.push_str(&format!("<summary>{}</summary>\n", escape_xml(summary)));
    if !tail.is_empty() && tail != "(no output yet)" {
        b.push_str(&format!(
            "<tail_preview>{}</tail_preview>\n",
            escape_xml(&tail)
        ));
    }
    b.push_str("</task-notification>");
    b
}

/// Latch then steer the notification into the agent loop
/// (deliverAs=steer, triggerTurn=true). Returns whether it was sent.
pub fn send_task_notification(reg: &Registry, job: &Arc<Job>) -> bool {
    // Check-and-set latch, exactly-once (atomic on the job's state mutex).
    if !job.try_latch_notified() {
        return false;
    }
    let Some(port) = reg.notifier() else {
        // No retained context (session never started): lose the notification
        // (exactly-once, never retried) but still evict.
        reg.forget(job);
        return false;
    };
    let summary = completion_summary(job);
    let msg = CustomMessage {
        custom_type: TASK_NOTIFICATION_CUSTOM_TYPE.to_string(),
        content: build_task_notification(job, &summary),
        display: true,
        details: json!({
            "jobId": job.id,
            "status": job.status().as_str(),
            "summary": summary,
            "outputFile": job.log_path,
        }),
    };
    if port.send_custom_message(msg, SendOptions::steer()).is_err() {
        // lost rather than retried (parity) — latched, so the lazy sweep
        // still evicts later.
        return false;
    }
    reg.forget(job);
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bg::mock::MockPort;
    use crate::bg::port::SdkPort;
    use crate::bg::registry::Registry;

    fn job_with(reg: &Registry, id: &str, cmd: &str) -> Arc<Job> {
        reg.new_running_job(id, cmd, None, "/tmp/n.log", "tc", "", true)
    }

    #[test]
    fn xml_escaping_and_oneline() {
        assert_eq!(escape_xml("a<b>&c"), "a&lt;b&gt;&amp;c");
        assert_eq!(one_line("  a\t b\n c  "), "a b c");
        assert_eq!(describe_job(&job_with(&Registry::new(), "bash-x", "ls -la")), "ls -la");
        let long = "x".repeat(200);
        assert_eq!(describe_job(&job_with(&Registry::new(), "bash-x", &long)).chars().count(), 81);
    }

    #[test]
    fn summaries_match_reference() {
        let reg = Registry::new();
        let j = job_with(&reg, "bash-s", "make");
        j.mark_terminal(crate::bg::registry::JobStatus::Completed, Some(0));
        assert_eq!(completion_summary(&j), "Background command \"make\" completed");
        let j = job_with(&reg, "bash-s2", "make");
        j.mark_terminal(crate::bg::registry::JobStatus::Completed, Some(2));
        assert_eq!(
            completion_summary(&j),
            "Background command \"make\" completed (exit code 2)"
        );
        let j = job_with(&reg, "bash-s3", "make");
        j.mark_terminal(crate::bg::registry::JobStatus::Failed, Some(2));
        assert_eq!(
            completion_summary(&j),
            "Background command \"make\" failed with exit code 2"
        );
        let j = job_with(&reg, "bash-s4", "make");
        j.mark_terminal(crate::bg::registry::JobStatus::Killed, None);
        assert_eq!(completion_summary(&j), "Background command \"make\" was stopped");
        let j = job_with(&reg, "bash-s5", "make");
        j.mark_terminal(crate::bg::registry::JobStatus::Failed, Some(1));
        j.set_stop_reason("output_limit");
        assert_eq!(
            completion_summary(&j),
            "Background command \"make\" was stopped: output exceeded the size limit"
        );
    }

    #[test]
    fn notification_xml_shape() {
        let reg = Registry::new();
        let j = job_with(&reg, "bash-abc123", "echo <hi> & bye");
        j.mark_terminal(crate::bg::registry::JobStatus::Completed, Some(0));
        let xml = build_task_notification(&j, "Background command \"echo\" completed");
        assert!(xml.starts_with("<task-notification>\n"));
        assert!(xml.contains("<task_id>bash-abc123</task_id>"));
        assert!(xml.contains("<status>completed</status>"));
        assert!(xml.contains("<exit_code>0</exit_code>"));
        assert!(xml.contains("<command>echo &lt;hi&gt; &amp; bye</command>"));
        assert!(xml.contains("<summary>"));
        assert!(!xml.contains("<tail_preview>"), "no output yet → no preview");
        assert!(xml.ends_with("</task-notification>"));
    }

    #[test]
    fn exactly_once_latch() {
        let reg = Registry::new();
        let port = Arc::new(MockPort::new());
        reg.set_notifier(port.clone() as Arc<dyn SdkPort>);
        let j = job_with(&reg, "bash-eo", "x");
        j.mark_terminal(crate::bg::registry::JobStatus::Completed, Some(0));
        assert!(send_task_notification(&reg, &j));
        assert!(!send_task_notification(&reg, &j), "second send suppressed");
        assert_eq!(port.send_count(), 1);
        // already latched by bg_output/bg_stop → no send
        let j2 = job_with(&reg, "bash-eo2", "x");
        j2.mark_terminal(crate::bg::registry::JobStatus::Completed, Some(0));
        reg.latch_terminal(&j2);
        assert!(!send_task_notification(&reg, &j2));
        assert_eq!(port.send_count(), 1);
    }

    #[test]
    fn send_failure_loses_but_sweep_evicts() {
        let reg = Registry::new();
        let port = Arc::new(MockPort::new());
        port.set_fail_send(true);
        reg.set_notifier(port.clone() as Arc<dyn SdkPort>);
        let j = job_with(&reg, "bash-fail", "x");
        j.mark_terminal(crate::bg::registry::JobStatus::Failed, Some(9));
        assert!(!send_task_notification(&reg, &j), "failure is not a send");
        assert_eq!(port.send_count(), 0);
        assert!(j.notified(), "latched anyway");
        {
            let (_, terminal, _) = reg.snapshot();
            assert!(
                terminal.iter().any(|x| x.id == "bash-fail"),
                "stays in the live map until sweep"
            );
        }
        reg.sweep_notified_terminal();
        {
            let (_, terminal, _) = reg.snapshot();
            assert!(terminal.is_empty(), "swept out of the live map");
        }
        // still visible via the recent ring (find_job searches it)
        assert!(reg.find_job("bash-fail").is_some());
        let (_, done, failed) = reg.counters();
        assert_eq!((done, failed), (0, 1));
    }

    #[test]
    fn no_notifier_loses_but_evicts() {
        let reg = Registry::new();
        let j = job_with(&reg, "bash-nonote", "x");
        j.mark_terminal(crate::bg::registry::JobStatus::Completed, Some(0));
        assert!(!send_task_notification(&reg, &j));
        assert!(j.notified());
        let (_, done, _) = reg.counters();
        assert_eq!(done, 1, "forgotten despite the lost send");
    }
}

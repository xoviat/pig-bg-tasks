//! The child side of the link (DELEGATED-WORKSPACES §B.2): `PIG_PARENT_SESSION`
//! names the immediate parent's session, therefore the endpoint to dial. The
//! child fetches the parent's sandbox policy once at session start (policy
//! inheritance) and, on a headless escalation, kicks the approval up and
//! blocks on the reply. The same socket runs the other way too: the parent
//! pushes a changed permission level down as `op:"policy-update"`
//! ([`push_policy`]). Every failure is fail-closed: no listener, a timeout
//! or a malformed reply means the escalation is denied.

use std::time::Duration;

use serde_json::{Value, json};

use crate::link::{ASK_TIMEOUT, Ask, Policy, PROTOCOL_VERSION, Stream, read_line, write_line};

/// One settled answer from the parent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AskOutcome {
    /// What the parent's user said: `"allow"` | `"deny"` | `"cancel"`.
    pub decision: String,
    pub reason: String,
    pub answered_by: String,
}

impl AskOutcome {
    pub fn allow(&self) -> bool {
        self.decision == "allow"
    }
}

const DIAL_INTERVAL: Duration = Duration::from_millis(250);

/// A read deadline (`SO_RCVTIMEO`) surfaces as `WouldBlock`/`TimedOut`.
fn is_timeout(e: &std::io::Error) -> bool {
    matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut)
}

/// One request over a fresh connection to `session_id`'s single endpoint
/// (see [`crate::link::endpoint`]). Connect/read failures are retried
/// across `attempts` rounds (the peer's listener may still be starting);
/// a peer that *answered* is final — its verdict (or refusal) is never
/// retried.
///
/// `who` names the peer in messages (`"parent"` → "parent session <id>"),
/// and `timeout_tail` is what a deadline appends: the ask path promises
/// "the escalation stays denied", a policy push has no escalation to deny.
fn request(
    session_id: &str,
    who: &str,
    payload: &Value,
    read_timeout: Duration,
    attempts: u32,
    timeout_tail: &str,
) -> Result<Value, String> {
    let ep = crate::link::endpoint(session_id);
    if !crate::link::fits(&ep) {
        return Err(format!(
            "endpoint for {who} session {session_id} does not fit this platform's socket path limit"
        ));
    }
    let mut last = String::new();
    for round in 0..attempts.max(1) {
        if round > 0 {
            // The parent's listener may still be starting: a short pause
            // between dial rounds (never inside a round — a refused connect
            // is instant).
            std::thread::sleep(DIAL_INTERVAL);
        }
        let mut stream = match Stream::connect(&ep) {
            Ok(s) => s,
            Err(e) => {
                last = format!("{}: {e}", ep.display());
                continue;
            }
        };
        if let Err(e) = stream.set_read_timeout(Some(read_timeout)) {
            last = format!("{}: timeout setup failed: {e}", ep.display());
            continue;
        }
        if let Err(e) = write_line(&mut stream, &payload.to_string()) {
            last = format!("{}: write failed: {e}", ep.display());
            continue;
        }
        let line = match read_line(&mut stream) {
            Ok(l) => l,
            // The deadline hit: the peer had its whole window to
            // answer — retrying would triple the child's block time
            // (and re-send an ask the parent is still waiting on).
            Err(e) if is_timeout(&e) => {
                return Err(format!(
                    "timed out after {}s waiting for an answer from {who} session {session_id}{timeout_tail}",
                    read_timeout.as_secs()
                ));
            }
            Err(e) => {
                last = format!("{}: read failed: {e}", ep.display());
                continue;
            }
        };
        let reply: Value = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(_) => {
                return Err(format!(
                    "malformed reply from {who} session {session_id} (expected one JSON object)"
                ));
            }
        };
        if reply.get("ok").and_then(Value::as_bool) == Some(true) {
            return Ok(reply);
        }
        return Err(
            reply
                .get("error")
                .and_then(Value::as_str)
                .unwrap_or("the peer refused the request")
                .to_string(),
        );
    }
    Err(format!(
        "no pig-bg-tasks listener reachable for {who} session {session_id} ({last})"
    ))
}

/// Ask the parent for its sandbox policy at session start. `None` = the
/// parent is unreachable (an older host, a stale marker): the child keeps
/// its own local policy — it never widens by being unreachable.
pub fn fetch_policy(parent_session: &str, child_session: &str) -> Option<Policy> {
    let payload = json!({
        "v": PROTOCOL_VERSION,
        "op": "policy",
        "child": {"session": child_session, "pid": std::process::id()},
    });
    // Short reads, a few dials: the parent's listener may be mid-startup.
    match request(
        parent_session,
        "parent",
        &payload,
        Duration::from_secs(10),
        5,
        "",
    ) {
        Ok(reply) => {
            let policy = reply.get("policy").and_then(Policy::from_value);
            if policy.is_none() {
                crate::bg::dbg::trace(json!({
                    "phase": "link_policy_malformed", "parent": parent_session
                }));
            }
            policy
        }
        Err(e) => {
            crate::bg::dbg::trace(json!({
                "phase": "link_policy_unreachable", "parent": parent_session, "err": e
            }));
            None
        }
    }
}

/// Push this session's current policy to one child over **that child's**
/// socket (the same endpoint derivation, `op:"policy-update"`): how a
/// parent's widened or narrowed permission level reaches a child that
/// already mirrored it at its `session_start`. One short dial, no retry
/// storm — a child that is gone is reported to the caller, which traces
/// it and moves on to the next child.
pub fn push_policy(
    child_session: &str,
    parent_session: &str,
    policy: &Policy,
) -> Result<Value, String> {
    let payload = json!({
        "v": PROTOCOL_VERSION,
        "op": "policy-update",
        "parent": parent_session,
        "policy": policy.to_value(),
    });
    request(
        child_session,
        "child",
        &payload,
        Duration::from_secs(2),
        1,
        "",
    )
}

/// What a [`Watch`] read produced: an event frame, a deadline with
/// nothing pending, or a link that went away.
#[derive(Debug, Clone, PartialEq)]
pub enum Event {
    /// One frame from the peer (a `task-busy` flip).
    Frame(Value),
    /// The deadline passed with no event — the subscription is healthy.
    Timeout,
    /// The connection closed, broke, or carried something that is not one
    /// JSON object per line (fail-closed: the caller re-subscribes).
    Closed,
}

/// A live `watch-tasks` subscription: the ack's snapshot plus the event
/// frames that follow it on this one connection.
pub struct Watch {
    stream: Stream,
    busy: bool,
}

/// The stream is not `Debug`; the subscription's observable state is.
impl std::fmt::Debug for Watch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Watch").field("busy", &self.busy).finish()
    }
}

impl Watch {
    /// The busy state the ack snapshot reported — the link's newest known
    /// state at subscribe time.
    pub fn busy(&self) -> bool {
        self.busy
    }

    /// Wait up to `timeout` for the next event frame.
    pub fn recv(&mut self, timeout: Duration) -> Event {
        if self.stream.set_read_timeout(Some(timeout)).is_err() {
            return Event::Closed;
        }
        match read_line(&mut self.stream) {
            Ok(line) => match serde_json::from_str::<Value>(&line) {
                Ok(v) => Event::Frame(v),
                Err(_) => Event::Closed,
            },
            Err(e) if is_timeout(&e) => Event::Timeout,
            Err(_) => Event::Closed,
        }
    }
}

/// Subscribe to `session_id`'s task busy-state notifications: the reply
/// ack carries the current state (`busy` — a task is running — or not),
/// then one `task-busy` event frame per flip arrives on this same
/// connection until the subscriber drops it or the link stops. `Err` = no
/// listener / refusal (fail-closed, like every other op).
pub fn watch_tasks(session_id: &str) -> Result<Watch, String> {
    let ep = crate::link::endpoint(session_id);
    if !crate::link::fits(&ep) {
        return Err(format!(
            "endpoint for parent session {session_id} does not fit this platform's socket path limit"
        ));
    }
    let payload = json!({"v": PROTOCOL_VERSION, "op": "watch-tasks"});
    let mut last = String::new();
    for round in 0..5u32 {
        if round > 0 {
            std::thread::sleep(DIAL_INTERVAL);
        }
        let mut stream = match Stream::connect(&ep) {
            Ok(s) => s,
            Err(e) => {
                last = format!("{}: {e}", ep.display());
                continue;
            }
        };
        if let Err(e) = stream.set_read_timeout(Some(Duration::from_secs(10))) {
            last = format!("{}: timeout setup failed: {e}", ep.display());
            continue;
        }
        if let Err(e) = write_line(&mut stream, &payload.to_string()) {
            last = format!("{}: write failed: {e}", ep.display());
            continue;
        }
        let line = match read_line(&mut stream) {
            Ok(l) => l,
            Err(e) if is_timeout(&e) => {
                return Err(format!(
                    "timed out after 10s waiting for a watch ack from parent session {session_id}"
                ));
            }
            Err(e) => {
                last = format!("{}: read failed: {e}", ep.display());
                continue;
            }
        };
        let reply: Value = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(_) => {
                return Err(format!(
                    "malformed watch ack from parent session {session_id} (expected one JSON object)"
                ));
            }
        };
        if reply.get("ok").and_then(Value::as_bool) != Some(true) {
            return Err(
                reply
                    .get("error")
                    .and_then(Value::as_str)
                    .unwrap_or("the peer refused the request")
                    .to_string(),
            );
        }
        let busy = reply.get("busy").and_then(Value::as_bool).ok_or_else(|| {
            format!("malformed watch ack from parent session {session_id} (no busy state)")
        })?;
        return Ok(Watch { stream, busy });
    }
    Err(format!(
        "no pig-bg-tasks listener reachable for parent session {session_id} ({last})"
    ))
}

/// Kick one escalation approval up to the parent and block for its answer
/// (up to [`ASK_TIMEOUT`]).
pub fn ask(parent_session: &str, ask: &Ask) -> Result<AskOutcome, String> {
    ask_with_timeout(parent_session, ask, ASK_TIMEOUT)
}

/// [`ask`] with an explicit deadline (tests use a short one).
pub fn ask_with_timeout(
    parent_session: &str,
    ask: &Ask,
    timeout: Duration,
) -> Result<AskOutcome, String> {
    let payload = json!({
        "v": PROTOCOL_VERSION,
        "op": "ask",
        "ask": ask.to_value(),
    });
    let reply = match request(
        parent_session,
        "parent",
        &payload,
        timeout,
        3,
        " — the escalation stays denied",
    ) {
        Ok(reply) => reply,
        Err(e) => {
            // Same visibility the policy fetch has (`link_policy_unreachable`):
            // a refused escalation used to leave no trace on this side.
            crate::bg::dbg::trace(json!({
                "phase": "link_ask_unreachable", "parent": parent_session,
                "ask": ask.uuid, "err": e
            }));
            return Err(e);
        }
    };
    let decision = reply
        .get("decision")
        .and_then(Value::as_str)
        .filter(|d| matches!(*d, "allow" | "deny" | "cancel"))
        .ok_or_else(|| {
            format!(
                "malformed decision from parent session {parent_session}: {}",
                reply.get("decision").and_then(Value::as_str).unwrap_or("missing")
            )
        })?;
    Ok(AskOutcome {
        decision: decision.to_string(),
        reason: reply
            .get("reason")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string(),
        answered_by: reply
            .get("answeredBy")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unreachable_parent_fails_closed_fast() {
        let _t = crate::link::test_mu::lock();
        // Nothing is listening on this session's tmp socket: no policy, and
        // an ask errors (deny) instead of hanging or panicking.
        assert!(fetch_policy("no-such-session", "child").is_none());
        let ask = Ask {
            uuid: "x".into(),
            mode: "danger-full-access".into(),
            summary: "s".into(),
            justification: "j".into(),
            title: String::new(),
            child_session: "child".into(),
            child_pid: 1,
            started_at_ms: 0,
        };
        let e = ask_with_timeout(
            "no-such-session",
            &ask,
            Duration::from_millis(500),
        )
        .unwrap_err();
        assert!(e.contains("no pig-bg-tasks listener reachable"), "{e}");
        // the push half of the same socket fails the same way (fail-closed)
        let policy = Policy {
            mode: "read-only".into(),
            workspace: String::new(),
            temp: String::new(),
            extras: vec![],
        };
        let e = push_policy("no-such-session", "parent", &policy).unwrap_err();
        assert!(e.contains("no pig-bg-tasks listener reachable"), "{e}");
    }
}

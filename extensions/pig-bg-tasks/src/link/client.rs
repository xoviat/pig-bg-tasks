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
    let reply = request(
        parent_session,
        "parent",
        &payload,
        timeout,
        3,
        " — the escalation stays denied",
    )?;
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

//! Port of `internal/ledger` — the denial-first gate's per-session denial
//! record. A real sandbox denial records one entry; the next escalation
//! request for the same session + kind consumes it (exactly once). Without an
//! unconsumed record, escalation fields are ignored — the hard "no escalation
//! before a denial" constraint that stops preemptive approval prompts.
//!
//! The extension runs as ONE process, so a static map is the process-wide
//! singleton (the reference needed `globalThis` for per-session module
//! instances; not applicable here).

use std::collections::{HashMap, HashSet};
use std::sync::{LazyLock, Mutex};

/// Mirrors the reference's `DenialKind` (bash-only build: always "command").
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Kind {
    Command,
    Operation,
}

impl Kind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Kind::Command => "command",
            Kind::Operation => "operation",
        }
    }
}

static PENDING: LazyLock<Mutex<HashMap<String, HashSet<Kind>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

fn lock() -> std::sync::MutexGuard<'static, HashMap<String, HashSet<Kind>>> {
    PENDING.lock().unwrap_or_else(|e| e.into_inner())
}

/// Store a denial (idempotent per session+kind).
pub fn record(session_id: &str, kind: Kind) {
    if session_id.is_empty() {
        return;
    }
    lock().entry(session_id.to_string()).or_default().insert(kind);
}

/// Spend one record; false when none exists. One-shot.
pub fn consume(session_id: &str, kind: Kind) -> bool {
    if session_id.is_empty() {
        return false;
    }
    let mut g = lock();
    let Some(set) = g.get_mut(session_id) else {
        return false;
    };
    if !set.remove(&kind) {
        return false;
    }
    if set.is_empty() {
        g.remove(session_id);
    }
    true
}

/// Drop a session's records (session shutdown / child disposal).
pub fn forget(session_id: &str) {
    lock().remove(session_id);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_consume_is_exactly_once() {
        let s = "sess-lifecycle-test";
        forget(s);
        assert!(!consume(s, Kind::Command), "nothing recorded yet");
        record(s, Kind::Command);
        record(s, Kind::Command); // idempotent
        assert!(consume(s, Kind::Command), "first consume spends it");
        assert!(!consume(s, Kind::Command), "second consume fails");
        assert!(consume(s, Kind::Command) == false);
        forget(s);
    }

    #[test]
    fn kinds_are_independent() {
        let s = "sess-kinds";
        forget(s);
        record(s, Kind::Operation);
        assert!(!consume(s, Kind::Command));
        assert!(consume(s, Kind::Operation));
        forget(s);
    }

    #[test]
    fn empty_session_ids_are_noops() {
        record("", Kind::Command);
        assert!(!consume("", Kind::Command));
        forget("");
    }

    #[test]
    fn forget_drops_session() {
        let s = "sess-forget";
        record(s, Kind::Command);
        forget(s);
        assert!(!consume(s, Kind::Command));
    }
}

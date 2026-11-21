//! The parent link: one OS socket per session between the pig-bg-tasks
//! hosted in a parent session and the pig-bg-tasks of a child process the
//! subprocess plugin (pi-subagents) launched. AF_UNIX on every platform —
//! including Windows (winsock `AF_UNIX`, maintainer directive; the same
//! `net.Listen("unix")` shape the Go link uses).
//!
//! Contract (DELEGATED-WORKSPACES §B):
//!
//! - **Parent side** ([`server`]): at `session_start` this session's id —
//!   from the SDK (`ctx.get_session_id()`) — names the endpoint; an accept
//!   loop serves one connection per request and answers `policy` (this
//!   session's sandbox policy) and `ask` (a delegated child's escalation,
//!   which this session's user answers through this session's own dialog).
//!   One socket transports *everything*: when this session's permission
//!   level widens or narrows, the same endpoint pushes the new level out
//!   as `op:"policy-update"` to every child that fetched a policy.
//! - **Child side** ([`client`]): the presence of `PIG_PARENT_SESSION` in
//!   the environment is what *makes* a session a child — it names the
//!   immediate parent's session and therefore the endpoint to dial. A
//!   session may be a child and a parent at the same time: the listener
//!   always starts for the SDK session id, and the client starts when the
//!   marker is set. A `policy-update` from its parent re-baselines the
//!   mirrored policy ([`crate::policy::inherit`]).
//! - **Fail-closed**: connect failure, timeout, or a malformed reply denies
//!   the escalation (the child runs confined instead of unapproved).
//!
//! There is exactly **one** endpoint per session — the OS temp dir holds
//! [`endpoint`]'s socket file — so parent and child derive the same path
//! from knowledge they already share (no config root to agree on).
//!
//! Wire: one JSON object per line, versioned by `v`.
//! Requests are `{"v":1,"op":"policy"|"ask"|"policy-update", …}`; replies are
//! `{"v":1,"ok":true, …}` or `{"v":1,"ok":false,"error":"…"}`.

pub mod client;
pub mod server;

#[cfg(unix)]
mod transport_unix;
#[cfg(windows)]
mod transport_win;

#[cfg(unix)]
use transport_unix as transport;
#[cfg(windows)]
use transport_win as transport;

pub use transport::{Listener, Stream};

/// One shared lock for the tests that touch the process-global listener and
/// ask registry (the link is process-wide, like the registry it serves).
#[cfg(test)]
pub(crate) mod test_mu {
    pub fn lock() -> std::sync::MutexGuard<'static, ()> {
        static MU: std::sync::Mutex<()> = std::sync::Mutex::new(());
        MU.lock().unwrap_or_else(|e| e.into_inner())
    }
}

use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

/// The single provenance marker: the session id of the session that
/// delegated this child. Its presence makes this session a child.
pub const PARENT_SESSION_ENV: &str = "PIG_PARENT_SESSION";

/// Wire version.
pub const PROTOCOL_VERSION: u64 = 1;

/// Child side: how long an `ask` waits for the parent's decision before it
/// fails closed (deny).
pub const ASK_TIMEOUT: Duration = Duration::from_secs(300);

/// Read/write budget for one connection's request frame.
pub const IO_TIMEOUT: Duration = Duration::from_secs(10);

/// Windows AF_UNIX `sun_path` is 108 bytes including the terminator;
/// macOS `sockaddr_un.sun_path` is 104. An endpoint at or over this length
/// cannot bind or connect on either platform, so both ends refuse it
/// deterministically — one socket, refused the same way on both sides.
const MAX_ENDPOINT_BYTES: usize = 100;

/// One request/reply frame.
const MAX_LINE_BYTES: usize = 256 * 1024;

/// This process's parent marker, if set: the session id of the immediate
/// parent. Empty/whitespace counts as unset.
pub fn parent_session() -> Option<String> {
    std::env::var(PARENT_SESSION_ENV)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// Whether this session is a delegated child (marker present).
pub fn is_child() -> bool {
    parent_session().is_some()
}

/// Session ids are uuids, but the endpoint name is a file path: keep only
/// path-safe characters so a hostile id cannot escape the directory.
pub fn safe_id(session_id: &str) -> String {
    let mut out = String::with_capacity(session_id.len());
    for c in session_id.chars() {
        if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
            out.push(c);
        } else {
            out.push('-');
        }
    }
    if out.is_empty() {
        out.push('-');
    }
    out
}

/// The socket directory: the **OS temp dir** (`%TEMP%` on Windows,
/// `$TMPDIR`/`/tmp` otherwise). One directory both ends already agree on —
/// a parent and its child derive the same path even when their config
/// roots differ, so this is the whole location agreement there is.
pub fn socket_dir() -> PathBuf {
    std::env::temp_dir()
}

/// The single agreed endpoint: `<socketDir>/pig-sandbox-<id>.sock`. One
/// socket per session transports everything that crosses the link — the
/// child's `policy` fetch, the `ask` relay, and the parent's
/// `policy-update` when its permission level changes. Both ends derive it
/// from the session id; the location is agreed on, never passed.
pub fn endpoint(session_id: &str) -> PathBuf {
    socket_dir().join(format!("pig-sandbox-{}.sock", safe_id(session_id)))
}

/// Whether `p` fits the platform's socket address limit (see
/// [`MAX_ENDPOINT_BYTES`]); a session whose endpoint does not fit gets no
/// link at all, refused identically on both sides.
pub fn fits(p: &Path) -> bool {
    p.to_string_lossy().len() < MAX_ENDPOINT_BYTES
}

/// Read one `\n`-terminated frame (bounded, `\r` tolerated).
pub fn read_line(s: &mut Stream) -> io::Result<String> {
    let mut buf: Vec<u8> = Vec::with_capacity(256);
    let mut chunk = [0u8; 4096];
    loop {
        let n = s.read(&mut chunk)?;
        if n == 0 {
            if buf.is_empty() {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "peer closed the link"));
            }
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
        if let Some(pos) = buf.iter().position(|&b| b == b'\n') {
            buf.truncate(pos);
            break;
        }
        if buf.len() > MAX_LINE_BYTES {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "link frame too large"));
        }
    }
    while buf.last() == Some(&b'\r') {
        buf.pop();
    }
    String::from_utf8(buf)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "link frame is not UTF-8"))
}

/// Write one `\n`-terminated frame.
pub fn write_line(s: &mut Stream, line: &str) -> io::Result<()> {
    s.write_all(line.as_bytes())?;
    s.write_all(b"\n")?;
    s.flush()
}

/// What the parent's user decided about a relayed ask — the parent asks
/// through its own dialog (the same Deny-first select a local escalation
/// shows), so the answer arrives in the child's ladder vocabulary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    Allow,
    /// Refused; the reason reaches the child's byte-stable wording.
    Deny(String),
    /// The dialog was dismissed without an answer — nothing approved.
    Cancelled,
}

impl Verdict {
    /// The reply frame's `decision` + `reason` fields.
    pub fn to_reply(&self) -> serde_json::Value {
        match self {
            Verdict::Allow => serde_json::json!({"decision": "allow", "reason": ""}),
            Verdict::Deny(reason) => {
                serde_json::json!({"decision": "deny", "reason": reason})
            }
            Verdict::Cancelled => {
                serde_json::json!({"decision": "cancel", "reason": ""})
            }
        }
    }

    /// Parse the reply frame (`Err` on anything unrecognized — the caller
    /// fails closed).
    pub fn from_reply(v: &serde_json::Value) -> Result<Verdict, String> {
        let reason = v
            .get("reason")
            .and_then(|r| r.as_str())
            .unwrap_or("")
            .to_string();
        match v.get("decision").and_then(|d| d.as_str()) {
            Some("allow") => Ok(Verdict::Allow),
            Some("deny") => Ok(Verdict::Deny(reason)),
            Some("cancel") => Ok(Verdict::Cancelled),
            other => Err(format!(
                "malformed decision from the parent session: {}",
                other.unwrap_or("missing")
            )),
        }
    }
}

/// This session's sandbox policy, as the parent reports it over the link.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Policy {
    pub mode: String,
    pub workspace: String,
    pub temp: String,
    pub extras: Vec<String>,
}

impl Policy {
    pub fn to_value(&self) -> serde_json::Value {
        serde_json::json!({
            "mode": self.mode,
            "workspace": self.workspace,
            "temp": self.temp,
            "extras": self.extras,
        })
    }

    pub fn from_value(v: &serde_json::Value) -> Option<Policy> {
        Some(Policy {
            mode: v.get("mode")?.as_str()?.to_string(),
            workspace: v.get("workspace").and_then(|x| x.as_str()).unwrap_or("").to_string(),
            temp: v.get("temp").and_then(|x| x.as_str()).unwrap_or("").to_string(),
            extras: v
                .get("extras")
                .and_then(|x| x.as_array())
                .map(|a| a.iter().filter_map(|e| e.as_str()).map(String::from).collect())
                .unwrap_or_default(),
        })
    }
}

/// One escalation approval a child kicks up to its parent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ask {
    /// Correlation id between the child's ask and the parent's dialog.
    pub uuid: String,
    /// Requested mode (`workspace-write` | `danger-full-access`).
    pub mode: String,
    /// Command preview.
    pub summary: String,
    /// The model's one-sentence justification.
    pub justification: String,
    /// The byte-stable dialog title the interactive path would have shown.
    pub title: String,
    /// The asking child's session id (provenance, ledger).
    pub child_session: String,
    /// The asking child's extension-process pid (identity hardening).
    pub child_pid: u32,
    /// Epoch millis when the child asked.
    pub started_at_ms: u64,
}

impl Ask {
    pub fn to_value(&self) -> serde_json::Value {
        serde_json::json!({
            "uuid": self.uuid,
            "mode": self.mode,
            "summary": self.summary,
            "justification": self.justification,
            "title": self.title,
            "childSession": self.child_session,
            "childPid": self.child_pid,
            "startedAt": self.started_at_ms,
        })
    }

    pub fn from_value(v: &serde_json::Value) -> Option<Ask> {
        let uuid = v.get("uuid")?.as_str()?.to_string();
        if uuid.is_empty() {
            return None;
        }
        Some(Ask {
            uuid,
            mode: v.get("mode").and_then(|x| x.as_str()).unwrap_or("").to_string(),
            summary: one_line(v.get("summary").and_then(|x| x.as_str()).unwrap_or("")),
            justification: one_line(v.get("justification").and_then(|x| x.as_str()).unwrap_or("")),
            title: v.get("title").and_then(|x| x.as_str()).unwrap_or("").to_string(),
            child_session: v.get("childSession").and_then(|x| x.as_str()).unwrap_or("").to_string(),
            child_pid: v.get("childPid").and_then(|x| x.as_u64()).unwrap_or(0) as u32,
            started_at_ms: v.get("startedAt").and_then(|x| x.as_u64()).unwrap_or(0),
        })
    }

    /// The operator-facing wake/listing line.
    pub fn describe(&self) -> String {
        format!(
            "{} escalation for child {}: {} — {}",
            self.mode,
            short_session(&self.child_session),
            self.summary,
            if self.justification.is_empty() {
                "(no justification)".to_string()
            } else {
                self.justification.clone()
            }
        )
    }
}

/// First segment of a session id (uuids print as their first group).
pub fn short_session(id: &str) -> String {
    let head = id.split('-').next().unwrap_or(id);
    if id.len() > head.len() {
        format!("{head}…")
    } else {
        id.to_string()
    }
}

/// Collapse whitespace runs to single spaces (log-safe previews).
fn one_line(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// The fail-closed wording for an ask that could not reach the parent
/// (shared by the relay and its tests so the model-visible text is one
/// string). `cause` is the transport error; the whole message promises
/// nothing ran.
pub fn channel_unreachable(mode: &str, parent: &str, cause: &str) -> String {
    format!(
        "sandbox escalation to {mode:?} needs approval from parent session {parent}, but the approval channel is unreachable ({cause}) — nothing was executed (fail-closed). Wait for the parent session's pig-bg-tasks (its link listens from its session_start), or do the work inside the writable roots."
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Serializes the env-reading tests (the marker is process-global).
    static TEST_MU: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn endpoint_derivation_is_agreed_and_path_safe() {
        let p = endpoint("sess-1");
        let want = std::env::temp_dir().join("pig-sandbox-sess-1.sock");
        assert_eq!(p, want, "{p:?}");
        assert_eq!(p.parent(), Some(socket_dir().as_path()), "{p:?}");
        // hostile ids cannot escape the directory
        let bad = endpoint("../../evil");
        let bad = bad.to_string_lossy();
        assert!(!bad.contains(".."), "{bad}");
        assert!(bad.ends_with("pig-sandbox-------evil.sock"), "{bad}");
    }

    #[test]
    fn one_socket_per_session_in_the_tmp_dir() {
        // Both ends derive the identical path from the session id alone —
        // no config root to share, so a parent and its child always agree.
        let a = endpoint("abc-123");
        assert_eq!(a, endpoint("abc-123"), "{a:?}");
        assert_eq!(
            a.file_name().unwrap().to_string_lossy(),
            "pig-sandbox-abc-123.sock",
            "{a:?}"
        );
        assert_eq!(a.parent(), Some(socket_dir().as_path()), "{a:?}");
        assert!(fits(&a), "{a:?}");
        // An id that would outrun the platform's `sun_path` gets no
        // endpoint at all — one socket, refused the same way on both sides.
        let long = endpoint(&"x".repeat(200));
        assert!(!fits(&long), "{long:?}");
    }

    #[test]
    fn marker_detection() {
        let _t = TEST_MU.lock().unwrap_or_else(|e| e.into_inner());
        std::env::remove_var(PARENT_SESSION_ENV);
        assert!(parent_session().is_none());
        assert!(!is_child());
        std::env::set_var(PARENT_SESSION_ENV, "  parent-9  ");
        assert_eq!(parent_session().as_deref(), Some("parent-9"));
        assert!(is_child());
        std::env::set_var(PARENT_SESSION_ENV, "   ");
        assert!(parent_session().is_none(), "blank counts as unset");
        std::env::remove_var(PARENT_SESSION_ENV);
    }

    #[test]
    fn ask_roundtrip() {
        let a = Ask {
            uuid: "ask-1".into(),
            mode: "danger-full-access".into(),
            summary: "git push --force".into(),
            justification: "deploy".into(),
            title: "Sandbox escalation: …".into(),
            child_session: "child-1".into(),
            child_pid: 4242,
            started_at_ms: 123,
        };
        let back = Ask::from_value(&a.to_value()).expect("roundtrip");
        assert_eq!(back, a);
        assert!(Ask::from_value(&serde_json::json!({"uuid": ""})).is_none());
        assert!(Ask::from_value(&serde_json::json!({})).is_none());
    }

    #[test]
    fn policy_roundtrip_and_lenient_extras() {
        let p = Policy {
            mode: "workspace-write".into(),
            workspace: r"C:\ws".into(),
            temp: "C:\\Temp".into(),
            extras: vec!["C:\\a".into()],
        };
        assert_eq!(Policy::from_value(&p.to_value()).unwrap(), p);
        let loose = serde_json::json!({"mode": "read-only", "extras": ["x", 1, null]});
        let p2 = Policy::from_value(&loose).unwrap();
        assert_eq!(p2.mode, "read-only");
        assert_eq!(p2.extras, vec!["x".to_string()], "non-strings dropped");
        assert!(Policy::from_value(&serde_json::json!({})).is_none());
    }

    #[test]
    fn framing_roundtrip() {
        let mut t = temp_stream();
        write_line(&mut t.0, "{\"v\":1}").unwrap();
        let s = read_line(&mut t.1).unwrap();
        assert_eq!(s, "{\"v\":1}");
        // CRLF tolerated
        t.0.write_all(b"abc\r\n").unwrap();
        t.0.flush().unwrap();
        assert_eq!(read_line(&mut t.1).unwrap(), "abc");
    }

    /// A connected pair (unix socketpair semantics via a bound socket).
    fn temp_stream() -> (Stream, Stream) {
        let path = std::env::temp_dir().join(format!("pig-link-frame-{}.sock", std::process::id()));
        let l = Listener::bind(&path).expect("bind frame fixture");
        let client = std::thread::spawn(move || Stream::connect(&path).expect("connect frame fixture"));
        let server = l.accept().expect("accept frame fixture");
        (client.join().expect("client thread"), server)
    }
}

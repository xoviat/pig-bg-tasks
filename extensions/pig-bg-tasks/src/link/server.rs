//! The parent side of the link (DELEGATED-WORKSPACES §B.1): at session
//! start this session's SDK id names the endpoint; one accept loop per
//! endpoint serves one connection per request — `policy` answers this
//! session's sandbox policy, `ask` puts the child's escalation in front of
//! **this session's user through this session's own dialog** (the same
//! Deny-first select a local escalation shows) and replies with the verdict.
//! No tool, no separate approval surface: a relayed ask reads exactly like
//! one that originated here. Without a UI the ask is refused fail-closed.

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::time::Duration;

use serde_json::{Value, json};

use crate::link::{
    self, IO_TIMEOUT, Listener, Policy, PROTOCOL_VERSION, Stream, Verdict, read_line, write_line,
};

/// What the listener needs from its session.
pub struct ServerOpts {
    /// This session's id (SDK `ctx.get_session_id()`) — the endpoint name.
    pub session_id: String,
    /// PiG config root (both ends derive the primary endpoint from it).
    pub config_root: String,
    /// This session's current sandbox policy (`op:"policy"`).
    pub policy: Arc<dyn Fn() -> Policy + Send + Sync>,
    /// Ask the user this session's question and return their verdict
    /// (`None` when the session has no UI — asks then fail closed).
    pub approver: Option<Arc<dyn Fn(&link::Ask) -> Result<Verdict, String> + Send + Sync>>,
}

struct Running {
    stopped: Arc<AtomicBool>,
    exited: mpsc::Receiver<()>,
    paths: Vec<PathBuf>,
}

static RUNNING: Mutex<Option<Running>> = Mutex::new(None);

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// Bind this session's endpoints and start serving. Returns the paths that
/// bound (empty = no link; children then fail closed, as before). Replaces
/// any listener a previous session in this process left behind.
pub fn start(opts: ServerOpts) -> Vec<PathBuf> {
    stop();
    let paths = link::endpoints(&opts.config_root, &opts.session_id);
    let opts = Arc::new(opts);
    let stopped = Arc::new(AtomicBool::new(false));
    let (exited_tx, exited_rx) = mpsc::channel();
    let mut bound = Vec::new();
    for path in paths {
        let listener = match Listener::bind(&path) {
            Ok(l) => l,
            Err(e) => {
                crate::bg::dbg::trace(json!({
                    "phase": "link_bind_failed", "path": path.to_string_lossy(), "err": e.to_string()
                }));
                continue;
            }
        };
        bound.push(path);
        let o = opts.clone();
        let stop = stopped.clone();
        let tx = exited_tx.clone();
        // One thread per endpoint; it owns the listener (and removes the
        // socket file on exit), so `stop` wakes it with a dummy connect.
        std::thread::spawn(move || {
            accept_loop(listener, o, stop);
            let _ = tx.send(());
        });
    }
    *lock(&RUNNING) = Some(Running { stopped, exited: exited_rx, paths: bound.clone() });
    crate::bg::dbg::trace(json!({
        "phase": "link_started", "session": opts.session_id, "endpoints": bound.len()
    }));
    bound
}

/// Wake every accept loop and wait briefly for the threads to release
/// their endpoints (socket files go with them).
pub fn stop() {
    let previous = lock(&RUNNING).take();
    let Some(running) = previous else { return };
    running.stopped.store(true, Ordering::SeqCst);
    // A dummy connection unblocks a listener parked in accept().
    for path in &running.paths {
        let _ = Stream::connect(path);
    }
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    for _ in &running.paths {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        let _ = running.exited.recv_timeout(remaining);
    }
    crate::bg::dbg::trace(json!({"phase": "link_stopped", "session_endpoints": running.paths.len()}));
}

/// Whether this session's link is serving.
pub fn is_running() -> bool {
    lock(&RUNNING).is_some()
}

/// The bound endpoints of the running link (tests / diagnostics).
pub fn endpoints() -> Vec<PathBuf> {
    lock(&RUNNING).as_ref().map(|r| r.paths.clone()).unwrap_or_default()
}

fn accept_loop(listener: Listener, opts: Arc<ServerOpts>, stopped: Arc<AtomicBool>) {
    loop {
        match listener.accept() {
            Ok(stream) => {
                if stopped.load(Ordering::SeqCst) {
                    return; // stop() woke us
                }
                let o = opts.clone();
                std::thread::spawn(move || serve(stream, o));
            }
            Err(e) => {
                if stopped.load(Ordering::SeqCst) {
                    return;
                }
                crate::bg::dbg::trace(json!({"phase": "link_accept_error", "err": e.to_string()}));
                std::thread::sleep(Duration::from_millis(50));
            }
        }
    }
}

/// Serve exactly one request frame and reply (one connection per request —
/// the child dials per call, so asks never serialize behind each other).
fn serve(mut stream: Stream, opts: Arc<ServerOpts>) {
    let _ = stream.set_read_timeout(Some(IO_TIMEOUT));
    let _ = stream.set_write_timeout(Some(IO_TIMEOUT));
    let line = match read_line(&mut stream) {
        Ok(l) => l,
        Err(_) => return,
    };
    let reply = match serde_json::from_str::<Value>(&line) {
        Ok(req) => dispatch(&req, &opts),
        Err(_) => err("malformed frame (expected one JSON object per line)"),
    };
    let _ = write_line(&mut stream, &reply.to_string());
}

fn ok(fields: Value) -> Value {
    let mut v = json!({"v": PROTOCOL_VERSION, "ok": true});
    if let (Some(obj), Some(fields)) = (v.as_object_mut(), fields.as_object()) {
        for (k, val) in fields {
            obj.insert(k.clone(), val.clone());
        }
    }
    v
}

fn err(msg: &str) -> Value {
    json!({"v": PROTOCOL_VERSION, "ok": false, "error": msg})
}

fn dispatch(req: &Value, opts: &ServerOpts) -> Value {
    let v = req.get("v").and_then(Value::as_u64).unwrap_or(0);
    if v != PROTOCOL_VERSION {
        return err(&format!("unsupported link version {v} (expected {PROTOCOL_VERSION})"));
    }
    match req.get("op").and_then(Value::as_str).unwrap_or("") {
        "policy" => {
            let policy = (opts.policy)();
            ok(json!({"policy": policy.to_value()}))
        }
        "ask" => handle_ask(req, opts),
        other => err(&format!("unknown op \"{other}\"")),
    }
}

/// One child escalation: put it in front of this session's user (the
/// approver shows the standard dialog) and reply with their verdict. Every
/// failure — no UI, a dialog error — refuses fail-closed.
fn handle_ask(req: &Value, opts: &ServerOpts) -> Value {
    let Some(ask) = link::Ask::from_value(req.get("ask").unwrap_or(&Value::Null)) else {
        return err("malformed ask payload");
    };
    crate::bg::dbg::trace(json!({
        "phase": "link_ask", "ask": ask.uuid, "child": ask.child_session,
        "mode": ask.mode, "summary": ask.summary
    }));
    let Some(approver) = opts.approver.as_ref() else {
        crate::bg::dbg::trace(json!({"phase": "link_ask_refused", "ask": ask.uuid, "why": "no ui"}));
        return err(
            "the parent session has no approval channel (it is headless) — the escalation stays denied",
        );
    };
    match approver(&ask) {
        Ok(verdict) => {
            crate::bg::dbg::trace(json!({
                "phase": "link_ask_settled", "ask": ask.uuid,
                "decision": match &verdict {
                    Verdict::Allow => "allow",
                    Verdict::Deny(_) => "deny",
                    Verdict::Cancelled => "cancel",
                }
            }));
            let mut fields = json!({"uuid": ask.uuid});
            if let (Some(obj), Some(v)) = (fields.as_object_mut(), verdict.to_reply().as_object()) {
                for (k, val) in v {
                    obj.insert(k.clone(), val.clone());
                }
            }
            ok(fields)
        }
        Err(e) => {
            crate::bg::dbg::trace(json!({
                "phase": "link_ask_failed", "ask": ask.uuid, "err": e
            }));
            err(&format!(
                "the parent session could not ask its user ({e}) — the escalation stays denied"
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::link::{Ask, client};

    fn opts(session: &str, config_root: &str) -> ServerOpts {
        ServerOpts {
            session_id: session.to_string(),
            config_root: config_root.to_string(),
            policy: Arc::new(|| Policy {
                mode: "workspace-write".into(),
                workspace: r"C:\ws".into(),
                temp: "C:\\Temp".into(),
                extras: vec![r"C:\cache".into()],
            }),
            approver: None,
        }
    }

    fn ask(uuid: &str) -> Ask {
        Ask {
            uuid: uuid.to_string(),
            mode: "danger-full-access".into(),
            summary: "git push".into(),
            justification: "deploy".into(),
            title: "Sandbox escalation: allow this command under \"danger-full-access\"?".into(),
            child_session: "child-1".into(),
            child_pid: 7,
            started_at_ms: 0,
        }
    }

    /// A stand-in for the parent's dialog: the ask arrives on one channel,
    /// the test answers on another (FIFO — one verdict per ask).
    fn probe() -> (
        mpsc::Receiver<Ask>,
        mpsc::Sender<Verdict>,
        Arc<dyn Fn(&Ask) -> Result<Verdict, String> + Send + Sync>,
    ) {
        let (tx_ask, rx_ask) = mpsc::channel();
        let (tx_dec, rx_dec) = mpsc::channel::<Verdict>();
        let rx_dec = Arc::new(Mutex::new(rx_dec));
        let approver: Arc<dyn Fn(&Ask) -> Result<Verdict, String> + Send + Sync> =
            Arc::new(move |ask| {
                tx_ask.send(ask.clone()).map_err(|e| e.to_string())?;
                rx_dec
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .recv()
                    .map_err(|e| e.to_string())
            });
        (rx_ask, tx_dec, approver)
    }

    #[test]
    fn policy_over_the_socket() {
        let _t = crate::link::test_mu::lock();
        let root = std::env::temp_dir().join("pig-link-test-policy");
        let _ = std::fs::remove_dir_all(&root);
        let paths = start(opts("sess-policy", root.to_string_lossy().as_ref()));
        assert_eq!(paths.len(), 2, "primary + temp fallback bound: {paths:?}");
        assert!(is_running());
        let policy = client::fetch_policy("sess-policy", root.to_string_lossy().as_ref(), "child-1")
            .expect("policy over the socket");
        assert_eq!(policy.mode, "workspace-write");
        assert_eq!(policy.extras, vec![r"C:\cache".to_string()]);
        stop();
        assert!(!is_running());
        // no listener → fail closed (None), not a panic
        assert!(client::fetch_policy("sess-policy", root.to_string_lossy().as_ref(), "child-1").is_none());
        let _ = std::fs::remove_dir_all(&root);
    }

    /// The ask reaches the parent's dialog intact and the verdict comes
    /// back to the child: allow, deny-with-reason, and cancel.
    #[test]
    fn ask_is_asked_of_the_parent_and_answered() {
        let _t = crate::link::test_mu::lock();
        let root = std::env::temp_dir().join("pig-link-test-ask");
        let _ = std::fs::remove_dir_all(&root);
        let (rx_ask, tx_dec, approver) = probe();
        let mut o = opts("sess-ask", root.to_string_lossy().as_ref());
        o.approver = Some(approver);
        start(o);
        let cfg = root.to_string_lossy().into_owned();

        // (a) allow
        let parent = "sess-ask".to_string();
        let c = cfg.clone();
        let asker = std::thread::spawn(move || client::ask(&parent, &c, &ask("a-1")));
        let seen = rx_ask.recv_timeout(Duration::from_secs(5)).expect("the dialog saw the ask");
        assert_eq!(seen.uuid, "a-1");
        assert_eq!(seen.mode, "danger-full-access");
        assert_eq!(seen.summary, "git push");
        assert_eq!(seen.child_session, "child-1");
        assert!(seen.title.starts_with("Sandbox escalation:"), "{}", seen.title);
        tx_dec.send(Verdict::Allow).expect("answer");
        let out = asker.join().expect("ask thread").expect("allow");
        assert!(out.allow());
        assert!(out.reason.is_empty());

        // (b) deny with a reason
        let parent = "sess-ask".to_string();
        let c = cfg.clone();
        let asker = std::thread::spawn(move || client::ask(&parent, &c, &ask("a-2")));
        rx_ask.recv_timeout(Duration::from_secs(5)).expect("second ask");
        tx_dec.send(Verdict::Deny("never touch the shared repo".into())).expect("answer");
        let out = asker.join().expect("ask thread").expect("deny frame");
        assert!(!out.allow());
        assert_eq!(out.reason, "never touch the shared repo");

        // (c) cancelled dialog
        let parent = "sess-ask".to_string();
        let c = cfg.clone();
        let asker = std::thread::spawn(move || client::ask(&parent, &c, &ask("a-3")));
        rx_ask.recv_timeout(Duration::from_secs(5)).expect("third ask");
        tx_dec.send(Verdict::Cancelled).expect("answer");
        let out = asker.join().expect("ask thread").expect("cancel frame");
        assert!(!out.allow());
        assert_eq!(out.decision, "cancel");
        assert!(out.reason.is_empty());

        stop();
        let _ = std::fs::remove_dir_all(&root);
    }

    /// A headless parent (no dialog to show) refuses fail-closed.
    #[test]
    fn headless_parent_refuses_the_ask() {
        let _t = crate::link::test_mu::lock();
        let root = std::env::temp_dir().join("pig-link-test-headless");
        let _ = std::fs::remove_dir_all(&root);
        start(opts("sess-headless", root.to_string_lossy().as_ref()));
        let parent = "sess-headless".to_string();
        let cfg = root.to_string_lossy().into_owned();
        let e = client::ask(&parent, &cfg, &ask("h-1")).unwrap_err();
        assert!(e.contains("no approval channel"), "{e}");
        assert!(e.contains("stays denied"), "{e}");
        stop();
        let _ = std::fs::remove_dir_all(&root);
    }

    /// The whole §B.3 flow: a child's escalation blocks in `approve`, the
    /// parent's dialog settles it over the socket, and the verdict lands
    /// back in the escalation ladder's byte-stable wording.
    #[test]
    fn approve_settles_over_the_link() {
        let _t = crate::link::test_mu::lock();
        let root = std::env::temp_dir().join("pig-link-test-approve");
        let _ = std::fs::remove_dir_all(&root);
        let (rx_ask, tx_dec, approver) = probe();
        let mut o = opts("sess-approve", root.to_string_lossy().as_ref());
        o.approver = Some(approver);
        start(o);
        let cfg = root.to_string_lossy().into_owned();

        // The relay-shaped Ui `ext::resolve::relay_ui` builds: one ask
        // frame to the parent, the reply mapped back onto the ladder by the
        // same function production uses.
        fn relay(parent: String, cfg: String, uuid: String) -> crate::escalate::Ui {
            crate::escalate::Ui {
                has_ui: true,
                ask: Box::new(move |title, _opts, _prompt| {
                    let mut a = ask(&uuid);
                    a.title = title.to_string();
                    match client::ask(&parent, &cfg, &a) {
                        Ok(out) => Ok(crate::ext::resolve::verdict_decision(&out)),
                        Err(e) => Err(crate::link::channel_unreachable(&a.mode, &parent, &e)),
                    }
                }),
            }
        }

        fn req() -> crate::escalate::Request {
            crate::escalate::Request {
                requested_mode: "danger-full-access".into(),
                justification: "deploy".into(),
                effective_mode: crate::policy::Mode::WorkspaceWrite,
                subject: "command".into(),
                summary: "git push".into(),
            }
        }

        // (a) allow: approve blocks, the parent's dialog allows, mode widens
        let ui = relay("sess-approve".into(), cfg.clone(), "ap-1".into());
        let approver_thread =
            std::thread::spawn(move || crate::escalate::approve(&req(), &ui));
        let seen = rx_ask.recv_timeout(Duration::from_secs(5)).expect("dialog saw the ask");
        assert_eq!(seen.uuid, "ap-1");
        tx_dec.send(Verdict::Allow).expect("answer");
        assert_eq!(
            approver_thread.join().expect("approve thread").expect("allowed"),
            crate::policy::Mode::DangerFullAccess
        );

        // (b) deny with a reason: the ladder's byte-stable wording carries
        //     the parent's reason to the child
        let ui = relay("sess-approve".into(), cfg.clone(), "ap-2".into());
        let approver_thread =
            std::thread::spawn(move || crate::escalate::approve(&req(), &ui));
        rx_ask.recv_timeout(Duration::from_secs(5)).expect("second ask");
        tx_dec.send(Verdict::Deny("never touch the shared repo".into())).expect("answer");
        let e = approver_thread.join().expect("approve thread").unwrap_err();
        assert!(
            e.contains("the user rejected escalating this command to \"danger-full-access\""),
            "{e}"
        );
        assert!(e.ends_with(". The user's reason: never touch the shared repo"), "{e}");

        // (c) a dismissed dialog approves nothing — the ladder reports the
        //     cancellation
        let ui = relay("sess-approve".into(), cfg.clone(), "ap-3".into());
        let approver_thread =
            std::thread::spawn(move || crate::escalate::approve(&req(), &ui));
        rx_ask.recv_timeout(Duration::from_secs(5)).expect("third ask");
        tx_dec.send(Verdict::Cancelled).expect("answer");
        let e = approver_thread.join().expect("approve thread").unwrap_err();
        assert!(e.contains("was cancelled"), "{e}");
        assert!(e.contains("nothing was executed"), "{e}");

        // (d) unreachable parent: fail-closed with the channel named
        stop();
        let ui = relay("sess-approve".into(), cfg, "ap-4".into());
        let e = crate::escalate::approve(&req(), &ui).unwrap_err();
        assert!(e.contains("nothing was executed"), "{e}");
        assert!(e.contains("approval channel is unreachable"), "{e}");
        assert!(e.contains("sess-approve"), "{e}");

        let _ = std::fs::remove_dir_all(&root);
    }
}

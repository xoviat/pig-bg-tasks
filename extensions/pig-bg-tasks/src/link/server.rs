//! The parent side of the link (DELEGATED-WORKSPACES §B.1): at session
//! start this session's SDK id names the endpoint; one accept loop serves
//! one connection per request — `policy` answers this session's sandbox
//! policy (and records the child that asked), `ask` puts the child's
//! escalation in front of **this session's user through this session's own
//! dialog** (the same Deny-first select a local escalation shows) and
//! replies with the verdict. No tool, no separate approval surface: a
//! relayed ask reads exactly like one that originated here. Without a UI
//! the ask is refused fail-closed.
//!
//! The same socket runs the other way: [`broadcast_policy`] pushes this
//! session's current policy to every child that has fetched one whenever
//! its permission level widens or narrows (`op:"policy-update"`), so a
//! child never keeps a level the parent has already moved off.

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::time::Duration;

use serde_json::{Value, json};

use crate::link::{
    self, IO_TIMEOUT, Listener, Policy, PROTOCOL_VERSION, Stream, Verdict, read_line, write_line,
};

/// Ask the user this session's question and return their verdict
/// (`None` when the session has no UI — asks then fail closed).
pub type Approver = Arc<dyn Fn(&link::Ask) -> Result<Verdict, String> + Send + Sync>;

/// Apply a parent's pushed policy (`op:"policy-update"`) and report whether
/// it was applied — `None` when this session mirrors no parent. The applier
/// refuses a sender that is not that parent (fail-closed), so only the
/// session that spawned this child moves its baseline.
pub type PolicyApplier = Arc<dyn Fn(&str, Policy) -> bool + Send + Sync>;

/// What the listener needs from its session.
pub struct ServerOpts {
    /// This session's id (SDK `ctx.get_session_id()`) — the endpoint name.
    pub session_id: String,
    /// This session's current sandbox policy (`op:"policy"`), read live so
    /// a `/sandbox` switch and a nested inheritance both show up in it —
    /// and so a [`broadcast_policy`] always carries the newest level.
    pub policy: Arc<dyn Fn() -> Policy + Send + Sync>,
    /// Ask the user this session's question and return their verdict
    /// (`None` when the session has no UI — asks then fail closed).
    pub approver: Option<Approver>,
    /// Apply a parent's pushed policy, if this session mirrors one.
    pub on_policy_update: Option<PolicyApplier>,
}

struct Running {
    stopped: Arc<AtomicBool>,
    exited: mpsc::Receiver<()>,
    paths: Vec<PathBuf>,
    /// The live opts: [`broadcast_policy`] reads this session's id and
    /// policy closure from here.
    opts: Arc<ServerOpts>,
}

/// A child that has spoken to this link (from `op:"policy"` or `op:"ask"`):
/// the fan-out set for [`broadcast_policy`]. Keyed by session id — a child
/// that fetches again just refreshes its pid.
#[derive(Debug, Clone)]
struct Child {
    session: String,
    /// Recorded for the `SO_PEERCRED` hardening DELEGATED-WORKSPACES §B.4
    /// lists as open; nothing reads it yet.
    #[allow(dead_code)]
    pid: u32,
}

static CHILDREN: Mutex<Vec<Child>> = Mutex::new(Vec::new());

/// Record (or refresh) a child that talked to this link. Empty ids are
/// ignored — there is no socket to push to.
fn note_child(session: &str, pid: u32) {
    if session.is_empty() {
        return;
    }
    let mut g = lock(&CHILDREN);
    match g.iter_mut().find(|c| c.session == session) {
        Some(c) => c.pid = pid,
        None => g.push(Child { session: session.to_string(), pid }),
    }
}

/// The children this session has heard from (tests / diagnostics).
pub fn children() -> Vec<String> {
    lock(&CHILDREN).iter().map(|c| c.session.clone()).collect()
}

static RUNNING: Mutex<Option<Running>> = Mutex::new(None);

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// Bind this session's single socket and start serving. Returns the bound
/// path (empty = no link; children then fail closed, as before). Replaces
/// any listener a previous session in this process left behind, and starts
/// the child registry over — the new session has no children yet.
pub fn start(opts: ServerOpts) -> Vec<PathBuf> {
    stop(); // also forgets the previous session's children
    let path = link::endpoint(&opts.session_id);
    let opts = Arc::new(opts);
    let stopped = Arc::new(AtomicBool::new(false));
    let (exited_tx, exited_rx) = mpsc::channel();
    let mut bound = Vec::new();
    if !link::fits(&path) {
        crate::bg::dbg::trace(json!({
            "phase": "link_endpoint_too_long", "session": opts.session_id,
            "len": path.to_string_lossy().len()
        }));
    } else {
        match Listener::bind(&path) {
            Ok(listener) => {
                bound.push(path.clone());
                let o = opts.clone();
                let stop = stopped.clone();
                let tx = exited_tx.clone();
                // The thread owns the listener (and removes the socket file
                // on exit), so `stop` wakes it with a dummy connect.
                std::thread::spawn(move || {
                    accept_loop(listener, o, stop);
                    let _ = tx.send(());
                });
            }
            Err(e) => {
                crate::bg::dbg::trace(json!({
                    "phase": "link_bind_failed", "path": path.to_string_lossy(), "err": e.to_string()
                }));
            }
        }
    }
    *lock(&RUNNING) = Some(Running {
        stopped,
        exited: exited_rx,
        paths: bound.clone(),
        opts: opts.clone(),
    });
    crate::bg::dbg::trace(json!({
        "phase": "link_started", "session": opts.session_id, "endpoints": bound.len()
    }));
    bound
}

/// Wake the accept loop and wait briefly for the thread to release its
/// endpoint (the socket file goes with it).
pub fn stop() {
    let previous = lock(&RUNNING).take();
    lock(&CHILDREN).clear();
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

/// The bound endpoint of the running link (tests / diagnostics).
pub fn endpoints() -> Vec<PathBuf> {
    lock(&RUNNING).as_ref().map(|r| r.paths.clone()).unwrap_or_default()
}

/// The fan-out set for a policy push: this session's live opts plus the
/// children that have spoken to its link (`None` = nothing to push).
fn fanout() -> Option<(Arc<ServerOpts>, Vec<String>)> {
    let running = lock(&RUNNING);
    let r = running.as_ref()?;
    let children = lock(&CHILDREN);
    if children.is_empty() {
        return None;
    }
    Some((
        r.opts.clone(),
        children.iter().map(|c| c.session.clone()).collect(),
    ))
}

/// Push this session's current permission level to every child that has
/// spoken to this link, over each child's own socket (`op:"policy-update"`).
/// This is how a `/sandbox` widen or narrow propagates: the children
/// mirrored a snapshot at their `session_start`, so without this they
/// would keep running the level the parent has already moved off.
///
/// Detached — the switch never waits on a child; a child that is gone is
/// traced and skipped. No running link or no children ⇒ no-op.
pub fn broadcast_policy() {
    let Some((opts, children)) = fanout() else { return };
    std::thread::spawn(move || deliver_policy(&opts, &children));
}

/// [`broadcast_policy`] on the calling thread (tests / diagnostics).
/// Returns how many children acknowledged the new level.
pub fn broadcast_policy_now() -> usize {
    let Some((opts, children)) = fanout() else { return 0 };
    deliver_policy(&opts, &children)
}

/// One push per child: the policy snapshot is read once (the same live
/// closure `op:"policy"` answers with), then each child gets one short
/// dial — a failure there is that child's problem, not the switch's.
fn deliver_policy(opts: &ServerOpts, children: &[String]) -> usize {
    let policy = (opts.policy)();
    let mut applied = 0usize;
    for child in children {
        match crate::link::client::push_policy(child, &opts.session_id, &policy) {
            Ok(reply) => {
                let ok = reply.get("applied").and_then(Value::as_bool) == Some(true);
                applied += usize::from(ok);
                crate::bg::dbg::trace(json!({
                    "phase": "link_policy_pushed", "child": child, "applied": ok
                }));
            }
            Err(e) => {
                crate::bg::dbg::trace(json!({
                    "phase": "link_policy_push_failed", "child": child, "err": e
                }));
            }
        }
    }
    applied
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
            // The child that asked is now reachable on its own socket —
            // the fan-out set for [`broadcast_policy`].
            if let Some(child) = req.get("child") {
                note_child(
                    child.get("session").and_then(Value::as_str).unwrap_or(""),
                    child.get("pid").and_then(Value::as_u64).unwrap_or(0) as u32,
                );
            }
            let policy = (opts.policy)();
            ok(json!({"policy": policy.to_value()}))
        }
        "policy-update" => handle_policy_update(req, opts),
        "ask" => handle_ask(req, opts),
        other => err(&format!("unknown op \"{other}\"")),
    }
}

/// A parent pushed its (now wider or narrower) permission level down this
/// session's own socket. The applier decides whether the sender may move
/// the baseline — a frame from anyone else leaves the mirror untouched —
/// and its answer is what the parent traces as applied/refused.
fn handle_policy_update(req: &Value, opts: &ServerOpts) -> Value {
    let Some(policy) = req.get("policy").and_then(Policy::from_value) else {
        return err("malformed policy payload");
    };
    let Some(applier) = opts.on_policy_update.as_ref() else {
        return err("this session does not mirror a parent policy");
    };
    let sender = req.get("parent").and_then(Value::as_str).unwrap_or("");
    let applied = applier(sender, policy);
    crate::bg::dbg::trace(json!({
        "phase": if applied { "link_policy_update_applied" } else { "link_policy_update_refused" },
        "sender": sender
    }));
    ok(json!({"applied": applied}))
}

/// One child escalation: put it in front of this session's user (the
/// approver shows the standard dialog) and reply with their verdict. Every
/// failure — no UI, a dialog error — refuses fail-closed.
fn handle_ask(req: &Value, opts: &ServerOpts) -> Value {
    let Some(ask) = link::Ask::from_value(req.get("ask").unwrap_or(&Value::Null)) else {
        return err("malformed ask payload");
    };
    // An asking child is a child with a socket too (it may never have
    // fetched a policy): keep it in the fan-out set.
    note_child(&ask.child_session, ask.child_pid);
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

    fn opts(session: &str) -> ServerOpts {
        ServerOpts {
            session_id: session.to_string(),
            policy: Arc::new(|| Policy {
                mode: "workspace-write".into(),
                workspace: r"C:\ws".into(),
                temp: "C:\\Temp".into(),
                extras: vec![r"C:\cache".into()],
            }),
            approver: None,
            on_policy_update: None,
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
    fn probe() -> (mpsc::Receiver<Ask>, mpsc::Sender<Verdict>, Approver) {
        let (tx_ask, rx_ask) = mpsc::channel();
        let (tx_dec, rx_dec) = mpsc::channel::<Verdict>();
        let rx_dec = Arc::new(Mutex::new(rx_dec));
        let approver: Approver = Arc::new(move |ask| {
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
        let paths = start(opts("sess-policy"));
        assert_eq!(paths.len(), 1, "one socket per session: {paths:?}");
        assert_eq!(paths[0], link::endpoint("sess-policy"), "{paths:?}");
        assert!(is_running());
        let policy = client::fetch_policy("sess-policy", "child-1")
            .expect("policy over the socket");
        assert_eq!(policy.mode, "workspace-write");
        assert_eq!(policy.extras, vec![r"C:\cache".to_string()]);
        // the child that asked is now reachable for policy pushes
        assert_eq!(children(), vec!["child-1".to_string()]);
        stop();
        assert!(!is_running());
        assert!(children().is_empty(), "a stopped link forgets its children");
        // no listener → fail closed (None), not a panic
        assert!(client::fetch_policy("sess-policy", "child-1").is_none());
    }

    /// The ask reaches the parent's dialog intact and the verdict comes
    /// back to the child: allow, deny-with-reason, and cancel.
    #[test]
    fn ask_is_asked_of_the_parent_and_answered() {
        let _t = crate::link::test_mu::lock();
        let (rx_ask, tx_dec, approver) = probe();
        let mut o = opts("sess-ask");
        o.approver = Some(approver);
        start(o);

        // (a) allow
        let parent = "sess-ask".to_string();
        let asker = std::thread::spawn(move || client::ask(&parent, &ask("a-1")));
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
        let asker = std::thread::spawn(move || client::ask(&parent, &ask("a-2")));
        rx_ask.recv_timeout(Duration::from_secs(5)).expect("second ask");
        tx_dec.send(Verdict::Deny("never touch the shared repo".into())).expect("answer");
        let out = asker.join().expect("ask thread").expect("deny frame");
        assert!(!out.allow());
        assert_eq!(out.reason, "never touch the shared repo");

        // (c) cancelled dialog
        let parent = "sess-ask".to_string();
        let asker = std::thread::spawn(move || client::ask(&parent, &ask("a-3")));
        rx_ask.recv_timeout(Duration::from_secs(5)).expect("third ask");
        tx_dec.send(Verdict::Cancelled).expect("answer");
        let out = asker.join().expect("ask thread").expect("cancel frame");
        assert!(!out.allow());
        assert_eq!(out.decision, "cancel");
        assert!(out.reason.is_empty());

        stop();
    }

    /// A headless parent (no dialog to show) refuses fail-closed.
    #[test]
    fn headless_parent_refuses_the_ask() {
        let _t = crate::link::test_mu::lock();
        start(opts("sess-headless"));
        let parent = "sess-headless".to_string();
        let e = client::ask(&parent, &ask("h-1")).unwrap_err();
        assert!(e.contains("no approval channel"), "{e}");
        assert!(e.contains("stays denied"), "{e}");
        stop();
    }

    /// The whole §B.3 flow: a child's escalation blocks in `approve`, the
    /// parent's dialog settles it over the socket, and the verdict lands
    /// back in the escalation ladder's byte-stable wording.
    #[test]
    fn approve_settles_over_the_link() {
        let _t = crate::link::test_mu::lock();
        let (rx_ask, tx_dec, approver) = probe();
        let mut o = opts("sess-approve");
        o.approver = Some(approver);
        start(o);

        // The relay-shaped Ui `ext::resolve::relay_ui` builds: one ask
        // frame to the parent, the reply mapped back onto the ladder by the
        // same function production uses.
        fn relay(parent: String, uuid: String) -> crate::escalate::Ui {
            crate::escalate::Ui {
                has_ui: true,
                ask: Box::new(move |title, _opts, _prompt| {
                    let mut a = ask(&uuid);
                    a.title = title.to_string();
                    match client::ask(&parent, &a) {
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
        let ui = relay("sess-approve".into(), "ap-1".into());
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
        let ui = relay("sess-approve".into(), "ap-2".into());
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
        let ui = relay("sess-approve".into(), "ap-3".into());
        let approver_thread =
            std::thread::spawn(move || crate::escalate::approve(&req(), &ui));
        rx_ask.recv_timeout(Duration::from_secs(5)).expect("third ask");
        tx_dec.send(Verdict::Cancelled).expect("answer");
        let e = approver_thread.join().expect("approve thread").unwrap_err();
        assert!(e.contains("was cancelled"), "{e}");
        assert!(e.contains("nothing was executed"), "{e}");

        // (d) unreachable parent: fail-closed with the channel named
        stop();
        let ui = relay("sess-approve".into(), "ap-4".into());
        let e = crate::escalate::approve(&req(), &ui).unwrap_err();
        assert!(e.contains("nothing was executed"), "{e}");
        assert!(e.contains("approval channel is unreachable"), "{e}");
        assert!(e.contains("sess-approve"), "{e}");
    }

    /// The propagation half of §B, over the single tmp socket: a child
    /// fetches its baseline (and is registered for pushes), the parent's
    /// permission level then moves — narrow, then widen — and
    /// [`broadcast_policy_now`] carries each new level to the **child's**
    /// own socket, where the applier takes it. The "child process" is a
    /// second listener on its own endpoint, served by the same `serve`
    /// code production runs (two processes cannot share one listener).
    #[test]
    fn permission_changes_fan_out_to_children() {
        let _t = crate::link::test_mu::lock();

        // Child side: its own socket + the applier production wires (here:
        // hand the update to this test over a channel, sender included).
        let (tx, rx) = mpsc::channel::<(String, Policy)>();
        let child_opts = Arc::new(ServerOpts {
            session_id: "child-1".into(),
            policy: Arc::new(|| Policy {
                mode: "workspace-write".into(),
                workspace: String::new(),
                temp: String::new(),
                extras: vec![],
            }),
            approver: None,
            on_policy_update: Some(Arc::new(move |sender, p| {
                tx.send((sender.to_string(), p)).is_ok()
            })),
        });
        let child_path = link::endpoint("child-1");
        let child_listener = Listener::bind(&child_path).expect("child socket");
        std::thread::spawn(move || {
            // exactly as many connections as the pushes below send, then
            // drop the listener (which removes the socket file)
            for _ in 0..2 {
                let Ok(stream) = child_listener.accept() else { break };
                serve(stream, child_opts.clone());
            }
            drop(child_listener);
        });

        // Parent side: a live policy snapshot — production reads the
        // `/sandbox` override through this same closure.
        let level = Arc::new(Mutex::new(Policy {
            mode: "workspace-write".into(),
            workspace: r"C:\ws".into(),
            temp: "C:\\Temp".into(),
            extras: vec![r"C:\old".into()],
        }));
        let live = level.clone();
        let mut o = opts("sess-broadcast");
        o.policy = Arc::new(move || live.lock().unwrap_or_else(|e| e.into_inner()).clone());
        start(o);

        // The child registers by fetching its baseline.
        let got = client::fetch_policy("sess-broadcast", "child-1").expect("policy");
        assert_eq!(got.mode, "workspace-write");
        assert_eq!(children(), vec!["child-1".to_string()]);

        // Narrow: the push carries the new level + the new roots.
        *level.lock().unwrap_or_else(|e| e.into_inner()) = Policy {
            mode: "read-only".into(),
            workspace: r"C:\ws".into(),
            temp: "C:\\Temp".into(),
            extras: vec![r"C:\new".into()],
        };
        assert_eq!(broadcast_policy_now(), 1, "the child acknowledged the narrow");
        let (sender, p) = rx.recv_timeout(Duration::from_secs(5)).expect("narrow push");
        assert_eq!(sender, "sess-broadcast", "the frame names the pushing parent");
        assert_eq!(p.mode, "read-only");
        assert_eq!(p.extras, vec![r"C:\new".to_string()]);

        // Widen: the same socket, the newest level.
        *level.lock().unwrap_or_else(|e| e.into_inner()) = Policy {
            mode: "danger-full-access".into(),
            workspace: r"C:\ws".into(),
            temp: "C:\\Temp".into(),
            extras: vec![r"C:\new".into()],
        };
        assert_eq!(broadcast_policy_now(), 1, "the child acknowledged the widen");
        let (sender, p) = rx.recv_timeout(Duration::from_secs(5)).expect("widen push");
        assert_eq!(sender, "sess-broadcast");
        assert_eq!(p.mode, "danger-full-access");

        stop();
        // No link, no children ⇒ nothing to push.
        assert_eq!(broadcast_policy_now(), 0);
        // Wake the child's accept loop so its thread drops the listener
        // (and the socket file with it), whatever the counts above were.
        let _ = link::Stream::connect(&child_path);
    }

    /// A session that mirrors no parent refuses `policy-update`, and a
    /// malformed payload fails closed — the mirror only moves when an
    /// applier says the sender may move it.
    #[test]
    fn policy_update_without_a_mirror_is_refused() {
        let o = opts("sess-no-mirror");
        let req = json!({
            "v": PROTOCOL_VERSION, "op": "policy-update", "parent": "sess-x",
            "policy": {"mode": "read-only", "extras": []}
        });
        let reply = handle_policy_update(&req, &o);
        assert_eq!(reply.get("ok"), Some(&Value::Bool(false)), "{reply}");
        assert!(
            reply["error"].as_str().unwrap().contains("does not mirror"),
            "{reply}"
        );
        let bad = json!({"v": PROTOCOL_VERSION, "parent": "sess-x"});
        let reply = handle_policy_update(&bad, &o);
        assert_eq!(reply.get("ok"), Some(&Value::Bool(false)), "{reply}");
        assert!(reply["error"].as_str().unwrap().contains("malformed"), "{reply}");
    }
}

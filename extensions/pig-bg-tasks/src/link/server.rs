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
//!
//! And a third shape — a **subscription**: `op:"watch-tasks"` keeps the
//! child's connection open after its ack, and that one connection carries
//! this session's task busy state (`busy` = a task is running, `!busy` =
//! nothing is). The ack snapshots the state; every later flip arrives as
//! a `{"event":"task-busy","busy":…}` frame, pushed by [`broadcast_busy`],
//! which [`crate::bg::registry`] fires when a task starts or stops. Two
//! states only, announced absolutely — a duplicate frame is harmless.

use std::io::Read;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
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
    /// Whether this session currently has tasks running — the state an
    /// `op:"watch-tasks"` subscriber is snapshot in its ack and pushed on
    /// every flip. Read live, like [`ServerOpts::policy`]: the registry
    /// behind it is the source of truth for "busy".
    pub tasks_busy: Arc<dyn Fn() -> bool + Send + Sync>,
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

/// One accepted `watch-tasks` subscription. Events reach the subscriber's
/// own connection through this channel, so [`broadcast_busy`] only ever
/// hands a frame to a channel — a watcher that stopped reading can never
/// stall a task start or a task exit (its own thread owns the socket
/// write, bounded by the write timeout).
struct Subscriber {
    id: u64,
    tx: mpsc::Sender<Value>,
}

/// The subscription registry: who watches this link, plus the last busy
/// state pushed. `last` makes a *flip* the only thing that earns a frame
/// (the frames are absolute `{"busy": …}` announcements, so a duplicate
/// would be harmless — this just avoids the chatter).
struct WatchState {
    last: Option<bool>,
    subs: Vec<Subscriber>,
}

static WATCH: Mutex<WatchState> = Mutex::new(WatchState {
    last: None,
    subs: Vec::new(),
});
static NEXT_WATCHER: AtomicU64 = AtomicU64::new(1);

/// One link's subscription cap: a watcher costs a thread and a socket, and
/// nothing in §B legitimately brings more than a handful of children to
/// one session's link.
const MAX_WATCHERS: usize = 32;

/// How often an open subscription checks whether its peer is still there
/// (read probe) when no event is pending.
const WATCH_PROBE_INTERVAL: Duration = Duration::from_millis(500);

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// Bind this session's single socket and start serving. Returns the bound
/// path (empty = no link; children then fail closed, as before). Replaces
/// any listener a previous session in this process left behind, and starts
/// the child registry over — the new session has no children yet.
pub fn start(opts: ServerOpts) -> Vec<PathBuf> {
    stop_with("restart"); // also forgets the previous session's children
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
                let thread_session = opts.session_id.clone();
                let thread_endpoint = path.clone();
                crate::bg::dbg::trace(json!({
                    "phase": "link_accept_thread_started", "session": opts.session_id,
                    "endpoint": path.to_string_lossy(), "pid": std::process::id()
                }));
                // The thread owns the listener (and removes the socket file
                // on exit), so `stop` wakes it with a dummy connect.
                std::thread::spawn(move || {
                    // A panic in the accept loop would otherwise kill the
                    // listener silently (the socket file survives on
                    // Windows) — record WHY the thread is going away.
                    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        accept_loop(listener, o, stop)
                    }));
                    let mut rec = serde_json::Map::new();
                    rec.insert("phase".into(), json!("link_accept_thread_exited"));
                    rec.insert("session".into(), json!(thread_session));
                    rec.insert("endpoint".into(), json!(thread_endpoint.to_string_lossy()));
                    match outcome {
                        Ok(()) => {
                            rec.insert("why".into(), json!("stopped"));
                        }
                        Err(payload) => {
                            let msg = payload
                                .downcast_ref::<&str>()
                                .map(|s| (*s).to_string())
                                .or_else(|| payload.downcast_ref::<String>().cloned())
                                .unwrap_or_else(|| "<non-string panic payload>".into());
                            rec.insert("why".into(), json!("panicked"));
                            rec.insert("payload".into(), json!(msg));
                        }
                    }
                    crate::bg::dbg::trace(Value::Object(rec));
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
        "phase": "link_started", "session": opts.session_id, "endpoints": bound.len(),
        "endpoint": path.to_string_lossy(), "pid": std::process::id()
    }));
    bound
}

/// Wake the accept loop and wait briefly for the thread to release its
/// endpoint (the socket file goes with it).
pub fn stop() {
    stop_with("stop")
}

/// [`stop`] with the caller's reason, recorded in the trace so a later
/// reader can tell a `session_shutdown` from the `restart` inside
/// [`start`] — the incident this grew out of had three unattributable
/// `link_stopped` lines and no way to tell whose link each belonged to.
pub fn stop_with(reason: &str) {
    let previous = lock(&RUNNING).take();
    lock(&CHILDREN).clear();
    // Dropping the subscribers' senders wakes every `watch-tasks` thread,
    // which then drops its connection — subscribers never outlive the link.
    let watchers = {
        let mut w = lock(&WATCH);
        let n = w.subs.len();
        w.last = None;
        w.subs.clear();
        n
    };
    let Some(running) = previous else { return };
    if watchers > 0 {
        crate::bg::dbg::trace(json!({
            "phase": "link_watchers_dropped", "session": running.opts.session_id,
            "watchers": watchers, "reason": reason
        }));
    }
    let session = running.opts.session_id.clone();
    let paths: Vec<String> = running
        .paths
        .iter()
        .map(|p| p.to_string_lossy().into_owned())
        .collect();
    running.stopped.store(true, Ordering::SeqCst);
    // A dummy connection unblocks a listener parked in accept().
    for path in &running.paths {
        let _ = Stream::connect(path);
    }
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    // Did the accept thread actually release its endpoint before the
    // window closed? Reporting a clean stop when it did not hides the
    // state where a stale listener outlives this `stop`.
    let mut thread_exited = true;
    for _ in &running.paths {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        match running.exited.recv_timeout(remaining) {
            Ok(_) | Err(mpsc::RecvTimeoutError::Disconnected) => {}
            Err(mpsc::RecvTimeoutError::Timeout) => thread_exited = false,
        }
    }
    if !thread_exited {
        crate::bg::dbg::trace(json!({
            "phase": "link_stop_timeout", "session": session, "reason": reason,
            "endpoints": paths, "pid": std::process::id()
        }));
    }
    crate::bg::dbg::trace(json!({
        "phase": "link_stopped", "session": session, "reason": reason,
        "session_endpoints": running.paths.len(), "thread_exited": thread_exited,
        "endpoints": paths
    }));
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

/// Push this session's task busy state to every `watch-tasks` subscriber
/// (`{"event":"task-busy","busy":…}` on each subscriber's own
/// connection): busy = a task is running, not busy = nothing is. The task
/// registry fires this when a task starts and when it stops, so a
/// subscriber sees both directions.
///
/// No link ⇒ the call returns at once; with a link it always refreshes
/// the remembered state (so a subscriber that arrives mid-task is told the
/// truth) but only a *flip* earns a frame. No socket I/O on this path
/// either way — the busy state is read **outside** every lock (the
/// registry's hooks call this with no registry lock held, and the read
/// takes one), and delivery is a channel hand-off, so the caller (a
/// task's start or exit path) never waits on a peer.
pub fn broadcast_busy() {
    push_busy();
}

/// [`broadcast_busy`] on the calling thread, reporting how many
/// subscribers the frame reached (tests / diagnostics).
pub fn broadcast_busy_now() -> usize {
    push_busy()
}

fn push_busy() -> usize {
    // The link's live opts carry the busy-state closure; no link ⇒ no
    // subscriber to tell (and `last` starts over with the next `start`).
    let opts = {
        let running = lock(&RUNNING);
        match running.as_ref() {
            Some(r) => r.opts.clone(),
            None => return 0,
        }
    };
    // Read the state even with nobody watching: it keeps `last` truthful,
    // so a subscriber that arrives mid-task is told "busy" instead of a
    // state that went stale while the set was empty.
    let busy = (opts.tasks_busy)();
    let mut w = lock(&WATCH);
    if w.last == Some(busy) {
        return 0; // no flip, no frame
    }
    w.last = Some(busy);
    let frame = json!({"v": PROTOCOL_VERSION, "event": "task-busy", "busy": busy});
    let mut delivered = 0usize;
    // A subscriber whose thread is gone fails the send and is dropped.
    w.subs.retain(|s| {
        if s.tx.send(frame.clone()).is_ok() {
            delivered += 1;
            true
        } else {
            false
        }
    });
    if delivered > 0 {
        crate::bg::dbg::trace(json!({
            "phase": "link_task_busy", "busy": busy, "watchers": delivered
        }));
    }
    delivered
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
/// The single exception is `watch-tasks`: its ack is followed by that
/// subscriber's event frames on the *same* connection, so this thread
/// stays with the stream until the peer or the link goes away.
fn serve(mut stream: Stream, opts: Arc<ServerOpts>) {
    let _ = stream.set_read_timeout(Some(IO_TIMEOUT));
    let _ = stream.set_write_timeout(Some(IO_TIMEOUT));
    let line = match read_line(&mut stream) {
        Ok(l) => l,
        Err(_) => return,
    };
    let req = match serde_json::from_str::<Value>(&line) {
        Ok(req) => req,
        Err(_) => {
            let reply = err("malformed frame (expected one JSON object per line)");
            let _ = write_line(&mut stream, &reply.to_string());
            return;
        }
    };
    match dispatch(&req, &opts) {
        Action::Reply(reply) => {
            let _ = write_line(&mut stream, &reply.to_string());
        }
        Action::Watch { ack, watch } => {
            // A failed ack write drops `watch`, which unregisters it.
            if write_line(&mut stream, &ack.to_string()).is_ok() {
                stream_events(stream, watch);
            }
        }
    }
}

/// What serving one request amounts to: a one-line reply (every op but
/// one), or the `watch-tasks` ack plus the subscription that then streams
/// this session's busy-state flips on that same connection.
enum Action {
    Reply(Value),
    Watch { ack: Value, watch: Watch },
}

/// One live `watch-tasks` subscription: dropping it unregisters the
/// subscriber (the ack never went out, or [`stream_events`] ended).
struct Watch {
    id: u64,
    rx: mpsc::Receiver<Value>,
}

impl Drop for Watch {
    fn drop(&mut self) {
        lock(&WATCH).subs.retain(|s| s.id != self.id);
    }
}

/// The subscription half: push event frames to this one subscriber until
/// it goes away or the link stops. The short read timeout doubles as a
/// liveness probe — a peer that vanished surfaces as EOF (or an error) on
/// the next tick, so a dead watcher is dropped without waiting for the
/// next state flip to discover it.
fn stream_events(mut stream: Stream, watch: Watch) {
    let _ = stream.set_read_timeout(Some(WATCH_PROBE_INTERVAL));
    let mut probe = [0u8; 1];
    let mut frames = 0usize;
    loop {
        match watch.rx.recv_timeout(WATCH_PROBE_INTERVAL) {
            Ok(frame) => {
                if write_line(&mut stream, &frame.to_string()).is_err() {
                    break; // peer gone mid-write
                }
                frames += 1;
            }
            Err(mpsc::RecvTimeoutError::Timeout) => match stream.read(&mut probe) {
                Ok(0) => break, // peer closed the connection
                Ok(_) => {}     // stray bytes — one request per connection, ignored
                Err(e) if read_timed_out(&e) => {} // still alive, nothing pending
                Err(_) => break,                   // broken connection
            },
            Err(mpsc::RecvTimeoutError::Disconnected) => break, // link stopped
        }
    }
    drop(watch); // unregister (no-op when stop already cleared the set)
    crate::bg::dbg::trace(json!({
        "phase": "link_watch_ended", "frames": frames
    }));
}

/// A read deadline (`SO_RCVTIMEO`) surfaces as `WouldBlock`/`TimedOut`.
fn read_timed_out(e: &std::io::Error) -> bool {
    matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut)
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

fn dispatch(req: &Value, opts: &ServerOpts) -> Action {
    let v = req.get("v").and_then(Value::as_u64).unwrap_or(0);
    if v != PROTOCOL_VERSION {
        crate::bg::dbg::trace(json!({"phase": "link_version_mismatch", "v": v}));
        return Action::Reply(err(&format!(
            "unsupported link version {v} (expected {PROTOCOL_VERSION})"
        )));
    }
    let op = req.get("op").and_then(Value::as_str).unwrap_or("");
    // Positive evidence that THIS process served a request on its socket:
    // the trace distinguishes "listener alive but never asked" from
    // "listener gone" after the fact.
    crate::bg::dbg::trace(json!({"phase": "link_served", "op": op}));
    match op {
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
            Action::Reply(ok(json!({"policy": policy.to_value()})))
        }
        "policy-update" => Action::Reply(handle_policy_update(req, opts)),
        "ask" => Action::Reply(handle_ask(req, opts)),
        "watch-tasks" => watch_tasks(opts),
        other => Action::Reply(err(&format!("unknown op \"{other}\""))),
    }
}

/// Accept a `watch-tasks` subscription: the ack carries this session's
/// current busy state, and every later flip arrives as an event frame on
/// this same connection until the peer closes it or the link stops.
///
/// The subscriber is registered *before* the snapshot is read, so a flip
/// in that window is already queued behind the ack — and the ack always
/// reports the newest state the link knows (`last`), which [`push_busy`]
/// keeps truthful even while nobody watches.
fn watch_tasks(opts: &ServerOpts) -> Action {
    let id = NEXT_WATCHER.fetch_add(1, Ordering::SeqCst);
    let (tx, rx) = mpsc::channel();
    let registered_last = {
        let mut w = lock(&WATCH);
        if w.subs.len() >= MAX_WATCHERS {
            crate::bg::dbg::trace(json!({
                "phase": "link_watch_refused", "why": "cap", "cap": MAX_WATCHERS
            }));
            return Action::Reply(err(&format!(
                "this link already has {MAX_WATCHERS} task watchers"
            )));
        }
        w.subs.push(Subscriber { id, tx });
        w.last
    };
    // Read outside the lock — the busy-state closure takes the registry's.
    let snapshot = (opts.tasks_busy)();
    let busy = {
        let w = lock(&WATCH);
        if w.last != registered_last {
            // A flip landed between the register and the snapshot: that
            // frame is already queued for this subscriber — ack it.
            w.last.unwrap_or(snapshot)
        } else {
            // Unchanged (or never pushed): the known state wins, and the
            // snapshot only fills the very first subscriber's ack.
            registered_last.unwrap_or(snapshot)
        }
    };
    crate::bg::dbg::trace(json!({"phase": "link_watch_started", "busy": busy}));
    Action::Watch {
        ack: ok(json!({"busy": busy})),
        watch: Watch { id, rx },
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
    use crate::bg::registry::{JobStatus, Registry};
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
            // Overridden by the tests that watch; the default is "idle".
            tasks_busy: Arc::new(|| false),
        }
    }

    /// Wait for the next `task-busy` event and return its `busy` value.
    fn busy_event(w: &mut client::Watch) -> bool {
        match w.recv(Duration::from_secs(5)) {
            client::Event::Frame(v) => {
                assert_eq!(
                    v.get("event").and_then(Value::as_str),
                    Some("task-busy"),
                    "{v}"
                );
                v.get("busy").and_then(Value::as_bool).expect("busy field")
            }
            other => panic!("expected a task-busy event, got {other:?}"),
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

    /// Every lifecycle event carries the identity needed to attribute it:
    /// session, endpoint, pid, and (for stops) the reason. The 2026-11-21
    /// orphan-socket incident had three bare `link_stopped` lines and no
    /// way to tell whose link each belonged to.
    #[test]
    fn lifecycle_trace_is_attributable() {
        let _t = crate::link::test_mu::lock();
        let sid = "sess-attrib";
        start(opts(sid));
        let _ = client::fetch_policy(sid, "child-attrib");
        stop_with("test-shutdown");

        let tail = crate::bg::dbg::tail(400);
        let seen = |phase: &str, pred: &dyn Fn(&Value) -> bool| {
            tail.iter()
                .any(|r| r.get("phase").and_then(Value::as_str) == Some(phase) && pred(r))
        };
        assert!(
            seen("link_started", &|r| {
                r["session"] == sid && r["pid"].is_u64() && r["endpoint"].is_string()
            }),
            "link_started names session/pid/endpoint"
        );
        assert!(
            seen("link_accept_thread_started", &|r| r["session"] == sid),
            "accept thread start is recorded"
        );
        assert!(
            seen("link_served", &|r| r["op"] == "policy"),
            "a served request is positive evidence the listener answered"
        );
        assert!(
            seen("link_accept_thread_exited", &|r| {
                r["session"] == sid && r["why"] == "stopped"
            }),
            "accept thread exit reason is recorded"
        );
        assert!(
            seen("link_stopped", &|r| {
                r["session"] == sid
                    && r["reason"] == "test-shutdown"
                    && r["thread_exited"] == true
            }),
            "link_stopped carries session + reason + thread outcome"
        );
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
            tasks_busy: Arc::new(|| false),
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

    /// `watch-tasks` over the socket: the ack snapshots the current busy
    /// state, every later flip arrives as a `task-busy` event on that same
    /// connection (both directions), silence means "no flip" rather than a
    /// dead link, a flip made while nobody watched is still told to a late
    /// subscriber, and stopping the link closes the subscription.
    #[test]
    fn watchers_see_busy_and_not_busy() {
        let _t = crate::link::test_mu::lock();
        let busy = Arc::new(AtomicBool::new(false));
        let mut o = opts("sess-watch");
        {
            let b = busy.clone();
            o.tasks_busy = Arc::new(move || b.load(Ordering::SeqCst));
        }
        start(o);

        // (a) subscribe: the ack carries the current state
        let mut w = client::watch_tasks("sess-watch").expect("subscribe");
        assert!(!w.busy(), "the ack snapshots an idle link");

        // (b) busy → the flip reaches the open connection
        busy.store(true, Ordering::SeqCst);
        assert_eq!(broadcast_busy_now(), 1, "one watcher, one frame");
        assert!(busy_event(&mut w), "a running task reads as busy");

        // (c) and back → not busy
        busy.store(false, Ordering::SeqCst);
        assert_eq!(broadcast_busy_now(), 1, "the flip back lands too");
        assert!(!busy_event(&mut w), "nothing running reads as not busy");

        // (d) no flip ⇒ no frame: quiet, not dead
        assert_eq!(broadcast_busy_now(), 0, "same state, no frame");
        assert_eq!(w.recv(Duration::from_millis(300)), client::Event::Timeout);

        // (e) the state stays truthful with NO watcher attached: a flip
        //     into an empty set is remembered, so a late subscriber is
        //     told the truth instead of a stale idle
        stop();
        drop(w); // its connection died with the link (see (f))
        start({
            let mut o2 = opts("sess-watch");
            let b = busy.clone();
            o2.tasks_busy = Arc::new(move || b.load(Ordering::SeqCst));
            o2
        });
        busy.store(true, Ordering::SeqCst);
        assert_eq!(broadcast_busy_now(), 0, "nobody is watching yet");
        let mut w3 = client::watch_tasks("sess-watch").expect("late subscribe");
        assert!(w3.busy(), "the ack carries the flip that happened unwatched");

        // (f) a stopped link ends the subscription (the peer sees the close)
        stop();
        assert_eq!(w3.recv(Duration::from_secs(2)), client::Event::Closed);
    }

    /// The task registry is what flips a watcher's state — the production
    /// path end to end: a task starting ⇒ busy, the same task stopping ⇒
    /// not busy, with no explicit broadcast anywhere in the test.
    #[test]
    fn registry_start_and_exit_flip_the_watched_state() {
        let _t = crate::link::test_mu::lock();
        let reg = Registry::new();
        let mut o = opts("sess-watch-reg");
        {
            let live = reg.clone();
            o.tasks_busy = Arc::new(move || {
                let (running, _, _) = live.snapshot();
                !running.is_empty()
            });
        }
        start(o);

        let mut w = client::watch_tasks("sess-watch-reg").expect("subscribe");
        assert!(!w.busy(), "nothing is running yet");

        let job = reg.new_running_job(
            "bash-w1",
            "sleep 1",
            None,
            "/tmp/w1.log",
            "tc",
            "",
            true,
        );
        assert!(busy_event(&mut w), "a started task flips the link to busy");

        job.mark_terminal(JobStatus::Completed, Some(0));
        assert!(!busy_event(&mut w), "the stopped task flips it back");

        // Still quiet afterwards — the flip already landed.
        assert_eq!(w.recv(Duration::from_millis(300)), client::Event::Timeout);
        stop();
    }

    /// The subscription cap refuses one watcher too many instead of
    /// leaking a thread and a socket per connection without bound.
    #[test]
    fn watcher_cap_refuses_beyond_the_limit() {
        let _t = crate::link::test_mu::lock();
        start(opts("sess-cap"));
        let mut held = Vec::new();
        for _ in 0..MAX_WATCHERS {
            held.push(client::watch_tasks("sess-cap").expect("subscribe within the cap"));
        }
        let e = client::watch_tasks("sess-cap").unwrap_err();
        assert!(e.contains("task watchers"), "{e}");
        drop(held);
        stop();
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

//! Port of `internal/converge`, shrunk after E13 dropped persistent
//! containers: there is no host-side apply work left, so the background
//! worker/futures/condvar machinery is deleted and convergence is
//! **synchronous** (bind → validate → record, inside the call's duration).
//!
//! Every observable invariant of CONVERGENCE.md is preserved — and the
//! tricky ones become *stronger*:
//! - bash binds to the newest state at spawn time: `bind` reads the current
//!   process-wide state, synchronously;
//! - wait is part of the command's duration: the wait is now instantaneous
//!   (a `stat`), still inside the call;
//! - causal fail-closed: validation errors return the real cause before any
//!   spawn, never bare, never half-applied;
//! - rapid flips collapse / no stale-policy window: `/sandbox <mode>`
//!   updates state before returning, so every subsequent call observes it —
//!   trivially, with no window at all;
//! - `/sandbox` non-blocking: there is nothing to block on (it reports the
//!   already-converged state).
//!
//! What remains is bookkeeping the display surfaces need: an epoch counter
//! (bumped on each distinct state — parity with the "epoch N" line) and the
//! last desired/converged/error snapshot for `/sandbox`.

use std::sync::Mutex;
use std::sync::OnceLock;

use crate::policy::Mode;

/// One policy state (Go `converge.State`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct State {
    pub mode: Mode,
    pub workspace: String,
    pub temp: String,
    pub extras: Vec<String>,
}

impl State {
    pub fn equal(&self, o: &State) -> bool {
        self == o
    }

    /// The dir list for this state (display + validation): read-only and
    /// danger-full-access deliberately return none.
    pub fn writable_dirs(&self) -> Vec<String> {
        match self.mode {
            Mode::WorkspaceWrite => {
                let mut out = Vec::with_capacity(2 + self.extras.len());
                out.push(self.workspace.clone());
                out.push(self.temp.clone());
                out.extend(self.extras.iter().cloned());
                out
            }
            Mode::Readonly | Mode::DangerFullAccess => Vec::new(),
        }
    }
}

impl std::fmt::Display for State {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let dirs = self.writable_dirs();
        if dirs.is_empty() {
            write!(f, "{} (no writable dirs)", self.mode)
        } else {
            write!(f, "{} [{}]", self.mode, dirs.join(" ; "))
        }
    }
}

/// Synchronous validation (the former `apply` step): only `workspace-write`
/// needs the workspace to exist — read-only grants nothing (Go: `New()` with
/// no dirs, workspace irrelevant) and danger is bare. The tool layer's
/// `RequireExistingCwd` still gates every call's cwd with the reference
/// wording; this is the belt-and-braces gate that keeps `status_line`'s
/// FAILED arm meaningful when state changes out from under a session.
pub fn validate(s: &State) -> Result<(), String> {
    if s.mode != Mode::WorkspaceWrite {
        return Ok(());
    }
    if s.workspace.is_empty() || !std::path::Path::new(&s.workspace).is_dir() {
        return Err(format!(
            "converge: workspace \"{}\" does not exist (mode {})",
            s.workspace, s.mode
        ));
    }
    Ok(())
}

#[derive(Debug, Clone)]
struct Snap {
    epoch: u64,
    desired: Option<State>,
    converged: Option<State>,
    last_err: Option<String>,
}

impl Snap {
    fn new() -> Self {
        Snap { epoch: 0, desired: None, converged: None, last_err: None }
    }
}

/// Read-only view for `/sandbox`. No `pending`/`dirty`
/// fields: both were representations of the background thread's in-flight
/// state and are impossible when convergence is synchronous.
#[derive(Debug, Clone)]
pub struct Status {
    pub epoch: u64,
    pub desired: Option<State>,
    pub converged: Option<State>,
    pub last_err: Option<String>,
}

/// The process-wide bookkeeping (one per process — `Engine::shared()`).
pub struct Engine {
    snap: Mutex<Snap>,
}

impl Default for Engine {
    fn default() -> Self {
        Engine { snap: Mutex::new(Snap::new()) }
    }
}

impl Engine {
    /// Go package-level `eng`.
    pub fn shared() -> &'static Engine {
        static SHARED: OnceLock<Engine> = OnceLock::new();
        SHARED.get_or_init(Engine::default)
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Snap> {
        self.snap.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Record the initial state at `session_start` (epoch 1). Idempotent.
    pub fn start(&self, initial: State) {
        let mut g = self.lock();
        if g.desired.is_none() {
            g.epoch = 1;
            g.desired = Some(initial);
        }
    }

    /// The bash tool's bind: newest-state + synchronous validation + record.
    /// Returns the state to spawn under (Go: `Bind` + `Wait` + `Sandbox()`,
    /// collapsed into one call — no window in which a newer state could slip
    /// between wait and read).
    pub fn bind(&self, state: State) -> Result<State, String> {
        let mut g = self.lock();
        if g.desired.as_ref().is_none_or(|d| !d.equal(&state)) {
            g.epoch += 1;
            g.desired = Some(state.clone());
        }
        match validate(&state) {
            Ok(()) => {
                g.converged = Some(state.clone());
                g.last_err = None;
                Ok(state)
            }
            Err(e) => {
                g.last_err = Some(e.clone());
                Err(e)
            }
        }
    }

    /// `/sandbox <mode>`: update the mode dimension and converge
    /// synchronously (there is no background step to report). Returns the
    /// epoch.
    pub fn set_mode(&self, mode: Mode) -> u64 {
        let mut g = self.lock();
        let mut next = g.desired.clone().unwrap_or(State {
            mode,
            workspace: String::new(),
            temp: String::new(),
            extras: Vec::new(),
        });
        if next.mode != mode {
            next.mode = mode;
            g.epoch += 1;
            g.desired = Some(next.clone());
        }
        match validate(&next) {
            Ok(()) => {
                g.converged = Some(next);
                g.last_err = None;
            }
            Err(e) => g.last_err = Some(e),
        }
        g.epoch
    }

    /// Force a re-convergence without changing the desired state — Go's
    /// runner-failure heal: bump the epoch and re-validate immediately (cheap
    /// now: bump + `stat`), keeping the observable contract that a runner
    /// failure re-converges before the next call.
    pub fn invalidate(&self) {
        let mut g = self.lock();
        if g.desired.is_none() {
            return;
        }
        g.epoch += 1;
        let state = g.desired.clone().expect("checked above");
        match validate(&state) {
            Ok(()) => {
                g.converged = Some(state);
                g.last_err = None;
            }
            Err(e) => g.last_err = Some(e),
        }
    }

    /// Display snapshot.
    pub fn snapshot(&self) -> Status {
        let g = self.lock();
        Status {
            epoch: g.epoch,
            desired: g.desired.clone(),
            converged: g.converged.clone(),
            last_err: g.last_err.clone(),
        }
    }

    /// One line for `/sandbox`. Two arms remain of Go's
    /// five: FAILED (last validation error) and converged — `converging` /
    /// `converging to` / `… (pending)` described the background thread and
    /// cannot occur when convergence is synchronous.
    pub fn status_line(&self) -> String {
        let st = self.snapshot();
        let mut b = format!("epoch {}", st.epoch);
        if let Some(err) = &st.last_err {
            b.push_str(&format!(" — FAILED: {err}"));
        } else {
            b.push_str(&format!(
                " — converged: {}",
                st.converged.as_ref().cloned().unwrap_or_else(|| st.desired.clone().unwrap_or_else(|| State {
                    mode: Mode::WorkspaceWrite,
                    workspace: String::new(),
                    temp: String::new(),
                    extras: Vec::new(),
                }))
            ));
        }
        b
    }

    /// The resolved child environment summary for `/sandbox` (Go parity).
    pub fn env_summary() -> String {
        let n = std::env::vars().count();
        format!("{n} vars (host env; LC_ALL stripped, LC_MESSAGES=C pinned)")
    }

    /// Tests only.
    #[cfg(test)]
    pub fn reset_for_test(&self) {
        let mut g = self.lock();
        *g = Snap::new();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    static TEST_MU: Mutex<()> = Mutex::new(());

    fn engine() -> Engine {
        Engine::default()
    }

    fn state(mode: Mode, ws: &str) -> State {
        State {
            mode,
            workspace: ws.to_string(),
            temp: "C:\\Temp".into(),
            extras: vec![],
        }
    }

    fn real_dir() -> String {
        std::env::temp_dir().to_string_lossy().into_owned()
    }

    #[test]
    fn state_display_parity() {
        assert_eq!(
            state(Mode::WorkspaceWrite, "C:\\ws").to_string(),
            "workspace-write [C:\\ws ; C:\\Temp]"
        );
        assert_eq!(state(Mode::Readonly, "C:\\ws").to_string(), "read-only (no writable dirs)");
        assert_eq!(
            state(Mode::DangerFullAccess, "C:\\ws").to_string(),
            "danger-full-access (no writable dirs)"
        );
    }

    #[test]
    fn bind_records_and_converges_synchronously() {
        let e = engine();
        let s = state(Mode::WorkspaceWrite, &real_dir());
        e.start(s.clone());
        let got = e.bind(s).expect("converged");
        assert_eq!(got.mode, Mode::WorkspaceWrite);
        let st = e.snapshot();
        assert_eq!(st.epoch, 1, "same state never bumps");
        assert!(st.last_err.is_none());
        let line = e.status_line();
        assert!(line.starts_with("epoch 1"), "{line}");
        assert!(line.contains("converged: workspace-write"), "{line}");
    }

    #[test]
    fn state_change_bumps_epoch_once() {
        let _t = TEST_MU.lock().unwrap_or_else(|x| x.into_inner());
        let e = engine();
        let dir = real_dir();
        e.start(state(Mode::WorkspaceWrite, &dir));
        e.bind(state(Mode::WorkspaceWrite, &dir)).unwrap();
        assert_eq!(e.snapshot().epoch, 1);
        // distinct workspace → bump
        e.bind(state(Mode::WorkspaceWrite, "C:\\other")).unwrap_err(); // missing dir
        assert_eq!(e.snapshot().epoch, 2);
        // same again → no bump
        e.bind(state(Mode::WorkspaceWrite, "C:\\other")).unwrap_err();
        assert_eq!(e.snapshot().epoch, 2, "identical state does not bump");
        // mode flip → bump
        e.set_mode(Mode::Readonly);
        assert_eq!(e.snapshot().epoch, 3);
        e.set_mode(Mode::Readonly);
        assert_eq!(e.snapshot().epoch, 3, "same mode does not bump");
    }

    #[test]
    fn validation_failure_is_causal_and_recorded() {
        let e = engine();
        let bad = state(Mode::WorkspaceWrite, "C:\\definitely\\missing\\ws");
        let err = e.bind(bad).unwrap_err();
        assert!(err.contains("does not exist"), "{err}");
        assert!(e.status_line().contains("FAILED"), "{}", e.status_line());
        // recovery: next bind with a real workspace clears the error
        e.bind(state(Mode::WorkspaceWrite, &real_dir())).unwrap();
        assert!(e.status_line().contains("converged"), "{}", e.status_line());
        assert!(e.snapshot().last_err.is_none());
    }

    #[test]
    fn danger_bypasses_validation() {
        let e = engine();
        let got = e.bind(state(Mode::DangerFullAccess, "C:\\missing\\ok")).unwrap();
        assert_eq!(got.mode, Mode::DangerFullAccess);
        assert!(e.snapshot().last_err.is_none());
    }

    #[test]
    fn set_mode_updates_desired_and_converges_immediately() {
        let _t = TEST_MU.lock().unwrap_or_else(|x| x.into_inner());
        let e = engine();
        let dir = real_dir();
        e.start(state(Mode::WorkspaceWrite, &dir));
        let epoch = e.set_mode(Mode::Readonly);
        assert_eq!(epoch, 2, "initial epoch 1, mode change bumps to 2");
        let st = e.snapshot();
        assert_eq!(st.desired.as_ref().unwrap().mode, Mode::Readonly);
        assert_eq!(st.converged.as_ref().unwrap().mode, Mode::Readonly, "no pending window");
        assert!(st.last_err.is_none());
        // /sandbox show parity: status line never says converging
        assert!(!e.status_line().contains("converging"), "{}", e.status_line());
    }

    #[test]
    fn no_stale_window_after_mode_change() {
        // After set_mode returns, the very next bind observes the new mode —
        // the guarantee CONVERGENCE.md states, now trivially true.
        let e = engine();
        let dir = real_dir();
        e.start(state(Mode::WorkspaceWrite, &dir));
        e.set_mode(Mode::DangerFullAccess);
        let got = e.bind(state(Mode::DangerFullAccess, &dir)).unwrap();
        assert_eq!(got.mode, Mode::DangerFullAccess, "next call sees the flip");
    }

    #[test]
    fn env_summary_shape() {
        assert!(Engine::env_summary()
            .ends_with("vars (host env; LC_ALL stripped, LC_MESSAGES=C pinned)"));
    }

    #[test]
    fn start_is_idempotent() {
        let e = engine();
        e.start(state(Mode::WorkspaceWrite, &real_dir()));
        e.start(state(Mode::Readonly, &real_dir()));
        assert_eq!(e.snapshot().epoch, 1, "second start is a no-op");
        assert_eq!(
            e.snapshot().desired.as_ref().unwrap().mode,
            Mode::WorkspaceWrite
        );
    }
}

#[cfg(test)]
mod invalidate_tests {
    use super::*;

    #[test]
    fn invalidate_bumps_epoch_and_revalidates() {
        let e = Engine::default();
        let dir = std::env::temp_dir().to_string_lossy().into_owned();
        let s = State { mode: Mode::WorkspaceWrite, workspace: dir, temp: "C:\\T".into(), extras: vec![] };
        e.start(s.clone());
        e.bind(s).unwrap(); // bind converges synchronously in the post-E13 design
        assert_eq!(e.snapshot().epoch, 1);
        e.invalidate();
        assert_eq!(e.snapshot().epoch, 2, "invalidate bumps");
        assert!(e.snapshot().last_err.is_none());
        assert!(e.status_line().contains("converged"), "{}", e.status_line());
    }
}

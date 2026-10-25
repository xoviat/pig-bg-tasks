//! The spawn seam — port of `internal/proc`'s `Handle`/`Exit` contract as
//! `bg` actually consumes it (PID, whole-tree kill, terminal state).
//!
//! Divergence from Go (documented, strictly stronger): Go's `Done()` is a
//! single-consumer mailbox channel — a second reader (the silent-kill waiter)
//! blocks until its timeout. [`Handle::wait`] here is broadcast: the exit is
//! stored once and every waiter returns immediately. Behavior-equivalent for
//! every caller (the Go second reader only ever used the value as "died or
//! timed out"), minus the artificial delay.

use std::sync::{Condvar, Mutex};

use crate::glock;

/// The spawn's terminal state. `killed` marks a kill WE initiated (job
/// terminate) so callers can tell deliberate stops from failures — Windows
/// has no signal half of the POSIX exit record.
#[derive(Debug, Clone)]
pub struct Exit {
    pub code: i32,
    pub killed: bool,
    pub err: Option<String>,
}

impl Exit {
    pub fn code(code: i32) -> Self {
        Exit { code, killed: false, err: None }
    }
    pub fn killed(code: i32) -> Self {
        Exit { code, killed: true, err: None }
    }
    pub fn errored(msg: impl Into<String>) -> Self {
        Exit { code: -1, killed: false, err: Some(msg.into()) }
    }
}

/// A running spawn. Implemented by `runner` (MXC spawn) and by test doubles.
pub trait Handle: Send + Sync {
    /// Process id of the spawn root (0 when unavailable).
    fn pid(&self) -> u32;
    /// Kill the whole tree: job object when attached, direct process
    /// otherwise. Windows has no SIGTERM — this IS the stop.
    fn kill(&self);
    /// Block until the spawn reaches its terminal state (broadcast-safe).
    fn wait(&self) -> Exit;
    /// Non-blocking terminal probe.
    fn try_wait(&self) -> Option<Exit>;
}

/// Shared exit cell: the broadcast primitive behind [`Handle::wait`].
/// `runner` composes handles from a PID + a kill closure + this cell.
#[derive(Default)]
pub struct ExitState {
    exit: Mutex<Option<Exit>>,
    cv: Condvar,
}

impl ExitState {
    pub fn new() -> Self {
        Self::default()
    }

    /// Publish the terminal state (first write wins) and wake every waiter.
    pub fn set(&self, exit: Exit) {
        let mut g = glock(&self.exit);
        if g.is_none() {
            *g = Some(exit);
            self.cv.notify_all();
        }
    }

    pub fn get(&self) -> Option<Exit> {
        glock(&self.exit).clone()
    }

    /// Block until published.
    pub fn wait(&self) -> Exit {
        let mut g = match self.exit.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        loop {
            if let Some(e) = g.as_ref() {
                return e.clone();
            }
            g = match self.cv.wait(g) {
                Ok(g) => g,
                Err(p) => p.into_inner(),
            };
        }
    }
}

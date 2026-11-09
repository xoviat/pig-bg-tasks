//! Port of `internal/bg` — the extension's core: job registry, bounded
//! output handling, lifecycle (tree-kill semantics via the `Handle` seam),
//! exactly-once completion notifications, and the UI surface (hint widget,
//! status pill, list formatting).
//!
//! Parity notes (RUST-PLAN §5 "mechanism-independent, port first"):
//! - the registry is in-process; `Registry::shared()` is the process
//!   singleton (Go `bg.Default()`), `Registry::new()` builds fresh instances
//!   for tests;
//! - the two Go imports become seams defined *here* and implemented outside:
//!   [`handle::Handle`] (spawn/kill/wait — runner implements it) and
//!   [`port::SdkPort`] (retained PiG context — ext layer implements it);
//! - Go's `sdk.Context{}` zero-value check maps to `Option<Arc<dyn SdkPort>>`.

pub mod dbg;
pub mod handle;
pub mod lifecycle;
pub mod notify;
pub mod output;
pub mod port;
pub mod registry;
pub mod ui;

#[cfg(test)]
pub(crate) mod mock;

pub use handle::{Exit, ExitState, Handle};
pub use port::{CustomMessage, SendOptions, SdkPort};
pub use registry::{BackgroundReason, ForegroundSlot, Job, JobStatus, Registry};

use std::sync::{Mutex, MutexGuard};

// Constants — parity with the reference's types.ts / bg.go.
pub const DEFAULT_TIMEOUT_MS: u64 = 120_000;
pub const QUICK_COMPLETION_MS: u64 = 2_000;
pub const OUTPUT_PREVIEW_CHARS: usize = 12_000;
pub const TASK_OUTPUT_TAIL_CHARS: usize = 32 * 1024;
pub const NOTIFY_TAIL_CHARS: i64 = 1_000;
pub const MAX_LOG_BYTES: u64 = 64 * 1024 * 1024;
pub const OUTPUT_WATCH_INTERVAL_MS: u64 = 2_000;
pub const KILL_GRACE_SECS: u64 = 5;
pub const RECENT_TERMINAL_KEEP: usize = 20;
pub const MAX_CONCURRENT_JOBS: usize = 16;
pub const STALE_LOG_MAX_AGE_SECS: u64 = 24 * 60 * 60;
pub const FOREGROUND_TAIL_BYTES: i64 = 4_096;

/// Lock helper that tolerates poisoning: Go's locks never panic, and debug
/// output / status rendering must not be able to take the extension down.
pub(crate) fn glock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

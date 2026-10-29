//! pig-bg-tasks Rust extension — single crate (RUST-PLAN §5; collapsed from
//! a 6-crate workspace for compile speed).
//!
//! The pig factory: [`new_extension`] builds the combined extension (ONE
//! composed `bash` tool = bg layer × sandbox layer, plus task tools,
//! `/sandbox`-family commands, notifications and session wiring). Pig owns
//! the entry point (`Extension::run` is called by the host loader — the E7
//! scaffold pattern: factory only, no `main`).

pub mod bg;
pub mod classify;
pub mod escalate;
pub mod ext;
pub mod policy;
pub mod runner;

/// The conventional factory entry point.
pub fn new_extension() -> pig_sdk::Extension {
    ext::build()
}

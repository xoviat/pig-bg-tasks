//! pig-bg-tasks Rust extension — workspace root (RUST-PLAN §5).
//!
//! The pig factory: [`new_extension`] builds the combined extension (ONE
//! composed `bash` tool = bg layer × sandbox layer, plus task tools,
//! `/sandbox`-family commands, notifications and session wiring). Pig owns
//! the entry point (`Extension::run` is called by the host loader — the E7
//! scaffold pattern: factory only, no `main`).

pub mod ext;

/// The conventional factory entry point.
pub fn new_extension() -> pig_sdk::Extension {
    ext::build()
}

//! Sandbox-policy mirroring across the parent link (DELEGATED-WORKSPACES
//! §B): a delegated child **mirrors the policy of the session that spawned
//! it** — fetched over the socket at `session_start`.
//!
//! Semantics:
//!
//! - **mode**: with a reachable parent the parent's mode is the baseline —
//!   the child's own `sandbox.json` default does not apply — and a local
//!   `/sandbox` choice may only *narrow* it (`min(choice, parent)`); nothing
//!   widens a child past its parent.
//! - **extra writable roots**: the parent's list replaces the child's (a
//!   mirror, not a union) — same machine, same config, so it is normally
//!   identical anyway; when it differs, the parent is authoritative.
//!
//! Nothing here dials the socket: [`crate::link::client::fetch_policy`]
//! does that at `session_start`; an unreachable parent simply leaves this
//! empty and the child keeps its local policy (it never *widens* by being
//! unreachable).

use std::sync::Mutex;

use crate::policy::Mode;

/// What a child mirrored from its parent session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Inherited {
    /// The parent session id (`PIG_PARENT_SESSION`).
    pub parent: String,
    pub mode: Mode,
    pub extras: Vec<String>,
}

static INHERITED: Mutex<Option<Inherited>> = Mutex::new(None);

fn lock() -> std::sync::MutexGuard<'static, Option<Inherited>> {
    INHERITED.lock().unwrap_or_else(|e| e.into_inner())
}

/// Install the mirrored policy (called once at `session_start`, child side).
pub fn set(parent: String, mode: Mode, extras: Vec<String>) {
    *lock() = Some(Inherited { parent, mode, extras });
}

/// The mirrored policy, if this session is a child with a reachable parent.
pub fn get() -> Option<Inherited> {
    lock().clone()
}

/// Drop the mirrored policy (session shutdown).
pub fn clear() {
    *lock() = None;
}

/// The effective mode: the parent's mode is the baseline for a mirrored
/// child (its own config default does not apply), and a local override may
/// only narrow it. Identity when nothing is mirrored.
pub fn mirror_mode(mode_override: Option<Mode>, config_default: Mode) -> Mode {
    match lock().as_ref() {
        Some(i) => mode_override.unwrap_or(i.mode).min(i.mode),
        None => mode_override.unwrap_or(config_default),
    }
}

/// Cap `local` at the mirrored mode — `/sandbox` can never widen a child
/// past its parent (identity when nothing is mirrored).
pub fn floor(local: Mode) -> Mode {
    match lock().as_ref() {
        Some(i) => local.min(i.mode),
        None => local,
    }
}

/// The effective extras: the parent's list when mirrored, the local config's
/// otherwise.
pub fn mirror_extras(local: &[String]) -> Vec<String> {
    match lock().as_ref() {
        Some(i) => i.extras.clone(),
        None => local.to_vec(),
    }
}

/// Serializes the tests that mutate the process-global mirrored policy
/// (the same lock the `resolve_effective_mode` tests take — mirroring is
/// part of that function's behavior now).
#[cfg(test)]
pub(crate) fn test_lock() -> std::sync::MutexGuard<'static, ()> {
    static MU: Mutex<()> = Mutex::new(());
    MU.lock().unwrap_or_else(|e| e.into_inner())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mirror_sets_the_baseline_and_narrowing_is_allowed() {
        let _t = test_lock();
        clear();
        // no mirror: identity (config default + override)
        assert_eq!(mirror_mode(None, Mode::WorkspaceWrite), Mode::WorkspaceWrite);
        assert_eq!(
            mirror_mode(Some(Mode::DangerFullAccess), Mode::Readonly),
            Mode::DangerFullAccess
        );

        // mirrored: the parent's mode is the baseline — the child's own
        // config (even a stricter one) does not apply
        set("parent-1".into(), Mode::WorkspaceWrite, vec![]);
        assert_eq!(
            mirror_mode(None, Mode::Readonly),
            Mode::WorkspaceWrite,
            "the parent's mode replaces the child's config default"
        );
        assert_eq!(
            mirror_mode(None, Mode::DangerFullAccess),
            Mode::WorkspaceWrite,
            "…whatever the child's config says"
        );
        // a local choice may narrow, never widen
        assert_eq!(mirror_mode(Some(Mode::Readonly), Mode::DangerFullAccess), Mode::Readonly);
        assert_eq!(
            mirror_mode(Some(Mode::DangerFullAccess), Mode::DangerFullAccess),
            Mode::WorkspaceWrite,
            "widening is capped at the parent"
        );
        // the /sandbox cap agrees
        assert_eq!(floor(Mode::DangerFullAccess), Mode::WorkspaceWrite);
        assert_eq!(floor(Mode::Readonly), Mode::Readonly);

        clear();
        assert_eq!(mirror_mode(None, Mode::DangerFullAccess), Mode::DangerFullAccess);
        assert_eq!(floor(Mode::DangerFullAccess), Mode::DangerFullAccess);
    }

    #[test]
    fn extras_mirror_the_parent_exactly() {
        let _t = test_lock();
        clear();
        let local = vec!["C:\\a".to_string(), "C:\\b".to_string()];
        assert_eq!(mirror_extras(&local), local, "identity without a parent");

        set(
            "parent-1".into(),
            Mode::WorkspaceWrite,
            vec!["C:\\parent-a".to_string(), "C:\\parent-b".to_string()],
        );
        assert_eq!(
            mirror_extras(&local),
            vec!["C:\\parent-a".to_string(), "C:\\parent-b".to_string()],
            "the parent's list replaces the child's (a mirror, not a union)"
        );
        clear();
    }

    #[test]
    fn roundtrip_get_and_clear() {
        let _t = test_lock();
        clear();
        assert!(get().is_none());
        set("p".into(), Mode::Readonly, vec!["C:\\x".into()]);
        let i = get().expect("mirrored");
        assert_eq!(i.parent, "p");
        assert_eq!(i.mode, Mode::Readonly);
        assert_eq!(i.extras, vec!["C:\\x".to_string()]);
        clear();
        assert!(get().is_none());
    }
}

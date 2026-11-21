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
//! The mirror is not a one-shot read: whenever the parent widens or
//! narrows its permission level, the parent pushes the new snapshot over
//! the same socket (`op:"policy-update"`) and [`apply_update`] moves this
//! baseline to it — both directions, but only for the session that
//! spawned this child.
//!
//! Nothing here *dials* the socket: [`crate::link::client::fetch_policy`]
//! does that at `session_start`, and the push arrives on this session's
//! own listener — an unreachable parent simply leaves the mirror empty (or
//! at its last known value) and the child keeps that policy (it never
//! *widens* by being unreachable).

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

/// Apply a policy pushed over the parent link (`op:"policy-update"`): the
/// sender must be the session this child mirrors — anyone else's frame is
/// refused (fail-closed) — and the snapshot replaces the baseline, so a
/// parent's **widened or narrowed** level reaches a child that mirrored
/// it at its `session_start`.
///
/// Returns whether it applied. No mirror, a foreign sender, or an unknown
/// mode leaves the mirror untouched (`false`), which the parent traces.
pub fn apply_update(sender: &str, policy: &crate::link::Policy) -> bool {
    let mut g = lock();
    let Some(current) = g.as_mut() else {
        crate::bg::dbg::trace(serde_json::json!({
            "phase": "link_policy_update_refused", "sender": sender, "why": "no mirror"
        }));
        return false;
    };
    if current.parent != sender {
        crate::bg::dbg::trace(serde_json::json!({
            "phase": "link_policy_update_refused", "sender": sender,
            "why": "not this session's parent", "parent": current.parent
        }));
        return false;
    }
    let Some(mode) = crate::policy::parse_mode(&policy.mode) else {
        crate::bg::dbg::trace(serde_json::json!({
            "phase": "link_policy_update_refused", "sender": sender,
            "why": "unknown mode", "mode": policy.mode
        }));
        return false;
    };
    current.mode = mode;
    current.extras = policy.extras.clone();
    crate::bg::dbg::trace(serde_json::json!({
        "phase": "link_policy_updated", "parent": current.parent, "mode": mode.as_str()
    }));
    true
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

    fn pushed(mode: &str, extras: &[&str]) -> crate::link::Policy {
        crate::link::Policy {
            mode: mode.to_string(),
            workspace: String::new(),
            temp: String::new(),
            extras: extras.iter().map(|s| s.to_string()).collect(),
        }
    }

    /// A parent's level change, pushed over the link, moves this child's
    /// baseline in **both** directions — and only the parent may move it.
    #[test]
    fn apply_update_moves_the_baseline_in_both_directions() {
        let _t = test_lock();
        clear();
        // nothing mirrored ⇒ nothing to move (fail-closed)
        assert!(!apply_update("parent-1", &pushed("read-only", &[])));

        set("parent-1".into(), Mode::WorkspaceWrite, vec!["C:\\old".into()]);
        // the parent narrows ⇒ the child's baseline narrows (roots too)
        assert!(apply_update("parent-1", &pushed("read-only", &[])));
        let i = get().expect("mirrored");
        assert_eq!(i.mode, Mode::Readonly);
        assert!(i.extras.is_empty(), "the roots mirror follows the level");
        assert_eq!(floor(Mode::DangerFullAccess), Mode::Readonly, "the new cap holds");

        // the parent widens ⇒ the child's baseline widens
        assert!(apply_update("parent-1", &pushed("danger-full-access", &["C:\\new"])));
        let i = get().expect("mirrored");
        assert_eq!(i.mode, Mode::DangerFullAccess);
        assert_eq!(i.extras, vec!["C:\\new".to_string()]);

        // any other sender — or an unknown mode — moves nothing
        assert!(!apply_update("someone-else", &pushed("read-only", &[])));
        assert!(!apply_update("parent-1", &pushed("admin", &[])));
        let i = get().expect("mirrored");
        assert_eq!(i.mode, Mode::DangerFullAccess, "the mirror kept its value");
        clear();
    }
}

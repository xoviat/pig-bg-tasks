//! Port of `internal/permission` — the process-wide mode override backing
//! `/sandbox`. One PiG extension process serves every session, so a static IS
//! the process-wide singleton the reference needed `globalThis` for. The
//! override applies on the next tool call in every session.

use std::sync::Mutex;

use crate::policy::Mode;

static OVERRIDE: Mutex<Option<Mode>> = Mutex::new(None);

/// Current process-wide override (`None` = none).
pub fn get() -> Option<Mode> {
    *guard()
}

/// Install a new process-wide override.
pub fn set(mode: Mode) {
    *guard() = Some(mode);
}

/// Test hook (the Go package had none; cache hygiene needed for isolation).
#[cfg(test)]
pub(crate) fn clear() {
    *guard() = None;
}

fn guard() -> std::sync::MutexGuard<'static, Option<Mode>> {
    OVERRIDE.lock().unwrap_or_else(|e| e.into_inner())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn override_roundtrip() {
        clear();
        assert_eq!(get(), None);
        set(Mode::Readonly);
        assert_eq!(get(), Some(Mode::Readonly));
        set(Mode::DangerFullAccess);
        assert_eq!(get(), Some(Mode::DangerFullAccess));
        clear();
        assert_eq!(get(), None);
    }
}

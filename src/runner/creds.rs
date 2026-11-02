//! `GH_TOKEN` pass-through for confined spawns — the gh-CLI fix.
//!
//! Measured on this host (Windows 11, gh 2.82.1): MXC containment blocks the
//! Windows Credential Manager outright — `CredReadW`/`CredEnumerateW` return
//! `ERROR_ACCESS_DENIED` (5) for ANY target name inside the container, while
//! outside it the same call succeeds (`gh:github.com:<user>`). gh stores its
//! token ONLY in the keyring (`go-keyring`/`wincred`; `hosts.yml` carries no
//! `oauth_token`), so inside a confined spawn gh sends no `Authorization`
//! header and every API call is a 401 — and `gh auth login` cannot fix it
//! from inside either (the vault write is denied too).
//!
//! The escape hatch is the environment: `GH_TOKEN` is honored by gh without
//! touching the vault, and the container env is inherited unscrubbed
//! (`inherit_default_environment`), so an injected pair reaches the child.
//! Resolution (per spawn, cached host-side):
//!
//! 1. the host env `GH_TOKEN`/`GITHUB_TOKEN` when set — explicit user choice
//!    wins outright (an empty value counts as set: don't second-guess);
//! 2. otherwise the wincred token for the active github.com user (the
//!    extension runs in the pig host process, OUTSIDE the container, where
//!    the vault is readable; the active user comes from gh's `hosts.yml`).
//!
//! Nothing is injected when neither source yields a token — this is a
//! pass-through, never a fabrication, and it never logs the secret.
//!
//! Scope: the caller (bash `build_spec`) injects this ONLY under
//! `workspace-write`. Read-only spawns stay tokenless, and
//! `danger-full-access` runs bare where wincred is readable natively.
//!
//! Non-Windows: env vars only (the POSIX runner is runtime-unavailable
//! anyway; keyring formats differ per platform).

use std::sync::Mutex;

/// The gh host we resolve credentials for (gh's default; GHE is out of scope).
const GH_HOST: &str = "github.com";

static WINCRED_TOKEN: Mutex<Option<Option<String>>> = Mutex::new(None);

/// Serializes the process-global env mutations in tests (shared with the
/// `bash` gate test — env vars are process-wide).
#[cfg(test)]
pub(crate) static ENV_TEST_MU: Mutex<()> = Mutex::new(());

fn g<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// The env pairs to layer into a spawn: `GH_TOKEN` (from host env or
/// wincred) plus `GITHUB_TOKEN` when the host env sets it. Empty when no
/// token is available anywhere.
pub fn gh_token_env() -> Vec<(String, String)> {
    // 1. Host env wins outright — gh reads `GH_TOKEN`, then `GITHUB_TOKEN`.
    let mut out: Vec<(String, String)> = Vec::new();
    for key in ["GH_TOKEN", "GITHUB_TOKEN"] {
        if let Ok(v) = std::env::var(key) {
            out.push((key.to_string(), v));
        }
    }
    if !out.is_empty() {
        return out;
    }
    // 2. The wincred token for the active user (cached — one vault read per
    //    process; the host-side read is a sub-millisecond CredReadW).
    if let Some(token) = wincred_token() {
        out.push(("GH_TOKEN".to_string(), token));
    }
    out
}

/// The gh keyring token (cached; `None` = unresolved, `Some(None)` = none).
fn wincred_token() -> Option<String> {
    let mut slot = g(&WINCRED_TOKEN);
    if let Some(cached) = slot.as_ref() {
        return cached.clone().filter(|t| !t.is_empty());
    }
    let resolved = resolve_wincred_token().filter(|t| !t.is_empty());
    *slot = Some(resolved.clone());
    resolved
}

fn resolve_wincred_token() -> Option<String> {
    inline_oauth_token().or_else(keyring_token)
}

/// gh's legacy plaintext storage: `oauth_token` next to the active user in
/// `hosts.yml` (older gh wrote the token there; harmless to honor).
fn inline_oauth_token() -> Option<String> {
    let hosts = read_hosts_yml()?;
    parse_hosts(&hosts, GH_HOST).1
}

/// The keyring target `gh:github.com:<user>` — `<user>` is the active
/// account from `hosts.yml` (fallbacks: every `users:` entry, then the
/// legacy unqualified `gh:github.com` target).
#[cfg(windows)]
fn keyring_token() -> Option<String> {
    let hosts = read_hosts_yml().unwrap_or_default();
    let (user, _) = parse_hosts(&hosts, GH_HOST);
    let mut targets: Vec<String> = Vec::new();
    if let Some(u) = user.as_ref().filter(|u| !u.is_empty()) {
        targets.push(format!("gh:{GH_HOST}:{u}"));
    }
    targets.push(format!("gh:{GH_HOST}"));
    targets.iter().find_map(|t| cred_read_generic(t))
}

#[cfg(not(windows))]
fn keyring_token() -> Option<String> {
    None
}

/// `%APPDATA%\GitHub CLI\hosts.yml` (gh's global config; absent is normal).
fn read_hosts_yml() -> Option<String> {
    let appdata = std::env::var_os("APPDATA")?;
    let path = std::path::Path::new(&appdata)
        .join("GitHub CLI")
        .join("hosts.yml");
    std::fs::read_to_string(path).ok()
}

/// The active user and inline `oauth_token` for `host` in a `hosts.yml`
/// body. Structure (gh-generated, 4-space indent):
///
/// ```yaml
/// github.com:
///     git_protocol: ssh
///     users:
///         xoviat:
///     user: xoviat
/// ```
///
/// Deliberately line-based rather than a YAML dependency: the file is
/// machine-written by gh, and the E9 pin keeps the dep list minimal.
fn parse_hosts(hosts: &str, host: &str) -> (Option<String>, Option<String>) {
    let mut current_host = String::new();
    let mut in_users = false;
    let mut active_user: Option<String> = None;
    let mut oauth_token: Option<String> = None;
    let mut accounts: Vec<String> = Vec::new();
    for line in hosts.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let indent = line.len() - line.trim_start().len();
        let trimmed = line.trim();
        if indent == 0 {
            current_host = trimmed.trim_end_matches(':').to_string();
            in_users = false;
            continue;
        }
        if current_host != host {
            continue;
        }
        match (indent, trimmed) {
            (4, "users:") => in_users = true,
            (4, t) if t.starts_with("user:") => {
                let v = t["user:".len()..].trim();
                if !v.is_empty() {
                    active_user = Some(v.to_string());
                }
            }
            (8, t) if in_users && t.ends_with(':') => {
                accounts.push(t.trim_end_matches(':').to_string());
            }
            (_, t) if t.starts_with("oauth_token:") => {
                // host-level or nested under the user entry — either placement
                let v = t["oauth_token:".len()..].trim();
                if !v.is_empty() {
                    oauth_token = Some(v.to_string());
                }
            }
            _ => {}
        }
    }
    let user = active_user.or_else(|| accounts.into_iter().next());
    (user, oauth_token)
}

/// One generic credential read (Windows): target name in, secret blob out.
#[cfg(windows)]
fn cred_read_generic(target: &str) -> Option<String> {
    use std::os::windows::ffi::OsStrExt;

    const CRED_TYPE_GENERIC: u32 = 1;

    #[repr(C)]
    struct FileTime {
        dw_low_date_time: u32,
        dw_high_date_time: u32,
    }

    #[repr(C)]
    struct CredentialW {
        flags: u32,
        cred_type: u32,
        target_name: *mut u16,
        comment: *mut u16,
        last_written: FileTime,
        cred_blob_size: u32,
        cred_blob: *mut u8,
        persist: u32,
        attribute_count: u32,
        attributes: *mut std::ffi::c_void,
        target_alias: *mut u16,
        user_name: *mut u16,
    }

    #[link(name = "advapi32")]
    extern "system" {
        fn CredReadW(
            target: *const u16,
            cred_type: u32,
            flags: u32,
            credential: *mut *mut CredentialW,
        ) -> i32;
        fn CredFree(buffer: *mut std::ffi::c_void);
    }

    let wide: Vec<u16> = std::ffi::OsStr::new(target)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let mut cred: *mut CredentialW = std::ptr::null_mut();
    // SAFETY: `wide` is NUL-terminated; on success `cred` points at a
    // CredReadW-allocated credential we free exactly once with CredFree.
    let ok = unsafe { CredReadW(wide.as_ptr(), CRED_TYPE_GENERIC, 0, &mut cred) };
    if ok == 0 || cred.is_null() {
        return None; // not found, or (in-container) ACCESS_DENIED — either way: no token
    }
    let token = unsafe {
        let c: &CredentialW = &*cred;
        if c.cred_blob.is_null() || c.cred_blob_size == 0 {
            None
        } else {
            let blob = std::slice::from_raw_parts(c.cred_blob, c.cred_blob_size as usize);
            Some(String::from_utf8_lossy(blob).into_owned())
        }
    };
    unsafe { CredFree(cred as *mut std::ffi::c_void) };
    token
}

#[cfg(test)]
mod tests {
    use super::*;

    const HOSTS: &str = "github.com:\n    git_protocol: ssh\n    users:\n        xoviat:\n    user: xoviat\n";

    #[test]
    fn parse_active_user_and_no_inline_token() {
        let (user, token) = parse_hosts(HOSTS, "github.com");
        assert_eq!(user.as_deref(), Some("xoviat"));
        assert_eq!(token, None);
    }

    #[test]
    fn parse_inline_oauth_token_and_users_fallback() {
        let hosts = "github.com:\n    users:\n        alice:\n        bob:\n    user: bob\n    oauth_token: gho_abc\n";
        let (user, token) = parse_hosts(hosts, "github.com");
        assert_eq!(user.as_deref(), Some("bob"));
        assert_eq!(token.as_deref(), Some("gho_abc"));
        // no `user:` line → first `users:` entry
        let (user, _) = parse_hosts("github.com:\n    users:\n        carol:\n", "github.com");
        assert_eq!(user.as_deref(), Some("carol"));
    }

    #[test]
    fn parse_scopes_to_the_named_host() {
        let hosts = "example.com:\n    users:\n        eve:\n    user: eve\ngithub.com:\n    user: alice\n";
        let (user, _) = parse_hosts(hosts, "github.com");
        assert_eq!(user.as_deref(), Some("alice"));
    }

    #[test]
    fn host_env_wins_over_wincred() {
        let _t = ENV_TEST_MU.lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var("GH_TOKEN", "from-env");
        std::env::remove_var("GITHUB_TOKEN");
        let env = gh_token_env();
        assert_eq!(env, vec![("GH_TOKEN".to_string(), "from-env".to_string())]);
        std::env::remove_var("GH_TOKEN");
    }

    #[test]
    fn github_token_env_is_passed_too() {
        let _t = ENV_TEST_MU.lock().unwrap_or_else(|e| e.into_inner());
        std::env::remove_var("GH_TOKEN");
        std::env::set_var("GITHUB_TOKEN", "from-env-2");
        let env = gh_token_env();
        assert_eq!(env, vec![("GITHUB_TOKEN".to_string(), "from-env-2".to_string())]);
        std::env::remove_var("GITHUB_TOKEN");
    }

    #[test]
    fn token_resolution_is_cached_and_resettable() {
        let _t = ENV_TEST_MU.lock().unwrap_or_else(|e| e.into_inner());
        *g(&WINCRED_TOKEN) = Some(Some("cached-token".to_string()));
        assert_eq!(wincred_token().as_deref(), Some("cached-token"));
        *g(&WINCRED_TOKEN) = None; // reset: real resolution (may or may not find one)
        let _ = wincred_token();
        // empty tokens never surface
        *g(&WINCRED_TOKEN) = Some(Some(String::new()));
        assert_eq!(wincred_token(), None);
        *g(&WINCRED_TOKEN) = None;
    }

    #[test]
    fn no_token_anywhere_yields_nothing() {
        let _t = ENV_TEST_MU.lock().unwrap_or_else(|e| e.into_inner());
        std::env::remove_var("GH_TOKEN");
        std::env::remove_var("GITHUB_TOKEN");
        *g(&WINCRED_TOKEN) = Some(None);
        assert!(gh_token_env().is_empty());
        *g(&WINCRED_TOKEN) = None;
    }

    /// Windows: the live read must not panic, and a found token is
    /// non-empty (never surfaces the empty-string credential).
    #[cfg(windows)]
    #[test]
    fn live_wincred_read_is_sound() {
        let _t = ENV_TEST_MU.lock().unwrap_or_else(|e| e.into_inner());
        *g(&WINCRED_TOKEN) = None;
        if let Some(t) = wincred_token() {
            assert!(!t.is_empty());
        }
        *g(&WINCRED_TOKEN) = None;
    }
}

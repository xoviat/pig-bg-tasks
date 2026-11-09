//! MXC wrapper (plan §4/§5) — the only MXC-aware crate:
//! - [`shell`]: `shellPath` resolution (settings win over PATH/standard
//!   locations), WSL-alias skip;
//! - [`request`]: `ContainerRequest` build from the converged policy
//!   (filesystem grants, network posture, UI, env, cwd, command-line
//!   quoting);
//! - [`proc`]: one spawn — confined through `mxc_sdk::v1::spawn`, bare
//!   (`danger-full-access`) through `std::process` + a tree-kill handle
//!   (KILL_ON_JOB_CLOSE job object on Windows, process group on Unix) —
//!   implementing [`crate::bg::Handle`];
//! - [`creds`]: `GH_TOKEN` pass-through for workspace-write spawns (the
//!   gh-CLI fix — wincred is blocked in-container);
//! - [`converge`]: the epoch engine (CONVERGENCE.md) — one background
//!   thread, bind/wait, causal fail-closed, collapse on rapid flips.

pub mod converge;
pub mod creds;
pub mod proc;
pub mod request;
pub mod shell;

use crate::policy::Mode;

/// Names a runner backend (Go `runner.Kind` — kept verbatim for `/sandbox`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    WindowsAcl,
    /// mxc's native backend on Unix: Bubblewrap on Linux, Seatbelt on macOS
    /// (mxc `Containment::Process` resolves per host OS).
    Posix,
    Unavailable,
}

impl Kind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Kind::WindowsAcl => "windows-acl",
            Kind::Posix => {
                if cfg!(target_os = "linux") {
                    "bwrap"
                } else if cfg!(target_os = "macos") {
                    "seatbelt"
                } else {
                    "posix"
                }
            }
            Kind::Unavailable => "unavailable",
        }
    }
}

/// `windows-acl`/`bwrap`/`seatbelt` are always "partial" (structural gaps:
/// NTFS hard-link aliasing, unconfined reads, standing grants) — honest docs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Enforcement {
    Full,
    Partial,
}

impl Enforcement {
    pub fn as_str(&self) -> &'static str {
        match self {
            Enforcement::Full => "full",
            Enforcement::Partial => "partial",
        }
    }
}

/// The verdict (cached per process).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Selected {
    pub kind: Kind,
    pub enforcement: Enforcement,
}

/// Fail-closed error: the command must never run bare.
#[derive(Debug)]
pub struct ErrUnavailable {
    pub detail: String,
}

impl std::fmt::Display for ErrUnavailable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if !self.detail.is_empty() {
            write!(
                f,
                "SANDBOX_UNAVAILABLE: sandbox runner failed before the command ran: {}",
                self.detail
            )
        } else {
            write!(
                f,
                "SANDBOX_UNAVAILABLE: no usable sandbox runner on this host; the command was NOT \
                 executed. Set mode \"danger-full-access\" explicitly to run unconfined."
            )
        }
    }
}

impl std::error::Error for ErrUnavailable {}

/// Shell could not be resolved (parity message).
pub const ERR_SHELL_UNAVAILABLE: &str =
    "bash shell could not be resolved (shellPath, then PATH, then the standard shell locations)";

fn chain_verdict() -> Selected {
    // Availability is "resolve a shell" on every platform (resolveability,
    // never spawn). Confinement itself is mxc's per-host `Containment::Process`
    // selection — ProcessContainer (Windows), Bubblewrap (Linux), Seatbelt
    // (macOS) — and if the host lacks the backend (e.g. `bwrap` off PATH) the
    // spawn fails with the backend's real cause, fail-closed.
    if shell::resolve().is_err() {
        return Selected { kind: Kind::Unavailable, enforcement: Enforcement::Full };
    }
    if cfg!(windows) {
        Selected { kind: Kind::WindowsAcl, enforcement: Enforcement::Partial }
    } else {
        Selected { kind: Kind::Posix, enforcement: Enforcement::Partial }
    }
}

/// Resolve the runner chain once per process (availability checks only —
/// "resolveability, never spawn").
pub fn select(_probe_timeout_ms: i32) -> Selected {
    static CACHED: std::sync::OnceLock<Selected> = std::sync::OnceLock::new();
    *CACHED.get_or_init(chain_verdict)
}

/// Tests only (Go `ResetCache` — the shell cache reset covers most needs;
/// this exists because `OnceLock` has no reset).
#[cfg(test)]
pub fn reset_select_cache_for_test() {
    // verdict derives entirely from shell::resolve, whose cache IS resettable;
    // select's OnceLock is only read after shell state is stable in tests.
}

/// Renders the `/sandbox` "runner:" line.
pub fn describe(sel: Selected, effective: Mode) -> String {
    if effective == Mode::DangerFullAccess {
        return "bypassed (danger-full-access)".to_string();
    }
    if sel.kind == Kind::Unavailable {
        return "unavailable (fail-closed: confined commands will be refused; no usable runner on this host)"
            .to_string();
    }
    format!("{} ({} enforcement)", sel.kind.as_str(), sel.enforcement.as_str())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn describe_lines_match_go() {
        let sel = Selected { kind: Kind::WindowsAcl, enforcement: Enforcement::Partial };
        assert_eq!(describe(sel, Mode::Readonly), "windows-acl (partial enforcement)");
        assert_eq!(describe(sel, Mode::DangerFullAccess), "bypassed (danger-full-access)");
        let down = Selected { kind: Kind::Unavailable, enforcement: Enforcement::Full };
        assert!(describe(down, Mode::WorkspaceWrite).starts_with("unavailable (fail-closed"));
        assert!(describe(down, Mode::DangerFullAccess) == "bypassed (danger-full-access)");
    }

    #[test]
    fn err_unavailable_wording() {
        let e = ErrUnavailable { detail: String::new() };
        assert!(e.to_string().starts_with("SANDBOX_UNAVAILABLE: no usable sandbox runner"));
        let e = ErrUnavailable { detail: "shell missing".into() };
        assert_eq!(
            e.to_string(),
            "SANDBOX_UNAVAILABLE: sandbox runner failed before the command ran: shell missing"
        );
    }

    #[test]
    fn kind_names_follow_the_host_backend() {
        // /sandbox renders the backend that actually confines on this OS.
        if cfg!(target_os = "linux") {
            assert_eq!(Kind::Posix.as_str(), "bwrap");
        } else if cfg!(target_os = "macos") {
            assert_eq!(Kind::Posix.as_str(), "seatbelt");
        } else {
            assert_eq!(Kind::Posix.as_str(), "posix");
        }
        assert_eq!(Kind::WindowsAcl.as_str(), "windows-acl");
        assert_eq!(Kind::Unavailable.as_str(), "unavailable");
    }
}

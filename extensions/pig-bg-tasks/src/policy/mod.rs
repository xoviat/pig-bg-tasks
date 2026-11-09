//! Port of `internal/policy` + `internal/permission` + `internal/config`
//! (plan §5): the file-effect mode model and path helpers, the process-wide
//! `/sandbox` override, and `sandbox.json` semantics — global-only, silent
//! project-file ignore, read-once-per-process, fail-safe defaults.
//!
//! Path divergence (documented in README, mirrored here): the reference reads
//! `~/.pi/agent/sandbox.json`; as a PiG extension we read
//! `<ConfigHome>/agent/sandbox.json`. Same filename, same schema.

pub mod config;
pub mod permission;

use std::path::Path;

/// One of the three permission modes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Mode {
    Readonly,
    WorkspaceWrite,
    DangerFullAccess,
}

impl Mode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Mode::Readonly => "read-only",
            Mode::WorkspaceWrite => "workspace-write",
            Mode::DangerFullAccess => "danger-full-access",
        }
    }
}

impl std::fmt::Display for Mode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// User-facing vocabulary (completion + validation order).
pub const SANDBOX_MODES: [Mode; 3] = [Mode::Readonly, Mode::WorkspaceWrite, Mode::DangerFullAccess];

/// Whether `value` names a known mode.
pub fn is_mode(value: &str) -> bool {
    SANDBOX_MODES.iter().any(|m| m.as_str() == value)
}

/// Whether mode goes through a runner.
pub fn is_confined(mode: Mode) -> bool {
    mode != Mode::DangerFullAccess
}

/// Resolve symlinks for comparison purposes; a path that does not exist yet
/// is returned lexically cleaned (conservative — an unresolvable root matches
/// nothing, same as the reference).
pub fn canonical(path: &str) -> String {
    if let Ok(c) = dunce::canonicalize(path) {
        return c.to_string_lossy().into_owned();
    }
    lexical_clean(Path::new(path)).to_string_lossy().into_owned()
}

/// Lexical `filepath.Clean` equivalent (Go falls back to it when
/// `EvalSymlinks` fails).
pub(crate) fn lexical_clean(p: &Path) -> std::path::PathBuf {
    use std::path::Component;
    let mut out = std::path::PathBuf::new();
    for c in p.components() {
        match c {
            Component::Prefix(pref) => out.push(pref.as_os_str()),
            Component::RootDir => out.push("/"),
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            Component::Normal(x) => out.push(x),
        }
    }
    out
}

/// On Windows the only tmp root is `%TEMP%` (there is no POSIX `/tmp`).
pub fn default_tmp_roots() -> Vec<std::path::PathBuf> {
    vec![std::env::temp_dir()]
}

/// Derive workspace-write's writable roots (canonical, deduped,
/// order-preserving). `read-only` and `danger-full-access` return none:
/// extra dirs only apply to workspace-write.
pub fn writable_roots(mode: Mode, workspace_root: &str, extra_roots: &[String]) -> Vec<String> {
    if mode != Mode::WorkspaceWrite {
        return Vec::new();
    }
    let mut seen = std::collections::HashSet::new();
    let mut out: Vec<String> = Vec::new();
    let mut add = |p: &str| {
        let c = canonical(p);
        if seen.insert(c.clone()) {
            out.push(c);
        }
    };
    add(workspace_root);
    for t in default_tmp_roots() {
        add(&t.to_string_lossy());
    }
    for e in extra_roots {
        add(e);
    }
    out
}

/// Process-wide `/sandbox` override beats the config default. (An approved
/// escalation applies per call, at the tool layer.)
pub fn resolve_effective_mode(mode_override: Option<Mode>, config_default: Mode) -> Mode {
    mode_override.unwrap_or(config_default)
}

/// Home directory (Go `os.UserHomeDir`).
pub(crate) fn home_dir() -> std::path::PathBuf {
    std::env::var_os("USERPROFILE")
        .or_else(|| std::env::var_os("HOME"))
        .map(std::path::PathBuf::from)
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mode_vocabulary() {
        assert!(is_mode("read-only"));
        assert!(is_mode("workspace-write"));
        assert!(is_mode("danger-full-access"));
        assert!(!is_mode("admin"));
        assert!(!is_mode(""));
        assert_eq!(SANDBOX_MODES[0], Mode::Readonly);
        assert_eq!(Mode::WorkspaceWrite.to_string(), "workspace-write");
        assert!(is_confined(Mode::Readonly));
        assert!(is_confined(Mode::WorkspaceWrite));
        assert!(!is_confined(Mode::DangerFullAccess));
    }

    #[test]
    fn canonical_and_clean() {
        if cfg!(windows) {
            // existing path → canonical (no \\?\ prefix thanks to dunce)
            let c = canonical("C:\\Windows\\.");
            assert!(!c.contains("\\\\?\\"), "{c}");
            assert!(c.ends_with('\\') || c.eq_ignore_ascii_case("c:\\windows"), "{c}");
            // nonexistent → lexical clean
            let n = canonical("C:\\no\\such\\dir\\..\\..\\x");
            assert!(!n.contains(".."), "{n}");
            assert!(n.replace('/', "\\").ends_with("\\x"), "{n}");
        } else {
            // existing path → canonical (symlinks resolved, no prefix games)
            let t = std::env::temp_dir();
            let c = canonical(&t.join(".").to_string_lossy());
            assert!(!c.contains("\\\\?\\"), "{c}");
            assert!(std::path::Path::new(&c).is_dir(), "{c}");
            assert!(!c.contains(".."), "{c}");
            // nonexistent → lexical clean (filepath.Clean shape)
            let n = canonical("/no/such/dir/../../x");
            assert!(!n.contains(".."), "{n}");
            assert!(n.ends_with("/x"), "{n}");
        }
    }

    #[test]
    fn writable_roots_semantics() {
        let ws = "C:\\workspace\\repo";
        let extra = vec!["C:\\extra".to_string()];
        let ww = writable_roots(Mode::WorkspaceWrite, ws, &extra);
        assert_eq!(ww.len(), 3, "{ww:?}"); // workspace + %TEMP% + extra
        assert!(ww[0].ends_with("repo"), "{ww:?}");
        // dedupe: extra == workspace collapses
        let ww2 = writable_roots(Mode::WorkspaceWrite, ws, &[ws.to_string()]);
        assert_eq!(ww2.len(), 2);
        // read-only / danger → none
        assert!(writable_roots(Mode::Readonly, ws, &extra).is_empty());
        assert!(writable_roots(Mode::DangerFullAccess, ws, &extra).is_empty());
    }

    #[test]
    fn effective_mode_override() {
        assert_eq!(
            resolve_effective_mode(Some(Mode::Readonly), Mode::WorkspaceWrite),
            Mode::Readonly
        );
        assert_eq!(resolve_effective_mode(None, Mode::WorkspaceWrite), Mode::WorkspaceWrite);
    }
}

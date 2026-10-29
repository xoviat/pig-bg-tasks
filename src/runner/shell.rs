//! Port of `internal/runner`'s shell resolution — parity with pi core's
//! documented order: the configured `shellPath` setting first, then `$SHELL`,
//! then the standard Git for Windows locations, then `bash` on PATH — with
//! WSL launcher aliases skipped on PATH unless configured explicitly, so bare
//! commands never land in WSL by surprise. Cached per process.

use std::path::Path;
use std::sync::Mutex;

use crate::runner::ERR_SHELL_UNAVAILABLE;

static CONFIGURED: Mutex<String> = Mutex::new(String::new());
static RESOLVED: Mutex<Option<String>> = Mutex::new(None);

fn g<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// Record the configured bash (settings' `shellPath`) and invalidate the
/// cache. Empty returns to default resolution.
pub fn set_configured_shell(p: &str) {
    let mut c = g(&CONFIGURED);
    *c = p.to_string();
    drop(c);
    *g(&RESOLVED) = None;
}

/// The configured `shellPath` override ("" = none).
pub fn configured_shell() -> String {
    g(&CONFIGURED).clone()
}

/// Find the bash to run (cached; parity order above).
pub fn resolve() -> Result<String, String> {
    if let Some(p) = g(&RESOLVED).clone() {
        return Ok(p);
    }
    let mut candidates: Vec<String> = Vec::new();
    let configured = configured_shell();
    if !configured.is_empty() {
        // Explicit user choice wins outright — even a WSL/cygwin shell that
        // would be skipped below is honored when named in settings.
        candidates.push(configured.clone());
    }
    if let Ok(s) = std::env::var("SHELL") {
        if !s.is_empty() {
            candidates.push(s);
        }
    }
    // Git for Windows standard locations BEFORE PATH, so a PATH hit can
    // never shadow Git Bash.
    let prog_files =
        std::env::var("ProgramFiles").unwrap_or_else(|_| "C:\\Program Files".to_string());
    let local = std::env::var("LocalAppData").unwrap_or_default();
    for base in [prog_files.as_str(), local.as_str()] {
        if base.is_empty() {
            continue;
        }
        for rel in [
            "Git\\bin\\bash.exe",
            "Git\\usr\\bin\\bash.exe",
            "Git\\mingw64\\bin\\bash.exe",
        ] {
            candidates.push(format!("{base}\\{rel}"));
        }
    }
    if let Some(p) = look_path("bash") {
        if !is_wsl_alias(&p) {
            candidates.push(p);
        }
    }
    for c in candidates {
        let p = Path::new(&c);
        if p.is_file() {
            // Go: EvalSymlinks-else-Clean shape, but dunce-cleaned (no `\\?\`
            // prefix in user-visible shell paths).
            let abs = crate::policy::canonical(&c);
            *g(&RESOLVED) = Some(abs.clone());
            return Ok(abs);
        }
    }
    Err(ERR_SHELL_UNAVAILABLE.to_string())
}

/// `exec.LookPath("bash")` (PATHEXT-aware, PATH-only).
fn look_path(name: &str) -> Option<String> {
    let path = std::env::var("PATH").ok()?;
    let exts: Vec<String> = std::env::var("PATHEXT")
        .unwrap_or_else(|_| ".COM;.EXE;.BAT;.CMD".into())
        .split(';')
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .collect();
    for dir in std::env::split_paths(&path) {
        let base = dir.join(name);
        if base.is_file() {
            return Some(base.to_string_lossy().into_owned());
        }
        for ext in &exts {
            let cand = dir.join(format!("{name}{ext}"));
            if cand.is_file() {
                return Some(cand.to_string_lossy().into_owned());
            }
            // case-insensitive ext on Windows filesystems is free; try lower
            let cand = dir.join(format!("{name}{}", ext.to_lowercase()));
            if cand.is_file() {
                return Some(cand.to_string_lossy().into_owned());
            }
        }
    }
    None
}

/// WSL launcher that would silently run commands inside a WSL distro.
pub fn is_wsl_alias(p: &str) -> bool {
    let n = p.replace('/', "\\").to_lowercase();
    n.ends_with("\\microsoft\\windowsapps\\bash.exe") || n.ends_with("\\system32\\bash.exe")
}

/// Tests only.
pub fn reset_shell_cache() {
    *g(&RESOLVED) = None;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    static ENV_MU: Mutex<()> = Mutex::new(());

    #[test]
    fn configured_shell_wins_over_everything() {
        let _t = ENV_MU.lock().unwrap_or_else(|e| e.into_inner());
        reset_shell_cache();
        // parity: every candidate is stat'd — the configured path must exist
        let dir = std::env::temp_dir().join("pi-shell-cfg");
        std::fs::create_dir_all(&dir).unwrap();
        let exe = dir.join("brush.exe");
        std::fs::write(&exe, b"MZ").unwrap();
        set_configured_shell(&exe.to_string_lossy());
        let got = resolve().unwrap();
        assert!(got.to_lowercase().ends_with("\\brush.exe"), "{got}");
        assert!(!got.contains("\\\\?\\"), "no verbatim prefix in shell paths: {got}");
        // a configured-but-missing path falls through to the next candidate
        // (Go parity: candidates are stat-gated)
        set_configured_shell("C:\\custom\\brush.exe");
        match resolve() {
            Ok(p) => assert_ne!(p.to_lowercase(), "c:\\custom\\brush.exe", "missing file wins"),
            Err(e) => assert_eq!(e, ERR_SHELL_UNAVAILABLE),
        }
        set_configured_shell("");
        reset_shell_cache();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn wsl_alias_detection() {
        // Go parity: the suffix check targets the LOCALAPPDATA alias location
        // and System32 — Program Files\WindowsApps is NOT matched (same in Go).
        assert!(is_wsl_alias(
            "C:\\Users\\x\\AppData\\Local\\Microsoft\\WindowsApps\\bash.exe"
        ));
        assert!(is_wsl_alias("C:\\Windows\\System32\\bash.exe"));
        assert!(!is_wsl_alias("C:\\Program Files\\Git\\bin\\bash.exe"));
    }

    #[test]
    fn resolve_finds_something_on_this_host_or_fails_cleanly() {
        let _t = ENV_MU.lock().unwrap_or_else(|e| e.into_inner());
        reset_shell_cache();
        set_configured_shell("");
        match resolve() {
            Ok(p) => assert!(!p.is_empty()),
            Err(e) => assert_eq!(e, ERR_SHELL_UNAVAILABLE),
        }
    }

    #[cfg(windows)]
    #[test]
    fn look_path_finds_cmd() {
        let got = look_path("cmd");
        assert!(got.is_some(), "cmd.exe must be on PATH on Windows");
        assert!(got.unwrap().to_lowercase().ends_with("cmd.exe"));
    }
}

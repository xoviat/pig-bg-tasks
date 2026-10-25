//! Port of `internal/config` — loads the global `sandbox.json` (schema v2).
//! Only the GLOBAL config layer is read; a project-level `sandbox.json` is
//! ignored silently — the project dir is model-writable, so a config layer
//! there would hand the model its own mode.
//!
//! Read-once-per-process; any error falls back to defaults (fail-safe: a bad
//! config must never disable the sandbox).

use std::path::PathBuf;
use std::sync::Mutex;

use serde_json::Value;

use crate::{Mode, home_dir, is_mode};

/// Mirrors the reference `SandboxConfig`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    pub mode: Mode,
    pub runner_command: Option<Vec<String>>,
    pub runner_failure_signatures: Option<Vec<String>>,
    pub probe_timeout_ms: i32,
    pub extra_writable_dirs: Vec<String>,
}

/// Reference defaults (workspace-write, 5s probe, no extras).
impl Default for Config {
    fn default() -> Self {
        Config {
            mode: Mode::WorkspaceWrite,
            runner_command: None,
            runner_failure_signatures: None,
            probe_timeout_ms: 5000,
            extra_writable_dirs: Vec::new(),
        }
    }
}

static CACHED: Mutex<Option<Config>> = Mutex::new(None);

/// Load the config once per process (`config_home` is `ctx.ConfigHome()`,
/// the PiG config root). Falls back to defaults on any error.
pub fn get(config_home: &str) -> Config {
    let mut cache = CACHED.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(c) = cache.as_ref() {
        return c.clone();
    }
    let mut c = Config::default();
    let path: PathBuf = [config_home, "agent", "sandbox.json"].iter().collect();
    let source = path.to_string_lossy().into_owned();
    if let Ok(raw) = std::fs::read(&path) {
        let parsed: Option<Value> = serde_json::from_slice(&raw).ok();
        if let Some(Value::Object(map)) = parsed {
            c = validate(map, &source, c);
        }
    }
    // Resolve extra dirs: ~ expansion, absoluteness, existing directory,
    // dedupe. Invalid entries are warned and dropped; dangerous entries
    // (agent dir coverage) are KEPT with a warning.
    c.extra_writable_dirs = resolve_extras(&c.extra_writable_dirs, &source, config_home);
    *cache = Some(c.clone());
    c
}

/// Tests only (Go `ResetCache`).
pub fn reset_cache() {
    *CACHED.lock().unwrap_or_else(|e| e.into_inner()) = None;
}

fn validate(raw: serde_json::Map<String, Value>, source: &str, base: Config) -> Config {
    let mut c = base.clone();
    if let Some(v) = raw.get("mode") {
        if let Some(s) = v.as_str() {
            if is_mode(s) {
                c.mode = match s {
                    "read-only" => Mode::Readonly,
                    "workspace-write" => Mode::WorkspaceWrite,
                    _ => Mode::DangerFullAccess,
                };
            } else {
                warnf(&format!(
                    "invalid mode \"{s}\" in {source}, falling back to \"{}\"",
                    base.mode
                ));
            }
        }
    }
    if let Some(v) = raw.get("runnerCommand") {
        if !v.is_null() {
            match as_string_slice(v) {
                Some(arr) => c.runner_command = Some(arr),
                None => warnf(&format!("runnerCommand in {source} must be a string array; ignoring")),
            }
        }
    }
    if let Some(v) = raw.get("runnerFailureSignatures") {
        if !v.is_null() {
            match as_string_slice(v) {
                Some(arr) => c.runner_failure_signatures = Some(arr),
                None => warnf(&format!(
                    "runnerFailureSignatures in {source} must be a string array; ignoring"
                )),
            }
        }
    }
    if c.runner_command.is_some() != c.runner_failure_signatures.is_some() {
        warnf(&format!(
            "runnerCommand and runnerFailureSignatures must be configured together in {source}; ignoring both"
        ));
        c.runner_command = None;
        c.runner_failure_signatures = None;
    }
    if let Some(v) = raw.get("probeTimeoutMs") {
        if v.is_null() {
            // Go: present-but-nil does not warn
        } else {
            match v.as_f64() {
                Some(n) if n > 0.0 => c.probe_timeout_ms = n as i32,
                _ => warnf(&format!(
                    "probeTimeoutMs in {source} must be a positive number; using default"
                )),
            }
        }
    }
    if let Some(v) = raw.get("extraWritableDirs") {
        if !v.is_null() {
            match as_string_slice(v) {
                Some(arr) => c.extra_writable_dirs = arr,
                None => warnf(&format!(
                    "extraWritableDirs in {source} must be a string array; using default"
                )),
            }
        }
    }
    if c.runner_command.is_some() {
        // Custom runner argv is a bwrap-compat override — meaningless for the
        // Windows-only scope. Warn loudly and ignore (documented divergence).
        warnf(&format!(
            "runnerCommand is set in {source} but custom runners are not supported by this build (Windows-only scope); ignoring"
        ));
        c.runner_command = None;
        c.runner_failure_signatures = None;
    }
    c
}

fn as_string_slice(v: &Value) -> Option<Vec<String>> {
    let arr = v.as_array()?;
    let mut out = Vec::with_capacity(arr.len());
    for e in arr {
        out.push(e.as_str()?.to_string());
    }
    Some(out)
}

fn resolve_extras(entries: &[String], source: &str, config_home: &str) -> Vec<String> {
    let home = home_dir();
    let mut out: Vec<String> = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let agent_dir: PathBuf = [config_home, "agent"].iter().collect();
    let agent_s = agent_dir.to_string_lossy().into_owned();
    for raw in entries {
        let mut e = raw.clone();
        if e == "~" {
            e = home.to_string_lossy().into_owned();
        } else if let Some(rest) = e.strip_prefix("~/").or_else(|| e.strip_prefix("~\\")) {
            e = home.join(rest).to_string_lossy().into_owned();
        }
        let p = PathBuf::from(&e);
        if !p.is_absolute() {
            warnf(&format!(
                "extraWritableDirs entry is not an absolute path: \"{raw}\" in {source}, ignoring it"
            ));
            continue;
        }
        let meta = std::fs::metadata(&p);
        match meta {
            Ok(m) if m.is_dir() => {}
            _ => {
                warnf(&format!(
                    "extraWritableDirs entry is not an existing directory: \"{e}\" in {source}, ignoring it"
                ));
                continue;
            }
        }
        if let Ok(canon) = dunce::canonicalize(&p) {
            e = canon.to_string_lossy().into_owned();
        }
        if covers(&e, &agent_s) || covers(&agent_s, &e) {
            warnf(&format!(
                "extraWritableDirs entry {e} covers PiG's agent dir ({agent_s}); a confined model could rewrite the sandbox config with it"
            ));
        }
        if seen.insert(e.clone()) {
            out.push(e);
        }
    }
    out
}

/// Whether `root` contains `child` or vice versa (separator-aware).
fn covers(root: &str, child: &str) -> bool {
    if root == child {
        return true;
    }
    let r = crate::lexical_clean(std::path::Path::new(root));
    let c = crate::lexical_clean(std::path::Path::new(child));
    let r = r.to_string_lossy();
    let c = c.to_string_lossy();
    let (r, c) = (r.as_ref(), c.as_ref());
    if c.len() <= r.len() || !c.starts_with(r) {
        return false;
    }
    c[r.len()..].starts_with(['/', '\\'])
}

fn warnf(msg: &str) {
    // Go's builtin println writes to stderr.
    eprintln!("sandbox: {msg}");
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::sync::Mutex;

    // serialize tests: the config cache is process-global
    static TEST_MU: Mutex<()> = Mutex::new(());

    fn with_home(name: &str, body: &dyn Fn(&str)) {
        let _t = TEST_MU.lock().unwrap_or_else(|e| e.into_inner());
        reset_cache();
        let home = std::env::temp_dir().join(format!("pi-sandbox-cfg-{name}"));
        let _ = std::fs::remove_dir_all(&home);
        std::fs::create_dir_all(home.join("agent")).unwrap();
        let home_s = home.to_string_lossy().into_owned();
        body(&home_s);
        let _ = std::fs::remove_dir_all(&home);
        reset_cache();
    }

    fn write(home: &str, v: Value) {
        std::fs::write(
            [home, "agent", "sandbox.json"].iter().collect::<PathBuf>(),
            serde_json::to_vec(&v).unwrap(),
        )
        .unwrap();
    }

    #[test]
    fn defaults_without_file() {
        with_home("defaults", &|home| {
            let c = get(home);
            assert_eq!(c, Config::default());
            assert_eq!(c.mode, Mode::WorkspaceWrite);
            assert_eq!(c.probe_timeout_ms, 5000);
        });
    }

    #[test]
    fn reads_mode_and_probe() {
        with_home("mode", &|home| {
            write(
                home,
                json!({"mode": "read-only", "probeTimeoutMs": 1500.0}),
            );
            let c = get(home);
            assert_eq!(c.mode, Mode::Readonly);
            assert_eq!(c.probe_timeout_ms, 1500);
        });
    }

    #[test]
    fn read_once_per_process_until_reset() {
        with_home("once", &|home| {
            write(home, json!({"mode": "read-only"}));
            let c1 = get(home);
            assert_eq!(c1.mode, Mode::Readonly);
            // file changes are ignored while cached
            write(home, json!({"mode": "danger-full-access"}));
            let c2 = get(home);
            assert_eq!(c2.mode, Mode::Readonly, "cache wins until reset");
            reset_cache();
            let c3 = get(home);
            assert_eq!(c3.mode, Mode::DangerFullAccess);
        });
    }

    #[test]
    fn invalid_mode_falls_back_and_array_json_ignored() {
        with_home("invalid", &|home| {
            write(home, json!({"mode": "superuser"}));
            let c = get(home);
            assert_eq!(c.mode, Mode::WorkspaceWrite, "fail-safe default");
            reset_cache();
            std::fs::write(
                [home, "agent", "sandbox.json"].iter().collect::<PathBuf>(),
                b"[\"read-only\"]",
            )
            .unwrap();
            let c = get(home);
            assert_eq!(c.mode, Mode::WorkspaceWrite, "array JSON ignored");
        });
    }

    #[test]
    fn runner_command_ignored_with_warning() {
        with_home("runner", &|home| {
            write(
                home,
                json!({
                    "runnerCommand": ["bwrap", "--unshare"],
                    "runnerFailureSignatures": ["oom"]
                }),
            );
            let c = get(home);
            assert!(c.runner_command.is_none());
            assert!(c.runner_failure_signatures.is_none());
            reset_cache();
            // half-pair → both dropped
            write(home, json!({"runnerFailureSignatures": ["oom"]}));
            let c = get(home);
            assert!(c.runner_failure_signatures.is_none());
        });
    }

    #[test]
    fn extras_expand_and_dedupe_and_drop_invalid() {
        with_home("extras", &|home| {
            let tmp = std::env::temp_dir().to_string_lossy().into_owned();
            let missing = [home, "..", "nope-not-here"].iter().collect::<PathBuf>();
            write(
                home,
                json!({
                    "extraWritableDirs": [tmp.clone(), tmp.clone(), "relative/path",
                        missing.to_string_lossy(), "~"]
                }),
            );
            let c = get(home);
            // temp (canonicalized + dup) + home; relative + missing dropped
            assert_eq!(c.extra_writable_dirs.len(), 2, "{:?}", c.extra_writable_dirs);
            assert_eq!(c.extra_writable_dirs[0], crate::canonical(&tmp));
            assert_eq!(c.extra_writable_dirs[1], crate::canonical(&home_dir().to_string_lossy()));
        });
    }
}

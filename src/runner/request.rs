//! `ContainerRequest` build from the converged policy (plan §4 mechanism
//! mapping row 1) + Windows command-line quoting for the SDK's single-string
//! `command` field.

use std::sync::Mutex;

use mxc_sdk::v1::{
    ContainerRequest, Containment, FilesystemPolicy, NetworkAction, NetworkEgressPolicy,
    NetworkIngressPolicy, NetworkPolicy, UiPolicy,
};

/// The userland applets dir (settings `userlandDir`, or the drop-in
/// `<configHome>/agent/userland`), prepended to the child PATH in both
/// confined and bare spawns. Busybox applets supply `sed`/`grep`/`awk`/… where
/// brush has no built-in sed. Cached per process, like the configured shell.
static USERLAND: Mutex<String> = Mutex::new(String::new());

fn g<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// Record the userland dir ("" = none) — called from session_start.
pub fn set_userland_dir(p: &str) {
    *g(&USERLAND) = p.to_string();
}

/// The configured userland dir ("" = none).
pub fn userland_dir() -> String {
    g(&USERLAND).clone()
}

/// `userland;path` (empty base → just the userland dir).
fn prepend_path(userland: &str, path_val: &str) -> String {
    if path_val.is_empty() {
        userland.to_string()
    } else {
        format!("{userland};{path_val}")
    }
}

/// Operational rule (memo E4/E5): broad read of `C:\` (0.16 s measured; makes
/// profile/system reads work on T3-class tiers, harmless ambient on T1).
pub const READONLY_ROOT: &str = "C:\\";

/// Build the confined spawn request for `argv` with the epoch's write roots.
///
/// - filesystem: `write_roots` read-write + `C:\` read-only (E4/E5 rule);
/// - network: always allowed (README product posture — srt-win parity);
/// - UI: enabled (`ui.disable=false`) — cmd/powershell/brush console init
///   needs win32k on this host (E8 quirk);
/// - env: supplied entries layer over the inherited default (E8 quirk:
///   `inherit_default_environment` is required for PATH), with the LC pins
///   (Go `proc.mergeEnv`: LC_ALL neutralized, LC_MESSAGES=C so denial text
///   stays classifiable);
/// - timeout: `0` = no backend timeout (schema §process.timeout) — the bg
///   layer's auto-background and the tool's own timers govern;
/// - cwd: explicit (E8 quirk: backend default is not the caller's dir).
pub fn build_request(
    argv: &[String],
    cwd: &str,
    env_extra: &[(String, String)],
    write_roots: &[String],
) -> ContainerRequest {
    let mut req = ContainerRequest::new(command_line(argv));
    req.containment = Containment::Process;
    req.filesystem = Some(FilesystemPolicy {
        readwrite_paths: write_roots.to_vec(),
        readonly_paths: vec![READONLY_ROOT.to_string()],
        denied_paths: vec![],
        clear_policy_on_exit: Some(true),
    });
    req.network = Some(NetworkPolicy {
        egress: Some(NetworkEgressPolicy {
            default: Some(NetworkAction::Allow),
            ..Default::default()
        }),
        ingress: Some(NetworkIngressPolicy {
            default: Some(NetworkAction::Allow),
            host_loopback: Some(NetworkAction::Allow),
        }),
        ..Default::default()
    });
    req.ui = Some(UiPolicy { disable: false, ..UiPolicy::default() });
    req.timeout_ms = Some(0);
    req.working_directory = Some(cwd.to_string());
    let mut env: Vec<(String, String)> = env_extra
        .iter()
        .filter(|(k, _)| !k.eq_ignore_ascii_case("LC_ALL") && !k.eq_ignore_ascii_case("LC_MESSAGES"))
        .cloned()
        .collect();
    env.push(("LC_ALL".to_string(), String::new()));
    env.push(("LC_MESSAGES".to_string(), "C".to_string()));
    // Userland first on PATH (resolve order: applets, then inherited host).
    // An env_extra PATH (callers today pass none) stays the base — userland
    // prepends to it instead of being replaced.
    let userland = userland_dir();
    if !userland.is_empty() {
        let idx = env.iter().position(|(k, _)| k.eq_ignore_ascii_case("PATH"));
        match idx {
            Some(i) => {
                let base = env[i].1.clone();
                env[i].1 = prepend_path(&userland, &base);
            }
            None => {
                let host = std::env::var("PATH").unwrap_or_default();
                env.push(("PATH".to_string(), prepend_path(&userland, &host)));
            }
        }
    }
    req.environment = Some(env);
    req.inherit_default_environment = Some(true);
    req
}

/// Join argv into one Windows command line (SDK `command` is a single
/// string). Standard MSVC/`CommandLineToArgvW` quoting: args with spaces or
/// quotes are wrapped; backslashes before a quote (or at the end of a quoted
/// arg) are doubled; `"` is escaped as `\"`.
pub fn command_line(argv: &[String]) -> String {
    argv.iter().map(|a| quote_arg(a)).collect::<Vec<_>>().join(" ")
}

fn quote_arg(a: &str) -> String {
    let needs_quotes = a.is_empty()
        || a.contains(|c: char| matches!(c, ' ' | '\t' | '\n' | '\r' | '"'));
    if !needs_quotes {
        return a.to_string();
    }
    let mut out = String::from('"');
    let mut backslashes = 0usize;
    for c in a.chars() {
        match c {
            '\\' => backslashes += 1,
            '"' => {
                out.push_str(&"\\".repeat(backslashes * 2 + 1));
                out.push('"');
                backslashes = 0;
            }
            _ => {
                out.push_str(&"\\".repeat(backslashes));
                backslashes = 0;
                out.push(c);
            }
        }
    }
    out.push_str(&"\\".repeat(backslashes * 2));
    out.push('"');
    out
}

/// The bare (`danger-full-access`) spawn environment — Go `proc.mergeEnv`:
/// inherit the parent, drop `LC_ALL`/`LC_MESSAGES` (LC_ALL would override
/// LC_MESSAGES and hide denial text from classification), apply `extra`
/// last-wins (case-insensitive key), pin `LC_MESSAGES=C`.
pub fn bare_env(extra: &[(String, String)]) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();
    for (k, v) in std::env::vars() {
        let lk = k.to_lowercase();
        if lk == "lc_all" || lk == "lc_messages" {
            continue;
        }
        out.push((k, v));
    }
    for (k, v) in extra {
        if k.to_lowercase() == "lc_all" {
            continue;
        }
        let lk = k.to_lowercase();
        out.retain(|(ek, _)| ek.to_lowercase() != lk);
        out.push((k.clone(), v.clone()));
    }
    out.retain(|(k, _)| !k.eq_ignore_ascii_case("lc_messages"));
    out.push(("LC_MESSAGES".to_string(), "C".to_string()));
    // Same prepend as the confined path: applets before the inherited PATH.
    let userland = userland_dir();
    if !userland.is_empty() {
        let idx = out.iter().position(|(k, _)| k.eq_ignore_ascii_case("PATH"));
        match idx {
            Some(i) => {
                let base = out[i].1.clone();
                out[i].1 = prepend_path(&userland, &base);
            }
            None => out.push(("PATH".to_string(), userland)),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Serializes the USERLAND-mutating tests with the env-reading ones.
    static TEST_MU: Mutex<()> = Mutex::new(());

    fn args(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn quoting_basics() {
        assert_eq!(command_line(&args(&["cmd.exe", "/c", "echo", "hi"])), "cmd.exe /c echo hi");
        assert_eq!(
            command_line(&args(&["C:\\Program Files\\a\\brush.exe", "-c", "echo hi"])),
            "\"C:\\Program Files\\a\\brush.exe\" -c \"echo hi\""
        );
        assert_eq!(command_line(&args(&[""])), "\"\"");
        // embedded quote
        assert_eq!(quote_arg(r#"say "hi""#), r#""say \"hi\"""#);
        // no metachars → no quotes: backslashes are literal outside quotes
        // (CommandLineToArgvW treats them specially only before a quote)
        assert_eq!(quote_arg("C:\\dir\\"), "C:\\dir\\");
        // inside quotes: trailing backslashes double
        assert_eq!(quote_arg("C:\\dir with space\\"), "\"C:\\dir with space\\\\\"");
        // backslash before an embedded quote
        assert_eq!(quote_arg(r#"a\"b"#), r#""a\\\"b""#);
    }

    #[test]
    fn request_shape() {
        let _t = TEST_MU.lock().unwrap_or_else(|e| e.into_inner());
        set_userland_dir("");
        let roots = vec!["C:\\ws".to_string(), "C:\\Temp".to_string()];
        let req = build_request(
            &args(&["C:\\bin\\brush.exe", "-c", "echo hi"]),
            "C:\\ws",
            &[("FOO".into(), "bar".into())],
            &roots,
        );
        assert_eq!(req.command, "C:\\bin\\brush.exe -c \"echo hi\"");
        assert_eq!(req.working_directory.as_deref(), Some("C:\\ws"));
        assert_eq!(req.timeout_ms, Some(0), "0 = no backend timeout");
        assert!(matches!(req.containment, Containment::Process));
        let fs = req.filesystem.expect("fs");
        assert_eq!(fs.readwrite_paths, roots);
        assert_eq!(fs.readonly_paths, vec![r"C:\".to_string()]);
        assert!(fs.denied_paths.is_empty());
        assert_eq!(fs.clear_policy_on_exit, Some(true));
        let ui = req.ui.expect("ui");
        assert!(!ui.disable, "console init needs win32k (E8 quirk)");
        let net = req.network.expect("net");
        assert_eq!(net.egress.unwrap().default, Some(NetworkAction::Allow));
        let ing = net.ingress.unwrap();
        assert_eq!(ing.default, Some(NetworkAction::Allow));
        assert_eq!(ing.host_loopback, Some(NetworkAction::Allow));
        assert_eq!(req.inherit_default_environment, Some(true), "PATH needs inherit (E8)");
        let env = req.environment.expect("env");
        assert!(env.contains(&("FOO".into(), "bar".into())));
        assert!(env.contains(&("LC_MESSAGES".into(), "C".into())));
        assert!(env.contains(&("LC_ALL".into(), String::new())));
    }

    #[test]
    fn bare_env_parity() {
        let _t = TEST_MU.lock().unwrap_or_else(|e| e.into_inner());
        set_userland_dir("");
        let env = bare_env(&[("FOO".into(), "1".into()), ("lc_all".into(), "X".into())]);
        assert!(env.iter().any(|(k, _)| k == "FOO"));
        assert!(env.iter().any(|(k, v)| k == "LC_MESSAGES" && v == "C"));
        assert!(!env.iter().any(|(k, _)| k.eq_ignore_ascii_case("lc_all")), "LC_ALL always dropped");
        // last-wins: overriding an inherited key replaces it once
        let env = bare_env(&[("Path".into(), "rewritten".into())]);
        let path_count = env.iter().filter(|(k, _)| k.eq_ignore_ascii_case("path")).count();
        assert_eq!(path_count, 1, "extras replace, not append");
        assert_eq!(
            env.iter().find(|(k, _)| k.eq_ignore_ascii_case("path")).unwrap().1,
            "rewritten"
        );
    }

    #[test]
    fn userland_prepends_to_child_path() {
        let _t = TEST_MU.lock().unwrap_or_else(|e| e.into_inner());
        set_userland_dir(r"C:\ubin");
        let host = std::env::var("PATH").unwrap_or_default();

        // confined: PATH = userland first, then the full host PATH
        let req = build_request(
            &args(&["brush.exe", "-c", "x"]),
            "C:\\ws",
            &[],
            &[r"C:\ws".into()],
        );
        let env = req.environment.expect("env");
        let path = env.iter().find(|(k, _)| k.eq_ignore_ascii_case("PATH")).expect("PATH");
        assert_eq!(path.1, format!(r"C:\ubin;{host}"), "userland precedes host PATH");

        // env_extra-carried PATH stays the base — prepend, don't replace
        let req2 = build_request(
            &args(&["brush.exe"]),
            "C:\\ws",
            &[("PATH".into(), r"D:\only".into())],
            &[],
        );
        let env2 = req2.environment.expect("env");
        let p2 = env2.iter().find(|(k, _)| k.eq_ignore_ascii_case("PATH")).unwrap();
        assert_eq!(p2.1, r"C:\ubin;D:\only");

        // bare: inherited PATH gets the prepend, exactly one PATH key
        let envb = bare_env(&[]);
        let paths: Vec<_> = envb.iter().filter(|(k, _)| k.eq_ignore_ascii_case("path")).collect();
        assert_eq!(paths.len(), 1);
        assert!(paths[0].1.starts_with(r"C:\ubin;"), "{}", paths[0].1);

        // reset: no residue
        set_userland_dir("");
        let pc = bare_env(&[])
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("path"))
            .unwrap()
            .1
            .clone();
        assert!(!pc.starts_with(r"C:\ubin;"), "{pc}");
    }
}

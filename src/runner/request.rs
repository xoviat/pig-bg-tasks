//! `ContainerRequest` build from the converged policy (plan §4 mechanism
//! mapping row 1) + host command-line quoting for the SDK's single-string
//! `command` field: Windows `CommandLineToArgvW` rules on Windows (mxc feeds
//! ProcessContainer a `CreateProcess` line), POSIX `/bin/sh -c` rules on
//! Unix (mxc feeds Bubblewrap/Seatbelt `sh -c` — `mxc_common::cmdline`).

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

/// `PATH` separator for this platform: `;` on Windows, `:` on POSIX.
pub const PATH_SEP: char = if cfg!(windows) { ';' } else { ':' };

/// `userland;path` (empty base → just the userland dir).
fn prepend_path(userland: &str, path_val: &str) -> String {
    if path_val.is_empty() {
        userland.to_string()
    } else {
        format!("{userland}{PATH_SEP}{path_val}")
    }
}

/// Operational rule (memo E4/E5): broad read of the system root — `C:\` on
/// Windows (0.16 s measured; makes profile/system reads work on T3-class
/// tiers, harmless ambient on T1), `/` on Unix (the mxc filesystem policy
/// ro-binds it either way).
#[cfg(windows)]
pub const READONLY_ROOT: &str = "C:\\";
#[cfg(not(windows))]
pub const READONLY_ROOT: &str = "/";

/// Build the confined spawn request for `argv` with the epoch's write roots.
///
/// - filesystem: `write_roots` read-write + [`READONLY_ROOT`] read-only
///   (E4/E5 rule);
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

/// Join argv into one command line (SDK `command` is a single string),
/// quoted for the parser this host's backend feeds it to — see
/// [`command_line_windows`] / [`command_line_posix`].
pub fn command_line(argv: &[String]) -> String {
    if cfg!(windows) {
        command_line_windows(argv)
    } else {
        command_line_posix(argv)
    }
}

/// Join argv under Windows rules: standard MSVC/`CommandLineToArgvW`
/// quoting — args with spaces or quotes are wrapped; backslashes before a
/// quote (or at the end of a quoted arg) are doubled; `"` is escaped as
/// `\"`. (Always compiled so the parity tests run on every host.)
pub fn command_line_windows(argv: &[String]) -> String {
    argv.iter().map(|a| quote_arg(a)).collect::<Vec<_>>().join(" ")
}

/// Join argv under POSIX rules for `/bin/sh -c`: single quotes around
/// anything that is not a plain shell-safe token (`'` → `'\''`), mirroring
/// mxc's `append_posix_shell` so argv data never becomes shell syntax
/// (`$`, backticks, `;`, `*`, … stay literal).
pub fn command_line_posix(argv: &[String]) -> String {
    argv.iter().map(|a| quote_arg_posix(a)).collect::<Vec<_>>().join(" ")
}

fn quote_arg_posix(a: &str) -> String {
    if !a.is_empty()
        && a.bytes().all(|b| {
            matches!(
                b,
                b'a'..=b'z'
                    | b'A'..=b'Z'
                    | b'0'..=b'9'
                    | b'_'
                    | b'@'
                    | b'%'
                    | b'+'
                    | b'='
                    | b':'
                    | b','
                    | b'.'
                    | b'/'
                    | b'-'
            )
        })
    {
        return a.to_string();
    }
    let mut out = String::from("'");
    for c in a.chars() {
        if c == '\'' {
            out.push_str("'\\''");
        } else {
            out.push(c);
        }
    }
    out.push('\'');
    out
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
///
/// Non-UTF-8 env pairs (possible on Unix) are skipped rather than panic —
/// the spec type carries `String` pairs only.
pub fn bare_env(extra: &[(String, String)]) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();
    for (k, v) in std::env::vars_os() {
        let (Some(k), Some(v)) = (k.to_str(), v.to_str()) else {
            continue;
        };
        let lk = k.to_lowercase();
        if lk == "lc_all" || lk == "lc_messages" {
            continue;
        }
        out.push((k.to_string(), v.to_string()));
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
        // Windows rules (the parity suite) — exercised on every host.
        assert_eq!(
            command_line_windows(&args(&["cmd.exe", "/c", "echo", "hi"])),
            "cmd.exe /c echo hi"
        );
        assert_eq!(
            command_line_windows(&args(&["C:\\Program Files\\a\\brush.exe", "-c", "echo hi"])),
            "\"C:\\Program Files\\a\\brush.exe\" -c \"echo hi\""
        );
        assert_eq!(command_line_windows(&args(&[""])), "\"\"");
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
    fn quoting_posix_basics() {
        // Unix rules: the command string reaches `/bin/sh -c` (mxc maps the
        // Bubblewrap/Seatbelt backends to PosixShell), so shell metacharacters
        // must never leak unquoted.
        assert_eq!(
            command_line_posix(&args(&["/bin/bash", "-c", "echo hi"])),
            "/bin/bash -c 'echo hi'"
        );
        assert_eq!(command_line_posix(&args(&[""])), "''");
        assert_eq!(quote_arg_posix("plain-token_1.2/3"), "plain-token_1.2/3");
        assert_eq!(quote_arg_posix("a b"), "'a b'");
        assert_eq!(quote_arg_posix("it's"), "'it'\\''s'");
        assert_eq!(quote_arg_posix("$(rm -rf /)"), "'$(rm -rf /)'");
        assert_eq!(quote_arg_posix("a;rm -rf b"), "'a;rm -rf b'");
        assert_eq!(quote_arg_posix("`whoami`"), "'`whoami`'");
        assert_eq!(quote_arg_posix("*"), "'*'");
    }

    #[test]
    fn command_line_dispatches_to_host_rules() {
        let a = args(&["a b", "c"]);
        if cfg!(windows) {
            assert_eq!(command_line(&a), command_line_windows(&a));
        } else {
            assert_eq!(command_line(&a), command_line_posix(&a));
        }
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
        assert_eq!(
            req.command,
            if cfg!(windows) {
                "C:\\bin\\brush.exe -c \"echo hi\""
            } else {
                "C:\\bin\\brush.exe -c 'echo hi'"
            },
            "quoting follows the host backend's parser"
        );
        assert_eq!(req.working_directory.as_deref(), Some("C:\\ws"));
        assert_eq!(req.timeout_ms, Some(0), "0 = no backend timeout");
        assert!(matches!(req.containment, Containment::Process));
        let fs = req.filesystem.expect("fs");
        assert_eq!(fs.readwrite_paths, roots);
        assert_eq!(fs.readonly_paths, vec![READONLY_ROOT.to_string()]);
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
        assert_eq!(path.1, format!("C:\\ubin{PATH_SEP}{host}"), "userland precedes host PATH");

        // env_extra-carried PATH stays the base — prepend, don't replace
        let req2 = build_request(
            &args(&["brush.exe"]),
            "C:\\ws",
            &[("PATH".into(), "D:\\only".into())],
            &[],
        );
        let env2 = req2.environment.expect("env");
        let p2 = env2.iter().find(|(k, _)| k.eq_ignore_ascii_case("PATH")).unwrap();
        assert_eq!(p2.1, format!("C:\\ubin{PATH_SEP}D:\\only"));

        // bare: inherited PATH gets the prepend, exactly one PATH key
        let envb = bare_env(&[]);
        let paths: Vec<_> = envb.iter().filter(|(k, _)| k.eq_ignore_ascii_case("path")).collect();
        assert_eq!(paths.len(), 1);
        assert!(
            paths[0].1.starts_with(&format!("C:\\ubin{PATH_SEP}")),
            "{}",
            paths[0].1
        );

        // reset: no residue
        set_userland_dir("");
        let pc = bare_env(&[])
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("path"))
            .unwrap()
            .1
            .clone();
        assert!(!pc.starts_with(&format!("C:\\ubin{PATH_SEP}")), "{pc}");
    }
}

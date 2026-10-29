//! Smoke matrix — successor of `pig-tmp/srt-smoke.sh` (34 sections), the
//! runner-level subset that must be green before the ext port (plan §7
//! Phase 1 exit criterion: "matrix green modulo memo deltas").
//!
//! Sections translate the Go smoke suite's spawn/confine/write/deny themes
//! plus §6's *inverted* assertions (profile write now denied, schannel now
//! succeeds). Needs this machine's shell facts (E3 decision): a native
//! Win32 shell (`shellPath`-style brush.exe) and busybox-w32 applets as the
//! userland — both overridable via env for other hosts.

use std::path::PathBuf;
use std::sync::OnceLock;
use std::sync::Arc;

use pig_bg_tasks::bg::Handle as _;
use pig_bg_tasks::policy::Mode;

/// Everything the matrix needs, resolved once. `None` = this host lacks the
/// native shell (tests then skip with a notice instead of failing — the
/// matrix's *claims* are machine-class claims, same as the gates).
struct Fixture {
    /// Confined workspace (a granted read-write root).
    ws: PathBuf,
    logs: PathBuf,
    /// Native shell (`brush.exe` by default).
    shell: String,
    /// `ubin;host PATH` — busybox applets first (E3-bis userland).
    path: String,
    /// busybox source for `sleep.exe` (tree-kill fixture), if present.
    busybox: Option<PathBuf>,
}

fn fixture() -> Option<Arc<Fixture>> {
    static FIX: OnceLock<Option<Arc<Fixture>>> = OnceLock::new();
    FIX.get_or_init(|| {
        let shell = native_shell()?;
        let root = std::env::temp_dir().join("pi-smoke");
        let ws = root.join("ws");
        let logs = root.join("logs");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&ws).unwrap();
        std::fs::create_dir_all(&logs).unwrap();

        let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let ubin = manifest.join("pig-tmp/shell-candidates/ubin");
        let host_path = std::env::var("PATH").unwrap_or_default();
        let path = if ubin.is_dir() {
            format!("{};{host_path}", ubin.to_string_lossy())
        } else {
            host_path
        };
        let busybox = std::env::var_os("PIG_TEST_BUSYBOX")
            .map(PathBuf::from)
            .or_else(|| {
                let p = manifest.join("pig-tmp/shell-candidates/busybox64.exe");
                p.is_file().then_some(p)
            });
        if let Some(bb) = &busybox {
            let _ = std::fs::copy(bb, ws.join("sleep.exe"));
        }
        Some(Arc::new(Fixture { ws, logs, shell, path, busybox }))
    })
    .clone()
}

/// The native shell under test: `PIG_TEST_SHELL` → pig's `shellPath`-style
/// default (brush.exe on this machine per the E3 decision) → configured →
/// host resolution.
fn native_shell() -> Option<String> {
    if let Ok(s) = std::env::var("PIG_TEST_SHELL") {
        if !s.is_empty() && PathBuf::from(&s).is_file() {
            return Some(s);
        }
    }
    let home = std::env::var("USERPROFILE").ok()?;
    let brush = PathBuf::from(&home).join(".cargo").join("bin").join("brush.exe");
    if brush.is_file() {
        return Some(brush.to_string_lossy().into_owned());
    }
    // fall back to host resolution
    pig_bg_tasks::runner::shell::reset_shell_cache();
    pig_bg_tasks::runner::shell::set_configured_shell("");
    pig_bg_tasks::runner::shell::resolve().ok()
}

/// Run one script confined in the workspace, returning (exit, log body).
fn confined(f: &Fixture, name: &str, script: &str, mode: Mode) -> (pig_bg_tasks::bg::Exit, String) {
    confined_in(f, name, script, mode, &f.ws.clone())
}

fn confined_in(
    f: &Fixture,
    name: &str,
    script: &str,
    mode: Mode,
    cwd: &std::path::Path,
) -> (pig_bg_tasks::bg::Exit, String) {
    let roots = pig_bg_tasks::policy::writable_roots(mode, &f.ws.to_string_lossy(), &[]);
    let argv = vec![
        f.shell.clone(),
        "-c".to_string(),
        script.to_string(),
    ];
    let req = pig_bg_tasks::runner::request::build_request(
        &argv,
        &cwd.to_string_lossy(),
        &[("PATH".to_string(), f.path.clone())],
        &roots,
    );
    let log = f.logs.join(format!("{name}.log"));
    let spec = pig_bg_tasks::runner::proc::Spec {
        argv,
        cwd: cwd.to_string_lossy().into_owned(),
        env_extra: vec![],
        log_path: log.to_string_lossy().into_owned(),
        request: Some(req),
    };
    let h = pig_bg_tasks::runner::proc::Handle::start(spec).expect("confined spawn");
    let exit = h.wait();
    let body = std::fs::read_to_string(&log).unwrap_or_default();
    (exit, body)
}

fn skip_or_get() -> Option<Arc<Fixture>> {
    match fixture() {
        Some(f) => Some(f),
        None => {
            eprintln!("smoke: no native Win32 shell on this host — section skipped");
            None
        }
    }
}

// --- §6 acceptance, carried over: confined echo ---------------------------

#[test]
fn s01_confined_echo() {
    let Some(f) = skip_or_get() else { return };
    let (exit, body) = confined(&f, "s01", "echo S01_CONFINED_OK", Mode::WorkspaceWrite);
    assert_eq!(exit.code, 0, "{exit:?} body={body}");
    assert!(body.contains("S01_CONFINED_OK"), "{body}");
}

#[test]
fn s02_workspace_write_and_read_back() {
    let Some(f) = skip_or_get() else { return };
    let marker = f.ws.join("s02-marker.txt");
    let script = format!(
        "echo CREATED > \"{}\" && grep -q CREATED \"{}\" && echo S02_RW_OK",
        marker.display(),
        marker.display()
    );
    let (exit, body) = confined(&f, "s02", &script, Mode::WorkspaceWrite);
    assert_eq!(exit.code, 0, "{exit:?} body={body}");
    assert!(body.contains("S02_RW_OK"), "{body}");
    assert!(marker.is_file());
    let _ = std::fs::remove_file(&marker);
}

/// **Inverted assertion** (§6): write outside the granted roots is DENIED in
/// workspace-write (today's Go build asserts this as an accepted gap).
#[test]
fn s03_profile_write_denied_and_classified() {
    let Some(f) = skip_or_get() else { return };
    let home = std::env::var("USERPROFILE").expect("USERPROFILE");
    let target = PathBuf::from(&home).join("pi-smoke-s03-should-not-exist.txt");
    let _ = std::fs::remove_file(&target);
    // the redirect IS the last command — its failure must be the exit code
    let script = format!("echo x > \"{}\"", target.display());
    let (exit, body) = confined(&f, "s03", &script, Mode::WorkspaceWrite);
    assert_ne!(exit.code, 0, "outside write must be denied: {body}");
    assert!(
        pig_bg_tasks::classify::denial(Some(exit.code), &body, pig_bg_tasks::classify::DENIAL_SIGNATURES),
        "denial must be classifiable (denial-first escalation depends on it): {body}"
    );
    assert!(!target.exists(), "file must not exist: {}", target.display());
}

/// **Inverted assertion** (§6): read-only has no write roots — even the
/// workspace is unwritable.
#[test]
fn s04_read_only_denies_workspace_write() {
    let Some(f) = skip_or_get() else { return };
    let target = f.ws.join("s04-should-not-exist.txt");
    let _ = std::fs::remove_file(&target);
    let script = format!("echo x > \"{}\"", target.display());
    let (exit, body) = confined(&f, "s04", &script, Mode::Readonly);
    assert_ne!(exit.code, 0, "read-only must deny workspace writes: {body}");
    assert!(
        pig_bg_tasks::classify::denial(Some(exit.code), &body, pig_bg_tasks::classify::DENIAL_SIGNATURES),
        "{body}"
    );
    assert!(!target.exists());
}

/// `danger-full-access` runs bare — outside writes allowed (the s03 twin).
#[test]
fn s05_danger_bare_writes_outside() {
    let Some(f) = skip_or_get() else { return };
    let home = std::env::var("USERPROFILE").expect("USERPROFILE");
    let target = PathBuf::from(&home).join("pi-smoke-s05-bare.txt");
    let _ = std::fs::remove_file(&target);
    let argv = vec![
        f.shell.clone(),
        "-c".to_string(),
        format!("echo BARE_OK > \"{}\"", target.display()),
    ];
    let log = f.logs.join("s05.log");
    let spec = pig_bg_tasks::runner::proc::Spec {
        argv,
        cwd: f.ws.to_string_lossy().into_owned(),
        env_extra: vec![("PATH".to_string(), f.path.clone())],
        log_path: log.to_string_lossy().into_owned(),
        request: None,
    };
    let h = pig_bg_tasks::runner::proc::Handle::start(spec).expect("bare spawn");
    let exit = h.wait();
    assert_eq!(exit.code, 0, "{exit:?}");
    assert!(target.is_file(), "bare mode must write outside");
    assert_eq!(std::fs::read_to_string(&target).unwrap().trim(), "BARE_OK");
    let _ = std::fs::remove_file(&target);
}

// --- confinement shape: reads ambient, env, cwd, exit codes ---------------

/// E4 re-scoped contract: system files readable under confinement.
#[test]
fn s06_ambient_system_read() {
    let Some(f) = skip_or_get() else { return };
    let hosts = "C:\\Windows\\System32\\drivers\\etc\\hosts";
    let script = format!("test -f \"{hosts}\" && echo S06_READ_OK");
    let (exit, body) = confined(&f, "s06", &script, Mode::WorkspaceWrite);
    assert_eq!(exit.code, 0, "{exit:?} body={body}");
    assert!(body.contains("S06_READ_OK"), "{body}");
}

/// E8 env quirks: inherited PATH (with our busybox ubin prepended) and the
/// LC pins (`LC_MESSAGES=C` so denial text stays classifiable).
#[test]
fn s07_env_inheritance_and_lc_pins() {
    let Some(f) = skip_or_get() else { return };
    let script = "echo PATH_SET=$([ -n \"$PATH\" ] && echo yes) LC=$LC_MESSAGES LC_ALL_EMPTY=$([ -z \"$LC_ALL\" ] && echo yes)";
    let (exit, body) = confined(&f, "s07", script, Mode::WorkspaceWrite);
    assert_eq!(exit.code, 0, "{exit:?} body={body}");
    assert!(body.contains("PATH_SET=yes"), "PATH must inherit: {body}");
    assert!(body.contains("LC=C"), "LC_MESSAGES=C pin: {body}");
    assert!(body.contains("LC_ALL_EMPTY=yes"), "LC_ALL neutralized: {body}");
}

/// E8 cwd quirk: explicit `working_directory` is honored.
#[test]
fn s08_cwd_is_explicit() {
    let Some(f) = skip_or_get() else { return };
    let sub = f.ws.join("s08-sub");
    std::fs::create_dir_all(&sub).unwrap();
    let (exit, body) = confined_in(&f, "s08", "pwd && echo PWD_OK", Mode::WorkspaceWrite, &sub);
    assert_eq!(exit.code, 0, "{exit:?} body={body}");
    // brush prints the path with forward slashes
    let normalized = body.replace('/', "\\");
    assert!(
        normalized.to_lowercase().contains("s08-sub"),
        "cwd must be the explicit working_directory: {body}"
    );
    let _ = std::fs::remove_dir_all(&sub);
}

#[test]
fn s09_exit_code_roundtrip_confined() {
    let Some(f) = skip_or_get() else { return };
    let (exit, body) = confined(&f, "s09", "exit 42", Mode::WorkspaceWrite);
    assert_eq!(exit.code, 42, "{exit:?} body={body}");
}

/// §9: sspiprobe's schannel check as a permanent regression test — confined
/// HTTPS through the native schannel client must succeed (E2 inverted
/// assertion: today's Go build documents this as broken).
#[test]
fn s10_schannel_https_under_confinement() {
    let Some(f) = skip_or_get() else { return };
    let (exit, body) = confined(
        &f,
        "s10",
        "curl.exe -s -o NUL -w %{http_code} https://github.com",
        Mode::WorkspaceWrite,
    );
    assert_eq!(exit.code, 0, "curl must complete: {exit:?} body={body}");
    assert!(
        body.contains("200") || body.contains("301") || body.contains("302"),
        "expected an HTTP status from curl, got: {body}"
    );
}

/// Userland story (E3-bis): busybox applets on PATH inside the container.
#[test]
fn s11_busybox_userland_confined() {
    let Some(f) = skip_or_get() else { return };
    if f.busybox.is_none() {
        eprintln!("smoke: busybox source missing — section skipped");
        return;
    }
    let (exit, body) = confined(
        &f,
        "s11",
        "ls -la \"$(echo .)\" > /dev/null 2>&1; grep -q . <<< text && echo S11_USERLAND_OK",
        Mode::WorkspaceWrite,
    );
    assert_eq!(exit.code, 0, "{exit:?} body={body}");
    assert!(body.contains("S11_USERLAND_OK"), "{body}");
}

/// Concurrency: several confined commands in parallel (separate containers —
/// E13's drop means no sharing to worry about).
#[test]
fn s13_parallel_confined_spawns() {
    let Some(f) = skip_or_get() else { return };
    let handles: Vec<_> = (0..4)
        .map(|i| {
            let f = f.clone();
            std::thread::spawn(move || {
                confined(&f, &format!("s13-{i}"), &format!("echo PAR_{i}"), Mode::WorkspaceWrite)
            })
        })
        .collect();
    for (i, h) in handles.into_iter().enumerate() {
        let (exit, body) = h.join().expect("thread");
        assert_eq!(exit.code, 0, "s13-{i}: {exit:?} body={body}");
        assert!(body.contains(&format!("PAR_{i}")), "s13-{i}: {body}");
    }
}

/// bg_stop semantics under confinement: kill lands promptly and the task is
/// terminal-killed (unit tests proved tree-kill bare; E8 proved it confined
/// with grandchildren — this pins OUR runner's path).
#[test]
fn s14_confined_kill() {
    let Some(f) = skip_or_get() else { return };
    if f.busybox.is_none() {
        eprintln!("smoke: busybox source missing — section skipped");
        return;
    }
    let sleep_exe = f.ws.join("sleep.exe");
    let argv = vec![f.shell.clone(), "-c".to_string(), format!("\"{}\" 30", sleep_exe.display())];
    let roots = pig_bg_tasks::policy::writable_roots(Mode::WorkspaceWrite, &f.ws.to_string_lossy(), &[]);
    let req = pig_bg_tasks::runner::request::build_request(
        &argv,
        &f.ws.to_string_lossy(),
        &[("PATH".to_string(), f.path.clone())],
        &roots,
    );
    let log = f.logs.join("s14.log");
    let spec = pig_bg_tasks::runner::proc::Spec {
        argv,
        cwd: f.ws.to_string_lossy().into_owned(),
        env_extra: vec![],
        log_path: log.to_string_lossy().into_owned(),
        request: Some(req),
    };
    let h = pig_bg_tasks::runner::proc::Handle::start(spec).expect("confined spawn");
    std::thread::sleep(std::time::Duration::from_millis(800));
    assert!(h.try_wait().is_none(), "still sleeping");
    let t = std::time::Instant::now();
    h.kill();
    let e = h.wait();
    assert!(e.killed, "{e:?}");
    assert!(t.elapsed() < std::time::Duration::from_secs(5), "kill too slow");
}

/// Epoch bookkeeping end-to-end: bind → validate → spawn under the returned
/// state, and the status line shape `/sandbox` renders.
#[test]
fn s15_epoch_bind_and_status_shape() {
    let Some(f) = skip_or_get() else { return };
    let eng = pig_bg_tasks::runner::converge::Engine::default();
    let ws = f.ws.to_string_lossy().into_owned();
    eng.start(pig_bg_tasks::runner::converge::State {
        mode: Mode::WorkspaceWrite,
        workspace: ws.clone(),
        temp: std::env::temp_dir().to_string_lossy().into_owned(),
        extras: vec![],
    });
    let state = eng
        .bind(pig_bg_tasks::runner::converge::State {
            mode: Mode::WorkspaceWrite,
            workspace: ws.clone(),
            temp: std::env::temp_dir().to_string_lossy().into_owned(),
            extras: vec![],
        })
        .expect("bind converges");
    let line = eng.status_line();
    assert!(line.starts_with("epoch 1 — converged: workspace-write"), "{line}");
    // spawn under the bound state
    let roots = pig_bg_tasks::policy::writable_roots(state.mode, &state.workspace, &[]);
    assert_eq!(roots.len(), 2, "workspace + temp: {roots:?}");
    let argv = vec![f.shell.clone(), "-c".to_string(), "echo S15_OK".into()];
    let req = pig_bg_tasks::runner::request::build_request(&argv, &ws, &[], &roots);
    let spec = pig_bg_tasks::runner::proc::Spec {
        argv,
        cwd: ws,
        env_extra: vec![],
        log_path: f.logs.join("s15.log").to_string_lossy().into_owned(),
        request: Some(req),
    };
    let h = pig_bg_tasks::runner::proc::Handle::start(spec).expect("spawn under bound state");
    let e = h.wait();
    assert_eq!(e.code, 0, "{e:?}");
}

//! Port of `internal/proc` — one spawn with log output and tree-kill
//! semantics, two backends behind one [`crate::bg::Handle`] implementation:
//!
//! - **confined**: `mxc_sdk::v1::spawn(ContainerRequest)` — stdout/stderr
//!   arrive as pipes, so two pump threads append them to the log file (plan
//!   §4: kernel-copy → userspace-copy divergence, same bytes);
//! - **bare** (`danger-full-access`): `std::process` with `CREATE_NO_WINDOW`
//!   and fd-direct handles (kernel moves the bytes — zero-copy, Go parity).
//!
//! Every spawn joins (or falls back around) a `KILL_ON_JOB_CLOSE` job object,
//! so `bg_stop` / session shutdown / a hard extension death take the whole
//! tree with them. Job/process handles are deliberately **never closed**
//! (Go parity: handles stay open until process exit — closing a job at
//! eviction time would kill lingering grandchildren of an already-completed
//! task, which today's behavior does not do).
//!
//! Exit production is a `try_wait` polling loop (20 ms) on both backends:
//! `MxcProcess::wait(&mut)` would hold the mutex for the process's whole
//! lifetime and deadlock `bg_stop`'s concurrent `kill(&mut)`.
//!
//! **Cross-platform note:** the `windows` crate and job-object machinery are
//! `#[cfg(windows)]`-gated. On Unix the bare backend puts the child in its
//! own process group (`process_group(0)`) and `kill(-pgid, SIGKILL)` takes
//! the whole tree — the POSIX analogue of KILL_ON_JOB_CLOSE. mxc-sdk is
//! cross-platform: confinement goes through the host's `Containment::Process`
//! backend (ProcessContainer on Windows, Bubblewrap on Linux, Seatbelt on
//! macOS).

use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::bg::{Exit, ExitState, Handle as TaskHandle};
use mxc_sdk::v1::{ContainerRequest, MxcProcess, SpawnOptions};

use crate::runner::request;

const POLL_MS: u64 = 20;

fn g<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// One spawn.
pub struct Spec {
    pub argv: Vec<String>,
    pub cwd: String,
    /// Extra env pairs merged over the inherited env (LC pins applied here).
    pub env_extra: Vec<(String, String)>,
    /// stdout+stderr target (created/truncated).
    pub log_path: String,
    /// `Some` = confined spawn through MXC; `None` = bare.
    pub request: Option<ContainerRequest>,
}

/// Kernel handle wrapper (Windows). Safety: `HANDLE`s are process-wide
/// integer-like values; `TerminateJobObject`/`TerminateProcess` are safe to
/// invoke from any thread — Go shares the same handles across goroutines.
/// Never closed (see module doc).
#[cfg(windows)]
#[derive(Clone, Copy)]
struct RawHandle(windows::Win32::Foundation::HANDLE);
#[cfg(windows)]
unsafe impl Send for RawHandle {}
#[cfg(windows)]
unsafe impl Sync for RawHandle {}

enum Inner {
    Bare {
        /// Fallback kill when the job attach is refused.
        #[cfg(windows)]
        term: RawHandle,
        #[cfg(windows)]
        job: Option<RawHandle>,
        /// POSIX: no job objects — the direct child IS the kill target
        /// (see module note for the tree-kill divergence).
        #[cfg(not(windows))]
        child: Arc<Mutex<Child>>,
    },
    Mxc { proc: Arc<Mutex<MxcProcess>> },
}

/// A running spawn implementing [`crate::bg::Handle`].
pub struct Handle {
    pid: u32,
    killed: Arc<AtomicBool>,
    exit: Arc<ExitState>,
    inner: Inner,
}

impl TaskHandle for Handle {
    fn pid(&self) -> u32 {
        self.pid
    }

    /// Whole tree: job object when attached, direct process otherwise.
    /// Windows has no SIGTERM — this IS the stop.
    fn kill(&self) {
        self.killed.store(true, Ordering::SeqCst);
        match &self.inner {
            #[cfg(windows)]
            Inner::Bare { term, job } => unsafe {
                if let Some(job) = job {
                    let _ = windows::Win32::System::JobObjects::TerminateJobObject(job.0, 1);
                } else {
                    let _ = windows::Win32::System::Threading::TerminateProcess(term.0, 1);
                }
            },
            #[cfg(not(windows))]
            Inner::Bare { child } => {
                // Whole tree: the child leads its own process group (see
                // `start_bare`), so the negative pid reaches grandchildren;
                // the direct-child kill is the fallback (group already gone).
                unsafe {
                    libc::kill(-(self.pid as i32), libc::SIGKILL);
                }
                let _ = g(child).kill();
            }
            Inner::Mxc { proc } => {
                let mut p = g(proc);
                let _ = p.kill();
            }
        }
    }

    /// Block until terminal (broadcast-safe; many waiters).
    fn wait(&self) -> Exit {
        self.exit.wait()
    }

    fn try_wait(&self) -> Option<Exit> {
        self.exit.get()
    }
}

enum Poll {
    Running,
    Exited(i32),
    Err(String),
}

impl Handle {
    /// Spawn the command (the one spawn entry point).
    pub fn start(spec: Spec) -> Result<Handle, String> {
        if spec.argv.is_empty() {
            return Err("proc: empty argv".to_string());
        }
        ensure_dir(&spec.log_path)?;
        let Spec { argv, cwd, env_extra, log_path, request } = spec;
        match request {
            Some(request) => Self::start_confined(
                Spec { argv, cwd, env_extra, log_path, request: None },
                request,
            ),
            None => Self::start_bare(Spec { argv, cwd, env_extra, log_path, request: None }),
        }
    }

    fn start_bare(spec: Spec) -> Result<Handle, String> {
        // fd-direct: one create/truncate handle for the child's stdout, a
        // duplicate (shared file position, Go parity) for stderr.
        let out = File::create(&spec.log_path).map_err(|e| format!("proc: open log: {e}"))?;
        let err = out.try_clone().map_err(|e| format!("proc: dup log: {e}"))?;

        let mut cmd = Command::new(&spec.argv[0]);
        cmd.args(&spec.argv[1..])
            .current_dir(&spec.cwd)
            .env_clear()
            .envs(request::bare_env(&spec.env_extra))
            .stdin(Stdio::null())
            .stdout(Stdio::from(out))
            .stderr(Stdio::from(err));
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            const CREATE_NO_WINDOW: u32 = 0x0800_0000;
            cmd.creation_flags(CREATE_NO_WINDOW);
        }
        #[cfg(not(windows))]
        {
            use std::os::unix::process::CommandExt;
            // Own process group: kill(-pgid) in `Handle::kill` then takes the
            // whole tree (grandchildren included) — the POSIX analogue of the
            // Windows KILL_ON_JOB_CLOSE job.
            cmd.process_group(0);
        }
        let child = cmd.spawn().map_err(|e| format!("proc: start: {e}"))?;
        let pid = child.id();

        let child = Arc::new(Mutex::new(child));
        let killed = Arc::new(AtomicBool::new(false));
        let exit = Arc::new(ExitState::new());
        spawn_watcher(WatchKind::Bare(child.clone()), killed.clone(), exit.clone());
        #[cfg(windows)]
        let inner = {
            let job = unsafe { attach_pid(pid) }.map(RawHandle);
            let term = unsafe { open_process_for_terminate(pid) }
                .map(RawHandle)
                .map_err(|e| format!("proc: open process: {e}"))?;
            Inner::Bare { term, job }
        };
        #[cfg(not(windows))]
        let inner = Inner::Bare { child };
        Ok(Handle { pid, killed, exit, inner })
    }

    fn start_confined(spec: Spec, request: ContainerRequest) -> Result<Handle, String> {
        let mut proc = mxc_sdk::v1::spawn(request, SpawnOptions::default())
            .map_err(|e| format!("proc: spawn: {e}"))?;
        let pid = proc.id();
        // Take the pipes up front; pump them to the log file (truncate first,
        // then two O_APPEND handles so concurrent streams cannot tear).
        let stdout = proc.take_stdout();
        let stderr = proc.take_stderr();
        let _ = File::create(&spec.log_path);
        let out_file = open_append(&spec.log_path)?;
        let err_file = open_append(&spec.log_path)?;
        if let Some(mut stream) = stdout {
            std::thread::spawn(move || pump(&mut stream, out_file));
        }
        if let Some(mut stream) = stderr {
            std::thread::spawn(move || pump(&mut stream, err_file));
        }

        let proc = Arc::new(Mutex::new(proc));
        let killed = Arc::new(AtomicBool::new(false));
        let exit = Arc::new(ExitState::new());
        spawn_watcher(WatchKind::Mxc(proc.clone()), killed.clone(), exit.clone());
        Ok(Handle { pid, killed, exit, inner: Inner::Mxc { proc } })
    }
}

enum WatchKind {
    Bare(Arc<Mutex<Child>>),
    Mxc(Arc<Mutex<MxcProcess>>),
}

/// Sole publisher of the exit cell: poll `try_wait` with brief lock holds
/// (`kill` must stay concurrent) every [`POLL_MS`].
fn spawn_watcher(kind: WatchKind, killed: Arc<AtomicBool>, exit: Arc<ExitState>) {
    std::thread::spawn(move || loop {
        let poll = match &kind {
            WatchKind::Bare(child) => {
                let mut c = g(child);
                match c.try_wait() {
                    Ok(None) => Poll::Running,
                    Ok(Some(status)) => Poll::Exited(status.code().unwrap_or(-1)),
                    Err(e) => Poll::Err(e.to_string()),
                }
            }
            WatchKind::Mxc(proc) => {
                let mut p = g(proc);
                match p.try_wait() {
                    Ok(None) => Poll::Running,
                    Ok(Some(code)) => Poll::Exited(code),
                    Err(e) => Poll::Err(e.to_string()),
                }
            }
        };
        match poll {
            Poll::Running => std::thread::sleep(Duration::from_millis(POLL_MS)),
            Poll::Exited(code) => {
                exit.set(Exit { code, killed: killed.load(Ordering::SeqCst), err: None });
                return;
            }
            Poll::Err(e) => {
                exit.set(Exit { code: -1, killed: killed.load(Ordering::SeqCst), err: Some(e) });
                return;
            }
        }
    });
}

fn ensure_dir(log_path: &str) -> Result<(), String> {
    if let Some(dir) = std::path::Path::new(log_path).parent() {
        if !dir.as_os_str().is_empty() {
            std::fs::create_dir_all(dir).map_err(|e| format!("proc: mkdir log dir: {e}"))?;
        }
    }
    Ok(())
}

fn open_append(path: &str) -> Result<File, String> {
    OpenOptions::new().create(true).append(true).open(path).map_err(|e| format!("proc: open log append: {e}"))
}

fn pump(stream: &mut dyn Read, mut file: File) {
    let _ = std::io::copy(stream, &mut file);
    let _ = file.flush();
}

/// Put the child (by pid) in a `KILL_ON_JOB_CLOSE` job; `None` when the
/// host refuses (nested jobs older than Win8, access denied) — callers keep
/// working with the direct-process fallback.
#[cfg(windows)]
unsafe fn attach_pid(pid: u32) -> Option<windows::Win32::Foundation::HANDLE> {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::JobObjects::{
        AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation,
        SetInformationJobObject, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
    };
    use windows::Win32::System::Threading::{OpenProcess, PROCESS_SET_QUOTA, PROCESS_TERMINATE};
    if pid == 0 {
        return None;
    }
    let job = CreateJobObjectW(None, None).ok()?;
    let mut info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
    info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    if SetInformationJobObject(
        job,
        JobObjectExtendedLimitInformation,
        &info as *const _ as *const _,
        std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
    )
    .is_err()
    {
        let _ = CloseHandle(job);
        return None;
    }
    let proc = match OpenProcess(PROCESS_SET_QUOTA | PROCESS_TERMINATE, false, pid) {
        Ok(p) => p,
        Err(_) => {
            let _ = CloseHandle(job);
            return None;
        }
    };
    if AssignProcessToJobObject(job, proc).is_err() {
        let _ = CloseHandle(proc);
        let _ = CloseHandle(job);
        return None;
    }
    let _ = CloseHandle(proc);
    Some(job)
}

#[cfg(windows)]
unsafe fn open_process_for_terminate(pid: u32) -> Result<windows::Win32::Foundation::HANDLE, String> {
    use windows::Win32::System::Threading::{OpenProcess, PROCESS_SYNCHRONIZE, PROCESS_TERMINATE};
    OpenProcess(PROCESS_TERMINATE | PROCESS_SYNCHRONIZE, false, pid).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bare_spec(argv: &[&str], log: &std::path::Path) -> Spec {
        Spec {
            argv: argv.iter().map(|s| s.to_string()).collect(),
            cwd: std::env::temp_dir().to_string_lossy().into_owned(),
            env_extra: vec![],
            log_path: log.to_string_lossy().into_owned(),
            request: None,
        }
    }

    #[test]
    fn empty_argv_rejected() {
        let err = match Handle::start(bare_spec(&[], std::path::Path::new("C:\\temp\\nope\\x.log"))) {
            Err(e) => e,
            Ok(_) => panic!("empty argv must be rejected"),
        };
        assert_eq!(err, "proc: empty argv");
    }

    #[cfg(windows)]
    #[test]
    fn bare_echo_writes_log_and_exit_zero() {
        let log = std::env::temp_dir().join("pi-proc-echo.log");
        let h = Handle::start(bare_spec(&["cmd.exe", "/c", "echo PROC_OK"], &log)).expect("spawn");
        let e = h.wait();
        assert_eq!(e.code, 0, "{e:?}");
        assert!(!e.killed);
        let body = std::fs::read_to_string(&log).unwrap();
        assert!(body.contains("PROC_OK"), "{body:?}");
        let _ = std::fs::remove_file(&log);
    }

    #[cfg(windows)]
    #[test]
    fn bare_exit_code_roundtrip() {
        let log = std::env::temp_dir().join("pi-proc-code.log");
        let h = Handle::start(bare_spec(&["cmd.exe", "/c", "exit 7"], &log)).expect("spawn");
        let e = h.wait();
        assert_eq!(e.code, 7, "{e:?}");
        let _ = std::fs::remove_file(&log);
    }

    #[cfg(windows)]
    #[test]
    fn log_dir_created() {
        let log = std::env::temp_dir().join("pi-proc-nested").join("deep").join("x.log");
        let h = Handle::start(bare_spec(&["cmd.exe", "/c", "echo nested"], &log)).expect("spawn");
        let _ = h.wait();
        assert!(log.is_file());
        let _ = std::fs::remove_file(&log);
    }

    /// Both ping-based tests count PING.EXE on the host — one serializing
    /// lock (parallel runs cross-talked: observed flake).
    #[cfg(windows)]
    static PING_MU: Mutex<()> = Mutex::new(());

    #[cfg(unix)]
    #[test]
    fn bare_echo_writes_log_and_exit_zero_unix() {
        let log = std::env::temp_dir().join("pi-proc-echo-unix.log");
        let h = Handle::start(bare_spec(&["/bin/sh", "-c", "echo PROC_OK"], &log)).expect("spawn");
        let e = h.wait();
        assert_eq!(e.code, 0, "{e:?}");
        assert!(!e.killed);
        let body = std::fs::read_to_string(&log).unwrap();
        assert!(body.contains("PROC_OK"), "{body:?}");
        let _ = std::fs::remove_file(&log);
    }

    #[cfg(unix)]
    #[test]
    fn bare_exit_code_roundtrip_unix() {
        let log = std::env::temp_dir().join("pi-proc-code-unix.log");
        let h = Handle::start(bare_spec(&["/bin/sh", "-c", "exit 7"], &log)).expect("spawn");
        let e = h.wait();
        assert_eq!(e.code, 7, "{e:?}");
        let _ = std::fs::remove_file(&log);
    }

    /// Whole-tree kill on Unix: `sh` backgrounds a `sleep` grandchild; the
    /// kill must take the group (sh + sleep), and the group must be gone
    /// afterwards (`kill(-pgid, 0)` → ESRCH), promptly, with a blocked
    /// waiter returning — the bg_stop shape.
    #[cfg(unix)]
    #[test]
    fn kill_takes_whole_tree_unix() {
        let log = std::env::temp_dir().join("pi-proc-kill-unix.log");
        let h =
            Handle::start(bare_spec(&["/bin/sh", "-c", "sleep 30 & wait"], &log)).expect("spawn");
        let pid = h.pid();
        std::thread::sleep(Duration::from_millis(600));
        assert!(h.try_wait().is_none(), "still running");

        let t = std::time::Instant::now();
        std::thread::scope(|s| {
            s.spawn(|| {
                let e = h.wait();
                assert!(e.killed, "waiter: {e:?}");
            });
            std::thread::sleep(Duration::from_millis(300));
            h.kill();
        });
        let e = h.wait();
        assert!(e.killed, "{e:?}");
        assert!(t.elapsed() < Duration::from_secs(5), "kill+wait too slow");

        // no leftovers: the group (grandchild included) must disappear
        let mut gone = unsafe { libc::kill(-(pid as i32), 0) } != 0;
        for _ in 0..50 {
            if gone {
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
            gone = unsafe { libc::kill(-(pid as i32), 0) } != 0;
        }
        assert!(gone, "process group {pid} still alive after kill");
        let _ = std::fs::remove_file(&log);
    }

    #[cfg(windows)]
    #[test]
    fn kill_takes_whole_tree_while_a_waiter_blocks() {
        let _lock = PING_MU.lock().unwrap_or_else(|e| e.into_inner());
        let baseline = count_named("PING.EXE");
        let log = std::env::temp_dir().join("pi-proc-kill.log");
        let h = Handle::start(bare_spec(&["cmd.exe", "/c", "ping -n 30 127.0.0.1 > nul"], &log))
            .expect("spawn");
        std::thread::sleep(Duration::from_millis(1200));
        let mid = count_named("PING.EXE");
        assert!(
            mid > baseline,
            "grandchild ping never started (baseline {baseline}, now {mid}); tasklist: {}",
            tasklist_raw("PING.EXE")
        );
        assert!(h.try_wait().is_none(), "still running");

        // The bg pattern: a waiter blocked in wait() while bg_stop kills —
        // both sides must return promptly (polling design, no long lock).
        let t = std::time::Instant::now();
        std::thread::scope(|s| {
            s.spawn(|| {
                let e = h.wait();
                assert!(e.killed, "waiter: {e:?}");
            });
            std::thread::sleep(Duration::from_millis(300));
            h.kill();
        });
        let e = h.wait();
        assert!(e.killed, "{e:?}");
        assert!(t.elapsed() < Duration::from_secs(5), "kill+wait too slow");

        // no leftovers: the job took cmd AND ping
        let mut after = count_named("PING.EXE");
        for _ in 0..10 {
            if after <= baseline {
                break;
            }
            std::thread::sleep(Duration::from_millis(300));
            after = count_named("PING.EXE");
        }
        assert!(
            after <= baseline,
            "orphaned ping survives (baseline {baseline}, after {after}); tasklist: {}",
            tasklist_raw("PING.EXE")
        );
        let _ = std::fs::remove_file(&log);
    }

    #[cfg(windows)]
    fn tasklist_raw(name: &str) -> String {
        let out = Command::new("tasklist")
            .args(["/FI", &format!("IMAGENAME eq {name}")])
            .output()
            .expect("tasklist");
        String::from_utf8_lossy(&out.stdout).into_owned()
    }

    #[cfg(windows)]
    fn count_named(name: &str) -> usize {
        tasklist_raw(name).to_lowercase().matches(&name.to_lowercase()).count()
    }
}

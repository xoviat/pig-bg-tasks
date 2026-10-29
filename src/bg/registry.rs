//! Port of `internal/bg/bg.go` — job registry, job model, log paths, and the
//! lifetime counters/sweeps. Pure state; behavior lives in `lifecycle`.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Condvar, Mutex, OnceLock};
use std::time::Instant;

use crate::bg::glock;
use crate::bg::handle::Handle;
use crate::bg::port::SdkPort;
use crate::bg::{MAX_CONCURRENT_JOBS, RECENT_TERMINAL_KEEP};

/// JobStatus mirrors the reference (`timed_out` reserved, no producer in v1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JobStatus {
    Running,
    Completed,
    Failed,
    Killed,
    TimedOut,
}

impl JobStatus {
    /// Terminal = final.
    pub fn terminal(&self) -> bool {
        !matches!(self, JobStatus::Running)
    }

    /// Wire value (parity with the reference's string statuses).
    pub fn as_str(&self) -> &'static str {
        match self {
            JobStatus::Running => "running",
            JobStatus::Completed => "completed",
            JobStatus::Failed => "failed",
            JobStatus::Killed => "killed",
            JobStatus::TimedOut => "timed_out",
        }
    }
}

impl std::fmt::Display for JobStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Why a foreground command moved to the background.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackgroundReason {
    Manual,
    Timeout,
    Steer,
}

impl BackgroundReason {
    pub fn as_str(&self) -> &'static str {
        match self {
            BackgroundReason::Manual => "manual",
            BackgroundReason::Timeout => "timeout",
            BackgroundReason::Steer => "steer",
        }
    }
}

/// Mutable job state guarded per job (Go guarded `Notified` via the registry
/// mutex; a per-job mutex gives the same mutual exclusion without holding the
/// registry during notification latches).
struct JobState {
    status: JobStatus,
    exit_code: Option<i32>,
    notified: bool,
    is_backgrounded: bool,
    stop_reason: String,
}

/// One tracked command.
pub struct Job {
    pub id: String,
    pub name: String,
    /// Display form (already human-readable).
    pub command: String,
    pub log_path: String,
    pub tool_call_id: String,
    pub start_time: Instant,
    pub pid: u32,
    pub handle: Option<Arc<dyn Handle>>,
    state: Mutex<JobState>,
    done: Mutex<bool>,
    done_cv: Condvar,
}

impl Job {
    pub fn status(&self) -> JobStatus {
        glock(&self.state).status
    }

    pub fn exit_code(&self) -> Option<i32> {
        glock(&self.state).exit_code
    }

    pub fn notified(&self) -> bool {
        glock(&self.state).notified
    }

    pub fn set_notified(&self) {
        glock(&self.state).notified = true;
    }

    /// Atomic check-and-set for the exactly-once notification latch:
    /// returns true iff this call performed the transition.
    pub fn try_latch_notified(&self) -> bool {
        let mut st = glock(&self.state);
        if st.notified {
            return false;
        }
        st.notified = true;
        true
    }

    pub fn is_backgrounded(&self) -> bool {
        glock(&self.state).is_backgrounded
    }

    pub fn set_backgrounded(&self, v: bool) {
        glock(&self.state).is_backgrounded = v;
    }

    pub fn stop_reason(&self) -> String {
        glock(&self.state).stop_reason.clone()
    }

    pub fn set_stop_reason(&self, reason: &str) {
        glock(&self.state).stop_reason = reason.to_string();
    }

    pub fn is_terminal(&self) -> bool {
        self.status().terminal()
    }

    /// Flip to a final state ONCE (later marks are no-ops) and resolve the
    /// done broadcast. Returns true iff this call performed the flip.
    pub fn mark_terminal(&self, status: JobStatus, exit_code: Option<i32>) -> bool {
        let mut st = glock(&self.state);
        if st.status.terminal() {
            return false;
        }
        st.status = status;
        st.exit_code = exit_code;
        drop(st);
        let mut d = match self.done.lock() {
            Ok(d) => d,
            Err(p) => p.into_inner(),
        };
        *d = true;
        self.done_cv.notify_all();
        true
    }

    pub fn is_done(&self) -> bool {
        *glock(&self.done)
    }

    /// Block until the job reaches a terminal state (broadcast — any number
    /// of waiters).
    pub fn wait_done(&self) {
        let mut d = match self.done.lock() {
            Ok(d) => d,
            Err(p) => p.into_inner(),
        };
        while !*d {
            d = match self.done_cv.wait(d) {
                Ok(d) => d,
                Err(p) => p.into_inner(),
            };
        }
    }

    /// Age in whole milliseconds.
    pub fn age_ms(&self) -> u128 {
        self.start_time.elapsed().as_millis()
    }
}

/// Lets Ctrl+Shift+B / the timeout timer / steering flip a running
/// foreground command into the background.
pub struct ForegroundSlot {
    pub request_pause: Box<dyn Fn(BackgroundReason) + Send + Sync>,
}

impl ForegroundSlot {
    pub fn new<F: Fn(BackgroundReason) + Send + Sync + 'static>(f: F) -> Self {
        ForegroundSlot { request_pause: Box::new(f) }
    }
}

struct RegInner {
    jobs: HashMap<String, Arc<Job>>,
    foreground: HashMap<String, Arc<ForegroundSlot>>,
    recent_terminal: Vec<Arc<Job>>,
    completed_count: u32,
    failed_count: u32,
    killed_count: u32,
    total_started: u32,
    non_interactive: bool,
    notifier: Option<Arc<dyn SdkPort>>,
}

/// The single source of truth. Cheap to clone (`Clone` shares the state) so
/// watcher threads can hold their own handle to the same registry.
#[derive(Clone)]
pub struct Registry {
    inner: Arc<Mutex<RegInner>>,
}

impl Registry {
    pub fn new() -> Self {
        Registry {
            inner: Arc::new(Mutex::new(RegInner {
                jobs: HashMap::new(),
                foreground: HashMap::new(),
                recent_terminal: Vec::new(),
                completed_count: 0,
                failed_count: 0,
                killed_count: 0,
                total_started: 0,
                non_interactive: false,
                notifier: None,
            })),
        }
    }

    /// The process registry (Go `bg.Default()`).
    pub fn shared() -> &'static Registry {
        static SHARED: OnceLock<Registry> = OnceLock::new();
        SHARED.get_or_init(Registry::new)
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, RegInner> {
        glock(&self.inner)
    }

    /// Retain a context usable after its handler returns (SDK D19). Called at
    /// session_start and on every tool call so the newest session drives
    /// notifications.
    pub fn set_notifier(&self, port: Arc<dyn SdkPort>) {
        self.lock().notifier = Some(port);
    }

    pub fn notifier(&self) -> Option<Arc<dyn SdkPort>> {
        self.lock().notifier.clone()
    }

    /// No UI to background FOR (print/RPC/headless — from session_start's
    /// HasUI).
    pub fn is_non_interactive(&self) -> bool {
        self.lock().non_interactive
    }

    pub fn set_non_interactive(&self, v: bool) {
        self.lock().non_interactive = v;
    }

    pub fn foreground_present(&self, tool_call_id: &str) -> bool {
        self.lock().foreground.contains_key(tool_call_id)
    }

    /// Mint `bash-` + 8 uniform base36 chars (unguessable, collision-checked
    /// against the live registry).
    pub fn new_job_id(&self) -> String {
        const ALPHABET: &[u8] = b"0123456789abcdefghijklmnopqrstuvwxyz";
        loop {
            let mut b = [0u8; 8];
            if getrandom::fill(&mut b).is_err() {
                // crypto failure: fall back to time+pid (still unique in-process)
                let t = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.subsec_nanos())
                    .unwrap_or(0);
                return format!("bash-{t:08x}");
            }
            let mut id = String::from("bash-");
            for byte in b {
                id.push(ALPHABET[byte as usize % ALPHABET.len()] as char);
            }
            if !self.lock().jobs.contains_key(&id) {
                return id;
            }
        }
    }

    /// Build and register a fresh running job.
    #[allow(clippy::too_many_arguments)]
    pub fn new_running_job(
        &self,
        id: &str,
        command: &str,
        handle: Option<Arc<dyn Handle>>,
        log_path: &str,
        tool_call_id: &str,
        name: &str,
        backgrounded: bool,
    ) -> Arc<Job> {
        let pid = handle.as_ref().map(|h| h.pid()).unwrap_or(0);
        let job = Arc::new(Job {
            id: id.to_string(),
            name: name.to_string(),
            command: command.to_string(),
            log_path: log_path.to_string(),
            tool_call_id: tool_call_id.to_string(),
            start_time: Instant::now(),
            pid,
            handle,
            state: Mutex::new(JobState {
                status: JobStatus::Running,
                exit_code: None,
                notified: false,
                is_backgrounded: backgrounded,
                stop_reason: String::new(),
            }),
            done: Mutex::new(false),
            done_cv: Condvar::new(),
        });
        self.lock().jobs.insert(id.to_string(), job.clone());
        job
    }

    /// The 16-running cap.
    pub fn at_concurrency_limit(&self) -> bool {
        let g = self.lock();
        let n = g.jobs.values().filter(|j| !j.is_terminal()).count();
        n >= MAX_CONCURRENT_JOBS
    }

    /// Promotion only — foreground jobs are not "started" until they move to
    /// the background.
    pub fn mark_started(&self) {
        self.lock().total_started += 1;
    }

    /// Live map first, then the recent-terminal ring.
    pub fn find_job(&self, id: &str) -> Option<Arc<Job>> {
        let g = self.lock();
        if let Some(j) = g.jobs.get(id) {
            return Some(j.clone());
        }
        g.recent_terminal.iter().rev().find(|j| j.id == id).cloned()
    }

    /// Evict a terminal job from the live map into the ring; update lifetime
    /// counters. No-op when the job is not (or no longer) in the map.
    pub fn forget(&self, job: &Arc<Job>) {
        let mut g = self.lock();
        if g.jobs.remove(&job.id).is_none() {
            return;
        }
        match job.status() {
            JobStatus::Completed => g.completed_count += 1,
            JobStatus::Failed => g.failed_count += 1,
            JobStatus::Killed | JobStatus::TimedOut => g.killed_count += 1,
            JobStatus::Running => {}
        }
        g.recent_terminal.push(job.clone());
        if g.recent_terminal.len() > RECENT_TERMINAL_KEEP {
            g.recent_terminal.remove(0);
        }
    }

    pub fn set_foreground(&self, tool_call_id: &str, slot: ForegroundSlot) {
        self.lock()
            .foreground
            .insert(tool_call_id.to_string(), Arc::new(slot));
    }

    /// Drop the slot (idempotent).
    pub fn remove_foreground(&self, tool_call_id: &str) {
        self.lock().foreground.remove(tool_call_id);
    }

    /// Mark a terminal job's outcome as already known (suppresses the
    /// completion notification) and run the lazy eviction sweep.
    /// `bg_output` / `bg_stop` call this before returning the outcome.
    pub fn latch_terminal(&self, job: &Arc<Job>) {
        if !job.is_terminal() {
            return;
        }
        job.set_notified();
        self.sweep_notified_terminal();
    }

    /// Evict terminal jobs whose outcome was already surfaced (lazy sweep
    /// run by `bg_list`).
    pub fn sweep_notified_terminal(&self) {
        let evict: Vec<Arc<Job>> = {
            let g = self.lock();
            g.jobs
                .values()
                .filter(|j| j.is_terminal() && j.notified())
                .cloned()
                .collect()
        };
        for j in evict {
            self.forget(&j);
        }
    }

    /// (running, terminal-still-in-map, recent ring) — map order, like the
    /// reference's iteration.
    pub fn snapshot(&self) -> (Vec<Arc<Job>>, Vec<Arc<Job>>, Vec<Arc<Job>>) {
        let g = self.lock();
        let mut running = Vec::new();
        let mut terminal_in_map = Vec::new();
        for j in g.jobs.values() {
            if j.is_terminal() {
                terminal_in_map.push(j.clone());
            } else {
                running.push(j.clone());
            }
        }
        (running, terminal_in_map, g.recent_terminal.clone())
    }

    /// Lifetime completed/failed+killed plus backgrounded-running.
    pub fn counters(&self) -> (u32, u32, u32) {
        let g = self.lock();
        let running_bg = g
            .jobs
            .values()
            .filter(|j| !j.is_terminal() && j.is_backgrounded())
            .count() as u32;
        (running_bg, g.completed_count, g.failed_count + g.killed_count)
    }

    /// Drain every registered foreground slot (used by `/bg` and steering).
    pub(crate) fn take_foreground_slots(&self) -> Vec<Arc<ForegroundSlot>> {
        let mut g = self.lock();
        g.foreground.drain().map(|(_, s)| s).collect()
    }
}

impl Default for Registry {
    fn default() -> Self {
        Registry::new()
    }
}

/// `%TEMP%\pi-bg-tasks` on Windows (inside the sandbox grant, so a confined
/// child can write its own log).
pub fn log_dir() -> PathBuf {
    std::env::temp_dir().join("pi-bg-tasks")
}

/// Map a task id to its log file.
pub fn log_path_for(id: &str) -> PathBuf {
    log_dir().join(format!("{id}.log"))
}

/// Delete logs older than 24h (session_start housekeeping).
pub fn sweep_stale_logs(now: std::time::SystemTime) -> usize {
    use crate::bg::STALE_LOG_MAX_AGE_SECS;
    let dir = log_dir();
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return 0;
    };
    let mut removed = 0;
    for e in entries.flatten() {
        let name = e.file_name();
        let Some(name) = name.to_str() else { continue };
        if e.file_type().map(|t| t.is_dir()).unwrap_or(true) || !name.ends_with(".log") {
            continue;
        }
        let Ok(meta) = e.metadata() else { continue };
        let Ok(modified) = meta.modified() else { continue };
        let age = now.duration_since(modified).unwrap_or_default();
        if age.as_secs() > STALE_LOG_MAX_AGE_SECS && std::fs::remove_file(e.path()).is_ok() {
            removed += 1;
        }
    }
    removed
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bg::handle::Exit;
    use crate::bg::mock::MockHandle;

    #[test]
    fn job_id_shape_and_uniqueness() {
        let r = Registry::new();
        let mut seen = std::collections::HashSet::new();
        for _ in 0..500 {
            let id = r.new_job_id();
            assert_eq!(id.len(), 13, "{id}"); // "bash-" + 8 base36
            assert!(id.starts_with("bash-"));
            assert!(id[5..].chars().all(|c| c.is_ascii_alphanumeric()), "{id}");
            assert!(seen.insert(id), "collision");
        }
    }

    #[test]
    fn mark_terminal_is_first_wins() {
        let r = Registry::new();
        let j = r.new_running_job("bash-t1", "echo hi", None, "/tmp/x.log", "tc", "", false);
        assert!(j.mark_terminal(JobStatus::Completed, Some(0)));
        assert!(!j.mark_terminal(JobStatus::Failed, Some(3)));
        assert_eq!(j.status(), JobStatus::Completed);
        assert_eq!(j.exit_code(), Some(0));
        assert!(j.is_done());
        j.wait_done(); // must not block after the flip
    }

    #[test]
    fn forget_counters_and_recent_ring_cap() {
        let r = Registry::new();
        for i in 0..(RECENT_TERMINAL_KEEP + 5) {
            let id = format!("bash-r{i:02}");
            let j = r.new_running_job(&id, "cmd", None, "/tmp/x.log", "tc", "", false);
            j.mark_terminal(JobStatus::Completed, Some(0));
            r.forget(&j);
        }
        let (_, terminal, recent) = r.snapshot();
        assert!(terminal.is_empty());
        assert_eq!(recent.len(), RECENT_TERMINAL_KEEP);
        let (_, done, failed) = r.counters();
        assert_eq!(done, (RECENT_TERMINAL_KEEP + 5) as u32);
        assert_eq!(failed, 0);
        // find still resolves from the ring
        assert!(r.find_job("bash-r00").is_none()); // aged out
        assert!(r.find_job("bash-r24").is_some());
    }

    #[test]
    fn concurrency_limit_at_16() {
        let r = Registry::new();
        let h: Arc<dyn Handle> = Arc::new(MockHandle::running());
        for i in 0..(MAX_CONCURRENT_JOBS - 1) {
            r.new_running_job(&format!("bash-c{i:02}"), "x", Some(h.clone()), "/tmp/x.log", "", "", false);
        }
        assert!(!r.at_concurrency_limit(), "15 running is under the cap");
        r.new_running_job("bash-c15", "x", Some(h.clone()), "/tmp/x.log", "", "", false);
        assert!(r.at_concurrency_limit(), "16 running hits the cap");
    }

    #[test]
    fn latch_and_sweep_evicts_only_notified_terminal() {
        let r = Registry::new();
        let done_j = r.new_running_job("bash-d1", "x", None, "/tmp/x.log", "", "", false);
        done_j.mark_terminal(JobStatus::Killed, None);
        r.latch_terminal(&done_j);
        assert!(r.find_job("bash-d1").is_some()); // in recent ring
        let (_, terminal, _) = r.snapshot();
        assert!(terminal.is_empty()); // evicted from live map

        let run_j = r.new_running_job("bash-r1", "x", None, "/tmp/x.log", "", "", false);
        r.latch_terminal(&run_j); // not terminal → no latch, no sweep effect
        assert!(!run_j.notified());
        assert!(r.find_job("bash-r1").is_some());
    }

    impl Registry {
        #[allow(dead_code)]
        fn running_count(&self) -> usize {
            let g = self.lock();
            g.jobs.values().filter(|j| !j.is_terminal()).count()
        }
    }

    #[test]
    fn exit_handle_contract() {
        let h = MockHandle::running();
        assert!(h.try_wait().is_none());
        h.kill();
        let e = h.wait();
        assert!(e.killed);
        assert_eq!(e.code, 1);
        // second kill cannot resurrect
        h.finish(Exit::code(0));
        assert!(h.wait().killed);
    }
}

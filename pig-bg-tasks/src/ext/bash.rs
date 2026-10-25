//! Port of `internal/tools/bash.go` — the composed bash tool: bg semantics
//! (run_in_background, quick window, auto-background, steering,
//! notifications) × sandbox semantics (modes, escalation, confinement,
//! denial classification). One definition, one execute path — every spawn
//! is confined exactly like every other.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bg::registry::{ForegroundSlot, Registry};
use bg::{lifecycle, output, ui, BackgroundReason, Handle as _};
use pig_sdk::{Context, ToolDefinition, ToolResult};
use policy::{self, config::Config, Mode};
use runner::converge::{Engine, State as ConvergeState};
use runner::proc::{self, Spec};
use runner::{ErrUnavailable, request, select, shell};
use serde_json::{Value, json};

use crate::ext::resolve::{config_for, escalation_notes, install_notifier, resolve_call, strip_escalation_placeholders, ResolvedCall};

pub const NO_WAIT_HINT: &str = "next_step: You will be automatically notified when it completes — do NOT wait, poll, or call bg_output to wait on it; continue with your current work.";

const SANDBOX_NOTE: &str = "Sandbox: confined to the current mode; workspace-write already allows the workspace and %TEMP%. Unless retrying a denial, omit these fields or send JSON null.";

const ENV_REDIRECT_GUIDELINE: &str = "Never work around the sandbox by relocating global cache/data directories into the workspace — no environment-variable overrides (XDG_CACHE_HOME, XDG_DATA_HOME, HOME, UV_CACHE_DIR, PIP_CACHE_DIR, npm_config_cache, PNPM_HOME, YARN_CACHE_FOLDER, CARGO_HOME, GOPATH, ...), no cache-relocating tool flags (--cache-dir, --store-dir, --cache), and no config files that do the same — unless the user explicitly asked for exactly that relocation. Run tools unmodified — including on the escalated retry: when their real global write is denied, retry that same call with escalation rather than adding a relocation.";

const ESCALATION_GUIDELINE: &str = "When a sandbox denial marker appears, you may retry the exact same call once with sandbox_permissions (the narrowest wider mode that suffices) plus justification; the user is asked to approve and may attach a reason when denying. Never send escalation fields before a denial — such requests are ignored and the call runs confined. If denied or unavailable, stop and explain instead of working around it.";

const BG_GUIDELINE1: &str =
    "Use bash with run_in_background=true when a command is expected to run for a long time (dev servers, watchers, long builds).";
const BG_GUIDELINE2: &str = "After starting a background command, do NOT wait on it or poll its output — you will be automatically notified when it completes; continue with other work or return control to the user.";
const BG_GUIDELINE3: &str = "Never block the turn with a bare `sleep N` or a long foreground polling loop. If a readiness gate is truly unavoidable (e.g. wait for a server to print READY before running tests), use a bounded foreground poll with a short timeout (e.g. `timeout 30 bash -c 'until grep -q READY log; do sleep 0.5; done'`) — it auto-backgrounds at the timeout and you will be notified.";
const BG_GUIDELINE4: &str = "Check background task status with bg_list; read a task's output with bg_output (a non-blocking snapshot); stop one with bg_stop.";

/// The single composed bash tool.
pub fn bash_definition() -> ToolDefinition {
    let log_dir = std::env::temp_dir().join("pi-bg-tasks");
    let mut def = ToolDefinition::new(
        "bash",
        "Bash (sandboxed)",
        format!(
            "Run a bash command. Long-running commands auto-background after the timeout. \
             Set run_in_background=true to start in the background immediately. \
             Use Ctrl+Shift+B or /bg to manually background a running command.\n\n{SANDBOX_NOTE}"
        ),
        json!({
            "type": "object",
            "properties": {
                "command": {"type": "string", "description": "Shell command to run"},
                "timeout": {"type": "number", "description": "Timeout in seconds (default: 120). A foreground command past the timeout auto-backgrounds instead of dying."},
                "run_in_background": {"type": "boolean", "description": format!("Set to true to run this command in the background immediately. Output is saved to {}/<taskId>.log.", log_dir.display())},
                "description": {"type": "string", "description": "Short description of what this command does"},
                "sandbox_permissions": {
                    "anyOf": [{"const": "workspace-write"}, {"const": "danger-full-access"}, {"type": "null"}],
                    "description": "Escalation: ONLY valid when retrying a command that just returned a sandbox denial. Narrowest wider mode that suffices; requires justification."
                },
                "justification": {
                    "anyOf": [{"type": "string"}, {"type": "null"}],
                    "description": "One-sentence reason for the escalation; shown to the user in the approval prompt."
                }
            }
        }),
        bash_execute,
    );
    def.prompt_snippet = Some(
        "Run shell commands; long-running commands auto-background, or use run_in_background=true"
            .into(),
    );
    def.prompt_guidelines = vec![
        BG_GUIDELINE1.into(),
        BG_GUIDELINE2.into(),
        BG_GUIDELINE3.into(),
        BG_GUIDELINE4.into(),
        ENV_REDIRECT_GUIDELINE.into(),
        ESCALATION_GUIDELINE.into(),
    ];
    def.prepare_arguments = Some(Box::new(strip_escalation_placeholders));
    def
}

/// The composed execute path.
fn bash_execute(ctx: &Context, params: Value) -> ToolResult {
    let command = params.get("command").and_then(Value::as_str).unwrap_or("").to_string();
    if lifecycle::is_blank_command(&command) {
        return ToolResult::Error("Command is empty.".to_string());
    }
    let cwd = ctx.cwd().to_string();
    if let Err(e) = lifecycle::require_existing_cwd(&cwd) {
        return ToolResult::Error(e);
    }
    let reg = Registry::shared();
    let port = install_notifier(ctx);
    if let Err(e) = lifecycle::assert_job_slot(&reg) {
        return ToolResult::Error(e);
    }
    let cfg = config_for(ctx);

    let rc = match resolve_call(ctx, &params, &cfg, &command) {
        Ok(rc) => rc,
        Err(e) => return ToolResult::Error(e), // fail-closed: nothing executed
    };

    let run_bg = params.get("run_in_background").and_then(Value::as_bool).unwrap_or(false);
    let desc = params.get("description").and_then(Value::as_str).unwrap_or("").to_string();
    let timeout_ms = params
        .get("timeout")
        .and_then(Value::as_f64)
        .filter(|v| *v > 0.0)
        .map(|v| (v * 1000.0) as u64)
        .unwrap_or(bg::DEFAULT_TIMEOUT_MS);

    let id = reg.new_job_id();
    let log_path = bg::registry::log_path_for(&id).to_string_lossy().into_owned();
    let session_id = ctx.get_session_id().unwrap_or_default(); // ledger writes at classify time

    // Bind to the newest epoch and converge synchronously — the wait is part
    // of the command's total duration (background-task composition unchanged:
    // quick-window/auto-background timers start after spawn). No stale-policy
    // window; causal failure = fail-closed.
    let state = ConvergeState {
        mode: rc.mode,
        workspace: policy::canonical(&cwd),
        temp: std::env::temp_dir().to_string_lossy().into_owned(),
        extras: cfg.extra_writable_dirs.clone(),
    };
    let converged = match Engine::shared().bind(state) {
        Ok(s) => s,
        Err(err) => {
            bg::dbg::trace(json!({
                "phase": "converge_failed", "id": id, "mode": rc.mode.as_str(), "err": err
            }));
            return ToolResult::Error(format!(
                "SANDBOX_UNAVAILABLE ({}): sandbox convergence failed before the command ran: {err} \
                 — the command was NOT executed (fail-closed; the error carries the real cause)",
                rc.mode
            ));
        }
    };

    let spec = match build_spec(&rc.mode, &cwd, &command, &log_path, &converged) {
        Ok(s) => s,
        Err(e) => {
            bg::dbg::trace(json!({
                "phase": "refused", "id": id, "mode": rc.mode.as_str(), "cwd": cwd, "err": e
            }));
            return ToolResult::Error(e); // fail-closed: confined construction refuses
        }
    };
    bg::dbg::trace(json!({
        "phase": "start", "id": id, "mode": rc.mode.as_str(),
        "confined": policy::is_confined(rc.mode),
        "epoch": Engine::shared().snapshot().epoch,
        "shell": spec.argv[0], "bg": run_bg, "cwd": cwd, "log": log_path
    }));

    let notes = escalation_notes(&rc);
    let tcid = ctx.tool_call_id().unwrap_or("").to_string();

    if run_bg {
        let h = match proc::Handle::start(spec) {
            Ok(h) => h,
            Err(e) => {
                bg::dbg::trace(json!({"phase": "start_error", "id": id, "bg": true, "err": e}));
                return ToolResult::Error(format!("failed to start background command: {e}"));
            }
        };
        let job =
            reg.new_running_job(&id, &command, Some(Arc::new(h)), &log_path, &tcid, &desc, true);
        lifecycle::start_background_job(&reg, &job, true);
        let text = format!(
            "Command running in background with ID: {id}. Output is being written to: {log_path}\n{NO_WAIT_HINT}"
        );
        return ToolResult::Text(with_notes(&text, &notes));
    }

    run_foreground(
        ctx, &reg, &port, spec, rc, id, command, log_path, timeout_ms, &cfg, &session_id, &tcid,
    )
}

fn with_notes(text: &str, notes: &str) -> String {
    if notes.is_empty() {
        text.to_string()
    } else {
        format!("{text}\n{notes}")
    }
}

/// Assemble the spawn: resolved shell, log path, and — for confined modes —
/// the bound epoch's policy. No host work, never blocks (convergence already
/// happened). Every failure REFUSES the command (fail-closed, never bare).
///
/// Plan §4 addition: under confinement an MSYS/Git-Bash engine is rejected
/// *before spawn* (mxc#1061 fail-fast) with an actionable `shellPath` hint.
fn build_spec(
    mode: &Mode,
    cwd: &str,
    command: &str,
    log_path: &str,
    converged: &ConvergeState,
) -> Result<Spec, String> {
    let shell = match shell::resolve() {
        Ok(s) => s,
        Err(e) => {
            if policy::is_confined(*mode) {
                return Err(ErrUnavailable {
                    detail: "bash shell could not be resolved (PATH, then standard Git for Windows locations)"
                        .to_string(),
                }
                .to_string());
            }
            return Err(e);
        }
    };
    let mut spec = Spec {
        argv: vec![shell, "-c".to_string(), command.to_string()],
        cwd: cwd.to_string(),
        env_extra: Vec::new(),
        log_path: log_path.to_string(),
        request: None,
    };
    if !policy::is_confined(*mode) {
        return Ok(spec); // danger-full-access: bare (explicit escape hatch)
    }
    if select(0).kind == runner::Kind::Unavailable {
        return Err(ErrUnavailable { detail: String::new() }.to_string());
    }
    shell::ensure_confined_shell(&spec.argv[0])?;
    let roots = policy::writable_roots(*mode, &converged.workspace, &converged.extras);
    spec.request = Some(request::build_request(&spec.argv, cwd, &[], &roots));
    Ok(spec)
}

#[allow(clippy::too_many_arguments)]
fn run_foreground(
    ctx: &Context,
    reg: &Registry,
    port: &Arc<dyn bg::SdkPort>,
    spec: Spec,
    rc: ResolvedCall,
    id: String,
    command: String,
    log_path: String,
    timeout_ms: u64,
    cfg: &Config,
    session_id: &str,
    tcid: &str,
) -> ToolResult {
    let h = match proc::Handle::start(spec) {
        Ok(h) => h,
        Err(e) => {
            bg::dbg::trace(json!({"phase": "start_error", "id": id, "bg": false, "err": e}));
            return ToolResult::Error(format!("failed to start command: {e}"));
        }
    };
    let handle: Arc<proc::Handle> = Arc::new(h);
    let job = reg.new_running_job(
        &id,
        &command,
        Some(handle.clone() as Arc<dyn bg::Handle>),
        &log_path,
        tcid,
        "",
        false,
    );

    // Foreground slot: Ctrl+Shift+B / timeout / steering flip to background.
    let pause_pending = Arc::new(AtomicBool::new(false));
    let (pause_tx, pause_rx) = std::sync::mpsc::channel::<BackgroundReason>();
    let timeout_tx = pause_tx.clone();
    let slot_tx = Arc::new(Mutex::new(Some(pause_tx)));
    {
        let pending = pause_pending.clone();
        reg.set_foreground(tcid, ForegroundSlot::new(move |r: BackgroundReason| {
            pending.store(true, Ordering::SeqCst);
            if let Some(tx) = slot_tx.lock().unwrap().as_ref() {
                let _ = tx.send(r);
            }
        }));
    }

    let started = Instant::now();
    let quick_end = started + Duration::from_millis(bg::QUICK_COMPLETION_MS);
    let deadline = started + Duration::from_millis(timeout_ms);
    let interactive = !reg.is_non_interactive();
    let mut streaming = false;
    let mut hinted = false;
    let mut streamer: Option<bg::output::Streamer> = None;
    #[allow(unused_assignments)] // every loop exit path assigns before break
    let mut outcome: Option<Result<String, String>> = None;

    loop {
        // Exit?
        if let Some(e) = handle.try_wait() {
            lifecycle::finish_foreground_job(reg, &job, e.clone());
            outcome = Some(finish_foreground(&rc, &e, &log_path, session_id, cfg));
            break;
        }
        // Pause request (manual / steer / timeout)?
        match pause_rx.try_recv() {
            Ok(reason) => {
                lifecycle::promote_to_background(reg, tcid, &job, true);
                let head = match reason {
                    BackgroundReason::Manual => {
                        format!("Command was manually backgrounded by user with ID: {id}.")
                    }
                    BackgroundReason::Steer => format!(
                        "Command was moved to the background with ID: {id} because the user sent a message while it was running."
                    ),
                    BackgroundReason::Timeout => {
                        format!("Command auto-backgrounded after {}s with ID: {id}.", timeout_ms / 1000)
                    }
                };
                let text =
                    format!("{head} Output is being written to: {log_path}\n{NO_WAIT_HINT}");
                outcome = Some(Ok(with_notes(&text, &escalation_notes(&rc))));
                break;
            }
            Err(std::sync::mpsc::TryRecvError::Empty) => {}
            Err(std::sync::mpsc::TryRecvError::Disconnected) => {}
        }
        // Genuine cancel (Esc / turn abort) kills the tree — unless a pause
        // was requested, in which case the process must survive into the
        // background (the queued reason handles the promotion).
        if !pause_pending.load(Ordering::SeqCst) && ctx_cancelled(ctx) {
            handle.kill();
        }
        // Auto-background timer (interactive sessions only — there is nobody
        // to background FOR in print/RPC mode, so the command simply runs out).
        if interactive
            && !pause_pending.load(Ordering::SeqCst)
            && Instant::now() >= deadline
        {
            pause_pending.store(true, Ordering::SeqCst);
            let _ = timeout_tx.send(BackgroundReason::Timeout);
        }
        // Quick-completion window elapsed: stream progress + show the hint.
        if !streaming && Instant::now() >= quick_end {
            streaming = true;
            ui::show_background_hint(port.as_ref());
            hinted = true;
            let ctx2 = ctx.clone();
            streamer = Some(output::start_stream(
                log_path.clone(),
                Duration::from_secs(1),
                Some(move |tail: &str| {
                    let _ = ctx2.on_update(ToolResult::Json(json!({
                        "content": [{"type": "text", "text": tail}]
                    })));
                }),
            ));
        }
        std::thread::sleep(Duration::from_millis(50));
    }

    // Deferred cleanup (Go's defers): stop the poller, clear the hint,
    // release the foreground slot (all exit paths — including the quick
    // window, where Go leaked the slot).
    drop(streamer);
    if hinted {
        ui::clear_background_hint(port.as_ref());
    }
    reg.remove_foreground(tcid);

    match outcome {
        Some(Ok(s)) => ToolResult::Text(s),
        Some(Err(e)) => ToolResult::Error(e),
        None => ToolResult::Error("internal: foreground loop ended without a result".to_string()),
    }
}

/// Run-level cancellation (Esc / turn abort) — the `ctx.Done()` equivalent:
/// the run's signal, falling back to request-level cancellation.
fn ctx_cancelled(ctx: &Context) -> bool {
    ctx.signal().map(|s| s.is_cancelled()).unwrap_or(false) || ctx.is_cancelled()
}

/// Classify and shape the result (Go reference `finishForeground` merged
/// with sandbox ops classification — classification reads the merged
/// stdout+stderr log tail instead of a piped stderr; documented divergence).
fn finish_foreground(
    rc: &ResolvedCall,
    e: &bg::Exit,
    log_path: &str,
    session_id: &str,
    _cfg: &Config,
) -> Result<String, String> {
    let mut output =
        output::read_bounded_tail(log_path, bg::OUTPUT_PREVIEW_CHARS as i64);
    let notes = escalation_notes(rc);

    if policy::is_confined(rc.mode) && !e.killed && e.code != 0 && e.code != -1 {
        let code = e.code;
        // Runner failure first: the command NEVER RAN (init fatal).
        if let Some(fatal) =
            classify::runner_failure(Some(code), &output, &classify::WINDOWS_RULES)
        {
            bg::dbg::trace(json!({
                "phase": "runner_failure", "code": code, "fatal": fatal, "log": log_path
            }));
            // No host work on the tool path beyond the synchronous heal: the
            // next bind re-validates under a fresh epoch (runner-failure
            // heal parity).
            Engine::shared().invalidate();
            return Err(format!(
                "SANDBOX_UNAVAILABLE ({}): sandbox runner failed before the command ran: {fatal} \
                 The command was NOT executed — the sandbox re-converges on the next call; \
                 retry the same command.",
                rc.mode
            ));
        }
        // Real denial: record it (arms the denial-first gate) + annotate.
        if classify::denial(Some(code), &output, classify::DENIAL_SIGNATURES) {
            bg::dbg::trace(json!({"phase": "denial", "code": code, "log": log_path}));
            if !session_id.is_empty() {
                escalate::ledger::record(session_id, escalate::ledger::Kind::Command);
            }
            output.push('\n');
            output.push_str(&escalate::denial_marker(rc.mode));
            output.push('\n');
            output.push_str(escalate::escalation_hint_marker());
        }
    }

    // Deliberate kill (Esc, or job teardown): never an error result.
    if e.killed {
        return Ok(with_notes(&output_or_no_output(&output), &notes));
    }
    if e.code != 0 && e.code != -1 {
        if output == "(no output yet)" || output.is_empty() {
            return Err(format!("Command exited with code {}", e.code));
        }
        return Err(with_notes(&output, &notes));
    }
    if e.code == -1 {
        return Err("command failed to run".to_string());
    }
    Ok(with_notes(&output_or_no_output(&output), &notes))
}

fn output_or_no_output(output: &str) -> String {
    if output.is_empty() || output == "(no output yet)" {
        "(no output)".to_string()
    } else {
        output.to_string()
    }
}

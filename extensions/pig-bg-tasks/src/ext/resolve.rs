//! Port of `internal/tools/resolve.go` — config plumbing and the
//! denial-first escalation resolution for the composed `bash` tool.

use std::sync::OnceLock;

use crate::bg::registry::Registry;
use crate::escalate::{Decision, DenialReasonPrompt, Request, Ui};
use pig_sdk::Context;
use crate::policy::{Mode, config, permission, resolve_effective_mode};
use serde_json::Value;
use std::sync::Arc;

use crate::ext::port::port_for;

static CONFIG_HOME: OnceLock<String> = OnceLock::new();

fn home_fallback() -> String {
    std::env::var("USERPROFILE")
        .or_else(|_| std::env::var("HOME"))
        .unwrap_or_default()
}

/// `ctx.ConfigHome()` once per process (one host roundtrip), with the Go
/// fallback to the user home when the host cannot answer.
pub fn config_home(ctx: &Context) -> String {
    CONFIG_HOME
        .get_or_init(|| match ctx.config_home() {
            Ok(h) if !h.is_empty() => h,
            _ => home_fallback(),
        })
        .clone()
}

/// The process-cached sandbox config for this host, with the mirrored
/// parent-session extras applied ([`crate::policy::inherit`]) — one choke
/// point, so every consumer (bash, `/sandbox` status, session start) sees
/// the same roots the spawn will actually get.
pub fn config_for(ctx: &Context) -> config::Config {
    let mut c = config::get(&config_home(ctx));
    c.extra_writable_dirs = crate::policy::inherit::mirror_extras(&c.extra_writable_dirs);
    c
}

/// Pin the config root at session_start (before any tool call needs it) and
/// warm the config so its warnings surface at startup.
pub fn pin_config_home(home: String) {
    let _ = CONFIG_HOME.set(home);
    if let Some(h) = CONFIG_HOME.get() {
        let _ = config::get(h); // warm: load warnings surface at startup
    }
}

/// One call's effective mode + escalation bookkeeping.
#[derive(Debug, Clone)]
pub struct ResolvedCall {
    pub mode: Mode,
    /// Approved escalation applied to THIS call.
    pub escalated: bool,
    /// Denial-first gate dropped the fields.
    pub ignored_escalation: bool,
}

/// Resolve denial-first escalation for bash (subject=command): placeholder
/// normalize → pair validation → effective mode (`/sandbox` override > config
/// default) → denial-ledger gate → approval dialogue. Nothing runs when it
/// returns an error (fail-closed, nothing executed).
pub fn resolve_call(
    ctx: &Context,
    params: &Value,
    cfg: &config::Config,
    summary: &str,
) -> Result<ResolvedCall, String> {
    let req_raw = params.get("sandbox_permissions").and_then(Value::as_str);
    let (requested, req_present) = crate::escalate::normalize_value(req_raw);
    let just_raw = params.get("justification").and_then(Value::as_str);
    let (justification, just_present) = crate::escalate::normalize_value(just_raw);

    crate::escalate::validate_args(
        req_present.then_some(requested.as_str()),
        just_present.then_some(justification.as_str()),
    )?;

    let effective = resolve_effective_mode(permission::get(), cfg.mode);
    if !req_present {
        return Ok(ResolvedCall { mode: effective, escalated: false, ignored_escalation: false });
    }

    // Denial-first hard gate: a strictly wider request needs an unconsumed
    // real denial of the same subject this session; otherwise the fields are
    // ignored and the call runs at the current mode.
    if crate::escalate::is_strictly_wider(effective, &requested) {
        let session_id = ctx.get_session_id().unwrap_or_default();
        if !crate::escalate::ledger::consume(&session_id, crate::escalate::ledger::Kind::Command) {
            return Ok(ResolvedCall {
                mode: effective,
                escalated: false,
                ignored_escalation: true,
            });
        }
    }

    let req = Request {
        requested_mode: requested,
        justification,
        effective_mode: effective,
        subject: "command".into(),
        summary: summary.to_string(),
    };
    let mode = crate::escalate::approve(&req, &ui_for(ctx, &req))?;
    Ok(ResolvedCall { mode, escalated: mode != effective, ignored_escalation: false })
}

/// The approval channel for one call, in priority order:
///
/// 1. this session has a UI → the host dialog (interactive sessions are
///    unchanged — the dialog wins);
/// 2. this session is a delegated child (`PIG_PARENT_SESSION` is set) → the
///    ask rides the parent link and blocks on the parent's answer
///    (DELEGATED-WORKSPACES §B);
/// 3. otherwise → the headless stub, which fails closed.
fn ui_for(ctx: &Context, req: &Request) -> Ui {
    if ctx.has_ui() {
        return dialog_ui(ctx.clone());
    }
    match crate::link::parent_session() {
        Some(parent) => relay_ui(ctx, &parent, req),
        None => Ui::headless(),
    }
}

/// The child side of the approval channel: one `ask` frame over the
/// parent's AF_UNIX socket, blocked on until the parent decides (or the
/// deadline hits — any transport problem is an error, and `approve` turns
/// errors into "nothing was executed").
fn relay_ui(ctx: &Context, parent: &str, req: &Request) -> Ui {
    let base = crate::link::Ask {
        uuid: new_ask_id(),
        mode: req.requested_mode.clone(),
        summary: truncate_runes(&req.summary, 500),
        justification: req.justification.clone(),
        // The dialog title `approve` builds: the parent renders it verbatim
        // so the wake message reads like the local dialog would.
        title: String::new(),
        child_session: ctx.get_session_id().unwrap_or_default(),
        child_pid: std::process::id(),
        started_at_ms: now_millis(),
    };
    let parent = parent.to_string();
    Ui {
        // `has_ui` here means "an approval channel exists": the parent
        // session's user is asked through the parent's own dialog.
        has_ui: true,
        ask: Box::new(
            move |title: &str, _options: &[&str], _prompt: Option<&DenialReasonPrompt>| {
                let mut ask = base.clone();
                ask.title = title.to_string();
                match crate::link::client::ask(&parent, &ask) {
                    Ok(out) => Ok(verdict_decision(&out)),
                    Err(e) => Err(crate::link::channel_unreachable(
                        &ask.mode,
                        &parent,
                        &e,
                    )),
                }
            },
        ),
    }
}

/// Map the parent's reply onto the escalation ladder's decision
/// vocabulary: allow → "Allow once", deny → "Deny" + the user's reason,
/// cancel → the empty choice `approve` reports as "was cancelled".
/// Shared with the link tests so both ends agree on the mapping.
pub fn verdict_decision(out: &crate::link::client::AskOutcome) -> Decision {
    match out.decision.as_str() {
        "allow" => Decision { choice: "Allow once".to_string(), reason: String::new() },
        "deny" => Decision { choice: "Deny".to_string(), reason: out.reason.clone() },
        _ => Decision::default(), // cancelled: nothing approved
    }
}

/// A child's ask id: process-unique and short enough to quote back in the
/// parent's dialog (`ask-<pid>-<32-bit random>`).
fn new_ask_id() -> String {
    let mut b = [0u8; 4];
    let rand = if getrandom::fill(&mut b).is_ok() {
        u32::from_le_bytes(b)
    } else {
        now_millis() as u32
    };
    format!("ask-{:x}-{:08x}", std::process::id(), rand)
}

fn now_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn truncate_runes(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        s.chars().take(n).collect()
    }
}

/// Adapt the SDK dialog surface to the escalation channel: select, then an
/// optional reason input after Deny (two-step serialised on one chain — the
/// host has a single dialog slot).
fn dialog_ui(ctx: Context) -> Ui {
    Ui {
        has_ui: ctx.has_ui(),
        ask: Box::new(move |title: &str, _options: &[&str], _prompt: Option<&DenialReasonPrompt>| {
            dialog_decide(&ctx, title)
        }),
    }
}

/// One interactive approval decision in THIS session: the Deny-first
/// select, then Deny's optional reason input. Shared by the local dialog
/// and the parent side of the link, so a relayed ask is asked exactly like
/// one that originated here. `Decision::default()` (empty choice) =
/// cancelled / no answer.
pub fn dialog_decide(ctx: &Context, title: &str) -> Result<Decision, String> {
    let (answer, ok) = ctx
        .select(title, &crate::escalate::ESCALATION_OPTIONS)
        .map_err(|e| e.to_string())?;
    // The client answers with any JSON value; only a string is a choice,
    // and a cancelled dialog answers null.
    let choice = answer.as_str().unwrap_or("").to_string();
    if !ok || choice.is_empty() {
        return Ok(Decision::default()); // cancelled
    }
    if choice == "Deny" {
        let prompt = &crate::escalate::DENIAL_REASON_PROMPT;
        match ctx.input(prompt.title, prompt.placeholder) {
            Ok((reason_answer, true)) => {
                let reason = reason_answer.as_str().unwrap_or("").to_string();
                return Ok(Decision { choice, reason });
            }
            // reason-input trouble never changes the denial semantics
            _ => return Ok(Decision { choice, reason: String::new() }),
        }
    }
    Ok(Decision { choice, reason: String::new() })
}

/// Drop placeholder STRINGS ("null" / blank) from the escalation fields
/// before schema validation (the reference's `prepareArguments` hook:
/// strict-schema providers mark the optional fields required and models fill
/// them with the literal "null", which would otherwise hard-fail validation
/// on the enum).
pub fn strip_escalation_placeholders(params: Value) -> Result<Value, String> {
    let mut map = match params {
        Value::Object(m) => m,
        other => return Ok(other),
    };
    let mut did_copy = false;
    for key in ["sandbox_permissions", "justification"] {
        let placeholder = match map.get(key) {
            Some(Value::String(s)) => {
                let t = s.trim();
                t.is_empty() || t.eq_ignore_ascii_case("null")
            }
            _ => false,
        };
        if placeholder && !did_copy {
            did_copy = true;
        }
        if placeholder {
            map.remove(key);
        }
    }
    let _ = did_copy;
    Ok(Value::Object(map))
}

/// Post-call feedback the model needs: approval covers one call; ignored
/// fields were dropped by the denial gate.
pub fn escalation_notes(rc: &ResolvedCall) -> String {
    if rc.ignored_escalation {
        crate::escalate::ignored_marker(rc.mode)
    } else if rc.escalated {
        crate::escalate::applied_marker(rc.mode)
    } else {
        String::new()
    }
}

/// Convenience used by the tools: install this call's notifier (Go
/// `SetNotifier` on every tool call — the newest session drives
/// notifications).
pub fn install_notifier(ctx: &Context) -> Arc<dyn crate::bg::SdkPort> {
    let port = port_for(ctx);
    Registry::shared().set_notifier(port.clone());
    port
}

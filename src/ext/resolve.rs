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

/// The process-cached sandbox config for this host.
pub fn config_for(ctx: &Context) -> config::Config {
    config::get(&config_home(ctx))
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

    let mode = crate::escalate::approve(
        &Request {
            requested_mode: requested,
            justification,
            effective_mode: effective,
            subject: "command".into(),
            summary: summary.to_string(),
        },
        &ui_for(ctx),
    )?;
    Ok(ResolvedCall { mode, escalated: mode != effective, ignored_escalation: false })
}

/// Adapt the SDK dialog surface to the escalation channel: select, then an
/// optional reason input after Deny (two-step serialised on one chain — the
/// host has a single dialog slot).
fn ui_for(ctx: &Context) -> Ui {
    let ctx = ctx.clone();
    Ui {
        has_ui: ctx.has_ui(),
        ask: Box::new(
            move |title: &str, options: &[&str], reason_prompt: Option<&DenialReasonPrompt>| {
                let (answer, ok) = ctx.select(title, options).map_err(|e| e.to_string())?;
                // The client answers with any JSON value; only a string is a
                // choice, and a cancelled dialog answers null.
                let choice = answer.as_str().unwrap_or("").to_string();
                if !ok || choice.is_empty() {
                    return Ok(Decision::default()); // cancelled
                }
                if choice == "Deny" {
                    if let Some(prompt) = reason_prompt {
                        match ctx.input(prompt.title, prompt.placeholder) {
                            Ok((reason_answer, true)) => {
                                let reason = reason_answer.as_str().unwrap_or("").to_string();
                                return Ok(Decision { choice, reason });
                            }
                            // reason-input trouble never changes the denial
                            // semantics
                            _ => return Ok(Decision { choice, reason: String::new() }),
                        }
                    }
                }
                Ok(Decision { choice, reason: String::new() })
            },
        ),
    }
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

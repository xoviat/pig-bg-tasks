//! Port of `internal/escalation` — the mode ladder, denial-first gating
//! vocabulary, approval dialogue, and the model-visible markers (byte-stable
//! wording matters — the model keys off them). Parity with the reference's
//! `src/escalation.ts`.
//!
//! This build is bash-only (write/edit fencing is owned by a separate
//! permission-system extension), so the subject vocabulary is just "command".
//! `internal/ledger` ports alongside in [`ledger`].

pub mod ledger;

use policy::Mode;

/// Strictly wider escalation targets per effective mode. `read-only` is the
/// floor and never an escalation target.
fn wider_modes(effective: Mode) -> &'static [Mode] {
    match effective {
        Mode::Readonly => &[Mode::WorkspaceWrite, Mode::DangerFullAccess],
        Mode::WorkspaceWrite => &[Mode::DangerFullAccess],
        Mode::DangerFullAccess => &[],
    }
}

/// Whether `requested` is a strictly wider mode than `effective`.
/// Same-table check for the denial gate and approval.
pub fn is_strictly_wider(effective: Mode, requested: &str) -> bool {
    wider_modes(effective).iter().any(|m| m.as_str() == requested)
}

/// The approval select list. Deny comes first: the host dialog rests on the
/// first option, so a stray Enter must deny.
pub const ESCALATION_OPTIONS: [&str; 2] = ["Deny", "Allow once"];

/// Optional second-step input after Deny.
#[derive(Debug, Clone)]
pub struct DenialReasonPrompt {
    pub title: &'static str,
    pub placeholder: &'static str,
}

/// Reference copy.
pub const DENIAL_REASON_PROMPT: DenialReasonPrompt = DenialReasonPrompt {
    title: "Why deny? (optional — the model will see it)",
    placeholder: "e.g. never touch files outside the workspace",
};

const MALFORMED_ESCALATION: &str =
    "invalid escalation: this call was rejected before execution (nothing ran).";
const ESCALATION_FIX: &str = "Fix: to run without escalation, omit BOTH fields or send JSON null for BOTH; to escalate, send sandbox_permissions (\"workspace-write\" | \"danger-full-access\") with a one-sentence justification.";

/// Reject half-filled or empty escalation field pairs before any execution
/// (parity copy of `validateEscalationArgs`).
pub fn validate_args(
    sandbox_permissions: Option<&str>,
    justification: Option<&str>,
) -> Result<(), String> {
    if sandbox_permissions.is_some() && justification.is_none() {
        return Err(format!(
            "{MALFORMED_ESCALATION} Cause: sandbox_permissions was sent without justification. {ESCALATION_FIX}"
        ));
    }
    if justification.is_some() && sandbox_permissions.is_none() {
        return Err(format!(
            "{MALFORMED_ESCALATION} Cause: justification was sent without sandbox_permissions. {ESCALATION_FIX}"
        ));
    }
    if let Some(j) = justification {
        if j.trim().is_empty() {
            return Err(format!(
                "{MALFORMED_ESCALATION} Cause: justification was empty. {ESCALATION_FIX}"
            ));
        }
    }
    Ok(())
}

/// Treat null-ish placeholders (`"null"`, empty, whitespace) as "not
/// requested" instead of malformed input. JSON null / non-string values are
/// `None` here — the caller handles them as not-requested (Go's `any` type
/// check).
pub fn normalize_value(v: Option<&str>) -> (String, bool) {
    let Some(s) = v else {
        return (String::new(), false);
    };
    let t = s.trim();
    if t.is_empty() || t.eq_ignore_ascii_case("null") {
        return (String::new(), false);
    }
    (t.to_string(), true)
}

// --- model-visible markers (byte-stable) ---

/// Annotates a real sandbox denial in the tool output.
pub fn denial_marker(mode: Mode) -> String {
    format!("[sandbox: file access denied under {mode} mode]")
}

/// Appended at the denial decision point.
pub fn escalation_hint_marker() -> &'static str {
    "[sandbox: escalation available — writable here: the workspace + %TEMP%; retry this exact command once with sandbox_permissions (the narrowest wider mode that suffices) + justification; the approval prompt asks the user]"
}

/// Reminds the model an approval covered one call only.
pub fn applied_marker(mode: Mode) -> String {
    format!(
        "[sandbox: this call ran with a one-shot escalation to {:?}; the approval covered this call only — later calls are confined again]",
        mode.as_str()
    )
}

/// In-place feedback when the denial-first gate dropped the escalation fields.
pub fn ignored_marker(mode: Mode) -> String {
    format!(
        "[sandbox: escalation fields were ignored — no sandbox denial was recorded for this session, so this call ran under {:?} mode. Send escalation fields only when retrying a call that just returned a denial marker.]",
        mode.as_str()
    )
}

/// Collapse whitespace and truncate to 500 runes.
pub fn sanitize_denial_reason(raw: &str) -> String {
    let collapsed = raw.split_whitespace().collect::<Vec<_>>().join(" ");
    if collapsed.is_empty() {
        return String::new();
    }
    let count = collapsed.chars().count();
    if count > 500 {
        let head: String = collapsed.chars().take(500).collect();
        return format!("{head}…");
    }
    collapsed
}

/// One approval dialogue's settlement. `choice == ""` means cancelled / no
/// channel.
#[derive(Debug, Clone, Default)]
pub struct Decision {
    pub choice: String,
    pub reason: String,
}

/// The approval channel: hasUI + one ask (select → optional Deny reason).
pub struct Ui {
    pub has_ui: bool,
    pub ask: Box<dyn Fn(&str, &[&str], Option<&DenialReasonPrompt>) -> Result<Decision, String> + Send + Sync>,
}

impl Ui {
    pub fn headless() -> Self {
        Ui { has_ui: false, ask: Box::new(|_, _, _| Err("headless".to_string())) }
    }
}

/// One escalation request.
#[derive(Debug, Clone)]
pub struct Request {
    pub requested_mode: String,
    pub justification: String,
    pub effective_mode: Mode,
    pub subject: String,
    pub summary: String,
}

/// Resolve one escalation request before execution. Order is priority and
/// everything fails closed: same-mode no approval → strictly wider check →
/// hasUI check → ask (Deny → error with optional reason). The result applies
/// to THIS call only.
pub fn approve(req: &Request, ui: &Ui) -> Result<Mode, String> {
    if req.requested_mode == req.effective_mode.as_str() {
        return Ok(req.effective_mode);
    }
    if !is_strictly_wider(req.effective_mode, &req.requested_mode) {
        return Err(format!(
            "sandbox escalation to {:?} is not strictly wider than this call's current {:?} mode — nothing was executed. Run the call as-is, or escalate to \"danger-full-access\".",
            req.requested_mode, req.effective_mode.as_str()
        ));
    }
    if !ui.has_ui {
        return Err(format!(
            "sandbox escalation to {:?} requires approval, but no approval channel is available — nothing was executed. This happens in headless sessions: do the work inside the writable roots, or ask the user to run /sandbox {} in their main session and retry.",
            req.requested_mode, req.requested_mode
        ));
    }
    let mut summary = req.summary.clone();
    if summary.chars().count() > 200 {
        summary = summary.chars().take(200).collect::<String>() + "…";
    }
    let noun = subject_noun(&req.subject);
    let title = format!(
        "Sandbox escalation: allow this {} under {:?}?\n\nReason: {}\n{}: {}",
        req.subject, req.requested_mode, req.justification, noun, summary
    );
    let decision = (ui.ask)(&title, &ESCALATION_OPTIONS, Some(&DENIAL_REASON_PROMPT))?;
    if decision.choice.is_empty() {
        return Err(format!(
            "approval for escalating to {:?} was cancelled — nothing was executed",
            req.requested_mode
        ));
    }
    if decision.choice == "Deny" {
        let reason = sanitize_denial_reason(&decision.reason);
        let suffix = if reason.is_empty() {
            String::new()
        } else {
            format!(". The user's reason: {reason}")
        };
        return Err(format!(
            "the user rejected escalating this {} to {:?}; it stays denied, so stop and explain instead of working around it — do not retry with a different mode or a rewritten command{}",
            req.subject, req.requested_mode, suffix
        ));
    }
    // Reached only via a strictly-wider table entry, so the requested mode
    // is one of the two ladder targets (or equal, handled above).
    let mode = match req.requested_mode.as_str() {
        "read-only" => Mode::Readonly,
        "danger-full-access" => Mode::DangerFullAccess,
        _ => Mode::WorkspaceWrite,
    };
    Ok(mode)
}

fn subject_noun(subject: &str) -> &'static str {
    if subject == "operation" {
        "Path"
    } else {
        "Command"
    }
}

/// Title for Deny's optional reason input (shared with the direct channel).
pub fn denial_reason_title() -> &'static str {
    DENIAL_REASON_PROMPT.title
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ladder_table() {
        assert!(is_strictly_wider(Mode::Readonly, "workspace-write"));
        assert!(is_strictly_wider(Mode::Readonly, "danger-full-access"));
        assert!(!is_strictly_wider(Mode::Readonly, "read-only"));
        assert!(is_strictly_wider(Mode::WorkspaceWrite, "danger-full-access"));
        assert!(!is_strictly_wider(Mode::WorkspaceWrite, "read-only"));
        assert!(!is_strictly_wider(Mode::DangerFullAccess, "workspace-write"));
        assert!(!is_strictly_wider(Mode::DangerFullAccess, "danger-full-access"));
    }

    #[test]
    fn validate_args_pair_rules() {
        assert!(validate_args(None, None).is_ok());
        assert!(validate_args(Some("workspace-write"), Some("needed")).is_ok());
        let e = validate_args(Some("workspace-write"), None).unwrap_err();
        assert!(e.contains("sandbox_permissions was sent without justification"), "{e}");
        assert!(e.starts_with("invalid escalation: this call was rejected before execution"));
        let e = validate_args(None, Some("needed")).unwrap_err();
        assert!(e.contains("justification was sent without sandbox_permissions"), "{e}");
        let e = validate_args(Some("workspace-write"), Some("   ")).unwrap_err();
        assert!(e.contains("justification was empty"), "{e}");
    }

    #[test]
    fn normalize_null_ish() {
        assert_eq!(normalize_value(None), (String::new(), false));
        assert_eq!(normalize_value(Some("")), (String::new(), false));
        assert_eq!(normalize_value(Some("  ")), (String::new(), false));
        assert_eq!(normalize_value(Some("null")), (String::new(), false));
        assert_eq!(normalize_value(Some("NULL")), (String::new(), false));
        assert_eq!(normalize_value(Some(" workspace-write ")), ("workspace-write".into(), true));
    }

    #[test]
    fn markers_are_byte_stable() {
        assert_eq!(
            denial_marker(Mode::Readonly),
            "[sandbox: file access denied under read-only mode]"
        );
        assert_eq!(
            applied_marker(Mode::WorkspaceWrite),
            "[sandbox: this call ran with a one-shot escalation to \"workspace-write\"; the approval covered this call only — later calls are confined again]"
        );
        assert!(ignored_marker(Mode::WorkspaceWrite).contains("no sandbox denial was recorded for this session"));
        assert!(escalation_hint_marker().starts_with("[sandbox: escalation available"));
        assert_eq!(sanitize_denial_reason("  a \n b  "), "a b");
        assert_eq!(sanitize_denial_reason(""), "");
        let long: String = "x".repeat(600);
        let s = sanitize_denial_reason(&long);
        assert_eq!(s.chars().count(), 501);
        assert!(s.ends_with('…'));
    }

    fn req(effective: Mode, requested: &str) -> Request {
        Request {
            requested_mode: requested.to_string(),
            justification: "need it".into(),
            effective_mode: effective,
            subject: "command".into(),
            summary: "echo hi".into(),
        }
    }

    #[test]
    fn approve_same_mode_needs_no_dialogue() {
        let ui = Ui::headless();
        assert_eq!(
            approve(&req(Mode::WorkspaceWrite, "workspace-write"), &ui).unwrap(),
            Mode::WorkspaceWrite
        );
    }

    #[test]
    fn approve_fails_closed() {
        // not strictly wider
        let e = approve(&req(Mode::WorkspaceWrite, "read-only"), &Ui::headless()).unwrap_err();
        assert!(e.contains("is not strictly wider"), "{e}");
        // headless
        let e = approve(&req(Mode::Readonly, "workspace-write"), &Ui::headless()).unwrap_err();
        assert!(e.contains("no approval channel is available"), "{e}");
        assert!(e.contains("/sandbox workspace-write"), "{e}");
        // cancelled
        let ui = Ui { has_ui: true, ask: Box::new(|_, _, _| Ok(Decision::default())) };
        let e = approve(&req(Mode::Readonly, "workspace-write"), &ui).unwrap_err();
        assert!(e.contains("was cancelled"), "{e}");
        // deny without reason
        let ui = Ui {
            has_ui: true,
            ask: Box::new(|_, _, _| {
                Ok(Decision { choice: "Deny".into(), reason: String::new() })
            }),
        };
        let e = approve(&req(Mode::Readonly, "danger-full-access"), &ui).unwrap_err();
        assert!(e.contains("the user rejected escalating this command to \"danger-full-access\""), "{e}");
        assert!(e.contains("do not retry with a different mode"), "{e}");
        // deny with reason → appended
        let ui = Ui {
            has_ui: true,
            ask: Box::new(|_, _, _| {
                Ok(Decision { choice: "Deny".into(), reason: "  never\noutside ".into() })
            }),
        };
        let e = approve(&req(Mode::Readonly, "workspace-write"), &ui).unwrap_err();
        assert!(e.ends_with(". The user's reason: never outside"), "{e}");
        // allow → requested mode
        let ui = Ui {
            has_ui: true,
            ask: Box::new(|title, options, prompt| {
                assert!(title.starts_with("Sandbox escalation: allow this command under \"workspace-write\"?"));
                assert!(title.contains("Reason: need it"));
                assert!(title.contains("Command: echo hi"));
                assert_eq!(options, ["Deny", "Allow once"]);
                assert!(prompt.is_some());
                Ok(Decision { choice: "Allow once".into(), reason: String::new() })
            }),
        };
        assert_eq!(
            approve(&req(Mode::Readonly, "workspace-write"), &ui).unwrap(),
            Mode::WorkspaceWrite
        );
    }

    #[test]
    fn summary_truncates_at_200_runes() {
        let ui = Ui {
            has_ui: true,
            ask: Box::new(|title, _, _| {
                let line = title.lines().last().unwrap().to_string();
                assert!(line.chars().count() <= "Command: ".len() + 201, "{line}");
                Ok(Decision { choice: "Allow once".into(), reason: String::new() })
            }),
        };
        let mut r = req(Mode::Readonly, "workspace-write");
        r.summary = "y".repeat(500);
        approve(&r, &ui).unwrap();
    }
}

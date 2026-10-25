// Package escalation holds the mode ladder, denial-first gating vocabulary,
// approval dialogue, and the model-visible markers — parity with the
// reference's src/escalation.ts.
//
// This build is bash-only (write/edit fencing is owned by a separate
// permission-system extension), so the subject vocabulary is just "command".

package escalation

import (
	"errors"
	"fmt"
	"strings"

	"example.com/pig-bg-tasks/internal/policy"
)

// widerModes maps effective mode → strictly wider escalation targets.
// read-only is the floor and is never an escalation target.
var widerModes = map[policy.Mode][]policy.Mode{
	policy.ModeReadonly:       {policy.ModeWorkspaceWrite, policy.ModeDangerFullAccess},
	policy.ModeWorkspaceWrite: {policy.ModeDangerFullAccess},
}

// IsStrictlyWider reports whether requested is a strictly wider mode than
// effective. Same-table check for the denial gate and approval.
func IsStrictlyWider(effective policy.Mode, requested string) bool {
	for _, m := range widerModes[effective] {
		if string(m) == requested {
			return true
		}
	}
	return false
}

// EscalationOptions is the approval select list. Deny comes first: the host
// dialog rests on the first option, so a stray Enter must deny.
var EscalationOptions = []string{"Deny", "Allow once"}

// DenialReasonPrompt is the optional second-step input after Deny.
type DenialReasonPrompt struct {
	Title       string
	Placeholder string
}

// DENIAL_REASON_PROMPT mirrors the reference copy.
var DENIAL_REASON_PROMPT = DenialReasonPrompt{
	Title:       "Why deny? (optional — the model will see it)",
	Placeholder: "e.g. never touch files outside the workspace",
}

const malformedEscalation = "invalid escalation: this call was rejected before execution (nothing ran)."
const escalationFix = `Fix: to run without escalation, omit BOTH fields or send JSON null for BOTH; to escalate, send sandbox_permissions ("workspace-write" | "danger-full-access") with a one-sentence justification.`

// ValidateArgs rejects half-filled or empty escalation field pairs before any
// execution (parity copy of validateEscalationArgs).
func ValidateArgs(sandboxPermissions, justification *string) error {
	if sandboxPermissions != nil && justification == nil {
		return errors.New(malformedEscalation + " Cause: sandbox_permissions was sent without justification. " + escalationFix)
	}
	if justification != nil && sandboxPermissions == nil {
		return errors.New(malformedEscalation + " Cause: justification was sent without sandbox_permissions. " + escalationFix)
	}
	if justification != nil && strings.TrimSpace(*justification) == "" {
		return errors.New(malformedEscalation + " Cause: justification was empty. " + escalationFix)
	}
	return nil
}

// NormalizeValue treats null-ish placeholders ("null", "", whitespace) as
// "not requested" instead of malformed input.
func NormalizeValue(v any) (string, bool) {
	s, ok := v.(string)
	if !ok {
		return "", false // nil / JSON null / non-string → not requested (or handled by caller)
	}
	t := strings.TrimSpace(s)
	if t == "" || strings.EqualFold(t, "null") {
		return "", false
	}
	return t, true
}

// Model-visible markers (byte-stable wording matters — the model keys off them).

// DenialMarker annotates a real sandbox denial in the tool output.
func DenialMarker(mode policy.Mode) string {
	return fmt.Sprintf("[sandbox: file access denied under %s mode]", mode)
}

// EscalationHintMarker is appended at the denial decision point.
func EscalationHintMarker() string {
	return `[sandbox: escalation available — writable here: the workspace + %TEMP%; retry this exact command once with sandbox_permissions (the narrowest wider mode that suffices) + justification; the approval prompt asks the user]`
}

// AppliedMarker reminds the model an approval covered one call only.
func AppliedMarker(mode policy.Mode) string {
	return fmt.Sprintf(`[sandbox: this call ran with a one-shot escalation to %q; the approval covered this call only — later calls are confined again]`, mode)
}

// IgnoredMarker gives in-place feedback when the denial-first gate dropped the
// escalation fields.
func IgnoredMarker(mode policy.Mode) string {
	return fmt.Sprintf(`[sandbox: escalation fields were ignored — no sandbox denial was recorded for this session, so this call ran under %q mode. Send escalation fields only when retrying a call that just returned a denial marker.]`, mode)
}

// SanitizeDenialReason collapses whitespace and truncates to 500 runes.
func SanitizeDenialReason(raw string) string {
	collapsed := strings.Join(strings.Fields(raw), " ")
	if collapsed == "" {
		return ""
	}
	r := []rune(collapsed)
	if len(r) > 500 {
		return string(r[:500]) + "…"
	}
	return collapsed
}

// Decision is one approval dialogue's settlement. Choice=="" means
// cancelled / no channel.
type Decision struct {
	Choice string
	Reason string
}

// UI is the approval channel: hasUI + one ask (select → optional Deny reason).
type UI struct {
	HasUI bool
	Ask   func(title string, options []string, reasonPrompt *DenialReasonPrompt) (Decision, error)
}

// Request is one escalation request.
type Request struct {
	RequestedMode string
	Justification string
	EffectiveMode policy.Mode
	Subject       string
	Summary       string
}

// Approve resolves one escalation request before execution. Order is
// priority and everything fails closed: same-mode no approval → strictly
// wider check → hasUI check → ask (Deny → error with optional reason).
// The result applies to THIS call only.
func Approve(req Request, ui UI) (policy.Mode, error) {
	if req.RequestedMode == string(req.EffectiveMode) {
		return req.EffectiveMode, nil
	}
	if !IsStrictlyWider(req.EffectiveMode, req.RequestedMode) {
		return "", fmt.Errorf(`sandbox escalation to %q is not strictly wider than this call's current %q mode — nothing was executed. Run the call as-is, or escalate to "danger-full-access".`, req.RequestedMode, req.EffectiveMode)
	}
	if !ui.HasUI {
		return "", fmt.Errorf(`sandbox escalation to %q requires approval, but no approval channel is available — nothing was executed. This happens in headless sessions: do the work inside the writable roots, or ask the user to run /sandbox %s in their main session and retry.`, req.RequestedMode, req.RequestedMode)
	}
	summary := req.Summary
	if len([]rune(summary)) > 200 {
		summary = string([]rune(summary)[:200]) + "…"
	}
	title := fmt.Sprintf("Sandbox escalation: allow this %s under %q?\n\nReason: %s\n%s: %s",
		req.Subject, req.RequestedMode, req.Justification, subjectNoun(req.Subject), summary)
	decision, err := ui.Ask(title, EscalationOptions, &DENIAL_REASON_PROMPT)
	if err != nil {
		return "", err
	}
	if decision.Choice == "" {
		return "", fmt.Errorf(`approval for escalating to %q was cancelled — nothing was executed`, req.RequestedMode)
	}
	if decision.Choice == "Deny" {
		suffix := ""
		if r := SanitizeDenialReason(decision.Reason); r != "" {
			suffix = ". The user's reason: " + r
		}
		return "", fmt.Errorf(`the user rejected escalating this %s to %q; it stays denied, so stop and explain instead of working around it — do not retry with a different mode or a rewritten command%s`, req.Subject, req.RequestedMode, suffix)
	}
	return policy.Mode(req.RequestedMode), nil
}

func subjectNoun(subject string) string {
	if subject == "operation" {
		return "Path"
	}
	return "Command"
}

// SanitizedStatusLine renders Deny's optional reason input title (shared with
// the broker-less direct channel).
func DenialReasonTitle() string { return DENIAL_REASON_PROMPT.Title }

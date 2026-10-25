// Package tools composes the single `bash` tool (bg layer + sandbox layer,
// plan Part 3.1) plus the task tools and the /sandbox command surface.
package tools

import (
	"fmt"
	"os"
	"strings"
	"sync"

	"example.com/pig-bg-tasks/internal/config"
	"example.com/pig-bg-tasks/internal/escalation"
	"example.com/pig-bg-tasks/internal/ledger"
	"example.com/pig-bg-tasks/internal/permission"
	"example.com/pig-bg-tasks/internal/policy"
	sdk "github.com/MichaelKinsy/PiG/extensions/sdk"
)

// configHome caches ctx.ConfigHome() (one host roundtrip per process).
var (
	configHomeOnce sync.Once
	configHomeVal  string
	configHomeErr  error
)

func configHome(ctx sdk.Context) string {
	configHomeOnce.Do(func() {
		configHomeVal, configHomeErr = ctx.ConfigHome()
		if configHomeErr != nil || configHomeVal == "" {
			if h, err := os.UserHomeDir(); err == nil {
				configHomeVal = h // fallback; config.Get joins /agent/sandbox.json
			}
		}
	})
	return configHomeVal
}

// ConfigFor returns the process-cached sandbox config for this host.
func ConfigFor(ctx sdk.Context) config.Config { return config.Get(configHome(ctx)) }

// ConfigHome exposes the resolved config root (extension wiring uses it for
// the OB-dir name cache).
func ConfigHome() string { return configHomeVal }

// PinConfigHome sets the config root at session_start (before any tool call
// needs it). Persistent sandbox state (including the MSYS object-dir name
// cache) belongs to srt-win alone — its own HKCU\Software\srt-win — so
// nothing is wired here.
func PinConfigHome(home string) {
	configHomeOnce.Do(func() { configHomeVal = home })
	_ = config.Get(configHomeVal) // warm: load warnings surface at startup
}

// ResolvedCall is one call's effective mode + escalation bookkeeping.
type ResolvedCall struct {
	Mode              policy.Mode
	Escalated         bool // approved escalation applied to THIS call
	IgnoredEscalation bool // denial-first gate dropped the fields
}

// normalizeEscalationValue: null / "null" / blank = "not requested" (never
// malformed — a MALFORMED error here would read to the model as a sandbox
// denial and trigger a max-escalation spiral, reference rationale).
func normalizeEscalationValue(v any) (string, bool) {
	if v == nil {
		return "", false
	}
	if s, ok := v.(string); ok {
		t := strings.TrimSpace(s)
		if t == "" || strings.EqualFold(t, "null") {
			return "", false
		}
		return t, true
	}
	return fmt.Sprintf("%v", v), true
}

// ResolveCall implements denial-first escalation for bash (subject=command):
// placeholder normalize → pair validation → effective mode (/sandbox
// override > config default) → denial-ledger gate → approval dialogue.
// Nothing runs when it returns an error (fail-closed, nothing executed).
func ResolveCall(ctx sdk.Context, params map[string]any, cfg config.Config, summary string) (ResolvedCall, error) {
	requested, reqPresent := normalizeEscalationValue(params["sandbox_permissions"])
	justification, justPresent := normalizeEscalationValue(params["justification"])

	var rp, jp *string
	if reqPresent {
		rp = &requested
	}
	if justPresent {
		jp = &justification
	}
	if err := escalation.ValidateArgs(rp, jp); err != nil {
		return ResolvedCall{}, err // rejected BEFORE execution (wording says so)
	}

	effective := policy.ResolveEffectiveMode(permission.Get(), cfg.Mode)
	if !reqPresent {
		return ResolvedCall{Mode: effective}, nil
	}

	// Denial-first hard gate: a strictly wider request needs an unconsumed
	// real denial of the same subject this session; otherwise the fields are
	// ignored and the call runs at the current mode.
	if escalation.IsStrictlyWider(effective, requested) {
		sessionID, _ := ctx.GetSessionID()
		if !ledger.Consume(sessionID, ledger.KindCommand) {
			return ResolvedCall{Mode: effective, IgnoredEscalation: true}, nil
		}
	}

	mode, err := escalation.Approve(escalation.Request{
		RequestedMode: requested,
		Justification: justification,
		EffectiveMode: effective,
		Subject:       "command",
		Summary:       summary,
	}, uiFor(ctx))
	if err != nil {
		return ResolvedCall{}, err
	}
	return ResolvedCall{Mode: mode, Escalated: mode != effective}, nil
}

// uiFor adapts the sdk dialog surface to the escalation channel: select, then
// an optional reason input after Deny (two-step serialised on one chain —
// the host has a single dialog slot).
func uiFor(ctx sdk.Context) escalation.UI {
	return escalation.UI{
		HasUI: ctx.HasUI(),
		Ask: func(title string, options []string, reasonPrompt *escalation.DenialReasonPrompt) (escalation.Decision, error) {
			answer, ok, err := ctx.Select(title, options)
			if err != nil {
				return escalation.Decision{}, err
			}
			// the client answers with any JSON value; only a string is a choice,
			// and a cancelled dialog answers nil where it used to be "".
			choice, _ := answer.(string)
			if !ok || choice == "" {
				return escalation.Decision{}, nil // cancelled
			}
			if choice == "Deny" && reasonPrompt != nil {
				reasonAnswer, rok, rerr := ctx.Input(reasonPrompt.Title, reasonPrompt.Placeholder)
				if rerr == nil && rok {
					reason, _ := reasonAnswer.(string)
					return escalation.Decision{Choice: choice, Reason: reason}, nil
				}
				// reason-input trouble never changes the denial semantics
				return escalation.Decision{Choice: choice}, nil
			}
			return escalation.Decision{Choice: choice}, nil
		},
	}
}

// StripEscalationPlaceholders drops placeholder STRINGS ("null" / blank) from
// the escalation fields before schema validation (the reference's
// prepareArguments hook: strict-schema providers mark the optional fields
// required and models fill them with the literal "null", which would
// otherwise hard-fail validation on the enum).
func StripEscalationPlaceholders(params map[string]any) (map[string]any, error) {
	out := params
	didCopy := false
	for _, key := range []string{"sandbox_permissions", "justification"} {
		v, present := out[key]
		if !present {
			continue
		}
		if s, isStr := v.(string); isStr {
			t := strings.TrimSpace(s)
			if t == "" || strings.EqualFold(t, "null") {
				if !didCopy {
					out = make(map[string]any, len(params))
					for k, vv := range params {
						out[k] = vv
					}
					didCopy = true
				}
				delete(out, key)
			}
		}
	}
	return out, nil
}

// escalationNotes is the post-call feedback the model needs: approval covers
// one call; ignored fields were dropped by the denial gate.
func escalationNotes(rc ResolvedCall) string {
	switch {
	case rc.IgnoredEscalation:
		return escalation.IgnoredMarker(rc.Mode)
	case rc.Escalated:
		return escalation.AppliedMarker(rc.Mode)
	default:
		return ""
	}
}

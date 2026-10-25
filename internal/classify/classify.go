// Package classify decides whether a confined command's output shows a
// SANDBOX RUNNER FAILURE (the command never ran) or a real SANDBOX DENIAL
// (the command ran and a file effect was refused) — parity with the
// reference's src/confine.ts classification, Windows-only signatures.
//
// English-only by design: enforcement is language-independent, but the marker
// (and therefore denial-first escalation) is not. A missing marker is a
// classification gap, not a confinement failure.

package classify

import "strings"

// Rule describes one runner-failure pattern: gate on allowed exit codes
// (nil = any non-zero), drop informational lines, then substring-match the
// fatal signatures per remaining line.
type Rule struct {
	AllowedExitCodes   []int
	FatalSignatures    []string
	InformationalLines []string
}

// Windows-acl runner failures: cygwin/msys init dies before the command runs.
// These strings only ever appear in runtime-init fatals, not in ordinary
// command output (documented divergence from the reference's prefixed
// "windows-acl-run:" signature — our runner is in-process, no prefix exists).
var WindowsRules = []Rule{{
	FatalSignatures: []string{
		"*** fatal error -",
		"couldn't create signal pipe",
		"ntcreatedirectoryobject(",
		"createfilemapping",
		"entrying the cli failed",
		"starting the clr failed",
	},
}}

// CustomRunnerSignatures cover an operator-supplied runnerCommand (parity
// field; ignored by this build's Windows-only runner selection).
var CustomRunnerSignatures = []string{"read-only file system", "permission denied"}

// RunnerFailure returns the fatal stderr line when the runner died before the
// command executed. Exit 0 or signal-death (nil) is never a runner failure.
func RunnerFailure(exitCode *int, stderr string, rules []Rule) (string, bool) {
	if exitCode == nil || *exitCode == 0 {
		return "", false
	}
	for _, rule := range rules {
		if len(rule.AllowedExitCodes) > 0 && !containsInt(rule.AllowedExitCodes, *exitCode) {
			continue
		}
		informational := map[string]bool{}
		for _, line := range rule.InformationalLines {
			informational[strings.ToLower(strings.TrimSpace(line))] = true
		}
		for _, line := range strings.Split(stderr, "\n") {
			trimmed := strings.TrimSpace(line)
			if trimmed == "" {
				continue
			}
			if informational[strings.ToLower(trimmed)] {
				continue
			}
			lower := strings.ToLower(trimmed)
			for _, sig := range rule.FatalSignatures {
				if strings.Contains(lower, strings.ToLower(sig)) {
					return trimmed, true
				}
			}
		}
	}
	return "", false
}

// DenialSignatures are the Windows denial dialects (validated by spike):
// cmd's "Access is denied.", PowerShell/.NET "Access to the path …",
// MSYS/bash "Permission denied" / "Operation not permitted", plus the cygwin
// init wall that reads as a write denial.
var DenialSignatures = []string{
	"access is denied",
	"access to the path",
	"permission denied",
	"operation not permitted",
	"write-protected",
	"read-only file system",
}

// Denial reports a sandbox denial: non-zero exit + any dialect substring in
// the (merged stdout+stderr) output tail, case-insensitive.
func Denial(exitCode *int, output string, signatures []string) bool {
	if exitCode == nil || *exitCode == 0 {
		return false
	}
	lower := strings.ToLower(output)
	for _, sig := range signatures {
		if strings.Contains(lower, strings.ToLower(sig)) {
			return true
		}
	}
	return false
}

func containsInt(hay []int, needle int) bool {
	for _, v := range hay {
		if v == needle {
			return true
		}
	}
	return false
}

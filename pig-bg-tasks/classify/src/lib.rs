//! Port of `internal/classify` — verbatim signatures (plan §5): decides
//! whether a confined command's output shows a SANDBOX RUNNER FAILURE (the
//! command never ran) or a real SANDBOX DENIAL (the command ran and a file
//! effect was refused). Windows-only signatures; English-only by design —
//! a missing marker is a classification gap, not a confinement failure.

use std::sync::LazyLock;

/// One runner-failure pattern: gate on allowed exit codes (`None` = any
/// non-zero), drop informational lines, then substring-match the fatal
/// signatures per remaining line.
#[derive(Debug, Clone)]
pub struct Rule {
    pub allowed_exit_codes: Option<Vec<i32>>,
    pub fatal_signatures: Vec<String>,
    pub informational_lines: Vec<String>,
}

/// Windows-acl runner failures: cygwin/msys init dies before the command
/// runs. These strings only ever appear in runtime-init fatals, not in
/// ordinary command output (documented divergence from the reference's
/// prefixed `windows-acl-run:` signature — our runner is in-process).
pub static WINDOWS_RULES: LazyLock<Vec<Rule>> = LazyLock::new(|| {
    vec![Rule {
        allowed_exit_codes: None,
        fatal_signatures: [
            "*** fatal error -",
            "couldn't create signal pipe",
            "ntcreatedirectoryobject(",
            "createfilemapping",
            "entrying the cli failed",
            "starting the clr failed",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect(),
        informational_lines: Vec::new(),
    }]
});

/// Cover an operator-supplied `runnerCommand` (parity field; ignored by this
/// build's Windows-only runner selection).
pub static CUSTOM_RUNNER_SIGNATURES: &[&str] = &["read-only file system", "permission denied"];

/// Windows denial dialects (validated by spike): cmd's "Access is denied.",
/// PowerShell/.NET "Access to the path …", MSYS/bash "Permission denied" /
/// "Operation not permitted", plus the cygwin init wall that reads as a
/// write denial.
pub static DENIAL_SIGNATURES: &[&str] = &[
    "access is denied",
    "access to the path",
    "permission denied",
    "operation not permitted",
    "write-protected",
    "read-only file system",
];

/// The fatal stderr line when the runner died before the command executed.
/// Exit 0 or signal-death (`None`) is never a runner failure.
pub fn runner_failure(
    exit_code: Option<i32>,
    stderr: &str,
    rules: &[Rule],
) -> Option<String> {
    let code = exit_code?;
    if code == 0 {
        return None;
    }
    for rule in rules {
        if let Some(allowed) = &rule.allowed_exit_codes {
            if !allowed.contains(&code) {
                continue;
            }
        }
        let informational: std::collections::HashSet<String> = rule
            .informational_lines
            .iter()
            .map(|l| l.trim().to_lowercase())
            .collect();
        for line in stderr.split('\n') {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            if informational.contains(&trimmed.to_lowercase()) {
                continue;
            }
            let lower = trimmed.to_lowercase();
            if rule
                .fatal_signatures
                .iter()
                .any(|sig| lower.contains(&sig.to_lowercase()))
            {
                return Some(trimmed.to_string());
            }
        }
    }
    None
}

/// A sandbox denial: non-zero exit + any dialect substring in the (merged
/// stdout+stderr) output tail, case-insensitive.
pub fn denial(exit_code: Option<i32>, output: &str, signatures: &[&str]) -> bool {
    let Some(code) = exit_code else { return false };
    if code == 0 {
        return false;
    }
    let lower = output.to_lowercase();
    signatures.iter().any(|sig| lower.contains(&sig.to_lowercase()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nz(code: i32) -> Option<i32> {
        Some(code)
    }

    #[test]
    fn runner_failure_picks_fatal_line() {
        let stderr = "info: loading\n*** fatal error - couldn't create signal pipe\nafter";
        let got = runner_failure(nz(1), stderr, &WINDOWS_RULES);
        assert_eq!(got.as_deref(), Some("*** fatal error - couldn't create signal pipe"));
        // case-insensitive signature
        assert!(runner_failure(nz(1), "Cygwin: Couldn't Create Signal Pipe", &WINDOWS_RULES).is_some());
        // msys object namespace wall
        assert!(runner_failure(
            nz(1),
            "NtCreateDirectoryObject() failed",
            &WINDOWS_RULES
        )
        .is_some());
    }

    #[test]
    fn runner_failure_never_on_zero_or_signal() {
        assert!(runner_failure(nz(0), "*** fatal error -", &WINDOWS_RULES).is_none());
        assert!(runner_failure(None, "*** fatal error -", &WINDOWS_RULES).is_none());
        assert!(runner_failure(nz(1), "all fine", &WINDOWS_RULES).is_none());
    }

    #[test]
    fn allowed_exit_gate_and_informational_drops() {
        let rules = vec![Rule {
            allowed_exit_codes: Some(vec![3]),
            fatal_signatures: vec!["fatal".into()],
            informational_lines: vec!["Fatal (info)".into()],
        }];
        assert!(runner_failure(nz(2), "fatal here", &rules).is_none(), "exit gate");
        assert!(runner_failure(nz(3), "fatal here", &rules).is_some());
        assert!(
            runner_failure(nz(3), "fatal (info)", &rules).is_none(),
            "informational line dropped"
        );
    }

    #[test]
    fn denial_dialects() {
        assert!(denial(nz(1), "cat: x: Access is denied.", DENIAL_SIGNATURES));
        assert!(denial(nz(1), "Access to the path 'C:\\x' is denied.", DENIAL_SIGNATURES));
        assert!(denial(nz(1), "cp: PERMISSION DENIED", DENIAL_SIGNATURES));
        assert!(denial(nz(1), "Operation not permitted", DENIAL_SIGNATURES));
        // non-zero is required
        assert!(!denial(nz(0), "Access is denied.", DENIAL_SIGNATURES));
        assert!(!denial(None, "Access is denied.", DENIAL_SIGNATURES));
        assert!(!denial(nz(1), "everything fine", DENIAL_SIGNATURES));
    }
}

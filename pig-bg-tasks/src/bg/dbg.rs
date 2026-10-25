//! Port of `internal/dbg` — the agent-facing debug trace: one JSON line per
//! bash call appended next to the task logs inside the granted `%TEMP%` tree
//! so an agent can read it while diagnosing an installed session.
//!
//! Parity: never fails the caller (debug output must not be able to break a
//! bash call); `ts` is auto-filled as RFC3339Nano UTC when absent.

use std::fs::OpenOptions;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{Value, json};

use crate::bg::glock;

static MU: Mutex<()> = Mutex::new(());

/// Trace file location (`%TEMP%\pi-bg-tasks\bash-calls.jsonl`).
pub fn path() -> PathBuf {
    std::env::temp_dir().join("pi-bg-tasks").join("bash-calls.jsonl")
}

/// Append one record. Never panics or fails the caller.
pub fn trace(mut rec: Value) {
    if !rec.is_object() {
        return;
    }
    if rec.get("ts").is_none() {
        rec["ts"] = json!(now_rfc3339());
    }
    let Ok(line) = serde_json::to_string(&rec) else {
        return;
    };
    let _g = glock(&MU);
    let p = path();
    if let Some(dir) = p.parent() {
        if std::fs::create_dir_all(dir).is_err() {
            return;
        }
    }
    if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(&p) {
        use std::io::Write;
        let _ = writeln!(f, "{line}");
    }
}

/// Last `n` records, oldest first; empty when absent (Go returns nil).
pub fn tail(n: usize) -> Vec<Value> {
    if n == 0 {
        return Vec::new();
    }
    let Ok(raw) = std::fs::read_to_string(path()) else {
        return Vec::new();
    };
    let lines: Vec<&str> = raw.lines().filter(|l| !l.trim().is_empty()).collect();
    let start = lines.len().saturating_sub(n);
    lines[start..]
        .iter()
        .filter_map(|l| serde_json::from_str::<Value>(l).ok())
        .collect()
}

/// RFC3339 with nanoseconds, UTC — Go `time.Now().UTC().Format(time.RFC3339Nano)`.
pub fn now_rfc3339() -> String {
    rfc3339_at(SystemTime::now(), true)
}

/// RFC3339, UTC — `nanos=false` matches Go `Format(time.RFC3339)` (debug
/// line, file mtimes); `nanos=true` matches `RFC3339Nano` (trace `ts`).
pub fn rfc3339_at(t: SystemTime, nanos: bool) -> String {
    let d = t.duration_since(UNIX_EPOCH).unwrap_or_default();
    let secs = d.as_secs() as i64;
    let nanos_n = d.subsec_nanos();
    let days = secs.div_euclid(86_400);
    let sod = secs.rem_euclid(86_400);
    let (y, m, dd) = civil_from_days(days);
    if nanos {
        format!(
            "{y:04}-{m:02}-{dd:02}T{:02}:{:02}:{:02}.{nanos_n:09}Z",
            sod / 3600,
            (sod % 3600) / 60,
            sod % 60
        )
    } else {
        format!(
            "{y:04}-{m:02}-{dd:02}T{:02}:{:02}:{:02}Z",
            sod / 3600,
            (sod % 3600) / 60,
            sod % 60
        )
    }
}

/// Days-since-epoch → civil date (Howard Hinnant's `civil_from_days`).
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc3339_shape() {
        let s = now_rfc3339();
        // 2026-ish date, exact shape: YYYY-MM-DDTHH:MM:SS.nnnnnnnnnZ
        assert_eq!(s.len(), 30, "{s}");
        assert_eq!(&s[4..5], "-");
        assert_eq!(&s[10..11], "T");
        assert_eq!(&s[19..20], ".");
        assert!(s.ends_with('Z'));
        assert!(s.starts_with("20"), "{s}");
    }

    #[test]
    fn trace_and_tail_roundtrip() {
        let p = path();
        let _ = std::fs::remove_file(&p);
        trace(json!({"phase": "unit-test", "n": 1}));
        trace(json!({"phase": "unit-test", "n": 2}));
        let t = tail(10);
        assert!(t.len() >= 2, "tail got {} records", t.len());
        assert!(t.iter().any(|r| r["n"] == 2));
        assert!(t.iter().all(|r| r["ts"].is_string()));
        // tail cap keeps only the newest n
        let t1 = tail(1);
        assert_eq!(t1.len(), 1);
        assert_eq!(t1[0]["n"], 2);
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn trace_never_fails_on_garbage() {
        trace(json!("not-an-object"));
        trace(json!({"bad": Value::Null}));
    }
}

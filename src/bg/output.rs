//! Port of `internal/bg/output.go` — bounded tails (O(maxBytes), not
//! O(fileSize)), ANSI/control stripping so job output cannot inject escapes
//! into the TUI or the model context, and a live-tail poller that feeds the
//! tool's update callback.
//!
//! `strip_ansi` is a hand-rolled byte scanner instead of Go's three regexes
//! — same language (CSI, OSC-to-BEL/ST, then C0/C1 controls keeping
//! `\t \n \r`), no regex dependency.

use std::io::{Read, Seek, SeekFrom};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

const NO_OUTPUT: &str = "(no output yet)";

/// Read only the last `max_bytes` of a file.
pub fn read_bounded_tail(path: &str, max_bytes: i64) -> String {
    let Ok(mut f) = std::fs::File::open(Path::new(path)) else {
        return NO_OUTPUT.to_string();
    };
    let Ok(meta) = f.metadata() else {
        return NO_OUTPUT.to_string();
    };
    let size = meta.len() as i64;
    if size == 0 {
        return NO_OUTPUT.to_string();
    }
    let (max_bytes, offset, truncated) = if size > max_bytes {
        (max_bytes, size - max_bytes, true)
    } else {
        (size, 0, false)
    };
    let mut buf = vec![0u8; max_bytes.max(0) as usize];
    if f.seek(SeekFrom::Start(offset.max(0) as u64)).is_err() {
        return NO_OUTPUT.to_string();
    }
    let mut read = 0usize;
    while read < buf.len() {
        match f.read(&mut buf[read..]) {
            Ok(0) => break,
            Ok(n) => read += n,
            Err(_) => break,
        }
    }
    if read == 0 {
        return NO_OUTPUT.to_string();
    }
    let body = String::from_utf8_lossy(&buf[..read]).into_owned();
    if truncated {
        format!("...[truncated, showing last {max_bytes} chars]\n{body}")
    } else {
        body
    }
}

/// Remove ANSI CSI/OSC sequences and C0/C1 control chars (newlines, tabs
/// and CR are kept for the caller).
pub fn strip_ansi(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < b.len() {
        let c = b[i];
        if c == 0x1b {
            // CSI: ESC [ params intermediates final
            if i + 1 < b.len() && b[i + 1] == b'[' {
                i += 2;
                while i < b.len() {
                    let n = b[i];
                    i += 1;
                    if (0x40..=0x7e).contains(&n) {
                        break;
                    }
                }
                continue;
            }
            // OSC: ESC ] ... BEL | ESC \
            if i + 1 < b.len() && b[i + 1] == b']' {
                i += 2;
                while i < b.len() {
                    if b[i] == 0x07 {
                        i += 1;
                        break;
                    }
                    if b[i] == 0x1b && i + 1 < b.len() && b[i + 1] == b'\\' {
                        i += 2;
                        break;
                    }
                    i += 1;
                }
                continue;
            }
            // stray ESC (and other controls) fall through to the control pass
            i += 1;
            continue;
        }
        // C0/C1 controls except \t (0x09) \n (0x0A) \r (0x0D)
        let keep = !matches!(c, 0x00..=0x08 | 0x0b | 0x0c | 0x0e..=0x1f | 0x7f);
        if keep {
            // copy the full UTF-8 sequence starting at i
            let width = utf8_width(c);
            let end = (i + width).min(b.len());
            out.push_str(&String::from_utf8_lossy(&b[i..end]));
            i = end;
        } else {
            i += 1;
        }
    }
    out
}

fn utf8_width(first: u8) -> usize {
    match first {
        0x00..=0x7f => 1,
        0xc0..=0xdf => 2,
        0xe0..=0xef => 3,
        0xf0..=0xf7 => 4,
        _ => 1, // invalid lead — byte dropped by lossy below; step 1
    }
}

/// The last non-empty line of a log's tail, ANSI-stripped and
/// tab-normalized ("" when there is no output yet).
pub fn read_last_line(path: &str, scan_bytes: i64) -> String {
    let tail = read_bounded_tail(path, scan_bytes);
    if tail == NO_OUTPUT {
        return String::new();
    }
    let stripped = strip_ansi(&tail);
    for line in stripped
        .split(|c| c == '\r' || c == '\n')
        .rev()
    {
        let line = line.replace('\t', " ").trim().to_string();
        if !line.is_empty() {
            return line;
        }
    }
    String::new()
}

/// Polls a log's tail and invokes `on_update` only on change (the foreground
/// progress stream). Stops cleanly; never holds the turn.
pub struct Streamer {
    stop: Arc<AtomicBool>,
}

/// Poll `path` every `interval`, calling `on_update` with the bounded tail
/// when it changed. `on_update` may be `None`.
pub fn start_stream<F>(
    path: String,
    interval: Duration,
    on_update: Option<F>,
) -> Streamer
where
    F: Fn(&str) + Send + 'static,
{
    let stop = Arc::new(AtomicBool::new(false));
    let flag = stop.clone();
    std::thread::spawn(move || {
        let mut last = String::new();
        while !flag.load(Ordering::SeqCst) {
            std::thread::sleep(interval);
            if flag.load(Ordering::SeqCst) {
                return;
            }
            let tail = read_bounded_tail(&path, 4096);
            if tail != last {
                last = tail.clone();
                if let Some(cb) = &on_update {
                    cb(&tail);
                }
            }
        }
    });
    Streamer { stop }
}

impl Streamer {
    /// Release the poller (idempotent).
    pub fn stop(&self) {
        self.stop.store(true, Ordering::SeqCst);
    }
}

impl Drop for Streamer {
    fn drop(&mut self) {
        self.stop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str, contents: &[u8]) -> String {
        let p = std::env::temp_dir().join(format!("pi-bg-out-{name}.log"));
        std::fs::write(&p, contents).unwrap();
        p.to_string_lossy().into_owned()
    }

    #[test]
    fn bounded_tail_truncates_with_marker() {
        let body: Vec<u8> = (0..100u8).collect();
        let p = scratch("trunc", &body);
        let t = read_bounded_tail(&p, 10);
        assert!(t.starts_with("...[truncated, showing last 10 chars]\n"), "{t}");
        assert!(t.ends_with(&(90..100u8).collect::<Vec<u8>>().iter().map(|b| char::from(*b)).collect::<String>()));
        let full = read_bounded_tail(&p, 1000);
        assert_eq!(full.len(), 100);
        assert!(!full.contains("truncated"));
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn bounded_tail_missing_or_empty() {
        assert_eq!(read_bounded_tail("C:\\definitely\\missing.log", 100), NO_OUTPUT);
        let p = scratch("empty", b"");
        assert_eq!(read_bounded_tail(&p, 100), NO_OUTPUT);
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn strip_ansi_csi_osc_controls() {
        assert_eq!(strip_ansi("\x1b[31mred\x1b[0m plain"), "red plain");
        assert_eq!(strip_ansi("\x1b]0;title\x07after"), "after");
        assert_eq!(strip_ansi("\x1b]0;t\x1b\\after"), "after");
        assert_eq!(strip_ansi("a\x07\x7fb"), "ab"); // BEL + DEL removed
        assert_eq!(strip_ansi("keep\ttab\nnl\rcr"), "keep\ttab\nnl\rcr");
        assert_eq!(strip_ansi("\x1b[38;5;9mX"), "X"); // unterminated CSI → dropped
        assert_eq!(strip_ansi("héllo wörld"), "héllo wörld"); // UTF-8 intact
    }

    #[test]
    fn last_line_normalizes() {
        let p = scratch("last", b"\x1b[32mgreen line\tindented\x1b[0m\n\n   \nlast!\n");
        assert_eq!(read_last_line(&p, 4096), "last!");
        let p2 = scratch("last2", b"only\tafter\ttabs\n");
        assert_eq!(read_last_line(&p2, 4096), "only after tabs");
        std::fs::remove_file(&p).ok();
        std::fs::remove_file(&p2).ok();
        assert_eq!(read_last_line("C:\\missing.log", 4096), "");
    }

    #[test]
    fn streamer_fires_on_change_only() {
        let p = scratch("stream", b"v1\n");
        let updates = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
        let sink = updates.clone();
        let s = start_stream(p.clone(), Duration::from_millis(15), Some(move |t: &str| {
            sink.lock().unwrap().push(t.to_string());
        }));
        std::thread::sleep(Duration::from_millis(80));
        std::fs::write(&p, b"v1\nv2\n").unwrap();
        std::thread::sleep(Duration::from_millis(80));
        s.stop();
        let got = updates.lock().unwrap().clone();
        assert!(got.iter().any(|t| t.contains("v1")), "{got:?}");
        assert!(got.iter().any(|t| t.contains("v2")), "{got:?}");
        // no change after stop → count is bounded (not one per poll forever)
        std::thread::sleep(Duration::from_millis(50));
        assert_eq!(updates.lock().unwrap().len(), got.len());
        std::fs::remove_file(&p).ok();
    }
}

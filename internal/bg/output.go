package bg

import (
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Output readers — parity with the reference's output.ts: bounded tails
// (O(maxBytes), not O(fileSize)), ANSI/control stripping so job output cannot
// inject escapes into the TUI or the model context, and a live-tail poller
// that feeds the tool's update callback.

var (
	ansiCSI = regexp.MustCompile("\u001b\\[[0-9;?]*[ -/]*[@-~]")
	ansiOSC = regexp.MustCompile("\u001b\\][\\s\\S]*?(?:\u0007|\u001b\\\\)")
	// nolint: control chars except \t \n \r handled by caller-newlines
	controlChars = regexp.MustCompile("[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]")
)

// ReadBoundedTail reads only the last maxBytes of a file.
func ReadBoundedTail(path string, maxBytes int64) string {
	f, err := os.Open(path)
	if err != nil {
		return "(no output yet)"
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return "(no output yet)"
	}
	size := fi.Size()
	if size == 0 {
		return "(no output yet)"
	}
	toRead := size
	offset := int64(0)
	truncated := false
	if toRead > maxBytes {
		toRead = maxBytes
		offset = size - maxBytes
		truncated = true
	}
	buf := make([]byte, toRead)
	if _, err := f.ReadAt(buf, offset); err != nil && len(buf) == 0 {
		return "(no output yet)"
	}
	body := string(buf)
	if truncated {
		return "...[truncated, showing last " + itoa(maxBytes) + " chars]\n" + body
	}
	return body
}

func itoa(v int64) string {
	const digits = "0123456789"
	if v == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for v > 0 {
		i--
		b[i] = digits[v%10]
		v /= 10
	}
	return string(b[i:])
}

// StripAnsi removes ANSI CSI/OSC sequences and C0/C1 control chars (newlines,
// tabs and CR are left to the caller).
func StripAnsi(s string) string {
	s = ansiCSI.ReplaceAllString(s, "")
	s = ansiOSC.ReplaceAllString(s, "")
	s = controlChars.ReplaceAllString(s, "")
	return s
}

// ReadLastLine returns the last non-empty line of a log's tail, ANSI-stripped
// and tab-normalized ("" when there is no output yet).
func ReadLastLine(path string, scanBytes int64) string {
	tail := ReadBoundedTail(path, scanBytes)
	if tail == "(no output yet)" {
		return ""
	}
	lines := strings.FieldsFunc(StripAnsi(tail), func(r rune) bool { return r == '\r' || r == '\n' })
	for i := len(lines) - 1; i >= 0; i-- {
		line := strings.ReplaceAll(lines[i], "\t", " ")
		line = strings.TrimSpace(line)
		if line != "" {
			return line
		}
	}
	return ""
}

// Streamer polls a log's tail and invokes onUpdate only on change (the
// foreground progress stream). Stops cleanly; never holds the turn.
type Streamer struct {
	stop chan struct{}
	once sync.Once
}

// StartStream polls path every interval, calling onUpdate with the bounded
// tail when it changed. onUpdate may be nil.
func StartStream(path string, interval time.Duration, onUpdate func(string)) *Streamer {
	s := &Streamer{stop: make(chan struct{})}
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		last := ""
		for {
			select {
			case <-s.stop:
				return
			case <-ticker.C:
				tail := ReadBoundedTail(path, 4096)
				if tail != last {
					last = tail
					if onUpdate != nil {
						onUpdate(tail)
					}
				}
			}
		}
	}()
	return s
}

// Stop releases the poller (idempotent).
func (s *Streamer) Stop() {
	if s == nil {
		return
	}
	s.once.Do(func() { close(s.stop) })
}

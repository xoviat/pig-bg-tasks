//go:build windows

// Package proc spawns one command with fd-direct log output and tree-kill
// semantics — the Go port of pi-bg-tasks' spawn.ts plus the Windows
// confinement hook (restricted primary token + CREATE_NO_WINDOW + Job object).
//
// The child writes stdout+stderr straight to the log file's handle (kernel
// moves the bytes, zero Go in the data path). Progress is read back by
// polling the log tail (bg/output.go). Every child joins a Job object with
// KILL_ON_JOB_CLOSE so bg_stop / session shutdown / a hard extension death
// all take the whole tree with them (validated failure mode: orphaned
// grandchildren holding inherited handles — PLAN.txt Part 2f).
package proc

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync/atomic"
	"syscall"
	"unsafe"

	srtwin "example.com/srt-win"
	"golang.org/x/sys/windows"
)

// Spec describes one spawn.
type Spec struct {
	Argv    []string
	Cwd     string
	Env     []string        // extra KEY=VALUE pairs merged over the inherited env
	LogPath string          // stdout+stderr target (created)
	Sandbox *srtwin.Sandbox // confined spawn through the srtwin token; nil = unconfined
}

// Exit is the spawn's terminal state. Killed marks a kill WE initiated
// (job terminate / Process.Kill) so callers can tell deliberate stops from
// failures — Windows has no signal half of the POSIX exit record.
type Exit struct {
	Code   int
	Killed bool
	Err    error
}

// Handle is a running spawn.
type Handle struct {
	pid    int
	wait   func() error
	kill   func() error
	code   func() int
	job    windows.Handle
	killed atomic.Bool
	exit   chan Exit
}

// ErrUnsupported is returned on non-Windows builds (deferred scope).
var ErrUnsupported = errors.New("proc: platform not supported by this build (Windows-only scope; Linux/macOS runners deferred)")

// Start spawns the command. Its parent-side stdio file handles are closed
// before Start returns; the child holds inherited copies.
func Start(spec Spec) (*Handle, error) {
	if len(spec.Argv) == 0 {
		return nil, errors.New("proc: empty argv")
	}
	if err := ensureDir(spec.LogPath); err != nil {
		return nil, err
	}
	logFile, err := createInheritable(spec.LogPath, windows.GENERIC_WRITE, windows.CREATE_ALWAYS)
	if err != nil {
		return nil, fmt.Errorf("proc: open log: %w", err)
	}
	logF := os.NewFile(uintptr(logFile), spec.LogPath) // ownership → logF; single close
	defer logF.Close()
	nulH, err := createInheritable(`NUL`, windows.GENERIC_READ, windows.OPEN_EXISTING)
	if err != nil {
		return nil, fmt.Errorf("proc: open NUL: %w", err)
	}
	nulF := os.NewFile(uintptr(nulH), "NUL")
	defer nulF.Close()

	h := &Handle{exit: make(chan Exit, 1)}
	if spec.Sandbox != nil {
		// Confined path: the srtwin library spawns under its pre-minted
		// restricted token (os/exec semantics; ensureMsysReady runs inside
		// Cmd.Start). Stdio stays fd-direct: *os.File values are handed to
		// the child as handles, same as the bare path below.
		c := spec.Sandbox.Command(spec.Argv[0], spec.Argv[1:]...)
		c.Dir = spec.Cwd
		c.Env = mergeEnv(spec.Env)
		c.Stdin, c.Stdout, c.Stderr = nulF, logF, logF
		if err := c.Start(); err != nil {
			return nil, fmt.Errorf("proc: start: %w", err)
		}
		h.pid = c.Process.Pid
		h.wait = c.Wait
		h.kill = func() error { return c.Process.Kill() }
		h.code = func() int {
			if c.ProcessState != nil {
				return c.ProcessState.ExitCode()
			}
			return -1
		}
	} else {
		cmd := exec.Command(spec.Argv[0], spec.Argv[1:]...)
		cmd.Dir = spec.Cwd
		cmd.Env = mergeEnv(spec.Env)
		cmd.Stdin, cmd.Stdout, cmd.Stderr = nulF, logF, logF
		sys := &syscall.SysProcAttr{
			HideWindow:    true,
			CreationFlags: 0x08000000 | 0x00000400, // CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT
		}
		cmd.SysProcAttr = sys
		if err := cmd.Start(); err != nil {
			return nil, fmt.Errorf("proc: start: %w", err)
		}
		h.pid = cmd.Process.Pid
		h.wait = cmd.Wait
		h.kill = func() error { return cmd.Process.Kill() }
		h.code = func() int {
			if cmd.ProcessState != nil {
				return cmd.ProcessState.ExitCode()
			}
			return -1
		}
	}

	h.job = attachPID(uint32(h.pid))
	go func() {
		err := h.wait()
		h.exit <- Exit{Code: h.code(), Killed: h.killed.Load(), Err: err}
	}()
	return h, nil
}

// PID of the direct child.
func (h *Handle) PID() int { return h.pid }

// Done yields the spawn's terminal state exactly once (mailbox semantics:
// one consumer — the foreground race OR the background watcher).
func (h *Handle) Done() <-chan Exit { return h.exit }

// Kill terminates the whole tree: job object when attached, direct process
// otherwise. Windows has no SIGTERM, so this IS the stop (documented
// divergence: no graceful grace window on Windows).
func (h *Handle) Kill() {
	h.killed.Store(true)
	if h.job != 0 {
		windows.TerminateJobObject(h.job, 1)
		return
	}
	if h.kill != nil {
		_ = h.kill()
	}
}

// Alive reports whether the direct child has not exited yet (cheap probe).
func (h *Handle) Alive() bool {
	select {
	case <-h.exit:
		return false
	default:
		return true
	}
}

// attachPID puts the child (by pid) in a KILL_ON_JOB_CLOSE job; returns 0
// when the host refuses (nested jobs older than Win8, access denied) —
// callers keep working with the direct-process fallback.
func attachPID(pid uint32) windows.Handle {
	if pid == 0 {
		return 0
	}
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil || job == 0 {
		return 0
	}
	info := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{}
	info.BasicLimitInformation.LimitFlags = 0x2000 // JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	if _, err := windows.SetInformationJobObject(job,
		windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info))); err != nil {
		windows.CloseHandle(job)
		return 0
	}
	proc, err := windows.OpenProcess(windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE, false, pid)
	if err != nil {
		windows.CloseHandle(job)
		return 0
	}
	defer windows.CloseHandle(proc)
	if err := windows.AssignProcessToJobObject(job, proc); err != nil {
		windows.CloseHandle(job)
		return 0
	}
	return job
}

// Close releases the job handle (children keep running; KILL_ON_JOB_CLOSE
// applies when THIS process exits — which is exactly the no-orphans rule).
func (h *Handle) CloseJob() {
	if h.job != 0 {
		windows.CloseHandle(h.job)
		h.job = 0
	}
}

func createInheritable(path string, access uint32, disp uint32) (windows.Handle, error) {
	sa := &windows.SecurityAttributes{
		Length:        uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
		InheritHandle: 1,
	}
	return windows.CreateFile(
		windows.StringToUTF16Ptr(path),
		access,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		sa, disp, windows.FILE_ATTRIBUTE_NORMAL, 0)
}

func ensureDir(logPath string) error {
	dir := logPath
	if i := strings.LastIndexByte(logPath, '\\'); i >= 0 {
		dir = logPath[:i]
	} else if i = strings.LastIndexByte(logPath, '/'); i >= 0 {
		dir = logPath[:i]
	}
	return os.MkdirAll(dir, 0o755)
}

// mergeEnv inherits the parent env, drops LC_ALL (it would override
// LC_MESSAGES and hide denial text from classification — parity with the
// reference's env handling), applies spec extras last-wins, and pins
// LC_MESSAGES=C so denial diagnostics stay classifiable.
func mergeEnv(extras []string) []string {
	out := make([]string, 0, len(os.Environ())+len(extras)+2)
	for _, kv := range os.Environ() {
		if hasPrefixCI(kv, "LC_ALL=") || hasPrefixCI(kv, "LC_MESSAGES=") {
			continue
		}
		out = append(out, kv)
	}
	for _, kv := range extras {
		if hasPrefixCI(kv, "LC_ALL=") {
			continue
		}
		out = append(out, kv)
	}
	return append(out, "LC_MESSAGES=C")
}

func hasPrefixCI(s, prefix string) bool {
	return len(s) >= len(prefix) && strings.EqualFold(s[:len(prefix)], prefix)
}

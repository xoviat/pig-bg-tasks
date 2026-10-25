//go:build windows

// Cmd mirrors os/exec semantics over the sandbox's private token.
//
// The spawn itself is os/exec's StartProcess with SysProcAttr.Token set,
// which is CreateProcessAsUserW with a DuplicateTokenEx'd primary:
// STARTF_USESTDHANDLES for stdio, a hand-built UTF-16 lpEnvironment from
// the resolved Cmd.Env with CREATE_UNICODE_ENVIRONMENT, bInheritHandles
// = TRUE restricted to the three std handles (PROC_THREAD_ATTRIBUTE_HANDLE_LIST),
// lpCurrentDirectory from Cmd.Dir, and a Wait that waits on the process
// handle. Delegating to os/exec is what makes Process/ProcessState real
// *os.Process / *os.ProcessState values and ExitCode/Output/CombinedOutput
// behave exactly like their os/exec counterparts.
//
// Stdio follows the os/exec pattern: an *os.File value is handed to the
// child as its handle (os/exec duplicates every std handle as inheritable
// before the spawn), nil means the null device, anything else gets an
// os.Pipe plus a copier goroutine that Wait joins.

package srtwin

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"syscall"

	"golang.org/x/sys/windows"
)

const createNoWindow = 0x08000000 // CREATE_NO_WINDOW (no console flashes)

// ExitError is the library's exit error: the exit code, a message, and —
// where captured — stderr (Output/CombinedOutput attach it like
// exec.ExitError.Stderr). It is deliberately NOT type-compatible with
// *exec.ExitError: an *os.ProcessState cannot be synthesized outside
// os/exec, so no conversion the other way exists. Callers should type
// assert on *srtwin.ExitError.
type ExitError struct {
	Code         int
	Stderr       []byte
	ProcessState *os.ProcessState
	msg          string
}

func (e *ExitError) Error() string {
	if e.msg != "" {
		return e.msg
	}
	return fmt.Sprintf("exit status %d", e.Code)
}

// ExitCode returns the child's exit code.
func (e *ExitError) ExitCode() int { return e.Code }

// Cmd mirrors exec.Cmd: Command does not start the process; Start/Wait,
// Run, Output, CombinedOutput and ExitCode behave like os/exec.
type Cmd struct {
	Path   string
	Args   []string
	Env    []string // nil = inherit os.Environ() (same convention as os/exec)
	Dir    string   // working directory; "" = inherit
	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer

	// Process and ProcessState mirror os/exec (nil until started / waited).
	Process      *os.Process
	ProcessState *os.ProcessState

	sb      *Sandbox
	ec      *exec.Cmd
	started bool
	waited  bool
	waitErr error
}

// Command mirrors exec.Command: Path is resolved via exec.LookPath at
// Command time, the process is not started.
func (s *Sandbox) Command(name string, args ...string) *Cmd {
	c := &Cmd{Args: append([]string{name}, args...), sb: s}
	c.Path = name
	if lp, err := exec.LookPath(name); err == nil {
		c.Path = lp
	}
	return c
}

// resolveEnv implements the Env convention: nil inherits the parent
// environment, anything else is used as-is (including an explicit empty
// environment, exactly like os/exec).
func resolveEnv(env []string) []string {
	if env != nil {
		return env
	}
	return os.Environ()
}

// buildEnvBlock renders env as the UTF-16 lpEnvironment block for
// CREATE_UNICODE_ENVIRONMENT: NUL-separated entries, double-NUL
// terminated. Start uses it to fail fast on a malformed entry (os/exec
// performs the actual conversion with the same layout).
func buildEnvBlock(env []string) ([]uint16, error) {
	if len(env) == 0 {
		return []uint16{0, 0}, nil // canonical empty block (os/exec does the same)
	}
	var block []uint16
	for _, kv := range env {
		// Note: entries starting with '=' ("=D:=D:\\" drive-cwd variables
		// set by MSYS/cmd) are legal — only a missing '=' is malformed.
		if i := strings.IndexByte(kv, '='); i < 0 {
			return nil, fmt.Errorf("srt-win: malformed environment entry %q (want KEY=VALUE)", kv)
		}
		u, err := windows.UTF16FromString(kv)
		if err != nil {
			return nil, fmt.Errorf("srt-win: environment entry %q: %w", kv, err)
		}
		block = append(block, u...)
	}
	return append(block, 0), nil
}

// Start creates the process under the sandbox token; it does not wait.
func (c *Cmd) Start() error {
	if c.started {
		return errors.New("srt-win: Cmd already started")
	}
	if c.sb == nil {
		return errors.New("srt-win: sandbox is closed")
	}
	tok := c.sb.tokenHandle()
	if tok == 0 {
		return errors.New("srt-win: sandbox is closed")
	}
	if c.Path == "" {
		return errors.New("srt-win: no command")
	}
	env := resolveEnv(c.Env)
	if _, err := buildEnvBlock(env); err != nil {
		return err
	}
	// Make the MSYS object directory and the cygwin shared sections
	// reachable before the spawn (ready gate once per process; the section
	// pin runs every spawn). Non-msys children are unaffected by held
	// objects.
	ensureMsysReady()
	ec := &exec.Cmd{
		Path:   c.Path,
		Args:   c.Args,
		Dir:    c.Dir,
		Env:    env,
		Stdin:  c.Stdin,
		Stdout: c.Stdout,
		Stderr: c.Stderr,
		SysProcAttr: &syscall.SysProcAttr{
			HideWindow: true,
			CreationFlags: createNoWindow | // no console window
				0x00000400, // CREATE_UNICODE_ENVIRONMENT (os/exec adds it too)
			Token: syscall.Token(uintptr(tok)),
		},
	}
	if err := ec.Start(); err != nil {
		return fmt.Errorf("srt-win: start %s: %w", c.Path, err)
	}
	c.ec = ec
	c.Process = ec.Process
	c.started = true
	return nil
}

// Wait waits for the process to exit. Repeated calls return the first
// result (idempotent about resource cleanup, like a joined exec.Cmd).
func (c *Cmd) Wait() error {
	if !c.started {
		return errors.New("srt-win: Cmd was not started")
	}
	if c.waited {
		return c.waitErr
	}
	err := c.ec.Wait()
	c.ProcessState = c.ec.ProcessState
	c.waited = true
	c.waitErr = convertExit(err)
	return c.waitErr
}

// Run is Start + Wait.
func (c *Cmd) Run() error {
	if err := c.Start(); err != nil {
		return err
	}
	return c.Wait()
}

// ExitCode is the child's exit code, or -1 if it has not started/exited.
func (c *Cmd) ExitCode() int {
	if c.ProcessState == nil {
		return -1
	}
	return c.ProcessState.ExitCode()
}

// Output runs the command and returns its stdout, attaching stderr to a
// *ExitError like exec.ExitError.Stderr.
func (c *Cmd) Output() ([]byte, error) {
	if c.started {
		return nil, errors.New("srt-win: Cmd already started")
	}
	if c.Stdout != nil {
		return nil, errors.New("srt-win: Stdout already set")
	}
	var out bytes.Buffer
	c.Stdout = &out
	err := c.Run()
	return out.Bytes(), err
}

// CombinedOutput runs the command with stdout and stderr interleaved into
// the returned buffer (and attached to a *ExitError on failure).
func (c *Cmd) CombinedOutput() ([]byte, error) {
	if c.started {
		return nil, errors.New("srt-win: Cmd already started")
	}
	if c.Stdout != nil || c.Stderr != nil {
		return nil, errors.New("srt-win: Stdout or Stderr already set")
	}
	var buf bytes.Buffer
	c.Stdout = &buf
	c.Stderr = &buf
	err := c.Run()
	if ee, ok := err.(*ExitError); ok && len(ee.Stderr) == 0 {
		ee.Stderr = buf.Bytes()
	}
	return buf.Bytes(), err
}

// convertExit maps os/exec's exit error onto the library's ExitError.
func convertExit(err error) error {
	if err == nil {
		return nil
	}
	ee, ok := err.(*exec.ExitError)
	if !ok {
		return err
	}
	out := &ExitError{Code: -1, msg: ee.Error(), ProcessState: ee.ProcessState}
	if ee.ProcessState != nil {
		out.Code = ee.ProcessState.ExitCode()
	}
	if len(ee.Stderr) > 0 {
		out.Stderr = append([]byte(nil), ee.Stderr...)
	}
	return out
}

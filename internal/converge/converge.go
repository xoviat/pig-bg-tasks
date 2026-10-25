// Package converge is the single background thread through which ALL
// extension-level ACL work happens (CONVERGENCE.md).
//
// Desired state = writable set (+ env, resolved from the host at spawn),
// derived from config. Event handlers and tool executes never perform ACL
// work and never block on it — they only read shared state:
//
//   - Start (session_start) spawns the worker and returns immediately.
//   - Every distinct policy state bumps an epoch: the initial startup state,
//     /sandbox <mode>, and a workspace change (detected when bash binds a
//     call whose canonical cwd differs from the desired workspace).
//   - Bind(state) returns the newest epoch's completion; Wait blocks until
//     THAT epoch's convergence — the wait is part of the bash call's total
//     duration. Rapid flips collapse: superseded pending epochs resolve with
//     the newest epoch's result, so a bound call never executes against a
//     stale policy and never waits on a policy that will not run.
//   - Convergence failure resolves the wait causally (the real cause, no
//     temporal timeout) and the call fails closed — never a half-applied
//     policy, never a bare spawn.
//   - Shutdown performs no ACL forgets (this package owns none): standing
//     grants stay on disk, inert without a live token that carries their
//     synthetic SID; stale/moved workspaces are forgotten by the next
//     epoch's convergence via srtwin's state-DB move detection.
//
// The apply step delegates to the srtwin library: workspace-write/read-only
// grant via srtwin.New(dirs...) (read-only = New() with no dirs — its
// synthetic SID differs from every granted set, so previous grants are inert
// for the read-only token), danger-full-access retires the sandbox entirely.
// Retired sandboxes are deliberately NOT closed: a racing spawn that already
// snapshotted the sandbox must still be able to start (handles are few — one
// per epoch — and no child is ever handed a retired token).
package converge

import (
	"fmt"
	"os"
	"strings"
	"sync"

	"example.com/pig-bg-tasks/internal/policy"
	srtwin "example.com/srt-win"
)

// State is one epoch's desired policy state.
type State struct {
	Mode      policy.Mode
	Workspace string
	Temp      string
	Extras    []string
}

func (s State) equal(o State) bool {
	if s.Mode != o.Mode || s.Workspace != o.Workspace || s.Temp != o.Temp {
		return false
	}
	if len(s.Extras) != len(o.Extras) {
		return false
	}
	for i := range s.Extras {
		if s.Extras[i] != o.Extras[i] {
			return false
		}
	}
	return true
}

func (s State) String() string {
	dirs := s.writableDirs()
	if len(dirs) == 0 {
		return fmt.Sprintf("%s (no writable dirs)", s.Mode)
	}
	return fmt.Sprintf("%s [%s]", s.Mode, strings.Join(dirs, " ; "))
}

// writableDirs derives the srtwin dir list for this state: read-only is
// deliberately empty (New() with no dirs); danger-full-access is bare.
func (s State) writableDirs() []string {
	switch s.Mode {
	case policy.ModeWorkspaceWrite:
		out := make([]string, 0, 2+len(s.Extras))
		out = append(out, s.Workspace, s.Temp)
		out = append(out, s.Extras...)
		return out
	case policy.ModeReadonly:
		return nil
	default: // danger-full-access: no sandbox at all
		return nil
	}
}

// future is one epoch's completion.
type future struct {
	done chan struct{}
	err  error
}

func newFuture() *future { return &future{done: make(chan struct{})} }

func (f *future) resolve(err error) {
	select {
	case <-f.done:
	default:
		f.err = err
		close(f.done)
	}
}

// Future is an epoch-completion handle returned by Bind.
type Future struct{ f *future }

// Status is the read-only view for /sandbox and bg_debug.
type Status struct {
	Epoch      uint64
	Desired    State
	Converged  State
	Pending    bool  // the newest epoch has not resolved yet
	Dirty      bool  // desired state differs from the last successful apply
	LastErr    error // last convergence error (nil = last apply succeeded)
	Warnings   []string
	SandboxSID string // "" = no sandbox (danger, or not yet converged)
}

type engine struct {
	mu        sync.Mutex
	started   bool
	epoch     uint64
	desired   State
	cur       *future
	chain     []*future // superseded pending futures (resolve together)
	sb        *srtwin.Sandbox
	retired   []*srtwin.Sandbox
	converged State
	applied   bool // at least one successful apply
	lastErr   error
	warnings  []string
	wake      chan struct{}
	once      sync.Once
}

var eng = &engine{wake: make(chan struct{}, 1)}

// applyFn is the ACL-work seam (swapped in tests).
var applyFn = defaultApply

// Start spawns the convergence thread and begins the initial epoch. It
// returns immediately; idempotent.
func Start(initial State) {
	eng.once.Do(func() {
		eng.mu.Lock()
		eng.started = true
		eng.epoch = 1
		eng.desired = initial
		eng.cur = newFuture()
		eng.mu.Unlock()
		go worker()
		kick()
	})
}

// Bind returns the newest epoch's completion for state, bumping the epoch
// when the desired state differs (workspace change / mode change). Never
// performs ACL work; never blocks.
func Bind(state State) *Future {
	eng.mu.Lock()
	if !eng.started { // defensive: session_start normally started us
		eng.mu.Unlock()
		Start(state)
		eng.mu.Lock()
	}
	if !eng.desired.equal(state) {
		eng.desired = state
		bumpLocked()
	} else if isDone(eng.cur) && eng.cur.err != nil {
		// A failed epoch is not sticky: the next bind retries convergence
		// (each attempt still resolves causally — fail-closed, never bare).
		bumpLocked()
	}
	f := eng.cur
	eng.mu.Unlock()
	return &Future{f: f}
}

// SetMode updates only the mode dimension (the /sandbox handler path) and
// bumps when it changed. Non-blocking.
func SetMode(m policy.Mode) uint64 {
	eng.mu.Lock()
	if !eng.started {
		eng.mu.Unlock()
		Start(State{Mode: m})
		eng.mu.Lock()
	}
	if eng.desired.Mode != m {
		eng.desired.Mode = m
		bumpLocked()
	}
	e := eng.epoch
	eng.mu.Unlock()
	return e
}

// Invalidate forces a re-convergence without changing the desired state
// (runner-failure heal: the next bind waits for a fresh apply).
func Invalidate() {
	eng.mu.Lock()
	if eng.started {
		bumpLocked()
	}
	eng.mu.Unlock()
}

// Wait blocks until the bound epoch's convergence resolves and returns its
// causal error (nil = converged). No temporal timeout — by design.
func Wait(f *Future) error {
	<-f.f.done
	return f.f.err
}

// Sandbox is the converged sandbox for the newest successful epoch (nil =
// danger-full-access mode, or no successful apply yet). Read-only.
func Sandbox() *srtwin.Sandbox {
	eng.mu.Lock()
	defer eng.mu.Unlock()
	return eng.sb
}

// SandboxSID is the current sandbox's synthetic SID ("" = none) — trace
// diagnostics only.
func SandboxSID() string {
	eng.mu.Lock()
	defer eng.mu.Unlock()
	if eng.sb == nil {
		return ""
	}
	return eng.sb.SIDString()
}

// Snapshot captures the engine for display surfaces.
func Snapshot() Status {
	eng.mu.Lock()
	defer eng.mu.Unlock()
	st := Status{
		Epoch:   eng.epoch,
		Desired: eng.desired,
		Pending: !isDone(eng.cur),
		LastErr: eng.lastErr,
	}
	if eng.applied {
		st.Converged = eng.converged
		st.Dirty = !eng.desired.equal(eng.converged)
	}
	st.Warnings = append([]string(nil), eng.warnings...)
	st.SandboxSID = sandboxSIDLocked()
	return st
}

// sandboxSIDLocked reads the SID while eng.mu is held.
func sandboxSIDLocked() string {
	if eng.sb == nil {
		return ""
	}
	return eng.sb.SIDString()
}

// StatusLine renders one line for /sandbox and bg_debug.
func StatusLine() string {
	st := Snapshot()
	var b strings.Builder
	fmt.Fprintf(&b, "epoch %d", st.Epoch)
	switch {
	case st.Pending && st.Dirty:
		fmt.Fprintf(&b, " — converging to %s", st.Desired)
	case st.Pending:
		b.WriteString(" — converging")
	case st.LastErr != nil:
		fmt.Fprintf(&b, " — FAILED: %v", st.LastErr)
	case st.Dirty:
		fmt.Fprintf(&b, " — converged %s; desired %s (pending)", st.Converged, st.Desired)
	default:
		fmt.Fprintf(&b, " — converged: %s", st.Desired)
	}
	if st.SandboxSID != "" {
		fmt.Fprintf(&b, " (sandbox SID %s)", st.SandboxSID)
	}
	if len(st.Warnings) > 0 {
		fmt.Fprintf(&b, " — %d warning(s): %s", len(st.Warnings), strings.Join(st.Warnings, "; "))
	}
	return b.String()
}

func isDone(f *future) bool {
	select {
	case <-f.done:
		return true
	default:
		return false
	}
}

// bumpLocked starts a new epoch: the current pending future (if any) moves
// to the superseded chain and resolves together with the next apply.
func bumpLocked() {
	eng.epoch++
	if eng.cur != nil && !isDone(eng.cur) {
		eng.chain = append(eng.chain, eng.cur)
	}
	eng.cur = newFuture()
	kick()
}

func kick() {
	select {
	case eng.wake <- struct{}{}:
	default:
	}
}

// worker is the ONE background thread doing ACL work.
func worker() {
	for range eng.wake {
		eng.mu.Lock()
		if eng.cur == nil || isDone(eng.cur) {
			eng.mu.Unlock()
			continue
		}
		e, s := eng.epoch, eng.desired
		f := eng.cur
		batch := eng.chain
		eng.chain = nil
		eng.mu.Unlock()

		sb, warns, err := applyFn(s)

		eng.mu.Lock()
		// Publish only if this epoch is still the newest; a bump that raced
		// the apply leaves the newer epoch's future pending (the retired
		// sandbox stays alive — see package doc).
		if eng.epoch == e {
			if err == nil {
				if eng.sb != nil && eng.sb != sb {
					eng.retired = append(eng.retired, eng.sb)
				}
				eng.sb = sb
				eng.converged = s
				eng.applied = true
				eng.warnings = warns
			}
			eng.lastErr = err
		}
		f.resolve(err)
		for _, bf := range batch {
			bf.resolve(err)
		}
		eng.mu.Unlock()
	}
}

// defaultApply performs the epoch's ACL work through the srtwin library —
// the only place this package touches disk ACLs or mints tokens.
func defaultApply(s State) (*srtwin.Sandbox, []string, error) {
	if s.Mode == policy.ModeDangerFullAccess {
		return nil, nil, nil // bare: no sandbox desired
	}
	dirs := s.writableDirs()
	sb, err := srtwin.New(dirs...)
	if err != nil {
		return nil, nil, fmt.Errorf("srtwin.New(%s): %w", strings.Join(dirs, ", "), err)
	}
	return sb, sb.Warnings(), nil
}

// EnvSummary renders the resolved child environment for /sandbox: the host
// environment as the spawn layer resolves it (LC_ALL stripped,
// LC_MESSAGES=C pinned — see proc.mergeEnv).
func EnvSummary() string {
	n := 0
	for range os.Environ() {
		n++
	}
	return fmt.Sprintf("%d vars (host env; LC_ALL stripped, LC_MESSAGES=C pinned)", n)
}

// ResetForTest swaps the apply seam and returns the previous one.
func ResetForTest(fn func(State) (*srtwin.Sandbox, []string, error)) func(State) (*srtwin.Sandbox, []string, error) {
	old := applyFn
	if fn == nil {
		applyFn = defaultApply
	} else {
		applyFn = fn
	}
	return old
}

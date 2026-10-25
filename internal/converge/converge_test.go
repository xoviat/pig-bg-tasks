package converge

import (
	"errors"
	"strings"
	"sync"
	"testing"

	"example.com/pig-bg-tasks/internal/policy"
	srtwin "example.com/srt-win"
)

// The engine is a process singleton with one worker; these tests swap the
// apply seam so no ACL work happens. Sequential subtests share it.
func TestEpochBindWaitCollapseRetry(t *testing.T) {
	var mu sync.Mutex
	calls := 0
	var fail error
	ResetForTest(func(s State) (*srtwin.Sandbox, []string, error) {
		mu.Lock()
		defer mu.Unlock()
		calls++
		if fail != nil {
			return nil, nil, fail
		}
		return nil, nil, nil
	})
	defer ResetForTest(nil)

	ws1 := State{Mode: policy.ModeWorkspaceWrite, Workspace: `C:\ws`, Temp: `C:\t`}
	Start(ws1)

	// Initial epoch converges once for an unchanged state.
	if err := Wait(Bind(ws1)); err != nil {
		t.Fatalf("initial wait: %v", err)
	}
	mu.Lock()
	if calls != 1 {
		t.Fatalf("initial apply count = %d, want 1", calls)
	}
	mu.Unlock()

	// Rapid flips collapse: superseded pending futures resolve with the
	// newest epoch's result; no wait hangs and none fails.
	ws2 := State{Mode: policy.ModeWorkspaceWrite, Workspace: `C:\ws2`, Temp: `C:\t`}
	ro := State{Mode: policy.ModeReadonly, Workspace: `C:\ws2`, Temp: `C:\t`}
	f1 := Bind(ws2)
	f2 := Bind(ro)
	if err := Wait(f1); err != nil {
		t.Fatalf("superseded future must resolve with the newest result: %v", err)
	}
	if err := Wait(f2); err != nil {
		t.Fatalf("newest future: %v", err)
	}
	st := Snapshot()
	if st.Epoch < 3 {
		t.Fatalf("epoch = %d, want >= 3 after two bumps", st.Epoch)
	}
	if st.Pending {
		t.Fatal("everything resolved")
	}

	// Failure resolves causally...
	mu.Lock()
	fail = errors.New("boom: grant failed")
	mu.Unlock()
	bad := State{Mode: policy.ModeWorkspaceWrite, Workspace: `C:\bad`, Temp: `C:\t`}
	err := Wait(Bind(bad))
	if err == nil || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("failed epoch must carry the real cause, got %v", err)
	}

	// ...and is not sticky: binding the same state again retries.
	mu.Lock()
	fail = nil
	mu.Unlock()
	if err := Wait(Bind(bad)); err != nil {
		t.Fatalf("retry after failure must converge: %v", err)
	}
	if Snapshot().LastErr != nil {
		t.Fatalf("last error must clear after success, got %v", Snapshot().LastErr)
	}
}

// SetMode bumps only when the mode dimension changes (the /sandbox path).
func TestSetModeBumpsOnce(t *testing.T) {
	ResetForTest(func(s State) (*srtwin.Sandbox, []string, error) { return nil, nil, nil })
	defer ResetForTest(nil)
	e1 := SetMode(policy.ModeReadonly)
	e2 := SetMode(policy.ModeReadonly) // no change: no bump
	if e2 != e1 {
		t.Fatalf("SetMode(same) bumped: %d -> %d", e1, e2)
	}
	e3 := SetMode(policy.ModeWorkspaceWrite)
	if e3 <= e2 {
		t.Fatalf("SetMode(changed) must bump: %d -> %d", e2, e3)
	}
}

//go:build !windows

// Non-Windows spawn is deferred with the Linux/macOS runners (PLAN.txt scope
// note). The API surface exists so shared code compiles everywhere; every
// call fails closed.
package proc

type Spec struct {
	Argv    []string
	Cwd     string
	Env     []string
	LogPath string
	Sandbox any // *srtwin.Sandbox on Windows builds; unused here
}

type Exit struct {
	Code   int
	Killed bool
	Err    error
}

type Handle struct{}

var ErrUnsupported = errors.New("proc: platform not supported by this build (Windows-only scope; Linux/macOS runners deferred)")

func Start(spec Spec) (*Handle, error) { return nil, ErrUnsupported }
func (h *Handle) PID() int             { return 0 }
func (h *Handle) Done() <-chan Exit {
	ch := make(chan Exit, 1)
	ch <- Exit{Code: -1, Err: ErrUnsupported}
	return ch
}
func (h *Handle) Kill()       {}
func (h *Handle) Alive() bool { return false }
func (h *Handle) CloseJob()   {}

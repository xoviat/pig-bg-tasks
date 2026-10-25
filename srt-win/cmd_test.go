//go:build windows

package srtwin

import (
	"os"
	"reflect"
	"strings"
	"testing"
)

// TestEnvBlockBuilder: UTF-16, NUL-separated entries, double-NUL
// terminated — the lpEnvironment layout for CREATE_UNICODE_ENVIRONMENT.
func TestEnvBlockBuilder(t *testing.T) {
	block, err := buildEnvBlock([]string{"A=1", "B=two"})
	if err != nil {
		t.Fatalf("buildEnvBlock: %v", err)
	}
	want := []uint16{
		'A', '=', '1', 0,
		'B', '=', 't', 'w', 'o', 0,
		0, // final NUL ⇒ double-NUL terminator
	}
	if !reflect.DeepEqual(block, want) {
		t.Fatalf("block = %v, want %v", block, want)
	}

	// Empty environment is the canonical double-NUL block.
	empty, err := buildEnvBlock(nil)
	if err != nil {
		t.Fatalf("buildEnvBlock(nil): %v", err)
	}
	if !reflect.DeepEqual(empty, []uint16{0, 0}) {
		t.Fatalf("empty block = %v, want [0 0]", empty)
	}

	// Malformed entries (no '=' at all) are rejected before any spawn;
	// MSYS/cmd drive-cwd entries like "=D:=D:\\" (empty key) are legal.
	if _, err := buildEnvBlock([]string{"NOEQUALS"}); err == nil {
		t.Error("buildEnvBlock accepted an entry without '='")
	}
	if _, err := buildEnvBlock([]string{"=D:=D:\\"}); err != nil {
		t.Errorf("buildEnvBlock rejected a legal drive-cwd entry: %v", err)
	}
}

// TestResolveEnv: nil inherits the parent environment (os.Environ — the
// same convention as os/exec), non-nil is used verbatim.
func TestResolveEnv(t *testing.T) {
	if got := resolveEnv(nil); !reflect.DeepEqual(got, os.Environ()) {
		t.Errorf("resolveEnv(nil) does not equal os.Environ()")
	}
	custom := []string{"FOO=bar"}
	if got := resolveEnv(custom); !reflect.DeepEqual(got, custom) {
		t.Errorf("resolveEnv(custom) = %v, want %v", got, custom)
	}
}

// TestCmdEnvResolution: a Cmd with nil Env resolves to the parent
// environment; a Cmd with an explicit Env keeps it. Command() also does
// its LookPath resolution up front, like exec.Command.
func TestCmdEnvResolution(t *testing.T) {
	sb := &Sandbox{} // no token needed: env resolution happens before spawn
	c := sb.Command("cmd.exe", "/c", "echo hi")

	if !strings.Contains(c.Path, `\`) {
		t.Errorf("Command did not resolve Path via LookPath: %q", c.Path)
	}
	if got := resolveEnv(c.Env); !reflect.DeepEqual(got, os.Environ()) {
		t.Errorf("nil Cmd.Env does not resolve to os.Environ()")
	}
	c.Env = []string{"ONLY=this"}
	if got := resolveEnv(c.Env); !reflect.DeepEqual(got, []string{"ONLY=this"}) {
		t.Errorf("explicit Cmd.Env lost: %v", got)
	}
	if _, err := buildEnvBlock(resolveEnv(c.Env)); err != nil {
		t.Errorf("env block for explicit Env: %v", err)
	}
}

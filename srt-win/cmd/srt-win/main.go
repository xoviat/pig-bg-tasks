//go:build windows

// srt-win — thin CLI over the srtwin library. All flag parsing lives
// here; no sandbox logic in this package.
//
//	srt-win <writable-dir> [<writable-dir>...] [-- <command> [args...]]
//
// No command: print the deterministic SID and exit 0. With a command:
// run it under the write-restricted token with stdio passed straight
// through (handle pass-through), then propagate the child's exit code.
// Always unelevated — nothing here ever triggers or requires UAC.
package main

import (
	"fmt"
	"os"

	srtwin "example.com/srt-win"
)

const usage = `usage: srt-win <writable-dir> [<writable-dir>...] [-- <command> [args...]]

Runs a command under a Windows write-restricted token that can only write
to the whitelisted directories. Without -- <command>, prints the
deterministic sandbox SID for the directory set.

example: srt-win C:\work -- cmd /c "echo hi > ok.txt"`

func main() {
	dirs, cmd := parse(os.Args[1:])
	if len(dirs) == 0 {
		fmt.Fprintln(os.Stderr, usage)
		os.Exit(2)
	}

	sb, err := srtwin.New(dirs...)
	if err != nil {
		if se, ok := err.(*srtwin.SetupError); ok {
			for _, w := range se.Warnings {
				fmt.Fprintln(os.Stderr, "warning: "+w)
			}
		}
		fmt.Fprintln(os.Stderr, err.Error()) // errors carry the srt-win: prefix
		os.Exit(1)
	}
	defer sb.Close()
	for _, w := range sb.Warnings() {
		fmt.Fprintln(os.Stderr, "warning: "+w)
	}

	// No command: print the SID, exit 0.
	if len(cmd) == 0 {
		fmt.Println("SID: " + sb.SIDString())
		return
	}

	c := sb.Command(cmd[0], cmd[1:]...)
	c.Stdin, c.Stdout, c.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := c.Run(); err != nil {
		if code := c.ExitCode(); code >= 0 {
			os.Exit(code)
		}
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
}

// parse splits argv at the first "--": dirs before, command after.
// Without "--", every argument is a writable dir.
func parse(args []string) (dirs, cmd []string) {
	for i, a := range args {
		if a == "--" {
			return args[:i], args[i+1:]
		}
	}
	return args, nil
}

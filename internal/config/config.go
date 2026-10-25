// Package config loads the global sandbox.json (parity with the pi-sandbox
// reference, schema v2). Only the GLOBAL config layer is read; a project-level
// sandbox.json is ignored silently — the project dir is model-writable, so a
// config layer there would hand the model its own mode.
//
// Path divergence from the reference (documented in README): the reference
// reads ~/.pi/agent/sandbox.json (pi's agent dir). As a PiG extension we read
// <ConfigHome>/agent/sandbox.json (i.e. ~/.pig/agent/sandbox.json) — the
// PiG config root. Same filename, same schema, same semantics.
package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"example.com/pig-bg-tasks/internal/policy"
)

// Config mirrors the reference SandboxConfig.
type Config struct {
	Mode                    policy.Mode `json:"mode"`
	RunnerCommand           []string    `json:"runnerCommand"`
	RunnerFailureSignatures []string    `json:"runnerFailureSignatures"`
	ProbeTimeoutMs          int         `json:"probeTimeoutMs"`
	ExtraWritableDirs       []string    `json:"extraWritableDirs"`
}

// Default returns the reference defaults (workspace-write, 5s probe, no extras).
func Default() Config {
	return Config{
		Mode:              policy.ModeWorkspaceWrite,
		RunnerCommand:     nil,
		ProbeTimeoutMs:    5000,
		ExtraWritableDirs: []string{},
	}
}

var cached *Config

// Get loads the config once per process and falls back to defaults on any
// error (fail-safe: a bad config must never disable the sandbox).
// configHome is ctx.ConfigHome() (the PiG config root).
func Get(configHome string) Config {
	if cached != nil {
		return *cached
	}
	c := Default()
	path := filepath.Join(configHome, "agent", "sandbox.json")
	raw, err := os.ReadFile(path)
	if err == nil {
		var parsed map[string]any
		if json.Unmarshal(raw, &parsed) == nil && parsed != nil && !isArrayJSON(raw) {
			c = validate(parsed, path, c)
		}
	}
	// Resolve extra dirs: ~ expansion, absoluteness, existing directory,
	// dedupe. Invalid entries are warned about and dropped (reference
	// semantics); dangerous entries (home, config root) are KEPT with a warning.
	c.ExtraWritableDirs = resolveExtras(c.ExtraWritableDirs, path, configHome)
	cached = &c
	return c
}

// ResetCache is for tests only.
func ResetCache() { cached = nil }

func isArrayJSON(raw []byte) bool {
	t := strings.TrimSpace(string(raw))
	return strings.HasPrefix(t, "[")
}

func validate(raw map[string]any, source string, base Config) Config {
	c := base
	if v, ok := raw["mode"].(string); ok {
		if policy.IsMode(v) {
			c.Mode = policy.Mode(v)
		} else {
			warnf("invalid mode %q in %s, falling back to %q", v, source, base.Mode)
		}
	}
	if v, ok := raw["runnerCommand"]; ok && v != nil {
		if arr, ok := asStringSlice(v); ok {
			c.RunnerCommand = arr
		} else {
			warnf("runnerCommand in %s must be a string array; ignoring", source)
		}
	}
	if v, ok := raw["runnerFailureSignatures"]; ok && v != nil {
		if arr, ok := asStringSlice(v); ok {
			c.RunnerFailureSignatures = arr
		} else {
			warnf("runnerFailureSignatures in %s must be a string array; ignoring", source)
		}
	}
	if (c.RunnerCommand == nil) != (c.RunnerFailureSignatures == nil) {
		warnf("runnerCommand and runnerFailureSignatures must be configured together in %s; ignoring both", source)
		c.RunnerCommand, c.RunnerFailureSignatures = nil, nil
	}
	if v, ok := raw["probeTimeoutMs"].(float64); ok && v > 0 {
		c.ProbeTimeoutMs = int(v)
	} else if v, ok := raw["probeTimeoutMs"]; ok && v != nil {
		warnf("probeTimeoutMs in %s must be a positive number; using default", source)
	}
	if v, ok := raw["extraWritableDirs"]; ok && v != nil {
		if arr, ok := asStringSlice(v); ok {
			c.ExtraWritableDirs = arr
		} else {
			warnf("extraWritableDirs in %s must be a string array; using default", source)
		}
	}
	if c.RunnerCommand != nil {
		// Custom runner argv is a bwrap-compat override — meaningless for the
		// Windows-only scope. Warn loudly and ignore (documented divergence).
		warnf("runnerCommand is set in %s but custom runners are not supported by this build (Windows-only scope); ignoring", source)
		c.RunnerCommand, c.RunnerFailureSignatures = nil, nil
	}
	return c
}

func asStringSlice(v any) ([]string, bool) {
	arr, ok := v.([]any)
	if !ok {
		return nil, false
	}
	out := make([]string, 0, len(arr))
	for _, e := range arr {
		s, ok := e.(string)
		if !ok {
			return nil, false
		}
		out = append(out, s)
	}
	return out, true
}

func resolveExtras(entries []string, source, configHome string) []string {
	home, _ := os.UserHomeDir()
	out := make([]string, 0, len(entries))
	seen := map[string]bool{}
	agentDir := filepath.Join(configHome, "agent")
	for _, raw := range entries {
		e := raw
		if e == "~" {
			e = home
		} else if strings.HasPrefix(e, "~/") || strings.HasPrefix(e, `~\`) {
			e = filepath.Join(home, e[2:])
		}
		if !filepath.IsAbs(e) {
			warnf("extraWritableDirs entry is not an absolute path: %q in %s, ignoring it", raw, source)
			continue
		}
		fi, err := os.Stat(e)
		if err != nil || !fi.IsDir() {
			warnf("extraWritableDirs entry is not an existing directory: %q in %s, ignoring it", e, source)
			continue
		}
		if canon, err := filepath.EvalSymlinks(e); err == nil {
			e = canon
		}
		if covers(e, agentDir) || covers(agentDir, e) {
			warnf("extraWritableDirs entry %s covers PiG's agent dir (%s); a confined model could rewrite the sandbox config with it", e, agentDir)
		}
		if !seen[e] {
			seen[e] = true
			out = append(out, e)
		}
	}
	return out
}

// covers reports whether root contains child or vice versa (separator-aware).
func covers(root, child string) bool {
	if root == child {
		return true
	}
	r := filepath.Clean(root)
	c := filepath.Clean(child)
	if len(c) <= len(r) {
		return false
	}
	if !strings.HasPrefix(c, r) {
		return false
	}
	sep := string(filepath.Separator)
	return strings.HasPrefix(c[len(r):], sep)
}

func warnf(format string, args ...any) {
	println("sandbox: " + fmt.Sprintf(format, args...))
}

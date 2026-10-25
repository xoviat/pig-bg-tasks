//go:build windows

package srtwin

import (
	"testing"

	"golang.org/x/sys/windows/registry"
)

// withTestRegistry points the state DB at a scratch subtree for the
// duration of one test and removes it afterwards.
func withTestRegistry(t *testing.T) {
	t.Helper()
	old := regPath
	regPath = `Software\srt-win-test`
	t.Cleanup(func() {
		// Best-effort recursive delete of the scratch tree.
		_ = registry.DeleteKey(registry.CURRENT_USER, regPath+`\Config`)
		_ = registry.DeleteKey(registry.CURRENT_USER, regPath+`\Sids`)
		_ = registry.DeleteKey(registry.CURRENT_USER, regPath)
		regPath = old
	})
}

// TestRegistryRoundTrip: Config lookup, Sids Dirs/Used/Roots write-read,
// and deletion.
func TestRegistryRoundTrip(t *testing.T) {
	withTestRegistry(t)

	dirs := []string{`C:\work\alpha`, `C:\work\beta`}
	roots := []rootRecord{{Serial: 0x11223344, FileID: 0xAABBCCDDEEFF0011},
		{Serial: 1, FileID: 2}}
	sid := "S-1-5-21-100-200-300-0"
	key := "deadbeef"

	if _, ok := lookupConfig(key); ok {
		t.Fatal("config lookup hit on empty DB")
	}
	if err := putConfig(key, sid); err != nil {
		t.Fatalf("putConfig: %v", err)
	}
	got, ok := lookupConfig(key)
	if !ok || got != sid {
		t.Fatalf("lookupConfig = %q,%v want %q,true", got, ok, sid)
	}

	if err := writeDirs(sid, dirs); err != nil {
		t.Fatalf("writeDirs: %v", err)
	}
	if err := writeRoots(sid, roots); err != nil {
		t.Fatalf("writeRoots: %v", err)
	}
	before := filetimeNow()
	if err := touchUsed(sid); err != nil {
		t.Fatalf("touchUsed: %v", err)
	}

	if g := readDirs(sid); len(g) != 2 || g[0] != dirs[0] || g[1] != dirs[1] {
		t.Errorf("readDirs = %v, want %v", g, dirs)
	}
	gotRoots := readRoots(sid)
	if len(gotRoots) != 2 || gotRoots[0] != roots[0] || gotRoots[1] != roots[1] {
		t.Errorf("readRoots = %+v, want %+v", gotRoots, roots)
	}
	if u := readUsed(sid); u < before {
		t.Errorf("Used = %d, want >= %d", u, before)
	}

	sids, err := listSids()
	if err != nil {
		t.Fatalf("listSids: %v", err)
	}
	found := false
	for _, s := range sids {
		if s == sid {
			found = true
		}
	}
	if !found {
		t.Errorf("listSids = %v, want to contain %s", sids, sid)
	}

	// Deletion paths.
	deleteConfig(key)
	if _, ok := lookupConfig(key); ok {
		t.Error("config still present after deleteConfig")
	}
	deleteSidEntry(sid)
	if g := readDirs(sid); g != nil {
		t.Errorf("dirs still present after deleteSidEntry: %v", g)
	}
}

// TestRootRecordEncoding: fixed 12-byte records, order preserved.
func TestRootRecordEncoding(t *testing.T) {
	in := []rootRecord{{Serial: 1, FileID: 2}, {Serial: 0xFFFFFFFF, FileID: 0x0102030405060708}}
	b := encodeRoots(in)
	if len(b) != 2*rootRecordSize {
		t.Fatalf("encoded %d bytes, want %d", len(b), 2*rootRecordSize)
	}
	out := decodeRoots(b)
	if len(out) != 2 {
		t.Fatalf("decoded %d records, want 2", len(out))
	}
	if out[0] != in[0] || out[1] != in[1] {
		t.Fatalf("round trip mismatch: %+v vs %+v", out, in)
	}
}

// TestPickEvictionLRU: oldest Used wins; ties broken deterministically.
func TestPickEvictionLRU(t *testing.T) {
	entries := []sidUse{
		{sid: "s-c", used: 300},
		{sid: "s-a", used: 100},
		{sid: "s-b", used: 200},
	}
	if got := pickEviction(entries); got != "s-a" {
		t.Errorf("pickEviction = %s, want s-a (oldest)", got)
	}
	// All-zero Used (fresh entries): deterministic lowest string.
	tie := []sidUse{{sid: "s-z", used: 0}, {sid: "s-y", used: 0}}
	if got := pickEviction(tie); got != "s-y" {
		t.Errorf("pickEviction tie = %s, want s-y", got)
	}
	// Empty input.
	if got := pickEviction(nil); got != "" {
		t.Errorf("pickEviction(nil) = %q, want empty", got)
	}
}

//go:build windows

// Persistent state: one HKCU state database shared by the CLI and the
// library (unelevated => HKCU, never HKLM):
//
//	Software\srt-win
//	  Config\<hash-of-dirs>        REG_SZ       -> SID string
//	  Sids\<SID string>\Dirs       REG_MULTI_SZ -> sorted normalized dirs
//	  Sids\<SID string>\Used       REG_QWORD    -> FILETIME of last use
//	  Sids\<SID string>\Roots      REG_BINARY   -> per-root volume serial (4B)
//	                                              + NTFS file ID (8B), fixed
//	                                              12-byte records, same order
//	                                              as Dirs
//	  MsysDir                      REG_SZ       -> cached MSYS object dir name
//
// The per-root identity records are stored for every config — they are what
// makes deferred move cleanup possible. Registry entries are written only
// after the corresponding ACLs succeed.

package srtwin

import (
	"encoding/binary"
	"time"

	"golang.org/x/sys/windows/registry"
)

// regPath is the HKCU state root. A var so tests can point at a scratch
// subtree of their own.
var regPath = `Software\srt-win`

// maxConfigs is the eviction threshold (N = 8).
const maxConfigs = 8

// rootRecord is one per-root identity: volume serial + 8-byte NTFS file ID.
type rootRecord struct {
	Serial uint32
	FileID uint64
}

// rootRecordSize is the fixed REG_BINARY record width.
const rootRecordSize = 12

func encodeRoots(rs []rootRecord) []byte {
	b := make([]byte, 0, len(rs)*rootRecordSize)
	for _, r := range rs {
		var rec [rootRecordSize]byte
		binary.LittleEndian.PutUint32(rec[0:4], r.Serial)
		binary.LittleEndian.PutUint64(rec[4:12], r.FileID)
		b = append(b, rec[:]...)
	}
	return b
}

func decodeRoots(b []byte) []rootRecord {
	n := len(b) / rootRecordSize
	out := make([]rootRecord, 0, n)
	for i := 0; i < n; i++ {
		rec := b[i*rootRecordSize:]
		out = append(out, rootRecord{
			Serial: binary.LittleEndian.Uint32(rec[0:4]),
			FileID: binary.LittleEndian.Uint64(rec[4:12]),
		})
	}
	return out
}

// filetimeNow is the current time as a FILETIME (100ns ticks since 1601).
func filetimeNow() uint64 {
	const epochOffset100ns = int64(11644473600) * 10000000 // 1601-01-01 -> 1970-01-01
	return uint64(time.Now().UnixNano()/100) + uint64(epochOffset100ns)
}

func sidKeyName(sid string) string { return regPath + `\Sids\` + sid }

// lookupConfig resolves Config\<hash> to its SID string.
func lookupConfig(key string) (string, bool) {
	k, err := registry.OpenKey(registry.CURRENT_USER, regPath+`\Config`,
		registry.QUERY_VALUE)
	if err != nil {
		return "", false
	}
	defer k.Close()
	v, _, err := k.GetStringValue(key)
	if err != nil {
		return "", false
	}
	return v, true
}

// putConfig records Config\<hash> -> sid.
func putConfig(key, sid string) error {
	k, _, err := registry.CreateKey(registry.CURRENT_USER, regPath+`\Config`,
		registry.SET_VALUE|registry.QUERY_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	return k.SetStringValue(key, sid)
}

// deleteConfig removes Config\<hash> (absent is fine).
func deleteConfig(key string) {
	k, err := registry.OpenKey(registry.CURRENT_USER, regPath+`\Config`,
		registry.SET_VALUE|registry.QUERY_VALUE)
	if err != nil {
		return
	}
	defer k.Close()
	_ = k.DeleteValue(key)
}

// listSids returns every stored SID string ("" when none).
func listSids() ([]string, error) {
	k, err := registry.OpenKey(registry.CURRENT_USER, regPath+`\Sids`,
		registry.ENUMERATE_SUB_KEYS|registry.QUERY_VALUE)
	if err != nil {
		if err == registry.ErrNotExist {
			return nil, nil
		}
		return nil, err
	}
	defer k.Close()
	return k.ReadSubKeyNames(-1)
}

// touchUsed refreshes Sids\<sid>\Used to now.
func touchUsed(sid string) error {
	k, _, err := registry.CreateKey(registry.CURRENT_USER, sidKeyName(sid),
		registry.SET_VALUE|registry.QUERY_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	return k.SetQWordValue("Used", filetimeNow())
}

// readUsed returns Sids\<sid>\Used (0 when absent).
func readUsed(sid string) uint64 {
	k, err := registry.OpenKey(registry.CURRENT_USER, sidKeyName(sid),
		registry.QUERY_VALUE)
	if err != nil {
		return 0
	}
	defer k.Close()
	v, _, err := k.GetIntegerValue("Used")
	if err != nil {
		return 0
	}
	return v
}

// writeDirs stores the sorted normalized dir list for a SID.
func writeDirs(sid string, dirs []string) error {
	k, _, err := registry.CreateKey(registry.CURRENT_USER, sidKeyName(sid),
		registry.SET_VALUE|registry.QUERY_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	return k.SetStringsValue("Dirs", dirs)
}

// readDirs returns the stored dir list for a SID (nil when absent).
func readDirs(sid string) []string {
	k, err := registry.OpenKey(registry.CURRENT_USER, sidKeyName(sid),
		registry.QUERY_VALUE)
	if err != nil {
		return nil
	}
	defer k.Close()
	v, _, err := k.GetStringsValue("Dirs")
	if err != nil {
		return nil
	}
	return v
}

// writeRoots stores the per-root identity records (same order as Dirs).
func writeRoots(sid string, roots []rootRecord) error {
	k, _, err := registry.CreateKey(registry.CURRENT_USER, sidKeyName(sid),
		registry.SET_VALUE|registry.QUERY_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	return k.SetBinaryValue("Roots", encodeRoots(roots))
}

// readRoots returns the stored per-root identity records.
func readRoots(sid string) []rootRecord {
	k, err := registry.OpenKey(registry.CURRENT_USER, sidKeyName(sid),
		registry.QUERY_VALUE)
	if err != nil {
		return nil
	}
	defer k.Close()
	b, _, err := k.GetBinaryValue("Roots")
	if err != nil {
		return nil
	}
	return decodeRoots(b)
}

// deleteSidEntry removes the whole Sids\<sid> subtree.
func deleteSidEntry(sid string) {
	_ = registry.DeleteKey(registry.CURRENT_USER, sidKeyName(sid))
}

// updateSidRecord rewrites Dirs/Roots for a SID after move cleanup,
// deleting the record when no dirs remain.
func updateSidRecord(sid string, dirs []string, roots []rootRecord) {
	if len(dirs) == 0 {
		deleteSidEntry(sid)
		return
	}
	_ = writeDirs(sid, dirs)
	_ = writeRoots(sid, roots)
}

// pickEviction selects the least-recently-used SID when the config count
// reaches maxConfigs — pure function so the LRU order is unit-testable.
type sidUse struct {
	sid  string
	used uint64
}

func pickEviction(entries []sidUse) string {
	var worst string
	var worstUsed uint64
	for i, e := range entries {
		if i == 0 || e.used < worstUsed || (e.used == worstUsed && e.sid < worst) {
			worst, worstUsed = e.sid, e.used
		}
	}
	return worst
}

// msysDirName cache: srt-win owns it (no separate extension storage).
func readMsysDirCache() string {
	k, err := registry.OpenKey(registry.CURRENT_USER, regPath, registry.QUERY_VALUE)
	if err != nil {
		return ""
	}
	defer k.Close()
	v, _, err := k.GetStringValue("MsysDir")
	if err != nil {
		return ""
	}
	return v
}

func writeMsysDirCache(name string) {
	k, _, err := registry.CreateKey(registry.CURRENT_USER, regPath, registry.SET_VALUE|registry.QUERY_VALUE)
	if err != nil {
		return
	}
	defer k.Close()
	_ = k.SetStringValue("MsysDir", name)
}

//go:build windows

// Deterministic SIDs: one directory set maps to exactly one SID, forever.
//
// Normalize each writable dir (GetFullPathNameW, strip trailing
// backslashes, compare case-insensitively), sort, join with NUL, SHA-256,
// take three 32-bit little-endian words -> SID
// S-1-5-21-h1-h2-h3-0 via AllocateAndInitializeSid (identifier authority
// {0,0,0,0,0,5}, revision 1, five subauthorities: 21, h1, h2, h3, 0).
//
// Because the SID is a pure function of the dir set, ACLs and registry
// state survive across processes: the CLI and the library share one cache.

package srtwin

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// maxFullPath bounds GetFullPathNameW (extended-length path limit).
const maxFullPath = 32768

// NormalizeDir resolves dir to an absolute path with no trailing
// backslash (drive roots keep their "\"), independent of whether dir
// exists on disk.
func NormalizeDir(dir string) (string, error) {
	if dir == "" {
		return "", fmt.Errorf("srt-win: empty directory path")
	}
	in, err := windows.UTF16PtrFromString(dir)
	if err != nil {
		return "", fmt.Errorf("srt-win: %q: %w", dir, err)
	}
	buf := make([]uint16, maxFullPath)
	n, err := windows.GetFullPathName(in, uint32(len(buf)), &buf[0], nil)
	if err != nil {
		return "", fmt.Errorf("srt-win: resolve %q: %w", dir, err)
	}
	if int(n) >= len(buf) { // buffer too small: retry at the reported size
		buf = make([]uint16, int(n)+1)
		n, err = windows.GetFullPathName(in, uint32(len(buf)), &buf[0], nil)
		if err != nil || int(n) >= len(buf) {
			return "", fmt.Errorf("srt-win: resolve %q: path too long", dir)
		}
	}
	return trimTrailingSep(windows.UTF16ToString(buf[:n])), nil
}

// trimTrailingSep strips trailing backslashes but keeps a drive root
// ("C:\") and the root "\" intact.
func trimTrailingSep(p string) string {
	for len(p) > 0 && p[len(p)-1] == '\\' {
		if len(p) == 3 && p[1] == ':' { // C:\
			break
		}
		if len(p) == 1 { // \
			break
		}
		p = p[:len(p)-1]
	}
	return p
}

// NormalizeDirs normalizes every dir, drops case-insensitive duplicates,
// and sorts case-insensitively so the result is canonical: the same set of
// directories always produces the same slice regardless of spelling order,
// case, or trailing slashes.
func NormalizeDirs(dirs []string) ([]string, error) {
	seen := make(map[string]bool, len(dirs))
	out := make([]string, 0, len(dirs))
	for _, d := range dirs {
		n, err := NormalizeDir(d)
		if err != nil {
			return nil, err
		}
		k := dirKey(n)
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, n)
	}
	sort.Slice(out, func(i, j int) bool { return dirKey(out[i]) < dirKey(out[j]) })
	return out, nil
}

// dirKey is the case-insensitive comparison/hash key for a normalized dir.
func dirKey(d string) string { return strings.ToLower(d) }

// hashDirs is the SHA-256 over the sorted, lowercased dir list joined
// with NUL — the config key and the SID seed.
func hashDirs(dirs []string) [sha256.Size]byte {
	h := sha256.New()
	for _, d := range dirs {
		h.Write([]byte(dirKey(d)))
		h.Write([]byte{0})
	}
	var out [sha256.Size]byte
	copy(out[:], h.Sum(nil))
	return out
}

// configKey renders the hash as the registry Config value name.
func configKey(sum [sha256.Size]byte) string { return hex.EncodeToString(sum[:]) }

// sidSubauthorities takes the first three 32-bit little-endian words.
func sidSubauthorities(sum [sha256.Size]byte) (h1, h2, h3 uint32) {
	return binary.LittleEndian.Uint32(sum[0:4]),
		binary.LittleEndian.Uint32(sum[4:8]),
		binary.LittleEndian.Uint32(sum[8:12])
}

// sidStringForDirs renders the SID string for normalized dirs without
// touching any OS SID API — the pure-function form used by tests and the
// CLI's SID printout (the real SID object is minted by allocateSID).
func sidStringForDirs(dirs []string) string {
	sum := hashDirs(dirs)
	h1, h2, h3 := sidSubauthorities(sum)
	return fmt.Sprintf("S-1-5-21-%d-%d-%d-0", h1, h2, h3)
}

var (
	procAllocateAndInitializeSid = advapi32.NewProc("AllocateAndInitializeSid")
	procFreeSid                  = advapi32.NewProc("FreeSid")
)

// allocateSID mints S-1-5-21-h1-h2-h3-0 from the dir-set hash with
// AllocateAndInitializeSid (identifier authority {0,0,0,0,0,5}, revision
// 1, five subauthorities: 21, h1, h2, h3, 0). Free with freeSID.
func allocateSID(sum [sha256.Size]byte) (*windows.SID, error) {
	h1, h2, h3 := sidSubauthorities(sum)
	var auth windows.SidIdentifierAuthority
	auth.Value = [6]byte{0, 0, 0, 0, 0, 5}
	var psid uintptr
	r1, _, e := procAllocateAndInitializeSid.Call(
		uintptr(unsafe.Pointer(&auth)), // pIdentifierAuthority
		5,                              // nSubAuthorityCount: 21, h1, h2, h3, 0
		uintptr(21), uintptr(h1), uintptr(h2), uintptr(h3), 0,
		0, 0, 0, // s5..s7 unused
		uintptr(unsafe.Pointer(&psid)),
	)
	if r1 == 0 || psid == 0 {
		return nil, fmt.Errorf("srt-win: AllocateAndInitializeSid: %v", e)
	}
	return (*windows.SID)(ptrFrom(psid)), nil
}

// freeSID releases an allocateSID buffer.
func freeSID(sid *windows.SID) {
	if sid != nil {
		procFreeSid.Call(uintptr(unsafe.Pointer(sid)))
	}
}

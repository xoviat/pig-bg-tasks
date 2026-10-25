//go:build windows

// Move detection — for THIS SID only, run at the point of use (New):
// an ACE is only dangerous when its SID sits in a live token, and a live
// token for this SID only exists between this New and Close.
//
// For each recorded root of this SID: GetFileAttributesW.
//
//   - missing path  → open the volume (\\.\C: with desired access 0 +
//     FILE_FLAG_BACKUP_SEMANTICS), then OpenFileById with the stored file
//     ID. Success: GetFinalPathNameByHandle gives the moved location —
//     strip this SID's ACEs there and drop the path from the state DB.
//     Failure (deleted, or moved cross-volume where file IDs change):
//     just drop the path from the state DB.
//   - present path  → nothing to do (the cheap "is our ACE still there"
//     sanity check happens later when ACEs are verified).
//
// If the unelevated volume-handle open is gated, degrade gracefully: warn,
// skip ID-based detection, keep the path-existence checks.

package srtwin

import (
	"encoding/binary"
	"fmt"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

var procOpenFileById = kernel32.NewProc("OpenFileById")

// fileIdentity reads a path's volume serial (4B) and NTFS file ID (8B).
func fileIdentity(path string) (rootRecord, error) {
	h, err := windows.CreateFile(windows.StringToUTF16Ptr(path), 0,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		return rootRecord{}, err
	}
	defer windows.CloseHandle(h)
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &info); err != nil {
		return rootRecord{}, err
	}
	return rootRecord{
		Serial: info.VolumeSerialNumber,
		FileID: (uint64(info.FileIndexHigh) << 32) | uint64(info.FileIndexLow),
	}, nil
}

// volumeHint renders the \\.\X: volume path for a drive-local dir ("" for
// UNC or relative paths — those degrade to existence checks only).
func volumeHint(dir string) string {
	if len(dir) >= 2 && dir[1] == ':' {
		return `\\.\` + dir[:2]
	}
	return ""
}

// pathExists reports whether dir is present on disk.
func pathExists(dir string) bool {
	_, err := windows.GetFileAttributes(windows.StringToUTF16Ptr(dir))
	return err == nil
}

// openVolume opens the volume behind dir (desired access 0 — unelevated).
// A failure here is the spec's "volume-handle open gated" case: degrade.
func openVolume(dir string) (windows.Handle, error) {
	vol := volumeHint(dir)
	if vol == "" {
		return 0, fmt.Errorf("no local volume for %s", dir)
	}
	vh, err := windows.CreateFile(windows.StringToUTF16Ptr(vol), 0,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		return 0, fmt.Errorf("open volume %s: %w", vol, err)
	}
	return vh, nil
}

// resolveByID opens the recorded file ID on an open volume handle and
// returns the path it resolves to now. A failure here means the file is
// gone (deleted, or moved cross-volume where file IDs change).
func resolveByID(vh windows.Handle, rec rootRecord) (string, error) {
	// FILE_ID_DESCRIPTOR { dwSize; Type; union } — FileIdType (0) takes a
	// LARGE_INTEGER: the 8-byte NTFS file ID.
	desc := make([]byte, 28)
	binary.LittleEndian.PutUint32(desc[0:4], uint32(len(desc)))
	binary.LittleEndian.PutUint32(desc[4:8], 0) // FileIdType (NOT 1 = ObjectIdType)
	binary.LittleEndian.PutUint64(desc[8:16], rec.FileID)

	r1, _, e := procOpenFileById.Call(
		uintptr(vh),
		uintptr(unsafe.Pointer(&desc[0])),
		uintptr(windows.FILE_READ_ATTRIBUTES|windows.SYNCHRONIZE),
		uintptr(windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE),
		0,
		uintptr(windows.FILE_FLAG_BACKUP_SEMANTICS))
	if r1 == 0 {
		return "", fmt.Errorf("OpenFileById(%016x): %v", rec.FileID, e)
	}
	fh := windows.Handle(r1)
	defer windows.CloseHandle(fh)

	buf := make([]uint16, maxFullPath)
	n, err := windows.GetFinalPathNameByHandle(fh, &buf[0], uint32(len(buf)), 0)
	if err != nil || n == 0 || int(n) >= len(buf) {
		return "", fmt.Errorf("GetFinalPathNameByHandle: %v", err)
	}
	p := windows.UTF16ToString(buf[:n])
	p = strings.TrimPrefix(p, `\\?\`)
	p = strings.TrimPrefix(p, `\\??\`)
	return p, nil
}

// detectMoves runs move detection for this SID's recorded dirs. It
// returns warnings (degraded probes, failed ACE strips). When paths were
// dropped the state DB is rewritten; the Config entry is deleted once no
// dirs remain.
func detectMoves(sidStr string, cfgKey string, dirs []string, roots []rootRecord) []string {
	var warns []string
	keepDirs := make([]string, 0, len(dirs))
	keepRoots := make([]rootRecord, 0, len(roots))
	dropped := false

	for i, d := range dirs {
		var rec rootRecord
		if i < len(roots) {
			rec = roots[i]
		}
		if pathExists(d) {
			keepDirs = append(keepDirs, d)
			if i < len(roots) {
				keepRoots = append(keepRoots, rec)
			}
			continue
		}
		// Missing: probe the volume first (degrade gracefully when gated).
		vh, verr := openVolume(d)
		if verr != nil {
			// Volume-handle open gated: warn, skip ID-based detection, keep
			// the path-existence check (New will fail naming the dir) and
			// keep the record so a later run can retry.
			warns = append(warns, fmt.Sprintf(
				"srt-win: cannot probe moved/deleted dir %s by file ID (%v); skipping ID-based cleanup", d, verr))
			keepDirs = append(keepDirs, d)
			if i < len(roots) {
				keepRoots = append(keepRoots, rec)
			}
			continue
		}
		moved, err := resolveByID(vh, rec)
		windows.CloseHandle(vh)
		if err != nil {
			// Deleted (or moved cross-volume where file IDs change): just
			// drop the path from the state DB.
			dropped = true
			warns = append(warns, fmt.Sprintf(
				"srt-win: recorded dir %s is gone (%v); dropped from the state DB", d, err))
			continue
		}
		if moved != d {
			if err := stripSIDACE(moved, sidStr); err != nil {
				warns = append(warns, fmt.Sprintf(
					"srt-win: stripped ACEs at moved location %s failed: %v", moved, err))
			}
		}
		dropped = true
		warns = append(warns, fmt.Sprintf(
			"srt-win: recorded dir %s moved to %q; old ACEs cleaned, path dropped from the state DB", d, moved))
	}

	if dropped {
		updateSidRecord(sidStr, keepDirs, keepRoots)
		if len(keepDirs) == 0 {
			deleteConfig(cfgKey)
		}
	}
	return warns
}

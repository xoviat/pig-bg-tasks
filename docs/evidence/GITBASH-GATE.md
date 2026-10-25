> **Archived evidence (Phase-4 cleanup, 2026-10-25)** — copied from the Go repo `srt-win/`.
> Gate result (RUST-DECISION E3/E3-bis, mxc#1061): Git Bash/MSYS engines CANNOT start inside an
> MXC container — maintainer-confirmed, no config workaround. The Rust extension refuses MSYS
> shells BEFORE spawn with an actionable shellPath hint (brush.exe). The restricted-token recipe
> below is historical: srt-win is not used by this build.

# srt-win + Git Bash: the signal-pipe write-restriction wall

**Status:** root-caused empirically; worked around by widening the restricted SID
list with the **user SID** (Option 2, implemented in `token.go`, spec amended in
`SRT-WIN.md` §"Build restricted SID list"). Full CLI smoke suite passes
(34/34, incl. the Git Bash gate) with the workaround in place. This document
contains everything needed to reproduce and re-examine the problem — e.g. to
find a way to run Git Bash _without_ the widened list, or to prove that's
impossible.

---

## 1. Symptom

Running Git Bash under an srt-win sandbox died during cygwin DLL init, before
any command executed:

```
$ srt-win.exe C:\...\in -- "C:\Program Files\Git\bin\bash.exe" -c "echo BASH_OK"
       0 [main] bash] couldn't create signal pipe, Win32 error 5
      73 [main] bash] child_process_fork: couldn't create pipe
fatal error: ...
rc = 1   (no output, no files written)
```

Win32 error 5 = `ERROR_ACCESS_DENIED`. Note the failure happens in **the bash
process itself at initialization**, not in srt-win, and _not_ at
`CreateNamedPipe` — a probe that replicates `CreateNamedPipe` succeeds under the
restricted token; the **client-side `CreateFile` on the same pipe fails**.

srt-win itself works: non-cygwin children (cmd.exe, pipeprobe, PowerShell) run
fine, writes inside the granted directories succeed, `C:\Windows` writes are
denied.

---

## 2. The access-check model srt-win uses

`srt-win/token.go` mints the child token with:

```
CreateRestrictedToken(
    flags            = DISABLE_MAX_PRIVILEGE | WRITE_RESTRICTED   (0x9),
    restricted SIDs  = { Everyone S-1-1-0,
                         logon SID  S-1-5-5-0-<random>,
                         synthetic  S-1-5-21-<hash-derived>,
                         user SID   S-1-5-21-<account> }          // ← Option 2 addition
)
→ default DACL {Everyone, logon, synthetic} GA
→ DuplicateTokenEx(MAXIMUM_ALLOWED) primary
```

Windows then evaluates every access check on this token in two passes:

- **pass-1** — ordinary check: DACL allow/deny ACEs vs. the token's
  user + group SIDs (denies beat allows; unelevated-admin's `Administrators`
  group is _deny-only_, and `SYSTEM` is not in the token at all).
- **pass-2** — because `WRITE_RESTRICTED` is set, a requested access that
  includes **write**-class rights must _also_ be granted by ACEs whose trustee
  is one of the **restricted SIDs**. This is the pass that decides everything
  below: an object whose DACL grants write only to `{user, Administrators,
SYSTEM}` is unwritable when the restricted list is
  `{Everyone, logon SID, synthetic SID}` — intersection = ∅.

Reads are unaffected by pass-2 (it applies only when the requested mask
includes write).

---

## 3. The exact cygwin sequence that fails

Reference sources are checked out under `../pig-tmp/win-sandbox-spike/ref/`:

- `sigproc.cc:449-461` — during `sigproc_init` (reached from `dll_crt0`,
  i.e. before `main`), cygwin builds the signal pipe:

  ```c
  PSECURITY_ATTRIBUTES sa = sec_user_nih((PSECURITY_ATTRIBUTES)char_sa_buf,
                                         cygheap->user.sid());
  ... CreateNamedPipe(pipename, open_mode | PIPE_ACCESS_FIRST_PIPE_INSTANCE,
                      PIPE_TYPE_MESSAGE, ...);
  // pipename = \\.\pipe\msys-<installation_key>-<pid>-sigwait
  ```

- `pipe.cc:866-960` (`fhandler_pipe::create`) — immediately after the server
  instance is created, cygwin opens it **as its own client**:

  ```c
  DWORD access = GENERIC_WRITE | FILE_READ_ATTRIBUTES;   // non-duplex pipes
  *w = CreateFile(pipename, access, 0, sa_ptr, OPEN_EXISTING, ...);
  // any failure -> "couldn't create signal pipe, Win32 error %E" -> NO retry
  ```

- `sec_user_nih` (see cygwin-cvs 2002q1/002289, 2002q2/002159 patches and
  `sec_acl(acl, admins, sid1, sid2)` source excerpts) builds an **explicit**
  security descriptor — not the token default DACL, not NULL.

**Empirically observed SD of a live helper's signal pipe**
(dumped from the helper process's own handle table — see §5):

```
\Device\NamedPipe\msys-1888ae32e00d56aa-18276-sigwait
  ACE mask=0x001F01FF (GENERIC_ALL)  S-1-5-21-3779940436-1165132650-320834970-1006
  ACE mask=0x001F01FF (GENERIC_ALL)  S-1-5-32-544        BUILTIN\Administrators
  ACE mask=0x001F01FF (GENERIC_ALL)  S-1-5-18            NT AUTHORITY\SYSTEM
```

So with the original restricted list `{Everyone, logon, synthetic}`:

```
pass-2 restricted SIDs ∩ pipe DACL trustees = ∅   ⇒  CreateFile ⇒ ERROR_ACCESS_DENIED (5)
                                                   ⇒  fatal "couldn't create signal pipe"
```

---

## 4. Why the shipped pig extension works (but the spec list didn't)

The extension's spike used restricted list
`{per-process priv SID, Administrators, SYSTEM, Everyone}` (recorded in the
spike findings). That set intersects the pipe DACL via `Administrators` /
`SYSTEM`, so Git Bash runs. SRT-WIN.md's literal three-SID list
`{Everyone, logon, synthetic}` can never match `{user, Administrators, SYSTEM}`.

The Codex Windows-sandbox design (dropped for _network_ reasons only) uses the
same `CreateRestrictedToken` recipe; nothing in it addresses cygwin either.

---

## 5. Reproduction — all steps are copy-paste ready

Environment: Windows 11, Go 1.27.2, Git for Windows bash at
`C:\Program Files\Git\bin\bash.exe`, repo root = this workspace.
All diagnostics live under `../pig-tmp/` (scratch).

```bash
# 0. build
cd srt-win
gofmt -w . && go vet ./...
go test -count=1 ./
CGO_ENABLED=0 go build -o ../pig-tmp/srt-win/srt-win.exe ./cmd/srt-win
CGO_ENABLED=0 go build -o ../pig-tmp/srt-win/pipeprobe.exe ./cmd/pipeprobe

# 1. THE SYMPTOM (once token.go's user SID is removed from `sas` — i.e. the
#    original spec list — this is what you see):
SRT=$(pwd)/../pig-tmp/srt-win/srt-win.exe
IN=$(cygpath -w "$(pwd)/../pig-tmp/srt-smoke/in")
"$SRT" "$IN" -- "C:\\Program Files\\Git\\bin\\bash.exe" -c "echo BASH_OK"
#   -> "couldn't create signal pipe, Win32 error 5"

# 2. THE MECHANISM WITHOUT REVERTING ANYTHING — pipeprobe selftest2 runs the
#    exact CreateNamedPipe + client CreateFile(GENERIC_WRITE|FILE_READ_ATTRIBUTES)
#    sequence under whatever token it runs in, with three SD shapes, then dumps
#    the token state and the ACTUAL SD the kernel applied:
"$SRT" "$IN" -- ../pig-tmp/srt-win/pipeprobe.exe selftest2     # confined
../pig-tmp/srt-win/pipeprobe.exe selftest2                    # unconfined baseline
```

Expected output (observed, 2026-10):

```
UNCONFINED BASELINE
restricted SIDs: 0
token default DACL: {user GA, Administrators GA, SYSTEM GA}
== c: explicit {Everyone GA} SD ==            CreateFile: OK
== a: explicit {user GA} SD ==                CreateFile: OK        <- cygwin's shape
== b: NULL SD ==                              CreateFile: OK        (actual SD = kernel
                                                                     default pipe SD, 5 ACEs:
                                                                     SYSTEM/Admins/user GA,
                                                                     Everyone/Anonymous 0x120089)

UNDER srt-win (pre-fix list {Everyone, logon, synthetic})
restricted SIDs: 3  (S-1-1-0, S-1-5-5-0-..., synthetic)
== c: explicit {Everyone GA} SD ==            CreateFile: OK        <- mechanics fine
== a: explicit {user GA} SD ==                CreateFile: Access is denied.   <<< THE WALL
== b: NULL SD ==                              CreateFile: Access is denied.   <- kernel default
                                                                      pipe SD has no write for
                                                                      the restricted SIDs
```

**Case a under srt-win is the identical failure cygwin hits** (its SD has the
same trustees as case a's, just with two more ACEs). Case c proves the
restricted-SID/ACL machinery itself works. Case b proves a NULL
`lpSecurityAttributes` does _not_ pick up the token's default DACL for named
pipes — the kernel applies a fixed default pipe SD — so "just don't pass an SD"
is not an escape hatch.

```bash
# 3. DUMP A LIVE SIGNAL PIPE'S DACL — two ways:

# 3a. hold a sandbox open so the resident unconstrained helper (and its
#     sigwait pipe) stays alive:
"$SRT" "$IN" -- cmd //c "timeout //t 25" &
sleep 3
powershell -NoProfile -ExecutionPolicy Bypass -File ../pig-tmp/list-sigwait.ps1
#   -> msys-1888ae32e00d56aa-<pid>-sigwait   (strip CR: | tr -d '\r')

# 3b. the pipe is already connected (ERROR_PIPE_BUSY on any client open), so
#     read its SD by walking the helper's handle table and duplicating the
#     server handle (SystemExtendedHandleInformation + NtQueryObject):
../pig-tmp/srt-win/pipeprobe.exe hdls <pid> sigwait
#   -> pipe DACL: {user GA, Administrators GA, SYSTEM GA}
```

```bash
# 4. FULL REGRESSION: the CLI smoke suite (includes the Git Bash gate):
bash ../pig-tmp/srt-smoke.sh        # sections: grants, denials, git-bash, ...
```

### Debug helpers present in the repo

- `srt-win/cmd/pipeprobe` — modes: `selftest`, `selftest2`, `dump <name>`,
  `hdls <pid> <substr>`.
- `../pig-tmp/list-sigwait.ps1` — lists live cygwin signal pipes.
- `srt-win/debug_*_test.go` — `SRT_DIAG=1 go test -count=1 -run TestDebugDiag -v ./`
  (CRT flags, root DACL, OB enumeration, section pinning).
- `../pig-tmp/srt-smoke.sh` — 12-section smoke suite (write allow/deny matrix,
  move-detection ACL strip, Git Bash gate, read-only mode, …).

---

## 6. Why every non-widening fix was ruled out

| idea                                                                                   | why it fails                                                                                                                                                                                                                   |
| -------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Let cygwin pass a NULL SD                                                              | it doesn't; `sec_user_nih` is explicit. And NULL-SD pipes get a _fixed kernel default_ SD `{SYSTEM, Admins, user GA; Everyone/Anonymous read}` — still no write for `{Everyone, logon, synthetic}` (case b).                   |
| Pre-create the pipe with a good DACL before the child starts                           | cygwin opens the server with `PIPE_ACCESS_FIRST_PIPE_INSTANCE` → pre-existing name makes `CreateNamedPipe` fail with access-denied and the sigwait path has **no retry** (`if (!name) *r = NULL; break;` — name is "sigwait"). |
| Race: patch the pipe's DACL between the child's `CreateNamedPipe` and its `CreateFile` | the two calls are nanoseconds apart in the same thread; no interposition point exists from outside the child.                                                                                                                  |
| Pin/normalize the pipe DACL like the section objects                                   | same timing problem; sections work because the _helper_ creates them once in a directory srt-win can enumerate — pipes are per-child-pid, created inside the restricted child.                                                 |
| Change cygwin's SD via env/config                                                      | no such knob exists (checked `CYGRUN`/`CYGWIN` options; `sec_user_nih` is unconditional in `sigproc.cc`).                                                                                                                      |
| Hook/detour the cygwin DLL                                                             | out of scope (would require injecting into the child).                                                                                                                                                                         |

Only two real levers exist: **what SIDs are in the restricted list**, or
**what SIDs are in the pipe's DACL** — and cygwin owns the latter.

---

## 7. The fix that was applied (Option 2 vs Option 1)

Adding **the user's own SID** to the restricted list (Option 2, shipped):

```go
sas := []windows.SIDAndAttributes{
    {Sid: everyoneSID}, {Sid: logon}, {Sid: sid}, {Sid: currentUserSID()},
}
```

- Unblocks the pipe because its DACL contains the user SID.
- **Security cost:** pass-2 now also credits the user's own allow-ACEs, so
  places where the account already has standing write become writable —
  i.e. the home/profile tree (home DACL = `{user F, SYSTEM F, Administrators F}`),
  which the pig extension README already documents as an accepted gap
  ("Profile-tree write gap … and in read-only").
- Locations where the _user_ has no write of their own stay blocked, because
  pass-1 still fails: `C:\Windows`, `Program Files` (unelevated `Administrators`
  is deny-only), `SYSTEM`-only ACEs (`SYSTEM` isn't in the token).

Considered and rejected — **Option 1**: add `Administrators` + `SYSTEM`
(the extension's proven set). Also unblocks the pipe, but additionally credits
every ACE pair of _user-write ∩ Admins/SYSTEM-write_, which opens
`Users`-writable shared directories such as `ProgramData` app folders. Larger
blast radius for the same gate.

---

## 8. Open questions for the follow-up investigation

1. **Is Option 2 airtight?** Its cost is exactly "user's own ACE ⇒ writable".
   Are there user-writable locations outside the profile whose opening would
   matter more than `ProgramData` would under Option 1?
2. **Cygwin's other `sec_user`/`sec_user_nih` objects** (semaphores,
   process/thread inheritance, `fork` paths) carry the same
   `{user, Administrators, SYSTEM}` shape — Option 2 covers them via the user
   SID, but only the Git Bash gate was exercised end-to-end.
3. **Stale helpers:** repeated srt-win runs left several helper `bash`
   processes alive after the owning srt-win process exited (pids were visible
   in the sigwait-pipe list across runs). The job-object kill appears not to
   reach them — worth verifying separately (`tasklist | grep bash` after a
   run) — unrelated to the pipe wall but a real lifecycle bug.
4. **Default DACL vs pipe default:** confirm/document that
   `SetTokenInformation(TokenDefaultDacl)` has no effect on named pipes
   (kernel default pipe SD wins) — this contradicts the general
   "NULL-SD ⇒ token default DACL" rule used elsewhere in the recipe.

## 9. Key constants observed on the test machine

```
user SID          S-1-5-21-3779940436-1165132650-320834970-1006
synthetic SID     S-1-5-21-4148825835-2309231512-4233176867-0     (SHA-256 of sorted dir set)
installation key  1888ae32e00d56aa
pipe name         \\.\pipe\msys-1888ae32e00d56aa-<pid>-sigwait
OB dir            \BaseNamedObjects\msys-2.0S5-1888ae32e00d56aa
                  (shared sections: shared.5, <user-sid>.1)
```

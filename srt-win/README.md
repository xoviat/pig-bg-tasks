# Build `srt-win`: an unelevated write-restricted sandbox library + CLI for Windows

## Mission

Implement a Windows sandbox in Go (no CGO, `golang.org/x/sys/windows` for syscalls) with two surfaces over one core:

1. **A library** (`package srtwin`) whose central type is created from a directory list, privately holds a pre-minted write-restricted token, and can run many commands under it via an `os/exec`-style interface.
2. **A thin CLI** (`cmd/srt-win`) that wraps the library.

The mechanism is the same one OpenAI's Codex uses on Windows: a synthetic SID is granted write access via ACLs on whitelisted directories, and child processes run under a write-restricted token whose restricted SID list includes that synthetic SID — so the command and all its descendants can only write to the whitelisted directories. Do NOT attempt to restrict network access — out of scope entirely.

## Goal

The sandbox must, simultaneously:

1. **Restrict the entire spawned process tree** (the command and all descendants) from writing to directories not in the whitelist — kernel-enforced, unelevated, no CGO.
2. **Leave TLS/HTTPS fully functional under confinement** — any Schannel-based client (cargo, curl, PowerShell/.NET, git-over-https) must complete its handshake and fetch normally from inside the sandbox.

These are hard requirements, not a description of current behavior. (2) is known to fail today: every restricted-token design breaks Schannel's credential acquisition (`AcquireCredentialsHandle` → `SEC_E_NO_CREDENTIALS`), regardless of flags or restricted-SID list composition — see `SCHANNEL-GATE.md` for the full bisection. Treat the enforcement mechanism itself as open for redesign in service of meeting both requirements at once. Fixed constraints: kernel-enforced write restriction (not userspace filtering), whole-tree coverage, unelevated operation, no CGO, network left unrestricted.

Out of bounds: carving individual tools out of the sandbox (e.g. letting cargo run unconfined) does not satisfy (1) for that tool's process tree and is not an acceptable answer; nor is documenting the TLS failure as an accepted gap.

## Library interface (primary deliverable)

```go
package srtwin

type Sandbox struct {
    // token, SID, dirs — all private. No API exposes the token handle.
}

// New normalizes dirs, builds/verifies ACLs, runs move detection,
// and mints the restricted token ONCE. Safe to reuse for many commands.
func New(dirs ...string) (*Sandbox, error)

func (s *Sandbox) Close() error  // releases the token handle and resources

// Command mirrors exec.Command: it does not start the process.
func (s *Sandbox) Command(name string, args ...string) *Cmd

type Cmd struct {
    Path   string      // resolved via exec.LookPath at Command time (like exec.Command)
    Args   []string
    Env    []string    // nil = inherit os.Environ() — same convention as os/exec
    Dir    string      // working directory; "" = inherit
    Stdin  io.Reader
    Stdout io.Writer
    Stderr io.Writer
    // expose Process and ProcessState as *os.Process / *os.ProcessState like os/exec
}

func (c *Cmd) Run() error
func (c *Cmd) Start() error
func (c *Cmd) Wait() error
func (c *Cmd) Output() ([]byte, error)
func (c *Cmd) CombinedOutput() ([]byte, error)
func (c *Cmd) ExitCode() int    // -1 if not started/exited
```

Behavioral requirements for `Cmd`:

- Mirror `os/exec` semantics as closely as practical: `Env == nil` inherits the parent environment (this aligns with the environment-block gotcha below — build the `lpEnvironment` block from the resolved env); `Output()` captures stdout into the returned buffer; `CombinedOutput()` interleaves stderr into stdout; `Wait` is idempotent about resource cleanup; `Start` + `Wait` split works.
- Stdio plumbing follows the `os/exec` pattern: if a value is an `*os.File`, pass its handle directly to the child; otherwise create an `os.Pipe` and copy with a goroutine, waiting for the copy to finish in `Wait`. The CLI uses plain handle pass-through for stdin/stdout/stderr.
- Exit errors: return a library `*ExitError`-style type carrying the exit code, message, and stderr where applicable (`Output()`/`CombinedOutput()` should attach stderr to the error like `exec.ExitError.Stderr`). Do NOT promise type-compatibility with `*exec.ExitError` (its `*os.ProcessState` cannot be synthesized); document this.
- `Sandbox` is immutable after `New`; a single `Sandbox` must be safe for concurrent `Command`/`Run` use (the token handle is only read after `New`). If some detail makes this hard, prefer a small mutex over forbidding concurrency, and document the choice.
- One `Sandbox` = one directory set = one SID. A different dir list is a different `New`.

## CLI contract (thin wrapper over the library)

```
srt-win &lt;writable-dir&gt; [&lt;writable-dir&gt;...] [-- &lt;command&gt; [args...]]
```

- Parse dirs, call `srtwin.New(dirs...)`, `defer Close()`. **No command**: print the SID (`SID: S-1-5-21-...`), exit 0.
- **With command**: `sb.Command(name, args...)` with stdio left nil-inherited (handle pass-through), `Run()`, propagate the child's exit code (`ExitCode()`).
- The CLI must run unelevated. Never trigger or require UAC.
- All flag parsing lives in `cmd/srt-win/main.go`; no sandbox logic in the CLI package.

## Core design (library internals)

### Deterministic SIDs

- Normalize each writable dir: `GetFullPathNameW`, strip trailing backslashes, compare case-insensitively.
- Sort dirs, join with `\0`, SHA-256, take three 32-bit little-endian words → SID `S-1-5-21-h1-h2-h3` via `AllocateAndInitializeSid` (identifier authority `{0,0,0,0,0,5}`, revision 1, 5 subauthorities: `21, h1, h2, h3, 0`).
- The SID is a pure function of the dir set: same dirs → same SID, forever. This is what makes caching work.

### Persistent state: registry

Store under `HKCU\Software\srt-win` (unelevated ⇒ HKCU, never HKLM):

```
Config\&lt;hash-of-dirs&gt;          REG_SZ       → SID string
Sids\&lt;SID string&gt;\Dirs         REG_MULTI_SZ → sorted normalized dirs
Sids\&lt;SID string&gt;\Used         REG_QWORD    → FILETIME of last use
Sids\&lt;SID string&gt;\Roots        REG_BINARY   → per-root: volume serial (4B) + NTFS file ID (8B),
                                             fixed-size records, same order as Dirs
```

The per-root identity records are stored for **every** config, even rarely used ones — they are what make deferred move cleanup possible (below).

### Setup flow (runs once in `New`)

1. Parse dirs, normalize, hash → config key. Look up in `Config`. On hit: refresh the `Used` timestamp.
2. On miss: if `Sids` already holds **N = 8** entries, evict the one with the oldest `Used`:
   - For each dir in the victim's `Dirs`: read its DACL (`GetNamedSecurityInfo`), rebuild it excluding ACEs whose trustee SID equals the victim SID, write it back (`SetEntriesInAcl` + `SetNamedSecurityInfo`).
   - Delete the victim's `Sids` and `Config` entries.
   - Create the new SID and apply its ACEs.
3. **Move detection for this SID only** (section below).
4. Verify every dir passed to `New` exists; apply/refresh ACEs where missing.
5. Write/update registry entries (including per-root volume serial + file ID).
6. Mint the restricted token and store it privately in the `Sandbox`.

### Move detection — active SID only, deferred to point of use

Note: for library code, move detection should run on sandbox creation.

An ACE is only dangerous when its SID is in a live token, and a live token for this SID only ever exists between this `New` and `Close`. Detection is therefore deferred to setup time: run it for this SID only, never for other stored configs.

For each recorded root of this SID: `GetFileAttributesW`.

- **Missing path** → open the volume (`\\.\C:` with desired access 0 + `FILE_FLAG_BACKUP_SEMANTICS`), then `OpenFileById` with the stored file ID.
  - Success: `GetFinalPathNameByHandle` gives the moved location — strip this SID's ACEs there, drop the path from the registry config (delete the config entry if no dirs remain).
  - Failure (deleted, or moved cross-volume where file IDs change): just drop the path from the registry.
- **Present path**: a cheap sanity check that our ACE is still on the DACL is a plus but optional.

Must complete in milliseconds. If the unelevated volume-handle open proves gated in testing, degrade gracefully: print a warning, skip ID-based detection, keep the path-existence checks.

Note: a cache hit means the recorded dirs are exactly the dirs passed to `New` (same hash). So a "moved" dir also means a passed dir that doesn't exist — after cleanup, fail with a clear error naming the missing dir. Do not silently retarget to the moved location; the caller's dir list is authoritative.

### Applying ACEs

For each writable dir, merge grant ACEs into the existing DACL (never replace it): `EXPLICIT_ACCESS` with `GENERIC_WRITE | GENERIC_EXECUTE | DELETE`, `GRANT_ACCESS`, `OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE`, trustee = the synthetic SID. Read `GetNamedSecurityInfo` first and pass the existing DACL to `SetEntriesInAcl` so unrelated entries are preserved.

### Token creation (private)

1. `OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &tok)`.
2. Query `TokenLogonSid` (changes every logon — the token is minted once per `New`; document that a `Sandbox` must not be reused across logoff/logon).
3. Build restricted SID list: `Everyone` (`S-1-1-0`), the logon SID, the synthetic SID, and **the user's own SID** (owner of the process), all with attributes 0.

   The user SID is required for Git Bash: cygwin creates its signal pipe with an explicit security descriptor `{user, Administrators, SYSTEM}` (from `sec_user_nih`), and the write-restricted pass-2 check only evaluates restricted SIDs. Without the user SID in the list, cygwin's own `CreateFile(GENERIC_WRITE)` client open on that pipe is denied and bash dies during DLL init (`couldn't create signal pipe, Win32 error 5`). Full analysis and reproduction steps: `srt-win/GITBASH-GATE.md`. The cost is the already-documented profile-tree gap: locations where the user's own ACE grants write (home directory and profile) become writable, exactly as they are for the extension.

   Known inherent limitation of the restricted list (any list, not just this one): Schannel credential acquisition fails with `SEC_E_NO_CREDENTIALS`, breaking all OS-TLS HTTPS (cargo, curl, PowerShell/.NET). Bisection and evidence: `srt-win/SCHANNEL-GATE.md`.

4. `CreateRestrictedToken(tok, DISABLE_MAX_PRIVILEGE | WRITE_RESTRICTED, 3, sids, 0, NULL, 0, NULL, &rTok)`. (`CreateRestrictedTokenW`, `SetEntriesInAclW`, `OpenFileById`, and `GetFileInformationByHandleEx` may need `LazyProc` via `windows.NewLazySystemDLL` — use careful unsafe pointer handling and `UTF16PtrFromString` throughout.)
5. Store `rTok` in the private `Sandbox` field. Reusing one token handle across many `CreateProcessAsUserW` calls is valid — that is the entire point of the library API.

### Spawning (per `Cmd.Start`)

- `CreateProcessAsUserW` with the sandbox's private token.
- `STARTUPINFOW` with `STARTF_USESTDHANDLES`; std handles resolved per the os/exec-mirroring rules above (*os.File → handle directly, else pipe + copier goroutines). Ensure any handle passed to the child is inheritable (`GetHandleInformation`; `DuplicateHandle` with `bInheritHandle = TRUE` when it isn't).
- **`lpEnvironment` must be a hand-built block from the resolved `Cmd.Env`** (`strings.Join(env, "\x00") + "\x00\x00"`) with the `CREATE_UNICODE_ENVIRONMENT` flag. Passing NULL gives the child a bare system environment — this is the single most common way this kind of tool breaks (PATH lost, `python` not found). Add a test that the child sees e.g. `USERPROFILE`.
- `bInheritHandles = TRUE`. Use `PROC_THREAD_ATTRIBUTE_HANDLE_LIST` if convenient so only the intended handles are inherited; plain TRUE is acceptable, document the choice.
- `lpCurrentDirectory`: `Cmd.Dir` if set.
- `WaitForSingleObject` in `Wait`; populate `ProcessState`/exit code; close token-per-process handles (the shared sandbox token handle is NOT closed per command — only in `Sandbox.Close`).

## Hard requirements

- Works fully unelevated. If any step unexpectedly requires elevation, fail loudly with a clear message rather than half-applying state.
- The token is private: no exported identifier exposes a `windows.Token`/handle, and no API returns one.
- All filesystem/registry mutations must be crash-safe-ish: write registry entries only after the corresponding ACLs succeed; on failure mid-apply, attempt best-effort rollback of ACEs already applied.
- Path handling is UTF-16 throughout; no `string`↔ANSI conversions.
- Idempotent: two `New` calls with the same dirs must not duplicate ACEs or registry entries, and the second must be fast (&lt;100ms when ACLs are already correct).

## Documented limitations (README, don't "fix")

- Directories whose DACL grants `Everyone` write access remain writable by sandboxed children (because `Everyone` is in the restricted SID list). `Users`/`Authenticated Users` grants do not leak.
- Cross-volume moves/copies with preserved ACLs (e.g. `robocopy /COPYALL`) can orphan ACEs, but only for configs that aren't currently in use; they are cleaned (via `OpenFileById`) the next time that config's `New` runs, before its token is minted, and are never exploitable in the meantime. Same-volume moves are cleaned immediately.
- Setup (ACLs, move detection) is validated in `New`, not continuously: if a whitelisted dir is moved/deleted after `New`, behavior degrades accordingly until the next `New`. This is deliberate — detection runs at the point of use, and use begins in `New`.
- A `Sandbox` is tied to the logon session that created it (the token embeds that session's logon SID); do not persist a `Sandbox` across logoff.
- GUI apps spawned under the token may fail with a window-station error; this tool targets headless/piped commands.
- The library's exit error is not type-compatible with `*exec.ExitError`.

## Deliverables

- Go module, `go build ./...` clean, CGO disabled. Suggested layout:
  - root package `srtwin`: `sandbox.go`, `sid.go`, `registry.go`, `acl.go`, `token.go`, `cmd.go`, `moved.go`
  - `cmd/srt-win/main.go`: flag parsing and exit-code propagation only
- Unit tests (Windows, `go test`): normalization+hash determinism (same dirs → same SID string; case/trailing-slash variants → same), registry round-trip, eviction LRU selection, env-block builder, Cmd env resolution (nil → os.Environ).
- Integration tests or documented manual smoke tests: via the CLI — `srt-win &lt;tmpdir&gt; -- cmd /c "echo hi &gt; ok.txt"` succeeds; `srt-win &lt;tmpdir&gt; -- cmd /c "echo hi &gt; &lt;otherdir&gt;\no.txt"` fails with access denied; `srt-win &lt;tmpdir&gt;` with no command exits 0 and prints the SID; re-run is idempotent; rename a whitelisted dir, re-invoke `srt-win` with the same dir argument, confirm the run fails with a clear "missing dir" error AND the old SID's ACEs get stripped at the renamed location. Via the library — one `New`, then `Command` runs `echo`, `go version`, and a write-outside-whitelist probe; a second run reusing the same `Sandbox` still blocks the probe.

## Acceptance criteria

- [ ] CLI: `srt-win A B -- cmd /c echo ok` runs unelevated, exit code matches child
- [ ] Library: child can write inside whitelisted dirs, cannot write outside them (incl. `%USERPROFILE%`, `%TEMP%`), verified across multiple `Command` calls on one `Sandbox`
- [ ] Grandchild processes (e.g. `cmd /c cmd /c write`) still blocked outside whitelisted dirs
- [ ] Second `New` with the same dirs applies no duplicate ACEs and completes in &lt;100ms
- [ ] Eviction at 8 configs strips victim ACEs and removes registry entries
- [ ] `Cmd` with nil `Env` gives the child the parent environment (PATH, USERPROFILE visible)
- [ ] `Output()`/`CombinedOutput()`/exit-code error behavior matches os/exec conventions
- [ ] No exported API exposes the token handle
- [ ] README documents all listed limitations

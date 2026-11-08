# pig-bg-tasks (Rust)

**[`pi-bg-tasks`](https://www.npmjs.com/package/pi-bg-tasks), but in Rust + sandbox.**

[`pi-bg-tasks`](https://www.npmjs.com/package/pi-bg-tasks) (npm) is the lightweight background-bash
extension for PiG — `run_in_background`, timeout auto-background, `Ctrl+Shift+B`, completion
notifications ([source](https://github.com/cyzlmh/pi-extensions/tree/main/pi-bg-tasks)). This repo
is that extension rewritten in Rust against the PiG Rust SDK, **plus a permission sandbox**: every
bash spawn can be confined in a Microsoft eXecution Container ([mxc](https://github.com/microsoft/mxc),
via `mxc-sdk` 1.0.1 on crates.io) instead of running bare.

**What the sandbox adds over `pi-bg-tasks`:**

- **One composed `bash` tool** — sandbox params (`sandbox_permissions`, `justification`) and bg
  params (`run_in_background`, `timeout`, `description`) in a single tool with one execute path.
  Every spawn — foreground, quick-window, background — goes through the same spec builder; the only
  unconfined path is an explicit `danger-full-access`.
- **Permission modes** with fail-closed confinement, denial-first escalation and denial
  classification ([below](#how-the-sandbox-works)).
- **`/sandbox [mode]`** — inspect or switch the mode process-wide.

**Scope: bash only.** write/edit belong to a separate permission-system extension and are never
intercepted. **Network is always allowed** (no isolation). Threat model: fat-finger protection for a
non-malicious model — not adversarial isolation.

**Platform status: Windows is implemented and accepted end-to-end** (gates E1–E10 + R11 in
`RUST-DECISION.md`, smoke matrix 14/14, acceptance runs in `TESTING.md`). Linux/macOS runners are
deferred: off-Windows, confined calls fail closed with a message naming the deferral;
`danger-full-access` still runs bare.

## Install / develop

```bash
cargo test                            # 101 tests: 87 unit + 14 smoke — single crate
pig install . --validate-only --json                # cell build + registration check
PIG_HOME=<scratch-home> pig -ne -e "$(pwd)" -p      # piped-prompt run
```

Rules that are easy to get wrong (full recipe: **`TESTING.md`**):

- **The directory name is the extension identity** — a `-e <dir>` selection registers under the
  directory's name, and the factory registers `pig-bg-tasks`; a mismatch fails with
  `register:name_mismatch`. Hence the extension root is this directory itself, with the crate's
  `Cargo.toml`, `src/` and `tests/` at the top level.
- **`-ne` always** (skip ambient extensions — npm `pi-bg-tasks` registers the same tool names) with
  an explicit `-e`.
- **`pig-sdk` is never in `Cargo.toml`** (no `[patch]` either): pig resolves it at cell-build time
  into its own state dir. `.cargo/config.toml` carries a path patch for plain `cargo` runs only —
  machine-local, never shipped.
- **Freeze the tree during pig builds** (content-hash check) and warm the cell with
  `--validate-only` before timed piped runs (cold cell ≈ 9 min, warm ≈ 60 s).

## Tools

| tool | notes |
|---|---|
| `bash` | composed: sandbox params (`sandbox_permissions`, `justification`) + bg params (`run_in_background`, `timeout`, `description`). Denial-first escalation. 2 s quick-completion window (then live streaming); timeout auto-background (default 120 s) is **interactive-only** — in print/RPC the command runs out. |
| `bg_list` | running first, then recent terminal (lazy eviction of notified jobs). |
| `bg_output` | meta + last 32 KiB + log path; latches the completion notification. |
| `bg_stop` | Job-object terminate (whole tree) + bounded wait; latches silently first, returns real outcome. |

Commands: `/sandbox [mode]` (process-wide, with completions), `/bg`, `/bg-tasks`.
Shortcut: `Ctrl+Shift+B`. Message renderer: `<task-notification>` (one `● summary` line).
Steering (Enter mid-stream) auto-backgrounds running foreground commands.

Notifications are **exactly-once** via a check-and-set latch before send: any path that already
surfaced the outcome (`bg_output`/`bg_stop`, deliberate kill) suppresses it; a failed send is lost,
never retried. **User-initiated stops emit zero notifications by design.** Delivery is
`deliverAs=steer, triggerTurn=true` through a retained SDK context.

Logs: `%TEMP%\pi-bg-tasks\<taskId>.log` (the temp root is inside the workspace-write grant — a
confined child writes its own log). Bare spawns are fd-direct (kernel moves the bytes); confined
mxc spawns pump piped stdout/stderr into the same log. Cap 64 MiB with auto-kill; `session_start`
sweeps logs older than 24 h; `session_shutdown` silently kills everything (Job objects guarantee no
orphans, even on hard extension death).

## How the sandbox works

### Permission modes

| mode | file effects (Windows, mxc per-spawn policy) |
|---|---|
| `read-only` | zero writable roots: writes denied everywhere (workspace, `%TEMP%` included); `C:\` readable |
| `workspace-write` (default) | workspace + host `%TEMP%` + default home dirs (`~/go`, `~/AppData/Local/Packages`, `~/.cargo`, `~/.rustup`) + `extraWritableDirs` writable; `C:\` read-only; everything else denied on write |
| `danger-full-access` | bare spawn (explicit escape hatch) — `runner: bypassed`, OS ACLs only |

Mode switching is **`/sandbox [mode]`**: with no args it shows the mode, the writable set, resolved
env, epoch and runner status; switching installs the process-wide override and bumps an epoch — the
next bash call binds it synchronously.

### Per-spawn confinement through mxc

Each confined spawn builds its own `ContainerRequest` (`runner::request::build_request` →
`mxc_sdk::v1::spawn`) and starts a **fresh mxc ProcessContainer** — there is no long-lived sandbox:

1. **Filesystem**: `readwrite_paths` = the converged write roots, `readonly_paths` = `C:\`,
   `denied` empty, `clear_policy_on_exit`.
2. **Network**: egress + ingress + host loopback allowed (posture: no network isolation).
3. **UI**: `disable=false` — console init needs win32k on this host.
4. **Environment**: inherits the default env, plus `LC_ALL` emptied / `LC_MESSAGES=C` (stable denial
   classification) and the resolved PATH; `GH_TOKEN` is injected in `workspace-write` only
   (see *Known limits*).
5. **Engine**: the shell resolved from pig's `shellPath` setting (then `$SHELL`, the standard Git
   for Windows locations, and `bash` on PATH — see [Git Bash](#why-git-bash-needs-a-patch));
   `timeout_ms=0`, so the extension's own timers govern.
6. **Tree kill**: every spawn joins a Windows Job object with `KILL_ON_JOB_CLOSE` — `bg_stop`,
   session shutdown, and hard extension death take the whole tree (terminate on Windows is
   immediate; no SIGTERM).

### No standing grants (per-call convergence)

Each bash call binds the newest mode **epoch** inside its own duration (resolve → validate →
record); policy is rebuilt per spawn (~37 ms baseline) and cleared on exit — no background thread,
no persistent container. Failures are causal and fail-closed (`SANDBOX_UNAVAILABLE …` with the real
cause): never bare, never half-applied. Full invariant list: **`CONVERGENCE.md`**.

### Escalation (denial-first, bash only)

`sandbox_permissions` (`workspace-write` | `danger-full-access`) + `justification`:

- a **strictly wider** request is honored only after a real, unconsumed sandbox denial of the same
  subject this session — otherwise the fields are **ignored** (the result carries
  `[sandbox: escalation fields were ignored …]`);
- one denial buys exactly **one** escalation retry;
- the approval prompt is **Deny / Allow once** (Deny first); no UI (headless/print/subagent) ⇒
  fail-closed refusal, nothing executed — the message tells the model to work in the writable roots
  or ask the user to run `/sandbox danger-full-access` in the main session;
- placeholder `"null"`/blank values are stripped before schema validation; approval covers one call.

### Denial classification (English-only)

Non-zero exit + a signature in the merged log tail ⇒ real denial →
`[sandbox: file access denied under <mode> mode]` + escalation hint + ledger record. Signatures:
`access is denied`, `access to the path`, `permission denied`, `operation not permitted`,
`write-protected`, `read-only file system`.

A runner failure (the command **never ran**) ⇒ `SANDBOX_UNAVAILABLE …` refusal instead — shell
unresolvable, or the container spawn itself failed. A missing marker on a localized Windows is a
classification gap, not a confinement failure.

### Config — `<configRoot>/agent/sandbox.json`

Global only (`~/.pig/agent/sandbox.json`); project-level files are **ignored silently** (the project
is model-writable). Fields: `mode`, `probeTimeoutMs` (default 5000), `extraWritableDirs` (`~`
expanded, must exist, warned+dropped if invalid). Corrupt/missing ⇒ defaults. Read once per process
(restart to pick up changes). The shell comes from pig **`settings.json`** (`shellPath`), not from
`sandbox.json`.

**Default writable dirs** in `workspace-write`: four home-derived extras beyond workspace and
`%TEMP%` — `~/go` (default `GOPATH`), `~/AppData/Local/Packages` (per-app package data, including
mxc's own confinement dirs), `~/.cargo` (`CARGO_HOME`: registry caches, extracted crates, `bin` —
so sandboxed `cargo build` works) and `~/.rustup` (toolchain store). The user folder is resolved at
runtime (never hardcoded); a missing candidate is skipped silently, and `extraWritableDirs` **adds**
to these defaults rather than replacing them.

### Known limits (partial enforcement)

- **Reads are unconfined by design** (broad `C:\` read rule; the threat model is fat-finger writes).
- **The Windows Credential Manager is blocked inside the container**: `CredReadW`/
  `CredEnumerateW` return `ERROR_ACCESS_DENIED` for every target, so `gh` (whose token lives only
  in the keyring) sends no `Authorization` header → 401, and `git credential fill` fails too.
  Mitigation: `workspace-write` spawns get `GH_TOKEN` in their env (host `GH_TOKEN`/`GITHUB_TOKEN`
  first, else a host-side keyring read — the pig host process is outside the container, where the
  vault is readable). Read-only spawns stay tokenless; nothing is fabricated when no token exists.
- **`ping` (ICMP) fails in-container** (`Unable to contact IP driver`); native tools otherwise run.
  Use `powershell -NoProfile -Command "Start-Sleep N"` for long confined tasks.
- **No persistent containers**: policy is rebuilt per spawn instead of held for a session.
- **POSIX runners are deferred** (build-only; confined path fails closed off-Windows) and denial
  classification is English-only.

## Why Git Bash needs a patch

Git Bash (Git for Windows, <https://gitforwindows.org/>) is the usual shell for this extension —
but it is a **Cygwin/MSYS runtime**: bash and every child it forks share `msys-2.0.dll`'s
in-memory world (cygheap, named objects, pipes). The sandbox runs that shell inside an **mxc
ProcessContainer** — an AppContainer whose security model differs from a normal logon session —
and the stock runtime assumes the latter. Inside the container the stock `msys-2.0.dll` fails in
three ways (root-caused in the fork's [`STATUS.md`](https://github.com/xoviat/cygwin/blob/mxc/STATUS.md)
and [`FORK_FAILURES.md`](https://github.com/xoviat/cygwin/blob/mxc/FORK_FAILURES.md)):

1. **World-only object ACEs** — `_everyone_sd` grants access to World (S-1-1-0) only, but
   AppContainer processes are not covered by "Everyone": opens need an ALL APPLICATION PACKAGES
   (S-1-15-2-1) ACE. Without it `cygwin_pid()` fails, `fork()` returns 0, and both halves of a
   pipeline run the same command.
2. **Named objects and pipes** — absolute NT pipe names and session-namespace objects are denied or
   invisible in-container (named pipes die with `0xC00000B1`, `echo: write error`).
3. **Same-address fork vs. the container** — the runtime reserves its cygheap at a fixed address
   (`0x800000000`), which fails intermittently under the container, and mxc force-relocates images
   that have not opted into ASLR — breaking Cygwin's same-address fork: children die `0xC0000142`
   with `fork: retry: Resource temporarily unavailable`.

All three are fixed in the winsup layer of **<https://github.com/xoviat/cygwin>** (the Cygwin fork
carrying the mxc patches) and shipped as a **drop-in `msys-2.0.dll`** — you do not build anything.

### Install the patched Git Bash

1. Install **Git for Windows** (<https://gitforwindows.org/>) — default root `C:\Program Files\Git`.
2. Download `msys-2.0.dll`, `install.ps1` and `uninstall.ps1` from the latest release
   (<https://github.com/xoviat/cygwin/releases>, currently **`v0.4.0`**, 2026-11-03; the
   `cygwin1.dll` / `new-cygwin1.dll` assets are for a Cygwin tree, not needed for Git Bash) into
   one directory.
3. From an **elevated** PowerShell in that directory:

   ```powershell
   powershell -ExecutionPolicy Bypass -File install.ps1                    # default Git root
   powershell -ExecutionPolicy Bypass -File install.ps1 -GitRoot 'D:\Git'  # non-default root
   ```

4. Point pig's `shellPath` (in `settings.json`, NOT `sandbox.json`) at that install's `bash.exe`.

Notes:

- The script swaps `{usr\bin,bin}\msys-2.0.dll` (originals kept as `msys-2.0.dll.stock`) **and**
  opts every PE image in the install into ASLR — mandatory under mxc, whose force-relocation of
  non-ASLR images breaks Cygwin's same-address fork (`0xC0000142`). `-SkipPeFlags` skips the sweep
  (fine outside the sandbox, not inside it).
- Safe to re-run as an update; `uninstall.ps1` reverts the DLL and the PE flags from the manifest.
- Gate in the fork: `tools/final-verify.sh` → `RESULT: 14 passed, 0 failed` ("git bash works inside
  the mxc sandbox").

## License

MIT (ported sources MIT; see upstream packages).

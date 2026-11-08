# pig-bg-tasks (Rust)

One PiG extension combining two ports (MIT), now implemented **in Rust** against the PiG Rust SDK —
this workspace is the rewrite of the Go `pig-bg-tasks` extension per `RUST-PLAN.md`, with the
decision record in `RUST-DECISION.md` and the test recipe in `TESTING.md`:

- **bg layer** ← [pi-bg-tasks](https://github.com/cyzlmh/pi-extensions/tree/main/pi-bg-tasks): background bash tasks, registry, notifications, `Ctrl+Shift+B`, `/bg`, `/bg-tasks`
- **sandbox layer** ← [pi-sandbox](https://github.com/yandy/pi-packages/tree/main/pi-sandbox): permission modes, config, escalation, denial classification, confinement runner
- **confinement** ← Microsoft eXecution Containers via `mxc-sdk` (crates.io, pinned `1.0.1`) — the
  Go build's `srt-win` restricted-token layer was **not** ported and is not present in this repo.

Both packages override the built-in `bash` tool upstream; composed here into **one `bash` tool** with
one execute path. Every spawn — foreground, quick-window, `run_in_background` — goes through the same
spec builder; the only unconfined path is explicit `danger-full-access`.

**Scope: bash only.** write/edit belong to a separate permission-system extension and are never
intercepted. **Network is always allowed** (no isolation). Threat model: fat-finger protection for a
non-malicious model — not adversarial isolation.

**Platform status: Windows is implemented and accepted end-to-end** (MXC containment; gates E1–E10 +
R11 in `RUST-DECISION.md`, smoke matrix 14/14, acceptance runs through real `pig -ne -e -p` sessions
in `TESTING.md`). Linux (bwrap/landlock) and macOS (seatbelt) **runners** are deferred; the POSIX
side of the runner is behind the same `Kind`/`Enforcement` seam. On non-Windows hosts confined calls
fail closed with a message naming the deferral; `danger-full-access` still runs bare.

**The crate itself is cross-platform** (gate 2026-10-25): `cargo check --target
x86_64-unknown-linux-gnu --all-targets` is clean; the `windows` crate (job objects,
`CREATE_NO_WINDOW`) lives under `[target.'cfg(windows)'.dependencies]` with a POSIX fallback (bare
backend kills the direct child — see Honest gaps); `mxc-sdk` is cross-platform upstream (its own
Windows deps are target-gated), so no isolation-layer fork was needed.

## Install / develop

```bash
cargo test                            # 101 tests: 87 unit (bg/policy/runner/classify/escalate) + 14 smoke — single crate
cargo check --target x86_64-unknown-linux-gnu --all-targets   # cross-platform gate (rustup target add first)
pig install . --validate-only --json                # cell build + registration check
PIG_HOME=<scratch-home> pig -ne -e "$(pwd)" -p      # piped-prompt run
```

Rules that are easy to get wrong (full recipe: **`TESTING.md`**):

- **The directory name is the extension identity** — a `-e <dir>` selection registers under the
  directory's name, and the factory registers `pig-bg-tasks`; a mismatch fails with
  `register:name_mismatch`. Hence the extension root is this directory itself — the repo root
  `~/workspace/pig-bg-tasks` — with the crate's `Cargo.toml`, `src/` and `tests/` at the top level.
- **`-ne` always** (skip ambient extensions — the npm/Go `pi-bg-tasks` has the same tool names) with
  an explicit `-e`.
- **`pig-sdk` is never in `Cargo.toml`** (no `[patch]` either): pig resolves it at cell-build time
  into its own state dir. `.cargo/config.toml` carries a path patch for plain
  `cargo` runs only — machine-local, never shipped.
- **Freeze the tree during pig builds** (content-hash check) and warm the cell with
  `--validate-only` before timed piped runs (cold cell ≈ 9 min, warm ≈ 60 s).

## Prerequisites: shell engine + userland

Two things are NOT bundled with the extension — install/point to them yourself:

### 1. Bash engine — **brush** (pinned for tests)

Any bash reachable via pig's `shellPath` runs (Git Bash included); the engine
tested and pinned throughout this repo is a native Win32 bash:

- **Project**: [reubeno/brush](https://github.com/reubeno/brush) — "Bo(u)rne RUsty SHell";
  site/install docs: [brush.sh](https://brush.sh/getting-started/install/).
- **Install**: `cargo install brush` — crates.io: [`brush`](https://crates.io/crates/brush)
  (alias of [`brush-shell`](https://crates.io/crates/brush-shell); both provide `brush.exe`).
  Alternates proven in the gate battery: `niubash` (→ `niu.exe`), rubash (→ `bash.exe`).
- **Tested here**: `brush 0.4.0` at `%USERPROFILE%\.cargo\bin\brush.exe` — set pig's
  `shellPath` (in `settings.json`, NOT `sandbox.json`) to that path.

### 2. Userland applets — **busybox-w32** (`sed`, `grep`, `awk`, …)

Brush has no builtin `sed`, so external utilities come from BusyBox-w32 (native Win32, 179 applets in the build used here):

- **Project**: [frippery.org/busybox](https://frippery.org/busybox/) (busybox-w32 by Ron
  Yorston); source mirrors: [GitHub rmyorston/busybox-w32](https://github.com/rmyorston/busybox-w32),
  [GitLab](https://gitlab.com/rmyorston/busybox-w32).
- **Download the binaries**: the prebuilt index → **<https://frippery.org/files/busybox/>**
  (`busybox64.exe` builds, `SHA256SUM` alongside).
- **The exact build used here**: `BusyBox v1.38.0-FRP-6075-g169694ebd (2026-05-06)` (mingw64),
  kept at `pig-tmp/shell-candidates/busybox64.exe` (test hosts).
- **The `ubin/` folder is not a special distribution**: it is 16 *byte-identical copies* of that
  one binary renamed per applet (BusyBox dispatches on `argv[0]`):

  ```text
  awk cat cut diff find grep head ls mkdir ps sed sh sort tee wc xargs
  ```

  Rebuild anywhere with:

  ```bash
  mkdir ubin
  for a in awk cat cut diff find grep head ls mkdir ps sed sh sort tee wc xargs; do
    cp busybox64.exe "ubin/$a.exe"
  done
  ```

  More applets = another rename (the binary contains all 179).
- **Wire it up**: point pig's `userlandDir` setting at the directory, or drop the files at
  `<configRoot>/agent/userland` (auto-detected fallback). `bg_debug`'s `userland:` line and
  `command -v sed` inside a call confirm resolution. Extension-side auto-shipping is the one
  open sub-question (`RUST-PLAN.md` §10.7).

### 3. Git Bash — patched runtime from <https://github.com/xoviat/cygwin>

Any bash reachable via pig's `shellPath` runs, and the usual choice on Windows is **Git Bash**
(Git for Windows, <https://gitforwindows.org/>). The **stock** `msys-2.0.dll`, however, fails
inside the mxc ProcessContainer (AppContainer ACE, named-object namespace, pipe and fork failures —
root-caused in the fork's [`STATUS.md`](https://github.com/xoviat/cygwin/blob/mxc/STATUS.md) and
[`FORK_FAILURES.md`](https://github.com/xoviat/cygwin/blob/mxc/FORK_FAILURES.md)).

**<https://github.com/xoviat/cygwin>** is the Cygwin/winsup fork carrying those fixes; its releases
ship the patched runtime DLLs plus the installer. Install Git Bash patched for this sandbox:

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

4. Point pig's `shellPath` (in `settings.json`, not `sandbox.json`) at that install's `bash.exe`.

Notes:

- The script swaps `{usr\bin,bin}\msys-2.0.dll` (originals kept as `msys-2.0.dll.stock`) **and**
  opts every PE image in the install into ASLR — mandatory under mxc, whose force-relocation of
  non-ASLR images breaks Cygwin's same-address fork (`0xC0000142`). `-SkipPeFlags` skips the sweep
  (fine outside the sandbox, not inside it).
- Safe to re-run as an update; `uninstall.ps1` reverts the DLL and the PE flags from the manifest.
- Gate in the fork: `tools/final-verify.sh` → `RESULT: 14 passed, 0 failed` ("git bash works inside
  the mxc sandbox"). Source builds go through `tools/ci/apply-to-msys.sh` → the pinned msys2-runtime
  → `tools/ci/build-runtime-dll.sh`; the DLLs are also CI artifacts on every workflow run.

## Tools

| tool | notes |
|---|---|
| `bash` | composed: sandbox params (`sandbox_permissions`, `justification`) + bg params (`run_in_background`, `timeout`, `description`). Denial-first escalation. 2 s quick-completion window (then live streaming); timeout auto-background (default 120 s) is **interactive-only** — in print/RPC the command runs out (ported guard). |
| `bg_list` | running first, then recent terminal (lazy eviction of notified jobs). |
| `bg_output` | meta + last 32 KiB + log path; latches the completion notification. |
| `bg_stop` | Job-object terminate (whole tree) + bounded wait; latches silently first, returns real outcome. |

Commands: `/sandbox [mode]` (process-wide, with completions), `/bg`, `/bg-tasks`.
Shortcut: `Ctrl+Shift+B`. Message renderer: `<task-notification>` (one `● summary` line).
Steering (Enter mid-stream) auto-backgrounds running foreground commands.

Notifications are **exactly-once** via a check-and-set latch before send: any path that already
surfaced the outcome (`bg_output`/`bg_stop`, deliberate kill) suppresses it; a failed send is lost,
never retried. **User-initiated stops emit zero notifications by design** (Go
`TerminateJobSilently` parity). Delivery is `deliverAs=steer, triggerTurn=true` through a retained
SDK context (SDK D19).

Logs: `%TEMP%\pi-bg-tasks\<taskId>.log` (the temp root is inside the workspace-write grant — a
confined child writes its own log). Bare spawns are fd-direct (kernel moves the bytes); confined
MXC spawns pump piped stdout/stderr into the same log (documented divergence). Cap 64 MiB with
auto-kill; `session_start` sweeps logs older than 24 h; `session_shutdown` silently kills everything
(Job objects guarantee no orphans, even on hard extension death).

## Permission modes

| mode | file effects (Windows, MXC per-spawn policy) |
|---|---|
| `read-only` | zero writable roots: writes denied everywhere (workspace, `%TEMP%` included); `C:\` readable |
| `workspace-write` (default) | workspace + host `%TEMP%` + default home dirs (`~/go`, `~/AppData/Local/Packages`, `~/.cargo`, `~/.rustup`) + `extraWritableDirs` writable; `C:\` read-only; everything else denied on write |
| `danger-full-access` | bare spawn (explicit escape hatch) — `runner: bypassed`, OS ACLs only |

Mode switching is **`/sandbox [mode]`**: with no args it shows mode, writable set, resolved env,
epoch and runner status; switching installs the process-wide override and bumps an epoch — the next
bash call binds it synchronously (see `CONVERGENCE.md`).

## Convergence — synchronous, per spawn (`CONVERGENCE.md`)

No background thread and no standing grants: each bash call **binds the newest epoch inside its own
duration** (resolve → validate → record) and confined spawns carry their own `ContainerRequest`
filesystem policy with `clear_policy_on_exit`. E13 dropped persistence deliberately (no
lifecycle-capable backend exists for the spawn-capable container); the epoch/session seam stays for a
future backend. Failures are causal and fail-closed (`SANDBOX_UNAVAILABLE …` with the real cause),
never bare, never half-applied. Full invariant list: `CONVERGENCE.md`.

## Config — `<configRoot>/agent/sandbox.json`

Global only (`~/.pig/agent/sandbox.json`); project-level files are **ignored silently** (the project
is model-writable). Same schema as the reference: `mode`, `probeTimeoutMs` (default 5000),
`extraWritableDirs` (`~` expanded, must exist, warned+dropped if invalid; entries covering the agent
dir are **warned but kept**), `runnerCommand`/`runnerFailureSignatures` (parsed for parity,
**ignored** with a warning). Corrupt/missing ⇒ defaults. Read once per process (restart to pick up
changes).

**Default writable dirs** (documented divergence from the reference, whose list is empty): four
home-derived extras are always granted in `workspace-write` — `~/go` (default `GOPATH`),
`~/AppData/Local/Packages` (per-app package data, including MXC's own `sandbox.{…}`/`mxcprobe`
confinement dirs), `~/.cargo` (default `CARGO_HOME` — cargo's download cache `registry/cache`/`index`/`git`,
the extracted crate dirs `registry/src`/`git/checkouts`, and `bin`, so sandboxed `cargo build` with
dependencies works), and `~/.rustup` (default `RUSTUP_HOME` toolchain store, so toolchain/component
resolution during a build stays in-sandbox). The user folder is resolved at runtime (never
hardcoded); a missing candidate (e.g. no `~/go`) is skipped silently, and a configured
`extraWritableDirs` **adds** to these defaults rather than replacing them.

Engine and userland come from pig **settings** (not `sandbox.json`):

- `shellPath` — the bash engine (where to get it: **Prerequisites §1** — brush,
  `cargo install brush`). The configured path wins over every fallback (PATH,
  standard Git-for-Windows locations), so the engine is pinned exactly.
- `userlandDir` — a busybox-applet directory (`sed`, `grep`, `awk`, `wc`, `find`, `sort`, …)
  prepended to the child PATH in confined **and** bare spawns (brush has no built-in
  `sed`). Fallback: a drop-in `<configRoot>/agent/userland` directory.
  `bg_debug` shows the resolved `userland:` line. **Where the binaries come from and how `ubin/`
  is built: Prerequisites §2** (frippery.org busybox-w32). Shipping strategy for fresh installs is
  the one open sub-question (`RUST-PLAN.md` §10.7).

## Escalation (denial-first, bash only)

`sandbox_permissions` (`workspace-write` | `danger-full-access`) + `justification`:

- a **strictly wider** request is honored only after a real, unconsumed sandbox denial of the same
  subject this session — otherwise the fields are **ignored** (result carries
  `[sandbox: escalation fields were ignored …]`);
- one denial buys exactly **one** escalation retry;
- approval prompt is **Deny / Allow once** (Deny first); no UI (headless/print/subagent) ⇒
  fail-closed refusal, nothing executed — the message tells the model to do the work in the writable
  roots or ask the user to run `/sandbox danger-full-access` in the main session;
- placeholder `"null"`/blank values are stripped before schema validation; approval covers one call.

## Denial classification (English-only)

Non-zero exit + signature in the merged log tail ⇒ real denial →
`[sandbox: file access denied under <mode> mode]` + escalation hint + ledger record. Signatures:
`access is denied`, `access to the path`, `permission denied`, `operation not permitted`,
`write-protected`, `read-only file system`.

Runner failures (command **never ran**) ⇒ `SANDBOX_UNAVAILABLE …` refusal: shell unresolvable, or the
container spawn itself failing. A
missing marker on a localized Windows is a classification gap, not a confinement failure.

## Windows runner — the MXC recipe

Per confined spawn (`runner::request::build_request` → `mxc_sdk::v1::spawn`), evidence in
`RUST-DECISION.md` (gates E1–E10, R11; battery in E3-bis):

1. **Filesystem**: `readwrite_paths` = converged write roots, `readonly_paths` = `C:\`, `denied`
   empty, `clear_policy_on_exit` — E4/E5 gates measured the read rule (0.16 s broad read; profile
   writes denied under `workspace-write`).
2. **Network**: egress + ingress allow, host loopback allow — README product posture, network always
   allowed.
3. **UI**: `disable=false` — console init needs win32k on this host (E8 quirk).
4. **Environment**: `inherit_default_environment` (E8: PATH requires it) + our entries: `LC_ALL`
   emptied, `LC_MESSAGES=C` (classification stability), userland PATH prepend; bare mode uses
   Go-parity `mergeEnv` semantics. **`GH_TOKEN` under `workspace-write` only** (`runner::creds`) —
   the gh-CLI fix, see *Honest gaps*.
5. **Engine**: bash pinned by settings `shellPath` (brush);
   `timeout_ms=0` (extension timers govern); explicit `working_directory` (E8 quirk).
6. **Tree kills**: every spawn joins a Job object with `KILL_ON_JOB_CLOSE` — `bg_stop`, session
   shutdown, and hard extension death take the whole tree (no SIGTERM on Windows: terminate is
   immediate).

### Honest gaps (partial enforcement)

- **Reads are unconfined by design** (broad `C:\` read rule; threat model is fat-finger writes).
- **The Windows Credential Manager is blocked in-container** (measured, gh 2.82.1): `CredReadW` /
  `CredEnumerateW` return `ERROR_ACCESS_DENIED` (5) for **every** target under MXC containment,
  while the same calls succeed outside it. gh stores its token only in the keyring (`hosts.yml`
  has no `oauth_token`), so `gh` inside a confined spawn sends no `Authorization` header → 401,
  and `gh auth login` cannot repair it from inside either (the vault write is denied too).
  `git credential fill` fails the same way (`Failed to enumerate credentials. [0x5]`). Mitigation
  (`runner::creds`, **workspace-write only**): the spawn env gets `GH_TOKEN` — host env
  `GH_TOKEN`/`GITHUB_TOKEN` first, else a host-side keyring read of `gh:github.com:<user>` (active
  user from gh's `hosts.yml`; the pig host process is outside the container, where the vault is
  readable). Read-only spawns stay tokenless; `danger-full-access` reads the vault natively. Not
  injected when no token exists anywhere — pass-through, never fabrication.
- **`ping` (ICMP) fails inside the container** — `Unable to contact IP driver. General failure.` —
  the driver is not exposed to the container. Native tools otherwise run (E2 battery: cmd,
  PowerShell, curl/schannel, rustup…); use `powershell -NoProfile -Command "Start-Sleep N"` for long
  confined tasks. `ping` works in bare mode.
- **No persistent containers (E13 drop)**: policy is rebuilt per spawn (~37 ms E8 baseline) instead
  of held for a session; the seam is retained for a future backend.
- **POSIX is build-only, not run-ready**: the crate compiles and unit/smoke tests are portable, but
  the confined path is runtime-gated to `Kind::Unavailable` (fail-closed with the deferral message;
  `danger-full-access` runs bare). Without job objects, the POSIX bare backend kills the **direct
  child only** — whole-tree kill on Unix (process groups) lands with the deferred POSIX runner.
- **Userland provisioning is manual** (`userlandDir`/drop-in dir) until the shipping strategy in
  `RUST-PLAN.md` §10.7 lands.
- Classification is English-only; the bash-call trace file (`%TEMP%\pi-bg-tasks\bash-calls.jsonl`)
  is machine-wide — concurrent pig sessions share it (match by `id`/`ts`, see `TESTING.md`).

## Divergences from the references (summary)

- Native Win32 bash engine **external and settings-pinned** (brush via `shellPath`) instead of
  in-process or PowerShell-only.
- One composed `bash` tool; confinement is container policy, not command-text wrapping (no
  `unwrap.ts`).
- Classification reads the **merged log tail**; confined spawns reach it through userspace pipe
  pumps, bare spawns are fd-direct.
- Timeout auto-background / Ctrl+Shift+B / steer / status pill are interactive-only (print mode runs
  commands out — ported guard); `/sandbox` execution is a TUI affordance (registration + completions
  are validated; the toast is invisible in `-p`).
- Escalation subject vocabulary is `command` only; subagent escalation *forwarding* is not ported —
  headless/subagent escalations fail closed and name the `/sandbox` route in the main session.
- Config path under PiG's config root; `srt-win` does not exist in this repo.

## Acceptance results (this machine, Windows 11)

Full recipe, observed outputs, and traps: **`TESTING.md`**. Summary (all real pig runs,
2026-10-25): `pig install . --validate-only --json` → `valid: true`,
`registered: true`, `packable: true`, tools `[bash, bg_list, bg_output, bg_stop, bg_debug]`, commands
`[bg, bg-tasks, sandbox]` ✓; `cargo test` 101/101 ✓ (smoke matrix 14/14 incl. confined
echo, profile-write denial + classification, read-only denial, schannel HTTPS, busybox userland,
parallel spawns, whole-tree kill, epoch bind); piped-prompt acceptance: confined
`echo` (`HARNESS_OK`), userland `sed`/`grep`/`awk`/`wc` with `command -v sed` → `…\ubin\sed`,
denial marker + escalation hint, headless escalation refusal (and the ignore-note branch), git
clone+verify (`octocat/Hello-World`), bg lifecycle (start text, `Running (1)`, `bg_output` running,
`bg_stop` → `killed` "whole tree"), `danger-full-access` bare (`ping` 2/2 + `BARE_OK`, `runner:
bypassed`) ✓. Not covered: interactive-only UI (`Ctrl+Shift+B`, steer hint/pill, timeout
promotion, `/sandbox` execution in TUI), localized-OS classification, POSIX platforms.

## Relation to the Go implementation

This workspace replaces the Go extension; the full Go reference (extension, `internal/`, `srt-win/`,
`PLAN.txt`, npm patch notes) is preserved untouched at `~/workspace/pig-bg-tasks`. Phase-4 cleanup
removed every Go-era artifact from this repo (`RUST-PLAN.md` §9, executed 2026-10-25); the only
imported evidence lives in `docs/evidence/` — the two gate reports behind `RUST-DECISION.md`, with
headers recording their outcome for this build.

## License

MIT (ported sources MIT; see upstream packages).

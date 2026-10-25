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
R11 in `RUST-DECISION.md`, smoke matrix 15/15, acceptance runs through real `pig -ne -e -p` sessions
in `TESTING.md`). Linux (bwrap/landlock) and macOS (seatbelt) runners are deferred; the POSIX side of
the runner is behind the same `Kind`/`Enforcement` seam. On non-Windows hosts confined calls fail
closed with a message naming the deferral; `danger-full-access` still runs bare.

## Install / develop

```bash
cargo test --workspace                  # 103 tests (bg/runner/policy/escalate/classify + smoke)
pig install ./pig-bg-tasks --validate-only --json   # cell build + registration check
PIG_HOME=<scratch-home> pig -ne -e "$(pwd)/pig-bg-tasks" -p   # piped-prompt run
```

Rules that are easy to get wrong (full recipe: **`TESTING.md`**):

- **The directory name is the extension identity** — a `-e <dir>` selection registers under the
  directory's name, and the factory registers `pig-bg-tasks`; a mismatch fails with
  `register:name_mismatch`. Hence this workspace lives in `pig-bg-tasks/`.
- **`-ne` always** (skip ambient extensions — the npm/Go `pi-bg-tasks` has the same tool names) with
  an explicit `-e`.
- **`pig-sdk` is never in `Cargo.toml`** (no `[patch]` either): pig resolves it at cell-build time
  into its own state dir. `pig-bg-tasks/.cargo/config.toml` carries an absolute-path patch for plain
  `cargo` runs only — machine-local, never shipped.
- **Freeze the tree during pig builds** (content-hash check) and warm the cell with
  `--validate-only` before timed piped runs (cold cell ≈ 9 min, warm ≈ 60 s).
- Requires a native Win32 shell engine: `cargo install brush`, then `shellPath` →
  `…\.cargo\bin\brush.exe`, plus a `userlandDir` (below).

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
| `workspace-write` (default) | workspace + host `%TEMP%` + `extraWritableDirs` writable; `C:\` read-only; everything else denied on write |
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

Engine and userland come from pig **settings** (not `sandbox.json`):

- `shellPath` — the bash engine. Confined spawns **refuse MSYS/Git-Bash engines before spawn**
  (mxc#1061: the MSYS object namespace is denied under MXC; no config works around it) with an
  actionable hint: `cargo install brush` and point `shellPath` at `%USERPROFILE%\.cargo\bin\brush.exe`.
- `userlandDir` — a busybox-applet directory (`sed`, `grep`, `awk`, `wc`, `find`, `sort`, …)
  prepended to the child PATH in confined **and** bare spawns (host Git tools are MSYS and die under
  MXC; brush has no built-in `sed`). Fallback: a drop-in `<configRoot>/agent/userland` directory.
  `bg_debug` shows the resolved `userland:` line. Shipping strategy for fresh installs is the one
  open sub-question (`RUST-PLAN.md` §10.7).

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

Runner failures (command **never ran**) ⇒ `SANDBOX_UNAVAILABLE …` refusal: shell unresolvable, MSYS
engine detected (fail-fast with the `shellPath` fix), or the container spawn itself failing. A
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
   Go-parity `mergeEnv` semantics.
5. **Engine**: external native Win32 bash pinned by settings `shellPath` (brush), MSYS fail-fast
   pre-spawn; `timeout_ms=0` (extension timers govern); explicit `working_directory` (E8 quirk).
6. **Tree kills**: every spawn joins a Job object with `KILL_ON_JOB_CLOSE` — `bg_stop`, session
   shutdown, and hard extension death take the whole tree (no SIGTERM on Windows: terminate is
   immediate).

### Honest gaps (partial enforcement)

- **Reads are unconfined by design** (broad `C:\` read rule; threat model is fat-finger writes).
- **`ping` (ICMP) fails inside the container** — `Unable to contact IP driver. General failure.` —
  the driver is not exposed to the container. Native tools otherwise run (E2 battery: cmd,
  PowerShell, curl/schannel, rustup…); use `powershell -NoProfile -Command "Start-Sleep N"` for long
  confined tasks. `ping` works in bare mode.
- **MSYS engines cannot run inside the container** (mxc#1061, maintainer-confirmed) — this is why
  `shellPath` must name a native engine; Git Bash is rejected *before* spawn, and userland applets
  must be native (busybox), not Git's `/usr/bin`.
- **No persistent containers (E13 drop)**: policy is rebuilt per spawn (~37 ms E8 baseline) instead
  of held for a session; the seam is retained for a future backend.
- **Userland provisioning is manual** (`userlandDir`/drop-in dir) until the shipping strategy in
  `RUST-PLAN.md` §10.7 lands.
- Classification is English-only; the bash-call trace file (`%TEMP%\pi-bg-tasks\bash-calls.jsonl`)
  is machine-wide — concurrent pig sessions share it (match by `id`/`ts`, see `TESTING.md`).

## Divergences from the references (summary)

- Native Win32 bash engine **external and settings-pinned** (brush via `shellPath`) instead of
  in-process or PowerShell-only; MSYS engines refused up front instead of dying in-container.
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
2026-10-25): `pig install ./pig-bg-tasks --validate-only --json` → `valid: true`,
`registered: true`, `packable: true`, tools `[bash, bg_list, bg_output, bg_stop, bg_debug]`, commands
`[bg, bg-tasks, sandbox]` ✓; `cargo test --workspace` 103/103 ✓ (smoke matrix 15/15 incl. confined
echo, profile-write denial + classification, read-only denial, schannel HTTPS, busybox userland,
MSYS fail-fast, parallel spawns, whole-tree kill, epoch bind); piped-prompt acceptance: confined
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

# RUST-DECISION — Phase 0 gate results and verdict

Plan: [RUST-PLAN.md](RUST-PLAN.md) §3. One row per gate, observed on the target
machine class (Windows 11 build 26300, this dev box), against a pinned MXC.

## Pin (open question §10.1)

| item | value |
|---|---|
| `microsoft/mxc` rev | `05a430bc17a3e1b3fa2131524fc52e4319e07298` (cloned into `pig-tmp/mxc/`, gitignored scratch) |
| `mxc-sdk` | crates.io **1.0.1** (matches the cloned workspace version; pinnable by exact version) |
| toolchain | repo pins Rust **1.93** (`rust-toolchain.toml`); built fine with installed 1.97.1 |
| executor | `wxc-exec.exe` built locally: `cargo build -p wxc --features isolation_session --release` (3 m 17 s) |
| pig Rust scaffold | `pig extension init --lang rust` → staged SDK `sdk-rs-d8f02d83c091a8c1`; `pig-sdk = "0.1.0"` resolved by pig at build time |

Probe configs and logs: `pig-tmp/gates/` (e1…e8, e2-sspi, e4/e5 write/read matrices).

## Gate results

| # | Gate | Result | Observed evidence |
|---|---|---|---|
| E1 | Tier probe | **PASS — T1** | `wxc-exec --probe` → `"tier": "base-container"`, `baseContainerApiPresent: true`, `baseContainerSupportsDenyPaths: true`, `needsDaclAugmentation: false` (T3 fallback **not** engaged; `bfscfgPresent: false` ⇒ T2 compiled out, as predicted). Basic contained `cmd /c echo` → `TIER_PROBE_OK`. |
| E2 | Schannel / TLS | **PASS — all four** | Inside one container (network allow, `ui.disable:false`): `curl.exe` (schannel) → **200**; `powershell Invoke-WebRequest` → **200**; `cargo fetch` → **exit 0** (needs `inheritDefaultEnv:true` + `.cargo`/`.rustup` grants); `pig-tmp/sspiprobe` → `AcquireCredentialsHandle(SSP/Negotiate/Kerberos/NTLM) = 0` + cert/CryptoAPI OK, **byte-identical to the outside control**. `SEC_E_NO_CREDENTIALS` does **not** occur on T1. |
| E3 | Git Bash matrix | **FAIL — product decision required (see below)** | Every MSYS/Cygwin binary (`bash.exe`, `dash.exe`) exits `STATUS_DLL_INIT_FAILED (0xC0000142)`. Diagnosed as upstream **microsoft/mxc#1061**: `msys-2.0.dll` → `NtCreateDirectoryObject(\BaseNamedObjects\msys-2.0S5-…)` → `0xC0000022`; maintainer reply: *not a policy/config problem*, needs MSYS fix + OS namespace virtualization; **no config workaround exists** (verified: `ui.disable:false`, relaxed `ui.isolation`, `captureDenials` audit-allow mode all still fail). Native `git.exe` **works** under the container: `git status`/`rev-parse`/diff in this repo all correct (the one earlier "not a git repository" was my config omitting `cwd` — backend default is not the caller's dir; with explicit `cwd` everything passes; `.gitconfig` unread until the profile read grant is added). `cmd.exe` full matrix ✓. Related **mxc#1464** (DOS path resolution) did not bite any git operation exercised here with explicit `cwd`. |
| E4 | Read matrix | **PASS with delta** | System paths (`C:\Windows\…\hosts`, `C:\Windows\notepad.exe`) and HKCU registry read **ambient with zero grants**. The whole `C:\Users\…` + `ProgramData` trees are **denied without a grant** — mxc#1533's "reads remain readable" does **not** hold for user trees on T1 ⇒ "reads ambient" is re-scoped as: *ambient for system paths; profile reads need an explicit `fs_read_only` grant*. File **opens** under a scoped grant work; **directory enumeration** under scoped grants is denied (drive-root grant enumerates). A single `readonlyPaths: ["C:\\"]` grant makes opens **and** enumeration work everywhere (git, `dir`, type). |
| E5 | Grant cost | **PASS** | Full `fs_read_only = ["C:\\"]` grant: **0.16 s** per container run (create-and-run, cold policy build) — no ACL walk, no 527 s wedge; scoped workspace+temp set equally fast. **Inverted assertions verified**: with `readwritePaths=[workspace]`, `readonlyPaths=[C:\]` → `PROFILE_WRITE=DENIED`, `ROOT_WRITE=DENIED`, `WS_WRITE=OK` — the srt-win profile-tree write gap **closes**. |
| E6 | Elevation audit | **PASS** | Zero UAC prompts across every probe in this session; `--probe` and all container runs are unelevated; no host-prep step was required for `processcontainer` on this build. |
| E7 | PiG Rust parity | **PASS (API surface)** | Scaffold builds + `pig install --validate-only` → `registered: true`, `form: factory`, `factory: new_extension`, `packable: true`, `runtime: subprocess`, commands listed (cold build 3 m 34 s). Every checklist item exists in the staged SDK: tool registration w/ schema + `exposure`, `command` + `command_argument_completions`, `shortcut`, `message_renderer`, `config_home`, `on_event(session_start/session_shutdown/input)`, `notify`, `get_settings`, `cwd`, `execute_tool`, `set_active_tools`, `abort`, retained contexts (`Context: Clone` shares connection — unit-tested in SDK), `send_message(trigger_turn, deliver_as)` for `deliverAs=steer, triggerTurn=true`. **Remaining for Phase 2:** live end-to-end steer round-trip inside a real `pig` session. |
| E8 | Spawn probe | **PASS** | Standalone crate `pig-tmp/e8-spawn` on `mxc-sdk 1.0.1`: streamed marker in **37 ms** (Start/Wait split), grandchild `powershell` observed alive (baseline-diff counting), `kill()` mid-run → `TerminateJobObject` tree kill → wait **39 ms**, **0 leftover processes** vs baseline, `run()` exit code **42** round-trips. Caveats discovered (record, not blockers): ICMP fails inside the container (`Unable to contact IP driver`; TCP fine — E2), `start /b` fails inside the container, batch execution needs a read grant on `C:\` (cmd probes it), env needs `inheritDefaultEnv:true` or `PATH`/rustup vanish. |
| E9 | Pinning | **PASS** | `mxc-sdk = "1.0.1"` exact-pin on crates.io; schema contract versioned (`schemas/stable/…1.0.0.json` + documented dev `1.1.0-alpha`); full changelog/`docs/schema.md` readable at the pinned rev. |
| E10 | Build probe | **PASS** | Rust scaffold load/build via pig: cold **3 m 34 s**, warm (later rebuilds) seconds; documented `cargo`/`rustup` prerequisite is present on this machine. Requirement = stock `rustup` toolchain + crates.io on cold cache (pig's own docs state this). |
| R11 | Profile/state hygiene | **PASS (T1)** | T1 uses no AppContainer profiles (`needsDaclAugmentation: false` — profile store untouched); no `wxc-wsb`/mxc state dirs left after ~20 container runs; the `HKCU\Software\srt-win` key seen is pre-existing state from the **old Go extension**, not created by MXC. T3 `DaclManager` state not exercised (T3 never selected). |

## E3-bis: native bash candidates (spun off the model-performance concern)

The E3 failure is **msys-2.0.dll's** object-namespace access, not "non-PowerShell
shells" per se: **every** Git Bash binary (`bash.exe`, `sh.exe`, `ls.exe`,
`grep.exe`, `sed.exe` — all verified `msys-2.0.dll` importers) dies under MXC,
while **native Win32 binaries run fine** (native `git.exe`, `curl.exe` proven in
E2/E3). So the replacement must be a **native-Win32 shell *and* userland**.

Candidates tested inside the container (configs `pig-tmp/gates/e3-busybox64`,
`e3-brush*`, battery scripts `pig-tmp/shell-candidates/`):

| candidate | what | result under MXC |
|---|---|---|
| **busybox-w32** (MinGW, 64-bit; the 32-bit build fails `CreateProcessW` 623 under T1) | native ash shell + **179 native applets** (ls/grep/sed/awk/sort/…) | model-idiom battery **28/30** (both deltas are test-harness bugs: identical score outside the container = 29/30 w/ same harness bug); spawns native `git`/`cmd`/`curl` children ✓, schannel 200 ✓. Bashisms: `[[ ]]`, `<()`, `pipefail`, `${v/a/b}` ✓; **no arrays, no brace expansion, no `shopt`** |
| **brush 0.4.0** (`brush-shell` crate, Rust; Windows CI-tested upstream, `brush-core` embeddable) | bash/POSIX-compatible shell, 2 500+ upstream compat tests | launches ✓; model battery **29/30** (= control outside container; 1 delta = harness bug); deep bashism suite **39/41** (arrays ✓ assoc ✓ braces ✓ ranges ✓ herestrings ✓ `for((;;))` ✓ traps ✓ — gaps: `<()` fd-redirection unsupported on Windows, `. /dev/null`, `select` parse) |
| **brush + busybox userland** (busybox applet copies on `PATH`: sh/ls/grep/sed/…) | shell + tools, all native | model battery **29/30** — byte-identical to the unconfined control |
| **rubash 1.4.3 / niubash 1.4.4** (Rust; rubash = byte-level GNU Bash 5.3 compat verified against GNU's own 83-suite corpus — its `--version` even reports `GNU bash, version 5.3.20(1)-release`; Windows-first, no POSIX emulation layer, explicitly a Git-Bash/MSYS2 replacement; niubash = rubash engine + winuxcmd, self-described "AI-native bash shell for Windows"; ships a drop-in `bash.exe` + `niu.exe`) | native bash engine | model battery **29/30** each (= control); deep bashism suite **41/42** each — incl. `<()` process substitution, `select`, `source`, assoc arrays; the sole fail is my harness bug (real Git Bash also yields `i=11` for `let i=1; i+=1`, so the expected value `2` was wrong — all three engines match bash exactly). Without a native userland on PATH the engines still parse/execute (40/42) but child tools like `diff` resolve to MSYS binaries and die — confirming **the userland must be native too** |

**Conclusion:** the model-performance concern has a native-Win32 answer —
bash-syntax shells exist that run under T1 unchanged. This adds **E3 option 3**
to the product decision below.

Fidelity ranking on the deep suite (42 tests; the one universal "fail" is a
harness bug — real bash behaves identically): **rubash = niubash 41/42 (42/42
corrected) > brush 39/42**. Follow-up 60-feature matrix with real Git Bash as
oracle (run-matrix over features.tsv) pinned brush's exact gaps:

| brush gap (vs rubash, all verified vs bash oracle) | brush failure mode | rubash/niubash | model-output frequency |
|---|---|---|---|
| process substitution `<(...)` / `>(...)` | runtime error "operation not supported on this platform: fd redirections" — script continues | full support (rc matches bash) | **moderate** (`diff <(git show …)`) — the one models actually emit |
| `select` statement | **parse-fatal: kills the whole script** (line 2 syntax error; nothing runs) | works (bash-consistent) | rare (interactive menus) |
| namerefs `declare -n` / `local -n` | **silently wrong** — `-n` ignored, `ref` holds `"x"` not `5`, no error | correct | rare in one-shot commands |
| dynamic fd `exec {fd}>&1` | runtime "invalid redirection target" — continues | works | rare |
| `read -t` timed read | "poll-based timeout is not supported on this platform" — continues | works | occasional (watch loops) |
| `source /dev/null` | "failed to source file: /dev/null" — continues | works | rare (the far more common `cmd 2>/dev/null` **works** in brush) |
| `command_not_found_handle` | rc=127 | **also missing in rubash/niubash** — only real bash has it | effectively never |

Non-gaps (checked): brush parses `extglob` where bash `-c` and rubash both
syntax-error (brush is *more* permissive there); array_slice/prefix_keys/
subst_prefix/globstar "fails" reproduce in real bash (harness bugs).

Fidelity ranking on the deep suite
All three tie at 29/30 on the model-idiom battery (= unconfined control).
Supply note: rubash/niubash are young (13★) but self-measured against GNU's own
test corpus; brush is the most established (2 270★, upstream users incl. Zed).
PATH note: rubash installs `bash.exe` into `~/.cargo/bin` — on this machine Git's
bash precedes it, but a user with cargo first would silently get rubash as
`bash`; the extension must pin its shell by absolute path regardless.

## E3 product decision (RUST-PLAN §8 — blocks Phase 1)

MSYS shells (Git Bash) are unusable under MXC on every tier, by upstream design
of the AppContainer object namespace (mxc#1061). Two allowed paths:

1. **Accept the gap, steer to PowerShell/cmd** (plan §3 example delta).
   Confined spawns use `cmd.exe`/`powershell.exe` (both verified working,
   including schannel TLS and native `git.exe`). The composed `bash` tool keeps
   its name/schema but resolves to a non-MSYS shell under confinement.
   *Keeps the plan's "delete srt-win" end state intact.*
2. **Hybrid** — MXC default + legacy restricted-token spawn only for cygwin
   shells. Preserves Git Bash fidelity; keeps a sliver of `srt-win` alive and
   delays deletion past Phase 4 (explicitly allowed by §8, must be named here).

3. **Native bash** (new, from E3-bis) — ship a native-Win32 bash engine as the
   confined shell: **rubash/niubash** (highest measured fidelity: 41/42 w/ only
   a harness-bug fail; drop-in `bash.exe`; designed for exactly this niche) or
   **brush** (most established upstream; 39/42), plus a native userland
   (busybox-w32 applets proven 179-deep, or Microsoft's Rust `coreutils` as
   brush's README recommends). The model keeps writing bash; every spawn stays
   MXC-native; srt-win still dies. Costs: pin/monitor a young third-party
   shell (E9-style pinning), provision shell+tools (E10-style), and document
   each engine's compat deltas.

**Recommendation: option 3, fallback option 1.** The model-performance concern
is legitimate — models are trained on bash idioms, and PowerShell/cmd is a
measurably different language (different pipelines, test syntax, quoting,
aliases), which surfaces as failed commands and retries in agent loops. Option
3 removes that regression entirely: all three engines score **identically
inside and outside the container** on both batteries. It keeps the plan's end
state (delete srt-win) and avoids the hybrid's two-mechanism cost. Engine pick
(amended by the architecture addendum below): **brush as the external shell
binary** — on Windows pig's existing `shellPath` setting points at `brush.exe`
(installed by users with `cargo install brush`, version pinned in the README);
`niubash`/`rubash` remain drop-in alternates for the same setting (measured
fidelity strictly higher — see the gap table and deep-suite ranking above),
then option 1;
busybox-w32 applets as the userland in every case. Option 1 (steer to
PowerShell) remains the fallback if shipping a third-party shell is
operationally unacceptable.

## Addendum — architecture directives (2026-10-24, after the verdict)

Two directives amend the plan; both add gates and neither changes the
verdict:

1. **Shell engine: external binary configured via pig's `shellPath`**
   (supersedes the same-day embed proposal — embedding `brush-core` in the
   extension was considered and dropped). The extension keeps reading the
   `shellPath` settings key (the Go extension already does this: settings →
   `runner.SetConfiguredShell`, configured path wins over every fallback); on
   Windows users point it at `brush.exe` and install it with
   `cargo install brush` (README documents the exact tested version). No
   in-process engine, no tokio coexistence risk, no `--shell-host` self-launch
   mode — those gates (E12/E14) are struck from the plan; the E3-bis gap
   table stays exactly as the external-brush behavioral contract.
2. **One container per epoch; bash not persistent.** Source-confirmed in the
   pinned crate (`mxc-sdk = "1.0.1"` + repo rev `05a430bc`): `v1::container::
   {provision_container, start_container, spawn_in_container,
   run_in_container, stop_container, deprovision_container}` — plus an
   official `run-in-persisted-container` sample — and
   `ExecutionRequest{working_directory, environment,
   inherit_default_environment, timeout_ms}` per task. Design: the container
   is provisioned + started once per policy epoch, and **all bash tasks of
   that epoch run in that container** via `spawn_in_container`; only the
   container persists — each bash task is one fresh `brush.exe -c …` process
   living exactly as long as the task (fresh shell state, today's semantics).
   Epoch bump ⇒ provision+start the new container, old one drains its
   in-flight tasks, then stop + deprovision — matching CONVERGENCE.md's
   "in-flight calls are unaffected". E13 is therefore no longer an
   availability gate; it validates *behavior*: sibling-kill scope in a
   shared container (1.0.1 docs say both "Kill the child" and "Kill the
   container process tree" — decisive for `bg_stop`), 8-way concurrency,
   provision+start cost (bears on the <100 ms flip criterion; lazy
   provisioning is the fallback), drain-on-flip, and 20-cycle hygiene —
   recording Windows bench numbers as reference only (E8 baseline 37 ms;
   the performance goal is cross-platform and no other platform is
   measurable now).
   **Final directive (2026-10-24): persistence is the default.** Use the API
   if it is not too difficult; if behavior differences or disproportionate
   complexity appear, drop it (E13 surfaces those early; the per-task
   job-object wrapper is pre-authorized). When dropped: per-command
   `v1::spawn` containers through the same seam, unchanged semantics.

Confirmations (2026-10-24): (a) retire-then-drain on epoch flip — old
container keeps its tasks running to completion, then stop + deprovision;
(b) if MXC's kill proves container-wide, wrapping each task's tree in our own
Windows job object is **pre-authorized** — no further sign-off needed before
using it; (c) `danger-full-access` runs outside any container (plain
unconfined spawn, today's contract).

New gate (spec in plan §3): **E13** persistence spike — API availability is
source-confirmed, so the gate validates behavior: sibling-kill isolation
(`bg_stop` must not take the epoch down), 100 sequential + 8 concurrent
in-container `brush.exe -c` spawns, provision+start cost, epoch-flip-with-
inflight drain, 20-cycle hygiene; bench numbers recorded as Windows
reference (never a drop trigger alone). No Phase 1 porting before its
results are appended here.

### E13 results (2026-10-24; spike `pig-tmp/e13-persist`, log `pig-tmp/e13-run.log`)

**Verdict: PERSISTENCE DROPPED** — behavior difference, the pre-registered
trigger. Observed:

- `provision_container(IsolationSession + FilesystemPolicy)` fails at the SDK
  boundary: `malformed_request: IsolationSession state-aware provision does
  not accept filesystem policy` (the spike's run, phase A).
- Source verification (repo rev `05a430bc` + crates.io `mxc-sdk-1.0.1`): the
  IsolationSession backend **rejects filesystem policy at every phase** —
  `backends/isolation_session/common/policy.rs`: "Filesystem policy (rw, ro,
  denied) is rejected at every phase … the backend installs no persistent
  filesystem enforcement"; one-shot `spawn(IsolationSession + fs)` is refused
  with `ErrorCode::PolicyValidation` (upstream test
  `one_shot_refuses_an_unhonorable_policy_as_policy_validation`);
  `ExecutionRequest` and every lifecycle options struct carry no fs knob.
- The gated backend has no lifecycle at all: state-aware dispatch falls
  through to `unsupported_phase: backend ProcessContainer does not implement
  state-aware lifecycle` — persistence for the backend that passed E1–E5/E8
  does not exist.
- The only fs-capable lifecycle backend is WindowsSandbox: experimental
  full-VM (`require_experimental_optin`), and its fs model maps host dirs
  "at the same path" — host `readonlyPaths=["C:\\"]` (the E4/E5 operational
  rule) cannot map into a VM whose own `C:\` occupies that path, so E4's
  re-scoped ambient-read contract is unmeetable; no gate evidence transfers
  to it.

Consequences (runner strategy, now fixed):

- one `v1::spawn(ContainerRequest{containment: Process})` per bash task on
  ProcessContainer — E8-proven, 37 ms spawn-to-first-output reference;
- epochs keep their CONVERGENCE semantics unchanged (convergence = rebuild
  policy config; no ACL walks, no lifecycle — the <100 ms flip criterion gets
  *cheaper* than planned);
- the `epoch → session, task → spawn-into-session` seam is retained in the
  runner design, so a future MXC release adding lifecycle to ProcessContainer
  (or gating an fs-capable persistent backend) can flip the strategy back
  without touching bg/policy/ext;
- cross-platform note: per-spawn `Containment::Process` is the SDK's abstract
  cross-platform path (Windows ProcessContainer / Linux Bubblewrap / macOS
  Seatbelt) — uniform by construction; the lifecycle API was Windows/WSLC-only
  anyway, so nothing measurable was traded away.

## Verdict

# GO-WITH-DELTAS

with the following accepted deltas (E3 option 3 + architecture addendum
signed off by "proceed to implementation", 2026-10-24; **E13 executed —
persistence dropped, see "E13 results" above**):

- **E3 delta (decisive):** Git Bash unavailable under confinement
  (mxc#1061); resolved by **option 3** — native-Win32 bash engine:
  **external `brush.exe` pinned by pig's `shellPath`** per the addendum
  (`cargo install brush`; niubash/rubash alternates; busybox-w32 userland).
- **E4 delta:** "reads ambient" is re-scoped — system paths + HKCU ambient;
  profile reads via a `fs_read_only` set (practically `["C:\\"]`, measured
  0.16 s) instead of true ambient reads.
- **E4/E5 operational rule:** ship `readonlyPaths=["C:\\"]` +
  `readwritePaths=[workspace, %TEMP%, logDir]` + `inheritDefaultEnv=true`;
  `%TEMP%` must be added to read-write explicitly for child temp writes
  (open question §10.4: host `%TEMP%` contract preserved).
- **E8 quirks:** no ICMP in-container, no `start /b`, explicit `cwd` required
  (backend default is not the caller's dir), UI policy must allow win32k
  (`ui.disable:false`) for PowerShell/cmd console init.
- All other gates (E1, E2, E6, E7, E9, E10, R11) pass without deltas.

Kill criteria (§8): **not triggered** — E2 (the stated rewrite-killer) passed
cleanly; E7 parity holds at API level; E8 spawn semantics fully expressible.

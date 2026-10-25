# RUST-PLAN: rewrite the extension in Rust on top of MXC, delete srt-win

**Status:** proposal. **Principle of this plan: every unknown that can kill the
rewrite is tested BEFORE any porting code is written.** Phase 0 is a set of
go/no-go gates with named kill criteria; a decision memo is a hard deliverable
gate between Phase 0 and Phase 1. If the memo says no, this plan stops and the
Go/srt-win tree stays.

## 1. Goal

Replace the entire Windows sandbox mechanism (`srt-win`: restricted token,
synthetic SIDs, ACL grant/forget, HKCU registry state, move detection, MSYS
object-dir bootstrap) with **Microsoft eXecution Containers** (`microsoft/mxc`,
`mxc-sdk` Rust crate), and port the extension itself from Go to **Rust** (PiG
supports Rust extensions natively: factory `pub fn new_extension() -> Extension`
in `src/lib.rs`; `pig extension init --lang rust`). `srt-win/` is deleted at the
end — code, CLI, and both gate documents (their evidence is preserved here and
in git history).

Behavior that must survive unchanged (it is the product, not the mechanism):

- composed `bash` tool: bg params + sandbox params on one execute path; every
  spawn confined except explicit `danger-full-access`;
- permission modes `read-only` / `workspace-write` / `danger-full-access`;
- epoch/convergence semantics (`CONVERGENCE.md`): bash binds to the newest
  epoch at spawn time, waits for *that* epoch's convergence as part of the
  command's duration, fails closed with the real cause — never bare,
  never half-applied;
- denial-first escalation, one-denial-one-retry, headless fail-closed;
- denial classification on the merged log tail (`internal/classify`);
- bg layer: exactly-once notifications (check-and-set latch), `bg_list` /
  `bg_output` / `bg_stop`, 64 MiB log cap with auto-kill, 24h sweep, whole-tree
  kill on `bg_stop`/shutdown/hard death;
- config `<configRoot>/agent/sandbox.json` semantics (global-only, silent
  ignore of project files, read-once-per-process).

Intended behavior **changes** (these are improvements the rewrite buys; smoke
assertions that encode the old gaps must be inverted, see §6):

- the **profile-tree write gap closes** on tiers that gate writes by grant
  (`%USERPROFILE%` and `%TEMP%` outside the granted set become unwritable —
  the srt-win SCHANNEL-GATE/GITBASH-GATE trade no longer has to be made);
- Schannel/HTTPS works under confinement **if and only if** Gate E2 passes
  (today it is a documented inherent failure);
- `read-only` becomes "no write roots" instead of "no dirs ⇒ nothing granted";
- **per-task spawn on the gated backend** (E13 outcome, 2026-10-24): every
  bash task = one `v1::spawn(ContainerRequest)` on ProcessContainer —
  E8-proven (37 ms to first output), policy rides the request per task.
  Persistence was **dropped** by E13: the lifecycle API exists only for
  backends that cannot scope the filesystem (IsolationSession refuses fs
  policy at every phase) or that carry ungated cost/risk (WindowsSandbox
  experimental VM); ProcessContainer itself has no lifecycle. The
  `epoch → session, task → spawn-into-session` seam stays in the runner so a
  future MXC lifecycle+fs release flips the strategy back without touching
  bg/policy/ext. Cross-platform: per-spawn `Containment::Process` is the
  SDK's uniform path (Windows ProcessContainer / Linux Bubblewrap / macOS
  Seatbelt);
- **shell resolution via pig's `shellPath` config**: the settings key
  `shellPath` (already read by the Go extension at session start →
  `runner.SetConfiguredShell`) is the engine pin — on Windows users point it
  at the brush binary and install it with `cargo install brush`; the
  configured path wins over every fallback, so no PATH lookup and no
  shadowing (rubash ships a `bash.exe` drop-in into `~/.cargo/bin`; Git Bash
  is E3-dead under confinement anyway).

Non-goals: network isolation (stays "always allowed"), write/edit fencing
(stays in the permission-system extension), Linux/macOS runners (still
deferred), adversarial isolation claims (threat model remains fat-finger
protection).

## 2. Why MXC (evidence, not hope)

- Policy shape matches the goal exactly: per-container **read-write**,
  **read-only**, and **denied** path sets + network posture + UI restrictions —
  reads stay ambient-ish while writes are scoped, which is the one property
  `CreateRestrictedToken` + `WRITE_RESTRICTED` cannot express without breaking
  Schannel (`srt-win/SCHANNEL-GATE.md`: the trigger is the mere presence of a
  restricting-SID list).
- Enforcement tiers on Windows (`processcontainer`, min build 26100), selected
  at runtime by `fallback_detector.rs`:
  - **T1 BaseContainer** — `processmodel.dll!Experimental_CreateProcessInSandbox`
    (now documented as `CreateProcessInSandbox`), FlatBuffer `SandboxSpec`
    (`fs_read_write` / `fs_read_only` / `network_policy` / `capabilities` /
    `ui_restrictions` / `integrity`); the **OS** constructs the sandbox.
  - **T2 AppContainer + BFS** — classic AppContainer token + Brokered File
    System (`bfscfg.exe`); policy lives with the broker, no host SD mutation.
    Compiled out of stock builds (`tier2_bfs` cargo feature).
  - **T3 AppContainer + DACL** — classic AppContainer + host NTFS ACEs for the
    package SID. This is srt-win's ACL machinery with a different SID, and MXC's
    `DaclManager` owns state-file persistence + orphan reaping.
- Microsoft's own `isolation_session` `protected_paths_filter.rs` documents
  grants "propagat[ing] an agent SID's ACE through entire subtrees —
  catastrophic for drive roots, the Windows directory, the Users root,
  ProgramFiles, and ProgramData" (issue #330) — independent corroboration of
  `PLAN.txt`'s 527-second measurement, and a problem T2/T1 avoid structurally.
- `mxc#1533` reports that under T1, "files outside explicit filesystem grants
  remain readable" — i.e. ambient reads + granted writes, which is exactly this
  product's desired shape (but it is filed as a bug-to-clarify, so Gate E4
  verifies rather than assumes).
- SDK is Rust-first (`mxc_sdk::v1`, `ContainerRequest`, run-to-completion and
  spawn), MIT license, Codex already ships on it (`codex-rs/mxc-sandbox`).

Counter-evidence to keep visible: the MXC README states **"no MXC profiles
should be treated as security boundaries currently"**; `mxc#1464` shows T1
breaks `GetFinalPathNameByHandleW(VOLUME_NAME_DOS)` (git cwd, Node
`realpath.native`); T1 sits behind an `Experimental_` API; the Git Bash
signal-pipe SD (`{user, Administrators, SYSTEM}`, `GITBASH-GATE.md` §3) carries
no package-SID/ALL-APPLICATION-PACKAGES ACE, so under T2/T3 the cygwin wall
likely returns in new form. All of these are Phase 0 gates, not Phase 4
surprises.

## 3. Risk register → Phase 0 gates

Every gate is run **outside the extension** (standalone probes + the existing
`pig-tmp` probe sources + `wxc-exec.exe` from the MXC repo/bin payload) on the
target machine class (Windows 11 24H2/25H2+; this dev box is build 26300).
Each gate has a **kill criterion** — what result stops or reshapes the rewrite.

| # | Risk | Gate (experiment) | Pass | Kill / derail criterion |
|---|---|---|---|---|
| R1 | Tier actually available on target machines. T1 needs `processmodel.dll` + OS feature (25H2+); T2 compiled out of stock builds; T3 is the common fallback | **E1 tier probe**: run `wxc-exec` with `containment: "processcontainer"` on each supported build; read tier selection logs; confirm `processmodel.dll!Experimental_CreateProcessInSandbox` resolves | T1 or T2 on the primary machine class; T3 acceptable only if E4/E5 also pass | Only T3 available **and** E5 fails (broad read grants unaffordable) ⇒ MXC gives nothing over srt-win; stop |
| R2 | **Schannel gate**: `SEC_E_NO_CREDENTIALS` under containment (the whole reason for leaving `CreateRestrictedToken`) | **E2 TLS probe**: `pig-tmp/sspiprobe`-equivalent + `curl.exe` (schannel) + `cargo fetch` + PowerShell `Invoke-WebRequest` inside an MXC container on the winning tier; same commands outside as control | All four complete handshakes inside | Any schannel client fails at `AcquireCredentialsHandle` on the tier you ship ⇒ the goal is not met by MXC either; stop the rewrite (see §8) |
| R3 | **Git Bash gate**: cygwin signal pipe (`{user, Administrators, SYSTEM}` SD) and `mxc#1464` (git cwd under T1) | **E3 shell matrix**: `bash -c "echo BASH_OK"`, `git status`, `git clone` over https, `cmd //c echo`, fork/pipe, from inside an MXC container; compare with the 34/34 `srt-smoke.sh` baseline | bash + git usable; failures attributable and documented at worst | bash dies at `couldn't create signal pipe` or git is unusable ⇒ **product decision required before Phase 1** (accept documented gap and steer to PowerShell, or hybrid: MXC for non-cygwin + legacy token for bash). Do not discover this in Phase 3 |
| R4 | Read model: T2/T3 gate reads (AppContainer check); the product promises ambient reads | **E4 read matrix**: read `%USERPROFILE%\.gitconfig`, a repo outside the workspace, `C:\Windows\System32\drivers\etc\hosts`, HKCU via reg, inside the container on the winning tier | Reads ambient on T1; or on T2/T3, reads work with a *finite* `fs_read_only` set (E5 measured) | Reads require profile-wide grants to work ⇒ falls afoul of E5; stop or re-scope "reads ambient" as a documented limitation |
| R5 | Broad `fs_read_only` grants cost (subtree inheritance; #330 mitigation; `PLAN.txt` 527 s wedge) | **E5 grant-cost probe**: time `fs_read_only = [C:\, %USERPROFILE%]`-equivalent grants on T3 (expect: refused or catastrophic — record actuals), and the *scoped* alternative (workspace + toolchains + profile subtrees actually read by the smoke suite) | Scoped set converges in < 1 s per epoch and the smoke suite passes within it | Only the broad grant works and it costs seconds+ per epoch ⇒ MXC-on-T3 is not viable for this UX; stop or ship T1-only |
| R6 | Unelevated operation; `wxc-host-prep.exe` is `requireAdministrator` for one-time host prep | **E6 elevation audit**: launch containers unelevated with and without prior host-prep; record exactly which steps prompt UAC | Per-launch confinement is UAC-free; host-prep is one-time and fits pig's escalation-at-install flow | Per-launch UAC or machine-wide prerequisites beyond one-time prep ⇒ violates "never trigger or require UAC"; stop |
| R7 | Long-running spawn semantics: bg needs Start/Wait split, arbitrary lifetime, tree kill, exit codes; MXC streams stdio via its own pipes | **E8 spawn probe**: Rust program using `mxc-sdk` starts a 30-minute child, streams output, kills the tree (`bg_stop` semantics: no orphans incl. grandchildren), reads exit codes; verify log-cap/auto-kill can still be enforced | Full bg lifecycle expressible over the SDK's spawn API | SDK only offers run-to-completion or no tree kill ⇒ the bg layer cannot be preserved as-is; stop (no acceptable workaround that forks a second mechanism) |
| R8 | PiG Rust extension surface parity: retained contexts (SDK D19), `deliverAs=steer`, commands+completions, toasts, tool schema, `ctx.ConfigHome()`, events | **E7 scaffold spike**: `pig extension init --lang rust`, register `bash`/`bg_*` + `/sandbox`, one tool call, one steer notification round-trip | Parity for every API the current extension touches (checklist in §5) | Missing API (esp. retained contexts / steer delivery) ⇒ rewrite is blocked on the PiG SDK, not on MXC; keep Go for the extension layer and revisit (see §8 hybrid) |
| R9 | Instability: preview maturity, `Experimental_` API, schema churn until 1.0 | **E9 pinning probe**: build against a pinned `mxc-sdk` rev; diff `docs/schema.md`/`BaseContainerSpecification.fbs` for churn over the gate window | Pinnable to an exact rev/crate version; changelog readable | Unpinnable or silent wire-format breakage ⇒ treat MXC as moving target; delay rewrite until 1.0 |
| R10 | Install story: Rust extension needs a Rust toolchain on user machines (Go extensions compile against the staged SDK; Rust presumably needs `cargo`) | **E10 build probe**: `pig` load/build of the Rust scaffold on a clean-ish machine; record the toolchain requirement and build latency | Acceptable (documented `rustup` prerequisite) or pig stages a prebuilt binary | Toolchain requirement unacceptable for distribution ⇒ ship as Piglet/prebuilt binary path or keep Go |
| R11 | Profiles / container-name hygiene: `CreateAppContainerProfile` entries accumulate (analogue of srt-win's N=8 LRU + move detection) | Folded into **E1**: create/destroy containers across 20 epoch flips; inspect profile store and MXC's DaclManager state after crash-kill | No unbounded growth; crash leaves inert state that the next start reaps | State leaks comparable to srt-win's registry ⇒ the rewrite's simplicity claim dies; reconsider T2/T1-only |
| R13 | One container per epoch serving all its bash tasks (persistence via the state-aware lifecycle API). **Executed 2026-10-24** — spike `pig-tmp/e13-persist`, log `pig-tmp/e13-run.log`, verified at repo rev `05a430bc` + crates.io `1.0.1`: typed lifecycle exists only for IsolationSession/Wslc (+ WindowsSandbox via raw JSON); IsolationSession **refuses filesystem policy at every phase** (`common/policy.rs`: "the backend installs no persistent filesystem enforcement"; one-shot spawn with fs ⇒ `ErrorCode::PolicyValidation`); ProcessContainer — the backend every gate (E1–E5, E8) passed on — answers `unsupported_phase: backend ProcessContainer does not implement state-aware lifecycle`; WindowsSandbox is an experimental full-VM whose same-path dir mapping cannot satisfy the E4 `readonlyPaths=["C:\\"]` rule (host `C:\` vs VM `C:\` collision) | E13 plan (for the record): lifecycle + 100/8 bench + sibling-kill + hygiene ×20 | — | **TRIGGERED → persistence dropped** (behavior difference, per the 2026-10-24 directive): runner strategy fixed to per-command `v1::spawn(ContainerRequest)` on ProcessContainer (E8-proven, 37 ms reference); `epoch → session` seam retained for a future lifecycle+fs MXC release; details in memo "E13 results" |

### Phase 0 procedure (this is the "risk up-front")

1. Vendor/clone `microsoft/mxc` at a pinned rev into `pig-tmp/mxc/` (scratch,
   gitignored). Build or obtain `wxc-exec.exe`.
2. Run E1–E6 with `wxc-exec` directly (JSON configs, no extension code).
3. Run E7–E10 as throwaway scaffolds (`pig-tmp/`), not in this tree.
4. E13 (persistence gate, added post-verdict) ran as the first deliverable of
   Phase 1 in `pig-tmp/` — **executed 2026-10-24, results appended to the
   memo's addendum (persistence dropped)**.
5. Write the **decision memo** `RUST-DECISION.md`: one table, one row per gate,
   observed results, and a final `GO` / `NO-GO` / `GO-WITH-DELTAS` verdict with
   any accepted deltas listed explicitly (e.g. "Git Bash gap accepted, steer to
   PowerShell"). **No Phase 1 work starts before this memo exists.**

## 4. Architecture after the rewrite

Mechanism mapping (old → new):

| srt-win / Go today | MXC / Rust after |
|---|---|
| `srtwin.New(dirs...)`: SID derivation (SHA-256 of dir set), ACL grants, move detection, token mint | `mxc_sdk::v1::ContainerRequest` built from the policy: `fs_read_write = dirs ∪ {logDir, NUL-equivalents}`, `fs_read_only` = scoped set if tier demands it, network allow, UI restrictions off (or minimal), `denied` = control paths if adopted |
| `srtwin.Cmd` (`CreateProcessAsUserW`, env block, handle inheritance) | runner crate wrapper over the SDK spawn API; env block via the request's environment policy (MXC builds a clean `CreateEnvironmentBlock` env — the classic "PATH lost" trap is inverted here: **explicitly pass through the resolved env**, verify `USERPROFILE`/`PATH` visible, port the existing env-block tests) |
| registry `HKCU\Software\srt-win` (Config/Sids/Used/Roots) | **deleted** on T1/T2 (no host state). On T3, MXC `DaclManager` owns its state file + orphan reaping; we keep only a small list of created AppContainer profile names for cleanup (R11) |
| SID eviction LRU (N=8) + move detection (`OpenFileById`) | **deleted** — grants are per-container and torn down by MXC (`--clearpolicy` on T2, DaclManager inverse-replay on T3). Move detection becomes MXC's problem or a no-op |
| MSYS object dir bootstrap + section pinning (`ensureMsysReady`) | **deleted if E3 passes** (new containers get their own object namespace / OS-managed sandbox); retained only if E3 proves otherwise — decide in the memo |
| token default DACL trick | **deleted** |
| `internal/proc.Spec{Sandbox *srtwin.Sandbox}` | `Spec{Container: Option<Arc<MxcContainer>>}` — same seam, same call sites in `runner`/`tools`/`bg` |
| `internal/converge` epochs applying ACL grants on one background thread | **shrunk to synchronous bookkeeping** (decision 2026-10-24: without persistent containers there is no host work left to background): bind → validate (a `stat`) → record happens inside the call's duration; the worker thread, futures, and collapse chain are deleted. Every observable invariant survives — bind-newest, wait-in-duration, causal fail-closed, no-stale-window (stronger: `/sandbox` state flips before returning), rapid flips collapse (trivially). Epoch counter + `StatusLine` stay for `/sandbox`/`bg_debug` display |
| `Session_shutdown` does no revocation ("grants inert") | still true: container teardown on session end is a bonus, not relied upon |
| Job object `KILL_ON_JOB_CLOSE` tree kill | E8 proved per-spawn tree kill; after E13 tasks never share a container, so sibling isolation holds by construction — keep MXC's per-spawn tree semantics; wrap a task's tree in our own job object only if a shared-session strategy ever returns |
| log handle fd-direct stdout | MXC streams via pipes ⇒ a Rust pump thread writes the log file (data path now in Rust; keep the 64 MiB cap + auto-kill and note the documented divergence: kernel-copy → userspace-copy) |
| `internal/classify` signatures | kept verbatim + MXC runner-failure signatures added (`SANDBOX_UNAVAILABLE` path must cover MXC provision failures) |
| `srt-win/SCHANNEL-GATE.md`, `GITBASH-GATE.md` | archived under `docs/evidence/` with a header pointing at the memo's gate results |
| bash engine resolved on PATH (`bash.exe`/`rubash.exe`/busybox userland per the E3-bis decision) | **external brush binary pinned by pig's `shellPath`** (Go parity: `settings["shellPath"]` read at session start → `runner.SetConfiguredShell`; configured path wins over every fallback); install recipe `cargo install brush` (tested version pinned in the README); fallback chain (PATH, standard locations) kept for unconfined runs; under
  confinement, a resolved shell that is MSYS/Git-Bash (or any known-E3-dead
  engine) is rejected **before spawn** with an actionable error pointing at
  `shellPath` → `brush.exe` — fail-fast instead of an in-container mxc#1061
  death; userland stays busybox-w32 applets + native tools under a granted
  tool dir |
| one `ContainerRequest` per command | **one `v1::spawn(ContainerRequest)` per bash task** (E13 outcome): ProcessContainer builds + tears down per spawn (E8-proven, 37 ms reference); the epoch's policy (fs readwrite/readonly sets, network allow, UI) rides the request per task; the `epoch → session, task → spawn-into-session` seam is retained in the runner interface so a future lifecycle+fs backend slots in without touching bg/policy/ext |

**Runner strategy sketch (post-E13)**: one `v1::spawn` per bash task —
foreground, auto-promoted, or background — with the epoch's policy on the
request, `inherit_default_environment` + explicit `working_directory` (E8
quirks), and `danger-full-access` spawning bare (no container; confirmed
2026-10-24). Per-task streaming/kill/wait drive log cap, timeout promotion,
and `bg_stop` tree kill — E8-proven, with sibling isolation by construction.
Epoch flip = rebuild the policy config for subsequent spawns; CONVERGENCE
semantics are unchanged (bind-newest, wait-for-convergence as part of the
call, in-flight unaffected — tasks were never in a shared container), and
rapid flips still collapse. The bg layer stays outside the mechanism
(exactly-once latches, notifications, sweep are mechanism-independent).
Convergence failure ⇒ runner-failure signature (`classify` keeps its
`SANDBOX_UNAVAILABLE` path); next call re-runs convergence (self-heal). The
seam stays deliberately thin so a future MXC release that adds lifecycle to
ProcessContainer — or gates an fs-capable persistent backend — can flip the
strategy back to per-epoch containers without touching bg/policy/ext.

Convergence cost model after the rewrite: no ACL walks, no registry, no
file-ID lookups, no background thread — an epoch flip is a synchronous
in-memory bump + `stat`, so the 100 ms idempotence requirement and the
"second `New` is fast" acceptance criteria are met by orders of magnitude
(measure anyway in Phase 4). CONVERGENCE.md's single-worker-thread contract
is replaced by synchronous binds; its behavioral invariants (bind-newest,
wait-as-part-of-duration, causal fail-closed, collapse) are preserved —
Phase 4 updates the document accordingly.

## 5. Crate layout and porting map

Rust workspace in this repo (replaces `go.work`, `go.mod`, `extension.go`,
`internal/`):

```
srt-rs/                        (name TBD; workspace root)
├── Cargo.toml                 [workspace]
├── src/lib.rs                 pig factory: pub fn new_extension() -> Extension
├── src/ext/                   port of extension.go: tool registration, commands,
│                              retained context, steer notifications, ui
├── bg/                        port of internal/bg (registry, notify latch, output,
│                              lifecycle, ui) — mechanism-independent, port first
├── policy/                    port of internal/policy + internal/permission +
│                              internal/config (sandbox.json) → ContainerRequest
├── runner/                    MXC wrapper: session/container build/spawn/wait/kill-tree,
│                              env resolution, shell resolution (shellPath parity),
│                              stdio pump, exit codes
├── classify/                  port of internal/classify (verbatim signatures)
├── escalate/                  port of internal/escalation + internal/ledger
└── tests/                     smoke matrix (successor of pig-tmp/srt-smoke.sh)
```

API-parity checklist for E7 (every item is used by the current extension; a
missing item is an E7 failure): tool registration with input schema +
`exposure`; composed `bash` parameters (`run_in_background`, `timeout`,
`sandbox_permissions`, `justification`); commands `/sandbox`, `/bg`, `/bg-tasks`
with completions; `ctx.ConfigHome()`; `ctx.GetSettings()` with the
`shellPath` key (load-bearing since the E3 decision: it pins the engine);
retained SDK contexts and
`deliverAs=steer, triggerTurn=true` notifications; session events
(`session_start`, `session_shutdown`); `ctx.executeTool` if used at port time;
toast/print behavior parity.

Porting order inside Phase 3 (each step lands green with tests): `bg` →
`classify`/`escalate`/`config` → `policy`+`runner` (the only MXC-aware
crates; runner also owns shellPath resolution) → `ext` composition (bash
tool, commands, notifications) → convergence rewiring. The Go tree stays buildable until the last step; the two live
side-by-side behind `pig -ne -e` (Go) vs the Rust build (separate config root or
explicit `-e`), never both registering `bash` in one session.

## 6. Acceptance criteria (Phase 4)

Carried over verbatim from the current README acceptance results (real
`pig -ne -e` runs): registration; confined echo; workspace write+read; outside
write denied + marker + hint; headless escalation refusal; read-only denies
workspace with mode-specific marker; fork/pipe/`git status`/`cmd.exe` from
inside bash (subject to R3); `/sandbox` show+set; bg start + `bg_list` live
progress; `<task-notification>` exactly-once with tail preview; `bg_stop` tree
kill with zero leftovers; `danger-full-access` bare; no console windows.

**Inverted / new assertions** (these encode the rewrite's benefits — if they
still fail the rewrite has not delivered):

- write to `%USERPROFILE%` outside granted dirs is **denied** in
  `workspace-write` and `read-only` (today asserted as accepted gap);
- `%TEMP%` outside the granted set is denied (today granted as "host %TEMP%");
- schannel HTTPS from confined `curl`/PowerShell **succeeds** (today asserted
  broken) — only if E2 passed; otherwise the memo's delta is asserted instead;
- epoch flip converges in < 100 ms (rebuild policy config only) and two
  identical policy states apply no duplicate host state (T3: DaclManager
  state unchanged);
- crash-kill of the extension leaves no orphaned ACEs/profiles beyond what the
  next start reaps (R11);
- per-task overhead stands on the E8 baseline (37 ms spawn-to-first-output;
  persistence dropped by E13 — re-measure in the runner phase if desired);
- (withdrawn with persistence: container-retire, container-loss self-heal,
  and shared-container concurrency items — tasks no longer share anything);

## 7. Phases (risk-ordered; each phase is a stop point)

- **Phase 0 — gates + decision memo** (§3). Deliverable: `RUST-DECISION.md`.
  *Nothing else is built in this phase.*
- **Phase 1 — runner proof in plain Rust (no pig).** A standalone crate that
  first delivered the E13 spike (**executed 2026-10-24: persistence dropped —
  memo "E13 results"**; the runner strategy is fixed to per-command
  `v1::spawn`), then maps a dir list to a
  `ContainerRequest`, runs the full smoke matrix (the 34 sections of
  `srt-smoke.sh`, translated), and produces before/after tables for the
  inverted assertions. Exit criterion: matrix green modulo memo deltas.
- **Phase 2 — PiG Rust scaffold spike** (E7 promoted to real code): same tools/
  commands registered, one end-to-end steer notification. Exit criterion:
  parity checklist complete. Test recipe (isolated `PIG_HOME`, `-ne -e … -p`
  piped prompts, `--validate-only`): **`TESTING.md`** at the repo root.
- **Phase 3 — port layers** in the §5 order, green tests per layer, Go tree
  kept alive until the bash tool composes end-to-end.
- **Phase 4 — acceptance rerun** (§6) + docs: rewrite README (recipe section
  becomes "MXC policy" and gains the Windows shell setup: `cargo install brush`
  at the tested version + `shellPath`; honest-gaps section shrinks to what the
  memo lists), keep `TESTING.md` current (isolated pig + piped-prompt recipe),
  archive both GATE docs, delete `srt-win/`, `go.*`, `extension.go`, `internal/`,
  update `CONVERGENCE.md` to the new convergence work.
- **Phase 5 — hardening:** profile/state hygiene loop (R11), tier-reporting in
  `/sandbox` output ("containment: T1 BaseContainer"), fallback UX when the host
  lands on T3, `mxc-sdk` pin + upgrade policy, CI matrix over supported builds.

## 8. Kill criteria and fallbacks (decided now, not mid-flight)

- **E2 fails** (Schannel broken on the tier you get): the goal is not achievable
  via MXC either. **Do not rewrite.** Fallbacks, in order: (a) stay on Go +
  srt-win with the documented gap; (b) MXC for write-scoping only *if* the memo
  explicitly re-frames the goal as "writes scoped, TLS gap accepted" — requires
  a conscious goal change, since §1 goal (2) then cannot be met; (c) wait for
  T1 GA and re-run Phase 0.
- **E3 fails** (Git Bash dead): product decision before Phase 1 — accept the gap
  + steer to PowerShell/cmd, or hybrid (two spawn mechanisms: MXC default,
  legacy restricted-token only for cygwin shells). The hybrid is allowed but
  must be named in the memo as an accepted compromise; it keeps a sliver of
  srt-win alive and therefore delays "delete srt-win" past Phase 4.
- **E7 fails** (PiG Rust parity gap): rewrite is blocked on the PiG SDK. Keep
  the Go extension and implement the MXC runner as a standalone Rust helper
  binary invoked per spawn (`runnerCommand`-style seam that `internal/config`
  already parses). This is the **hybrid baseline** and is the most likely
  near-term outcome — it still deletes srt-win's mechanism without requiring
  the extension layer to move languages.
- **E8 fails** (spawn semantics): no rewrite; the bg layer is the product.
- **E13 (executed 2026-10-24 → persistence dropped)**: no fs-capable
  lifecycle backend exists for the gated tier — runner strategy is
  per-command `v1::spawn` on ProcessContainer (the E8-proven path); revisit
  only if MXC adds lifecycle to ProcessContainer or gates an fs-capable
  persistent backend. No other change to the rewrite.

## 9. What gets deleted (Phase 4 checklist)

- `srt-win/` — all of it (library, `cmd/srt-win`, `cmd/pipeprobe`, debug tests).
- `srt-win/GITBASH-GATE.md`, `srt-win/SCHANNEL-GATE.md` — archived to
  `docs/evidence/` with gate-result headers, not deleted (they are the reason
  this plan exists).
- `go.work`, `go.mod`, `go.sum`, `extension.go`, `internal/` — after Phase 3/4.
- Spike scratch (`pig-tmp/`, probes) — kept only as `tests/` inputs worth
  porting (sspiprobe's schannel check becomes a permanent smoke test; it is the
  regression test for the original gate).

## 10. Open questions for the memo

1. Exact `mxc-sdk` pin (git rev vs crates.io version) and its MSRV; does pig's
   Rust extension build use `cargo` at load time (R10) or a prebuilt artifact?
2. Does T1's `SandboxSpec` support the `denied` paths we might want for control
   dirs (`.git`, extension state) — and do we want them (they are a behavior
   change vs today's contract)?
3. ~~Provisioning timing (eager vs lazy)~~ — **resolved by E13**: no
   container persists, so epoch flip is "rebuild policy config" only.
4. `%TEMP%` handling: keep "host `%TEMP%` granted" (today's contract) or move
   the child to a container-scoped temp (MXC's `getTemporaryFilesPolicy`)? The
   smoke suite asserts the former.
5. NUL/`CONIN$` special handles and `CREATE_NO_WINDOW` equivalents under the
   MXC spawn path (no console flash is a hard acceptance item today).
6. If the hybrid baseline (E7 fail → Rust helper binary) lands first, what
   triggers the later full-Rust port — pig SDK parity, or nothing?
7. **Userland provisioning — IMPLEMENTED 2026-10-25 (shipping strategy still
   open):** the PATH prepend is wired and e2e-validated — settings key
   `userlandDir` (wins) with fallback to a drop-in `<configHome>/agent/userland`
   directory; `runner::request` prepends it in both confined (`build_request`)
   and bare (`bare_env`) spawns; `bg_debug` shows the `userland:` line.
   Validated through pig: `command -v sed` → `…\ubin\sed` and
   `sed`/`grep`/`awk`/`wc` all executed inside the workspace-write container
   (2026-10-25, `TESTING.md` §4 Observed). The original `sed`-gap reason for
   keeping `shellPath` on Git Bash is closed — Git Bash itself still cannot
   run under confinement (MSYS fail-fast stands), so point `shellPath` at
   brush **together with** a `userlandDir`. Still open: how applets reach a
   fresh install — bundle busybox resources in the extension vs
   auto-materialize into `<configHome>/agent/userland` vs document a manual
   copy (test hosts keep using `pig-tmp/shell-candidates/ubin`).
8. **Trace sharing across sessions (observed 2026-10-25):** `%TEMP%\pi-bg-tasks\bash-calls.jsonl`
   is machine-wide — every pig session and both extensions append to it
   (pre-existing Go design), so `bg_debug`'s `trace:` section can show other
   sessions' records (a test session saw the harness session's
   `danger-full-access`/Git-Bash lines next to its own). Options: tag records
   with the session id and filter in `bg_debug` (small, additive divergence),
   or document as-is. Note for test assertions: the model may run `bash` and
   `bg_debug` in parallel, so the debug tail can snapshot milliseconds before
   the freshest records flush — make prompts explicitly sequential.

(Resolved by the 2026-10-24 directives and E13: persistence **dropped** —
no shared epoch container, so container identity, task sharing,
retire-then-drain, job-wrapper, provisioning-timing, and supervisor IPC are
all moot; per-command `v1::spawn` on ProcessContainer is the runner strategy;
the `epoch → session` seam is retained for a future fs-capable lifecycle
backend.)

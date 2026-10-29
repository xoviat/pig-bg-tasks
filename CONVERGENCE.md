## Sandbox state, epochs, and background convergence (the ONLY grant/revoke path)

**Rust port status (2026-10-25): mechanism replaced, invariants preserved (E13).** The reference's
single-worker-thread / `srt-win` ACL model is gone. This extension converges **synchronously inside
each bash call** and applies policy **per spawn** through Microsoft eXecution Containers
(`mxc-sdk::v1::spawn(ContainerRequest)`). There is no background thread, no standing grant, no state
DB, and nothing to revoke: the E13 gate proved no persistent-filesystem lifecycle backend exists for
the spawn-capable container (`RUST-DECISION.md` §E13), so persistence was **dropped deliberately** —
the epoch/session seam is kept for a future lifecycle-capable backend.

Desired state = writable set + env, derived from config (`<configRoot>/agent/sandbox.json`,
global-only, project-level ignored silently, `/sandbox` a process-wide override). Every distinct
policy state (initial startup, `/sandbox <mode>`, workspace change) bumps an **epoch**; binding an
epoch = resolve policy → validate (the workspace/temp `stat`s) → record — inside the call's
duration, never on another thread, never deferred.

- **Epochs / bind-newest (preserved).** Bash calls bind to the newest epoch at spawn time; the bind
  **is** convergence — there is no wait, hence no stale-policy window: after `/sandbox read-only`
  returns, the very next call already binds read-only. In-flight (already spawned) calls are
  unaffected; rapid mode flips collapse because every new call simply binds the newest state.
  Binding happens *before* the spawn is built, so the trace record and the container policy always
  agree with the bound epoch.
- **Causal fail-closed, no temporal timeout (preserved, strengthened).** Bind OK ⇒ build the
  `ContainerRequest` (write roots + read-only `C:\`, network allowed, UI on, `timeout_ms=0`) and
  spawn. Bind/validate/refusal failed (workspace missing, runner unavailable) ⇒ the tool returns an error carrying the real cause — never
  half-applied, never bare. Spawn failure is `converge_failed`/`refused`-traced and surfaces
  `SANDBOX_UNAVAILABLE …` with the cause. The call duration still composes with background-task
  semantics (2 s quick-completion race, interactive timeout promotion, exactly-once completion
  notification).
- **Per-spawn policy = no revocation problem (stronger than the reference).** Each confined child
  carries its own filesystem policy with `clear_policy_on_exit`; `session_shutdown` kills
  background TASKS only and performs **no revocation** because there is nothing to revoke — a
  crash leaves no standing side effects at all (the reference's identity-gated inert-grant argument
  becomes unnecessary). `/sandbox [mode]` (no args: show mode, writable set, env, epoch/runner
  status) bumps the epoch and returns immediately — the next call binds synchronously.
- **Background layer (ported 1:1; invariants enforced by unit tests, 36+27 cases).**
  **Exactly-once notifications** via a check-and-set latch *before* send: any path that already
  surfaced the outcome (`bg_output`, `bg_stop`, deliberate kill) suppresses it; a failed send is
  lost, never retried. User-initiated `bg_stop` and `session_shutdown` go through Go's
  `TerminateJobSilently` (latch notified → kill tree → mark terminal) and therefore emit **zero**
  notifications by design — verified line-for-line against the Go reference; watcher-path
  completion/failure emits exactly one. Plus: 64 MiB log cap with auto-kill and marker, 24 h log
  sweep at `session_start`, whole-tree kills via `KILL_ON_JOB_CLOSE` job objects (survive hard
  extension death), 16-job concurrency cap, `fg` calls tracked and evicted on completion (no
  notification — the tool result is the surface).

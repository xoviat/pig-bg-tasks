# Delegated workspaces — sandbox support for subagent children

**Status: §B is implemented and tested in this crate** (`src/link/` +
`src/policy/inherit.rs`, 2026-11-20 — AF_UNIX on every platform including
Windows, per the maintainer directive; the task busy-state watch
(`op:"watch-tasks"`) added 2026-11-25 — 17 link + 4 policy-mirror tests
green, full suite 130 unit + 14 smoke + 1 Go-client test). Design decisions: **no new model
tools** — a child's approval is put in front of the parent session's user
through the parent session's *own* dialog, and **a child mirrors the
parent's sandbox policy** (the parent is the baseline; a child's own
`sandbox.json` does not apply while mirrored). **§A (workspace-roots
derivation) and §C (junction grants) remain proposals** — nothing in them
is compiled yet. This document details what pig-bg-tasks needs so that
*delegated* work — subagent children, but any parent-spawned task — can run under its sandbox without the workarounds a
recent delegation session was forced into. The companion half is one generic marker: the pi-subagents Go port
(`../pigpen/components/subagents/extensions/pi-subagents/parent.go`) stamps every delegated child with
`PIG_PARENT_SESSION` (§2) and nothing else. All policy, transport, and semantics live here.

## 1. Why: four observed failure modes

A parent session delegated three tasks into git worktrees it created under the repository's `tmp/`. Each child was a
`pig` process whose bash tool runs under this sandbox family. Observed failures:

| # | failure | evidence | root cause |
|---|---|---|---|
| F1 | git writes denied in a worktree | `git checkout` denied (index lock in the shared repo); a child committed into a **stranded local repo** (`<worktree>/tmp/lcgit`) and printed manual landing steps | a linked worktree's `.git` file points into the parent repository's git dir; the sandbox writable set is the workspace (+ `%TEMP%`), so every shared-`.git` write is denied |
| F2 | shared build roots unreachable | a child copied **279 MB** of Qt/deps into its worktree because `tmp/`, `_fc_src/` (git-ignored, outside the workspace) were not writable/readable there | no derivation or configuration of the shared roots a delegated task legitimately needs |
| F3 | escalation dead-ends headless | `sandbox escalation to "danger-full-access" requires approval, but no approval channel is available — nothing was executed` | the approval dialogue is a host UI dialog (`escalate::Ui.ask`); headless contexts have none, and there is no relay |
| F4 | parent link serves nothing (orphan socket, observed 2026-11-21) | a child's `op:"policy"`/`op:"ask"` dial fails `No connection could be made because the target machine actively refused it. (os error 10061)` while `%TEMP%\pig-sandbox-<parent>.sock` still exists on disk | the parent's extension runner died without `session_shutdown` (host: `extension "pig-bg-tasks" disabled: packed member connection closed; /reload restarts it`), so the socket file outlives the listener; fail-closed on the child side. Diagnose from `ext_session_start_done` → `link_accept_thread_*` → `link_served` → `link_stopped{session,reason}` in `%TEMP%\pi-bg-tasks\bash-calls.jsonl` (0.3.2) — the incident's trace could not attribute its `link_stopped` lines |

F3 is the only failure with no legal workaround today; F1/F2 forced fragile ones, and F4's is the host-side `/reload`.

## 2. The contract (pi-subagents side: done)

Every delegated child carries exactly one marker in its environment:

| variable | meaning |
|---|---|
| `PIG_PARENT_SESSION` | the **session id** of the session that delegated this child (`getSessionID()` of that session) |

That is the entire contract. It is plain provenance — the spawner declares no policy, no endpoints, no sandbox
vocabulary. Everything below is derived by pig-bg-tasks from this one fact plus its own knowledge.

- **Inheritance.** The marker rides the child `pig` process's environment into its extension cells (cells inherit the
  host's environment — the same hop ambient variables like `HC_TERMINAL_*` already make today).
- **Nesting.** Each level re-declares: the marker names the *immediate* parent's session, so a subagent of a subagent
  points at the intermediate session — exactly the session whose pig-bg-tasks should field its asks. Spawners strip an
  inherited value and set their own (the Go port's `childEnv` does).
- **Local derivation covers the rest.** The child's workspace is its cwd; its shared git dir is resolvable from
  `<cwd>/.git` (a directory, or a `gitdir:` file whose `commondir` names a linked worktree's shared git dir); shared
  build roots come from this crate's own `<configRoot>/agent/sandbox.json` (§3.A).

## 3. Work items

### A. Workspace roots derivation (policy-side) — *not implemented yet*

**Seams (verified):** `policy/mod.rs:89` already has
`pub fn writable_roots(mode: Mode, workspace_root: &str, extra_roots: &[String]) -> Vec<String>`; `runner/request.rs:73`
already funnels `write_roots: &[String]` into the `ContainerRequest` (`readwrite_paths: write_roots.to_vec()`).

- Derive the delegated case inside `policy/` (no spawner input needed): when the workspace is a git worktree —
  detectable generically from `<cwd>/.git` being a `gitdir:` file — resolve `commondir` and add the **shared git dir**
  to the writable set (F1's fix). The derivation is plain file reads; the pi-subagents prototype that computed it
  (gitdir → commondir) is reproduced in §4's evidence.
- Shared build roots (F2) come from `<configRoot>/agent/sandbox.json`: a `caches`/`roots` allowlist (e.g. `tmp`,
  `_fc_src`) merged through the existing `extra_roots` channel, fail-closed for anything outside the workspace, the
  derived git dir, or the allowlist.
- *(Dropped from the contract: spawner-declared root variables. If a generic roots channel is ever needed, it should be
  its own provenance-style marker, not a sandbox contract in the spawner.)*

### B. Headless escalation relay (system socket keyed by the parent session)

**Implemented** (`src/link/{mod,client,server,asks}.rs`,
`src/ext/{mod,resolve,tasks}.rs`, `src/policy/inherit.rs`):

1. **Parent side (listener).** `session_start` binds this session's id —
   from the SDK (`ctx.get_session_id()`) — at the **single** endpoint
   `<osTempDir>/pig-sandbox-<id>.sock` (the OS temp dir — `%TEMP%` /
   `$TMPDIR` — which both ends already agree on, so parent and child
   derive the same path even when their config roots differ); an accept
   loop serves one connection per request. On Windows
   the endpoint is a real **AF_UNIX socket** (winsock `AF_UNIX` through the
   `uds_windows` crate's `UnixListener`/`UnixStream` — std's own
   `TcpListener::accept` rejects the AF_UNIX address family with EINVAL,
   which is exactly why an AF_UNIX-aware acceptor is needed); on Unix it is
   std's `UnixListener`. Same path convention and same JSON-per-line wire on
   both platforms. One socket transports *all* of §B: `policy` fetch,
   `ask` relay, and the parent's `policy-update` push below.
2. **Child side (asker).** `PIG_PARENT_SESSION` present ⇒ this session is
   a child (its presence *is* the test; a session may be child and parent
   at once — the listener always starts for the SDK id). On a headless
   escalation the ask rides one connection per request
   (`{"v":1,"op":"ask","ask":{uuid, mode, summary, justification, title,
   childSession, childPid, startedAt}}`) and blocks on the JSON reply up
   to `ASK_TIMEOUT` (300 s); connect failure, timeout, malformed reply or
   a parent refusal is an error, and `escalate::approve` turns any error
   into "nothing was executed" (fail-closed, wording shared as
   `link::channel_unreachable`). Interactive sessions are unchanged:
   `has_ui` still wins and the local dialog runs.
3. **Answering — the parent's own dialog, no new tools.** The parent's
   connection thread hands the ask to this session's user with the *same*
   Deny-first select a local escalation shows (`resolve::dialog_decide`,
   title from `escalate::approval_title` — byte-identical either way, so a
   relayed ask reads as if it originated here), then replies
   `{"decision":"allow"|"deny"|"cancel","reason":…}`. A dismissed dialog
   cancels (the child's ladder reports "was cancelled"); a headless
   parent or a dialog error refuses fail-closed ("the escalation stays
   denied"). There is no `bg_approvals`/`bg_approve`/`bg_deny` surface, no
   wake message, and no pending-ask registry: one connection = one ask =
   one dialog. The child maps the verdict back with
   `resolve::verdict_decision`, so `approve`'s byte-stable wording
   (including `. The user's reason: …`) is unchanged.

4. **Identity.** The endpoint name carries the session id (a uuid — the
   capability, sufficient for this crate's fat-finger threat model) and
   the socket file is user-only (0600 on Unix; the user-owned temp
   directory on Windows). Optional hardening still open: verify the peer
   pid (`SO_PEERCRED`) and correlate `childSession` with the spawner's
   records.

**Policy mirroring (§B's other half).** At `session_start` the child asks
the same endpoint for `op:"policy"` and mirrors the snapshot
(`policy::inherit`): the **parent's mode becomes the baseline** (the
child's own `sandbox.json` default does not apply) and a local `/sandbox`
choice may only *narrow* it — nothing runs a child wider than its parent;
the **parent's extra writable roots replace the child's** (a mirror, not a
union) through `config_for`, the single choke point bash, `/sandbox`
status and session start all read. An unreachable parent leaves the local
policy untouched: a child never *widens* by being unreachable. Nested
children mirror their immediate parent, which already mirrors its own —
the chain propagates.

**Level changes propagate (the mirror is not a one-shot read).** A child
registers itself with the parent when it fetches `op:"policy"` (and on
every `ask`); when the parent's level then **widens or narrows** —
`/sandbox`, which calls `permission::set` — it pushes its live policy
closure down each registered child's socket as
`{"v":1,"op":"policy-update","parent":<parent session>,"policy":{mode,
workspace, temp, extras}}`, best-effort and off the calling thread (a
child that is gone is traced, never delays the switch). The child's
applier (`inherit::apply_update`) replaces its baseline **only** when the
frame's `parent` equals the session it mirrors — a foreign sender, an
unknown mode or no mirror at all leaves the mirror untouched — and
replies `{"applied":true|false}`, which is what the parent traces. The
child's next tool call converges under the new level (mode *and* roots),
so a grandchild inherits the change on the next hop of the same chain.

**Task busy-state subscriptions (§B's third shape, 2026-11-25).** The
same socket also serves `{"v":1,"op":"watch-tasks"}`: the reply acks with
this session's current task state (`{"v":1,"ok":true,"busy":true|false}`
— *busy* while any task in the registry runs, background **or**
foreground) and the connection then **stays open**, carrying one
`{"v":1,"event":"task-busy","busy":…}` frame per flip until the
subscriber closes it or the link stops. Two states only, announced
absolutely. The registry fires the flip itself — `new_running_job` and
`mark_terminal` call `link::server::broadcast_busy()` — and the broadcast
only hands the frame to a per-subscriber channel: the socket write runs
on that subscriber's own thread (a 500 ms read probe catches a peer that
vanished), so a watcher that stops reading can never stall a task's start
or exit. The last pushed state is refreshed even while nobody watches (a
late subscriber is acked the truth, not a stale idle), the set is capped
at 32 per link, a dead subscriber is pruned, and `stop_with` drops every
subscription — the peer sees the close. Verified end to end with a real
**Go** client (`tests/go_watch.rs`: subscribe → task starts → task stops
→ link shutdown → `EOF`, exit 0); the Go source is generated at run time
into the gitignored `pig-tmp/linkwatch/` — **no `.go` file is committed**
(maintainer directive).

**Not implemented from this section:** the file-rendezvous fallback
(atomic write + poll-for-reply + bounded wait next to the socket). Today
an unreachable socket is simply fail-closed (deny), which the test plan's
"no listener" case accepts; the fallback stays a listed improvement for a
parent whose *listener* died while its session lives.

### C. Junction grants inside declared roots — *not implemented yet*

**Seam:** the spawn policy (`FilesystemPolicy` in `runner/request.rs`) and job setup (`runner/proc.rs`).

- Allow creating directory junctions when the link's parent and the **resolved target** are both inside writable roots
  (workspace, derived git dir, configured `caches`) — realpath check, no symlink-following into the check itself. This
  turns F2's 279 MB copy into one junction to a configured cache.
- If mxc cannot express reparse-point grants per spawn, the pragmatic fallback is **extension-created links**: the spawn
  spec gains `link_into_job: [{target, link}]`, and the extension process (unconfined) creates the junction after
  validating both ends, before the confined child starts. General Rust: a junction is `CreateFileW` +
  `DeviceIoControl(FSCTL_SET_REPARSE_POINT)`; the `windows` crate already in `Cargo.toml` needs the `Win32_System_IO`
  and `Win32_Storage_FileSystem` features added (`std::os::windows::fs::symlink_dir` exists but needs developer mode or
  a privilege; junctions do not). On Unix the same contract maps to `std::os::unix::fs::symlink` inside the roots.

## 4. Feasibility verification (§B compiled + tested; §A/§C inspection only)

| claim | evidence |
|---|---|
| the parent session id is available at spawn | Go SDK `extensions/sdk/session_manager.go:39` `GetSessionID()` (alongside `GetSessionDir()` the port already uses); staged Rust SDK `src/session_manager.rs:23` `get_session_id()` |
| the marker survives to the child's extension cells | extensions read the host's ambient environment — existing precedent: the Go port's `panesEnabled` reads `HC_TERMINAL_*` from env inside the extension process, and `PIG_EXT_SOCKET*` is layered on at cell spawn (`extension-api.md`) |
| nested children re-declare correctly | the Go port's `childEnv` strips inherited `PIG_PARENT_SESSION` and sets its own (`parent_test.go`) |
| additive writable roots per spawn are expressible | `policy::writable_roots(mode, workspace_root, extra_roots)` already takes `extra_roots`; `runner/request.rs` already maps a `&[String]` onto `FilesystemPolicy.readwrite_paths` of `mxc_sdk::ContainerRequest` |
| worktree git-dir derivation needs only file reads | `<cwd>/.git` directory → itself; `gitdir:` file → worktree git dir; its `commondir` file → shared git dir (the prototype lived in the Go port's `workspace.go`, removed in favor of this derivation) |
| the approval channel is swappable without touching the ladder | `escalate::Ui.ask` is a boxed closure behind `has_ui`; `is_strictly_wider`/`validate_args`/the decision settlement are independent of transport |
| the relay can run over a system socket from a tool call | std `env`/threads/`Instant`; **AF_UNIX on both platforms** (maintainer directive): `std::os::unix::net::UnixListener` on Unix, the `uds_windows` crate's `UnixListener` (winsock `AF_UNIX`) on Windows — proved end-to-end by `link::server` tests; long-blocking tool calls are the norm in this crate (bash) |
| the parent side can ask its user from a connection thread | `Context::select(...)` / `Context::input(...)` are plain host calls over the thread-safe `Connection` (the same pair the local dialog uses, `block_for_user` a no-op outside a tool call); the relay is exercised in-crate through an injected approver — a **live TUI dialog is still unverified** |
| headless is already detectable | `ctx.has_ui()` is used at `ext/mod.rs:102`; `Ui::headless()` is the current stub |

The §A/§C rows were verified by inspection only (no `cargo`, no `mxc`); §B's rows were later compiled and
tested in-crate (see the status line) — including the std `accept` caveat, which probing proved: Windows AF_UNIX
needs an AF_UNIX-aware accept, not `std::net::TcpListener::accept` (the `uds_windows` crate provides it).

## 5. Test plan (smoke-matrix style, gates E1–E10 + R11 extended)

- **A:** a spawn inside a linked worktree can `git checkout`/`commit` with no declaration at all (derived git dir); a
  configured cache root is writable and an undeclared outside root is refused with a marker; `read-only` mode ignores
  derivation entirely.
- **B:** ✅ covered in-crate — a headless escalation connects to the
  parent-named socket and blocks; the parent's dialog settles it
  (`link::server::approve_settles_over_the_link`: allow widens the mode, a
  deny's reason arrives in the ladder's byte-stable wording, a dismissed
  dialog reports "was cancelled", an unreachable parent errors
  fail-closed); a headless parent refuses the ask outright
  (`headless_parent_refuses_the_ask`); the ask reaches the dialog intact
  (`ask_is_asked_of_the_parent_and_answered`); mirroring floors mode +
  replaces extras (`policy::inherit`, `resolve_effective_mode`);
  interactive sessions are unchanged (the local dialog still wins when
  `has_ui`). *Not covered:* a live host dialog (needs a real session) and
  the file rendezvous (not implemented).

- **C:** a junction inside the writable set is creatable and traversable by the confined child; a target outside the
  roots is refused; extension-created links validate both ends before creation.
- **Regression fixtures (replay the incident):** (1) `git checkout` + `git commit` from a linked worktree lands in the
  real repo on the worktree's branch; (2) a build reading/writing `tmp/`-style shared roots via the config allowlist;
  (3) an escalation from a headless child answered from the parent session over the socket.

## 6. Risks and notes

- **Writable git dir widens fat-finger reach** (a bad `git` can hurt the shared repo). Acceptable under this crate's
  threat model and strictly better than the alternative observed (stranded commits), but it deserves a line in the
  README threat-model section; keep the root gated to the *resolved* git dir of the declared workspace.
- **`PIG_PARENT_SESSION` is not authentication** — any same-user process can set it. Under the fat-finger model the
  endpoint name (a uuid) plus a user-ACL is the bar; the optional peer-pid correlation raises it.
- **Ask/reply trust (fallback files):** bound file sizes, validate uuid correlation, and record the answering session in
  the ledger.
- **Multi-session asks:** several interactive sessions may answer; first reply wins (atomic write/pipe message), the
  rest see a "settled" marker — the ledger records the winner.
- **Scope:** nothing here is subagent-specific. `PIG_PARENT_SESSION` is generic provenance any spawner can set, and
  pig-bg-tasks remains the sole owner of sandbox policy, escalation, and transport.

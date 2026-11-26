# Changelog

## [0.3.5] - 2026-11-25

- **Task busy-state notifications over the parent link** (`op:"watch-tasks"`): the single
  `<osTempDir>/pig-sandbox-<id>.sock` now carries a third shape — a **subscription**. The reply
  acks with this session's current state (`{"v":1,"ok":true,"busy":true|false}` — *busy* while
  any task in the registry runs, background **or** foreground; *not busy* when none does), and the
  connection then stays open, carrying one `{"v":1,"event":"task-busy","busy":…}` frame per flip
  until the subscriber closes it or the link stops. Two states only, announced absolutely, so a
  duplicate frame is harmless. Mechanism: `ServerOpts` gained a live `tasks_busy` closure (wired at
  `session_start` to `Registry::shared()`), `bg::registry` fires `link::server::broadcast_busy()`
  from `new_running_job` (task started) and `mark_terminal` (the first-wins guard means one call
  per transition), and the broadcast only hands the frame to a per-subscriber channel — the socket
  write runs on that subscriber's own thread (500 ms read probe for liveness), so a watcher that
  stops reading can never stall a task's start or exit. `last` is refreshed even while nobody
  watches, so a late subscriber is acked the truth instead of a stale idle; the set is capped at 32
  per link, a dead subscriber fails its channel send and is pruned, and `stop_with` drops every
  subscription (the peer sees the close). Child side: `link::client::watch_tasks` returns a `Watch`
  (`busy()` snapshot, `recv(timeout)` → `Frame` / `Timeout` / `Closed`).
- **Verified with a real Go client** (`tests/go_watch.rs`, 1 test): the Rust link server accepts a
  generated Go program's `watch-tasks` subscription over its AF_UNIX socket, the registry then
  starts a task (`EVENT busy=true`) and stops that same task (`EVENT busy=false`), and the link's
  shutdown closes the connection (the Go side prints `EOF` and exits 0). The Go source rides inside
  the test and is written to the gitignored `pig-tmp/linkwatch/` at run time — **no `.go` file is
  committed** (maintainer directive); the test skips when `go` is not installed.
- Tests: +3 unit (`watchers_see_busy_and_not_busy` — ack snapshot, both flip directions, the
  quiet-not-dead gap, an unwatched flip still told to a late subscriber, stop closing the
  subscription; `registry_start_and_exit_flip_the_watched_state` — the production registry path
  with no explicit broadcast in the test; `watcher_cap_refuses_beyond_the_limit`) +1 integration
  (`go_client_receives_busy_notifications`) — 130 unit + 14 smoke + 1 Go green, `cargo check
  --all-targets` and the `x86_64-unknown-linux-gnu` cross check clean.

## [0.3.4] - 2026-11-25

- **Hung-task notification**: a command that was *not* launched with `run_in_background` but was
  backgrounded later (timeout auto-background, `Ctrl+Shift+B`, steering) and is **still running 10
  minutes after the promotion** now earns one extra steered notification (`bg-task-hung-notification`,
  rendered as a `● summary` line like `<task-notification>`). Its `<task-hung-notification>` XML carries
  `<backgrounded_for>` / `<running_for>` / `<tail_preview>` and the model-facing instruction *"Call bg_list
  to see all tasks, then call bg_stop for any hung tasks."* — so the model wakes up, lists the tasks and
  stops the hung ones. Mechanism: `promote_to_background` stamps a new `Job::promoted_at` (first call
  wins) and arms a one-shot watcher thread at `HUNG_NOTIFY_AFTER_MS` (10 min); `notify::send_hung_notification`
  re-checks eligibility (still running, actually backgrounded) and takes its own `hung_notified` latch
  BEFORE the send — independent of the completion latch, so the two notifications can neither steal nor
  be stolen from each other. Exactly-once per task, lost-not-retried on send failure or missing notifier
  (same policy as completions); a task that finished or was stopped during the 10-minute window sends
  nothing, and `session_shutdown`'s silent kill qualifies as "stopped". Tasks launched with
  `run_in_background=true` never arm the watcher and are refused by the sender even if called directly
  (`promoted_at` stays `None`) — they are intentional, not backgrounded-against-the-model's-plan.
- Tests: +8 (4 `notify` — eligibility gate, XML/instruction shape, exactly-once with latch independence,
  terminal/no-notifier suppression; 4 `lifecycle` — the 10-minute threshold constant, promotion stamps
  the clock while launch-background jobs have none, the watcher nags a still-running promoted task,
  silence for a task finished during the wait) — 127 unit + 14 smoke green.

## [0.3.3] - 2026-11-22

- **Windows link transport swapped for the `uds_windows` crate, and the two per-platform
  transport files collapsed into one** (`link::transport`): the hand-rolled winsock code
  (`WSAStartup`, `sockaddr_un` packing, raw `bind`/`listen`/`accept`/
  `connect`, wrapping the accepted handle in a `TcpStream`) is gone — the Windows build now uses
  `uds_windows::UnixListener`/`UnixStream`, the std-shaped AF_UNIX lookalikes. With both
  platforms on the std-shaped API, `transport_unix.rs` + `transport_win.rs` are one file whose
  only `cfg` difference is the type import (plus Unix's 0600 socket mode). Same socket: still
  winsock `AF_UNIX` at `<osTempDir>/pig-sandbox-<id>.sock`, same JSON-per-line wire, same
  stale-socket removal + trace on bind and listener `Drop`, same read/write timeouts
  (`SO_RCVTIMEO`/`SO_SNDTIMEO`, as `TcpStream` set them). The std `TcpListener::accept` caveat
  that motivated the raw `accept` is unchanged — `uds_windows` does the AF_UNIX-aware accept.
  The `windows` crate keeps its job-object/process features; `Win32_Networking_WinSock` is no
  longer needed (pinned `=1.2.1`, E9-style).
- Tests: unchanged — full suite green on Windows (119 unit + 14 smoke, the link suite binding
  real sockets) and the `x86_64-unknown-linux-gnu` cross-check stays clean.

## [0.3.2] - 2026-11-21

- **Link diagnostics (logging only — no behavior change)**, grown out of the 2026-11-21 orphan-socket
  incident: a parent's extension runner died without `session_shutdown`, its `%TEMP%/pig-sandbox-<id>.sock`
  file outlived the listener, and every child dial failed `os error 10061` while the trace could not say
  whose `link_stopped` belonged to whom or when the listener actually died. Now:
  - `link_started` carries `endpoint` + `pid`; `link_stopped` carries `session`, `reason`
    (`session_shutdown` vs the `restart` inside `start` vs plain `stop`), `endpoints`, and
    `thread_exited` — a stop whose accept thread missed the 2 s window additionally traces
    `link_stop_timeout` instead of pretending to be clean.
  - accept-thread lifecycle: `link_accept_thread_started` at bind, `link_accept_thread_exited`
    (`why: "stopped" | "panicked"` + panic payload) — a panic in the accept loop previously killed
    the listener without a trace.
  - `link_served {op}` per answered request: positive evidence this process's listener answered,
    separating "alive but never asked" from "gone" after the fact; `link_version_mismatch` for
    refused frames.
  - ignored filesystem failures are no longer silent: `link_stale_socket_remove_failed` (bind) and
    `link_socket_remove_failed` (listener Drop) — the exact "file present, connect refused" state.
  - extension lifecycle markers `ext_session_start_done` / `ext_session_shutdown_done` (session +
    pid) bound the death window of a runner that never got its shutdown event.
  - child side: a refused escalation now traces `link_ask_unreachable {parent, ask, err}` alongside
    the existing `link_policy_unreachable`.
- Tests: +1 (`lifecycle_trace_is_attributable`) — 119 unit + 14 smoke green.

## [0.3.1] - 2026-11-21

- **One socket per session, in the OS temp dir** (`DELEGATED-WORKSPACES.md` §B): the link's
  endpoint is now `<osTempDir>/pig-sandbox-<sessionId>.sock` — a single socket instead of the old
  config-root primary plus temp-dir fallback, so parent and child derive the same path from
  knowledge they already share (a config root that differs between the two no longer matters;
  `config_root` left the link API entirely). Everything that crosses the link rides that one
  socket: the `policy` fetch, the `ask` relay, and the new `policy-update` push below.
- **Permission-level changes propagate to children**: a child that fetches `op:"policy"` (or asks)
  is registered with its parent, and `/sandbox` — the one place a session's level widens or
  narrows — pushes the parent's live policy down every registered child's socket
  (`{"v":1,"op":"policy-update","parent":…,"policy":{mode, workspace, temp, extras}}`).
  Detached and best-effort: a child that is gone is traced and never delays the switch. The child's
  applier (`inherit::apply_update`) replaces its mirrored baseline in **both** directions and only
  when the frame names the session it mirrors — a foreign sender, an unknown mode or no mirror at
  all leaves the mirror untouched — and replies `applied`, which is what the parent traces. The
  child's next tool call converges under the new level, so grandchildren follow on the next hop.
- Tests: +3 (single-socket endpoint derivation, the fan-out over two sockets, `apply_update`'s
  both-directions baseline move) — 118 unit + 14 smoke green.

## [0.3.0] - 2026-11-20

- **Delegated-workspace parent link** (`DELEGATED-WORKSPACES.md` §B): one AF_UNIX socket per
  session — `<configRoot>/agent/sandbox-asks/<sessionId>.sock` with a temp-dir fallback, on every
  platform including Windows (winsock `AF_UNIX`; std's `TcpListener::accept` cannot accept an
  AF_UNIX address, so the listener wraps a raw winsock `accept`). The parent's pig-bg-tasks listens
  from `session_start` under its own SDK session id; a child (any environment carrying
  `PIG_PARENT_SESSION`) dials it. A session may be child and parent at the same time.
- **Approvals flow to the parent, asked of the user as if they originated there** — no new model
  tools. A headless child's escalation rides the socket and blocks (≤ 300 s); the parent session
  puts it in front of its user through its **own** Deny-first dialog (same title builder, byte
  -identical wording), and replies `allow` / `deny` (+ reason) / `cancel`. A dismissed dialog
  approves nothing; a headless parent, a dialog error, no listener or a timeout is fail-closed —
  nothing executes — and a deny's reason reaches the child in the ladder's usual wording.
- **Children mirror the parent's sandbox policy**: fetched at `session_start`, the parent's mode
  becomes the child's baseline (its own `sandbox.json` default does not apply) and a local
  `/sandbox` choice may only narrow it; the parent's extra writable roots replace the child's
  (through `config_for`, the single choke point). An unreachable parent leaves the local policy
  untouched — a child never widens by being unreachable; nested children mirror their immediate
  parent, so the chain propagates.
- Tests: 11 link tests (AF_UNIX framing, endpoint derivation, policy fetch, ask → dialog verdict
  including deny/cancel/headless refusal, `escalate::approve` over the socket, fail-closed
  unreachable parent, client deadline) + 3 policy-mirror tests — full suite green (115 unit +
  14 smoke).

## [0.1.0] - 2026-11-08

- First npm release.
- One composed `bash` tool: sandbox params (`sandbox_permissions`,
  `justification`) and background params (`run_in_background`, `timeout`,
  `description`) on a single execute path, with denial-first escalation.
- Permission modes with fail-closed mxc confinement (ProcessContainer /
  Bubblewrap / Seatbelt) and denial classification; `/sandbox [mode]` to
  inspect or switch process-wide.
- `bg_list`, `bg_output`, `bg_stop`; `Ctrl+Shift+B`; `/bg`, `/bg-tasks`;
  `<task-notification>` renderer with exactly-once completion notifications.

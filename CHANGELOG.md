# Changelog

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

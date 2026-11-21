# Changelog

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

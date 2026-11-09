# Changelog

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

#!/usr/bin/env bash
# Quickly (re-)apply the shell-resolution patch to the INSTALLED npm
# pi-bg-tasks package. Needed after EVERY `pig install npm:pi-bg-tasks`:
# npm installs overwrite the fix, and an unpatched pi-bg-tasks spawns a
# bare `bash`, which on Windows resolves to the WSL alias — every bash-tool
# command then runs inside WSL (OSTYPE=linux-gnu, quoting corrupted,
# shellPath ignored). See github.com/cyzlmh/pi-extensions/issues/2.
#
# Usage (from this repo, Git Bash or any bash):
#   bash tools/apply-pi-bg-tasks-patch.sh
#
# Verify after running: reload pig, then `echo $OSTYPE` must print
# `msys` or `cygwin` — never `linux-gnu`.
set -euo pipefail

DIR="${PIG_BG_TASKS_DIR:-$HOME/.pig/agent/npm/node_modules/pi-bg-tasks}"
SPAWN="$DIR/extensions/bg-tasks/spawn.ts"
PATCH="$(cd "$(dirname "$0")" && pwd)/pi-bg-tasks-shell.patch"

if [ ! -f "$SPAWN" ]; then
  echo "ERROR: installed pi-bg-tasks not found at:" >&2
  echo "  $SPAWN" >&2
  echo "Install it first:  pig install npm:pi-bg-tasks" >&2
  echo "(or set PIG_BG_TASKS_DIR to the package root)" >&2
  exit 1
fi

if grep -q 'proc = spawn(shell' "$SPAWN"; then
  echo "already patched: $SPAWN"
  exit 0
fi

patch -p1 -d "$DIR" --no-backup-if-mismatch < "$PATCH"

if ! grep -q 'proc = spawn(shell' "$SPAWN"; then
  echo "ERROR: patch did not apply — inspect $SPAWN" >&2
  exit 1
fi

echo "patched: $SPAWN"
echo "Now reload pig (or restart), and check: echo \$OSTYPE  ->  msys/cygwin"
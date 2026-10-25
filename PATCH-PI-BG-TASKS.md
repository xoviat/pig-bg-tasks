# Re-applying the `pi-bg-tasks` shell patch (Windows)

The npm `pi-bg-tasks` package spawns a **bare `bash`**, which on Windows
resolves to the **WSL app-execution alias**. Every bash-tool command then runs
inside WSL instead of the configured shell:

- `shellPath` in settings is ignored
- `$OSTYPE` prints `linux-gnu`; the filesystem/env view is `/mnt/c/...`, `HOME=/home/<wsl-user>`
- quoting is corrupted by the Windows→WSL argv hop (`echo 'Q$HOME'` expands `$HOME`)

Upstream issue: <https://github.com/cyzlmh/pi-extensions/issues/2>
(patch = `getShellConfig()` from the pi runtime, which resolves
`shellPath` → Git Bash in standard locations → `bash` on PATH).

> The `pig-bg-tasks` extension in this repo does **not** need this patch — it
> resolves the configured shell itself (`internal/runner`). This document is
> only for using the **npm package** as a fallback.

## Quick apply (one command)

```bash
bash tools/apply-pi-bg-tasks-patch.sh
```

Idempotent (says `already patched` when present), applies
`tools/pi-bg-tasks-shell.patch` to
`~/.pig/agent/npm/node_modules/pi-bg-tasks/extensions/bg-tasks/spawn.ts`
(override the package root with `PIG_BG_TASKS_DIR=...` if needed).

**Re-run it after every `pig install npm:pi-bg-tasks`** — an npm (re)install
overwrites `spawn.ts` and silently drops the fix.

## Switch-back recipe (npm fallback flow)

```bash
pig remove pig-bg-tasks                                   # remove this extension
pig install npm:pi-bg-tasks                               # fresh (unpatched!) install
bash tools/apply-pi-bg-tasks-patch.sh                     # <-- apply BEFORE reloading
```

Then `/reload` (or restart pig) and verify:

```bash
echo $OSTYPE     # must print: msys  or  cygwin   (never linux-gnu)
```

## What the patch changes

`extensions/bg-tasks/spawn.ts`:

```ts
// before
import { SIGTERM_GRACE_MS, type SpawnExit } from "./types.ts";
...
proc = spawn("bash", ["-c", args.command], { ... });

// after
import { SIGTERM_GRACE_MS, type SpawnExit } from "./types.ts";
import { getShellConfig } from "@earendil-works/pi-coding-agent";
...
const { shell, args: shellArgs, commandTransport } = getShellConfig();
// stdin transport is only selected for the legacy System32 WSL bash;
// this backend ignores stdin (output rides the log fd), so in that
// case the command must be passed as an argument instead.
const argList = commandTransport === "stdin" ? ["-c"] : shellArgs;
proc = spawn(shell, [...argList, args.command], { ... });
```

## Manual fallback

If the script cannot run, apply the diff by hand or with GNU patch from the
package root:

```bash
cd ~/.pig/agent/npm/node_modules/pi-bg-tasks
patch -p1 --no-backup-if-mismatch < /path/to/pig-bg-tasks/tools/pi-bg-tasks-shell.patch
```

Verify both markers landed:

```bash
grep -n "getShellConfig\|proc = spawn(shell" \
  ~/.pig/agent/npm/node_modules/pi-bg-tasks/extensions/bg-tasks/spawn.ts
# expect: the import line, the destructure line, and proc = spawn(shell, ...
```

## Validation status

The script + patch were round-trip tested on this machine: pristine package →
patch applied (both hunks) → result byte-identical to the known-good file;
second run reports `already patched` and changes nothing.
# Testing the Rust extension (`pig-bg-tasks/`)

The extension directory **must be named `pig-bg-tasks`**: a direct `-e`
directory selection takes the _directory_ as the extension identity
(`extensions.md`), and runtime registration is `Extension::new("pig-bg-tasks")`
— a mismatch fails with `register:name_mismatch`. The Go extension's repo
root carries the same name for the same reason.

Every test of the _extension itself_ runs **through pig** — pig owns Rust
extension builds: it generates the runner, stages the matching SDK under the
active config root, and compiles everything into a content-addressed runtime
cell (`extensions.md`: "PiG generates the runner"; `packages.md`: "A source
extension builds into a content-addressed runtime cell"). Plain `cargo build`
cannot resolve the root package — `pig-sdk = "0.1.0"` is not on crates.io —
and that is by design (E7-verified; no `[patch]` belongs in `Cargo.toml`).

All commands below run from the repository root. Scratch lives under
`pig-tmp/` (gitignored).

## 1. Isolated pig home

```bash
PIG_HOME="$(pwd)/pig-tmp/pig-home-test"
mkdir -p "$PIG_HOME/agent"
# seed ONLY the model config — never copy extensions/
cp -n ~/.pig/agent/settings.json ~/.pig/agent/auth.json "$PIG_HOME/agent/"
cp -n ~/.pig/agent/models.json ~/.pig/agent/models-store.json "$PIG_HOME/agent/" 2>/dev/null
# retarget the TEST home's shell at brush — the real global config may still
# point at Git Bash, which confined spawns REJECT by design (MSYS fail-fast)
python - <<'EOF'
import json, pathlib
p = pathlib.Path("pig-tmp/pig-home-test/agent/settings.json")
s = json.loads(p.read_text(encoding="utf-8"))
s["shellPath"] = r"~\.cargo\bin\brush.exe"
p.write_text(json.dumps(s, indent=2), encoding="utf-8")
EOF
```

`PIG_HOME` moves settings, sessions, trust decisions and product state
(`environment-variables.md`): the scratch home starts with no sessions, no
installed packages and no `agent/extensions/`. The model files are copied so
print mode has a model to call.

One staging quirk: the **first** `PIG_HOME=…` run can fail with
`replace staged rust SDK: … Access is denied` — a `.transaction.lock` race in
`<PIG_HOME>/state/pigsdk/`. Rerun; staging succeeds (Go, Python and Rust SDKs
appear: `sdk-<hash>`, `sdk-py-<hash>`, `sdk-rs-<hash>`).

## 2. Load ONLY the Rust extension — always `-ne`

```bash
PIG_HOME="$PIG_HOME" pig -ne -e "$(pwd)/pig-bg-tasks" …
```

`pig -ne` is `--no-extensions`: _"Skip discovered, configured, and built-in
extensions; useful for isolating bugs. Explicit `-e` paths still load"_
(`commands.md`). **Never launch without it when testing this extension**: the
config root's discovery (`~/.pig/agent/extensions`, settings-declared
extension paths, packages) can load the **Go pig-bg-tasks extension**, and
both extensions register the identical tool names (`bash`, `bg_list`,
`bg_output`, `bg_stop`, `bg_debug`) — same-name registration means whichever
loads wins, and a mixed session silently tests the wrong one.

## 3. Validate: build + registration, no session

```bash
PIG_HOME="$PIG_HOME" pig install ./pig-bg-tasks --validate-only --json
```

Resolution "builds or launches it, accepts runtime registration, verifies
identity" (`extensions.md`) — the cheapest full build check. Expect:

```json
{ "valid": true, "commands": [ ... bg, bg-tasks, sandbox ... ], ... }
```

The **first run builds the runtime cell** (cargo compiles the whole workspace
plus `mxc-sdk` and the staged `pig-sdk` — minutes; `PIG_CELL_BUILD_TIMEOUT`
raises the build cap, `environment-variables.md`). Later runs hit the
content-addressed cache and are fast. `pig reload` drops cells an older SDK
produced.

## 4. End-to-end: piped prompts in print mode

```bash
printf '%s\n' "Run: echo HARNESS_OK — use the bash tool and reply with its exact output." \
  | PIG_HOME="$PIG_HOME" pig -ne -e "$(pwd)/pig-bg-tasks" -p \
  > pig-tmp/smoke-rs-harness.log 2>&1
```

Print-mode facts (`cli-integration.md`):

- `-p` / `--print` takes **no value**; the prompt comes from piped stdin
  (the pipe must reach EOF, else startup waits — `--no-stdin` skips the
  read), then `@file` arguments, then the first message argument. Further
  message arguments run as extra prompts after the first finishes.
- stdout carries **only the final assistant answer**; everything tools or
  the extension write goes to **stderr** — extension failures appear there
  as `Extension error (<path>): <message>`. Redirect both to the log (as
  above) to capture the tool traffic.
- Exit codes: `0` answer completed; `1` no model / start failure / error
  stop reason; `128+signal` interrupted.
- PiG auto-selects print mode when stdin/stdout is not a terminal, so a pipe
  alone is enough.

This is the README's acceptance pattern (`pig -ne -e ./ -p`, 30 s caps,
logs `pig-tmp/smoke-*.log`): confined `echo`, workspace write+read, outside
write denied + denial marker + escalation hint, headless escalation refusal,
read-only denies workspace, `bg_list`/`bg_output`/`bg_stop`, `<task-notification>`
exactly-once, `danger-full-access` bare, `/sandbox` via its route.

Wrap runs in a cap: `timeout 90 …` (or the harness's own 30 s cap) — a
hung tool must not hang the agent. **But size the cap for the cell build:**
on _changed sources_ the session first rebuilds the packed Rust cell —
observed ~9 min cold (vs ~60 s warm) — and during it the log shows nothing
beyond the package lines until it finishes; a 240 s cap killed a healthy run
with `EXIT=124` and a 132-byte log. Recipe: warm the cell first with
`pig install … --validate-only` (set `PIG_CELL_BUILD_TIMEOUT=1200` for the
cold build), then run the piped prompts with modest caps — they reuse the
cached cell. Re-warm after ANY source edit.

### Observed (2026-10-25, this machine)

- `pig install ./pig-bg-tasks --validate-only --json` →
  `"valid": true, "registered": true`, definition
  `{form: factory, language: rust, package: pig-bg-tasks, factory:
new_extension, packable: true, runtime: subprocess, sdk: pig-sdk-rs}` —
  all 5 tools and 3 commands registered.
- One piped prompt (bash `echo HARNESS_OK` + `bg_debug`) → answer contained
  `HARNESS_OK` and the verbatim debug block: `mode: workspace-write (config
default) confined: true`, `runner: windows-acl (partial enforcement)`,
  `convergence: epoch 1 — converged: workspace-write [workspace ; temp]`,
  `shell: …\.cargo\bin\brush.exe (configured shellPath override: …)`,
  `config file: …pig-home-test\agent\sandbox.json (absent — defaults in use)`,
  `noninteractive=true` (print mode). The traced spawn shows
  `"mode":"workspace-write","confined":true,"shell":"…brush.exe"` with
  `age_ms:100`.

Two traps observed in that run's log — assert accordingly:

- **The trace file is machine-wide** (`%TEMP%\pi-bg-tasks\bash-calls.jsonl`):
  every pig session and every extension appends to it (pre-existing Go
  design). `bg_debug`'s `trace:` section therefore shows _other sessions'_
  records — here: the harness session's own `danger-full-access` + Git-Bash
  records. Match records by `id`/`ts` (the session's job ids are in its task
  logs), not by expecting only this session's lines.
- **The model may run `bash` and `bg_debug` in parallel** — the debug tail
  then snapshots a few milliseconds _before_ the bash records flush and omits
  them (observed: same-second timestamps, freshest records missing). For a
  deterministic trace assertion, make the prompt explicitly sequential ("first
  … then … after it finished") or re-read the JSONL afterwards.
- **Quote Windows paths in test commands.** Unquoted backslashes are eaten by
  bash word processing (`echo x > C:\Windows\Temp\f.txt` → target
  `C:WindowsTemppig-f.txt`, a drive-relative name that resolves _inside the
  workspace_): the write succeeds, exit 0, no output — and the run looks like
  "the denial never happened" when the protected path was simply never
  targeted. Observed 2026-10-25 (stray `WindowsTemppig-*.txt` litter in the
  repo root, cleaned). Use `> "C:\Windows\Temp\f.txt"` — backslashes are
  literal inside double quotes — and assert on the _quoted_ form in prompts.

### Acceptance matrix through pig (§6) — observed 2026-10-25, all green

| Run                 | Log                                       | Result                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| ------------------- | ----------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| tools/sed           | `pig-tmp/smoke-rs-tools.log`              | `command -v sed` → `…\shell-candidates\ubin\sed`; sed/wc/grep/awk pipeline + marker; `bg_debug` shows `userland: …\ubin` and the _fresh_ sequential trace (`bash-6kz0reqv` confined/brush/epoch 1, 453 ms)                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| denial              | `smoke-rs-deny2.log`                      | quoted write to `C:\Windows\Temp` → brush `…Access is denied. (os error 5)` + `[sandbox: file access denied under workspace-write mode]` + escalation hint (writable roots, retry shape, approval note); file created nowhere                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| headless escalation | `smoke-rs-deny2.log`                      | retry with `danger-full-access` after a recorded denial → `requires approval, but no approval channel is available — nothing was executed` (fail-closed). The _ignore-note_ branch is in `smoke-rs-deny.log` (B1): escalation with no denial on record → fields dropped, ran workspace-write with `[sandbox: escalation fields were ignored …]`                                                                                                                                                                                                                                                                                                                        |
| bg lifecycle        | `smoke-rs-bg3.log` (+ `bg`, `bg2`)        | `run_in_background` → `Command running in background with ID: bash-113kgfil …`; `bg_list` `Running (1) ▶ bg (1s)` with live tail; `bg_output` `Status: running`; `bg_stop` → `Status: killed` + `Task … stopped (Job-object terminate — whole tree)`. fg calls also register (`smoke-rs-bg.log`/`bg2`): `Recent: … ✓ completed exit=0`, `bg_output` 32 KiB tail, `bg_stop` no-op (`already completed/failed`). **No `<task-notification>` on user-stop is CORRECT** — Go `TerminateJobSilently` latches `Notified` before the kill (verified `lifecycle.go:138`, ported 1:1): silent kills emit zero notifications; watcher-path completions/failures emit exactly one |
| git clone           | `smoke-rs-gitclone.log`                   | `git clone --depth 1 https://github.com/octocat/Hello-World.git` → `README` + commit `7fd1a60` + marker (native `git.exe` survives MXC; tree re-verified out-of-band, then removed)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| danger bare         | `smoke-rs-bare.log`, `smoke-rs-bare2.log` | fixture `agent/sandbox.json` = `{"mode":"danger-full-access"}` → `mode: danger-full-access (config default)  confined: false`, `runner: bypassed (danger-full-access)`, trace `confined:false`; `ping` 2/2 + `BARE_OK`. Restore = delete the fixture (`config file: … (absent — defaults in use)`)                                                                                                                                                                                                                                                                                                                                                                     |

Environment facts for future prompts:

- **ICMP is blocked inside the container**: `ping` → `Unable to contact IP
driver. General failure.` exit 1 (native tool runs; the driver refuses).
  Use `powershell -NoProfile -Command "Start-Sleep N"` for long tasks
  confined (works; one harmless `InitializeDefaultDrives` stderr line).
  `ping` works in bare mode — that contrast is the confinement delta.
- A trailing ` .` (sentence punctuation) becomes part of the command —
  `ping … .` → `Bad parameter .`. End prompts with a separator word, not a
  period directly after the command.

## 5. `session_start` without a model session

```bash
PIG_HOME="$PIG_HOME" pig extension preview-login "$(pwd)/pig-bg-tasks"
```

"Start exactly one extension and render the login set during `session_start`;
no model session starts" (`commands.md`) — exercises the `session_start`
handler (config home pin, `shellPath` read, epoch start, status pill) in
isolation.

## 6. Unit + smoke tests (cargo)

```bash
cd pig-bg-tasks && cargo test --workspace     # bg, policy, runner, classify, escalate, smoke matrix
```

`pig-sdk` resolution for plain cargo comes from `pig-bg-tasks/.cargo/config.toml`,
which carries an **absolute-path** `[patch.crates-io]` to the staged SDK.
It is deliberately a _config file_, not a `Cargo.toml` patch: pig copies
sources into its cell, where a relative manifest patch would resolve to the
wrong place (and pig resolves the dependency itself at build time anyway).

The smoke matrix (`pig-bg-tasks/tests/smoke.rs`, 15 sections) drives the runner
directly against real MXC containers and needs this machine's shell facts
(overridable by env):

- `PIG_TEST_SHELL` — native Win32 shell (default: `%USERPROFILE%\.cargo\bin\brush.exe`,
  per the E3 decision; MSYS/Git-Bash engines are rejected under confinement);
- `PIG_TEST_BUSYBOX` — busybox-w32 source for the `sleep.exe` fixture
  (default: `pig-tmp/shell-candidates/busybox64.exe`; applet userland from
  `pig-tmp/shell-candidates/ubin` is prepended to the in-container `PATH`).

Without a native shell the smoke sections skip with a notice instead of
failing (they assert machine-class claims, same as the Phase 0 gates).

## 7. Known gaps when testing (deferred work)

- **No userland provisioning yet (deferred 2026-10-24).** The extension does
  NOT put busybox applets on the child `PATH` — so under `shellPath=brush`,
  externals like **`sed` are unavailable inside confined spawns** (the host
  PATH's `sed` is Git's MSYS build, which dies under MXC per the E3-bis
  findings). The smoke matrix works around it by prepending
  `pig-tmp/shell-candidates/ubin` in _its own_ spawn env; the extension
  proper does not. Keep harness prompts on brush builtins (`echo`, `test`,
  redirections), or treat missing-`sed` as this known gap — proper
  provisioning (ship applets + child-PATH wiring) is a **later session's
  task**.
- **Never edit `pig-bg-tasks/` during a pig build.** Pig content-hashes the
  extension source while building the cell; a mid-build edit fails with
  `the source of … pig-bg-tasks changed while it was being built, so nothing was
cached; start again to build the current source`. Freeze the tree, run,
  then edit (and rerun).
- **The real global `shellPath` may be Git Bash** (it is, as of
  2026-10-24). Confined spawns reject MSYS/Git-Bash engines _before_ spawn
  (the mxc#1061 fail-fast, plan §4) — that is correct behavior, not a bug.
  Always override `shellPath` in the TEST home (step 1) or expect every
  confined `bash` call to return the `SANDBOX_UNAVAILABLE: … MSYS …` refusal.
- The scratch settings copied from the real home may list `packages`
  (including the Go pig-bg-tasks package). `-ne` skips them — one more reason
  never to drop `-ne`.
- **`.cargo/config.toml`'s `pig-sdk` patch path must be ABSOLUTE.** Cargo does
  not expand `~`: if the file shows a `~/.pig/state/pigsdk/…` form (observed
  2026-10-25 rewritten mid-session, mtime traced to a pig run window — some
  staging step normalizes it), plain cargo fails with
  `failed to read <workspace>\pig-bg-tasks\~\.pig\… (os error 3)`. Restore
  `path = "%USERPROFILE%/.pig/state/pigsdk/sdk-rs-<hash>"` (the dir must
  exist under `%USERPROFILE%\.pig\state\pigsdk\`). Pig's own cell builds are
  unaffected — they resolve the SDK themselves.

## 8. Where things live

| Thing                        | Location                                                                                                 |
| ---------------------------- | -------------------------------------------------------------------------------------------------------- |
| Isolated config root         | `pig-tmp/pig-home-test/` (scratch, gitignored)                                                           |
| Staged SDKs (Go/Python/Rust) | `$PIG_HOME/state/pigsdk/sdk-*`                                                                           |
| Model config (copied)        | `$PIG_HOME/agent/{settings,auth,models,models-store}.*`                                                  |
| Print-mode run logs          | `pig-tmp/smoke-rs-*.log` (stderr half has tool traffic)                                                  |
| Task logs / trace            | `%TEMP%\pi-bg-tasks\*.log`, `%TEMP%\pi-bg-tasks\bash-calls.jsonl` (also surfaced by the `bg_debug` tool) |
| Unit/smoke test logs         | `pig-bg-tasks/target/…` via `cargo test`                                                                 |

Related: `RUST-PLAN.md` (phases, gates), `RUST-DECISION.md` (gate results,
E13 persistence drop), `README.md` (the Go extension's acceptance history —
the pattern above is ported from it).

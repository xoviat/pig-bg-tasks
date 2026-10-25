> **Archived evidence (Phase-4 cleanup, 2026-10-25)** — copied from the Go repo `srt-win/`.
> Original result: Schannel/OS-TLS fails under srt-win restricted tokens (SEC_E_NO_CREDENTIALS).
> MXC delta (RUST-DECISION E2/E10, smoke s10): Schannel HTTPS WORKS under MXC confinement — the
> finding below does not apply to this build; it documents why srt-win was replaced.

# srt-win + Schannel: the restricted-SID list kills all OS-TLS credential acquisition

**Status:** root-caused empirically; **no fix exists** — the trigger is the mere
presence of a restricted-SID list, which is the one thing `CreateRestrictedToken`
cannot do without. Every Schannel-based TLS client (cargo, curl, PowerShell,
.NET, git-over-https) fails under any srt-win sandbox with
`SEC_E_NO_CREDENTIALS`. OpenSSL-backed clients (node, python, openssl.exe) are
unaffected. This document contains everything needed to reproduce and re-examine
the problem — e.g. to find an exemption strategy, or to prove none exists.

Reported upstream for other restricted-token sandboxes too: openai/codex#17459,
dsh-sandbox troubleshooting doc, dotnet/runtime#102692 — same signature.

---

## 1. Symptom

Report: "cargo could not fetch deps from crates.io inside the sandbox."
Reproduced verbatim (`pig-tmp/cargo-repro`, a scratch crate depending on
`serde`):

```bash
# unconfined — works
CARGO_HOME=<scratch> cargo fetch
#   Downloaded serde_core v1.0.229 / serde v1.0.229 / syn v3.0.9 / ...

# confined — identical env, workspace + %TEMP% writable
srt-win.exe "C:\...\workspace\pig-bg-tasks" "C:\Users\...\AppData\Local\Temp" \
    -- cargo fetch
warning: spurious network error (2 tries remaining): [35] SSL connect error
  (schannel: AcquireCredentialsHandle failed: SEC_E_NO_CREDENTIALS (0x8009030e)
   - No credentials are available in the security package)
error: failed to load source for dependency `serde`
  ... unable to update registry `crates-io` ... download of config.json failed
```

Not cargo-specific:

```bash
srt-win.exe <dirs> -- curl -s https://index.crates.io/config.json
#   curl: (35) ... SEC_E_NO_CREDENTIALS (0x8009030e)     [exit 35, http 000]
```

DNS, TCP connect, plain HTTP, and all file **reads** work. The failure is
exactly at `AcquireCredentialsHandle` — the TLS handshake never starts.

---

## 2. What it is NOT (each ruled out by a probe)

Probes built for this investigation (scratch, rebuild as needed — see §5):

| probe                                                                                                                                                                                   | finding                                                                                                                                                                                                                  |
| --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `pig-tmp/sspiprobe` — calls `AcquireCredentialsHandle` for schannel/Negotiate/Kerberos/NTLM directly, plus `CertOpenSystemStore(Root/MY)` and `CryptAcquireContext` (incl. `NEWKEYSET`) | cert stores and CAPI **succeed** under the token; only the SSPI calls return `0x8009030E` (Kerberos: `0x80090304`)                                                                                                       |
| Procmon capture of the confined probe                                                                                                                                                   | the only `ACCESS DENIED` in the probe process is `HKLM\...\WinSock2\Parameters` opened _All Access_ — **which fails identically unconfined** (retried with Read, succeeds). Zero lsass.exe denials in the whole capture. |
| `pig-tmp/lsaprobe` — `LsaConnectUntrusted` → `LsaLookupAuthenticationPackage` → `LsaCallAuthenticationPackage` → `GetUserNameEx` → `DsGetDcName`                                        | **byte-identical** confined vs unconfined. The LSA layer itself is reachable and healthy.                                                                                                                                |
| granting extra writable dirs (`AppData\Local\Microsoft`, whole profile)                                                                                                                 | no effect — it is not a file write                                                                                                                                                                                       |

So: not a missing writable dir, not a file/registry ACL that Procmon can see,
not a broken LSA connection. It is inside SSPI's credential acquisition on a
restricted token.

---

## 3. The bisection — what exactly triggers it

`srt-win` mints the token with
`flags = DISABLE_MAX_PRIVILEGE | WRITE_RESTRICTED (0x9)` and restricted list
`{Everyone, logon SID, synthetic SID, user SID}` (see `GITBASH-GATE.md` §2 for
the two-pass access-check model).

`pig-tmp/sidprobe` mints `CreateRestrictedToken` variants (any flags, any
restricted list) and runs `sspiprobe` under each. Observed (2026-10, the test
machine of `GITBASH-GATE.md`):

| flags                       | restricted-SID list                                                                                                  | schannel/NTLM/Negotiate         |
| --------------------------- | -------------------------------------------------------------------------------------------------------------------- | ------------------------------- |
| 0x9 (srt-win's)             | `{Everyone, logon, synthetic, user}`                                                                                 | **FAIL** `SEC_E_NO_CREDENTIALS` |
| 0x8 (WRITE_RESTRICTED only) | same                                                                                                                 | **FAIL**                        |
| 0x1 (privilege loss only)   | same (superset form, see note)                                                                                       | **FAIL**                        |
| 0x9 / 0x1 / **0**           | **full 15-group superset** of the user's token groups                                                                | **FAIL**                        |
| 0x9                         | base + each well-known SID individually (Users, Authenticated Users, INTERACTIVE, NETWORK, THIS ORGANIZATION, LOCAL) | **FAIL**                        |
| 0x9                         | superset + SYSTEM / LOCAL SERVICE / NETWORK SERVICE / CREATOR OWNER                                                  | **FAIL**                        |
| 0x9                         | **empty list** (`WRITE_RESTRICTED` with pass-2-∅)                                                                    | **OK**                          |
| 0x9                         | **empty list** (`DISABLE_MAX_PRIVILEGE\|WRITE_RESTRICTED`)                                                           | **OK**                          |
| 0                           | empty list (control)                                                                                                 | **OK**                          |

Note: `flags=0x1`/`0` with the _small_ base list fails differently —
`STATUS_DLL_NOT_FOUND`/`#126`, because without `WRITE_RESTRICTED` pass-2 gates
**reads** too and the small list can't read System32. The superset rows fix
process startup; SSPI still fails.

**Conclusion:** the trigger is exactly _the presence of a restricted-SID list_.
Not `WRITE_RESTRICTED` itself (empty list + WRITE_RESTRICTED works), not any
missing SID (the full group superset doesn't help, adding SYSTEM doesn't
help). With a restricted list, pass-2 consults _only_ those SIDs — and
something in Schannel/SSPI's credential-acquisition path fails that check no
matter how broad the list is. Since even a list crediting _every_ SID the user
holds (plus SYSTEM et al.) fails, the failing check is very likely not a DACL
at all but an explicit restricted-token refusal inside the security packages —
consistent with the upstream reports linked above.

---

## 4. Impact on the pig extension

- **Broken under every confined mode** (`workspace-write` and `read-only`):
  cargo, curl (schannel build), PowerShell `Invoke-WebRequest`, .NET
  `HttpClient`/`SslStream`, git-over-https, npm/pnpm registry fetches via
  schannel — anything using the OS TLS stack.
- **Working:** plain HTTP, DNS/TCP, OpenSSL-backed clients (node, python,
  `openssl.exe s_client`), file reads, cert-store reads, CAPI.
- **Not fixable by widening the writable set or the restricted list** — §3.
- The threat model is fat-finger write protection, not network isolation, so
  the practical levers are:
  1. **exempt network-only tools** — spawn `cargo`/`curl`/`git`/`node` etc.
     outside the restricted token (bare spawn), since network is already
     unrestricted by design (`README.md`: "Network is always allowed");
  2. **document + escalate** — detect the `SEC_E_NO_CREDENTIALS` signature in
     the denial classifier and surface the escalation path;
  3. **steer the model** to OpenSSL-backed clients where a choice exists.

Option 1 is the only one that actually restores HTTPS; note it must be an
allowlist by tool, not by env var — there is no knob that makes cargo use a
non-schannel TLS backend (its bundled libcurl uses Schannel on Windows).

---

## 5. Reproduction — copy-paste ready

Environment: Windows 11, Go 1.27.2, cargo 1.97.1, repo root = this workspace.
Scratch lives under `../pig-tmp/` (gitignored).

```bash
cd srt-win && go build -o ../pig-tmp/srt-win.exe ./cmd/srt-win
SRT=../pig-tmp/srt-win.exe
W="~\\workspace\\pig-bg-tasks"
T="~\\AppData\\Local\\Temp"

# 1. cargo symptom
cd ../pig-tmp/cargo-repro
CARGO_HOME=... cargo fetch                       # unconfined: OK
"$SRT" "$W" "$T" -- cargo fetch                  # confined: SEC_E_NO_CREDENTIALS

# 2. minimal TLS probe
"$SRT" "$W" "$T" -- curl -s -o NUL -w "%{http_code}" https://index.crates.io/config.json
#   -> 000 (exit 35);  unconfined -> 200

# 3. layer probes (rebuild: cd pig-tmp/<probe> && GOWORK=off go build .)
"$SRT" "$W" "$T" -- ../pig-tmp/sspiprobe/sspiprobe.exe    # SSPI: FAIL, cert/CAPI: OK
"$SRT" "$W" "$T" -- ../pig-tmp/lsaprobe/lsaprobe.exe      # LSA walk: identical to baseline

# 4. the trigger bisection (mints token variants itself, no srt-win involved)
../pig-tmp/sidprobe/sidprobe.exe                 # empty list -> OK; any list -> FAIL
```

The probes are small standalone `GOWORK=off` modules (`golang.org/x/sys` only);
the repo's `go.work` must be bypassed when building them from inside the
workspace.

---

## 6. What was ruled out, briefly

| idea                                                               | why it fails                                                                                                          |
| ------------------------------------------------------------------ | --------------------------------------------------------------------------------------------------------------------- |
| Grant more writable dirs (profile, `AppData\Local\...`)            | no `ACCESS DENIED` anywhere relevant (Procmon); cert/CAPI writes already succeed under the token                      |
| Add SIDs to the restricted list                                    | tried 6 well-known SIDs individually, the full 15-group token superset, and +SYSTEM/SERVICES/CREATOR — all still fail |
| Drop `WRITE_RESTRICTED`, keep the list                             | still fails (0x1 superset row)                                                                                        |
| Drop the list, keep `WRITE_RESTRICTED`                             | **works** — but a WRITE_RESTRICTED token with no restricted SIDs can write _nothing_; useless as a sandbox            |
| `flags=0` with the list                                            | still fails — so neither flag is required; the list alone triggers it                                                 |
| LSA-level workaround (pre-acquired credentials, different package) | the failure is in the packages themselves; Negotiate/NTLM/schannel all fail, Kerberos returns `0x80090304`            |

The one thing not attempted: an API-level trace _inside_ the security packages
(detours/API monitor, or an NTLM `NtMlMLogFile` capture — the registry knob
`HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0\NtMlMDebugLevel` +
`NtMlMLogFile` was set during this investigation and produced no log for the
acquire path, then cleaned up). If someone wants the exact internal refusal
site, that's the next instrument.

---

## 7. Cleanup notes from the investigation

- NTLM debug values `NtMlMDebugLevel`/`NtMlMLogFile` were added to
  `HKLM\...\Lsa\MSV1_0` and **removed** afterwards; verify with
  `reg query "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0"` if in doubt.
- Dir-grant experiments left synthetic-SID ACEs on
  `AppData\Local\Microsoft`, `AppData\Local`, and the profile root — stripped
  with `icacls <dir> /remove <sid>` (the SID is deterministic:
  `srt-win.exe <dir>` with no command prints it).
- ETW session `sspitrace` (logman, needed admin) was stopped and deleted; the
  Schchannel-Events provider only logs session start/stop, nothing at
  credential acquisition — don't repeat that detour expecting detail.
- Procmon captures were ~750 MB total; delete after use.

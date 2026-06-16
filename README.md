# Find-HardcodedSecrets

A read-only **incident-response** scanner for **Microsoft Defender for Endpoint – Live Response**. It sweeps a live Windows host for `.env` and `.config` files that contain hardcoded secrets and reports **only the location** of each finding — it **never prints the secret value**.

Built for the constrained Live Response shell: Windows PowerShell 5.1, tolerant of Constrained Language Mode and restricted execution policy, fully non-interactive, and forensically sound.

## Script suite (run each separately)

On a large or OneDrive-synced endpoint a single full-disk pass can exceed the Live Response session cap and get killed with no output. So the scan is also split into **focused, single-purpose scripts** — each scoped narrowly so it finishes fast and well under the cap. Upload the one(s) you need and run with the bare, arg-less `run`:

| Script | Scope | Speed | When to use |
|---|---|---|---|
| **`Find-EnvVarSecrets.ps1`** | Environment variables (registry: System + each loaded user hive) | **Seconds** | Always run first — instant, high-value (catches `*_API_KEY`, `*_PASSWORD`, `*_SECRET`, etc.) |
| **`Find-UserProfileSecrets.ps1`** | `.env` / `.config` under `C:\Users` | Fast (bounded) | Most app/developer secrets live in user profiles |
| **`Find-ServerConfigSecrets.ps1`** | IIS (`inetpub`, `applicationHost.config`), .NET Framework `Config`, `ProgramData` | Fast (bounded) | Web/app servers, service configs, `machine.config` |
| **`Find-HardcodedSecrets.ps1`** | Everything: env vars + all fixed drives | Slow (full disk) | Comprehensive sweep when you have the time budget |

```text
run Find-EnvVarSecrets.ps1
run Find-UserProfileSecrets.ps1
run Find-ServerConfigSecrets.ps1
```

All four share the same detection rules (a `rulesRev=` tag in each script's `META` line lets you confirm they carry the same rule generation), output format (`META | / FILE | / FINDING | / SUMMARY |`), and safety guarantees. The rest of this document describes the full `Find-HardcodedSecrets.ps1`; the focused scripts are trimmed subsets of it.

The focused scripts default to a bare `run`, but also accept parameters via `runscript -args` for targeted/triage use: the file scanners expose `-Roots` (override the scanned locations), `-MaxFileSizeMB`, `-ExcludePaths`, `-MinConfidence`, `-MaxRuntimeMinutes`, `-IncludePlaceholders`; the env scanner exposes `-MinConfidence`, `-IncludePlaceholders`, `-AggressiveValueScan`, `-SkipServiceAccounts`. Every default reproduces the bare-`run` behavior exactly. Example: `runscript -scriptName Find-UserProfileSecrets.ps1 -args "-Roots C:\Users\sean.kennedy"`.

### Maintaining the suite

Because each scanner is self-contained, the detection rule table, the pre-filter `TriggerPattern`, the `PlaceholderPatterns`, and the `RulesRev` tag are duplicated across the scripts. After editing any of those, run the drift guard — a dev/CI tool, **not** a Live Response script — which parses every scanner and fails if a rule shared by two scripts differs in pattern or confidence, or if the trigger/placeholders/`RulesRev` diverge:

```powershell
powershell -File tools\Test-SuiteConsistency.ps1   # exit 0 = consistent, 1 = drift
```

All scanners are PSScriptAnalyzer-clean (0 warnings/errors).

## Safety properties

- **Read-only.** Never edits, moves, deletes, renames, or alters any file, attribute, or registry value.
- **Writes nothing to the endpoint.** All output goes to stdout (Live Response captures it). No results file, log, transcript, or temp file.
- **Never emits secret values.** Findings report rule label, confidence, line number, file path, file SHA-256, and the matched-substring *length* (an integer) — never the secret text.
- **No network / off-box activity.** No web requests, DNS, telemetry, module installs, or package downloads.
- **No persistence.** No registry writes, scheduled tasks, or elevation prompts.
- Opens files read-only with shared read/write access, so it does not lock files or block other processes.

## Live Response timeouts &amp; large / OneDrive hosts

Defender Live Response returns a command's output **only when it completes**, and it **terminates** long-running commands — a killed command returns *nothing* (the "Command canceled" / "Terminated by system" result). To stay inside that window the scan:

- Runs the **environment-variable sweep first** (fast, high-value), so those findings are captured even if the file scan is later cut short.
- Bounds the **file** scan with `-MaxRuntimeMinutes` (**default 30**); when the budget is hit it stops cleanly, prints partial results, and sets `truncated=True`. Keep this **below** your tenant's Live Response session cap — if a session is killed by the system first, you get no output. Lower it (e.g. 20) if runs are terminated.
- **Skips cloud / offline placeholder files** (OneDrive Files On-Demand, archival/HSM stubs — `Offline` / `RecallOnOpen` / `RecallOnDataAccess` attributes). Opening one would trigger **hydration** (a download that can hang the scan for many minutes *and* generate off-box traffic) — the most common cause of a scan that runs long and gets killed. These are counted as `skippedCloud`.

So a bare, arg-less `run Find-HardcodedSecrets.ps1` completes and returns results even on a big, OneDrive-synced corporate endpoint.

## Performance

The full-disk walk is the dominant cost, so the scan is tuned to cover as much as possible inside the Live Response window — without sacrificing recall:

- **Faster traversal.** In Full Language Mode it enumerates directories with `System.IO.DirectoryInfo.GetFileSystemInfos()` instead of `Get-ChildItem`, skipping PowerShell's per-item object wrapping (the dominant cost across tens of thousands of directories). Constrained Language Mode falls back to `Get-ChildItem`. Measured **~3× faster** traversal (`C:\Windows`: 35.6s → 11.3s).
- **Cheaper matching.** A single pre-filter regex (a strict *superset* of every rule's trigger) gates the per-line rule loop, so lines that can't match skip the ~23 rule evaluations entirely. Measured **~12× faster** on a 5 MB config (16.5s → 1.3s), with **zero recall loss** (validated against a line matching every rule, in both language modes).
- **No wasted opens.** Cloud/offline placeholders are skipped before opening (no hydration); hashes are computed only for files that have findings.

Both speed-ups preserve detection exactly and work under Constrained Language Mode.

## Requirements

- Windows PowerShell **5.1** (the version available in Live Response). No PowerShell 7+ syntax is used.
- Works under **Constrained Language Mode** and restricted execution policy (built-in cmdlets + core .NET types only).

## Usage — Defender Live Response

Upload `Find-HardcodedSecrets.ps1` to the Live Response library, then from a session:

```text
# Zero args: scan all local fixed drives, no time cap
runscript -scriptName Find-HardcodedSecrets.ps1

# Recommended on a real host: high-confidence only, 30-minute budget
runscript -scriptName Find-HardcodedSecrets.ps1 -args "-MinConfidence High -MaxRuntimeMinutes 30"

# Scope to one drive and include placeholder values
runscript -scriptName Find-HardcodedSecrets.ps1 -args "-Drives C: -IncludePlaceholders"

# Files-only (skip the environment-variable sweep)
runscript -scriptName Find-HardcodedSecrets.ps1 -args "-SkipEnvironment"
```

> The bare, arg-less `run Find-HardcodedSecrets.ps1` scans **files and environment
> variables** — env scanning is on by default, because the Live Response `run`
> command cannot pass arguments. Use `runscript … -args` only when you need a
> non-default option (and only if your console supports it).

Wait for the `SUMMARY |` line — that marks the end of the run. If `truncated=True`, the time budget was hit and results are partial; raise `-MaxRuntimeMinutes` and re-run.

## Usage — local

```powershell
# Scan a specific folder (-Drives also accepts directory paths)
.\Find-HardcodedSecrets.ps1 -Drives "C:\path\to\scan" -MinConfidence Medium

# Built-in help
Get-Help .\Find-HardcodedSecrets.ps1 -Full

# If your local execution policy blocks it (Live Response is unaffected)
powershell -ExecutionPolicy Bypass -File .\Find-HardcodedSecrets.ps1 -Drives "C:\path\to\scan"
```

## Usage — Intune (fleet hunting)

For scanning the whole fleet, use the **`intune/Detect-*Secrets.ps1`** scripts as **Remediations detection scripts** (Devices → *Scripts and remediations*). Unlike Intune *platform* scripts — which only report success/failure and bury stdout in the per-device IME log — a Remediation surfaces the detection script's output in the portal ("Pre-remediation detection output").

| Detection script | Scans | Use as |
|---|---|---|
| **`intune/Detect-EnvVarSecrets.ps1`** | Environment variables (registry, all loaded hives) | Remediation #1 — instant |
| **`intune/Detect-UserProfileSecrets.ps1`** | `.env` / `.config` under `C:\Users` | Remediation #2 — file-based |

- **Settings (both):** run as **System** (not logged-on user), **64-bit**, signature check **off**. Intune passes no arguments, so the script defaults are the config. Upload the **whole file** (browse to it — don't paste, which can truncate to just the comment header and produce empty output / a false "clean").
- **Behavior:** each script **exits 1** when secrets are found (device flagged "issue detected") and **0** when clean. Intune Remediations surface only the **last** stdout line, so the whole report is packed onto **one line** (verdict + counts + findings inline), capped under ~2 KB:
  ```text
  STATUS=FOUND | host=PC123 ver=1.0.1 n=3 high=1 med=2 low=0 scopes=2 rev=1 :: HIGH AWS_AKID User:sean.kennedy::AWS_ACCESS_KEY_ID(20) ; MED ENV_NAMED_SECRET User:sean.kennedy::BRIVO_PASSWORD(13) ; ...
  STATUS=FOUND | host=PC123 ver=1.0.0 n=4 high=1 med=3 low=0 files=2 scanned=3 trunc=0 rev=1 :: HIGH AWS_AKID C:\Users\sean\app\.env:1 ; MED GEN_PASSWORD C:\Users\sean\app\.env:2 ; ...
  ```
  (or `STATUS=CLEAN …` / `STATUS=ERROR …`). They never print the secret value — only the location (scope+name, or path:line). The file scanner adds `trunc=1` if its time budget was hit (partial results); for full per-finding detail run the matching `Find-*Secrets.ps1` via Live Response on a flagged device.
- **Note:** Intune (and the IME) terminate scripts after ~30 minutes, so the full-disk `Find-HardcodedSecrets.ps1` is a poor fit for Intune. The env detection runs in seconds; the user-profile one is bounded (default 10-min budget). Detection logic is identical to the matching `Find-*Secrets.ps1` and is kept in sync by the drift guard.

## Parameters

| Parameter | Default | Purpose |
|---|---|---|
| `-Drives` | all fixed drives | Drive letters (`C:`) and/or directory paths to scan |
| `-MinConfidence` | `Medium` | `High` / `Medium` / `Low` (Low includes encrypted-config hits) |
| `-MaxRuntimeMinutes` | `30` | Time budget for the **file** scan; stops gracefully and flags `truncated=True` when exceeded. Keep below your Live Response session cap. `0` = unlimited (only when not under a session timeout) |
| `-MaxFileSizeMB` | `10` | Skip files larger than this |
| `-ExcludePaths` | surgical noise list | Path fragments to skip (keeps `C:\Windows` in scope so `machine.config`/`web.config` are scanned) |
| `-IncludePlaceholders` | off | Stop filtering placeholders like `${VAR}`, `changeme`, `<your-secret>` |
| `-SkipEnvironment` | off | Skip the environment-variable sweep (do a files-only scan) |
| `-AggressiveValueScan` | off | Also flag high-entropy-looking *values* regardless of name (catches odd-named secrets; noisier) |

## Environment variables (on by default)

Secrets are often stored in environment variables (e.g. `BRIVO_API_KEY`, `DB_PASSWORD`), which live in the **registry**, not the file system — so a file scan alone won't see them. Environment scanning therefore runs **by default** (pass `-SkipEnvironment` to turn it off). It reads (read-only):

- **System** — `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment`
- **Each loaded user hive** — `HKU\<SID>\Environment`, covering classic (`S-1-5-21-…`), service-account (`S-1-5-18/19/20`), and **Azure AD / Entra ID** (`S-1-12-1-…`) SIDs

Detection on each variable:

- **Structured value rules (High):** the value is matched against the provider-format rules (AWS, GitHub, …).
- **Secret-like name (Medium):** the variable *name* is matched as a substring against secret keywords (`password`, `secret`, `api_key`, `token`, …), with the value placeholder-filtered. This catches `*_API_KEY` / `*_PASSWORD` that the word-boundary file rules wouldn't.

Findings reuse the `FINDING |` format with the location set to `ENV:<scope>::<VariableName>` and `line=0`. As everywhere, **only the name + scope + length are emitted — never the value**.

> Read-only by design: offline (logged-off) user hives are **not** mounted, because `reg load` of an `NTUSER.DAT` is a registry write and file lock that would violate the read-only guarantee. Only already-loaded hives are read.

## File targeting

Matched case-insensitively, kept deliberately tight to stay fast and low-noise on a full-disk scan:

- `*.env` — `.env`, `secret.env`, `prod.env`, `database.env`, …
- `.env.*` — `.env.local`, `.env.production`, `.env.development`, …
- `*.config` — `web.config`, `app.config`, `machine.config`, `*.exe.config`, `applicationHost.config`, …

## Output

Plain text to stdout with stable, greppable line prefixes (no color/ANSI):

| Prefix | Meaning |
|---|---|
| `META \|` | Run metadata and heartbeats (host, UTC start, params, drives) |
| `FILE \|` | One per file with ≥1 finding: `FILE \| <sha256> \| <sizeBytes> \| <lastWriteUtc> \| <path>` |
| `FINDING \|` | One per finding: `FINDING \| <confidence> \| <ruleId> \| <label> \| line=<n> \| len=<n> \| <path>` |
| `ERROR \|` | Terse access-denied / IO / encoding one-liners |
| `SUMMARY \|` | Final rollup + a human-readable block; includes `truncated=<bool>` |

## Detection

A single, commented `$Rules` collection drives detection. Each rule has an `Id`, `Label`, regex `Pattern`, `Confidence`, and `Type`:

- **Structured (High):** provider-specific formats — AWS access key IDs, Google API/OAuth, Slack (tokens + webhook URLs), GitHub (classic + fine-grained PATs), GitLab, Stripe, SendGrid, Twilio (API key SID + Account SID), OpenAI/Anthropic, npm, Azure AD client secrets, Mailgun, PEM/OpenSSH/PGP private-key blocks, JWTs, Azure storage `AccountKey`, and **URLs with embedded credentials** (`scheme://user:pass@host`). The whole match is the token, so placeholder filtering is not applied.
- **Contextual (Medium):** keyword = value assignments — `password`/`passwd`/`pwd`, `api_key`/`secret`/`token`/`access_key`/`auth_token`, and connection strings with embedded credentials. The captured value is run through a placeholder filter before recording.

**False-positive reduction:** contextual values matching placeholders/references (`${VAR}`, `%VAR%`, `{{VAR}}`, `<your-secret>`, `changeme`, `example`, `xxxx`, etc.) are dropped unless `-IncludePlaceholders` is set. For `.config`, findings near a `configProtectionProvider` marker are downgraded to **Low** and relabeled "encrypted config section (value protected)".

Add new rules by appending an entry to `$Rules` — nothing else needs to change.

### Coverage vs. false positives

Detection is **keyword-anchored** (known secret-ish names) **or** **format-anchored** (known provider tokens / credential-bearing URLs) — the standard low-false-positive model. It will *not*, by default, flag a secret hidden in an oddly-named variable whose value isn't a recognized format (e.g. `BRIVO_KEY=<random>`). For that, pass **`-AggressiveValueScan`**, which adds a heuristic that flags environment values that "look like" a random secret (length + character diversity + mixed character classes), skipping paths, GUIDs, and short/low-diversity values. It is deliberately noisier and reported at Medium as rule `ENV_HIGH_ENTROPY`. As always, the value itself is never emitted.

## License

[MIT](LICENSE)

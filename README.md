# Find-HardcodedSecrets

A read-only **incident-response** scanner for **Microsoft Defender for Endpoint – Live Response**. It sweeps a live Windows host for `.env` and `.config` files that contain hardcoded secrets and reports **only the location** of each finding — it **never prints the secret value**.

Built for the constrained Live Response shell: Windows PowerShell 5.1, tolerant of Constrained Language Mode and restricted execution policy, fully non-interactive, and forensically sound.

## Safety properties

- **Read-only.** Never edits, moves, deletes, renames, or alters any file, attribute, or registry value.
- **Writes nothing to the endpoint.** All output goes to stdout (Live Response captures it). No results file, log, transcript, or temp file.
- **Never emits secret values.** Findings report rule label, confidence, line number, file path, file SHA-256, and the matched-substring *length* (an integer) — never the secret text.
- **No network / off-box activity.** No web requests, DNS, telemetry, module installs, or package downloads.
- **No persistence.** No registry writes, scheduled tasks, or elevation prompts.
- Opens files read-only with shared read/write access, so it does not lock files or block other processes.

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

# Also scan environment variables (registry-backed), in addition to files
runscript -scriptName Find-HardcodedSecrets.ps1 -args "-IncludeEnvironment -MinConfidence Medium"
```

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

## Parameters

| Parameter | Default | Purpose |
|---|---|---|
| `-Drives` | all fixed drives | Drive letters (`C:`) and/or directory paths to scan |
| `-MinConfidence` | `Medium` | `High` / `Medium` / `Low` (Low includes encrypted-config hits) |
| `-MaxRuntimeMinutes` | `0` (unlimited) | Stops gracefully and flags `truncated=True` when exceeded (30–45 is sane for large hosts) |
| `-MaxFileSizeMB` | `10` | Skip files larger than this |
| `-ExcludePaths` | surgical noise list | Path fragments to skip (keeps `C:\Windows` in scope so `machine.config`/`web.config` are scanned) |
| `-IncludePlaceholders` | off | Stop filtering placeholders like `${VAR}`, `changeme`, `<your-secret>` |
| `-IncludeEnvironment` | off | Also scan environment variables (registry-backed) for secrets |

## Environment variables (`-IncludeEnvironment`)

Secrets are often stored in environment variables (e.g. `BRIVO_API_KEY`, `DB_PASSWORD`), which live in the **registry**, not the file system — so a file scan won't see them. With `-IncludeEnvironment` the tool additionally reads (read-only):

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

- **Structured (High):** provider-specific formats — AWS access key IDs, Google API/OAuth, Slack, GitHub, GitLab, Stripe, SendGrid, Twilio, PEM/OpenSSH/PGP private-key blocks, JWTs, Azure storage `AccountKey`. The whole match is the token, so placeholder filtering is not applied.
- **Contextual (Medium):** keyword = value assignments — `password`/`passwd`/`pwd`, `api_key`/`secret`/`token`/`access_key`/`auth_token`, and connection strings with embedded credentials. The captured value is run through a placeholder filter before recording.

**False-positive reduction:** contextual values matching placeholders/references (`${VAR}`, `%VAR%`, `{{VAR}}`, `<your-secret>`, `changeme`, `example`, `xxxx`, etc.) are dropped unless `-IncludePlaceholders` is set. For `.config`, findings near a `configProtectionProvider` marker are downgraded to **Low** and relabeled "encrypted config section (value protected)".

Add new rules by appending an entry to `$Rules` — nothing else needs to change.

## License

[MIT](LICENSE)

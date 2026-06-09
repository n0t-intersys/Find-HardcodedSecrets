<#
.SYNOPSIS
    Read-only, full-disk incident-response scanner that locates .env and .config
    files containing hardcoded secrets and reports ONLY their location -- never
    the secret value itself.

.DESCRIPTION
    Find-HardcodedSecrets.ps1 is designed to be uploaded to the Microsoft Defender
    for Endpoint Live Response library and executed on a live, suspect Windows host
    during an active investigation.

    It performs a forensically-sound, READ-ONLY sweep of all local fixed drives,
    opening only a tight candidate set of files (.env / .env.* / *.config), and
    matches their contents against a curated, low-false-positive set of secret
    detection rules. For every match it emits the rule label, confidence, line
    number and file path (plus a SHA-256 of the file for chain-of-custody). The
    matched secret text is NEVER printed, logged, masked or stored; at most the
    matched substring's *length* (an integer) is reported.

    The script is built for the constrained Live Response shell:
      * Targets Windows PowerShell 5.1 only (no PowerShell 7+ syntax).
      * Tolerates Constrained Language Mode and restricted execution policy
        (built-in cmdlets + core .NET types only; no Add-Type / reflection / COM).
      * Fully non-interactive; runs to completion with zero arguments.
      * Read-only: writes NOTHING to the endpoint (no results file, log, transcript
        or temp file). All output goes to stdout, which Live Response captures.
      * No network, registry, scheduled-task or persistence activity of any kind.

    Directory traversal is performed with per-directory error isolation (each
    directory read is wrapped in its own try/catch) rather than a single
    Get-ChildItem -Recurse, so a single access-denied directory cannot abort the
    whole enumeration. Reparse points (junctions / symlinks) are detected and
    skipped to avoid loops and accidental traversal into network-backed paths.

.PARAMETER Drives
    Roots to scan. Accepts drive letters ('C:' or 'C') and/or explicit directory
    paths (useful for scoping a scan to a mounted evidence path). Default: all
    local FIXED drives (Win32_LogicalDisk DriveType = 3). Removable, network and
    CD-ROM drives are never auto-included.

.PARAMETER MaxFileSizeMB
    Skip any candidate file larger than this many megabytes. Real config/env files
    are small; this is a guardrail for a full-disk scan. Default: 10.

.PARAMETER ExcludePaths
    Case-insensitive path fragments to exclude from traversal. Default is a
    surgical, high-noise list (WinSxS, servicing, $Recycle.Bin, System Volume
    Information, Defender directories). NOTE: C:\Windows is intentionally NOT
    excluded, because machine.config, applicationHost.config and framework
    web.config files live beneath it.

.PARAMETER MinConfidence
    Minimum confidence to report: High, Medium or Low. Default: Medium (shows
    Medium and High; hides Low / encrypted-config findings).

.PARAMETER MaxRuntimeMinutes
    Optional overall time budget. 0 = unlimited (default). When exceeded the scan
    stops gracefully, reports partial results, and flags the run as TRUNCATED in
    the summary. 30-45 is a reasonable cap for large hosts under a session timeout.

.PARAMETER IncludePlaceholders
    Switch. When set, disables placeholder/reference filtering (e.g. ${VAR},
    <your-secret>, changeme). Off by default so obvious non-secrets are ignored.

.PARAMETER SkipEnvironment
    Switch. By DEFAULT the scan ALSO covers environment variables (a common
    secret stash) in addition to files. Environment variables live in the
    registry, not the file system, so this reads (read-only):
      * System scope          : HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment
      * Each loaded user hive : HKU\<SID>\Environment (incl. Azure AD / Entra ID
                                S-1-12-1-... SIDs)
    It reports the variable name + scope + value length only, NEVER the value.
    Pass -SkipEnvironment for a files-only scan. Offline (logged-off) user hives
    are never mounted (that would be a registry write + file lock), so only
    currently-loaded hives are read -- run while the target user is logged on.

    NOTE: env scanning is ON by default precisely because the Live Response
    'run' command takes NO arguments; the zero-arg scan must be comprehensive.

.EXAMPLE
    Defender Live Response, zero arguments -- scans files AND environment
    variables by default. Works with the arg-less 'run' command:
        run Find-HardcodedSecrets.ps1

.EXAMPLE
    Files-only scan (skip the environment-variable sweep), where args are usable:
        runscript -scriptName Find-HardcodedSecrets.ps1 -args "-SkipEnvironment"

.EXAMPLE
    Defender Live Response (high-confidence only, 30-minute budget):
        runscript -scriptName Find-HardcodedSecrets.ps1 -args "-MinConfidence High -MaxRuntimeMinutes 30"

.EXAMPLE
    Scope the scan to a single drive and include placeholder values:
        runscript -scriptName Find-HardcodedSecrets.ps1 -args "-Drives C: -IncludePlaceholders"

.NOTES
    Safety notes:
      * READ-ONLY. The script never edits, moves, deletes, renames, quarantines
        or alters any file, attribute or registry value.
      * Writes NO files to the endpoint -- output is stdout only.
      * NEVER prints, logs or masks a secret value. Only rule labels, confidences,
        line numbers, file paths, file hashes and (optionally) match lengths.
      * No network, DNS, telemetry, module install or off-box activity.
      * Files are opened read-only with shared read/write access so the script
        does not lock files or block other processes.

    Version : 1.2.0
    Author  : DFIR
#>

# NOTE: #requires must follow the comment-based help block, not precede it --
# Get-Help only recognizes script help when the help block is the first content
# in the file. #requires is enforced regardless of its line position.
#requires -Version 5.1

[CmdletBinding()]
param(
    [string[]]$Drives,

    [int]$MaxFileSizeMB = 10,

    [string[]]$ExcludePaths = @(
        '\Windows\WinSxS',
        '\Windows\servicing',
        '\$Recycle.Bin',
        '\System Volume Information',
        '\ProgramData\Microsoft\Windows Defender',
        '\Program Files\Windows Defender',
        '\Program Files (x86)\Windows Defender'
    ),

    [ValidateSet('High', 'Medium', 'Low')]
    [string]$MinConfidence = 'Medium',

    [int]$MaxRuntimeMinutes = 0,

    [switch]$IncludePlaceholders,

    [switch]$SkipEnvironment
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$ScriptVersion = '1.2.0'

# ---------------------------------------------------------------------------
# Detection rules.
#
# Each rule is a hashtable (NOT [pscustomobject]: Constrained Language Mode
# forbids constructing custom objects -- "only core types are supported" -- but
# hashtables are always allowed) with:
#   Id            - short stable identifier (greppable).
#   Label         - human-readable description.
#   Pattern       - the regex (string). Matching uses the -match / -cmatch
#                   operators rather than [regex] objects so the script works
#                   even under Constrained Language Mode, where invoking methods
#                   on arbitrary .NET types may be blocked.
#   CaseSensitive - $true  -> matched with -cmatch (preserves provider casing
#                            so e.g. an AWS [0-9A-Z] class is not silently
#                            widened to match lowercase under case-insensitive
#                            matching, which would raise false positives).
#                   $false -> matched with -match (case-insensitive).
#   Confidence    - High / Medium / Low.
#   Type          - 'Structured'  : provider-specific format; the whole match IS
#                                    the token, so placeholder filtering is NOT
#                                    applied (these patterns are self-validating).
#                   'Contextual'  : keyword = value assignment. The value is
#                                    captured as a named group (?<val>...) and is
#                                    run through the placeholder filter before the
#                                    finding is recorded. The value is used only
#                                    for filtering / length and is never emitted.
#
# Add new rules by appending objects here -- nothing else needs to change.
# ---------------------------------------------------------------------------
$script:Rules = @(
    # -- High confidence: structured, provider-specific formats. Low FP because
    #    the fixed prefixes + exact lengths almost never occur by chance. --

    @{ Id = 'AWS_AKID';      Label = 'AWS Access Key ID';                 Pattern = '\b(AKIA|ASIA)[0-9A-Z]{16}\b';                                  CaseSensitive = $true;  Confidence = 'High'; Type = 'Structured' }
    @{ Id = 'GCP_APIKEY';    Label = 'Google API key';                    Pattern = '\bAIza[0-9A-Za-z\-_]{35}\b';                                   CaseSensitive = $true;  Confidence = 'High'; Type = 'Structured' }
    @{ Id = 'GCP_OAUTH';     Label = 'Google OAuth client ID';            Pattern = '[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com';        CaseSensitive = $true;  Confidence = 'High'; Type = 'Structured' }
    @{ Id = 'SLACK_TOKEN';   Label = 'Slack token';                       Pattern = '\bxox[baprs]-[0-9A-Za-z-]{10,}\b';                             CaseSensitive = $true;  Confidence = 'High'; Type = 'Structured' }
    @{ Id = 'GITHUB_TOKEN';  Label = 'GitHub token';                      Pattern = '\bgh[pousr]_[0-9A-Za-z]{36,}\b';                               CaseSensitive = $true;  Confidence = 'High'; Type = 'Structured' }
    @{ Id = 'GITLAB_PAT';    Label = 'GitLab personal access token';      Pattern = '\bglpat-[0-9A-Za-z\-_]{20,}\b';                                CaseSensitive = $true;  Confidence = 'High'; Type = 'Structured' }
    @{ Id = 'STRIPE_LIVE';   Label = 'Stripe live secret key';            Pattern = '\b(sk|rk)_live_[0-9A-Za-z]{20,}\b';                            CaseSensitive = $true;  Confidence = 'High'; Type = 'Structured' }
    @{ Id = 'SENDGRID_KEY';  Label = 'SendGrid API key';                  Pattern = '\bSG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}\b';               CaseSensitive = $true;  Confidence = 'High'; Type = 'Structured' }
    @{ Id = 'TWILIO_SK';     Label = 'Twilio API key SID';                Pattern = '\bSK[0-9a-fA-F]{32}\b';                                        CaseSensitive = $true;  Confidence = 'High'; Type = 'Structured' }
    @{ Id = 'PRIVATE_KEY';   Label = 'Private key block (PEM/OpenSSH/PGP)'; Pattern = '-----BEGIN (RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----'; CaseSensitive = $true; Confidence = 'High'; Type = 'Structured' }
    @{ Id = 'JWT';           Label = 'JSON Web Token';                    Pattern = '\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b'; CaseSensitive = $true; Confidence = 'High'; Type = 'Structured' }
    @{ Id = 'AZURE_STORAGE'; Label = 'Azure storage AccountKey';          Pattern = 'AccountKey=[A-Za-z0-9+/=]{40,}';                               CaseSensitive = $true;  Confidence = 'High'; Type = 'Structured' }

    # -- Medium confidence: contextual keyword = value assignments. Higher FP
    #    risk, so the captured value is placeholder-filtered before recording.
    #    The value is captured but never printed. --

    @{ Id = 'GEN_PASSWORD';  Label = 'Password assignment';               Pattern = '\b(password|passwd|pwd)\s*[:=]\s*["'']?(?<val>[^"''\s;]{4,})';                       CaseSensitive = $false; Confidence = 'Medium'; Type = 'Contextual' }
    @{ Id = 'GEN_SECRET';    Label = 'Secret/token/key assignment';       Pattern = '\b(api[_-]?key|secret|client[_-]?secret|access[_-]?key|auth[_-]?token|token)\s*[:=]\s*["'']?(?<val>[^"''\s;]{8,})'; CaseSensitive = $false; Confidence = 'Medium'; Type = 'Contextual' }
    @{ Id = 'CONN_STRING';   Label = 'Connection string with credentials'; Pattern = '(connectionstring\s*=|<add[^>]+connectionstring\s*=)[^>]*\b(password|pwd)\s*=\s*(?<val>[^;"''>\s]+)'; CaseSensitive = $false; Confidence = 'Medium'; Type = 'Contextual' }
)

# ---------------------------------------------------------------------------
# Placeholder / reference patterns. A contextual value matching ANY of these is
# treated as a non-secret and dropped (unless -IncludePlaceholders). These are
# matched case-insensitively against the captured value only.
# ---------------------------------------------------------------------------
$script:PlaceholderPatterns = @(
    'your[-_ ]?',        # your-secret, your_password ...
    'changeme',
    'example',
    'x{4,}',             # xxxx / XXXXXXXX
    '\*{3,}',            # ***
    '<[^>]+>',           # <your-secret>
    '\$\{[^}]+\}',       # ${VAR}
    '%[^%]+%',           # %VAR%
    '\{\{[^}]+\}\}',     # {{VAR}}
    '\$\([^)]+\)',       # $(VAR)
    '#\{[^}]+\}'         # #{VAR}
)

# ---------------------------------------------------------------------------
# Environment-variable NAME keywords (used by the env scan, on by default).
#
# Env var names embed the keyword after a prefix and an underscore
# (e.g. BRIVO_API_KEY, DB_PASSWORD), so the file rules' word-boundary anchors
# (\bapi_key) would NOT match. Here we match the keyword as a SUBSTRING of the
# name, case-insensitive. Kept tight so identifiers like *_CLIENT_ID and
# *_USERNAME are not flagged. The variable VALUE is still placeholder-filtered
# and never emitted.
# ---------------------------------------------------------------------------
$script:EnvNameKeywordPattern = '(?i)(password|passwd|pwd|secret|api[_-]?key|apikey|access[_-]?key|secret[_-]?key|client[_-]?secret|auth[_-]?token|token|account[_-]?key|connection[_-]?string|connectionstring|private[_-]?key|credential)'

# Confidence ranking for -MinConfidence filtering.
$script:ConfRank = @{ 'High' = 3; 'Medium' = 2; 'Low' = 1 }

# Run-wide counters (hashtable = reference type, mutated in place by functions).
$script:Stats = @{
    DirsTraversed     = 0
    DirErrors         = 0
    ReparseSkipped    = 0
    CandidatesMatched = 0
    FilesScanned      = 0
    SkippedSize       = 0
    SkippedBinary     = 0
    FileErrors        = 0
    HashErrors        = 0
    FilesWithFindings = 0
    TotalFindings     = 0
    ByConfidence      = @{}
    ByRule            = @{}
    Truncated         = $false
    EnvScopesScanned     = 0
    EnvVarsScanned       = 0
    EnvVarsWithFindings  = 0
}

# Populated in main; read by the scanning functions.
$script:TimeUp              = $false
$script:StartLocal          = $null
$script:UseDotNetIO         = $false
$script:MaxFileSizeBytes    = [long]$MaxFileSizeMB * 1MB
$script:MaxRuntimeMinutes   = $MaxRuntimeMinutes
$script:ExcludePaths        = $ExcludePaths
$script:IncludePlaceholders = [bool]$IncludePlaceholders
$script:MinRank             = $script:ConfRank[$MinConfidence]

# ===========================================================================
# Helper functions
# ===========================================================================

function Add-Count {
    # Increment a count in a hashtable, initialising the key if needed.
    param($Hash, $Key)
    if ($Hash.ContainsKey($Key)) { $Hash[$Key] = $Hash[$Key] + 1 }
    else { $Hash[$Key] = 1 }
}

function Get-FixedDrive {
    # Return local FIXED drives as 'C:' style strings (DriveType 3 only).
    $result = @()
    try {
        $disks = Get-CimInstance -ClassName Win32_LogicalDisk -Filter 'DriveType=3' -ErrorAction Stop
        foreach ($d in $disks) { if ($d.DeviceID) { $result += $d.DeviceID } }
    }
    catch {
        # Fallback: enumerate filesystem PSDrives that are backed by a fixed root.
        try {
            $psd = Get-PSDrive -PSProvider FileSystem -ErrorAction Stop
            foreach ($p in $psd) {
                if ($p.Name -match '^[A-Za-z]$') { $result += ($p.Name + ':') }
            }
        }
        catch { }
    }
    return $result
}

function Test-ExcludeDir {
    # $true if the directory path contains any configured exclusion fragment.
    param([string]$Path)
    $lower = $Path.ToLowerInvariant()
    foreach ($x in $script:ExcludePaths) {
        if ($x -and $lower.Contains($x.ToLowerInvariant())) { return $true }
    }
    return $false
}

function Test-IsCandidate {
    # $true if the file name is a scan target:
    #   *.env       -> '.env' and the common '<name>.env' form (secret.env,
    #                  prod.env, database.env, ...). Matching only the literal
    #                  '.env' would miss these real-world env files.
    #   .env.*      -> '.env.local', '.env.production', '.env.development', ...
    #                  (these end in '.local' etc., so '*.env' alone misses them).
    #   *.config    -> web.config, app.config, machine.config, *.exe.config,
    #                  applicationHost.config, ...
    param([string]$Name)
    $n = $Name.ToLowerInvariant()
    if ($n.EndsWith('.env'))    { return $true }
    if ($n.StartsWith('.env.')) { return $true }
    if ($n.EndsWith('.config')) { return $true }
    return $false
}

function Test-TimeUp {
    # $true if a runtime budget is set and has been exceeded.
    if ($script:MaxRuntimeMinutes -le 0) { return $false }
    $elapsed = ((Get-Date) - $script:StartLocal).TotalMinutes
    return ($elapsed -ge $script:MaxRuntimeMinutes)
}

function Test-IsPlaceholder {
    # $true if a captured value is an obvious placeholder / reference / empty.
    param([string]$Value)
    if ([string]::IsNullOrEmpty($Value)) { return $true }
    foreach ($p in $script:PlaceholderPatterns) {
        if ($Value -match $p) { return $true }
    }
    return $false
}

function Test-FileIsBinary {
    # Read the first chunk of bytes and treat the file as binary if it contains
    # a NUL byte. Uses Get-Content -Encoding Byte (works in both language modes).
    param([string]$Path)
    $bytes = Get-Content -LiteralPath $Path -Encoding Byte -TotalCount 8192 -ErrorAction Stop
    if ($null -eq $bytes) { return $false }
    foreach ($b in $bytes) { if ($b -eq 0) { return $true } }
    return $false
}

function Read-FileLine {
    # Return the file's lines as a string array, read-only.
    #   * Full Language Mode: use a FileStream opened with FileShare.ReadWrite so
    #     locked / in-use files still read and we never block other writers, plus
    #     a StreamReader that auto-detects the BOM and defaults to UTF-8.
    #   * Constrained Language Mode: fall back to Get-Content (cmdlet only).
    param([string]$Path)
    if ($script:UseDotNetIO) {
        $fs = $null
        $sr = $null
        try {
            $fs = [System.IO.File]::Open($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
            $sr = New-Object System.IO.StreamReader -ArgumentList @($fs, $true)
            $text = $sr.ReadToEnd()
        }
        finally {
            if ($sr) { $sr.Dispose() }
            elseif ($fs) { $fs.Dispose() }
        }
        # Split on CRLF / CR / LF without a regex object.
        return [string[]]($text -split "`r`n|`n|`r")
    }
    else {
        return @(Get-Content -LiteralPath $Path -ErrorAction Stop)
    }
}

# ===========================================================================
# Output writers (stdout only; stable, greppable prefixes; no color/ANSI).
# ===========================================================================

function Write-Meta      { param([string]$Message) Write-Output "META | $Message" }
function Write-ErrLine   { param([string]$Message) Write-Output "ERROR | $Message" }
function Write-FileLine  { param([string]$Sha, [long]$Size, [string]$LastWriteUtc, [string]$Path) Write-Output "FILE | $Sha | $Size | $LastWriteUtc | $Path" }
function Write-FindingLine {
    param([string]$Confidence, [string]$RuleId, [string]$Label, [int]$Line, [int]$Length, [string]$Path)
    Write-Output "FINDING | $Confidence | $RuleId | $Label | line=$Line | len=$Length | $Path"
}

# ===========================================================================
# Per-file scan
# ===========================================================================

function Invoke-FileScan {
    param($Item)   # System.IO.FileInfo from Get-ChildItem

    $script:Stats.CandidatesMatched++
    $path = $Item.FullName

    # Size guardrail.
    if ($Item.Length -gt $script:MaxFileSizeBytes) {
        $script:Stats.SkippedSize++
        return
    }

    # Binary / garbage guard.
    try {
        if (Test-FileIsBinary -Path $path) {
            $script:Stats.SkippedBinary++
            return
        }
    }
    catch {
        $script:Stats.FileErrors++
        Write-ErrLine ("read | {0}" -f $path)
        return
    }

    # Read content.
    $lines = $null
    try {
        $lines = @(Read-FileLine -Path $path)
    }
    catch {
        $script:Stats.FileErrors++
        Write-ErrLine ("read | {0}" -f $path)
        return
    }
    $script:Stats.FilesScanned++

    $name     = $Item.Name.ToLowerInvariant()
    $isConfig = $name.EndsWith('.config')

    # Pre-compute "encrypted config" line windows: if a .config contains the
    # configProtectionProvider marker, any finding within +/-5 lines of it is
    # downgraded to Low and relabelled (value is protected, not plaintext-leaked).
    $encWindow = @{}
    if ($isConfig) {
        for ($i = 0; $i -lt $lines.Count; $i++) {
            if ($lines[$i] -match 'configProtectionProvider') {
                # Manual clamp (no [Math]:: -- System.Math method calls are blocked
                # under Constrained Language Mode).
                $lo = $i - 5
                if ($lo -lt 0) { $lo = 0 }
                $hi = $i + 5
                $maxIdx = $lines.Count - 1
                if ($hi -gt $maxIdx) { $hi = $maxIdx }
                for ($j = $lo; $j -le $hi; $j++) { $encWindow[$j] = $true }
            }
        }
    }

    $fileFindings = @()
    $seen = @{}   # de-dupe one finding per (ruleId,line)

    for ($i = 0; $i -lt $lines.Count; $i++) {
        $line = $lines[$i]
        if ([string]::IsNullOrEmpty($line)) { continue }

        foreach ($rule in $script:Rules) {
            if ($rule.CaseSensitive) { $isMatch = $line -cmatch $rule.Pattern }
            else                     { $isMatch = $line -match  $rule.Pattern }
            if (-not $isMatch) { continue }

            $dupKey = "$($rule.Id)|$i"
            if ($seen.ContainsKey($dupKey)) { continue }

            # Determine the value (contextual) and the reported length.
            if ($rule.Type -eq 'Contextual') {
                $val = ''
                if ($matches.Contains('val')) { $val = [string]$matches['val'] }

                # Placeholder / reference filtering on the value only.
                if (-not $script:IncludePlaceholders) {
                    if (Test-IsPlaceholder -Value $val) { continue }
                }
                $mlen = $val.Length
            }
            else {
                $mlen = ([string]$matches[0]).Length
            }

            # Confidence (with encrypted-config downgrade).
            $conf  = $rule.Confidence
            $label = $rule.Label
            if ($isConfig -and $encWindow.ContainsKey($i)) {
                $conf  = 'Low'
                $label = 'encrypted config section (value protected)'
            }

            # Apply -MinConfidence filter.
            if ($script:ConfRank[$conf] -lt $script:MinRank) { continue }

            $seen[$dupKey] = $true
            # Hashtable (not [pscustomobject]) for Constrained Language Mode safety.
            $fileFindings += @{
                Line       = ($i + 1)
                RuleId     = $rule.Id
                Label      = $label
                Confidence = $conf
                Length     = $mlen
            }
        }
    }

    if ($fileFindings.Count -eq 0) { return }

    # File had findings -> emit forensic FILE line + FINDING lines.
    # Get-FileHash is a module FUNCTION (not a compiled cmdlet) that creates a
    # crypto object internally. Under policy-enforced Constrained Language Mode
    # (WDAC/AppLocker), trusted system modules run in Full Language so this works
    # normally. In the rare event hashing is unavailable (locked file, or a
    # session forced fully into CLM), we degrade gracefully to 'UNAVAILABLE' and
    # count it -- we never fail the scan over a hash.
    $sha = 'UNAVAILABLE'
    try {
        $h = Get-FileHash -LiteralPath $path -Algorithm SHA256 -ErrorAction Stop
        $sha = $h.Hash
    }
    catch {
        $script:Stats.HashErrors++
    }

    $lastWriteUtc = $Item.LastWriteTimeUtc.ToString('yyyy-MM-ddTHH:mm:ssZ')
    Write-FileLine -Sha $sha -Size $Item.Length -LastWriteUtc $lastWriteUtc -Path $path

    $script:Stats.FilesWithFindings++
    # $fileFindings is already in ascending (line, rule) order from the scan
    # loops, so no Sort-Object is needed -- which also avoids sorting hashtables
    # by a pseudo-property (unreliable) and keeps the code Constrained-Language-safe.
    foreach ($f in $fileFindings) {
        Write-FindingLine -Confidence $f.Confidence -RuleId $f.RuleId -Label $f.Label -Line $f.Line -Length $f.Length -Path $path
        $script:Stats.TotalFindings++
        Add-Count $script:Stats.ByConfidence $f.Confidence
        Add-Count $script:Stats.ByRule $f.Label
    }
}

# ===========================================================================
# Directory traversal (recursive, per-directory error isolation).
#
# A recursive function gives each directory its own try/catch, so one
# access-denied directory cannot abort the whole enumeration (the failure mode
# of a single Get-ChildItem -Recurse). Reparse points are skipped to prevent
# loops and traversal into network-backed paths. Depth is bounded by the
# filesystem path-length limit, so unbounded recursion is not a concern.
# ===========================================================================

function Invoke-DirScan {
    param([string]$Dir)

    if ($script:TimeUp) { return }
    if (Test-TimeUp)    { $script:TimeUp = $true; return }

    if (Test-ExcludeDir -Path $Dir) { return }

    $script:Stats.DirsTraversed++

    # Sparse heartbeat so the console is not flooded.
    if (($script:Stats.DirsTraversed % 2000) -eq 0) {
        # [int] cast instead of [Math]::Round (Constrained Language Mode safe).
        $el = [int](((Get-Date) - $script:StartLocal).TotalSeconds)
        Write-Meta ("heartbeat | dirs={0} candidates={1} findings={2} elapsedSec={3}" -f `
            $script:Stats.DirsTraversed, $script:Stats.CandidatesMatched, $script:Stats.TotalFindings, $el)
    }

    $children = $null
    try {
        $children = @(Get-ChildItem -LiteralPath $Dir -Force -ErrorAction Stop)
    }
    catch {
        # Access denied, long path, IO error, etc. Isolate and keep going.
        $script:Stats.DirErrors++
        return
    }

    # Process candidate files first.
    foreach ($c in $children) {
        if ($script:TimeUp) { return }
        if ($c.PSIsContainer) { continue }
        if (Test-IsCandidate -Name $c.Name) {
            if (Test-TimeUp) { $script:TimeUp = $true; return }
            Invoke-FileScan -Item $c
        }
    }

    # Then recurse into subdirectories (skipping reparse points).
    foreach ($c in $children) {
        if ($script:TimeUp) { return }
        if (-not $c.PSIsContainer) { continue }
        if ($c.Attributes -match 'ReparsePoint') {
            $script:Stats.ReparseSkipped++
            continue
        }
        Invoke-DirScan -Dir $c.FullName
    }
}

# ===========================================================================
# Environment-variable scan (registry-backed; on by default, -SkipEnvironment off)
#
# Read-only throughout: uses the registry PROVIDER cmdlets (Get-ItemProperty /
# Get-ChildItem / Test-Path) and PSObject property enumeration rather than
# RegistryKey methods, so it works under Constrained Language Mode (where method
# calls on non-core .NET types such as RegistryKey are blocked). Values are used
# only for matching / length and are NEVER emitted.
# ===========================================================================

function Resolve-UserScopeName {
    # Map a user SID to a friendly name via the ProfileList (read-only), with
    # well-known service-account fallbacks. Returns the SID if unresolved.
    param([string]$Sid)
    try {
        $pp = Get-ItemProperty -LiteralPath ('HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\' + $Sid) -Name 'ProfileImagePath' -ErrorAction Stop
        $path = [string]$pp.ProfileImagePath
        if (-not [string]::IsNullOrEmpty($path)) { return (Split-Path -Leaf $path) }
    }
    catch { }
    switch ($Sid) {
        'S-1-5-18' { return 'SYSTEM' }
        'S-1-5-19' { return 'LocalService' }
        'S-1-5-20' { return 'NetworkService' }
    }
    return $Sid
}

function Get-EnvScope {
    # Return the environment-variable scopes to read: System + every loaded user
    # hive (HKU\<SID>\Environment). Each item: @{ Friendly; RegPath; Display }.
    $scopes = @()
    $scopes += @{
        Friendly = 'System'
        RegPath  = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment'
        Display  = 'HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment'
    }

    # Enumerate loaded user hives. SilentlyContinue + per-hive try/catch is
    # essential: HKEY_USERS contains protected hives (e.g. S-1-5-18) that raise
    # "Requested registry access is not allowed" when not elevated; under the
    # script's Stop preference that would otherwise abort the whole discovery.
    $hives = @()
    try { $hives = @(Get-ChildItem -LiteralPath 'Registry::HKEY_USERS' -ErrorAction SilentlyContinue) }
    catch { $hives = @() }

    foreach ($k in $hives) {
        try {
            $sid = $k.PSChildName
            if ($sid -like '*_Classes') { continue }   # COM/class hives, not user env
            # Any user-hive SID: classic local/domain (S-1-5-21-...), built-in
            # service accounts (S-1-5-18/19/20), AND Azure AD / Entra ID
            # (S-1-12-1-...). Skips '.DEFAULT'. The Test-Path below drops hives
            # with no Environment subkey (or that we cannot open).
            if ($sid -notlike 'S-1-*') { continue }
            $envPath = 'Registry::HKEY_USERS\' + $sid + '\Environment'
            if (-not (Test-Path -LiteralPath $envPath -ErrorAction SilentlyContinue)) { continue }
            $scopes += @{
                Friendly = 'User:' + (Resolve-UserScopeName -Sid $sid)
                RegPath  = $envPath
                Display  = 'HKU\' + $sid + '\Environment'
            }
        }
        catch {
            # Inaccessible / protected hive -- skip and keep going.
            $script:Stats.DirErrors++
            continue
        }
    }
    return $scopes
}

function Invoke-EnvScan {
    # Scan environment variables across all scopes. Emits FINDING lines using the
    # same format as the file scan, with the location being the variable name and
    # scope (never the value).
    $scopes = Get-EnvScope
    foreach ($s in $scopes) {
        if ($script:TimeUp) { return }
        if (Test-TimeUp) { $script:TimeUp = $true; return }

        $script:Stats.EnvScopesScanned++
        Write-Meta ("env-scope | {0} | {1}" -f $s.Friendly, $s.Display)

        $ip = $null
        try { $ip = Get-ItemProperty -LiteralPath $s.RegPath -ErrorAction Stop }
        catch {
            $script:Stats.DirErrors++
            Write-ErrLine ("env-scope-read | {0}" -f $s.Display)
            continue
        }

        foreach ($prop in $ip.PSObject.Properties) {
            $vname = $prop.Name
            if ($vname -like 'PS*') { continue }   # provider noise: PSPath, PSParentPath, ...
            $script:Stats.EnvVarsScanned++

            $vval = ''
            if ($null -ne $prop.Value) { $vval = [string]$prop.Value }
            if ([string]::IsNullOrEmpty($vval)) { continue }

            $varFindings = @()
            $seen = @{}

            # Pass A: structured provider-format rules against the VALUE -> High.
            foreach ($rule in $script:Rules) {
                if ($rule.Type -ne 'Structured') { continue }
                if ($rule.CaseSensitive) { $isMatch = $vval -cmatch $rule.Pattern }
                else                     { $isMatch = $vval -match  $rule.Pattern }
                if (-not $isMatch) { continue }
                if ($seen.ContainsKey($rule.Id)) { continue }
                if ($script:ConfRank[$rule.Confidence] -lt $script:MinRank) { continue }
                $seen[$rule.Id] = $true
                $varFindings += @{ RuleId = $rule.Id; Label = $rule.Label; Confidence = $rule.Confidence; Length = ([string]$matches[0]).Length }
            }

            # Pass B: secret-like NAME + non-placeholder value -> Medium.
            if ($vname -match $script:EnvNameKeywordPattern) {
                $isPlaceholder = $false
                if (-not $script:IncludePlaceholders) { $isPlaceholder = Test-IsPlaceholder -Value $vval }
                if ((-not $isPlaceholder) -and ($vval.Length -ge 4) -and ($script:ConfRank['Medium'] -ge $script:MinRank)) {
                    if (-not $seen.ContainsKey('ENV_NAMED_SECRET')) {
                        $seen['ENV_NAMED_SECRET'] = $true
                        $varFindings += @{ RuleId = 'ENV_NAMED_SECRET'; Label = 'Secret-like environment variable'; Confidence = 'Medium'; Length = $vval.Length }
                    }
                }
            }

            if ($varFindings.Count -eq 0) { continue }

            $script:Stats.EnvVarsWithFindings++
            $loc = 'ENV:' + $s.Friendly + '::' + $vname
            foreach ($f in $varFindings) {
                # Line=0: env vars have no line number. Location carries scope+name.
                Write-FindingLine -Confidence $f.Confidence -RuleId $f.RuleId -Label $f.Label -Line 0 -Length $f.Length -Path $loc
                $script:Stats.TotalFindings++
                Add-Count $script:Stats.ByConfidence $f.Confidence
                Add-Count $script:Stats.ByRule $f.Label
            }
        }
    }
}

# ===========================================================================
# Summary
# ===========================================================================

function Write-Summary {
    param([double]$ElapsedSeconds)

    $s = $script:Stats
    $truncated = $s.Truncated -or $script:TimeUp

    # Machine-parseable rollup.
    Write-Output ("SUMMARY | candidatesMatched={0} | filesScanned={1} | skippedSize={2} | skippedBinary={3} | fileErrors={4} | dirErrors={5} | reparseSkipped={6} | hashErrors={7} | filesWithFindings={8} | envScopes={9} | envVars={10} | envVarsWithFindings={11} | totalFindings={12} | elapsedSec={13} | truncated={14}" -f `
        $s.CandidatesMatched, $s.FilesScanned, $s.SkippedSize, $s.SkippedBinary, $s.FileErrors, `
        $s.DirErrors, $s.ReparseSkipped, $s.HashErrors, $s.FilesWithFindings, `
        $s.EnvScopesScanned, $s.EnvVarsScanned, $s.EnvVarsWithFindings, $s.TotalFindings, `
        ([int]$ElapsedSeconds), $truncated)

    foreach ($k in ($s.ByConfidence.Keys | Sort-Object)) {
        Write-Output ("SUMMARY | byConfidence | {0}={1}" -f $k, $s.ByConfidence[$k])
    }
    foreach ($k in ($s.ByRule.Keys | Sort-Object)) {
        Write-Output ("SUMMARY | byRule | {0}={1}" -f $k, $s.ByRule[$k])
    }

    # Human-readable block.
    Write-Output ''
    Write-Output '==================== Find-HardcodedSecrets summary ===================='
    Write-Output ("  Host                 : {0}" -f $env:COMPUTERNAME)
    Write-Output ("  Candidate files seen : {0}" -f $s.CandidatesMatched)
    Write-Output ("  Files content-scanned: {0}" -f $s.FilesScanned)
    Write-Output ("  Skipped (size)       : {0}" -f $s.SkippedSize)
    Write-Output ("  Skipped (binary)     : {0}" -f $s.SkippedBinary)
    Write-Output ("  File read errors     : {0}" -f $s.FileErrors)
    Write-Output ("  Directory errors     : {0}" -f $s.DirErrors)
    Write-Output ("  Reparse pts skipped  : {0}" -f $s.ReparseSkipped)
    Write-Output ("  Hash errors          : {0}" -f $s.HashErrors)
    Write-Output ("  Files with findings  : {0}" -f $s.FilesWithFindings)
    if ($s.EnvScopesScanned -gt 0) {
        Write-Output ("  Env scopes scanned   : {0}" -f $s.EnvScopesScanned)
        Write-Output ("  Env variables scanned: {0}" -f $s.EnvVarsScanned)
        Write-Output ("  Env vars w/ findings : {0}" -f $s.EnvVarsWithFindings)
    }
    Write-Output ("  Total findings       : {0}" -f $s.TotalFindings)
    if ($s.ByConfidence.Keys.Count -gt 0) {
        Write-Output '  Findings by confidence:'
        foreach ($k in ($s.ByConfidence.Keys | Sort-Object)) {
            Write-Output ("    {0,-7}: {1}" -f $k, $s.ByConfidence[$k])
        }
    }
    if ($s.ByRule.Keys.Count -gt 0) {
        Write-Output '  Findings by rule:'
        foreach ($k in ($s.ByRule.Keys | Sort-Object)) {
            Write-Output ("    {0} : {1}" -f $k, $s.ByRule[$k])
        }
    }
    Write-Output ("  Elapsed (seconds)    : {0}" -f ([int]$ElapsedSeconds))
    if ($truncated) {
        Write-Output '  *** SCAN TRUNCATED by -MaxRuntimeMinutes: results are PARTIAL ***'
    }
    Write-Output '======================================================================='
}

# ===========================================================================
# Main
# ===========================================================================

$script:StartLocal = Get-Date
$startUtc = $script:StartLocal.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')

# Detect language mode once: only use raw .NET file IO in Full Language Mode.
$langMode = $ExecutionContext.SessionState.LanguageMode
$script:UseDotNetIO = ($langMode -eq 'FullLanguage')

try {
    Write-Meta ("script=Find-HardcodedSecrets.ps1 version={0} host={1} startUtc={2} langMode={3}" -f `
        $ScriptVersion, $env:COMPUTERNAME, $startUtc, $langMode)
    Write-Meta ("params | minConfidence={0} maxFileSizeMB={1} maxRuntimeMinutes={2} includePlaceholders={3} envScanEnabled={4} dotNetIO={5} rules={6}" -f `
        $MinConfidence, $MaxFileSizeMB, $MaxRuntimeMinutes, $script:IncludePlaceholders, (-not $SkipEnvironment), $script:UseDotNetIO, $script:Rules.Count)

    # Resolve roots to scan.
    $roots = @()
    if ($Drives -and $Drives.Count -gt 0) {
        foreach ($d in $Drives) {
            if ([string]::IsNullOrWhiteSpace($d)) { continue }
            $isDir = $false
            try { $isDir = Test-Path -LiteralPath $d -PathType Container -ErrorAction Stop } catch { $isDir = $false }
            if ($isDir) {
                try { $roots += (Resolve-Path -LiteralPath $d -ErrorAction Stop).Path }
                catch { $roots += $d }
            }
            else {
                $letter = $d.TrimEnd('\').TrimEnd(':')
                if ($letter) { $roots += ($letter + ':\') }
            }
        }
    }
    else {
        foreach ($drv in (Get-FixedDrive)) { $roots += ($drv + '\') }
    }

    $roots = @($roots | Select-Object -Unique)
    Write-Meta ("rootsToScan | {0}" -f ($roots -join ', '))

    if ($roots.Count -eq 0) {
        Write-Meta 'no scannable roots resolved; nothing to do'
    }

    foreach ($root in $roots) {
        if ($script:TimeUp) { break }
        Write-Meta ("drive-scan-start | root={0}" -f $root)
        if (-not (Test-Path -LiteralPath $root -PathType Container)) {
            Write-ErrLine ("root-missing | {0}" -f $root)
            continue
        }
        Invoke-DirScan -Dir $root
        Write-Meta ("drive-scan-end | root={0} dirsTraversed={1} findings={2}" -f `
            $root, $script:Stats.DirsTraversed, $script:Stats.TotalFindings)
        if ($script:TimeUp) {
            $script:Stats.Truncated = $true
            Write-Meta 'runtime budget exceeded; stopping with partial results'
            break
        }
    }

    # Environment-variable scan (registry-backed), after the file scan. Runs by
    # DEFAULT (a common secret stash); pass -SkipEnvironment for files-only.
    # Default-on matters because the Live Response 'run' command takes no
    # arguments, so the zero-arg scan must already be the comprehensive one.
    if (-not $SkipEnvironment -and -not $script:TimeUp) {
        Write-Meta 'env-scan-start'
        Invoke-EnvScan
        Write-Meta ("env-scan-end | scopes={0} vars={1} varsWithFindings={2}" -f `
            $script:Stats.EnvScopesScanned, $script:Stats.EnvVarsScanned, $script:Stats.EnvVarsWithFindings)
        if ($script:TimeUp) { $script:Stats.Truncated = $true }
    }
}
catch {
    # Top-level safety net: never die with an uncaught exception.
    Write-ErrLine ("fatal | {0}" -f $_.Exception.Message)
}
finally {
    $elapsed = ((Get-Date) - $script:StartLocal).TotalSeconds
    Write-Summary -ElapsedSeconds $elapsed
}

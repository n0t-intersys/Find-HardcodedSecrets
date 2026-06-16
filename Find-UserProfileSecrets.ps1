<#
.SYNOPSIS
    Read-only Live Response scan of USER PROFILES (C:\Users) for .env / .config
    files containing hardcoded secrets. Reports location only -- never the value.
    Scoped to C:\Users so it finishes well under the Live Response session cap.

.DESCRIPTION
    One of a suite of focused Find-*Secrets.ps1 scripts split out of the full
    Find-HardcodedSecrets.ps1 so each runs fast. This one scans only the
    user-profile tree (C:\Users), where most application/developer secrets live
    (.env files, app.config, user-scoped web.config, etc.).

    Targets (case-insensitive): *.env, .env.* and *.config. Uses the same
    detection rules and forensic guarantees as the full scanner. Read-only;
    Windows PowerShell 5.1; tolerant of Constrained Language Mode. Skips reparse
    points and cloud/offline placeholders (no OneDrive hydration / off-box
    traffic). Runs as the bare, arg-less Live Response 'run' command.

.PARAMETER Roots
    One or more directories to scan. Default: C:\Users. Override to retarget the
    scan (a single profile, a mounted evidence path, etc.) -- the default keeps
    the zero-arg 'run' behavior identical.

.PARAMETER MinConfidence
    Minimum confidence to report: High, Medium or Low. Default: Medium.

.PARAMETER MaxFileSizeMB
    Skip candidate files larger than this many megabytes. Default: 10. Raise it
    to scan a large machine.config / JSON dump that exceeds the guardrail.

.PARAMETER MaxRuntimeMinutes
    File-scan time budget in minutes. Default: 10 (the scope is bounded, so this
    is plenty; keep it below your Live Response session cap). 0 = unlimited.

.PARAMETER ExcludePaths
    Case-insensitive path fragments to skip during traversal. Default: a small
    high-noise user-profile list (INetCache, AppData\Local\Packages, Explorer).

.PARAMETER IncludePlaceholders
    Switch. Disable placeholder/reference filtering (e.g. ${VAR}, changeme).

.EXAMPLE
    Live Response (zero arguments):
        run Find-UserProfileSecrets.ps1

.EXAMPLE
    Target a single profile (where args are usable):
        runscript -scriptName Find-UserProfileSecrets.ps1 -args "-Roots C:\Users\sean.kennedy"

.NOTES
    Safety: read-only; writes nothing (stdout only); never prints a secret value
    (labels/confidence/line/path/sha256/length only); no network.
    Version : 1.1.1
    Author  : DFIR
#>

#requires -Version 5.1

[CmdletBinding()]
param(
    [string[]]$Roots = @('C:\Users'),

    [ValidateSet('High', 'Medium', 'Low')]
    [string]$MinConfidence = 'Medium',

    [int]$MaxFileSizeMB = 10,

    [int]$MaxRuntimeMinutes = 10,

    [string[]]$ExcludePaths = @(
        '\AppData\Local\Microsoft\Windows\INetCache',
        '\AppData\Local\Packages',
        '\AppData\Local\Microsoft\Windows\Explorer'
    ),

    [switch]$IncludePlaceholders
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ScriptVersion = '1.1.1'
# Shared detection-rule generation (see suite note); bump in ALL Find-*Secrets.ps1
# when rules/TriggerPattern/placeholders change. Canonical: Find-HardcodedSecrets.ps1.
$RulesRev = '1'

# ---- Scope: default below; override with -Roots for targeted/triage scans. ----
$script:ScanRoots = $Roots

# ===========================================================================
# Detection rules (hashtables for Constrained Language Mode safety).
# CaseSensitive -> -cmatch; Type 'Structured' = whole match is the token (no
# placeholder filtering); 'Contextual' = keyword=value, value placeholder-filtered.
# ===========================================================================
$script:Rules = @(
    @{ Id = 'AWS_AKID';         Label = 'AWS Access Key ID';                   Pattern = '\b(AKIA|ASIA)[0-9A-Z]{16}\b';                                  CaseSensitive = $true;  Confidence = 'High';   Type = 'Structured' }
    @{ Id = 'GCP_APIKEY';       Label = 'Google API key';                      Pattern = '\bAIza[0-9A-Za-z\-_]{35}\b';                                   CaseSensitive = $true;  Confidence = 'High';   Type = 'Structured' }
    @{ Id = 'GCP_OAUTH';        Label = 'Google OAuth client ID';              Pattern = '[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com';        CaseSensitive = $true;  Confidence = 'High';   Type = 'Structured' }
    @{ Id = 'SLACK_TOKEN';      Label = 'Slack token';                         Pattern = '\bxox[baprs]-[0-9A-Za-z-]{10,}\b';                             CaseSensitive = $true;  Confidence = 'High';   Type = 'Structured' }
    @{ Id = 'GITHUB_TOKEN';     Label = 'GitHub token';                        Pattern = '\bgh[pousr]_[0-9A-Za-z]{36,}\b';                               CaseSensitive = $true;  Confidence = 'High';   Type = 'Structured' }
    @{ Id = 'GITLAB_PAT';       Label = 'GitLab personal access token';        Pattern = '\bglpat-[0-9A-Za-z\-_]{20,}\b';                                CaseSensitive = $true;  Confidence = 'High';   Type = 'Structured' }
    @{ Id = 'STRIPE_LIVE';      Label = 'Stripe live secret key';              Pattern = '\b(sk|rk)_live_[0-9A-Za-z]{20,}\b';                            CaseSensitive = $true;  Confidence = 'High';   Type = 'Structured' }
    @{ Id = 'SENDGRID_KEY';     Label = 'SendGrid API key';                    Pattern = '\bSG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}\b';               CaseSensitive = $true;  Confidence = 'High';   Type = 'Structured' }
    @{ Id = 'TWILIO_SK';        Label = 'Twilio API key SID';                  Pattern = '\bSK[0-9a-fA-F]{32}\b';                                        CaseSensitive = $true;  Confidence = 'High';   Type = 'Structured' }
    @{ Id = 'PRIVATE_KEY';      Label = 'Private key block (PEM/OpenSSH/PGP)';  Pattern = '-----BEGIN (RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----'; CaseSensitive = $true; Confidence = 'High'; Type = 'Structured' }
    @{ Id = 'JWT';              Label = 'JSON Web Token';                       Pattern = '\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b'; CaseSensitive = $true; Confidence = 'High'; Type = 'Structured' }
    @{ Id = 'AZURE_STORAGE';    Label = 'Azure storage AccountKey';            Pattern = 'AccountKey=[A-Za-z0-9+/=]{40,}';                               CaseSensitive = $true;  Confidence = 'High';   Type = 'Structured' }
    @{ Id = 'OPENAI_ANTHROPIC'; Label = 'OpenAI/Anthropic API key';            Pattern = '\bsk-(proj-|ant-)?[A-Za-z0-9_-]{20,}\b';                       CaseSensitive = $true;  Confidence = 'High';   Type = 'Structured' }
    @{ Id = 'NPM_TOKEN';        Label = 'npm access token';                    Pattern = '\bnpm_[A-Za-z0-9]{36}\b';                                      CaseSensitive = $true;  Confidence = 'High';   Type = 'Structured' }
    @{ Id = 'GITHUB_FG_PAT';    Label = 'GitHub fine-grained PAT';             Pattern = '\bgithub_pat_[0-9A-Za-z_]{82}\b';                              CaseSensitive = $true;  Confidence = 'High';   Type = 'Structured' }
    @{ Id = 'AZURE_AD_SECRET';  Label = 'Azure AD client secret';              Pattern = '\b[A-Za-z0-9_~.\-]{3}[78]Q~[A-Za-z0-9_~.\-]{31,34}\b';         CaseSensitive = $true;  Confidence = 'High';   Type = 'Structured' }
    @{ Id = 'SLACK_WEBHOOK';    Label = 'Slack webhook URL';                   Pattern = 'https://hooks\.slack\.com/services/[A-Za-z0-9/]+';             CaseSensitive = $false; Confidence = 'High';   Type = 'Structured' }
    @{ Id = 'TWILIO_AC';        Label = 'Twilio Account SID';                  Pattern = '\bAC[0-9a-f]{32}\b';                                           CaseSensitive = $true;  Confidence = 'Medium'; Type = 'Structured' }
    @{ Id = 'MAILGUN_KEY';      Label = 'Mailgun API key';                     Pattern = '\bkey-[0-9a-f]{32}\b';                                         CaseSensitive = $true;  Confidence = 'Medium'; Type = 'Structured' }
    @{ Id = 'URL_CRED';         Label = 'URL with embedded credentials';       Pattern = '(?i)[a-z][a-z0-9+.\-]*://[^:/?#\s@]+:[^@/?#\s]{2,}@';           CaseSensitive = $false; Confidence = 'High';   Type = 'Structured' }
    @{ Id = 'GEN_PASSWORD';     Label = 'Password assignment';                 Pattern = '\b(password|passwd|pwd)\s*[:=]\s*["'']?(?<val>[^"''\s;]{4,})';  CaseSensitive = $false; Confidence = 'Medium'; Type = 'Contextual' }
    @{ Id = 'GEN_SECRET';       Label = 'Secret/token/key assignment';         Pattern = '\b(api[_-]?key|secret|client[_-]?secret|access[_-]?key|auth[_-]?token|token)\s*[:=]\s*["'']?(?<val>[^"''\s;]{8,})'; CaseSensitive = $false; Confidence = 'Medium'; Type = 'Contextual' }
    @{ Id = 'CONN_STRING';      Label = 'Connection string with credentials';  Pattern = '(connectionstring\s*=|<add[^>]+connectionstring\s*=)[^>]*\b(password|pwd)\s*=\s*(?<val>[^;"''>\s]+)'; CaseSensitive = $false; Confidence = 'Medium'; Type = 'Contextual' }
)

# Pre-filter gate: strict SUPERSET of every rule trigger; lines with no trigger
# skip the per-rule loop. Broaden (never narrow) when adding rules.
$script:TriggerPattern = '(?i)(password|passwd|pwd|secret|api|access|auth|client|token|credential|connectionstring|akia|asia|aiza|googleusercontent|xox|gh[pousr]_|glpat-|_live_|sg\.|begin|eyj|accountkey=|\bsk|npm_|github_pat_|q~|hooks\.slack|\bac[0-9a-f]|key-|://)'

$script:PlaceholderPatterns = @(
    'your[-_ ]?', 'changeme', 'example', 'x{4,}', '\*{3,}', '<[^>]+>',
    '\$\{[^}]+\}', '%[^%]+%', '\{\{[^}]+\}\}', '\$\([^)]+\)', '#\{[^}]+\}'
)

$script:ExcludePaths = @($ExcludePaths | ForEach-Object { $_.ToLowerInvariant() })   # pre-lowered once for Test-ExcludeDir (hot path)

$script:ConfRank = @{ 'High' = 3; 'Medium' = 2; 'Low' = 1 }
$script:MinRank             = $script:ConfRank[$MinConfidence]
$script:IncludePlaceholders = [bool]$IncludePlaceholders
$script:MaxRuntimeMinutes   = $MaxRuntimeMinutes
$script:MaxFileSizeBytes    = [long]$MaxFileSizeMB * 1MB
$script:TimeUp              = $false
$script:StartLocal          = $null
$script:UseDotNetIO         = $false

$script:Stats = @{
    DirsTraversed = 0; DirErrors = 0; ReparseSkipped = 0; CandidatesMatched = 0
    FilesScanned = 0; SkippedSize = 0; SkippedBinary = 0; SkippedCloud = 0
    FileErrors = 0; HashErrors = 0; FilesWithFindings = 0; TotalFindings = 0
    ByConfidence = @{}; ByRule = @{}; Truncated = $false
}

# ===========================================================================
# Helpers (mirror the validated logic in Find-HardcodedSecrets.ps1)
# ===========================================================================

function Add-Count { param($Hash, $Key) if ($Hash.ContainsKey($Key)) { $Hash[$Key] = $Hash[$Key] + 1 } else { $Hash[$Key] = 1 } }

function Test-ExcludeDir {
    param([string]$Path)
    $lower = $Path.ToLowerInvariant()
    foreach ($x in $script:ExcludePaths) { if ($x -and $lower.Contains($x)) { return $true } }
    return $false
}

function Test-IsCandidate {
    param([string]$Name)
    $n = $Name.ToLowerInvariant()
    if ($n.EndsWith('.env'))    { return $true }
    if ($n.StartsWith('.env.')) { return $true }
    if ($n.EndsWith('.config')) { return $true }
    return $false
}

function Test-TimeUp {
    if ($script:MaxRuntimeMinutes -le 0) { return $false }
    return ((((Get-Date) - $script:StartLocal).TotalMinutes) -ge $script:MaxRuntimeMinutes)
}

function Test-IsPlaceholder {
    param([string]$Value)
    if ([string]::IsNullOrEmpty($Value)) { return $true }
    foreach ($p in $script:PlaceholderPatterns) { if ($Value -match $p) { return $true } }
    return $false
}

function Test-FileIsBinary {
    param([string]$Path)
    $bytes = Get-Content -LiteralPath $Path -Encoding Byte -TotalCount 8192 -ErrorAction Stop
    if ($null -eq $bytes) { return $false }
    foreach ($b in $bytes) { if ($b -eq 0) { return $true } }
    return $false
}

function Read-FileLine {
    param([string]$Path)
    if ($script:UseDotNetIO) {
        $fs = $null; $sr = $null
        try {
            $fs = [System.IO.File]::Open($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
            $sr = New-Object System.IO.StreamReader -ArgumentList @($fs, $true)
            $text = $sr.ReadToEnd()
        }
        finally { if ($sr) { $sr.Dispose() } elseif ($fs) { $fs.Dispose() } }
        return [string[]]($text -split "`r`n|`n|`r")
    }
    else { return @(Get-Content -LiteralPath $Path -ErrorAction Stop) }
}

function Write-Meta        { param([string]$Message) Write-Output "META | $Message" }
function Write-ErrLine     { param([string]$Message) Write-Output "ERROR | $Message" }
function Write-FileLine    { param([string]$Sha, [long]$Size, [string]$LastWriteUtc, [string]$Path) Write-Output "FILE | $Sha | $Size | $LastWriteUtc | $Path" }
function Write-FindingLine {
    param([string]$Confidence, [string]$RuleId, [string]$Label, [int]$Line, [int]$Length, [string]$Path)
    Write-Output "FINDING | $Confidence | $RuleId | $Label | line=$Line | len=$Length | $Path"
}

function Invoke-FileScan {
    param($Item)
    $script:Stats.CandidatesMatched++
    $path = $Item.FullName

    # Skip cloud/offline placeholders (Offline 0x1000 / RecallOnOpen 0x40000 /
    # RecallOnDataAccess 0x400000) -- opening them triggers hydration (a download
    # that can hang and create off-box traffic).
    $attrInt = 0
    try { $attrInt = [int]$Item.Attributes } catch { $attrInt = 0 }
    if (($attrInt -band 0x441000) -ne 0) { $script:Stats.SkippedCloud++; return }

    if ($Item.Length -gt $script:MaxFileSizeBytes) { $script:Stats.SkippedSize++; return }

    try { if (Test-FileIsBinary -Path $path) { $script:Stats.SkippedBinary++; return } }
    catch { $script:Stats.FileErrors++; Write-ErrLine ("read | {0}" -f $path); return }

    $lines = $null
    try { $lines = @(Read-FileLine -Path $path) }
    catch { $script:Stats.FileErrors++; Write-ErrLine ("read | {0}" -f $path); return }
    $script:Stats.FilesScanned++

    $name = $Item.Name.ToLowerInvariant()
    $isConfig = $name.EndsWith('.config')
    $encWindow = @{}
    # Only do the per-line encrypted-config window pass if the marker is present
    # at all -- one cheap whole-file -match avoids a second full-file line scan on
    # large configs (the common case) that contain no protected sections.
    if ($isConfig -and (($lines -join "`n") -match 'configProtectionProvider')) {
        for ($i = 0; $i -lt $lines.Count; $i++) {
            if ($lines[$i] -match 'configProtectionProvider') {
                $lo = $i - 5; if ($lo -lt 0) { $lo = 0 }
                $hi = $i + 5; $maxIdx = $lines.Count - 1; if ($hi -gt $maxIdx) { $hi = $maxIdx }
                for ($j = $lo; $j -le $hi; $j++) { $encWindow[$j] = $true }
            }
        }
    }

    $fileFindings = @()
    $seen = @{}
    for ($i = 0; $i -lt $lines.Count; $i++) {
        $line = $lines[$i]
        if ([string]::IsNullOrEmpty($line)) { continue }
        if ($line -notmatch $script:TriggerPattern) { continue }

        foreach ($rule in $script:Rules) {
            if ($rule.CaseSensitive) { $isMatch = $line -cmatch $rule.Pattern } else { $isMatch = $line -match $rule.Pattern }
            if (-not $isMatch) { continue }
            $dupKey = "$($rule.Id)|$i"
            if ($seen.ContainsKey($dupKey)) { continue }

            if ($rule.Type -eq 'Contextual') {
                $val = ''
                if ($matches.Contains('val')) { $val = [string]$matches['val'] }
                if (-not $script:IncludePlaceholders) { if (Test-IsPlaceholder -Value $val) { continue } }
                $mlen = $val.Length
            }
            else { $mlen = ([string]$matches[0]).Length }

            $conf = $rule.Confidence; $label = $rule.Label
            if ($isConfig -and $encWindow.ContainsKey($i)) { $conf = 'Low'; $label = 'encrypted config section (value protected)' }
            if ($script:ConfRank[$conf] -lt $script:MinRank) { continue }

            $seen[$dupKey] = $true
            $fileFindings += @{ Line = ($i + 1); RuleId = $rule.Id; Label = $label; Confidence = $conf; Length = $mlen }
        }
    }

    if ($fileFindings.Count -eq 0) { return }
    $sha = 'UNAVAILABLE'
    try { $h = Get-FileHash -LiteralPath $path -Algorithm SHA256 -ErrorAction Stop; $sha = $h.Hash } catch { $script:Stats.HashErrors++ }
    $lastWriteUtc = $Item.LastWriteTimeUtc.ToString('yyyy-MM-ddTHH:mm:ssZ')
    Write-FileLine -Sha $sha -Size $Item.Length -LastWriteUtc $lastWriteUtc -Path $path
    $script:Stats.FilesWithFindings++
    foreach ($f in $fileFindings) {
        Write-FindingLine -Confidence $f.Confidence -RuleId $f.RuleId -Label $f.Label -Line $f.Line -Length $f.Length -Path $path
        $script:Stats.TotalFindings++
        Add-Count $script:Stats.ByConfidence $f.Confidence
        Add-Count $script:Stats.ByRule $f.Label
    }
}

function Invoke-DirScan {
    param([string]$Dir)
    if ($script:TimeUp) { return }
    if (Test-TimeUp) { $script:TimeUp = $true; return }
    if (Test-ExcludeDir -Path $Dir) { return }
    $script:Stats.DirsTraversed++
    if (($script:Stats.DirsTraversed % 2000) -eq 0) {
        $el = [int](((Get-Date) - $script:StartLocal).TotalSeconds)
        Write-Meta ("heartbeat | dirs={0} candidates={1} findings={2} elapsedSec={3}" -f $script:Stats.DirsTraversed, $script:Stats.CandidatesMatched, $script:Stats.TotalFindings, $el)
    }

    $children = $null
    try {
        if ($script:UseDotNetIO) { $children = @((New-Object System.IO.DirectoryInfo -ArgumentList $Dir).GetFileSystemInfos()) }
        else { $children = @(Get-ChildItem -LiteralPath $Dir -Force -ErrorAction Stop) }
    }
    catch { $script:Stats.DirErrors++; return }

    foreach ($c in $children) {
        if ($script:TimeUp) { return }
        if ((([int]$c.Attributes) -band 0x10) -ne 0) { continue }
        if (Test-IsCandidate -Name $c.Name) {
            if (Test-TimeUp) { $script:TimeUp = $true; return }
            Invoke-FileScan -Item $c
        }
    }
    foreach ($c in $children) {
        if ($script:TimeUp) { return }
        if ((([int]$c.Attributes) -band 0x10) -eq 0) { continue }
        if ((([int]$c.Attributes) -band 0x400) -ne 0) { $script:Stats.ReparseSkipped++; continue }
        Invoke-DirScan -Dir $c.FullName
    }
}

function Write-Summary {
    param([double]$ElapsedSeconds)
    $s = $script:Stats
    $truncated = $s.Truncated -or $script:TimeUp
    Write-Output ("SUMMARY | candidatesMatched={0} | filesScanned={1} | skippedSize={2} | skippedBinary={3} | skippedCloud={4} | fileErrors={5} | dirErrors={6} | reparseSkipped={7} | hashErrors={8} | filesWithFindings={9} | totalFindings={10} | elapsedSec={11} | truncated={12}" -f `
        $s.CandidatesMatched, $s.FilesScanned, $s.SkippedSize, $s.SkippedBinary, $s.SkippedCloud, $s.FileErrors, $s.DirErrors, $s.ReparseSkipped, $s.HashErrors, $s.FilesWithFindings, $s.TotalFindings, ([int]$ElapsedSeconds), $truncated)
    foreach ($k in ($s.ByConfidence.Keys | Sort-Object)) { Write-Output ("SUMMARY | byConfidence | {0}={1}" -f $k, $s.ByConfidence[$k]) }
    foreach ($k in ($s.ByRule.Keys | Sort-Object)) { Write-Output ("SUMMARY | byRule | {0}={1}" -f $k, $s.ByRule[$k]) }
    Write-Output ''
    Write-Output '==================== Find-UserProfileSecrets summary ===================='
    Write-Output ("  Host                 : {0}" -f $env:COMPUTERNAME)
    Write-Output ("  Scan roots           : {0}" -f ($script:ScanRoots -join ', '))
    Write-Output ("  Candidate files seen : {0}" -f $s.CandidatesMatched)
    Write-Output ("  Files content-scanned: {0}" -f $s.FilesScanned)
    Write-Output ("  Skipped (size)       : {0}" -f $s.SkippedSize)
    Write-Output ("  Skipped (binary)     : {0}" -f $s.SkippedBinary)
    Write-Output ("  Skipped (cloud/offln): {0}" -f $s.SkippedCloud)
    Write-Output ("  Directory errors     : {0}" -f $s.DirErrors)
    Write-Output ("  Reparse pts skipped  : {0}" -f $s.ReparseSkipped)
    Write-Output ("  Files with findings  : {0}" -f $s.FilesWithFindings)
    Write-Output ("  Total findings       : {0}" -f $s.TotalFindings)
    Write-Output ("  Elapsed (seconds)    : {0}" -f ([int]$ElapsedSeconds))
    if ($truncated) { Write-Output '  *** SCAN TRUNCATED by -MaxRuntimeMinutes: results are PARTIAL ***' }
    Write-Output '========================================================================'
}

# ===========================================================================
# Main
# ===========================================================================
$script:StartLocal = Get-Date
$startUtc = $script:StartLocal.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
$langMode = $ExecutionContext.SessionState.LanguageMode
$script:UseDotNetIO = ($langMode -eq 'FullLanguage')

try {
    Write-Meta ("script=Find-UserProfileSecrets.ps1 version={0} rulesRev={1} host={2} startUtc={3} langMode={4}" -f $ScriptVersion, $RulesRev, $env:COMPUTERNAME, $startUtc, $langMode)
    Write-Meta ("params | minConfidence={0} maxFileSizeMB={1} maxRuntimeMinutes={2} includePlaceholders={3} dotNetIO={4} rules={5}" -f $MinConfidence, $MaxFileSizeMB, $MaxRuntimeMinutes, $script:IncludePlaceholders, $script:UseDotNetIO, $script:Rules.Count)
    Write-Meta ("scanRoots | {0}" -f ($script:ScanRoots -join ', '))
    foreach ($root in $script:ScanRoots) {
        if ($script:TimeUp) { break }
        if (-not (Test-Path -LiteralPath $root -PathType Container)) { Write-Meta ("root-missing | {0}" -f $root); continue }
        Write-Meta ("scan-start | root={0}" -f $root)
        Invoke-DirScan -Dir $root
        Write-Meta ("scan-end | root={0} dirsTraversed={1} findings={2}" -f $root, $script:Stats.DirsTraversed, $script:Stats.TotalFindings)
        if ($script:TimeUp) { $script:Stats.Truncated = $true; Write-Meta 'file-scan runtime budget exceeded; stopping with partial results'; break }
    }
}
catch { Write-ErrLine ("fatal | {0}" -f $_.Exception.Message) }
finally {
    $elapsed = ((Get-Date) - $script:StartLocal).TotalSeconds
    Write-Summary -ElapsedSeconds $elapsed
}

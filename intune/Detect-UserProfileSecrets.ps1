<#
.SYNOPSIS
    Microsoft Intune REMEDIATION DETECTION script. Read-only scan of user-profile
    files (C:\Users by default) for .env / .config files containing hardcoded
    secrets. Exits 1 when secrets are found (device flagged "issue detected"),
    0 when clean. Emits a compact, single-line report sized to survive Intune's
    ~2 KB detection-output cap. Never prints the secret value.

.DESCRIPTION
    Companion to Detect-EnvVarSecrets.ps1 for FILE-based secrets. Intune use:
    Devices -> Scripts and remediations -> create a remediation, use THIS as the
    detection script. Recommended settings: Run as SYSTEM, 64-bit, signature
    check off. Intune passes no arguments, so the defaults are the operative
    config; Intune surfaces only the LAST stdout line, so the whole report is on
    ONE line (verdict + counts + findings inline), capped under ~2 KB.

    Detection logic / rules are identical to Find-UserProfileSecrets.ps1 (kept in
    sync by tools\Test-SuiteConsistency.ps1). Read-only; opens files shared
    read/write; skips reparse points and cloud/offline placeholders (no OneDrive
    hydration); Windows PowerShell 5.1; tolerant of Constrained Language Mode.

    Output (single line):
      STATUS=FOUND | host=<h> ver=<v> n=<n> high=<a> med=<b> low=<c> files=<f> scanned=<s> trunc=<0|1> rev=<r> :: HIGH <RuleId> <path>:<line> ; MED ... [; (+N more)]
    or  STATUS=CLEAN | host=<h> ver=<v> n=0 scanned=<s> trunc=<0|1> rev=<r>
    or  STATUS=ERROR | host=<h> ver=<v> rev=<r> | msg=<...>   (exit 1)
    trunc=1 means the file-scan time budget was hit -> results are PARTIAL. For
    full per-finding detail (incl. SHA-256), run Find-UserProfileSecrets.ps1 via
    Live Response on a flagged device.

.PARAMETER Roots
    Directories to scan. Default: C:\Users. (Intune can't pass args; for local
    testing you can point this at a fixture folder.)

.PARAMETER MinConfidence
    Minimum confidence to report: High, Medium or Low. Default: Medium.

.PARAMETER MaxFileSizeMB
    Skip candidate files larger than this many megabytes. Default: 10.

.PARAMETER MaxRuntimeMinutes
    File-scan time budget in minutes. Default: 10 (well under Intune's ~30 min
    kill). On exceed, the scan stops, reports partial results, and sets trunc=1.
    0 = unlimited (not recommended for Intune).

.PARAMETER ExcludePaths
    Case-insensitive path fragments to skip. Default: high-noise user-profile
    caches (INetCache, AppData\Local\Packages, Explorer).

.PARAMETER IncludePlaceholders
    Switch. Disable placeholder/reference filtering (e.g. ${VAR}, changeme).

.EXAMPLE
    Local test:
        powershell -ExecutionPolicy Bypass -File .\Detect-UserProfileSecrets.ps1 ; $LASTEXITCODE

.NOTES
    Safety: read-only; writes nothing; never prints a secret value (path + line
    only); no network. Exit codes: 0 = clean, 1 = secrets found OR scan error.
    Version : 1.0.0
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
$ScriptVersion = '1.0.0'
# Shared detection-rule generation (see suite note); bump in ALL
# Find-*Secrets.ps1 / Detect-*Secrets.ps1 when rules / TriggerPattern /
# placeholders change. Canonical: Find-HardcodedSecrets.ps1.
$RulesRev = '1'

# ===========================================================================
# Detection rules (identical to Find-UserProfileSecrets.ps1; kept in sync by
# tools\Test-SuiteConsistency.ps1). Hashtables for Constrained Language Mode.
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

$script:TriggerPattern = '(?i)(password|passwd|pwd|secret|api|access|auth|client|token|credential|connectionstring|akia|asia|aiza|googleusercontent|xox|gh[pousr]_|glpat-|_live_|sg\.|begin|eyj|accountkey=|\bsk|npm_|github_pat_|q~|hooks\.slack|\bac[0-9a-f]|key-|://)'

$script:PlaceholderPatterns = @(
    'your[-_ ]?', 'changeme', 'example', 'x{4,}', '\*{3,}', '<[^>]+>',
    '\$\{[^}]+\}', '%[^%]+%', '\{\{[^}]+\}\}', '\$\([^)]+\)', '#\{[^}]+\}'
)

$script:ScanRoots          = $Roots
$script:ExcludePaths       = @($ExcludePaths | ForEach-Object { $_.ToLowerInvariant() })   # pre-lowered for Test-ExcludeDir
$script:ConfRank           = @{ 'High' = 3; 'Medium' = 2; 'Low' = 1 }
$script:MinRank            = $script:ConfRank[$MinConfidence]
$script:IncludePlaceholders = [bool]$IncludePlaceholders
$script:MaxRuntimeMinutes  = $MaxRuntimeMinutes
$script:MaxFileSizeBytes   = [long]$MaxFileSizeMB * 1MB
$script:TimeUp             = $false
$script:StartLocal         = $null
$script:UseDotNetIO        = $false

$script:Findings          = @()
$script:CandidatesMatched = 0
$script:FilesScanned      = 0
$script:FilesWithFindings = 0
$script:SkippedSize       = 0
$script:SkippedBinary     = 0
$script:SkippedCloud      = 0
$script:FileErrors        = 0
$script:DirErrors         = 0
$script:ReparseSkipped    = 0

# ===========================================================================
# Helpers (mirror Find-UserProfileSecrets.ps1; no inline output -- collect only)
# ===========================================================================

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

function Invoke-FileScan {
    param($Item)
    $script:CandidatesMatched++
    $path = $Item.FullName

    $attrInt = 0
    try { $attrInt = [int]$Item.Attributes } catch { $attrInt = 0 }
    if (($attrInt -band 0x441000) -ne 0) { $script:SkippedCloud++; return }   # cloud/offline placeholder

    if ($Item.Length -gt $script:MaxFileSizeBytes) { $script:SkippedSize++; return }

    try { if (Test-FileIsBinary -Path $path) { $script:SkippedBinary++; return } }
    catch { $script:FileErrors++; return }

    $lines = $null
    try { $lines = @(Read-FileLine -Path $path) }
    catch { $script:FileErrors++; return }
    $script:FilesScanned++

    $isConfig = $Item.Name.ToLowerInvariant().EndsWith('.config')
    $encWindow = @{}
    if ($isConfig -and (($lines -join "`n") -match 'configProtectionProvider')) {
        for ($i = 0; $i -lt $lines.Count; $i++) {
            if ($lines[$i] -match 'configProtectionProvider') {
                $lo = $i - 5; if ($lo -lt 0) { $lo = 0 }
                $hi = $i + 5; $maxIdx = $lines.Count - 1; if ($hi -gt $maxIdx) { $hi = $maxIdx }
                for ($j = $lo; $j -le $hi; $j++) { $encWindow[$j] = $true }
            }
        }
    }

    $hadFinding = $false
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
            }

            $conf = $rule.Confidence
            if ($isConfig -and $encWindow.ContainsKey($i)) { $conf = 'Low' }
            if ($script:ConfRank[$conf] -lt $script:MinRank) { continue }

            $seen[$dupKey] = $true
            $script:Findings += @{ Confidence = $conf; RuleId = $rule.Id; Path = $path; Line = ($i + 1) }
            $hadFinding = $true
        }
    }
    if ($hadFinding) { $script:FilesWithFindings++ }
}

function Invoke-DirScan {
    param([string]$Dir)
    if ($script:TimeUp) { return }
    if (Test-TimeUp) { $script:TimeUp = $true; return }
    if (Test-ExcludeDir -Path $Dir) { return }

    $children = $null
    try {
        if ($script:UseDotNetIO) { $children = @((New-Object System.IO.DirectoryInfo -ArgumentList $Dir).GetFileSystemInfos()) }
        else { $children = @(Get-ChildItem -LiteralPath $Dir -Force -ErrorAction Stop) }
    }
    catch { $script:DirErrors++; return }

    foreach ($c in $children) {
        if ($script:TimeUp) { return }
        if ((([int]$c.Attributes) -band 0x10) -ne 0) { continue }   # directory
        if (Test-IsCandidate -Name $c.Name) {
            if (Test-TimeUp) { $script:TimeUp = $true; return }
            Invoke-FileScan -Item $c
        }
    }
    foreach ($c in $children) {
        if ($script:TimeUp) { return }
        if ((([int]$c.Attributes) -band 0x10) -eq 0) { continue }   # not a directory
        if ((([int]$c.Attributes) -band 0x400) -ne 0) { $script:ReparseSkipped++; continue }   # reparse point
        Invoke-DirScan -Dir $c.FullName
    }
}

# ===========================================================================
# Main -- scan, then emit ONE summary line and set the exit code.
# ===========================================================================

$script:StartLocal = Get-Date
$script:UseDotNetIO = ($ExecutionContext.SessionState.LanguageMode -eq 'FullLanguage')

$err = $null
try {
    foreach ($root in $script:ScanRoots) {
        if ($script:TimeUp) { break }
        if (-not (Test-Path -LiteralPath $root -PathType Container)) { continue }
        Invoke-DirScan -Dir $root
    }
}
catch { $err = $_.Exception.Message }

if ($err) {
    Write-Output ("STATUS=ERROR | host={0} ver={1} rev={2} | msg={3}" -f $env:COMPUTERNAME, $ScriptVersion, $RulesRev, ($err -replace '\s+', ' '))
    exit 1
}

$findings = @($script:Findings)
$n = $findings.Count
$trunc = if ($script:TimeUp) { 1 } else { 0 }

if ($n -eq 0) {
    Write-Output ("STATUS=CLEAN | host={0} ver={1} n=0 scanned={2} trunc={3} rev={4}" -f $env:COMPUTERNAME, $ScriptVersion, $script:FilesScanned, $trunc, $RulesRev)
    exit 0
}

$high = @($findings | Where-Object { $_.Confidence -eq 'High' }).Count
$med  = @($findings | Where-Object { $_.Confidence -eq 'Medium' }).Count
$low  = @($findings | Where-Object { $_.Confidence -eq 'Low' }).Count

# Single line: Intune surfaces only the last stdout line. Findings inline,
# High -> Medium -> Low, capped under ~2 KB with a (+N more) overflow note.
$head = "STATUS=FOUND | host={0} ver={1} n={2} high={3} med={4} low={5} files={6} scanned={7} trunc={8} rev={9}" -f `
    $env:COMPUTERNAME, $ScriptVersion, $n, $high, $med, $low, $script:FilesWithFindings, $script:FilesScanned, $trunc, $RulesRev
$tag = @{ 'High' = 'HIGH'; 'Medium' = 'MED'; 'Low' = 'LOW' }
$budget = 2000
$used = $head.Length + 4
$parts = @()
$shown = 0
$stop = $false
foreach ($conf in @('High', 'Medium', 'Low')) {
    if ($stop) { break }
    foreach ($f in $findings) {
        if ($f.Confidence -ne $conf) { continue }
        $item = "{0} {1} {2}:{3}" -f $tag[$conf], $f.RuleId, $f.Path, $f.Line
        if (($used + $item.Length + 3) -gt $budget) {
            $parts += ("(+{0} more)" -f ($n - $shown))
            $stop = $true
            break
        }
        $parts += $item
        $used += $item.Length + 3
        $shown++
    }
}
Write-Output ($head + ' :: ' + ($parts -join ' ; '))
exit 1

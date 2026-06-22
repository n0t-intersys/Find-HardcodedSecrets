<#
.SYNOPSIS
    Microsoft Intune REMEDIATION DETECTION script. Read-only scan of the REGISTRY
    for hardcoded credentials -- both well-known credential keys (Windows
    auto-logon password, PuTTY / WinSCP saved sessions, VNC server passwords) and
    a broad sweep of value DATA under HKLM\SOFTWARE and each loaded user hive.
    Exits 1 when secrets are found (device flagged "issue detected"), 0 when clean.
    One compact stdout line. Never prints the secret value -- only key + value name
    + length.

.DESCRIPTION
    Part of the Intune Detect-*Secrets.ps1 set. Files and environment variables
    are covered by the other scripts; THIS one covers the registry, where apps and
    Windows itself stash credentials that a file scan never sees.

    Two passes:
      1. TARGETED -- a curated list of keys known to hold credentials, checked
         explicitly (fast, high-signal, low false-positive):
           * HKLM\...\Winlogon\DefaultPassword         (auto-logon, PLAINTEXT)
           * HKU\<sid>\...\PuTTY\Sessions\*\ProxyPassword
           * HKU\<sid>\...\WinSCP 2\Sessions\*\(Password|ProxyPassword)
           * RealVNC / TightVNC / UltraVNC server Password values
      2. BROAD -- recurse HKLM\SOFTWARE and each loaded HKU\<sid>\SOFTWARE, apply
         the shared provider-format rules to string value DATA and flag values
         whose NAME looks like a secret (password / api_key / token / ...), the
         same logic the env-var scanner uses.

    Intune use: Devices -> Scripts and remediations -> create a remediation, use
    THIS as the detection script. Recommended settings: Run as SYSTEM, 64-bit,
    signature check off. Intune passes no arguments, so the defaults are the
    operative config; it surfaces only the LAST stdout line, so the whole report
    is on ONE line, capped under ~2 KB.

    Detection rules / placeholders are the shared suite set (rev 3; kept in sync
    by tools\Test-SuiteConsistency.ps1). Read-only (registry reads only; writes
    nothing); Windows PowerShell 5.1; tolerant of Constrained Language Mode
    (cmdlets + PSObject.Properties only -- no RegistryKey methods). Never decrypts
    anything; obfuscated/encrypted values (VNC, etc.) are flagged by PRESENCE.

    Output (single line):
      STATUS=FOUND | host=<h> ver=<v> n=<n> high=<a> med=<b> low=<c> keys=<k> trunc=<0|1> rev=<r> :: HIGH <RuleId> <Scope>::<key\value>(<len>) ; MED ... [; (+N more)]
    or  STATUS=CLEAN | host=<h> ver=<v> n=0 keys=<k> trunc=<0|1> rev=<r>
    or  STATUS=ERROR | host=<h> ver=<v> rev=<r> | msg=<...>   (exit 1)
    trunc=1 means the broad-scan time budget was hit -> results are PARTIAL
    (targeted keys are always checked first, so they are never lost to a timeout).

.PARAMETER MinConfidence
    Minimum confidence to report: High, Medium or Low. Default: Medium.

.PARAMETER MaxRuntimeMinutes
    Broad-scan time budget in minutes. Default: 15 (well under Intune's ~30-min
    kill). On exceed, the broad scan stops, reports partial results, sets trunc=1.
    0 = unlimited (not recommended for Intune).

.PARAMETER ScanRoots
    Override the broad-scan roots (each a 'Registry::HKEY_...' path). Default
    (empty) = HKLM\SOFTWARE plus each loaded HKU\<sid>\SOFTWARE. For local testing.

.PARAMETER SkipBroadScan
    Switch. Run only the targeted credential-key checks (seconds), no recursion.

.PARAMETER IncludePlaceholders
    Switch. Disable placeholder/reference filtering (e.g. ${VAR}, changeme).

.PARAMETER AggressiveValueScan
    Switch (off by default). Also flag high-entropy-looking value data regardless
    of the value name. Noisier; for a fleet detection leave off.

.PARAMETER SkipServiceAccounts
    Switch (off by default). Skip the built-in service-account hives (S-1-5-18/19/20).

.EXAMPLE
    Local test:
        powershell -ExecutionPolicy Bypass -File .\Detect-RegistrySecrets.ps1 ; $LASTEXITCODE

.NOTES
    Safety: read-only; writes nothing; never prints a secret value (key+name+len
    only); never decrypts; no network. Exit codes: 0 = clean, 1 = found OR error.
    Version : 1.0.0
    Author  : DFIR
#>

#requires -Version 5.1

[CmdletBinding()]
param(
    [ValidateSet('High', 'Medium', 'Low')]
    [string]$MinConfidence = 'Medium',

    [int]$MaxRuntimeMinutes = 15,

    [string[]]$ScanRoots = @(),

    [switch]$SkipBroadScan,

    [switch]$IncludePlaceholders,

    [switch]$AggressiveValueScan,

    [switch]$SkipServiceAccounts
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ScriptVersion = '1.0.0'
# Shared detection-rule generation (see suite note); bump in ALL Find-*Secrets.ps1
# / Detect-*Secrets.ps1 when rules change. Canonical: Find-HardcodedSecrets.ps1.
$RulesRev = '4'

# --- Structured provider-format rules, matched against value DATA (identical to
#     the env-var scanner; kept in sync via the drift guard). ---
$script:Rules = @(
    @{ Id = 'AWS_AKID';         Label = 'AWS Access Key ID';                   Pattern = '\b(AKIA|ASIA)[0-9A-Z]{16}\b';                                  CaseSensitive = $true;  Confidence = 'High' }
    @{ Id = 'GCP_APIKEY';       Label = 'Google API key';                      Pattern = '\bAIza[0-9A-Za-z\-_]{35}\b';                                   CaseSensitive = $true;  Confidence = 'High' }
    @{ Id = 'GCP_OAUTH';        Label = 'Google OAuth client ID';              Pattern = '[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com';        CaseSensitive = $true;  Confidence = 'High' }
    @{ Id = 'SLACK_TOKEN';      Label = 'Slack token';                         Pattern = '\bxox[baprs]-[0-9A-Za-z-]{10,}\b';                             CaseSensitive = $true;  Confidence = 'High' }
    @{ Id = 'GITHUB_TOKEN';     Label = 'GitHub token';                        Pattern = '\bgh[pousr]_[0-9A-Za-z]{36,}\b';                               CaseSensitive = $true;  Confidence = 'High' }
    @{ Id = 'GITLAB_PAT';       Label = 'GitLab personal access token';        Pattern = '\bglpat-[0-9A-Za-z\-_]{20,}\b';                                CaseSensitive = $true;  Confidence = 'High' }
    @{ Id = 'STRIPE_LIVE';      Label = 'Stripe live secret key';              Pattern = '\b(sk|rk)_live_[0-9A-Za-z]{20,}\b';                            CaseSensitive = $true;  Confidence = 'High' }
    @{ Id = 'SENDGRID_KEY';     Label = 'SendGrid API key';                    Pattern = '\bSG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}\b';               CaseSensitive = $true;  Confidence = 'High' }
    @{ Id = 'TWILIO_SK';        Label = 'Twilio API key SID';                  Pattern = '\bSK[0-9a-fA-F]{32}\b';                                        CaseSensitive = $true;  Confidence = 'High' }
    @{ Id = 'PRIVATE_KEY';      Label = 'Private key block (PEM/OpenSSH/PGP)';  Pattern = '-----BEGIN (RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----'; CaseSensitive = $true; Confidence = 'High' }
    @{ Id = 'JWT';              Label = 'JSON Web Token';                       Pattern = '\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b'; CaseSensitive = $true; Confidence = 'High' }
    @{ Id = 'AZURE_STORAGE';    Label = 'Azure storage AccountKey';            Pattern = 'AccountKey=[A-Za-z0-9+/=]{40,}';                               CaseSensitive = $true;  Confidence = 'High' }
    @{ Id = 'OPENAI_ANTHROPIC'; Label = 'OpenAI/Anthropic API key';            Pattern = '\bsk-(proj-|ant-)?[A-Za-z0-9_-]{20,}\b';                       CaseSensitive = $true;  Confidence = 'High' }
    @{ Id = 'NPM_TOKEN';        Label = 'npm access token';                    Pattern = '\bnpm_[A-Za-z0-9]{36}\b';                                      CaseSensitive = $true;  Confidence = 'High' }
    @{ Id = 'GITHUB_FG_PAT';    Label = 'GitHub fine-grained PAT';             Pattern = '\bgithub_pat_[0-9A-Za-z_]{82}\b';                              CaseSensitive = $true;  Confidence = 'High' }
    @{ Id = 'AZURE_AD_SECRET';  Label = 'Azure AD client secret';              Pattern = '\b[A-Za-z0-9_~.\-]{3}[78]Q~[A-Za-z0-9_~.\-]{31,34}\b';         CaseSensitive = $true;  Confidence = 'High' }
    @{ Id = 'SLACK_WEBHOOK';    Label = 'Slack webhook URL';                   Pattern = 'https://hooks\.slack\.com/services/[A-Za-z0-9/]+';             CaseSensitive = $false; Confidence = 'High' }
    @{ Id = 'TWILIO_AC';        Label = 'Twilio Account SID';                  Pattern = '\bAC[0-9a-f]{32}\b';                                           CaseSensitive = $true;  Confidence = 'Medium' }
    @{ Id = 'MAILGUN_KEY';      Label = 'Mailgun API key';                     Pattern = '\bkey-[0-9a-f]{32}\b';                                         CaseSensitive = $true;  Confidence = 'Medium' }
    @{ Id = 'URL_CRED';         Label = 'URL with embedded credentials';       Pattern = '(?i)[a-z][a-z0-9+.\-]*://[^:/?#\s@]+:[^@/?#\s]{2,}@';           CaseSensitive = $false; Confidence = 'High' }
)

$script:PlaceholderPatterns = @(
    '\$\{[^}]+\}', '%[^%]+%', '\{\{[^}]+\}\}', '\$\([^)]+\)', '#\{[^}]+\}', '<[^>]+>',
    '\*{3,}', 'x{6,}',
    '^your[-_ ]', '^changeme', '^change-me', '^example', '^sample', '^placeholder',
    '^redacted', '^dummy', '^fakekey', '^test$', '^none$', '^null$', '^todo', '^tbd', '^xxx',
    '^[\*xX._\-]{4,}$', '(.)\1{9,}'
)

$script:NameKeywordPattern = '(?i)(password|passwd|pwd|secret|api[_-]?key|apikey|access[_-]?key|secret[_-]?key|client[_-]?secret|auth[_-]?token|token|account[_-]?key|connection[_-]?string|connectionstring|private[_-]?key|credential|passphrase|bearer|webhook|oauth)'
$script:NameKeywordBounded = '(?i)(^|[_\-])(pwd|key|keys|cert|certificate|pat|dsn|sas|sig|signature|signing|privkey)([_\-]|$)'

# Noise key fragments skipped during the broad recursion (huge, no user secrets).
$script:ExcludeKeyFragments = @(
    '\classes', '\wow6432node\classes', '\microsoft\windows\currentversion\installer',
    '\microsoft\windows\currentversion\component based servicing',
    '\microsoft\windows\currentversion\sidebyside',
    '\microsoft\windows nt\currentversion\fonts', '\microsoft\tracing',
    '\microsoft\windows defender', '\microsoft\cryptography\calais',
    '\microsoft\enterprisecertificates', '\microsoft\systemcertificates',
    '\microsoft\windows\currentversion\appx'
)

$script:ConfRank            = @{ 'High' = 3; 'Medium' = 2; 'Low' = 1 }
$script:MinRank             = $script:ConfRank[$MinConfidence]
$script:IncludePlaceholders = [bool]$IncludePlaceholders
$script:AggressiveValueScan = [bool]$AggressiveValueScan
$script:SkipServiceAccounts = [bool]$SkipServiceAccounts
$script:MaxRuntimeMinutes   = $MaxRuntimeMinutes
$script:TimeUp              = $false
$script:StartLocal          = $null

$script:Findings     = @()
$script:KeysScanned  = 0

# ===========================================================================
# Helpers (detection logic mirrors the env-var scanner; CLM-safe).
# ===========================================================================

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

function Test-LooksLikeSecretValue {
    param([string]$Value)
    if ([string]::IsNullOrEmpty($Value)) { return $false }
    if ($Value.Length -lt 20) { return $false }
    if ($Value -match '\s')   { return $false }
    if ($Value -match '[\\/]') { return $false }
    if ($Value -match '^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$') { return $false }
    $hasLower = $Value -cmatch '[a-z]'; $hasUpper = $Value -cmatch '[A-Z]'
    $hasDigit = $Value -match '[0-9]';  $hasSpec  = $Value -match '[^A-Za-z0-9]'
    $classes = 0
    if ($hasLower) { $classes++ }; if ($hasUpper) { $classes++ }
    if ($hasDigit) { $classes++ }; if ($hasSpec) { $classes++ }
    if ($classes -lt 2) { return $false }
    if (-not ($hasDigit -and ($hasLower -or $hasUpper))) { return $false }
    $seen = @{}
    foreach ($ch in $Value.ToCharArray()) { $seen[$ch] = $true }
    if ($seen.Keys.Count -lt 10) { return $false }
    return $true
}

function Resolve-UserScopeName {
    param([string]$Sid)
    try {
        $pp = Get-ItemProperty -LiteralPath ('HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\' + $Sid) -Name 'ProfileImagePath' -ErrorAction Stop
        $path = [string]$pp.ProfileImagePath
        if (-not [string]::IsNullOrEmpty($path)) { return (Split-Path -Leaf $path) }
    }
    catch { $null = $_ }
    switch ($Sid) {
        'S-1-5-18' { return 'SYSTEM' }
        'S-1-5-19' { return 'LocalService' }
        'S-1-5-20' { return 'NetworkService' }
    }
    return $Sid
}

function Get-LoadedUserSid {
    $sids = @()
    $hives = @()
    try { $hives = @(Get-ChildItem -LiteralPath 'Registry::HKEY_USERS' -ErrorAction SilentlyContinue) } catch { $hives = @() }
    foreach ($k in $hives) {
        $sid = $k.PSChildName
        if ($sid -like '*_Classes') { continue }
        if ($sid -notlike 'S-1-*') { continue }
        if ($script:SkipServiceAccounts -and ($sid -eq 'S-1-5-18' -or $sid -eq 'S-1-5-19' -or $sid -eq 'S-1-5-20')) { continue }
        $sids += $sid
    }
    return $sids
}

function Format-RegPath {
    param([string]$Path)
    $d = $Path -replace '^.*Registry::', ''
    $d = $d -replace '^HKEY_LOCAL_MACHINE', 'HKLM'
    $d = $d -replace '^HKEY_USERS', 'HKU'
    $d = $d -replace '^HKEY_CURRENT_USER', 'HKCU'
    $d = $d -replace '^HKEY_CURRENT_CONFIG', 'HKCC'
    return $d
}

function Test-ExcludeKey {
    param([string]$Path)
    $lower = $Path.ToLowerInvariant()
    foreach ($x in $script:ExcludeKeyFragments) { if ($lower.Contains($x)) { return $true } }
    return $false
}

function Add-ValueFinding {
    # Apply the same A/B/C detection passes the env scanner uses to one
    # (scope, key, value-name, value-data) tuple; append at most one finding.
    param([string]$Scope, [string]$KeyPath, [string]$Name, [string]$Value)
    if ([string]::IsNullOrEmpty($Value)) { return }
    $loc = (Format-RegPath -Path $KeyPath) + '\' + $Name
    $hit = $null

    foreach ($rule in $script:Rules) {
        if ($rule.CaseSensitive) { $isMatch = $Value -cmatch $rule.Pattern } else { $isMatch = $Value -match $rule.Pattern }
        if (-not $isMatch) { continue }
        if ($script:ConfRank[$rule.Confidence] -lt $script:MinRank) { continue }
        $hit = @{ Confidence = $rule.Confidence; RuleId = $rule.Id; Scope = $Scope; Loc = $loc; Length = ([string]$matches[0]).Length }
        break
    }

    if (-not $hit -and (($Name -match $script:NameKeywordPattern) -or ($Name -match $script:NameKeywordBounded))) {
        $isPh = $false
        if (-not $script:IncludePlaceholders) { $isPh = Test-IsPlaceholder -Value $Value }
        if ((-not $isPh) -and ($Value.Length -ge 4) -and ($script:ConfRank['Medium'] -ge $script:MinRank)) {
            $hit = @{ Confidence = 'Medium'; RuleId = 'REG_NAMED_SECRET'; Scope = $Scope; Loc = $loc; Length = $Value.Length }
        }
    }

    if (-not $hit -and $script:AggressiveValueScan) {
        $isPh = $false
        if (-not $script:IncludePlaceholders) { $isPh = Test-IsPlaceholder -Value $Value }
        if ((-not $isPh) -and ($script:ConfRank['Medium'] -ge $script:MinRank) -and (Test-LooksLikeSecretValue -Value $Value)) {
            $hit = @{ Confidence = 'Medium'; RuleId = 'REG_HIGH_ENTROPY'; Scope = $Scope; Loc = $loc; Length = $Value.Length }
        }
    }

    if ($hit) { $script:Findings += $hit }
}

function Get-RegStringValue {
    # Return the value as a scannable string, or $null for non-text (binary etc.).
    param($Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [string])   { return $Value }
    if ($Value -is [string[]]) { return ($Value -join ' ') }
    return $null
}

function Invoke-TargetedCheck {
    # High-signal credential keys, checked explicitly. Always runs first.
    $checks = @()
    # Machine, direct values.
    $checks += @{ Scope = 'HKLM'; Path = 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'; Values = @('DefaultPassword'); RuleId = 'REG_AUTOLOGON_PW'; Sessions = $false }
    $checks += @{ Scope = 'HKLM'; Path = 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\RealVNC\vncserver';   Values = @('Password'); RuleId = 'REG_VNC_PW'; Sessions = $false }
    $checks += @{ Scope = 'HKLM'; Path = 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\TightVNC\Server';     Values = @('Password', 'PasswordViewOnly', 'ControlPassword'); RuleId = 'REG_VNC_PW'; Sessions = $false }
    $checks += @{ Scope = 'HKLM'; Path = 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\ORL\WinVNC3';         Values = @('Password'); RuleId = 'REG_VNC_PW'; Sessions = $false }

    # Per-user, session containers (enumerate subkeys, check listed value names).
    $userTemplates = @(
        @{ Sub = 'Software\SimonTatham\PuTTY\Sessions'; Values = @('ProxyPassword'); RuleId = 'REG_PUTTY_PW' }
        @{ Sub = 'Software\Martin Prikryl\WinSCP 2\Sessions'; Values = @('Password', 'ProxyPassword'); RuleId = 'REG_WINSCP_PW' }
    )
    foreach ($sid in (Get-LoadedUserSid)) {
        $friendly = 'User:' + (Resolve-UserScopeName -Sid $sid)
        foreach ($t in $userTemplates) {
            $checks += @{ Scope = $friendly; Path = ('Registry::HKEY_USERS\' + $sid + '\' + $t.Sub); Values = $t.Values; RuleId = $t.RuleId; Sessions = $true }
        }
    }

    foreach ($c in $checks) {
        if (-not (Test-Path -LiteralPath $c.Path -ErrorAction SilentlyContinue)) { continue }
        $keys = @()
        if ($c.Sessions) {
            try { $keys = @(Get-ChildItem -LiteralPath $c.Path -ErrorAction Stop) } catch { $keys = @() }
        }
        else {
            $keys = @(@{ PSPath = $c.Path })   # treat the key itself as the single target
        }
        foreach ($k in $keys) {
            $kpath = $k.PSPath
            $script:KeysScanned++
            $ip = $null
            try { $ip = Get-ItemProperty -LiteralPath $kpath -ErrorAction Stop } catch { continue }
            foreach ($vn in $c.Values) {
                $prop = $ip.PSObject.Properties[$vn]
                if (-not $prop) { continue }
                $raw = $prop.Value
                if ($null -eq $raw) { continue }
                $len = 0
                try { $len = [int]$raw.Length } catch { $len = 0 }
                if ($len -le 0) { continue }
                if ($script:ConfRank['High'] -lt $script:MinRank) { continue }
                $script:Findings += @{ Confidence = 'High'; RuleId = $c.RuleId; Scope = $c.Scope; Loc = ((Format-RegPath -Path $kpath) + '\' + $vn); Length = $len }
            }
        }
    }
}

function Invoke-KeyScan {
    # Recurse a registry subtree, scanning string value data + value names.
    param([string]$RegPath, [string]$Scope)
    if ($script:TimeUp) { return }
    if (Test-TimeUp) { $script:TimeUp = $true; return }
    if (Test-ExcludeKey -Path $RegPath) { return }

    $ip = $null
    try { $ip = Get-ItemProperty -LiteralPath $RegPath -ErrorAction Stop } catch { $ip = $null }
    if ($ip) {
        $script:KeysScanned++
        foreach ($prop in $ip.PSObject.Properties) {
            $pn = $prop.Name
            if ($pn -like 'PS*') { continue }
            $sv = Get-RegStringValue -Value $prop.Value
            if ($null -eq $sv) { continue }
            Add-ValueFinding -Scope $Scope -KeyPath $RegPath -Name $pn -Value $sv
        }
    }

    $subs = $null
    try { $subs = @(Get-ChildItem -LiteralPath $RegPath -ErrorAction Stop) } catch { $subs = @() }
    foreach ($sk in $subs) {
        if ($script:TimeUp) { return }
        Invoke-KeyScan -RegPath $sk.PSPath -Scope $Scope
    }
}

# ===========================================================================
# Main -- targeted checks, then (optional) broad scan; emit ONE summary line.
# ===========================================================================

$script:StartLocal = Get-Date

$err = $null
try {
    Invoke-TargetedCheck

    if (-not $SkipBroadScan) {
        $roots = @()
        if ($ScanRoots -and $ScanRoots.Count -gt 0) {
            foreach ($r in $ScanRoots) { $roots += @{ Scope = 'Custom'; Path = $r } }
        }
        else {
            $roots += @{ Scope = 'HKLM'; Path = 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE' }
            foreach ($sid in (Get-LoadedUserSid)) {
                $roots += @{ Scope = ('User:' + (Resolve-UserScopeName -Sid $sid)); Path = ('Registry::HKEY_USERS\' + $sid + '\SOFTWARE') }
            }
        }
        foreach ($root in $roots) {
            if ($script:TimeUp) { break }
            if (-not (Test-Path -LiteralPath $root.Path -ErrorAction SilentlyContinue)) { continue }
            Invoke-KeyScan -RegPath $root.Path -Scope $root.Scope
        }
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
    Write-Output ("STATUS=CLEAN | host={0} ver={1} n=0 keys={2} trunc={3} rev={4}" -f $env:COMPUTERNAME, $ScriptVersion, $script:KeysScanned, $trunc, $RulesRev)
    exit 0
}

$high = @($findings | Where-Object { $_.Confidence -eq 'High' }).Count
$med  = @($findings | Where-Object { $_.Confidence -eq 'Medium' }).Count
$low  = @($findings | Where-Object { $_.Confidence -eq 'Low' }).Count

# Single line (Intune surfaces only the last stdout line). Findings inline,
# High -> Medium -> Low, capped under ~2 KB with a (+N more) overflow note.
$head = "STATUS=FOUND | host={0} ver={1} n={2} high={3} med={4} low={5} keys={6} trunc={7} rev={8}" -f `
    $env:COMPUTERNAME, $ScriptVersion, $n, $high, $med, $low, $script:KeysScanned, $trunc, $RulesRev
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
        $item = "{0} {1} {2}::{3}({4})" -f $tag[$conf], $f.RuleId, $f.Scope, $f.Loc, $f.Length
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

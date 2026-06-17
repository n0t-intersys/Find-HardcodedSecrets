<#
.SYNOPSIS
    Read-only Live Response scan of ENVIRONMENT VARIABLES (registry-backed) for
    hardcoded secrets. Reports only the variable name + scope + value length --
    never the value. Fast: completes in seconds (no file-system traversal).

.DESCRIPTION
    One of a suite of focused, single-purpose Find-*Secrets.ps1 scripts split out
    of Find-HardcodedSecrets.ps1 so each runs well under the Live Response session
    time cap. This one scans ONLY environment variables, which live in the
    registry, not the file system:
      * System scope          : HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment
      * Each loaded user hive : HKU\<SID>\Environment (incl. Azure AD / Entra ID
                                S-1-12-1-... SIDs)
    Detection per variable: provider-format rules against the VALUE (High), plus a
    secret-keyword match on the NAME (Medium). With -AggressiveValueScan it also
    flags high-entropy-looking values regardless of name.

    Runs as the bare, arg-less Live Response 'run' command (sensible defaults).
    Windows PowerShell 5.1; tolerant of Constrained Language Mode (built-in
    cmdlets + core types only). To read another user's loaded hive you must run
    as SYSTEM/admin (Live Response context) while that user is logged on; offline
    (logged-off) hives are never mounted (that would require a registry write).

.PARAMETER MinConfidence
    Minimum confidence to report: High, Medium or Low. Default: Medium.

.PARAMETER IncludePlaceholders
    Switch. Disable placeholder/reference filtering (e.g. ${VAR}, changeme).

.PARAMETER AggressiveValueScan
    Switch (off by default). Also flag high-entropy-looking values whose variable
    name has no secret keyword and whose value is not a known provider format.
    Noisier; skips paths, GUIDs, short/low-diversity values. Never emits values.

.PARAMETER SkipServiceAccounts
    Switch (off by default). Skip the built-in service-account hives
    (S-1-5-18 SYSTEM, S-1-5-19 LocalService, S-1-5-20 NetworkService), which
    rarely hold operator-planted secrets. Off by default so the zero-arg run
    still covers them exactly as before.

.EXAMPLE
    Live Response (zero arguments):
        run Find-EnvVarSecrets.ps1

.NOTES
    Safety: read-only; writes nothing to the endpoint (stdout only); never prints
    a secret value (only labels/confidence/scope/name/length); no network.
    Version : 1.1.1
    Author  : DFIR
#>

#requires -Version 5.1

[CmdletBinding()]
param(
    [ValidateSet('High', 'Medium', 'Low')]
    [string]$MinConfidence = 'Medium',

    [switch]$IncludePlaceholders,

    [switch]$AggressiveValueScan,

    [switch]$SkipServiceAccounts
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ScriptVersion = '1.1.1'
# Detection-rule generation shared across the Find-*Secrets.ps1 suite. The rule
# table, placeholder list and (file scanners) TriggerPattern are duplicated per
# script because Live Response forbids shared modules; bump this in ALL of them
# whenever those change, so an analyst can confirm they carry the same generation.
# Canonical source: Find-HardcodedSecrets.ps1.
$RulesRev = '2'

# --- Structured provider-format rules, matched against the variable VALUE.
#     Hashtables (not [pscustomobject]) for Constrained Language Mode safety.
#     CaseSensitive -> matched with -cmatch (preserve provider casing). ---
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

# Placeholder / reference values to ignore (matched against the value only).
$script:PlaceholderPatterns = @(
    'your[-_ ]?', 'changeme', 'example', 'x{4,}', '\*{3,}', '<[^>]+>',
    '\$\{[^}]+\}', '%[^%]+%', '\{\{[^}]+\}\}', '\$\([^)]+\)', '#\{[^}]+\}'
)

# Secret-keyword matching on the variable NAME. Distinctive keywords as plain
# substrings; short/ambiguous ones only as delimited tokens (so 'key'/'pat' do
# not hit PATH/MONKEY/KEYBOARD).
$script:EnvNameKeywordPattern = '(?i)(password|passwd|pwd|secret|api[_-]?key|apikey|access[_-]?key|secret[_-]?key|client[_-]?secret|auth[_-]?token|token|account[_-]?key|connection[_-]?string|connectionstring|private[_-]?key|credential|passphrase|bearer|webhook|oauth)'
$script:EnvNameKeywordBounded = '(?i)(^|[_\-])(pwd|key|keys|cert|certificate|pat|dsn|sas|sig|signature|signing|privkey)([_\-]|$)'

$script:ConfRank = @{ 'High' = 3; 'Medium' = 2; 'Low' = 1 }
$script:MinRank  = $script:ConfRank[$MinConfidence]
$script:IncludePlaceholders = [bool]$IncludePlaceholders
$script:AggressiveValueScan = [bool]$AggressiveValueScan
$script:SkipServiceAccounts = [bool]$SkipServiceAccounts

$script:Stats = @{
    EnvScopesScanned    = 0
    EnvVarsScanned      = 0
    EnvVarsWithFindings = 0
    TotalFindings       = 0
    ScopeErrors         = 0
    ByConfidence        = @{}
    ByRule              = @{}
}

# ===========================================================================
# Helpers
# ===========================================================================

function Add-Count {
    param($Hash, $Key)
    if ($Hash.ContainsKey($Key)) { $Hash[$Key] = $Hash[$Key] + 1 } else { $Hash[$Key] = 1 }
}

function Test-IsPlaceholder {
    param([string]$Value)
    if ([string]::IsNullOrEmpty($Value)) { return $true }
    foreach ($p in $script:PlaceholderPatterns) { if ($Value -match $p) { return $true } }
    return $false
}

function Test-LooksLikeSecretValue {
    # CLM-safe heuristic (no entropy maths): "looks like" a random secret.
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
    catch { $null = $_ }   # best-effort: fall through to well-known SIDs / raw SID
    switch ($Sid) {
        'S-1-5-18' { return 'SYSTEM' }
        'S-1-5-19' { return 'LocalService' }
        'S-1-5-20' { return 'NetworkService' }
    }
    return $Sid
}

function Get-EnvScope {
    $scopes = @()
    $scopes += @{ Friendly = 'System'; RegPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment'; Display = 'HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment' }
    $hives = @()
    try { $hives = @(Get-ChildItem -LiteralPath 'Registry::HKEY_USERS' -ErrorAction SilentlyContinue) } catch { $hives = @() }
    foreach ($k in $hives) {
        try {
            $sid = $k.PSChildName
            if ($sid -like '*_Classes') { continue }
            if ($sid -notlike 'S-1-*') { continue }   # local/domain + Azure AD (S-1-12-1-...)
            if ($script:SkipServiceAccounts -and ($sid -eq 'S-1-5-18' -or $sid -eq 'S-1-5-19' -or $sid -eq 'S-1-5-20')) { continue }
            $envPath = 'Registry::HKEY_USERS\' + $sid + '\Environment'
            if (-not (Test-Path -LiteralPath $envPath -ErrorAction SilentlyContinue)) { continue }
            $scopes += @{ Friendly = 'User:' + (Resolve-UserScopeName -Sid $sid); RegPath = $envPath; Display = 'HKU\' + $sid + '\Environment' }
        }
        catch { $script:Stats.ScopeErrors++; continue }
    }
    return $scopes
}

function Write-Meta        { param([string]$Message) Write-Output "META | $Message" }
function Write-ErrLine     { param([string]$Message) Write-Output "ERROR | $Message" }
function Write-FindingLine {
    param([string]$Confidence, [string]$RuleId, [string]$Label, [int]$Length, [string]$Path)
    Write-Output "FINDING | $Confidence | $RuleId | $Label | line=0 | len=$Length | $Path"
}

function Invoke-EnvScan {
    $scopes = Get-EnvScope
    foreach ($s in $scopes) {
        $script:Stats.EnvScopesScanned++
        Write-Meta ("env-scope | {0} | {1}" -f $s.Friendly, $s.Display)
        $ip = $null
        try { $ip = Get-ItemProperty -LiteralPath $s.RegPath -ErrorAction Stop }
        catch { $script:Stats.ScopeErrors++; Write-ErrLine ("env-scope-read | {0}" -f $s.Display); continue }

        foreach ($prop in $ip.PSObject.Properties) {
            $vname = $prop.Name
            if ($vname -like 'PS*') { continue }
            $script:Stats.EnvVarsScanned++
            $vval = ''
            if ($null -ne $prop.Value) { $vval = [string]$prop.Value }
            if ([string]::IsNullOrEmpty($vval)) { continue }

            $varFindings = @()
            $seen = @{}

            # Pass A: provider-format rules on the VALUE (per-rule confidence,
            # matching the reference scanner -- TWILIO_AC / MAILGUN_KEY are Medium).
            foreach ($rule in $script:Rules) {
                if ($rule.CaseSensitive) { $isMatch = $vval -cmatch $rule.Pattern } else { $isMatch = $vval -match $rule.Pattern }
                if (-not $isMatch) { continue }
                $matchLen = ([string]$matches[0]).Length   # capture while $matches is fresh for this rule
                if ($seen.ContainsKey($rule.Id)) { continue }
                if ($script:ConfRank[$rule.Confidence] -lt $script:MinRank) { continue }
                $seen[$rule.Id] = $true
                $varFindings += @{ RuleId = $rule.Id; Label = $rule.Label; Confidence = $rule.Confidence; Length = $matchLen }
            }

            # Pass B: secret-like NAME + non-placeholder value -> Medium.
            if (($vname -match $script:EnvNameKeywordPattern) -or ($vname -match $script:EnvNameKeywordBounded)) {
                $isPh = $false
                if (-not $script:IncludePlaceholders) { $isPh = Test-IsPlaceholder -Value $vval }
                if ((-not $isPh) -and ($vval.Length -ge 4) -and ($script:ConfRank['Medium'] -ge $script:MinRank)) {
                    if (-not $seen.ContainsKey('ENV_NAMED_SECRET')) {
                        $seen['ENV_NAMED_SECRET'] = $true
                        $varFindings += @{ RuleId = 'ENV_NAMED_SECRET'; Label = 'Secret-like environment variable'; Confidence = 'Medium'; Length = $vval.Length }
                    }
                }
            }

            # Pass C (opt-in): high-entropy value regardless of name.
            if ($script:AggressiveValueScan -and ($varFindings.Count -eq 0)) {
                $isPh = $false
                if (-not $script:IncludePlaceholders) { $isPh = Test-IsPlaceholder -Value $vval }
                if ((-not $isPh) -and ($script:ConfRank['Medium'] -ge $script:MinRank) -and (Test-LooksLikeSecretValue -Value $vval)) {
                    $varFindings += @{ RuleId = 'ENV_HIGH_ENTROPY'; Label = 'High-entropy environment value (aggressive)'; Confidence = 'Medium'; Length = $vval.Length }
                }
            }

            if ($varFindings.Count -eq 0) { continue }
            $script:Stats.EnvVarsWithFindings++
            $loc = 'ENV:' + $s.Friendly + '::' + $vname
            foreach ($f in $varFindings) {
                Write-FindingLine -Confidence $f.Confidence -RuleId $f.RuleId -Label $f.Label -Length $f.Length -Path $loc
                $script:Stats.TotalFindings++
                Add-Count $script:Stats.ByConfidence $f.Confidence
                Add-Count $script:Stats.ByRule $f.Label
            }
        }
    }
}

function Write-Summary {
    param([double]$ElapsedSeconds)
    $s = $script:Stats
    Write-Output ("SUMMARY | envScopes={0} | envVars={1} | envVarsWithFindings={2} | scopeErrors={3} | totalFindings={4} | elapsedSec={5}" -f `
        $s.EnvScopesScanned, $s.EnvVarsScanned, $s.EnvVarsWithFindings, $s.ScopeErrors, $s.TotalFindings, ([int]$ElapsedSeconds))
    foreach ($k in ($s.ByConfidence.Keys | Sort-Object)) { Write-Output ("SUMMARY | byConfidence | {0}={1}" -f $k, $s.ByConfidence[$k]) }
    foreach ($k in ($s.ByRule.Keys | Sort-Object)) { Write-Output ("SUMMARY | byRule | {0}={1}" -f $k, $s.ByRule[$k]) }
    Write-Output ''
    Write-Output '==================== Find-EnvVarSecrets summary ===================='
    Write-Output ("  Host                 : {0}" -f $env:COMPUTERNAME)
    Write-Output ("  Env scopes scanned   : {0}" -f $s.EnvScopesScanned)
    Write-Output ("  Env variables scanned: {0}" -f $s.EnvVarsScanned)
    Write-Output ("  Env vars w/ findings : {0}" -f $s.EnvVarsWithFindings)
    Write-Output ("  Total findings       : {0}" -f $s.TotalFindings)
    Write-Output ("  Elapsed (seconds)    : {0}" -f ([int]$ElapsedSeconds))
    Write-Output '===================================================================='
}

# ===========================================================================
# Main
# ===========================================================================

$startLocal = Get-Date
$startUtc = $startLocal.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
$langMode = $ExecutionContext.SessionState.LanguageMode

try {
    Write-Meta ("script=Find-EnvVarSecrets.ps1 version={0} rulesRev={1} host={2} startUtc={3} langMode={4}" -f $ScriptVersion, $RulesRev, $env:COMPUTERNAME, $startUtc, $langMode)
    Write-Meta ("params | minConfidence={0} includePlaceholders={1} aggressiveValueScan={2} skipServiceAccounts={3} rules={4}" -f $MinConfidence, $script:IncludePlaceholders, $script:AggressiveValueScan, $script:SkipServiceAccounts, $script:Rules.Count)
    Invoke-EnvScan
}
catch {
    Write-ErrLine ("fatal | {0}" -f $_.Exception.Message)
}
finally {
    $elapsed = ((Get-Date) - $startLocal).TotalSeconds
    Write-Summary -ElapsedSeconds $elapsed
}

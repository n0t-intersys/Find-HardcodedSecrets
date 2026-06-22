<#
.SYNOPSIS
    Microsoft Intune REMEDIATION DETECTION script. Read-only scan of environment
    variables (registry) for hardcoded secrets. Exits 1 when secrets are found
    (so the device is flagged "issue detected"), 0 when clean. Emits a compact,
    summary-first report sized to survive Intune's ~2 KB detection-output cap.

.DESCRIPTION
    Intune use: Devices -> Scripts and remediations -> create a remediation, use
    THIS as the detection script (no remediation script needed for hunting).
    Recommended settings: Run as SYSTEM (account = System), 64-bit, signature
    check off. Intune passes no arguments, so the defaults are the operative
    config; the "Pre-remediation detection output" column shows this script's
    stdout (truncated to ~2 KB), hence the summary-first / compact format.

    Detection logic is identical to Find-EnvVarSecrets.ps1 (same rule table /
    confidences); the drift guard tools\Test-SuiteConsistency.ps1 keeps them in
    sync. Read-only; registry only; Windows PowerShell 5.1; tolerant of
    Constrained Language Mode; never emits a secret VALUE (only scope + variable
    name + length).

    Output is a SINGLE line (Intune Remediations surfaces only the last stdout
    line as the detection output, so the whole report -- verdict, counts, and
    findings inline -- is packed onto one line, capped under ~2 KB):
      STATUS=FOUND | host=<h> ver=<v> n=<n> high=<a> med=<b> low=<c> scopes=<s> rev=<r> :: HIGH <RuleId> <Scope>::<VarName>(<len>) ; MED ... [; (+N more)]
    or  STATUS=CLEAN | host=<h> ver=<v> n=0 scopes=<s> rev=<r>
    or  STATUS=ERROR | host=<h> ver=<v> rev=<r> | msg=<...>   (exit 1, so scan failures surface)

.PARAMETER MinConfidence
    Minimum confidence to report: High, Medium or Low. Default: Medium.

.PARAMETER IncludePlaceholders
    Switch. Disable placeholder/reference filtering (e.g. ${VAR}, changeme).

.PARAMETER AggressiveValueScan
    Switch (off by default). Also flag high-entropy-looking values regardless of
    the variable name. Noisier; for a fleet detection leave off.

.PARAMETER SkipServiceAccounts
    Switch (off by default). Skip the built-in service-account hives
    (S-1-5-18/19/20).

.EXAMPLE
    Local test:
        powershell -ExecutionPolicy Bypass -File .\Detect-EnvVarSecrets.ps1 ; $LASTEXITCODE

.NOTES
    Safety: read-only; writes nothing; never prints a secret value; no network.
    Exit codes: 0 = clean, 1 = secrets found OR scan error.
    Version : 1.0.1
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
$ScriptVersion = '1.0.1'
# Shared detection-rule generation (see suite note); bump in ALL Find-*Secrets.ps1
# / Detect-*Secrets.ps1 when rules change. Canonical: Find-HardcodedSecrets.ps1.
$RulesRev = '4'

# --- Structured provider-format rules, matched against the variable VALUE
#     (identical to Find-EnvVarSecrets.ps1; kept in sync via the drift guard). ---
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

$script:EnvNameKeywordPattern = '(?i)(password|passwd|pwd|secret|api[_-]?key|apikey|access[_-]?key|secret[_-]?key|client[_-]?secret|auth[_-]?token|token|account[_-]?key|connection[_-]?string|connectionstring|private[_-]?key|credential|passphrase|bearer|webhook|oauth)'
$script:EnvNameKeywordBounded = '(?i)(^|[_\-])(pwd|key|keys|cert|certificate|pat|dsn|sas|sig|signature|signing|privkey)([_\-]|$)'

$script:ConfRank = @{ 'High' = 3; 'Medium' = 2; 'Low' = 1 }
$script:MinRank             = $script:ConfRank[$MinConfidence]
$script:IncludePlaceholders = [bool]$IncludePlaceholders
$script:AggressiveValueScan = [bool]$AggressiveValueScan
$script:SkipServiceAccounts = [bool]$SkipServiceAccounts

$script:EnvScopesScanned = 0
$script:Findings = @()   # collected, then reported summary-first

# ===========================================================================
# Helpers (identical detection logic to Find-EnvVarSecrets.ps1)
# ===========================================================================

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
    $scopes += @{ Friendly = 'System'; RegPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment' }
    $hives = @()
    try { $hives = @(Get-ChildItem -LiteralPath 'Registry::HKEY_USERS' -ErrorAction SilentlyContinue) } catch { $hives = @() }
    foreach ($k in $hives) {
        try {
            $sid = $k.PSChildName
            if ($sid -like '*_Classes') { continue }
            if ($sid -notlike 'S-1-*') { continue }
            if ($script:SkipServiceAccounts -and ($sid -eq 'S-1-5-18' -or $sid -eq 'S-1-5-19' -or $sid -eq 'S-1-5-20')) { continue }
            $envPath = 'Registry::HKEY_USERS\' + $sid + '\Environment'
            if (-not (Test-Path -LiteralPath $envPath -ErrorAction SilentlyContinue)) { continue }
            $scopes += @{ Friendly = 'User:' + (Resolve-UserScopeName -Sid $sid); RegPath = $envPath }
        }
        catch { continue }
    }
    return $scopes
}

function Invoke-EnvScan {
    # Collect findings into $script:Findings (no inline output -- we report
    # summary-first afterwards so the verdict survives Intune's output cap).
    foreach ($s in (Get-EnvScope)) {
        $script:EnvScopesScanned++
        $ip = $null
        try { $ip = Get-ItemProperty -LiteralPath $s.RegPath -ErrorAction Stop } catch { continue }
        foreach ($prop in $ip.PSObject.Properties) {
            $vname = $prop.Name
            if ($vname -like 'PS*') { continue }
            $vval = ''
            if ($null -ne $prop.Value) { $vval = [string]$prop.Value }
            if ([string]::IsNullOrEmpty($vval)) { continue }

            $hit = $null

            # Pass A: structured provider-format rules on the VALUE.
            foreach ($rule in $script:Rules) {
                if ($rule.CaseSensitive) { $isMatch = $vval -cmatch $rule.Pattern } else { $isMatch = $vval -match $rule.Pattern }
                if (-not $isMatch) { continue }
                $matchLen = ([string]$matches[0]).Length
                if ($script:ConfRank[$rule.Confidence] -lt $script:MinRank) { continue }
                $hit = @{ Confidence = $rule.Confidence; RuleId = $rule.Id; Scope = $s.Friendly; Name = $vname; Length = $matchLen }
                break
            }

            # Pass B: secret-like NAME + non-placeholder value -> Medium.
            if (-not $hit -and (($vname -match $script:EnvNameKeywordPattern) -or ($vname -match $script:EnvNameKeywordBounded))) {
                $isPh = $false
                if (-not $script:IncludePlaceholders) { $isPh = Test-IsPlaceholder -Value $vval }
                if ((-not $isPh) -and ($vval.Length -ge 4) -and ($script:ConfRank['Medium'] -ge $script:MinRank)) {
                    $hit = @{ Confidence = 'Medium'; RuleId = 'ENV_NAMED_SECRET'; Scope = $s.Friendly; Name = $vname; Length = $vval.Length }
                }
            }

            # Pass C (opt-in): high-entropy value regardless of name.
            if (-not $hit -and $script:AggressiveValueScan) {
                $isPh = $false
                if (-not $script:IncludePlaceholders) { $isPh = Test-IsPlaceholder -Value $vval }
                if ((-not $isPh) -and ($script:ConfRank['Medium'] -ge $script:MinRank) -and (Test-LooksLikeSecretValue -Value $vval)) {
                    $hit = @{ Confidence = 'Medium'; RuleId = 'ENV_HIGH_ENTROPY'; Scope = $s.Friendly; Name = $vname; Length = $vval.Length }
                }
            }

            if ($hit) { $script:Findings += $hit }
        }
    }
}

# ===========================================================================
# Main -- run, then emit summary-first compact output and set exit code.
# ===========================================================================

$err = $null
try { Invoke-EnvScan } catch { $err = $_.Exception.Message }

if ($err) {
    # Surface scan failure (exit 1) rather than silently reporting "clean".
    Write-Output ("STATUS=ERROR | host={0} ver={1} rev={2} | msg={3}" -f $env:COMPUTERNAME, $ScriptVersion, $RulesRev, ($err -replace '\s+', ' '))
    exit 1
}

$findings = @($script:Findings)
$n = $findings.Count
if ($n -eq 0) {
    Write-Output ("STATUS=CLEAN | host={0} ver={1} n=0 scopes={2} rev={3}" -f $env:COMPUTERNAME, $ScriptVersion, $script:EnvScopesScanned, $RulesRev)
    exit 0
}

$high = @($findings | Where-Object { $_.Confidence -eq 'High' }).Count
$med  = @($findings | Where-Object { $_.Confidence -eq 'Medium' }).Count
$low  = @($findings | Where-Object { $_.Confidence -eq 'Low' }).Count

# Intune Remediations surface only the LAST stdout line as the detection output,
# so emit the ENTIRE report on ONE line: verdict + counts, then the findings
# inline (High -> Medium -> Low), capped under ~2 KB with a (+N more) overflow
# note. One line also survives whatever the agent captures (first/last/all).
$head = "STATUS=FOUND | host={0} ver={1} n={2} high={3} med={4} low={5} scopes={6} rev={7}" -f `
    $env:COMPUTERNAME, $ScriptVersion, $n, $high, $med, $low, $script:EnvScopesScanned, $RulesRev
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
        $item = "{0} {1} {2}::{3}({4})" -f $tag[$conf], $f.RuleId, $f.Scope, $f.Name, $f.Length
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

<#
.SYNOPSIS
    Read-only Live Response scan of SERVER / WEB / FRAMEWORK config locations,
    finding hardcoded secrets in .env / .config files. Reports location only --
    never the value. Scoped to a handful of high-value directories so it finishes
    well under the Live Response session cap.

.DESCRIPTION
    One of a suite of focused Find-*Secrets.ps1 scripts split out of the full
    Find-HardcodedSecrets.ps1 so each runs fast. This one scans only the common
    server/web/framework configuration locations, where IIS site web.config,
    applicationHost.config, framework machine.config, and service app configs
    live:
      * C:\inetpub                              (IIS site web.config)
      * C:\Windows\System32\inetsrv\config      (applicationHost.config)
      * C:\Windows\Microsoft.NET\Framework      (machine.config / root web.config)
      * C:\Windows\Microsoft.NET\Framework64    (machine.config / root web.config)
      * C:\ProgramData                          (service / app configs)

    Targets (case-insensitive): *.env, .env.* and *.config. Same detection rules
    and forensic guarantees as the full scanner. Read-only; Windows PowerShell
    5.1; tolerant of Constrained Language Mode. Skips reparse points and
    cloud/offline placeholders. Runs as the bare, arg-less 'run' command.

.PARAMETER Roots
    One or more directories to scan. Default: the IIS / .NET Framework Config /
    ProgramData locations above. Override to target a single IIS site or a
    mounted evidence path -- the default keeps the zero-arg 'run' identical.

.PARAMETER MinConfidence
    Minimum confidence to report: High, Medium or Low. Default: Medium.

.PARAMETER MaxFileSizeMB
    Skip candidate files larger than this many megabytes. Default: 10. Raise it
    to scan a large machine.config / applicationHost.config that exceeds it.

.PARAMETER MaxRuntimeMinutes
    File-scan time budget in minutes. Default: 10 (scope is bounded). 0 = unlimited.

.PARAMETER ExcludePaths
    Case-insensitive path fragments to skip during traversal. Default: a small
    ProgramData noise list (Windows Defender, Package Cache, WER).

.PARAMETER IncludePlaceholders
    Switch. Disable placeholder/reference filtering (e.g. ${VAR}, changeme).

.EXAMPLE
    Live Response (zero arguments):
        run Find-ServerConfigSecrets.ps1

.EXAMPLE
    Target a single IIS site (where args are usable):
        runscript -scriptName Find-ServerConfigSecrets.ps1 -args "-Roots C:\inetpub\wwwroot\app1"

.NOTES
    Safety: read-only; writes nothing (stdout only); never prints a secret value
    (labels/confidence/line/path/sha256/length only); no network.
    Version : 1.1.1
    Author  : DFIR
#>

#requires -Version 5.1

[CmdletBinding()]
param(
    [string[]]$Roots = @(
        'C:\inetpub',
        'C:\Windows\System32\inetsrv\config',
        'C:\Windows\Microsoft.NET\Framework',
        'C:\Windows\Microsoft.NET\Framework64',
        'C:\ProgramData'
    ),

    [ValidateSet('High', 'Medium', 'Low')]
    [string]$MinConfidence = 'Medium',

    [int]$MaxFileSizeMB = 10,

    [int]$MaxRuntimeMinutes = 10,

    [string[]]$ExcludePaths = @(
        '\ProgramData\Microsoft\Windows Defender',
        '\ProgramData\Package Cache',
        '\ProgramData\Microsoft\Windows\WER'
    ),

    [switch]$IncludePlaceholders
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ScriptVersion = '1.1.1'
# Shared detection-rule generation (see suite note); bump in ALL Find-*Secrets.ps1
# when rules/TriggerPattern/placeholders change. Canonical: Find-HardcodedSecrets.ps1.
$RulesRev = '3'

# ---- Scope: defaults below; override with -Roots for a single IIS site etc. ----
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
    @{ Id = 'GEN_PASSWORD';     Label = 'Password assignment';                 Pattern = '(password|passwd|passphrase|pwd)["'']?\s*[:=]\s*["'']?(?<val>[^"''\s,;>]{4,})';  CaseSensitive = $false; Confidence = 'Medium'; Type = 'Contextual' }
    @{ Id = 'GEN_SECRET';       Label = 'Secret/token/key assignment';         Pattern = '(api[_-]?key|access[_-]?key|secret[_-]?key|session[_-]?key|client[_-]?secret|app[_-]?secret|consumer[_-]?secret|secret|access[_-]?token|refresh[_-]?token|id[_-]?token|auth[_-]?token|private[_-]?token|token)["'']?\s*[:=]\s*["'']?(?<val>[^"''\s,;>]{8,})'; CaseSensitive = $false; Confidence = 'Medium'; Type = 'Contextual' }
    @{ Id = 'CONN_STRING';      Label = 'Connection string with credentials';  Pattern = '(connectionstring\s*=|<add[^>]+connectionstring\s*=)[^>]*\b(password|pwd)\s*=\s*(?<val>[^;"''>\s]+)'; CaseSensitive = $false; Confidence = 'Medium'; Type = 'Contextual' }
    # --- Additional provider formats + structural rules (rev 3) ---
    @{ Id = 'SHOPIFY_TOKEN';    Label = 'Shopify access token';                Pattern = '\b(shpat_|shpss_|shppa_|shpca_)[A-Za-z0-9]{32,}\b';            CaseSensitive = $true;  Confidence = 'High';   Type = 'Structured' }
    @{ Id = 'DIGITALOCEAN_PAT'; Label = 'DigitalOcean token';                  Pattern = '\b(dop|doo|dor)_v1_[a-f0-9]{64}\b';                            CaseSensitive = $true;  Confidence = 'High';   Type = 'Structured' }
    @{ Id = 'DOPPLER_TOKEN';    Label = 'Doppler token';                       Pattern = '\bdp\.(pt|st|ct|scim|audit|sa)\.[A-Za-z0-9]{40,44}\b';         CaseSensitive = $true;  Confidence = 'High';   Type = 'Structured' }
    @{ Id = 'DATABRICKS_PAT';   Label = 'Databricks PAT';                      Pattern = '\bdapi[a-f0-9]{32}(-\d+)?\b';                                  CaseSensitive = $true;  Confidence = 'High';   Type = 'Structured' }
    @{ Id = 'GRAFANA_TOKEN';    Label = 'Grafana service-account token';       Pattern = '\bglsa_[A-Za-z0-9]{32}_[A-Fa-f0-9]{8}\b';                     CaseSensitive = $true;  Confidence = 'High';   Type = 'Structured' }
    @{ Id = 'POSTMAN_KEY';      Label = 'Postman API key';                     Pattern = '\bPMAK-[A-Fa-f0-9]{24}-[A-Fa-f0-9]{34}\b';                    CaseSensitive = $true;  Confidence = 'High';   Type = 'Structured' }
    @{ Id = 'FIGMA_TOKEN';      Label = 'Figma personal access token';         Pattern = '\bfigd_[A-Za-z0-9_-]{40,}\b';                                  CaseSensitive = $true;  Confidence = 'High';   Type = 'Structured' }
    @{ Id = 'LINEAR_KEY';       Label = 'Linear API key';                      Pattern = '\blin_api_[A-Za-z0-9]{40,}\b';                                 CaseSensitive = $true;  Confidence = 'High';   Type = 'Structured' }
    @{ Id = 'SENTRY_TOKEN';     Label = 'Sentry auth token';                   Pattern = '\bsntry[su]_[A-Za-z0-9._-]{40,}\b';                            CaseSensitive = $true;  Confidence = 'High';   Type = 'Structured' }
    @{ Id = 'PYPI_TOKEN';       Label = 'PyPI upload token';                   Pattern = '\bpypi-AgEIcHlwaS[A-Za-z0-9_-]{50,}\b';                        CaseSensitive = $true;  Confidence = 'High';   Type = 'Structured' }
    @{ Id = 'HUGGINGFACE_TOKEN';Label = 'Hugging Face token';                  Pattern = '\bhf_[A-Za-z0-9]{34,}\b';                                      CaseSensitive = $true;  Confidence = 'High';   Type = 'Structured' }
    @{ Id = 'NEWRELIC_KEY';     Label = 'New Relic API key';                   Pattern = '\bNRAK-[A-Z0-9]{27}\b';                                        CaseSensitive = $true;  Confidence = 'High';   Type = 'Structured' }
    @{ Id = 'NOTION_TOKEN';     Label = 'Notion integration token';            Pattern = '\bntn_[A-Za-z0-9]{40,}\b';                                     CaseSensitive = $true;  Confidence = 'High';   Type = 'Structured' }
    @{ Id = 'SQUARE_TOKEN';     Label = 'Square OAuth token';                  Pattern = '\bsq0(atp|csp|idp)-[A-Za-z0-9_-]{22,}\b';                      CaseSensitive = $true;  Confidence = 'High';   Type = 'Structured' }
    @{ Id = 'STRIPE_TEST';      Label = 'Stripe test/restricted key';          Pattern = '\b(sk|rk)_test_[0-9A-Za-z]{20,}\b';                            CaseSensitive = $true;  Confidence = 'Medium'; Type = 'Structured' }
    @{ Id = 'BEARER_TOKEN';     Label = 'Authorization bearer token';          Pattern = '(?i)\bbearer\s+(?<val>[A-Za-z0-9._\-+/=]{16,})';               CaseSensitive = $false; Confidence = 'Medium'; Type = 'Contextual' }
    @{ Id = 'XML_SECRET';       Label = 'XML element secret';                  Pattern = '<(password|passwd|pwd|secret|apikey|api[_-]?key|client[_-]?secret|token|connectionstring|accesskey|privatekey|passphrase)>\s*(?<val>[^<>\s]{4,})\s*</'; CaseSensitive = $false; Confidence = 'Medium'; Type = 'Contextual' }
    @{ Id = 'XML_ADD_KV';       Label = 'XML add key/value secret';            Pattern = '<add\s+key\s*=\s*["''][^"'']*(password|pwd|secret|api[_-]?key|token|connectionstring|accountkey)[^"'']*["'']\s+value\s*=\s*["''](?<val>[^"'']{4,})["'']'; CaseSensitive = $false; Confidence = 'Medium'; Type = 'Contextual' }
)

# Pre-filter gate: strict SUPERSET of every rule trigger; lines with no trigger
# skip the per-rule loop. Broaden (never narrow) when adding rules.
$script:TriggerPattern = '(?i)(password|passwd|passphrase|pwd|secret|api|access|auth|bearer|client|session|private|token|credential|connectionstring|akia|asia|aiza|googleusercontent|xox|gh[pousr]_|glpat-|_live_|_test_|sg\.|begin|eyj|accountkey=|\bsk|npm_|github_pat_|q~|hooks\.slack|\bac[0-9a-f]|key-|shpat_|shpss_|shppa_|shpca_|dop_v1|doo_v1|dor_v1|dp\.|dapi|glsa_|pmak-|figd_|lin_api_|sntry|pypi-|hf_|nrak-|ntn_|sq0|://)'

$script:PlaceholderPatterns = @(
    '\$\{[^}]+\}', '%[^%]+%', '\{\{[^}]+\}\}', '\$\([^)]+\)', '#\{[^}]+\}', '<[^>]+>',
    '\*{3,}', 'x{6,}',
    '^your[-_ ]', '^changeme', '^change-me', '^example', '^sample', '^placeholder',
    '^redacted', '^dummy', '^fakekey', '^test$', '^none$', '^null$', '^todo', '^tbd', '^xxx',
    '^[\*xX._\-]{4,}$', '(.)\1{9,}'
)

# Obvious non-secret values dropped from contextual matches (pure numbers,
# booleans, file paths, integrity-hash prefixes). Real secrets never look like
# these; keyword-anchoring already screens most noise, this trims the rest.
$script:NoiseValuePatterns = @(
    '^\d+$',
    '^(true|false|null|none|nil|n/a|na|yes|no|enabled|disabled|on|off|default|localhost)$',
    '^[A-Za-z]:[\\/]', '^\.{0,2}[\\/]', '^/[A-Za-z0-9._/-]*$',
    '^sha\d{1,3}[-:]'
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

function Test-IsNoiseValue {
    param([string]$Value)
    if ([string]::IsNullOrEmpty($Value)) { return $true }
    foreach ($p in $script:NoiseValuePatterns) { if ($Value -match $p) { return $true } }
    return $false
}

function Test-FileIsBinary {
    # BOM-aware: a NUL byte alone no longer means "binary" -- UTF-16/UTF-32 text
    # (very common on Windows: PowerShell Out-File, exported .config/.xml) is full
    # of NULs but is real text we must scan. Treat known text BOMs and BOM-less
    # UTF-16 (NULs on a single parity) as text; otherwise a NUL means binary.
    param([string]$Path)
    $bytes = Get-Content -LiteralPath $Path -Encoding Byte -TotalCount 8192 -ErrorAction Stop
    if ($null -eq $bytes) { return $false }
    $n = $bytes.Count
    if ($n -eq 0) { return $false }
    if ($n -ge 3 -and $bytes[0] -eq 239 -and $bytes[1] -eq 187 -and $bytes[2] -eq 191) { return $false }
    if ($n -ge 4 -and $bytes[0] -eq 255 -and $bytes[1] -eq 254 -and $bytes[2] -eq 0 -and $bytes[3] -eq 0) { return $false }
    if ($n -ge 4 -and $bytes[0] -eq 0 -and $bytes[1] -eq 0 -and $bytes[2] -eq 254 -and $bytes[3] -eq 255) { return $false }
    if ($n -ge 2 -and $bytes[0] -eq 255 -and $bytes[1] -eq 254) { return $false }
    if ($n -ge 2 -and $bytes[0] -eq 254 -and $bytes[1] -eq 255) { return $false }
    $nul = 0; $nulEven = 0; $nulOdd = 0
    for ($i = 0; $i -lt $n; $i++) {
        if ($bytes[$i] -eq 0) { $nul++; if (($i -band 1) -eq 0) { $nulEven++ } else { $nulOdd++ } }
    }
    if ($nul -eq 0) { return $false }
    if (($nul * 5) -ge ($n * 2) -and ($nulEven -eq 0 -or $nulOdd -eq 0)) { return $false }
    return $true
}

function Get-FileTextKind {
    # Pick an explicit decoder for BOM-less UTF-16; 'bom' lets the reader auto-detect
    # (handles BOM'd UTF-8/16/32 and plain ANSI/UTF-8).
    param([byte[]]$Head, [int]$N)
    if ($N -ge 2 -and $Head[0] -eq 239 -and $Head[1] -eq 187) { return 'bom' }
    if ($N -ge 2 -and $Head[0] -eq 255 -and $Head[1] -eq 254) { return 'bom' }
    if ($N -ge 2 -and $Head[0] -eq 254 -and $Head[1] -eq 255) { return 'bom' }
    $nul = 0; $ev = 0; $od = 0
    for ($i = 0; $i -lt $N; $i++) { if ($Head[$i] -eq 0) { $nul++; if (($i -band 1) -eq 0) { $ev++ } else { $od++ } } }
    if ($nul -gt 0 -and ($nul * 5) -ge ($N * 2)) {
        if ($od -gt 0 -and $ev -eq 0) { return 'utf16le' }
        if ($ev -gt 0 -and $od -eq 0) { return 'utf16be' }
    }
    return 'bom'
}

function Read-FileLine {
    param([string]$Path)
    $kind = 'bom'
    try {
        $head = Get-Content -LiteralPath $Path -Encoding Byte -TotalCount 512 -ErrorAction Stop
        if ($head) { $kind = Get-FileTextKind -Head $head -N $head.Count }
    } catch { $kind = 'bom' }
    if ($script:UseDotNetIO) {
        $fs = $null; $sr = $null
        try {
            $fs = [System.IO.File]::Open($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
            if ($kind -eq 'utf16le') { $enc = New-Object System.Text.UnicodeEncoding($false, $false); $sr = New-Object System.IO.StreamReader -ArgumentList @($fs, $enc, $false) }
            elseif ($kind -eq 'utf16be') { $enc = New-Object System.Text.UnicodeEncoding($true, $false); $sr = New-Object System.IO.StreamReader -ArgumentList @($fs, $enc, $false) }
            else { $sr = New-Object System.IO.StreamReader -ArgumentList @($fs, $true) }
            $text = $sr.ReadToEnd()
        }
        finally { if ($sr) { $sr.Dispose() } elseif ($fs) { $fs.Dispose() } }
        return [string[]]($text -split "`r`n|`n|`r")
    }
    else {
        if ($kind -eq 'utf16le') { return @(Get-Content -LiteralPath $Path -Encoding Unicode -ErrorAction Stop) }
        elseif ($kind -eq 'utf16be') { return @(Get-Content -LiteralPath $Path -Encoding BigEndianUnicode -ErrorAction Stop) }
        else { return @(Get-Content -LiteralPath $Path -ErrorAction Stop) }
    }
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
                if (-not $script:IncludePlaceholders) { if (Test-IsPlaceholder -Value $val) { continue } if (Test-IsNoiseValue -Value $val) { continue } }
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
    Write-Output '==================== Find-ServerConfigSecrets summary ===================='
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
    Write-Output '========================================================================='
}

# ===========================================================================
# Main
# ===========================================================================
$script:StartLocal = Get-Date
$startUtc = $script:StartLocal.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
$langMode = $ExecutionContext.SessionState.LanguageMode
$script:UseDotNetIO = ($langMode -eq 'FullLanguage')

try {
    Write-Meta ("script=Find-ServerConfigSecrets.ps1 version={0} rulesRev={1} host={2} startUtc={3} langMode={4}" -f $ScriptVersion, $RulesRev, $env:COMPUTERNAME, $startUtc, $langMode)
    Write-Meta ("params | minConfidence={0} maxFileSizeMB={1} maxRuntimeMinutes={2} includePlaceholders={3} dotNetIO={4} rules={5}" -f $MinConfidence, $MaxFileSizeMB, $MaxRuntimeMinutes, $script:IncludePlaceholders, $script:UseDotNetIO, $script:Rules.Count)
    Write-Meta ("scanRoots | {0}" -f ($script:ScanRoots -join ', '))
    foreach ($root in $script:ScanRoots) {
        if ($script:TimeUp) { break }
        if (-not (Test-Path -LiteralPath $root -PathType Container)) { Write-Meta ("root-missing | {0}" -f $root); continue }
        Write-Meta ("scan-start | root={0}" -f $root)
        # Capture baselines so the per-root scan-end logs THIS root's contribution
        # (deltas), not the running cumulative totals (multiple roots in this script).
        $dirsBefore = $script:Stats.DirsTraversed
        $findsBefore = $script:Stats.TotalFindings
        Invoke-DirScan -Dir $root
        Write-Meta ("scan-end | root={0} dirsTraversed={1} findings={2}" -f $root, ($script:Stats.DirsTraversed - $dirsBefore), ($script:Stats.TotalFindings - $findsBefore))
        if ($script:TimeUp) { $script:Stats.Truncated = $true; Write-Meta 'file-scan runtime budget exceeded; stopping with partial results'; break }
    }
}
catch { Write-ErrLine ("fatal | {0}" -f $_.Exception.Message) }
finally {
    $elapsed = ((Get-Date) - $script:StartLocal).TotalSeconds
    Write-Summary -ElapsedSeconds $elapsed
}

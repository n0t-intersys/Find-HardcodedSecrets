<#
.SYNOPSIS
    Microsoft Intune REMEDIATION DETECTION script. Read-only scan of SERVER /
    WEB / FRAMEWORK config locations on C: -- IIS (inetpub, applicationHost.config),
    .NET Framework machine/root config, and C:\ProgramData -- for hardcoded
    secrets. Exits 1 when secrets are found (device flagged "issue detected"),
    0 when clean. One compact stdout line. Never prints the secret value.

.DESCRIPTION
    Part of the Intune Detect-*Secrets.ps1 set. The set is split BY LOCATION so
    each remediation finishes well under Intune's ~30-min kill while together
    covering the whole system drive:
      * Detect-EnvVarSecrets.ps1         -- environment variables (registry)
      * Detect-UserProfileSecrets.ps1    -- C:\Users
      * Detect-CredentialFileSecrets.ps1 -- known per-profile credential files
      * Detect-ServerConfigSecrets.ps1   -- THIS: ProgramData + IIS + .NET config
      * Detect-ProgramFilesSecrets.ps1   -- Program Files + custom C: roots
    Scanned here:
      * C:\inetpub                           (IIS site web.config etc.)
      * C:\Windows\System32\inetsrv\config   (applicationHost.config)
      * C:\Windows\Microsoft.NET\Framework   (machine.config / root web.config)
      * C:\Windows\Microsoft.NET\Framework64 (machine.config / root web.config)
      * C:\ProgramData                       (service / app configs)

    Intune use: Devices -> Scripts and remediations -> create a remediation, use
    THIS as the detection script. Recommended settings: Run as SYSTEM, 64-bit,
    signature check off. Intune passes no arguments, so the defaults are the
    operative config; it surfaces only the LAST stdout line, so the whole report
    is on ONE line (verdict + counts + findings inline), capped under ~2 KB.

    Detection rules / TriggerPattern / placeholders are the shared suite set
    (rev 3; kept in sync by tools\Test-SuiteConsistency.ps1). BOM-aware
    (UTF-16/UTF-32 text is scanned, not skipped). Read-only; opens files shared
    read/write; skips reparse points and cloud/offline placeholders; Windows
    PowerShell 5.1; tolerant of Constrained Language Mode.

    Output (single line):
      STATUS=FOUND | host=<h> ver=<v> n=<n> high=<a> med=<b> low=<c> files=<f> scanned=<s> trunc=<0|1> rev=<r> :: HIGH <RuleId> <path>:<line> ; MED ... [; (+N more)]
    or  STATUS=CLEAN | host=<h> ver=<v> n=0 scanned=<s> trunc=<0|1> rev=<r>
    or  STATUS=ERROR | host=<h> ver=<v> rev=<r> | msg=<...>   (exit 1)
    trunc=1 means the time budget was hit -> results are PARTIAL.

.PARAMETER Roots
    Directories to scan. Default: the IIS / .NET Framework / ProgramData
    locations above. (Intune can't pass args; for local testing point elsewhere.)

.PARAMETER MinConfidence
    Minimum confidence to report: High, Medium or Low. Default: Medium.

.PARAMETER MaxFileSizeMB
    Skip candidate files larger than this many megabytes. Default: 10.

.PARAMETER MaxRuntimeMinutes
    Time budget in minutes. Default: 20 (well under Intune's ~30-min kill). On
    exceed, the scan stops, reports partial results, and sets trunc=1.
    0 = unlimited (not recommended for Intune).

.PARAMETER IncludePlaceholders
    Switch. Disable placeholder/reference filtering (e.g. ${VAR}, changeme).

.EXAMPLE
    Local test:
        powershell -ExecutionPolicy Bypass -File .\Detect-ServerConfigSecrets.ps1 ; $LASTEXITCODE

.NOTES
    Safety: read-only; writes nothing; never prints a secret value (path + line
    only); no network. Exit codes: 0 = clean, 1 = secrets found OR scan error.
    Version : 1.0.0
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

    [int]$MaxRuntimeMinutes = 20,

    [string[]]$ExcludePaths = @(
        '\ProgramData\Microsoft\Windows Defender',
        '\ProgramData\Package Cache',
        '\ProgramData\Microsoft\Windows\WER',
        '\node_modules', '\.nuget\packages', '\site-packages', '\__pycache__',
        '\.gradle', '\.cargo', '\.terraform'
    ),

    [switch]$IncludePlaceholders
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ScriptVersion = '1.0.0'
# Shared detection-rule generation (see suite note); bump in ALL
# Find-*Secrets.ps1 / Detect-*Secrets.ps1 when rules / TriggerPattern /
# placeholders change. Canonical: Find-HardcodedSecrets.ps1.
$RulesRev = '3'

# ===========================================================================
# Detection rules (identical to the suite; kept in sync by
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

$script:ScanRoots          = $Roots
$script:ExcludePaths       = @($ExcludePaths | ForEach-Object { $_.ToLowerInvariant() })   # pre-lowered for Test-ExcludeDir

# Candidate selection (broad: secrets live in many file types, not just .config).
# Extensions checked via String.EndsWith (CLM-safe; [System.IO.Path] is CLM-blocked).
$script:CandidateExt = @(
    '.env', '.config', '.json', '.yaml', '.yml', '.ini', '.toml', '.properties',
    '.conf', '.cfg', '.cnf', '.xml', '.ps1', '.psm1', '.psd1', '.bat', '.cmd',
    '.sh', '.py', '.js', '.ts', '.tf', '.tfvars', '.txt', '.pem', '.key',
    '.sql', '.hcl', '.ovpn', '.rdp'
)
$script:CandidateName = @(
    '.git-credentials', '.npmrc', '.netrc', '_netrc', '.pypirc', '.gitconfig',
    'credentials', '.pgpass', '.my.cnf', '.htpasswd', '.dockercfg', '.s3cfg', '.boto'
)

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
# Helpers (mirror the suite; no inline output -- collect only)
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
    if ($n.StartsWith('.env.')) { return $true }                              # .env.local / .env.production / ...
    foreach ($x in $script:CandidateName) { if ($n -eq $x) { return $true } } # exact credential filenames
    foreach ($x in $script:CandidateExt)  { if ($n.EndsWith($x)) { return $true } }
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
                if (-not $script:IncludePlaceholders) { if (Test-IsPlaceholder -Value $val) { continue } if (Test-IsNoiseValue -Value $val) { continue } }
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

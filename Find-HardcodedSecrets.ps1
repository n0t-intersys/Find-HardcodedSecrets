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
    Time budget for the FILE scan, in minutes. Default: 30. When exceeded, the file
    scan stops gracefully, partial results are reported, and the run is flagged
    TRUNCATED in the summary.

    This budget is deliberate: Microsoft Defender Live Response returns a
    command's output only when it COMPLETES, and it terminates long-running
    commands -- an unbounded full-disk scan gets killed by the system and returns
    NOTHING (the dreaded "Command canceled"). A bounded scan finishes and returns
    what it found. The environment-variable scan runs FIRST and is effectively
    instant, so those findings are captured regardless of this budget.

    IMPORTANT: set this BELOW your tenant's Live Response session/command cap. If
    a session is terminated by the system before the budget elapses you get the
    same "Command canceled" with no output. Lower it (e.g. 20) if runs are killed.
    Set 0 for unlimited (only when NOT under a session timeout).

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

.PARAMETER AggressiveValueScan
    Switch (OFF by default). Adds a heuristic that flags environment-variable
    VALUES which "look like" a random secret (length + character diversity +
    mixed classes) even when the variable NAME has no secret keyword and the
    value is not a known provider format -- e.g. BRIVO_KEY=<random>. It skips
    paths, GUIDs, short and low-diversity values, but is deliberately NOISIER
    than the keyword/provider rules (expect more false positives). Reported at
    Medium with rule id ENV_HIGH_ENTROPY. The value is still never emitted.

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

    Version : 1.6.1
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

    [int]$MaxRuntimeMinutes = 30,

    [switch]$IncludePlaceholders,

    [switch]$SkipEnvironment,

    [switch]$AggressiveValueScan
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$ScriptVersion = '1.6.1'
# Detection-rule generation shared across the Find-*Secrets.ps1 suite (this is the
# canonical rule set). Bump in ALL of them whenever the rules / TriggerPattern /
# placeholder list change, so an analyst can confirm they carry the same generation.
$RulesRev = '4'

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

    # -- Additional provider formats (broadened coverage). --
    @{ Id = 'OPENAI_ANTHROPIC'; Label = 'OpenAI/Anthropic API key';        Pattern = '\bsk-(proj-|ant-)?[A-Za-z0-9_-]{20,}\b';                       CaseSensitive = $true;  Confidence = 'High';   Type = 'Structured' }
    @{ Id = 'NPM_TOKEN';        Label = 'npm access token';                Pattern = '\bnpm_[A-Za-z0-9]{36}\b';                                      CaseSensitive = $true;  Confidence = 'High';   Type = 'Structured' }
    @{ Id = 'GITHUB_FG_PAT';    Label = 'GitHub fine-grained PAT';         Pattern = '\bgithub_pat_[0-9A-Za-z_]{82}\b';                              CaseSensitive = $true;  Confidence = 'High';   Type = 'Structured' }
    @{ Id = 'AZURE_AD_SECRET';  Label = 'Azure AD client secret';          Pattern = '\b[A-Za-z0-9_~.\-]{3}[78]Q~[A-Za-z0-9_~.\-]{31,34}\b';         CaseSensitive = $true;  Confidence = 'High';   Type = 'Structured' }
    @{ Id = 'SLACK_WEBHOOK';    Label = 'Slack webhook URL';               Pattern = 'https://hooks\.slack\.com/services/[A-Za-z0-9/]+';             CaseSensitive = $false; Confidence = 'High';   Type = 'Structured' }
    @{ Id = 'TWILIO_AC';        Label = 'Twilio Account SID';              Pattern = '\bAC[0-9a-f]{32}\b';                                           CaseSensitive = $true;  Confidence = 'Medium'; Type = 'Structured' }
    @{ Id = 'MAILGUN_KEY';      Label = 'Mailgun API key';                 Pattern = '\bkey-[0-9a-f]{32}\b';                                         CaseSensitive = $true;  Confidence = 'Medium'; Type = 'Structured' }
    @{ Id = 'URL_CRED';         Label = 'URL with embedded credentials';   Pattern = '(?i)[a-z][a-z0-9+.\-]*://[^:/?#\s@]+:[^@/?#\s]{2,}@';           CaseSensitive = $false; Confidence = 'High';   Type = 'Structured' }

    # -- Medium confidence: contextual keyword = value assignments. Higher FP
    #    risk, so the captured value is placeholder-filtered before recording.
    #    The value is captured but never printed. --

    @{ Id = 'GEN_PASSWORD';  Label = 'Password assignment';               Pattern = '(password|passwd|passphrase|pwd)["'']?\s*[:=]\s*["'']?(?<val>[^"''\s,;>]{4,})';                       CaseSensitive = $false; Confidence = 'Medium'; Type = 'Contextual' }
    @{ Id = 'GEN_SECRET';    Label = 'Secret/token/key assignment';       Pattern = '(api[_-]?key|access[_-]?key|secret[_-]?key|session[_-]?key|client[_-]?secret|app[_-]?secret|consumer[_-]?secret|secret|access[_-]?token|refresh[_-]?token|id[_-]?token|auth[_-]?token|private[_-]?token|token)["'']?\s*[:=]\s*["'']?(?<val>[^"''\s,;>]{8,})'; CaseSensitive = $false; Confidence = 'Medium'; Type = 'Contextual' }
    @{ Id = 'CONN_STRING';   Label = 'Connection string with credentials'; Pattern = '(connectionstring\s*=|<add[^>]+connectionstring\s*=)[^>]*\b(password|pwd)\s*=\s*(?<val>[^;"''>\s]+)'; CaseSensitive = $false; Confidence = 'Medium'; Type = 'Contextual' }
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
    @{ Id = 'GPP_CPASSWORD';    Label = 'Group Policy Preferences cpassword';   Pattern = 'cpassword\s*=\s*["''](?<val>[^"''\s]{4,})["'']'; CaseSensitive = $false; Confidence = 'High';   Type = 'Contextual' }
    @{ Id = 'UNATTEND_PW';      Label = 'Unattend/sysprep password';            Pattern = '<\w*password>\s*<value>(?<val>[^<\s]{4,})'; CaseSensitive = $false; Confidence = 'High';   Type = 'Contextual' }
)

# ---------------------------------------------------------------------------
# Placeholder / reference patterns. A contextual value matching ANY of these is
# treated as a non-secret and dropped (unless -IncludePlaceholders). These are
# matched case-insensitively against the captured value only.
# ---------------------------------------------------------------------------
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
# Distinctive keywords matched as a plain substring (low FP even unbounded).
$script:EnvNameKeywordPattern = '(?i)(password|passwd|pwd|secret|api[_-]?key|apikey|access[_-]?key|secret[_-]?key|client[_-]?secret|auth[_-]?token|token|account[_-]?key|connection[_-]?string|connectionstring|private[_-]?key|credential|passphrase|bearer|webhook|oauth)'
# Short / ambiguous keywords matched ONLY as a delimited token (^, $, _ or -),
# so 'key' does not hit PATH/MONKEY/KEYBOARD and 'pat' does not hit PATH.
$script:EnvNameKeywordBounded = '(?i)(^|[_\-])(pwd|key|keys|cert|certificate|pat|dsn|sas|sig|signature|signing|privkey)([_\-]|$)'

# ---------------------------------------------------------------------------
# Matching pre-filter gate. A single case-insensitive regex that is a strict
# SUPERSET of every rule's minimal trigger (a substring that MUST be present for
# that rule to match). Lines containing none of these triggers cannot match any
# rule, so the per-line rule loop is skipped for them -- the main matching
# speed-up on large files. CORRECTNESS RULE: when you add/modify a rule in
# $script:Rules, add its trigger here too, or that rule could be silently
# skipped. It is always safe to make this BROADER (over-include); only too-narrow
# is dangerous. (Validated against a line matching every current rule.)
# ---------------------------------------------------------------------------
$script:TriggerPattern = '(?i)(password|passwd|passphrase|pwd|secret|api|access|auth|bearer|client|session|private|token|credential|connectionstring|cpassword|akia|asia|aiza|googleusercontent|xox|gh[pousr]_|glpat-|_live_|_test_|sg\.|begin|eyj|accountkey=|\bsk|npm_|github_pat_|q~|hooks\.slack|\bac[0-9a-f]|key-|shpat_|shpss_|shppa_|shpca_|dop_v1|doo_v1|dor_v1|dp\.|dapi|glsa_|pmak-|figd_|lin_api_|sntry|pypi-|hf_|nrak-|ntn_|sq0|://)'

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
    SkippedCloud      = 0
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
$script:ExcludePaths        = @($ExcludePaths | ForEach-Object { $_.ToLowerInvariant() })   # pre-lowered once for Test-ExcludeDir (hot path)
$script:IncludePlaceholders = [bool]$IncludePlaceholders
$script:AggressiveValueScan = [bool]$AggressiveValueScan
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
        catch { $null = $_ }   # best-effort: return whatever drives resolved
    }
    return $result
}

function Test-ExcludeDir {
    # $true if the directory path contains any configured exclusion fragment.
    param([string]$Path)
    $lower = $Path.ToLowerInvariant()
    foreach ($x in $script:ExcludePaths) {
        if ($x -and $lower.Contains($x)) { return $true }
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

function Test-IsNoiseValue {
    # $true if a captured value is an obvious non-secret (number, boolean, path,
    # integrity-hash prefix). Keeps recall high while trimming generic-rule noise.
    param([string]$Value)
    if ([string]::IsNullOrEmpty($Value)) { return $true }
    foreach ($p in $script:NoiseValuePatterns) {
        if ($Value -match $p) { return $true }
    }
    return $false
}

function Test-LooksLikeSecretValue {
    # Heuristic used ONLY by -AggressiveValueScan: $true if a value "looks like" a
    # random secret regardless of where it lives (catches secrets in oddly-named
    # variables that no keyword/provider rule would match). Deliberately noisier
    # than the other rules. CLM-safe: no [Math]/entropy maths -- just length,
    # character-class checks, and distinct-character counting via a hashtable.
    param([string]$Value)
    if ([string]::IsNullOrEmpty($Value)) { return $false }
    if ($Value.Length -lt 20) { return $false }                 # too short to be a strong secret
    if ($Value -match '\s')   { return $false }                 # whitespace -> prose/list, not a token
    if ($Value -match '[\\/]') { return $false }                # path / URL -> handled elsewhere
    # Canonical GUID -> identifier, not a secret (skip to cut obvious noise).
    if ($Value -match '^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$') { return $false }

    $hasLower = $Value -cmatch '[a-z]'
    $hasUpper = $Value -cmatch '[A-Z]'
    $hasDigit = $Value -match  '[0-9]'
    $hasSpec  = $Value -match  '[^A-Za-z0-9]'
    $classes = 0
    if ($hasLower) { $classes++ }
    if ($hasUpper) { $classes++ }
    if ($hasDigit) { $classes++ }
    if ($hasSpec)  { $classes++ }
    if ($classes -lt 2) { return $false }                       # not mixed enough
    if (-not ($hasDigit -and ($hasLower -or $hasUpper))) { return $false }  # random tokens mix letters+digits

    # Distinct-character count: repetitive strings (aaaa..., 0000...) are not secrets.
    $seen = @{}
    foreach ($ch in $Value.ToCharArray()) { $seen[$ch] = $true }
    if ($seen.Keys.Count -lt 10) { return $false }
    return $true
}

function Test-FileIsBinary {
    # Read the first chunk of bytes and decide text vs binary. BOM-aware: a NUL
    # byte alone no longer means "binary" -- UTF-16/UTF-32 text (very common on
    # Windows: PowerShell Out-File, exported .config/.xml) is full of NULs but is
    # real text we must scan. Treat known text BOMs and BOM-less UTF-16 (NULs on a
    # single parity) as text; otherwise a NUL means binary. Uses Get-Content
    # -Encoding Byte (works in both language modes).
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
    # Return the file's lines as a string array, read-only.
    #   * Full Language Mode: use a FileStream opened with FileShare.ReadWrite so
    #     locked / in-use files still read and we never block other writers, plus
    #     a StreamReader. BOM'd files auto-detect; BOM-less UTF-16 gets an explicit
    #     decoder chosen from the first bytes (Get-FileTextKind).
    #   * Constrained Language Mode: fall back to Get-Content -Encoding (cmdlet only).
    param([string]$Path)
    $kind = 'bom'
    try {
        $head = Get-Content -LiteralPath $Path -Encoding Byte -TotalCount 512 -ErrorAction Stop
        if ($head) { $kind = Get-FileTextKind -Head $head -N $head.Count }
    }
    catch { $kind = 'bom' }
    if ($script:UseDotNetIO) {
        $fs = $null
        $sr = $null
        try {
            $fs = [System.IO.File]::Open($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
            if ($kind -eq 'utf16le') { $enc = New-Object System.Text.UnicodeEncoding($false, $false); $sr = New-Object System.IO.StreamReader -ArgumentList @($fs, $enc, $false) }
            elseif ($kind -eq 'utf16be') { $enc = New-Object System.Text.UnicodeEncoding($true, $false); $sr = New-Object System.IO.StreamReader -ArgumentList @($fs, $enc, $false) }
            else { $sr = New-Object System.IO.StreamReader -ArgumentList @($fs, $true) }
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
        if ($kind -eq 'utf16le') { return @(Get-Content -LiteralPath $Path -Encoding Unicode -ErrorAction Stop) }
        elseif ($kind -eq 'utf16be') { return @(Get-Content -LiteralPath $Path -Encoding BigEndianUnicode -ErrorAction Stop) }
        else { return @(Get-Content -LiteralPath $Path -ErrorAction Stop) }
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

    # Skip cloud / offline placeholder files (e.g. OneDrive Files On-Demand,
    # archival/HSM stubs). Opening one triggers HYDRATION -- an on-demand download
    # from the cloud that can HANG the scan for a long time (the per-file time
    # check cannot interrupt a blocked file-open) AND generate off-box network
    # traffic, both unacceptable in Live Response. This is the most likely cause
    # of a scan that runs for many minutes and is then killed by the system.
    # Bits: Offline (0x1000), RecallOnOpen (0x40000), RecallOnDataAccess
    # (0x400000). The latter two are not named in the .NET FileAttributes enum,
    # so test the raw attribute value numerically.
    $attrInt = 0
    try { $attrInt = [int]$Item.Attributes } catch { $attrInt = 0 }
    if (($attrInt -band 0x441000) -ne 0) {
        $script:Stats.SkippedCloud++
        return
    }

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

        # Pre-filter gate: a single cheap regex that is a strict SUPERSET of every
        # rule's minimal trigger. If a line contains none of those triggers it
        # cannot match any rule, so we skip the (otherwise ~23) per-rule regex
        # evaluations. This is the dominant matching cost on large files; the gate
        # is correctness-preserving (it can only skip lines no rule would match)
        # and CLM-safe (plain -match). See $script:TriggerPattern.
        if ($line -notmatch $script:TriggerPattern) { continue }

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
                    if (Test-IsNoiseValue -Value $val) { continue }
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

    # Enumerate this directory's children.
    #   Full Language Mode: System.IO.DirectoryInfo.GetFileSystemInfos() is ~2x+
    #     faster than Get-ChildItem when walking tens of thousands of directories,
    #     because it skips PowerShell's per-item PSObject wrapping (the dominant
    #     cost of a full-disk traversal).
    #   Constrained Language Mode: fall back to Get-ChildItem (method calls on
    #     DirectoryInfo are blocked in CLM).
    # Both return [System.IO.FileSystemInfo] objects, so the directory / reparse
    # tests below use the raw attribute BITS (Directory=0x10, ReparsePoint=0x400),
    # which work for both shapes and are CLM-safe (no PSIsContainer dependency).
    $children = $null
    try {
        if ($script:UseDotNetIO) {
            $children = @((New-Object System.IO.DirectoryInfo -ArgumentList $Dir).GetFileSystemInfos())
        }
        else {
            $children = @(Get-ChildItem -LiteralPath $Dir -Force -ErrorAction Stop)
        }
    }
    catch {
        # Access denied, long path, IO error, etc. Isolate and keep going.
        $script:Stats.DirErrors++
        return
    }

    # Process candidate files first.
    foreach ($c in $children) {
        if ($script:TimeUp) { return }
        if ((([int]$c.Attributes) -band 0x10) -ne 0) { continue }   # directory -> handled below
        if (Test-IsCandidate -Name $c.Name) {
            if (Test-TimeUp) { $script:TimeUp = $true; return }
            Invoke-FileScan -Item $c
        }
    }

    # Then recurse into subdirectories (skipping reparse points).
    foreach ($c in $children) {
        if ($script:TimeUp) { return }
        if ((([int]$c.Attributes) -band 0x10) -eq 0) { continue }    # not a directory
        if ((([int]$c.Attributes) -band 0x400) -ne 0) {              # ReparsePoint
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
    catch { $null = $_ }   # best-effort: fall through to well-known SIDs / raw SID
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
                $matchLen = ([string]$matches[0]).Length   # capture while $matches is fresh for this rule
                if ($seen.ContainsKey($rule.Id)) { continue }
                if ($script:ConfRank[$rule.Confidence] -lt $script:MinRank) { continue }
                $seen[$rule.Id] = $true
                $varFindings += @{ RuleId = $rule.Id; Label = $rule.Label; Confidence = $rule.Confidence; Length = $matchLen }
            }

            # Pass B: secret-like NAME (substring keywords OR delimited short
            # keywords) + non-placeholder value -> Medium.
            if (($vname -match $script:EnvNameKeywordPattern) -or ($vname -match $script:EnvNameKeywordBounded)) {
                $isPlaceholder = $false
                if (-not $script:IncludePlaceholders) { $isPlaceholder = Test-IsPlaceholder -Value $vval }
                if ((-not $isPlaceholder) -and ($vval.Length -ge 4) -and ($script:ConfRank['Medium'] -ge $script:MinRank)) {
                    if (-not $seen.ContainsKey('ENV_NAMED_SECRET')) {
                        $seen['ENV_NAMED_SECRET'] = $true
                        $varFindings += @{ RuleId = 'ENV_NAMED_SECRET'; Label = 'Secret-like environment variable'; Confidence = 'Medium'; Length = $vval.Length }
                    }
                }
            }

            # Pass C (opt-in -AggressiveValueScan): high-entropy-looking value
            # regardless of name. Only runs if nothing above already matched this
            # variable, so it purely fills the "odd-named secret" gap.
            if ($script:AggressiveValueScan -and ($varFindings.Count -eq 0)) {
                $isPlaceholder = $false
                if (-not $script:IncludePlaceholders) { $isPlaceholder = Test-IsPlaceholder -Value $vval }
                if ((-not $isPlaceholder) -and ($script:ConfRank['Medium'] -ge $script:MinRank) -and (Test-LooksLikeSecretValue -Value $vval)) {
                    $varFindings += @{ RuleId = 'ENV_HIGH_ENTROPY'; Label = 'High-entropy environment value (aggressive)'; Confidence = 'Medium'; Length = $vval.Length }
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
    Write-Output ("SUMMARY | candidatesMatched={0} | filesScanned={1} | skippedSize={2} | skippedBinary={3} | skippedCloud={4} | fileErrors={5} | dirErrors={6} | reparseSkipped={7} | hashErrors={8} | filesWithFindings={9} | envScopes={10} | envVars={11} | envVarsWithFindings={12} | totalFindings={13} | elapsedSec={14} | truncated={15}" -f `
        $s.CandidatesMatched, $s.FilesScanned, $s.SkippedSize, $s.SkippedBinary, $s.SkippedCloud, $s.FileErrors, `
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
    Write-Output ("  Skipped (cloud/offln): {0}" -f $s.SkippedCloud)
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
    Write-Meta ("script=Find-HardcodedSecrets.ps1 version={0} rulesRev={1} host={2} startUtc={3} langMode={4}" -f `
        $ScriptVersion, $RulesRev, $env:COMPUTERNAME, $startUtc, $langMode)
    Write-Meta ("params | minConfidence={0} maxFileSizeMB={1} maxRuntimeMinutes={2} includePlaceholders={3} envScanEnabled={4} aggressiveValueScan={5} dotNetIO={6} rules={7}" -f `
        $MinConfidence, $MaxFileSizeMB, $MaxRuntimeMinutes, $script:IncludePlaceholders, (-not $SkipEnvironment), $script:AggressiveValueScan, $script:UseDotNetIO, $script:Rules.Count)

    # Environment-variable scan FIRST (registry-backed). It is fast and high-value
    # (a common secret stash) and -- critically -- Live Response returns a
    # command's output only when it COMPLETES, while a long file scan can hit the
    # session/command time cap and be killed. Running env first guarantees these
    # findings are produced even if the file scan is later truncated by the time
    # budget. On by default; pass -SkipEnvironment for files-only.
    if (-not $SkipEnvironment) {
        Write-Meta 'env-scan-start'
        Invoke-EnvScan
        Write-Meta ("env-scan-end | scopes={0} vars={1} varsWithFindings={2}" -f `
            $script:Stats.EnvScopesScanned, $script:Stats.EnvVarsScanned, $script:Stats.EnvVarsWithFindings)
    }

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
            Write-Meta 'file-scan runtime budget exceeded; stopping with partial results'
            break
        }
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

<#
.SYNOPSIS
    Microsoft Intune REMEDIATION DETECTION script. Read-only INVENTORY of OS / app
    credential STORES on the device -- saved Wi-Fi PSKs (plaintext), Windows
    Credential Manager entries, machine/user certificate private keys, and browser
    saved-password stores. Exits 1 when any are present (device flagged "issue
    detected"), 0 when none. One compact stdout line. Never prints a secret value.

.DESCRIPTION
    Files, env vars and the registry are covered by the other Detect-*Secrets.ps1
    scripts. THIS one inventories credentials held in OS/app *stores* that a
    content scan never sees. It does NOT decrypt anything -- DPAPI/encrypted stores
    are reported by PRESENCE (and count), the one plaintext source (Wi-Fi key) is
    reported by LENGTH only, never the value.

    Sources:
      * WIFI_PSK            -- `netsh wlan` profiles that have a stored key
                               (WPA pre-shared key is recoverable in PLAINTEXT as
                               SYSTEM). High. Reported by SSID + key length only.
      * WIN_CRED_MANAGER    -- `cmdkey /list` saved credentials (target name only).
                               Medium. NOTE: as SYSTEM this sees the SYSTEM/computer
                               vault, not interactive users' vaults (per-user DPAPI).
      * CERT_PRIVATE_KEY    -- certificates WITH a private key in LocalMachine\My /
                               CurrentUser\My (exfiltration risk). Medium.
      * BROWSER_PWD_STORE   -- presence of Chrome/Edge "Login Data" and Firefox
                               logins.json per user profile (DPAPI-encrypted saved
                               passwords exist). Medium.

    Intune use: Devices -> Scripts and remediations -> create a remediation, use
    THIS as the detection script. Recommended: Run as SYSTEM, 64-bit, signature
    check off. Intune passes no arguments; it surfaces only the LAST stdout line,
    so the whole report is on ONE line, capped under ~2 KB. Runs in seconds.

    Windows PowerShell 5.1; tolerant of Constrained Language Mode (built-in
    cmdlets + external netsh/cmdkey only). Read-only; writes nothing; no network.

    Output (single line):
      STATUS=FOUND | host=<h> ver=<v> n=<n> high=<a> med=<b> low=<c> rev=<r> :: HIGH WIFI_PSK WiFi::<ssid>(<keylen>) ; MED BROWSER_PWD_STORE ... [; (+N more)]
    or  STATUS=CLEAN | host=<h> ver=<v> n=0 rev=<r>
    or  STATUS=ERROR | host=<h> ver=<v> rev=<r> | msg=<...>   (exit 1)

.PARAMETER MinConfidence
    Minimum confidence to report: High, Medium or Low. Default: Medium.

.PARAMETER SkipWifi
    Switch. Skip the `netsh wlan` Wi-Fi key enumeration.

.EXAMPLE
    Local test:
        powershell -ExecutionPolicy Bypass -File .\Detect-StoredCredentialSecrets.ps1 ; $LASTEXITCODE

.NOTES
    Safety: read-only; writes nothing; never prints a secret value (the Wi-Fi key
    is reported by length only); never decrypts; no network. This is an inventory
    of credential STORES, not a value dump. Exit codes: 0 = none, 1 = found OR error.
    Version : 1.0.0
    Author  : DFIR
#>

#requires -Version 5.1

[CmdletBinding()]
param(
    [ValidateSet('High', 'Medium', 'Low')]
    [string]$MinConfidence = 'Medium',

    [switch]$SkipWifi
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ScriptVersion = '1.0.0'
# Carries the shared generation tag so the drift guard treats it as part of the
# suite (this detector uses no regex rule table -- it inventories OS stores).
$RulesRev = '3'

$script:ConfRank = @{ 'High' = 3; 'Medium' = 2; 'Low' = 1 }
$script:MinRank  = $script:ConfRank[$MinConfidence]
$script:Findings = @()

function Add-Finding {
    param([string]$Confidence, [string]$RuleId, [string]$Scope, [string]$Name, [int]$Length)
    if ($script:ConfRank[$Confidence] -lt $script:MinRank) { return }
    $script:Findings += @{ Confidence = $Confidence; RuleId = $RuleId; Scope = $Scope; Name = $Name; Length = $Length }
}

# --- Wi-Fi pre-shared keys (plaintext as SYSTEM) -------------------------------
function Invoke-WifiCheck {
    $profilesOut = $null
    try { $profilesOut = & netsh wlan show profiles 2>$null } catch { return }
    if (-not $profilesOut) { return }
    $names = @()
    foreach ($line in $profilesOut) {
        if ($line -match 'User Profile\s*:\s*(.+?)\s*$') { $names += $matches[1] }
    }
    foreach ($ssid in ($names | Select-Object -Unique)) {
        $detail = $null
        try { $detail = & netsh wlan show profile name="$ssid" key=clear 2>$null } catch { continue }
        if (-not $detail) { continue }
        foreach ($line in $detail) {
            if ($line -match 'Key Content\s*:\s*(.+?)\s*$') {
                $klen = ([string]$matches[1]).Length
                if ($klen -gt 0) { Add-Finding -Confidence 'High' -RuleId 'WIFI_PSK' -Scope 'WiFi' -Name $ssid -Length $klen }
                break
            }
        }
    }
}

# --- Windows Credential Manager (target names only) ----------------------------
function Invoke-CredManagerCheck {
    $out = $null
    try { $out = & cmdkey /list 2>$null } catch { return }
    if (-not $out) { return }
    foreach ($line in $out) {
        if ($line -match '^\s*Target:\s*(.+?)\s*$') {
            $target = $matches[1]
            Add-Finding -Confidence 'Medium' -RuleId 'WIN_CRED_MANAGER' -Scope 'CredMan' -Name $target -Length 0
        }
    }
}

# --- Certificate private keys --------------------------------------------------
function Invoke-CertCheck {
    foreach ($store in @('Cert:\LocalMachine\My', 'Cert:\CurrentUser\My')) {
        $certs = $null
        try { $certs = @(Get-ChildItem -LiteralPath $store -ErrorAction SilentlyContinue) } catch { $certs = @() }
        foreach ($c in $certs) {
            $hasKey = $false
            try { $hasKey = [bool]$c.HasPrivateKey } catch { $hasKey = $false }
            if (-not $hasKey) { continue }
            $subj = ''
            try { $subj = [string]$c.Subject } catch { $subj = '' }
            $thumb = ''
            try { $thumb = [string]$c.Thumbprint } catch { $thumb = '' }
            if ($subj.Length -gt 60) { $subj = $subj.Substring(0, 60) }
            $scope = if ($store -like '*LocalMachine*') { 'Cert:LM' } else { 'Cert:CU' }
            Add-Finding -Confidence 'Medium' -RuleId 'CERT_PRIVATE_KEY' -Scope $scope -Name ($subj + ' [' + $thumb + ']') -Length 0
        }
    }
}

# --- Browser saved-password stores (presence) ----------------------------------
function Invoke-BrowserCheck {
    $users = @()
    try { $users = @(Get-ChildItem -LiteralPath 'C:\Users' -Directory -Force -ErrorAction SilentlyContinue) } catch { $users = @() }
    foreach ($u in $users) {
        if ((([int]$u.Attributes) -band 0x400) -ne 0) { continue }   # reparse / junction
        $base = $u.FullName
        $targets = @(
            @{ Browser = 'Chrome';  Glob = 'AppData\Local\Google\Chrome\User Data\*\Login Data' }
            @{ Browser = 'Edge';    Glob = 'AppData\Local\Microsoft\Edge\User Data\*\Login Data' }
            @{ Browser = 'Firefox'; Glob = 'AppData\Roaming\Mozilla\Firefox\Profiles\*\logins.json' }
        )
        foreach ($t in $targets) {
            $hits = $null
            try { $hits = @(Get-ChildItem -Path (Join-Path $base $t.Glob) -Force -ErrorAction SilentlyContinue) } catch { $hits = @() }
            foreach ($h in $hits) {
                $sz = 0
                try { $sz = [int]$h.Length } catch { $sz = 0 }
                Add-Finding -Confidence 'Medium' -RuleId 'BROWSER_PWD_STORE' -Scope ('Browser:' + $t.Browser) -Name ($u.Name) -Length $sz
            }
        }
    }
}

# ===========================================================================
# Main
# ===========================================================================

$err = $null
try {
    if (-not $SkipWifi) { Invoke-WifiCheck }
    Invoke-CredManagerCheck
    Invoke-CertCheck
    Invoke-BrowserCheck
}
catch { $err = $_.Exception.Message }

if ($err) {
    Write-Output ("STATUS=ERROR | host={0} ver={1} rev={2} | msg={3}" -f $env:COMPUTERNAME, $ScriptVersion, $RulesRev, ($err -replace '\s+', ' '))
    exit 1
}

$findings = @($script:Findings)
$n = $findings.Count
if ($n -eq 0) {
    Write-Output ("STATUS=CLEAN | host={0} ver={1} n=0 rev={2}" -f $env:COMPUTERNAME, $ScriptVersion, $RulesRev)
    exit 0
}

$high = @($findings | Where-Object { $_.Confidence -eq 'High' }).Count
$med  = @($findings | Where-Object { $_.Confidence -eq 'Medium' }).Count
$low  = @($findings | Where-Object { $_.Confidence -eq 'Low' }).Count

$head = "STATUS=FOUND | host={0} ver={1} n={2} high={3} med={4} low={5} rev={6}" -f `
    $env:COMPUTERNAME, $ScriptVersion, $n, $high, $med, $low, $RulesRev
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

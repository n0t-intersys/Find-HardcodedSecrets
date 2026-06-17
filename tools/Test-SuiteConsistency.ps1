#requires -Version 5.1
<#
.SYNOPSIS
    DEV / CI TOOL -- not for Live Response. Verifies that the detection
    definitions duplicated across the Find-*Secrets.ps1 suite stay in sync.

.DESCRIPTION
    The scanners must each be self-contained (Live Response forbids shared
    modules), so the detection rule table, the pre-filter TriggerPattern, the
    PlaceholderPatterns list, and the RulesRev tag are hand-duplicated across the
    scripts. That duplication has already caused a real shipped bug (an env-scope
    rule diverging in Confidence). This tool parses each scanner's AST, extracts
    those shared definitions, and asserts that every rule shared by two or more
    scripts is byte-identical (same Pattern and Confidence), that the
    TriggerPattern and PlaceholderPatterns match across the scripts that define
    them, and that all scripts carry the same RulesRev.

    Run it after editing any rule/pattern, and in CI. Exit code 0 = consistent,
    1 = drift detected (with details).

.PARAMETER Dir
    Folder containing the Find-*Secrets.ps1 scripts. Default: the repo root
    (parent of this tools\ folder).

.EXAMPLE
    pwsh -File tools\Test-SuiteConsistency.ps1
#>

[CmdletBinding()]
param(
    # Default to the repo root (parent of tools\). $PSScriptRoot can be empty when
    # invoked oddly (e.g. -File with a relative path), so fall back to the CWD.
    [string]$Dir = $(if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path })
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# --- AST helpers -----------------------------------------------------------

function Get-AssignmentRight {
    param($Ast, [string]$VarName)
    $assigns = $Ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.AssignmentStatementAst] }, $true)
    foreach ($a in $assigns) {
        if ($a.Left.Extent.Text -eq $VarName) { return $a.Right }
    }
    return $null
}

function Get-StringValue {
    param($Ast)
    if ($null -eq $Ast) { return $null }
    $sc = $Ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.StringConstantExpressionAst] }, $true) | Select-Object -First 1
    if ($sc) { return $sc.Value }
    return $null
}

function Get-ScannerModel {
    # Parse one scanner and pull out its shared detection definitions.
    param([string]$Path)
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$null, [ref]$null)

    # Rules: Id -> @{ Pattern; Confidence }
    $rules = @{}
    $rulesRight = Get-AssignmentRight -Ast $ast -VarName '$script:Rules'
    if ($rulesRight) {
        $hts = $rulesRight.FindAll({ param($n) $n -is [System.Management.Automation.Language.HashtableAst] }, $true)
        foreach ($ht in $hts) {
            $h = @{}
            foreach ($pair in $ht.KeyValuePairs) {
                $key = $pair.Item1.Extent.Text.Trim("'`"")
                $h[$key] = (Get-StringValue -Ast $pair.Item2)
            }
            if ($h.ContainsKey('Id') -and $h['Id']) {
                $rules[$h['Id']] = @{ Pattern = $h['Pattern']; Confidence = $h['Confidence'] }
            }
        }
    }

    # Placeholder list (string values, in order)
    $phRight = Get-AssignmentRight -Ast $ast -VarName '$script:PlaceholderPatterns'
    $placeholders = @()
    if ($phRight) {
        $placeholders = @($phRight.FindAll({ param($n) $n -is [System.Management.Automation.Language.StringConstantExpressionAst] }, $true) | ForEach-Object { $_.Value })
    }

    return @{
        Name         = (Split-Path -Leaf $Path)
        Rules        = $rules
        Trigger      = (Get-StringValue -Ast (Get-AssignmentRight -Ast $ast -VarName '$script:TriggerPattern'))
        Placeholders = $placeholders
        RulesRev     = (Get-StringValue -Ast (Get-AssignmentRight -Ast $ast -VarName '$RulesRev'))
    }
}

# --- Load all scanners -----------------------------------------------------

$paths = Get-ChildItem -Path $Dir -Recurse -File -Include 'Find-*Secrets.ps1', 'Detect-*Secrets.ps1' | Sort-Object Name
if (-not $paths) { Write-Output "FAIL | no Find-*Secrets.ps1 / Detect-*Secrets.ps1 scripts found in $Dir"; exit 1 }
$models = $paths | ForEach-Object { Get-ScannerModel -Path $_.FullName }

$problems = @()

# 1) Rules shared by >=2 scripts must have identical Pattern + Confidence.
$allIds = @($models | ForEach-Object { $_.Rules.Keys } | Sort-Object -Unique)
foreach ($id in $allIds) {
    $owners = @($models | Where-Object { $_.Rules.ContainsKey($id) })
    if ($owners.Count -lt 2) { continue }
    $pats  = @($owners | ForEach-Object { $_.Rules[$id].Pattern }     | Sort-Object -Unique)
    $confs = @($owners | ForEach-Object { [string]$_.Rules[$id].Confidence } | Sort-Object -Unique)
    if ($pats.Count -gt 1)  { $problems += "RULE PATTERN drift for '$id' across: " + (($owners | ForEach-Object { $_.Name }) -join ', ') }
    if ($confs.Count -gt 1) { $problems += "RULE CONFIDENCE drift for '$id': " + (($owners | ForEach-Object { $_.Name + '=' + $_.Rules[$id].Confidence }) -join ', ') }
}

# 2) TriggerPattern identical across scripts that define one.
$trigs = @($models | Where-Object { $_.Trigger } )
$trigVals = @($trigs | ForEach-Object { $_.Trigger } | Sort-Object -Unique)
if ($trigVals.Count -gt 1) { $problems += "TriggerPattern drift across: " + (($trigs | ForEach-Object { $_.Name }) -join ', ') }

# 3) PlaceholderPatterns identical across scripts that define them.
$phOwners = @($models | Where-Object { $_.Placeholders.Count -gt 0 })
$phJoined = @($phOwners | ForEach-Object { ($_.Placeholders -join "`u{241F}") } | Sort-Object -Unique)
if ($phJoined.Count -gt 1) { $problems += "PlaceholderPatterns drift across: " + (($phOwners | ForEach-Object { $_.Name }) -join ', ') }

# 4) RulesRev identical across all scripts that carry it.
$revOwners = @($models | Where-Object { $_.RulesRev })
$revVals = @($revOwners | ForEach-Object { $_.RulesRev } | Sort-Object -Unique)
if ($revVals.Count -gt 1) { $problems += "RulesRev drift: " + (($revOwners | ForEach-Object { $_.Name + '=' + $_.RulesRev }) -join ', ') }
if ($revOwners.Count -ne $models.Count) {
    $missing = @($models | Where-Object { -not $_.RulesRev } | ForEach-Object { $_.Name })
    $problems += "RulesRev missing in: " + ($missing -join ', ')
}

# --- Report ----------------------------------------------------------------

Write-Output ("Scanned {0} scripts: {1}" -f $models.Count, (($models | ForEach-Object { $_.Name }) -join ', '))
foreach ($m in $models) {
    Write-Output ("  {0,-30} rules={1} trigger={2} placeholders={3} rulesRev={4}" -f `
        $m.Name, $m.Rules.Count, $(if ($m.Trigger) { 'yes' } else { 'no' }), $m.Placeholders.Count, $m.RulesRev)
}
Write-Output ''
if ($problems.Count -eq 0) {
    Write-Output 'PASS | suite detection definitions are consistent (no drift).'
    exit 0
}
else {
    foreach ($p in $problems) { Write-Output "FAIL | $p" }
    exit 1
}

#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Diagnose why an exe is being blocked by SRP, even after whitelisting.
.DESCRIPTION
    Reads the most recent SRP block events, then for each blocked path enumerates
    every ALLOW and BLOCK rule that matches and computes which one wins on
    specificity. Tells you in plain language why the block is sticking.
.PARAMETER Path
    Specific exe path to diagnose. If omitted, uses the most recent block event.
.PARAMETER EventCount
    How many recent block events to list (default 5).
.EXAMPLE
    .\Diagnose-Whitelist.ps1
    .\Diagnose-Whitelist.ps1 -Path "C:\Users\kid\AppData\Local\Programs\CurseForge\Update.exe"
#>

param(
    [string]$Path,
    [int]$EventCount = 5
)

$BlockBase = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers\0\Paths"
$AllowBase = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers\262144\Paths"

function Get-MatchingRules {
    param($Target, $RegBase)
    $matches = @()
    Get-ChildItem $RegBase -ErrorAction SilentlyContinue | ForEach-Object {
        $rule = (Get-ItemProperty $_.PSPath).ItemData
        $expanded = [Environment]::ExpandEnvironmentVariables($rule)
        $pattern = '^' + [Regex]::Escape($expanded).Replace('\*', '[^\\]*').Replace('\?', '[^\\]') + '$'
        if ($Target -match $pattern) {
            $specificity = ($expanded -replace '[\*\?]', '').Length
            $matches += [PSCustomObject]@{
                Rule = $rule
                Expanded = $expanded
                Specificity = $specificity
            }
        }
    }
    return $matches | Sort-Object Specificity -Descending
}

Write-Host "`n=== Recent SRP block events ===" -ForegroundColor Cyan
$events = Get-WinEvent -LogName Application -MaxEvents 500 -ErrorAction SilentlyContinue |
    Where-Object { $_.Id -in 865, 866, 867, 868, 882 } |
    Select-Object -First $EventCount

if (-not $events) {
    Write-Host "  (no SRP block events found in last 500 Application log entries)" -ForegroundColor Yellow
} else {
    $i = 0
    foreach ($e in $events) {
        $i++
        $blockedPath = $null
        if ($e.Message -match 'Access to ([^\r\n]+) has been restricted') {
            $blockedPath = $matches[1].Trim()
        }
        Write-Host "  [$i] $($e.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')) - $blockedPath" -ForegroundColor White
    }
}

if (-not $Path -and $events) {
    if ($events[0].Message -match 'Access to ([^\r\n]+) has been restricted') {
        $Path = $matches[1].Trim()
    }
}

if (-not $Path) {
    Write-Host "`nNo path to diagnose. Pass -Path '<exe>' or trigger a block event first." -ForegroundColor Yellow
    exit 0
}

$ExpandedPath = [Environment]::ExpandEnvironmentVariables($Path)
Write-Host "`n=== Diagnosing: $ExpandedPath ===" -ForegroundColor Cyan

$blockMatches = Get-MatchingRules -Target $ExpandedPath -RegBase $BlockBase
$allowMatches = Get-MatchingRules -Target $ExpandedPath -RegBase $AllowBase

Write-Host "`n--- Matching BLOCK rules (most specific first) ---" -ForegroundColor Red
if ($blockMatches) {
    $blockMatches | Format-Table @{n='Specificity';e={$_.Specificity}}, Rule -AutoSize | Out-Host
} else {
    Write-Host "  (none)" -ForegroundColor Gray
}

Write-Host "--- Matching ALLOW rules (most specific first) ---" -ForegroundColor Green
if ($allowMatches) {
    $allowMatches | Format-Table @{n='Specificity';e={$_.Specificity}}, Rule -AutoSize | Out-Host
} else {
    Write-Host "  (none)" -ForegroundColor Gray
}

$bestBlock = $blockMatches | Select-Object -First 1
$bestAllow = $allowMatches | Select-Object -First 1

Write-Host "--- Verdict ---" -ForegroundColor Cyan
if ($bestBlock -and $bestAllow) {
    if ($bestAllow.Specificity -gt $bestBlock.Specificity) {
        Write-Host "  ALLOWED. Allow rule '$($bestAllow.Rule)' beats block rule '$($bestBlock.Rule)' on specificity." -ForegroundColor Green
        Write-Host "  If the exe is still blocked, the child user hasn't reloaded SRP (log off/on) or the event is stale." -ForegroundColor Yellow
    } elseif ($bestBlock.Specificity -gt $bestAllow.Specificity) {
        Write-Host "  BLOCKED. Block rule '$($bestBlock.Rule)' is more specific than your allow '$($bestAllow.Rule)'." -ForegroundColor Red
        Write-Host "  Fix: add an allow rule with more literal characters (push the wildcard further right)." -ForegroundColor Yellow
    } else {
        Write-Host "  BLOCKED (tie). Block '$($bestBlock.Rule)' and allow '$($bestAllow.Rule)' have equal specificity; SAFER picks the more restrictive rule." -ForegroundColor Red
        Write-Host "  Fix: make the allow rule more specific (add a literal subfolder name) OR remove the conflicting block." -ForegroundColor Yellow
    }
} elseif ($bestAllow) {
    Write-Host "  ALLOWED. Only allow rules match." -ForegroundColor Green
} elseif ($bestBlock) {
    Write-Host "  BLOCKED. Block rule '$($bestBlock.Rule)' matches and no allow rule covers this path." -ForegroundColor Red
    Write-Host "  Fix: .\Add-GameWhitelist.ps1 -CustomPath '$(Split-Path $Path -Parent)'" -ForegroundColor Yellow
} else {
    Write-Host "  No rules match this path. The block must be coming from somewhere else (AppLocker, antivirus, etc.)." -ForegroundColor Yellow
}

$leaf = Split-Path $ExpandedPath -Leaf
$parent = Split-Path $ExpandedPath -Parent
$parentLeaf = if ($parent) { Split-Path $parent -Leaf } else { $null }

if ($parentLeaf) {
    Write-Host "`n--- All ALLOW rules mentioning '$parentLeaf' (to spot typos / trailing-slash artifacts) ---" -ForegroundColor Cyan
    $hit = $false
    Get-ChildItem $AllowBase -ErrorAction SilentlyContinue | ForEach-Object {
        $rule = (Get-ItemProperty $_.PSPath).ItemData
        if ($rule -like "*$parentLeaf*") {
            $flag = ''
            if ($rule -match '\\\\') { $flag = '  <-- DOUBLE BACKSLASH (malformed)' }
            Write-Host "  $rule$flag" -ForegroundColor Gray
            $hit = $true
        }
    }
    if (-not $hit) { Write-Host "  (no allow rules contain '$parentLeaf')" -ForegroundColor Yellow }
}

Write-Host ""

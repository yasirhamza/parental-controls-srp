<#
.SYNOPSIS
    Validates the expected registry changes from -WhatIf output
.DESCRIPTION
    Runs Enable-SRP-Complete.ps1 -WhatIf, parses the output, and validates
    that the correct paths would be blocked/allowed.
#>

$ErrorActionPreference = "Stop"
$script:TestsPassed = 0
$script:TestsFailed = 0
$script:ScriptPath = Join-Path $PSScriptRoot "Enable-SRP-Complete.ps1"

function Write-TestResult {
    param (
        [string]$TestName,
        [bool]$Passed,
        [string]$Details = ""
    )
    if ($Passed) {
        Write-Host "[PASS] $TestName" -ForegroundColor Green
        $script:TestsPassed++
    } else {
        Write-Host "[FAIL] $TestName" -ForegroundColor Red
        if ($Details) { Write-Host "       $Details" -ForegroundColor Yellow }
        $script:TestsFailed++
    }
}

Write-Host "`n=== WhatIf Output Validation Tests ===" -ForegroundColor Cyan

# ============================================================
# Run -WhatIf and capture output
# ============================================================
Write-Host "`nRunning -WhatIf mode..." -ForegroundColor Yellow

# Write output to temp file to preserve encoding
$tempFile = Join-Path $env:TEMP "whatif_output.txt"
$null = & powershell -ExecutionPolicy Bypass -File $script:ScriptPath -WhatIf *> $tempFile
$output = Get-Content $tempFile -Raw -Encoding UTF8
Remove-Item $tempFile -ErrorAction SilentlyContinue

Write-Host "Captured $($output.Length) characters of output" -ForegroundColor DarkGray

# ============================================================
# Parse WOULD BLOCK paths - try multiple patterns
# ============================================================
$blockPaths = @()
$output -split "`r?`n" | ForEach-Object {
    $line = $_
    # Pattern 1: Standard format
    if ($line -match 'WOULD BLOCK\]\s*(.+)$') {
        $blockPaths += $Matches[1].Trim()
    }
    # Pattern 2: Match after ] with path starting with % or drive letter
    elseif ($line -match '\]\s*(%[^%]+%\\.+|[A-Z]:\\.+)$') {
        if ($line -match 'BLOCK') {
            $blockPaths += $Matches[1].Trim()
        }
    }
}

# ============================================================
# Parse WOULD ALLOW paths
# ============================================================
$allowPaths = @()
$output -split "`r?`n" | ForEach-Object {
    $line = $_
    if ($line -match 'WOULD ALLOW\]\s*(.+)$') {
        $allowPaths += $Matches[1].Trim()
    }
    elseif ($line -match '\]\s*(%[^%]+%\\.+|[A-Z]:\\.+)$') {
        if ($line -match 'ALLOW' -and $line -notmatch 'BLOCK') {
            $allowPaths += $Matches[1].Trim()
        }
    }
}

Write-Host "Parsed $($blockPaths.Count) BLOCK rules" -ForegroundColor DarkGray
Write-Host "Parsed $($allowPaths.Count) ALLOW rules" -ForegroundColor DarkGray

# ============================================================
# TEST: Basic counts
# ============================================================
Write-TestResult "Found block rules" ($blockPaths.Count -gt 0) "Count: $($blockPaths.Count)"
Write-TestResult "Found allow rules" ($allowPaths.Count -gt 0) "Count: $($allowPaths.Count)"

# ============================================================
# EXPECTED BLOCK PATHS - Critical user-writable locations
# ============================================================
$expectedBlocks = @(
    # AppData variations
    '%APPDATA%\*',
    '%LOCALAPPDATA%\*',
    '%USERPROFILE%\AppData\LocalLow\*',

    # User folders
    '%USERPROFILE%\Downloads\*',
    '%USERPROFILE%\Desktop\*',
    '%USERPROFILE%\Documents\*',

    # Temp folders
    '%TEMP%\*',
    '%TMP%\*',

    # Public folders
    'C:\Users\Public\*',

    # OneDrive
    '%OneDrive%\*',

    # Removable drives
    'D:\*',
    'E:\*',
    'F:\*'
)

Write-Host "`n--- Validating Expected BLOCK Paths ---" -ForegroundColor Cyan

$missingBlocks = @()
foreach ($expected in $expectedBlocks) {
    if ($blockPaths -contains $expected) {
        Write-Host "  [OK] $expected" -ForegroundColor Green
    } else {
        Write-Host "  [MISSING] $expected" -ForegroundColor Red
        $missingBlocks += $expected
    }
}

Write-TestResult "All critical user paths are blocked" ($missingBlocks.Count -eq 0) "Missing: $($missingBlocks -join ', ')"

# ============================================================
# EXPECTED ALLOW PATHS - System directories
# ============================================================
$expectedAllows = @(
    'C:\Windows\*',
    'C:\Program Files\*',
    'C:\Program Files (x86)\*',
    'C:\ProgramData\Microsoft\Windows Defender\*'
)

Write-Host "`n--- Validating Expected ALLOW Paths ---" -ForegroundColor Cyan

$missingAllows = @()
foreach ($expected in $expectedAllows) {
    if ($allowPaths -contains $expected) {
        Write-Host "  [OK] $expected" -ForegroundColor Green
    } else {
        Write-Host "  [MISSING] $expected" -ForegroundColor Red
        $missingAllows += $expected
    }
}

Write-TestResult "All system directories are allowed" ($missingAllows.Count -eq 0) "Missing: $($missingAllows -join ', ')"

# ============================================================
# EXPECTED ALLOW PATHS - Microsoft apps whitelist
# ============================================================
$expectedMSApps = @(
    '%LOCALAPPDATA%\Microsoft\OneDrive\*',
    '%LOCALAPPDATA%\Microsoft\Teams\*',
    '%LOCALAPPDATA%\Microsoft\EdgeWebView\*',
    '%LOCALAPPDATA%\Microsoft\WindowsApps\*'
)

Write-Host "`n--- Validating Microsoft App Whitelist ---" -ForegroundColor Cyan

$missingMSApps = @()
foreach ($expected in $expectedMSApps) {
    if ($allowPaths -contains $expected) {
        Write-Host "  [OK] $expected" -ForegroundColor Green
    } else {
        Write-Host "  [MISSING] $expected" -ForegroundColor Red
        $missingMSApps += $expected
    }
}

Write-TestResult "Microsoft apps are whitelisted" ($missingMSApps.Count -eq 0) "Missing: $($missingMSApps -join ', ')"

# ============================================================
# NEGATIVE TEST: System paths should NOT be blocked
# ============================================================
$shouldNotBlock = @(
    'C:\Windows\*',
    'C:\Program Files\*',
    'C:\Program Files (x86)\*'
)

Write-Host "`n--- Validating System Paths NOT Blocked ---" -ForegroundColor Cyan

$wronglyBlocked = @()
foreach ($path in $shouldNotBlock) {
    if ($blockPaths -contains $path) {
        Write-Host "  [ERROR] $path is blocked!" -ForegroundColor Red
        $wronglyBlocked += $path
    } else {
        Write-Host "  [OK] $path not blocked" -ForegroundColor Green
    }
}

Write-TestResult "System paths are NOT blocked" ($wronglyBlocked.Count -eq 0) "Wrongly blocked: $($wronglyBlocked -join ', ')"

# ============================================================
# DEPTH COVERAGE TEST: Verify wildcards at multiple depths
# ============================================================
Write-Host "`n--- Validating Depth Coverage ---" -ForegroundColor Cyan

$depthTests = @(
    @{ Base = '%APPDATA%'; Depths = @('*', '*\*', '*\*\*', '*\*\*\*') },
    @{ Base = '%LOCALAPPDATA%'; Depths = @('*', '*\*', '*\*\*', '*\*\*\*') },
    @{ Base = '%USERPROFILE%\Downloads'; Depths = @('*', '*\*', '*\*\*') }
)

$depthFailures = @()
foreach ($test in $depthTests) {
    $base = $test.Base
    $hasAllDepths = $true
    foreach ($depth in $test.Depths) {
        $fullPath = "$base\$depth"
        if ($blockPaths -notcontains $fullPath) {
            $hasAllDepths = $false
            $depthFailures += $fullPath
        }
    }
    if ($hasAllDepths) {
        Write-Host "  [OK] $base has all depth levels" -ForegroundColor Green
    } else {
        Write-Host "  [INCOMPLETE] $base missing some depths" -ForegroundColor Yellow
    }
}

Write-TestResult "Block rules cover multiple depths" ($depthFailures.Count -lt 3) "Missing depths: $($depthFailures.Count)"

# ============================================================
# BROWSER PATHS TEST
# ============================================================
Write-Host "`n--- Validating Browser Install Paths Blocked ---" -ForegroundColor Cyan

$browserPaths = @(
    '%LOCALAPPDATA%\Google\*',
    '%LOCALAPPDATA%\Mozilla\*',
    '%LOCALAPPDATA%\BraveSoftware\*'
)

$missingBrowserBlocks = @()
foreach ($path in $browserPaths) {
    if ($blockPaths -contains $path) {
        Write-Host "  [OK] $path" -ForegroundColor Green
    } else {
        Write-Host "  [MISSING] $path" -ForegroundColor Red
        $missingBrowserBlocks += $path
    }
}

Write-TestResult "Browser install paths are blocked" ($missingBrowserBlocks.Count -eq 0) "Missing: $($missingBrowserBlocks -join ', ')"

# ============================================================
# REMOVABLE DRIVE TEST
# ============================================================
Write-Host "`n--- Validating Removable Drives Blocked ---" -ForegroundColor Cyan

$driveLetters = @('D:', 'E:', 'F:', 'G:', 'H:', 'I:', 'J:', 'K:')
$missingDrives = @()

foreach ($drive in $driveLetters) {
    $drivePath = "$drive\*"
    if ($blockPaths -contains $drivePath) {
        Write-Host "  [OK] $drivePath" -ForegroundColor Green
    } else {
        Write-Host "  [MISSING] $drivePath" -ForegroundColor Red
        $missingDrives += $drivePath
    }
}

Write-TestResult "All removable drives (D-K) are blocked" ($missingDrives.Count -eq 0) "Missing: $($missingDrives -join ', ')"

# ============================================================
# WHATIF OUTPUT STRUCTURE VALIDATION
# ============================================================
Write-Host "`n--- Validating WhatIf Output Structure ---" -ForegroundColor Cyan

$structureChecks = @(
    @{ Name = "Shows WHATIF MODE banner"; Pattern = "WHATIF MODE" },
    @{ Name = "Shows Windows 11 fix step"; Pattern = "\[1/6\].*Windows 11" },
    @{ Name = "Shows backup step"; Pattern = "\[2/6\].*backup" },
    @{ Name = "Shows registry init step"; Pattern = "\[3/6\].*registry" },
    @{ Name = "Shows ALLOW rules step"; Pattern = "\[4/6\].*ALLOW" },
    @{ Name = "Shows BLOCK rules step"; Pattern = "\[5/6\].*BLOCK" },
    @{ Name = "Shows whitelist step"; Pattern = "\[6/6\].*whitelist" },
    @{ Name = "Shows SIMULATION COMPLETE"; Pattern = "SIMULATION COMPLETE" },
    @{ Name = "Shows PolicyScope = 1"; Pattern = "PolicyScope.*1" },
    @{ Name = "Shows instruction to run without WhatIf"; Pattern = "run without -WhatIf" }
)

foreach ($check in $structureChecks) {
    $found = $output -match $check.Pattern
    Write-TestResult $check.Name $found
}

# ============================================================
# SUMMARY
# ============================================================
Write-Host "`n" + ("=" * 50) -ForegroundColor Cyan
Write-Host "TEST SUMMARY" -ForegroundColor Cyan
Write-Host ("=" * 50) -ForegroundColor Cyan

Write-Host "`nPassed: $script:TestsPassed" -ForegroundColor Green
Write-Host "Failed: $script:TestsFailed" -ForegroundColor $(if ($script:TestsFailed -gt 0) { "Red" } else { "Green" })

Write-Host "`n--- Parsed Rules Summary ---"
Write-Host "Total BLOCK rules: $($blockPaths.Count)"
Write-Host "Total ALLOW rules: $($allowPaths.Count)"

if ($script:TestsFailed -eq 0) {
    Write-Host "`n[SUCCESS] All WhatIf output validations passed!" -ForegroundColor Green
    Write-Host "The script would create the expected registry configuration." -ForegroundColor Green
} else {
    Write-Host "`n[WARNING] Some validations failed. Review output above." -ForegroundColor Yellow
}

# Output all parsed paths for review
Write-Host "`n--- All Parsed BLOCK Paths ---" -ForegroundColor DarkGray
$blockPaths | ForEach-Object { Write-Host "  $_" -ForegroundColor DarkGray }

Write-Host "`n--- All Parsed ALLOW Paths ---" -ForegroundColor DarkGray
$allowPaths | ForEach-Object { Write-Host "  $_" -ForegroundColor DarkGray }

exit $script:TestsFailed

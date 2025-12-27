#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Monitors whitelisted folders for new/unknown executables
.DESCRIPTION
    Scans whitelisted paths and detects executables that weren't in the baseline.
    Can quarantine suspicious files and alert parents.
.PARAMETER Scan
    Run a scan now and report findings
.PARAMETER UpdateBaseline
    Update the baseline with current executables (run after installing legitimate apps)
.PARAMETER Quarantine
    Move detected executables to quarantine folder
.PARAMETER ShowBaseline
    Display current baseline
.EXAMPLE
    .\ExeMonitor.ps1 -Scan
.EXAMPLE
    .\ExeMonitor.ps1 -UpdateBaseline
#>

param(
    [switch]$Scan,
    [switch]$UpdateBaseline,
    [switch]$Quarantine,
    [switch]$ShowBaseline,
    [switch]$ConvertSaferLog,
    [switch]$Silent
)

$script:DataDir = "C:\ParentalControl\Data"
$script:LogDir = "C:\ParentalControl\Logs"
$script:QuarantineDir = "C:\ParentalControl\Quarantine"
$script:BaselineFile = "$script:DataDir\baseline.csv"
$script:AlertLog = "$script:LogDir\ExeMonitor.log"
$script:SaferLog = "$script:LogDir\SAFER.log"
$script:SaferLogUtf8 = "$script:LogDir\SAFER-utf8.log"
$script:BasePath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers\262144\Paths"

# Executable extensions to monitor
$script:ExeExtensions = @('.exe', '.msi', '.bat', '.cmd', '.com', '.scr', '.pif', '.vbs', '.js', '.wsf', '.ps1')

# ═══════════════════════════════════════════════════════════════════
# HELPER FUNCTIONS
# ═══════════════════════════════════════════════════════════════════

function Convert-SaferLogToUtf8 {
    <#
    .SYNOPSIS
        Converts SAFER.log from UTF-16 LE to UTF-8 for SIEM ingestion
    #>
    if (!(Test-Path $script:SaferLog)) {
        if (!$Silent) {
            Write-Host "  SAFER.log not found at: $script:SaferLog" -ForegroundColor Yellow
        }
        return $false
    }

    try {
        # Read as UTF-16 LE (Unicode) and write as UTF-8
        $content = Get-Content -Path $script:SaferLog -Encoding Unicode -ErrorAction Stop
        $content | Out-File -FilePath $script:SaferLogUtf8 -Encoding UTF8 -Force

        if (!$Silent) {
            $lineCount = ($content | Measure-Object -Line).Lines
            Write-Host "  Converted $lineCount lines to UTF-8" -ForegroundColor Green
            Write-Host "  Output: $script:SaferLogUtf8" -ForegroundColor Cyan
        }
        return $true
    }
    catch {
        if (!$Silent) {
            Write-Host "  Error converting log: $_" -ForegroundColor Red
        }
        return $false
    }
}

function Write-Log {
    param (
        [string]$Message,
        [string]$Level = "INFO"
    )

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"

    # Ensure log directory exists
    if (!(Test-Path $script:LogDir)) {
        New-Item -ItemType Directory -Path $script:LogDir -Force | Out-Null
    }

    Add-Content -Path $script:AlertLog -Value $logEntry -ErrorAction SilentlyContinue

    if (!$Silent) {
        switch ($Level) {
            "ALERT" { Write-Host "  ! $Message" -ForegroundColor Red }
            "WARN"  { Write-Host "  ? $Message" -ForegroundColor Yellow }
            "OK"    { Write-Host "  + $Message" -ForegroundColor Green }
            default { Write-Host "  $Message" -ForegroundColor White }
        }
    }
}

function Get-WhitelistedPaths {
    <#
    .SYNOPSIS
        Gets all whitelisted paths from the registry
    #>
    $paths = @()

    if (!(Test-Path $script:BasePath)) {
        return $paths
    }

    Get-ChildItem $script:BasePath -ErrorAction SilentlyContinue | ForEach-Object {
        $props = Get-ItemProperty $_.PSPath
        $path = $props.ItemData

        # Expand environment variables
        $expandedPath = [Environment]::ExpandEnvironmentVariables($path)

        # Remove wildcards to get the base folder
        $basePath = $expandedPath -replace '\\\*.*$', ''

        if ($basePath -and (Test-Path $basePath -ErrorAction SilentlyContinue)) {
            $paths += $basePath
        }
    }

    return $paths | Select-Object -Unique
}

function Get-ExecutablesInPath {
    param ([string]$Path)

    $executables = @()

    if (!(Test-Path $Path)) {
        return $executables
    }

    Get-ChildItem -Path $Path -Recurse -File -ErrorAction SilentlyContinue |
        Where-Object { $script:ExeExtensions -contains $_.Extension.ToLower() } |
        ForEach-Object {
            $hash = (Get-FileHash $_.FullName -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
            $executables += [PSCustomObject]@{
                Path = $_.FullName
                Name = $_.Name
                Hash = $hash
                Size = $_.Length
                Created = $_.CreationTime
                Modified = $_.LastWriteTime
            }
        }

    return $executables
}

function Initialize-Directories {
    @($script:DataDir, $script:LogDir, $script:QuarantineDir) | ForEach-Object {
        if (!(Test-Path $_)) {
            New-Item -ItemType Directory -Path $_ -Force | Out-Null
        }
    }
}

# ═══════════════════════════════════════════════════════════════════
# BASELINE MANAGEMENT
# ═══════════════════════════════════════════════════════════════════

function Update-Baseline {
    Write-Host "`n  Updating baseline..." -ForegroundColor Yellow

    Initialize-Directories

    $whitelistedPaths = Get-WhitelistedPaths

    if ($whitelistedPaths.Count -eq 0) {
        Write-Host "  No whitelisted paths found." -ForegroundColor Yellow
        return
    }

    Write-Host "  Scanning $($whitelistedPaths.Count) whitelisted locations..." -ForegroundColor White

    $allExecutables = @()

    foreach ($path in $whitelistedPaths) {
        Write-Host "    Scanning: $path" -ForegroundColor DarkGray
        $exes = Get-ExecutablesInPath -Path $path
        $allExecutables += $exes
    }

    if ($allExecutables.Count -gt 0) {
        $allExecutables | Export-Csv -Path $script:BaselineFile -NoTypeInformation -Force
        Write-Host "`n  Baseline updated: $($allExecutables.Count) executables recorded" -ForegroundColor Green
        Write-Log "Baseline updated with $($allExecutables.Count) executables" -Level "OK"
    } else {
        Write-Host "`n  No executables found in whitelisted paths" -ForegroundColor Yellow
    }
}

function Get-Baseline {
    if (!(Test-Path $script:BaselineFile)) {
        return @()
    }

    return Import-Csv $script:BaselineFile
}

function Show-Baseline {
    $baseline = Get-Baseline

    if ($baseline.Count -eq 0) {
        Write-Host "`n  No baseline exists. Run with -UpdateBaseline first." -ForegroundColor Yellow
        return
    }

    Write-Host "`n  Baseline: $($baseline.Count) known executables" -ForegroundColor Cyan
    Write-Host "  " + ("-" * 50) -ForegroundColor DarkGray

    $baseline | Group-Object { Split-Path (Split-Path $_.Path -Parent) -Leaf } | ForEach-Object {
        Write-Host "`n  [$($_.Name)] - $($_.Count) files" -ForegroundColor White
        $_.Group | Select-Object -First 5 | ForEach-Object {
            Write-Host "    $($_.Name)" -ForegroundColor DarkGray
        }
        if ($_.Count -gt 5) {
            Write-Host "    ... and $($_.Count - 5) more" -ForegroundColor DarkGray
        }
    }
}

# ═══════════════════════════════════════════════════════════════════
# SCANNING
# ═══════════════════════════════════════════════════════════════════

function Invoke-Scan {
    param ([switch]$QuarantineNew)

    Initialize-Directories

    $baseline = Get-Baseline
    $baselineHashes = @{}
    $baselinePaths = @{}

    foreach ($item in $baseline) {
        if ($item.Hash) { $baselineHashes[$item.Hash] = $item }
        if ($item.Path) { $baselinePaths[$item.Path] = $item }
    }

    $whitelistedPaths = Get-WhitelistedPaths

    if ($whitelistedPaths.Count -eq 0) {
        if (!$Silent) {
            Write-Host "`n  No whitelisted paths to scan." -ForegroundColor Yellow
        }
        return @()
    }

    if (!$Silent) {
        Write-Host "`n  Scanning $($whitelistedPaths.Count) whitelisted locations..." -ForegroundColor Yellow
    }

    $newExecutables = @()
    $knownCount = 0

    foreach ($path in $whitelistedPaths) {
        $exes = Get-ExecutablesInPath -Path $path

        foreach ($exe in $exes) {
            $isKnown = $false

            # Check by hash first (most reliable)
            if ($exe.Hash -and $baselineHashes.ContainsKey($exe.Hash)) {
                $isKnown = $true
            }
            # Fall back to path check
            elseif ($baselinePaths.ContainsKey($exe.Path)) {
                # Path exists but hash changed - suspicious!
                $oldHash = $baselinePaths[$exe.Path].Hash
                if ($oldHash -ne $exe.Hash) {
                    $exe | Add-Member -NotePropertyName "Reason" -NotePropertyValue "MODIFIED (hash changed)" -Force
                    $newExecutables += $exe
                    continue
                }
                $isKnown = $true
            }

            if ($isKnown) {
                $knownCount++
            } else {
                $exe | Add-Member -NotePropertyName "Reason" -NotePropertyValue "NEW (not in baseline)" -Force
                $newExecutables += $exe
            }
        }
    }

    # Report results
    if (!$Silent) {
        Write-Host "`n  Results:" -ForegroundColor White
        Write-Host "    Known executables: $knownCount" -ForegroundColor Green
        Write-Host "    New/Modified:      $($newExecutables.Count)" -ForegroundColor $(if ($newExecutables.Count -gt 0) { "Red" } else { "Green" })
    }

    # Handle new executables
    if ($newExecutables.Count -gt 0) {
        Write-Log "SCAN ALERT: Found $($newExecutables.Count) new/modified executables" -Level "ALERT"

        foreach ($exe in $newExecutables) {
            Write-Log "  $($exe.Reason): $($exe.Path)" -Level "ALERT"

            if (!$Silent) {
                Write-Host "`n  ALERT: $($exe.Reason)" -ForegroundColor Red
                Write-Host "    File: $($exe.Name)" -ForegroundColor White
                Write-Host "    Path: $($exe.Path)" -ForegroundColor DarkGray
                Write-Host "    Size: $([math]::Round($exe.Size / 1KB, 2)) KB" -ForegroundColor DarkGray
                Write-Host "    Created: $($exe.Created)" -ForegroundColor DarkGray
            }

            # Quarantine if requested
            if ($QuarantineNew) {
                $quarantinePath = Join-Path $script:QuarantineDir "$(Get-Date -Format 'yyyyMMdd_HHmmss')_$($exe.Name)"
                try {
                    Move-Item -Path $exe.Path -Destination $quarantinePath -Force
                    Write-Log "Quarantined: $($exe.Path) -> $quarantinePath" -Level "WARN"
                    if (!$Silent) {
                        Write-Host "    QUARANTINED -> $quarantinePath" -ForegroundColor Yellow
                    }
                } catch {
                    Write-Log "Failed to quarantine: $($exe.Path) - $_" -Level "ALERT"
                    if (!$Silent) {
                        Write-Host "    Failed to quarantine: $_" -ForegroundColor Red
                    }
                }
            }
        }
    } else {
        Write-Log "Scan complete: No new executables detected" -Level "OK"
    }

    return $newExecutables
}

# ═══════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════

if (!$Silent) {
    Write-Host @"
╔══════════════════════════════════════════════════════════════════╗
║  EXECUTABLE MONITOR                                              ║
╚══════════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan
}

# Handle log conversion (doesn't require SRP)
if ($ConvertSaferLog) {
    if (!$Silent) {
        Write-Host "`n  Converting SAFER.log to UTF-8..." -ForegroundColor Yellow
    }
    $result = Convert-SaferLogToUtf8
    exit $(if ($result) { 0 } else { 1 })
}

# Check if SRP is configured
$allowPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers\262144\Paths"
if (!(Test-Path $allowPath)) {
    Write-Host "`n  SRP not configured. Run Enable-SRP-Complete.ps1 first." -ForegroundColor Red
    exit 1
}

if ($ShowBaseline) {
    Show-Baseline
    exit 0
}

if ($UpdateBaseline) {
    Update-Baseline
    exit 0
}

if ($Scan) {
    $results = Invoke-Scan -QuarantineNew:$Quarantine

    if (!$Silent) {
        Write-Host ""
        if ($results.Count -eq 0) {
            Write-Host "  All clear - no suspicious executables found." -ForegroundColor Green
        } else {
            Write-Host "  Review the alerts above. Consider:" -ForegroundColor Yellow
            Write-Host "    - If legitimate: run -UpdateBaseline to add to known list" -ForegroundColor DarkGray
            Write-Host "    - If suspicious: run -Scan -Quarantine to move files" -ForegroundColor DarkGray
        }
    }

    exit $results.Count
}

# Show usage
Write-Host @"

USAGE:
  .\ExeMonitor.ps1 -Scan                Scan for new executables
  .\ExeMonitor.ps1 -Scan -Quarantine    Scan and quarantine new files
  .\ExeMonitor.ps1 -UpdateBaseline      Record current state as trusted
  .\ExeMonitor.ps1 -ShowBaseline        Show known executables
  .\ExeMonitor.ps1 -ConvertSaferLog     Convert SAFER.log to UTF-8

WORKFLOW:
  1. After whitelisting games/apps, run -UpdateBaseline
  2. Periodically run -Scan to check for new executables
  3. If alerts appear:
     - Legitimate app? Run -UpdateBaseline
     - Suspicious? Run -Scan -Quarantine

"@ -ForegroundColor White
